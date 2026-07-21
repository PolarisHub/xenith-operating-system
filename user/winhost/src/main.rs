#![cfg_attr(target_os = "none", no_std)]
#![cfg_attr(target_os = "none", no_main)]

//! Trusted bootstrap runner for the bounded Win64 console subset.
//!
//! The loaded image executes inside this process and therefore shares its
//! Xenith syscall authority and inherited descriptors. Structural PE checks
//! are not a security sandbox; only trusted conformance images belong here
//! until Xenith has a least-authority process launcher and syscall isolation.

use core::arch::asm;
use core::cell::UnsafeCell;
use core::ffi::c_void;
use core::hint::spin_loop;
#[cfg(target_os = "none")]
use core::panic::PanicInfo;
use core::sync::atomic::{AtomicBool, Ordering};

use libuser::args::Startup;
use libuser::syscall::{self, Error as SyscallError};
use xenith_abi::{OpenFlags, MAP_ANONYMOUS, MAP_PRIVATE, PROT_EXEC, PROT_READ, PROT_WRITE};
use xenith_pe::PeImage;
use xenith_winhost::path_runtime::{resolve_executable_path, ExecutablePathError};
use xenith_winhost::runtime::{decode_guest_handle, validate_console_write, BootstrapRuntime};
use xenith_winhost::{
    build_loaded_image, plan_runtime_relocations, visit_final_section_protections,
    BootstrapAddresses, FinalProtection, LoaderError, MAX_PE_FILE_BYTES, MAX_PE_PATH_BYTES,
};
use xenith_winhost_core::NtStatus;

const PAGE_SIZE: usize = 4096;
const SEEK_SET: u32 = 0;
const SEEK_END: u32 = 2;
const EXIT_USAGE: i32 = 2;
const EXIT_LOAD_FAILURE: i32 = 126;
#[cfg(target_os = "none")]
const EXIT_PANIC: i32 = 125;

// These bounded, 64-KiB-aligned addresses sit well inside Xenith's dynamic
// user range. A returned address is always compared with the request because
// mmap hints are allowed to fall back rather than replace an existing range.
const FALLBACK_IMAGE_BASES: [u64; 4] = [
    0x0000_1000_0000_0000,
    0x0000_1800_0000_0000,
    0x0000_2000_0000_0000,
    0x0000_2800_0000_0000,
];

const RUNTIME_HANDLE_CAPACITY: usize = 32;
const RUNTIME_OBJECT_CAPACITY: usize = 32;
type HostNtRuntime = BootstrapRuntime<RUNTIME_HANDLE_CAPACITY, RUNTIME_OBJECT_CAPACITY>;

struct RuntimeCell {
    held: AtomicBool,
    value: UnsafeCell<Option<HostNtRuntime>>,
}

// SAFETY: every access to `value` is serialized by the acquire/release lock.
unsafe impl Sync for RuntimeCell {}

impl RuntimeCell {
    const fn new() -> Self {
        Self {
            held: AtomicBool::new(false),
            value: UnsafeCell::new(None),
        }
    }

    fn replace(&self, runtime: HostNtRuntime) {
        self.lock(|slot| *slot = Some(runtime));
    }

    fn with<R>(&self, operation: impl FnOnce(&mut HostNtRuntime) -> R) -> Option<R> {
        self.lock(|slot| slot.as_mut().map(operation))
    }

    fn lock<R>(&self, operation: impl FnOnce(&mut Option<HostNtRuntime>) -> R) -> R {
        while self
            .held
            .compare_exchange_weak(false, true, Ordering::Acquire, Ordering::Relaxed)
            .is_err()
        {
            spin_loop();
        }
        let guard = RuntimeCellGuard(&self.held);
        // SAFETY: `guard` owns the unique lock, and every access uses this path.
        let result = operation(unsafe { &mut *self.value.get() });
        drop(guard);
        result
    }
}

struct RuntimeCellGuard<'a>(&'a AtomicBool);

impl Drop for RuntimeCellGuard<'_> {
    fn drop(&mut self) {
        self.0.store(false, Ordering::Release);
    }
}

static HOST_NT_RUNTIME: RuntimeCell = RuntimeCell::new();

#[derive(Debug)]
enum HostError {
    Usage,
    PathTooLong,
    WindowsPath(ExecutablePathError),
    InvalidFileSize,
    FileChanged,
    InvalidStackSize,
    Syscall {
        operation: &'static str,
        error: SyscallError,
    },
    Loader(LoaderError),
    Runtime(NtStatus),
    NoImageAddress,
}

impl From<LoaderError> for HostError {
    fn from(value: LoaderError) -> Self {
        Self::Loader(value)
    }
}

impl From<ExecutablePathError> for HostError {
    fn from(value: ExecutablePathError) -> Self {
        Self::WindowsPath(value)
    }
}

struct Mapping {
    address: *mut u8,
    length: usize,
}

struct Descriptor(i32);

impl Descriptor {
    fn open_read_only(path: &[u8]) -> Result<Self, HostError> {
        syscall::open(path, OpenFlags::RDONLY, 0)
            .map(Self)
            .map_err(|error| HostError::Syscall {
                operation: "open",
                error,
            })
    }

    const fn raw(&self) -> i32 {
        self.0
    }

    fn close(mut self) -> Result<(), HostError> {
        let descriptor = core::mem::replace(&mut self.0, -1);
        syscall::close(descriptor).map_err(|error| HostError::Syscall {
            operation: "close",
            error,
        })
    }
}

impl Drop for Descriptor {
    fn drop(&mut self) {
        if self.0 >= 0 {
            let _ = syscall::close(self.0);
        }
    }
}

impl Mapping {
    fn anonymous(address_hint: u64, length: usize) -> Result<Self, HostError> {
        let address_hint = usize::try_from(address_hint)
            .map_err(|_| HostError::Loader(LoaderError::AddressOverflow))?;
        let address = syscall::mmap(
            address_hint as *mut u8,
            length,
            PROT_READ | PROT_WRITE,
            MAP_PRIVATE | MAP_ANONYMOUS,
            -1,
            0,
        )
        .map_err(|error| HostError::Syscall {
            operation: "mmap",
            error,
        })?;
        Ok(Self { address, length })
    }

    fn base(&self) -> u64 {
        self.address as usize as u64
    }

    fn stack(length: usize) -> Result<Self, HostError> {
        if length < PAGE_SIZE || !length.is_multiple_of(PAGE_SIZE) {
            return Err(HostError::InvalidStackSize);
        }
        let allocation_length = length
            .checked_add(PAGE_SIZE)
            .ok_or(HostError::Loader(LoaderError::AddressOverflow))?;
        let mut mapping = Self::anonymous(0, allocation_length)?;
        let usable_address = (mapping.address as usize)
            .checked_add(PAGE_SIZE)
            .ok_or(HostError::Loader(LoaderError::AddressOverflow))?;
        syscall::munmap(mapping.address, PAGE_SIZE).map_err(|error| HostError::Syscall {
            operation: "munmap stack guard",
            error,
        })?;

        // The prefix is now an unmapped guard page. Adjusting the owner after
        // the successful unmap makes Drop cover exactly the remaining stack.
        mapping.address = usable_address as *mut u8;
        mapping.length = length;
        Ok(mapping)
    }

    fn checked_top(&self) -> Result<usize, HostError> {
        (self.address as usize)
            .checked_add(self.length)
            .ok_or(HostError::Loader(LoaderError::AddressOverflow))
    }

    /// Borrow the complete live anonymous mapping for loader writes.
    ///
    /// # Safety
    /// The mapping must still be live, uniquely borrowed, and writable.
    unsafe fn as_mut_slice(&mut self) -> &mut [u8] {
        // SAFETY: the constructor established this exact mapped range and the
        // mutable receiver prevents another slice from being created here.
        unsafe { core::slice::from_raw_parts_mut(self.address, self.length) }
    }

    /// Borrow initialized file bytes from the start of this mapping.
    ///
    /// # Safety
    /// `length` must not exceed this live mapping and the bytes must have been
    /// initialized by the caller before a parser observes them.
    unsafe fn initialized_prefix(&self, length: usize) -> &[u8] {
        debug_assert!(length <= self.length);
        // SAFETY: the stated contract bounds the immutable slice.
        unsafe { core::slice::from_raw_parts(self.address, length) }
    }
}

impl Drop for Mapping {
    fn drop(&mut self) {
        let _ = syscall::munmap(self.address, self.length);
    }
}

#[no_mangle]
/// Xenith entry point for the bounded Win64 console host.
///
/// # Safety
/// `startup` must be the loader-created, read-only Xenith startup block.
pub unsafe extern "C" fn _start(startup: *const Startup) -> ! {
    // SAFETY: the kernel loader owns the startup block contract.
    let startup = unsafe { startup.as_ref() };
    let result = startup.ok_or(HostError::Usage).and_then(run);
    match result {
        Ok(code) => syscall::exit(code as i32),
        Err(HostError::Usage) => {
            libuser::println!("usage: xenith-winhost <program.exe>");
            syscall::exit(EXIT_USAGE)
        },
        Err(error) => {
            report_error(&error);
            syscall::exit(EXIT_LOAD_FAILURE)
        },
    }
}

fn run(startup: &Startup) -> Result<u32, HostError> {
    // SAFETY: `_start` established the kernel startup-block contract.
    let path = unsafe { startup.argument(1) }.ok_or(HostError::Usage)?;
    run_path(path)
}

fn run_path(path: &[u8]) -> Result<u32, HostError> {
    if path.is_empty() {
        return Err(HostError::Usage);
    }
    if path.len() > MAX_PE_PATH_BYTES {
        return Err(HostError::PathTooLong);
    }

    const NATIVE_PATH_CAPACITY: usize = MAX_PE_PATH_BYTES + 16;
    let path = resolve_executable_path::<NATIVE_PATH_CAPACITY>(path)?;
    let (file_mapping, file_length) = read_bounded_file(path.as_bytes())?;
    // SAFETY: `read_bounded_file` initialized exactly `file_length` bytes and
    // keeps the containing mapping alive through this borrow.
    let file_bytes = unsafe { file_mapping.initialized_prefix(file_length) };
    let image = PeImage::parse(file_bytes).map_err(LoaderError::Pe)?;
    let loader = xenith_winhost::validate_runtime_subset(&image)?;
    let stack_length = usize::try_from(image.headers().optional.size_of_stack_reserve)
        .map_err(|_| HostError::Loader(LoaderError::AddressOverflow))?;
    let mut image_mapping = map_image(&image, loader.image_base, loader.size_of_image as usize)?;
    let actual_base = image_mapping.base();
    let addresses = bootstrap_addresses();
    initialize_runtime()?;
    {
        // SAFETY: this is a fresh, uniquely owned RW anonymous mapping.
        let output = unsafe { image_mapping.as_mut_slice() };
        build_loaded_image(&image, actual_base, addresses, output)?;
    }
    install_final_protections(&image, &image_mapping)?;
    let entry = (image_mapping.address as usize)
        .checked_add(loader.entry_rva as usize)
        .ok_or(LoaderError::AddressOverflow)?;

    // Nothing in the loaded image refers to the on-disk file mapping after
    // copies, relocations, and IAT binding are complete.
    drop(file_mapping);

    // Run Win64 code on its own declared, bounded stack rather than sharing
    // the host's fixed Xenith stack and live Rust frames. The full accepted
    // reserve is committed up front; automatic Windows guard growth is not
    // part of this bootstrap slice.
    let guest_stack = Mapping::stack(stack_length)?;
    let guest_stack_top = guest_stack.checked_top()?;

    // SAFETY: parsing proved an executable entry RVA, the actual-base sum was
    // checked, imports/relocations were fully installed, and final permissions
    // were switched to W^X before control reaches guest code. The dedicated
    // RW stack is live through the call and has an unmapped lower guard page.
    Ok(unsafe { invoke_entry(entry, guest_stack_top) })
}

fn read_bounded_file(path: &[u8]) -> Result<(Mapping, usize), HostError> {
    // Open first, then derive the length from that exact descriptor. This
    // avoids validating one path object and subsequently opening a replacement.
    let descriptor = Descriptor::open_read_only(path)?;
    let file_length =
        syscall::lseek(descriptor.raw(), 0, SEEK_END).map_err(|error| HostError::Syscall {
            operation: "lseek end",
            error,
        })?;
    let file_length = usize::try_from(file_length).map_err(|_| HostError::InvalidFileSize)?;
    if file_length == 0 || file_length > MAX_PE_FILE_BYTES {
        return Err(HostError::InvalidFileSize);
    }
    let reset =
        syscall::lseek(descriptor.raw(), 0, SEEK_SET).map_err(|error| HostError::Syscall {
            operation: "lseek start",
            error,
        })?;
    if reset != 0 {
        return Err(HostError::FileChanged);
    }
    let mapping_length = align_page(file_length).ok_or(HostError::InvalidFileSize)?;
    let mut mapping = Mapping::anonymous(0, mapping_length)?;

    // SAFETY: the mapping is live, uniquely held, and still RW.
    let destination = unsafe { mapping.as_mut_slice() };
    let read_result = read_exact_file(descriptor.raw(), &mut destination[..file_length]);
    let close_result = descriptor.close();
    read_result?;
    close_result?;
    Ok((mapping, file_length))
}

fn read_exact_file(descriptor: i32, destination: &mut [u8]) -> Result<(), HostError> {
    let mut offset = 0usize;
    while offset < destination.len() {
        let count = syscall::read(descriptor, &mut destination[offset..]).map_err(|error| {
            HostError::Syscall {
                operation: "read",
                error,
            }
        })?;
        if count == 0 {
            return Err(HostError::FileChanged);
        }
        offset = offset.checked_add(count).ok_or(HostError::FileChanged)?;
    }
    let mut extra = [0u8; 1];
    let count = syscall::read(descriptor, &mut extra).map_err(|error| HostError::Syscall {
        operation: "read",
        error,
    })?;
    if count != 0 {
        return Err(HostError::FileChanged);
    }
    Ok(())
}

fn map_image(image: &PeImage<'_>, preferred: u64, image_size: usize) -> Result<Mapping, HostError> {
    let mut mapping_failure = None;
    match Mapping::anonymous(preferred, image_size) {
        Ok(preferred_mapping) if preferred_mapping.base() == preferred => {
            return Ok(preferred_mapping);
        },
        Ok(preferred_mapping) => drop(preferred_mapping),
        Err(error) => mapping_failure = Some(error),
    }

    let mut relocation_failure = None;
    let mut found_relocatable_base = false;
    for candidate in FALLBACK_IMAGE_BASES {
        if let Err(error) = plan_runtime_relocations(image, candidate) {
            relocation_failure = Some(error);
            continue;
        }
        found_relocatable_base = true;
        match Mapping::anonymous(candidate, image_size) {
            Ok(mapping) if mapping.base() == candidate => return Ok(mapping),
            Ok(mapping) => drop(mapping),
            Err(error) => mapping_failure = Some(error),
        }
    }
    if found_relocatable_base {
        if let Some(error) = mapping_failure {
            return Err(error);
        }
        return Err(HostError::NoImageAddress);
    }
    if let Some(error) = relocation_failure {
        return Err(HostError::Loader(error));
    }
    Err(HostError::NoImageAddress)
}

fn install_final_protections(image: &PeImage<'_>, mapping: &Mapping) -> Result<(), HostError> {
    syscall::mprotect(mapping.address, mapping.length, PROT_READ).map_err(|error| {
        HostError::Syscall {
            operation: "mprotect image",
            error,
        }
    })?;
    let mut syscall_failure = None;
    visit_final_section_protections(image, |range| {
        if syscall_failure.is_some() {
            return;
        }
        let Some(address) = (mapping.address as usize).checked_add(range.rva as usize) else {
            syscall_failure = Some(HostError::Loader(LoaderError::AddressOverflow));
            return;
        };
        let protection = match range.protection {
            FinalProtection::Read => PROT_READ,
            FinalProtection::ReadWrite => PROT_READ | PROT_WRITE,
            FinalProtection::ReadExecute => PROT_READ | PROT_EXEC,
        };
        if let Err(error) = syscall::mprotect(address as *mut u8, range.size as usize, protection) {
            syscall_failure = Some(HostError::Syscall {
                operation: "mprotect section",
                error,
            });
        }
    })?;
    if let Some(error) = syscall_failure {
        return Err(error);
    }
    Ok(())
}

fn bootstrap_addresses() -> BootstrapAddresses {
    BootstrapAddresses {
        get_std_handle: kernel32_get_std_handle as *const () as usize as u64,
        write_file: kernel32_write_file as *const () as usize as u64,
        exit_process: kernel32_exit_process as *const () as usize as u64,
        rtl_exit_user_process: Some(ntdll_rtl_exit_user_process as *const () as usize as u64),
        nt_close: Some(ntdll_nt_close as *const () as usize as u64),
    }
}

fn initialize_runtime() -> Result<(), HostError> {
    let runtime = HostNtRuntime::try_new().map_err(HostError::Runtime)?;
    HOST_NT_RUNTIME.replace(runtime);
    Ok(())
}

/// Call the validated PE process entry using the Microsoft x64 ABI.
///
/// # Safety
/// `address` must name a live RX mapping containing a Win64 no-argument
/// process entry. Its imports and relocations must already be installed.
/// `stack_top` must be the exclusive upper bound of a live writable mapping
/// large enough for the accepted PE stack reserve.
unsafe fn invoke_entry(address: usize, stack_top: usize) -> u32 {
    let result: u32;
    // SAFETY: the caller supplies a live Win64 entry and the exclusive upper
    // bound of a writable stack mapping. R15 is nonvolatile in the Microsoft
    // x64 ABI, so a conforming entry preserves the saved Xenith stack pointer.
    // The sequence restores RSP before Rust observes the call result. A guest
    // which violates its ABI is outside this trusted bootstrap contract.
    unsafe {
        asm!(
            "mov r15, rsp",
            "mov rsp, {stack_top}",
            "and rsp, -16",
            "sub rsp, 32",
            "call {entry}",
            "mov rsp, r15",
            stack_top = in(reg) stack_top,
            entry = in(reg) address,
            lateout("eax") result,
            lateout("r15") _,
            clobber_abi("win64"),
        );
    }
    result
}

fn align_page(value: usize) -> Option<usize> {
    value
        .checked_add(PAGE_SIZE - 1)
        .map(|sum| sum & !(PAGE_SIZE - 1))
}

const INVALID_HANDLE_VALUE: isize = -1;

#[no_mangle]
pub extern "win64" fn kernel32_get_std_handle(kind: u32) -> isize {
    HOST_NT_RUNTIME
        .with(|runtime| runtime.get_std_handle(kind))
        .and_then(Result::ok)
        .map_or(INVALID_HANDLE_VALUE, |handle| handle.raw() as isize)
}

#[no_mangle]
/// Write a bounded buffer to a Xenith standard-output descriptor.
///
/// # Safety
/// `buffer` and `written` are untrusted guest addresses. The input buffer is
/// submitted directly to Xenith's checked usercopy path without becoming a
/// Rust reference. Synchronous calls require a non-null `written` pointer; an
/// invalid address faults this process because SEH is unavailable in this
/// slice.
pub unsafe extern "win64" fn kernel32_write_file(
    handle: isize,
    buffer: *const u8,
    requested: u32,
    written: *mut u32,
    overlapped: *mut c_void,
) -> i32 {
    let plan = match validate_console_write(
        handle,
        buffer as usize as u64,
        requested,
        written as usize as u64,
        overlapped as usize as u64,
    ) {
        Ok(plan) => plan,
        Err(_) => return 0,
    };
    let Some(Ok(descriptor)) =
        HOST_NT_RUNTIME.with(|runtime| runtime.write_descriptor(plan.handle))
    else {
        return 0;
    };
    // SAFETY: the raw assembly store deliberately preserves hardware fault
    // behavior without creating a Rust reference from a guest address.
    unsafe { store_guest_u32(written, 0) };
    let result = if plan.length == 0 {
        Ok(0)
    } else {
        // SAFETY: the pointer and bounded length remain stable for this
        // synchronous call. The wrapper passes them opaquely to kernel
        // usercopy and never creates a Rust slice.
        unsafe { syscall::write_raw(descriptor, buffer, plan.length) }
    };
    let Ok(count) = result else {
        return 0;
    };
    if !written.is_null() {
        // SAFETY: same raw optional output-pointer contract checked above.
        unsafe { store_guest_u32(written, count as u32) };
    }
    1
}

/// Store one Win32 `DWORD` without constructing a Rust reference from a guest
/// virtual address.
///
/// # Safety
/// The address is supplied by guest code. A non-writable or unmapped address
/// deliberately raises the architecture's normal user-mode page fault.
#[inline]
unsafe fn store_guest_u32(address: *mut u32, value: u32) {
    // SAFETY: this assembly has the explicit process-fault contract above. It
    // does not claim Rust pointer validity or alignment and performs one store.
    unsafe {
        asm!(
            "mov dword ptr [{address}], {value:e}",
            address = in(reg) address,
            value = in(reg) value,
            options(nostack, preserves_flags),
        );
    }
}

#[no_mangle]
pub extern "win64" fn kernel32_exit_process(code: u32) -> ! {
    syscall::exit(code as i32)
}

#[no_mangle]
pub extern "win64" fn ntdll_rtl_exit_user_process(status: u32) -> ! {
    syscall::exit(status as i32)
}

#[no_mangle]
pub extern "win64" fn ntdll_nt_close(raw_handle: isize) -> u32 {
    let handle = match decode_guest_handle(raw_handle) {
        Ok(handle) => handle,
        Err(status) => return status.as_u32(),
    };
    HOST_NT_RUNTIME
        .with(|runtime| runtime.close(handle))
        .unwrap_or(NtStatus::NOT_IMPLEMENTED)
        .as_u32()
}

fn report_error(error: &HostError) {
    if let HostError::WindowsPath(path) = error {
        libuser::println!("xenith-winhost: Windows path rejected: {:?}", path);
        return;
    }
    if let HostError::Loader(loader) = error {
        libuser::println!(
            "xenith-winhost: {:?} (NTSTATUS 0x{:08x})",
            loader,
            loader.nt_status().as_u32()
        );
        return;
    }
    if let HostError::Syscall { operation, error } = error {
        libuser::println!("xenith-winhost: {} failed (errno {})", operation, error.0);
        return;
    }
    if let HostError::Runtime(status) = error {
        libuser::println!("xenith-winhost: runtime NTSTATUS 0x{:08x}", status.as_u32());
        return;
    }
    libuser::println!("xenith-winhost: {:?}", error);
}

#[panic_handler]
#[cfg(target_os = "none")]
fn panic(_info: &PanicInfo<'_>) -> ! {
    libuser::println!("xenith-winhost: panic");
    syscall::exit(EXIT_PANIC)
}

#[cfg(not(target_os = "none"))]
fn main() {}
