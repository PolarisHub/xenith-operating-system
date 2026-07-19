#![no_std]
#![no_main]

mod abi;
mod file;
mod paging;

use core::arch::{asm, global_asm};
use core::ffi::c_void;
use core::panic::PanicInfo;
use core::{ptr, slice};

use abi::{
    is_error, BootServices, ConfigurationTable, GraphicsOutputProtocol, Handle, Status,
    SystemTable, ACPI_20_GUID, ACPI_GUID, ALLOCATE_MAX_ADDRESS, BUFFER_TOO_SMALL, GOP_GUID,
    INVALID_PARAMETER, LOADER_DATA, LOAD_ERROR, SUCCESS,
};
use file::{load_file, open_root, LoadedFile};
use paging::PageTables;
use xenith_boot_common::{
    append_region, Elf64, XenithBootInfo, XenithFramebuffer, XenithMemoryRegion, XenithModule,
    HHDM_OFFSET, PAGE_SIZE,
};
use xenith_uefi_loader::splash::Splash;
use xenith_uefi_loader::{
    boot_memory_kind, descriptor_length, normalize_memory_regions, uefi_command_line,
    MemoryDescriptor,
};

const KERNEL_PATH: &[u8] = b"\\EFI\\XENITH\\kernel.elf";
const KERNEL_FALLBACK: &[u8] = b"\\kernel.elf";
const INITRD_PATH: &[u8] = b"\\EFI\\XENITH\\initrd.cpio";
const INITRD_FALLBACK: &[u8] = b"\\initrd.cpio";
const MODULE_PATH: &[u8] = b"/initrd.cpio";
const PAGE_TABLE_PAGES: usize = 64;
const KERNEL_STACK_PAGES: usize = 16;
const MEMORY_MAP_RETRIES: usize = 8;

#[derive(Clone, Copy, Debug)]
enum LoaderError {
    Protocol(Status),
    File(Status),
    FileInfo(Status),
    FileSize,
    Path,
    Allocation(Status),
    Elf,
    KernelLayout,
    PageTables,
    MemoryMap(Status),
    MemoryMapCapacity,
    MemoryMapLayout,
    ExitBootServices(Status),
}

#[repr(C)]
struct BootStorage {
    info: XenithBootInfo,
    module: XenithModule,
    module_path: [u8; 32],
    command_line: [u8; 64],
}

struct MemoryMapStorage {
    raw_address: u64,
    raw_capacity: usize,
    region_address: u64,
    region_capacity: usize,
}

struct KernelImage {
    entry: u64,
}

global_asm!(
    ".text",
    ".global xenith_uefi_jump",
    "xenith_uefi_jump:",
    "cli",
    "mov cr3, rcx",
    "mov rsp, r9",
    "and rsp, -16",
    "sub rsp, 8",
    "xor rbp, rbp",
    "mov rdi, r8",
    "jmp rdx",
);

unsafe extern "efiapi" {
    fn xenith_uefi_jump(cr3: u64, entry: u64, boot_info: *const XenithBootInfo, stack: u64) -> !;
}

#[no_mangle]
/// UEFI application entry point.
///
/// # Safety
///
/// Firmware must supply the live image handle and system table defined by the UEFI ABI.
pub unsafe extern "efiapi" fn efi_main(
    image_handle: Handle,
    system_table: *mut SystemTable,
) -> Status {
    if system_table.is_null() {
        return INVALID_PARAMETER;
    }
    // SAFETY: UEFI invokes this entry with a live system-table pointer.
    let system_table = unsafe { &mut *system_table };
    match unsafe { run(image_handle, system_table) } {
        Ok(never) => match never {},
        Err(error) => {
            print_error(system_table, error);
            LOAD_ERROR
        },
    }
}

unsafe fn run(
    image_handle: Handle,
    system_table: &mut SystemTable,
) -> Result<core::convert::Infallible, LoaderError> {
    // SAFETY: Boot Services remains live until the explicit successful exit below.
    let boot_services = unsafe {
        system_table
            .boot_services
            .as_ref()
            .ok_or(LoaderError::Protocol(INVALID_PARAMETER))?
    };
    // Locate GOP once, paint before any filesystem I/O, and retain the exact
    // descriptor for the eventual native handoff.
    let framebuffer = unsafe { framebuffer(boot_services) };
    // SAFETY: GOP owns a live direct framebuffer until kernel handoff.
    let splash = unsafe { Splash::begin(framebuffer) };
    // SAFETY: protocol traversal is bounded to the loaded image's own filesystem.
    let root = unsafe { open_root(boot_services, image_handle)? };
    if let Some(splash) = splash {
        // SAFETY: no mode switch occurs during Xenith loader execution.
        unsafe { splash.progress(12) };
    }
    let kernel_file = unsafe {
        load_file(boot_services, root, KERNEL_PATH)
            .or_else(|_| load_file(boot_services, root, KERNEL_FALLBACK))?
    };
    if let Some(splash) = splash {
        // SAFETY: file allocation does not invalidate GOP storage.
        unsafe { splash.progress(22) };
    }
    let initrd = unsafe {
        load_file(boot_services, root, INITRD_PATH)
            .or_else(|_| load_file(boot_services, root, INITRD_FALLBACK))?
    };
    if let Some(splash) = splash {
        // SAFETY: file allocation does not invalidate GOP storage.
        unsafe { splash.progress(34) };
    }

    let page_tables_address = unsafe { allocate_low_pages(boot_services, PAGE_TABLE_PAGES)? };
    let stack_address = unsafe { allocate_low_pages(boot_services, KERNEL_STACK_PAGES)? };
    let stack_top = stack_address
        .checked_add(KERNEL_STACK_PAGES as u64 * PAGE_SIZE)
        .and_then(|top| HHDM_OFFSET.checked_add(top))
        .ok_or(LoaderError::KernelLayout)?;
    let boot_storage_address = unsafe { allocate_low_pages(boot_services, 1)? };
    // SAFETY: the new allocation is page-aligned, zeroable, and loader-exclusive.
    let mut page_tables = unsafe { PageTables::new(page_tables_address, PAGE_TABLE_PAGES)? };
    page_tables.map_transition_windows()?;
    if let Some(splash) = splash {
        // SAFETY: the firmware page tables remain active here.
        unsafe { splash.progress(44) };
    }

    let kernel = unsafe { load_kernel(boot_services, kernel_file, &mut page_tables)? };
    if let Some(splash) = splash {
        // SAFETY: the firmware page tables remain active here.
        unsafe { splash.progress(56) };
    }
    if framebuffer.address != 0 && framebuffer.address > u64::from(u32::MAX) {
        let bytes = u64::from(framebuffer.pitch)
            .checked_mul(u64::from(framebuffer.height))
            .ok_or(LoaderError::PageTables)?;
        page_tables.map_hhdm_physical(framebuffer.address, bytes)?;
    }
    let trampoline = xenith_uefi_jump as *const () as usize as u64;
    if trampoline > u64::from(u32::MAX) {
        page_tables.map_kernel(trampoline, trampoline, PAGE_SIZE * 2, false)?;
    }

    let memory_storage = unsafe { allocate_memory_map_storage(boot_services)? };
    if let Some(splash) = splash {
        // SAFETY: the firmware page tables remain active here.
        unsafe { splash.progress(62) };
    }
    // SAFETY: boot storage is one writable loader page and outlives ExitBootServices.
    let storage = unsafe { &mut *(boot_storage_address as *mut BootStorage) };
    storage.module_path.fill(0);
    storage.module_path[..MODULE_PATH.len()].copy_from_slice(MODULE_PATH);
    let command_line = uefi_command_line(splash.is_some());
    storage.command_line.fill(0);
    storage.command_line[..command_line.len()].copy_from_slice(command_line);
    storage.module = XenithModule {
        address: initrd.address,
        length: initrd.byte_len as u64,
        path: storage.module_path.as_ptr(),
        path_length: MODULE_PATH.len() as u32,
        reserved: 0,
    };
    storage.info = XenithBootInfo::empty();
    storage.info.hhdm_offset = HHDM_OFFSET;
    storage.info.framebuffer = framebuffer;
    storage.info.rsdp = find_rsdp(system_table);
    storage.info.modules = &storage.module;
    storage.info.module_count = 1;
    storage.info.command_line = storage.command_line.as_ptr();
    storage.info.command_line_length = command_line.len() as u32;
    storage.info.boot_cpu_apic_id = boot_apic_id();

    for _ in 0..MEMORY_MAP_RETRIES {
        let mut map_size = memory_storage.raw_capacity;
        let mut map_key = 0;
        let mut descriptor_size = 0;
        let mut descriptor_version = 0;
        // SAFETY: raw storage is page-backed for `raw_capacity` bytes.
        let status = unsafe {
            (boot_services.get_memory_map)(
                &mut map_size,
                memory_storage.raw_address as *mut MemoryDescriptor,
                &mut map_key,
                &mut descriptor_size,
                &mut descriptor_version,
            )
        };
        if is_error(status) {
            return Err(LoaderError::MemoryMap(status));
        }
        let region_count = unsafe {
            convert_memory_map(
                &memory_storage,
                map_size,
                descriptor_size,
                descriptor_version,
            )?
        };
        storage.info.memory_map = memory_storage.region_address as *const XenithMemoryRegion;
        storage.info.memory_map_count = region_count as u32;
        if let Some(splash) = splash {
            // SAFETY: direct framebuffer stores do not allocate or mutate the
            // firmware memory map captured immediately above.
            unsafe { splash.progress(66) };
        }
        // SAFETY: no allocations or protocol calls intervene between map capture and exit.
        let status = unsafe { (boot_services.exit_boot_services)(image_handle, map_key) };
        if status == SUCCESS {
            if let Some(splash) = splash {
                // SAFETY: ExitBootServices leaves the current mappings active
                // until `xenith_uefi_jump` installs the kernel page tables.
                unsafe { splash.progress(68) };
            }
            // SAFETY: paging covers the trampoline, stack, handoff, and all kernel segments.
            unsafe { xenith_uefi_jump(page_tables.cr3(), kernel.entry, &storage.info, stack_top) }
        }
        if status != INVALID_PARAMETER {
            return Err(LoaderError::ExitBootServices(status));
        }
    }
    Err(LoaderError::ExitBootServices(INVALID_PARAMETER))
}

unsafe fn allocate_low_pages(
    boot_services: &BootServices,
    pages: usize,
) -> Result<u64, LoaderError> {
    let mut address = u64::from(u32::MAX);
    // SAFETY: the result is checked and retained through kernel entry.
    let status = unsafe {
        (boot_services.allocate_pages)(ALLOCATE_MAX_ADDRESS, LOADER_DATA, pages, &mut address)
    };
    if is_error(status) {
        Err(LoaderError::Allocation(status))
    } else {
        Ok(address)
    }
}

unsafe fn load_kernel(
    boot_services: &BootServices,
    file: LoadedFile,
    page_tables: &mut PageTables,
) -> Result<KernelImage, LoaderError> {
    // SAFETY: file allocation remains live and immutable during ELF parsing.
    let bytes = unsafe { file.bytes() };
    let elf = Elf64::parse(bytes).map_err(|_| LoaderError::Elf)?;
    let (physical_start, physical_end) = elf.physical_span().map_err(|_| LoaderError::Elf)?;
    let allocation_size = physical_end
        .checked_sub(physical_start)
        .ok_or(LoaderError::KernelLayout)?;
    let allocation_pages =
        usize::try_from(allocation_size / PAGE_SIZE).map_err(|_| LoaderError::KernelLayout)?;
    let allocation = unsafe { allocate_low_pages(boot_services, allocation_pages)? };
    // SAFETY: the full physical span is a fresh loader allocation.
    unsafe {
        ptr::write_bytes(allocation as *mut u8, 0, allocation_size as usize);
    }
    for segment in elf.load_segments() {
        let segment = segment.map_err(|_| LoaderError::Elf)?;
        let offset = segment
            .physical_address
            .checked_sub(physical_start)
            .ok_or(LoaderError::KernelLayout)?;
        let destination = allocation
            .checked_add(offset)
            .ok_or(LoaderError::KernelLayout)?;
        let source = segment.file_bytes(bytes).map_err(|_| LoaderError::Elf)?;
        // SAFETY: validated ELF file and memory spans keep both ranges in bounds and disjoint.
        unsafe {
            ptr::copy_nonoverlapping(source.as_ptr(), destination as *mut u8, source.len());
        }
        page_tables.map_kernel(
            segment.virtual_address,
            destination,
            segment.memory_size,
            segment.flags & 2 != 0,
        )?;
    }
    Ok(KernelImage { entry: elf.entry() })
}

unsafe fn allocate_memory_map_storage(
    boot_services: &BootServices,
) -> Result<MemoryMapStorage, LoaderError> {
    let mut map_size = 0;
    let mut map_key = 0;
    let mut descriptor_size = 0;
    let mut descriptor_version = 0;
    // SAFETY: the UEFI sizing call accepts a zero-sized null buffer.
    let status = unsafe {
        (boot_services.get_memory_map)(
            &mut map_size,
            ptr::null_mut(),
            &mut map_key,
            &mut descriptor_size,
            &mut descriptor_version,
        )
    };
    if status != BUFFER_TOO_SMALL || descriptor_size < core::mem::size_of::<MemoryDescriptor>() {
        return Err(LoaderError::MemoryMap(status));
    }
    let raw_capacity = map_size
        .checked_add(descriptor_size * 32)
        .ok_or(LoaderError::MemoryMapCapacity)?;
    let raw_pages = raw_capacity
        .checked_add(4095)
        .ok_or(LoaderError::MemoryMapCapacity)?
        / 4096;
    let raw_address = unsafe { allocate_low_pages(boot_services, raw_pages)? };
    let region_capacity = raw_capacity / descriptor_size + 8;
    let region_bytes = region_capacity
        .checked_mul(core::mem::size_of::<XenithMemoryRegion>())
        .ok_or(LoaderError::MemoryMapCapacity)?;
    let region_pages = region_bytes
        .checked_add(4095)
        .ok_or(LoaderError::MemoryMapCapacity)?
        / 4096;
    let region_address = unsafe { allocate_low_pages(boot_services, region_pages)? };
    Ok(MemoryMapStorage {
        raw_address,
        raw_capacity: raw_pages * 4096,
        region_address,
        region_capacity: region_pages * 4096 / core::mem::size_of::<XenithMemoryRegion>(),
    })
}

unsafe fn convert_memory_map(
    storage: &MemoryMapStorage,
    map_size: usize,
    descriptor_size: usize,
    _descriptor_version: u32,
) -> Result<usize, LoaderError> {
    if descriptor_size < core::mem::size_of::<MemoryDescriptor>()
        || !map_size.is_multiple_of(descriptor_size)
    {
        return Err(LoaderError::MemoryMapCapacity);
    }
    // SAFETY: caller has just populated raw storage and allocated the region array.
    let output = unsafe {
        slice::from_raw_parts_mut(
            storage.region_address as *mut XenithMemoryRegion,
            storage.region_capacity,
        )
    };
    let mut used = 0;
    for offset in (0..map_size).step_by(descriptor_size) {
        // SAFETY: each descriptor prefix is at least `size_of::<MemoryDescriptor>()` bytes.
        let descriptor =
            unsafe { ptr::read_unaligned((storage.raw_address as *const u8).add(offset).cast()) };
        let length = descriptor_length(descriptor).ok_or(LoaderError::MemoryMapCapacity)?;
        append_region(
            output,
            &mut used,
            descriptor.physical_start,
            length,
            boot_memory_kind(descriptor.memory_type),
        )
        .map_err(|_| LoaderError::MemoryMapCapacity)?;
    }
    normalize_memory_regions(&mut output[..used]).map_err(|_| LoaderError::MemoryMapLayout)
}

unsafe fn framebuffer(boot_services: &BootServices) -> XenithFramebuffer {
    let mut interface = ptr::null_mut::<c_void>();
    // SAFETY: LocateProtocol writes a single interface pointer when GOP is available.
    let status =
        unsafe { (boot_services.locate_protocol)(&GOP_GUID, ptr::null_mut(), &mut interface) };
    if is_error(status) || interface.is_null() {
        return XenithFramebuffer::default();
    }
    // SAFETY: successful lookup returned the GOP interface and current mode pointers.
    let gop = unsafe { &*(interface.cast::<GraphicsOutputProtocol>()) };
    let Some(mode) = (unsafe { gop.mode.as_ref() }) else {
        return XenithFramebuffer::default();
    };
    let Some(info) = (unsafe { mode.info.as_ref() }) else {
        return XenithFramebuffer::default();
    };
    let (red_shift, red_size, green_shift, green_size, blue_shift, blue_size) =
        match info.pixel_format {
            0 => (0, 8, 8, 8, 16, 8),
            1 => (16, 8, 8, 8, 0, 8),
            2 => (
                mask_shift(info.pixel_information.red_mask),
                mask_size(info.pixel_information.red_mask),
                mask_shift(info.pixel_information.green_mask),
                mask_size(info.pixel_information.green_mask),
                mask_shift(info.pixel_information.blue_mask),
                mask_size(info.pixel_information.blue_mask),
            ),
            _ => return XenithFramebuffer::default(),
        };
    XenithFramebuffer {
        address: mode.frame_buffer_base,
        pitch: info.pixels_per_scan_line.saturating_mul(4),
        width: info.horizontal_resolution,
        height: info.vertical_resolution,
        bpp: 32,
        red_shift,
        red_size,
        green_shift,
        green_size,
        blue_shift,
        blue_size,
    }
}

fn mask_shift(mask: u32) -> u8 {
    if mask == 0 {
        0
    } else {
        mask.trailing_zeros() as u8
    }
}

fn mask_size(mask: u32) -> u8 {
    mask.count_ones() as u8
}

fn find_rsdp(system_table: &SystemTable) -> u64 {
    if system_table.configuration_table.is_null() || system_table.number_of_table_entries == 0 {
        return 0;
    }
    // SAFETY: firmware supplies exactly `number_of_table_entries` configuration records.
    let tables = unsafe {
        slice::from_raw_parts(
            system_table.configuration_table,
            system_table.number_of_table_entries,
        )
    };
    tables
        .iter()
        .find(|table| table.vendor_guid == ACPI_20_GUID)
        .or_else(|| tables.iter().find(|table| table.vendor_guid == ACPI_GUID))
        .map_or(0, |table: &ConfigurationTable| table.vendor_table as u64)
}

fn boot_apic_id() -> u32 {
    let mut ebx: u32;
    // SAFETY: x86_64 guarantees CPUID leaf 1.
    unsafe {
        asm!(
            "push rbx",
            "cpuid",
            "mov {result:e}, ebx",
            "pop rbx",
            inout("eax") 1_u32 => _,
            lateout("ecx") _,
            lateout("edx") _,
            result = lateout(reg) ebx,
        );
    }
    ebx >> 24
}

fn print_error(system_table: &mut SystemTable, error: LoaderError) {
    let detail = match error {
        LoaderError::Protocol(status)
        | LoaderError::File(status)
        | LoaderError::FileInfo(status)
        | LoaderError::Allocation(status)
        | LoaderError::MemoryMap(status)
        | LoaderError::ExitBootServices(status) => status,
        _ => 0,
    };
    let mut message = [0_u16; 96];
    let prefix = b"Xenith UEFI loader failed (status 0x";
    let mut used = 0;
    for &byte in prefix {
        message[used] = u16::from(byte);
        used += 1;
    }
    for shift in (0..usize::BITS).step_by(4).rev() {
        let digit = ((detail >> shift) & 0xf) as u8;
        message[used] = u16::from(if digit < 10 {
            b'0' + digit
        } else {
            b'a' + digit - 10
        });
        used += 1;
    }
    for &byte in b")\r\n" {
        message[used] = u16::from(byte);
        used += 1;
    }
    message[used] = 0;
    // SAFETY: console output is best-effort while Boot Services is still active.
    unsafe {
        if let Some(console) = system_table.con_out.as_mut() {
            let _ = (console.output_string)(console, message.as_ptr());
        }
    }
}

#[panic_handler]
fn panic(_info: &PanicInfo<'_>) -> ! {
    loop {
        // SAFETY: no unwinding is available in the UEFI binary.
        unsafe { asm!("cli", "hlt", options(nomem, nostack)) };
    }
}
