//! ELF64 validation and loading for native Xenith user processes.
//!
//! The loader accepts statically linked, little-endian x86-64 `ET_EXEC`
//! images.  It validates the complete program-header table before changing
//! an address space, plans every user page (including the fixed user stack),
//! allocates zeroed physical frames, maps them with W^X permissions, and only
//! then copies segment bytes through the HHDM.  A failed load is transactional:
//! every data frame and page-table frame allocated by the attempt is returned.

extern crate alloc;

use alloc::vec::Vec;
use core::{fmt, ptr};

use xenith_types::{Page, PageTableIndex, PhysFrame, VirtAddr, PAGE_SIZE};

use crate::mm::physical;
use crate::mm::r#virtual::address_space::{
    self, AddressSpace, MapError, PageTable, PageTableEntry, PageTableFlags, USER_MAX,
};

const ELF_HEADER_SIZE: usize = 64;
const PROGRAM_HEADER_SIZE: usize = 56;
const ELFCLASS64: u8 = 2;
const ELFDATA2LSB: u8 = 1;
const EV_CURRENT: u8 = 1;
const ET_EXEC: u16 = 2;
const EM_X86_64: u16 = 62;

const PT_LOAD: u32 = 1;
const PT_DYNAMIC: u32 = 2;
const PT_INTERP: u32 = 3;

const PF_X: u32 = 1;
const PF_W: u32 = 2;
const PF_R: u32 = 4;
const PF_KNOWN: u32 = PF_X | PF_W | PF_R;

/// Keep the null page unmapped so null dereferences reliably fault.
pub const USER_IMAGE_MIN: u64 = PAGE_SIZE;

/// Exclusive top of the initial user stack.
pub const USER_STACK_TOP: u64 = 0x0000_7FFF_FFF0_0000;

/// Initial stack capacity.  One guard page immediately below it is left
/// unmapped.
pub const USER_STACK_SIZE: u64 = 1024 * 1024;

/// Fixed read/execute page containing the nine-byte signal-return trampoline.
pub const USER_SIGNAL_TRAMPOLINE: u64 = USER_STACK_TOP;

/// Maximum number of program headers accepted from an untrusted image.
const MAX_PROGRAM_HEADERS: usize = 256;

/// A validated ELF program header.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ProgramHeader {
    pub kind: u32,
    pub flags: u32,
    pub offset: u64,
    pub virtual_address: u64,
    pub file_size: u64,
    pub memory_size: u64,
    pub alignment: u64,
}

impl ProgramHeader {
    #[inline]
    #[must_use]
    pub const fn is_load(self) -> bool {
        self.kind == PT_LOAD
    }

    #[inline]
    #[must_use]
    pub const fn writable(self) -> bool {
        self.flags & PF_W != 0
    }

    #[inline]
    #[must_use]
    pub const fn executable(self) -> bool {
        self.flags & PF_X != 0
    }

    fn memory_end(self) -> Option<u64> {
        self.virtual_address.checked_add(self.memory_size)
    }
}

/// A completely validated view of an ELF image.
pub struct ElfFile<'a> {
    image: &'a [u8],
    entry: VirtAddr,
    program_offset: usize,
    program_count: usize,
}

impl<'a> ElfFile<'a> {
    /// Validate the ELF identification, native ABI fields, table geometry,
    /// every program header, and the executable entry point.
    pub fn parse(image: &'a [u8]) -> Result<Self, ElfError> {
        if image.len() < ELF_HEADER_SIZE {
            return Err(ElfError::TruncatedHeader);
        }
        if image.get(0..4) != Some(b"\x7FELF") {
            return Err(ElfError::BadMagic);
        }
        if image[4] != ELFCLASS64 {
            return Err(ElfError::UnsupportedClass(image[4]));
        }
        if image[5] != ELFDATA2LSB {
            return Err(ElfError::UnsupportedEndian(image[5]));
        }
        if image[6] != EV_CURRENT {
            return Err(ElfError::UnsupportedVersion(u32::from(image[6])));
        }
        if image[8] != 0 {
            return Err(ElfError::UnsupportedAbiVersion(image[8]));
        }

        let file_type = read_u16(image, 16)?;
        if file_type != ET_EXEC {
            return Err(ElfError::UnsupportedType(file_type));
        }
        let machine = read_u16(image, 18)?;
        if machine != EM_X86_64 {
            return Err(ElfError::UnsupportedMachine(machine));
        }
        let version = read_u32(image, 20)?;
        if version != u32::from(EV_CURRENT) {
            return Err(ElfError::UnsupportedVersion(version));
        }

        let raw_entry = read_u64(image, 24)?;
        let entry = VirtAddr::new(raw_entry).ok_or(ElfError::NonCanonicalAddress(raw_entry))?;
        if !entry.is_user() || !(USER_IMAGE_MIN..=USER_MAX).contains(&raw_entry) {
            return Err(ElfError::AddressOutOfRange(raw_entry));
        }

        let program_offset = usize_from_u64(read_u64(image, 32)?)?;
        let header_size = usize::from(read_u16(image, 52)?);
        if header_size != ELF_HEADER_SIZE {
            return Err(ElfError::BadHeaderSize(header_size));
        }
        let program_entry_size = usize::from(read_u16(image, 54)?);
        if program_entry_size != PROGRAM_HEADER_SIZE {
            return Err(ElfError::BadProgramHeaderSize(program_entry_size));
        }
        let program_count = usize::from(read_u16(image, 56)?);
        if program_count == 0 || program_count > MAX_PROGRAM_HEADERS {
            return Err(ElfError::BadProgramHeaderCount(program_count));
        }
        let table_size = program_count
            .checked_mul(program_entry_size)
            .ok_or(ElfError::IntegerOverflow)?;
        let table_end = program_offset
            .checked_add(table_size)
            .ok_or(ElfError::IntegerOverflow)?;
        if program_offset < ELF_HEADER_SIZE || table_end > image.len() {
            return Err(ElfError::TruncatedProgramHeaders);
        }

        let file = Self {
            image,
            entry,
            program_offset,
            program_count,
        };

        let mut load_count = 0usize;
        let mut entry_is_executable = false;
        for index in 0..program_count {
            let header = file.program_header(index)?;
            match header.kind {
                PT_LOAD => {
                    load_count += 1;
                    validate_load_segment(image, header)?;
                    if header.executable()
                        && raw_entry >= header.virtual_address
                        && raw_entry < header.memory_end().ok_or(ElfError::IntegerOverflow)?
                    {
                        entry_is_executable = true;
                    }
                },
                PT_INTERP | PT_DYNAMIC => return Err(ElfError::DynamicImage),
                _ => {},
            }
        }
        if load_count == 0 {
            return Err(ElfError::NoLoadSegments);
        }
        if !entry_is_executable {
            return Err(ElfError::EntryNotExecutable(raw_entry));
        }
        Ok(file)
    }

    #[inline]
    #[must_use]
    pub const fn entry(&self) -> VirtAddr {
        self.entry
    }

    #[inline]
    #[must_use]
    pub const fn program_count(&self) -> usize {
        self.program_count
    }

    pub fn program_header(&self, index: usize) -> Result<ProgramHeader, ElfError> {
        if index >= self.program_count {
            return Err(ElfError::BadProgramHeaderIndex(index));
        }
        let offset = self
            .program_offset
            .checked_add(
                index
                    .checked_mul(PROGRAM_HEADER_SIZE)
                    .ok_or(ElfError::IntegerOverflow)?,
            )
            .ok_or(ElfError::IntegerOverflow)?;
        Ok(ProgramHeader {
            kind: read_u32(self.image, offset)?,
            flags: read_u32(self.image, offset + 4)?,
            offset: read_u64(self.image, offset + 8)?,
            virtual_address: read_u64(self.image, offset + 16)?,
            file_size: read_u64(self.image, offset + 32)?,
            memory_size: read_u64(self.image, offset + 40)?,
            alignment: read_u64(self.image, offset + 48)?,
        })
    }
}

/// One user page allocated by a successful image load.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct UserPage {
    pub page: Page,
    pub frame: PhysFrame,
}

/// Metadata needed by the process layer to launch and later reclaim an image.
pub struct LoadedImage {
    pub entry: VirtAddr,
    pub stack_top: VirtAddr,
    /// First page-aligned byte after every loadable ELF segment.
    initial_break: u64,
    pages: Vec<UserPage>,
}

impl LoadedImage {
    #[inline]
    #[must_use]
    pub fn pages(&self) -> &[UserPage] {
        &self.pages
    }

    /// Initial program break derived from the image rather than a global
    /// address. The value is page aligned and does not include stack or
    /// signal-trampoline mappings.
    #[inline]
    #[must_use]
    pub const fn initial_break(&self) -> u64 {
        self.initial_break
    }

    pub(crate) fn into_pages(self) -> Vec<UserPage> {
        self.pages
    }
}

#[derive(Clone, Copy)]
struct PlannedPage {
    page: Page,
    writable: bool,
    executable: bool,
}

impl PlannedPage {
    fn flags(self) -> PageTableFlags {
        let mut flags = PageTableFlags::USER;
        if self.writable {
            flags |= PageTableFlags::WRITABLE;
        }
        if !self.executable {
            flags |= PageTableFlags::NO_EXECUTE;
        }
        flags
    }
}

/// Load an ELF image and its initial user stack into `space`.
///
/// `space` should be a fresh address space.  The loader copies the currently
/// active kernel-half PML4 entries into it before installing user mappings so
/// the CR3 switch performed by `jump_to_user` remains executable.
pub fn load_image(image: &[u8], space: &mut AddressSpace) -> Result<LoadedImage, ElfError> {
    let elf = ElfFile::parse(image)?;
    let mut plan = Vec::new();
    plan.try_reserve(USER_STACK_SIZE as usize / PAGE_SIZE as usize + 32)
        .map_err(|_| ElfError::OutOfMemory)?;

    let mut image_end = USER_IMAGE_MIN;
    for index in 0..elf.program_count() {
        let header = elf.program_header(index)?;
        if !header.is_load() || header.memory_size == 0 {
            continue;
        }
        image_end = image_end.max(header.memory_end().ok_or(ElfError::IntegerOverflow)?);
        plan_segment(&mut plan, header)?;
    }
    let initial_break = image_end
        .checked_add(PAGE_SIZE - 1)
        .ok_or(ElfError::IntegerOverflow)?
        & !(PAGE_SIZE - 1);
    plan_stack(&mut plan)?;
    add_page(
        &mut plan,
        Page::containing_addr(
            VirtAddr::new(USER_SIGNAL_TRAMPOLINE)
                .ok_or(ElfError::AddressOutOfRange(USER_SIGNAL_TRAMPOLINE))?,
        ),
        false,
        true,
    )?;

    // Validation and planning are complete.  From here onward every failure
    // rolls back all mappings made by this invocation.
    let mut mapped = Vec::new();
    mapped
        .try_reserve_exact(plan.len())
        .map_err(|_| ElfError::OutOfMemory)?;
    copy_kernel_half(space)?;

    for planned in plan.iter().copied() {
        let Some(frame) = physical::allocate_frame() else {
            rollback(space, &mapped);
            return Err(ElfError::OutOfMemory);
        };
        zero_frame(frame);
        if let Err(error) = space.map_user(planned.page, frame, planned.flags()) {
            let _ = physical::deallocate(frame);
            rollback(space, &mapped);
            return Err(ElfError::Map(error));
        }
        mapped.push(UserPage {
            page: planned.page,
            frame,
        });
    }

    for index in 0..elf.program_count() {
        let header = elf.program_header(index)?;
        if !header.is_load() || header.file_size == 0 {
            continue;
        }
        let start = usize_from_u64(header.offset)?;
        let len = usize_from_u64(header.file_size)?;
        let source = image
            .get(start..start + len)
            .ok_or(ElfError::TruncatedSegment)?;
        if let Err(error) = write_user_initializing(space, &mapped, header.virtual_address, source)
        {
            rollback(space, &mapped);
            return Err(error);
        }
    }

    if let Err(error) = write_user_initializing(
        space,
        &mapped,
        USER_SIGNAL_TRAMPOLINE,
        &super::signal::SIGNAL_TRAMPOLINE,
    ) {
        rollback(space, &mapped);
        return Err(error);
    }

    Ok(LoadedImage {
        entry: elf.entry(),
        stack_top: VirtAddr::new(USER_STACK_TOP)
            .ok_or(ElfError::AddressOutOfRange(USER_STACK_TOP))?,
        initial_break,
        pages: mapped,
    })
}

/// Compatibility entry point required by the userspace work package.
/// Callers that own a process should prefer [`load_image`] so they retain the
/// page list needed for deterministic teardown.
pub fn load(image: &[u8], space: &mut AddressSpace) -> Result<VirtAddr, ElfError> {
    load_image(image, space).map(|loaded| loaded.entry)
}

/// Copy bytes into writable user mappings without activating `space`.
/// Physical frames are reached through the HHDM, so this is safe while a
/// different process's CR3 is active.
pub fn write_user(space: &AddressSpace, address: u64, bytes: &[u8]) -> Result<(), ElfError> {
    write_user_with_access(space, address, bytes, WriteAccess::Runtime)
}

/// Copy segment bytes into pages freshly allocated by this loader invocation.
///
/// ELF leaf permissions are installed in their final W^X form before any
/// file bytes are copied.  Consequently, executable and read-only segments
/// are intentionally not writable through their user mapping.  The kernel
/// may still initialise their owned physical frames through the writable HHDM
/// alias, provided every translated `(page, frame)` pair is present in
/// `owned`.
fn write_user_initializing(
    space: &AddressSpace,
    owned: &[UserPage],
    address: u64,
    bytes: &[u8],
) -> Result<(), ElfError> {
    write_user_with_access(
        space,
        address,
        bytes,
        WriteAccess::LoaderInitialization(owned),
    )
}

#[derive(Clone, Copy)]
enum WriteAccess<'a> {
    Runtime,
    LoaderInitialization(&'a [UserPage]),
}

fn validate_write_mapping(
    access: WriteAccess<'_>,
    page: Page,
    frame: PhysFrame,
    flags: PageTableFlags,
    address: u64,
) -> Result<(), ElfError> {
    if !flags.contains(PageTableFlags::USER) {
        return Err(ElfError::ReadOnlyWrite(address));
    }
    match access {
        WriteAccess::Runtime if !flags.contains(PageTableFlags::WRITABLE) => {
            Err(ElfError::ReadOnlyWrite(address))
        },
        WriteAccess::LoaderInitialization(owned)
            if !owned
                .iter()
                .any(|mapping| mapping.page == page && mapping.frame == frame) =>
        {
            Err(ElfError::UnownedInitializationWrite(address))
        },
        WriteAccess::Runtime | WriteAccess::LoaderInitialization(_) => Ok(()),
    }
}

fn write_user_with_access(
    space: &AddressSpace,
    address: u64,
    bytes: &[u8],
    access: WriteAccess<'_>,
) -> Result<(), ElfError> {
    if bytes.is_empty() {
        return Ok(());
    }
    let end = address
        .checked_add(bytes.len() as u64)
        .ok_or(ElfError::IntegerOverflow)?;
    if address < USER_IMAGE_MIN || end == 0 || end - 1 > USER_MAX {
        return Err(ElfError::AddressOutOfRange(address));
    }

    let mut copied = 0usize;
    while copied < bytes.len() {
        let virtual_address = address
            .checked_add(copied as u64)
            .ok_or(ElfError::IntegerOverflow)?;
        let virt =
            VirtAddr::new(virtual_address).ok_or(ElfError::NonCanonicalAddress(virtual_address))?;
        let page = Page::containing_addr(virt);
        let (frame, flags) = space
            .translate(page)
            .ok_or(ElfError::UnmappedWrite(virtual_address))?;
        validate_write_mapping(access, page, frame, flags, virtual_address)?;
        let page_offset = (virtual_address & (PAGE_SIZE - 1)) as usize;
        let chunk = (PAGE_SIZE as usize - page_offset).min(bytes.len() - copied);
        let destination =
            address_space::phys_to_virt(frame.start_address()).as_u64() + page_offset as u64;
        // SAFETY: `translate` proved the destination is a user mapping.
        // `validate_write_mapping` additionally proved either that the leaf
        // is writable at runtime or that this exact page/frame pair is owned
        // by the in-progress loader.  The HHDM maps the complete physical
        // frame writable in ring 0, and `chunk` stays within that frame.
        unsafe {
            ptr::copy_nonoverlapping(bytes.as_ptr().add(copied), destination as *mut u8, chunk);
        }
        copied += chunk;
    }
    Ok(())
}

/// Reclaim an inactive user address space and all data frames recorded by a
/// successful [`load_image`].
///
/// # Safety
/// `space` must not be active on any CPU and no thread may still access it.
pub unsafe fn destroy(space: AddressSpace, pages: &[UserPage]) {
    for mapping in pages {
        if let Ok(frame) = space.unmap(mapping.page) {
            if address_space::release_user_frame(frame) {
                if let Err(error) = physical::deallocate(frame) {
                    ::log::error!("user.elf: failed to free {:?}: {}", frame, error);
                }
            }
        }
    }
    clear_kernel_half(&space);
    // SAFETY: guaranteed by this function's caller.  Clearing the shared
    // upper-half entries prevents AddressSpace::destroy from freeing kernel
    // page tables that this process merely referenced.
    unsafe { space.destroy() };
}

fn validate_load_segment(image: &[u8], header: ProgramHeader) -> Result<(), ElfError> {
    if header.flags & !PF_KNOWN != 0 {
        return Err(ElfError::BadSegmentFlags(header.flags));
    }
    if header.writable() && header.executable() {
        return Err(ElfError::WritableExecutableSegment);
    }
    if header.file_size > header.memory_size {
        return Err(ElfError::FileLargerThanMemory);
    }
    let file_end = header
        .offset
        .checked_add(header.file_size)
        .ok_or(ElfError::IntegerOverflow)?;
    if file_end > image.len() as u64 {
        return Err(ElfError::TruncatedSegment);
    }
    if header.alignment > 1 {
        if !header.alignment.is_power_of_two() {
            return Err(ElfError::BadAlignment(header.alignment));
        }
        if header.virtual_address & (header.alignment - 1) != header.offset & (header.alignment - 1)
        {
            return Err(ElfError::MisalignedSegment);
        }
    }
    if header.memory_size == 0 {
        return Ok(());
    }
    let end = header.memory_end().ok_or(ElfError::IntegerOverflow)?;
    if header.virtual_address < USER_IMAGE_MIN || end == 0 || end - 1 > USER_MAX {
        return Err(ElfError::AddressOutOfRange(header.virtual_address));
    }
    if VirtAddr::new(header.virtual_address).is_none() || VirtAddr::new(end - 1).is_none() {
        return Err(ElfError::NonCanonicalAddress(header.virtual_address));
    }
    let stack_guard = USER_STACK_TOP - USER_STACK_SIZE - PAGE_SIZE;
    let reserved_end = USER_SIGNAL_TRAMPOLINE + PAGE_SIZE;
    if header.virtual_address < reserved_end && end > stack_guard {
        return Err(ElfError::StackCollision);
    }
    Ok(())
}

fn plan_segment(plan: &mut Vec<PlannedPage>, header: ProgramHeader) -> Result<(), ElfError> {
    let end = header.memory_end().ok_or(ElfError::IntegerOverflow)?;
    let mut address = header.virtual_address & !(PAGE_SIZE - 1);
    let end_page = (end - 1) & !(PAGE_SIZE - 1);
    loop {
        add_page(
            plan,
            Page::containing_addr(
                VirtAddr::new(address).ok_or(ElfError::NonCanonicalAddress(address))?,
            ),
            header.writable(),
            header.executable(),
        )?;
        if address == end_page {
            break;
        }
        address = address
            .checked_add(PAGE_SIZE)
            .ok_or(ElfError::IntegerOverflow)?;
    }
    Ok(())
}

fn plan_stack(plan: &mut Vec<PlannedPage>) -> Result<(), ElfError> {
    let bottom = USER_STACK_TOP - USER_STACK_SIZE;
    let mut address = bottom;
    while address < USER_STACK_TOP {
        add_page(
            plan,
            Page::containing_addr(
                VirtAddr::new(address).ok_or(ElfError::NonCanonicalAddress(address))?,
            ),
            true,
            false,
        )?;
        address += PAGE_SIZE;
    }
    Ok(())
}

fn add_page(
    plan: &mut Vec<PlannedPage>,
    page: Page,
    writable: bool,
    executable: bool,
) -> Result<(), ElfError> {
    if let Some(existing) = plan.iter_mut().find(|item| item.page == page) {
        existing.writable |= writable;
        existing.executable |= executable;
        if existing.writable && existing.executable {
            return Err(ElfError::WritableExecutablePage(
                page.start_address().as_u64(),
            ));
        }
        return Ok(());
    }
    plan.try_reserve(1).map_err(|_| ElfError::OutOfMemory)?;
    plan.push(PlannedPage {
        page,
        writable,
        executable,
    });
    Ok(())
}

fn copy_kernel_half(space: &AddressSpace) -> Result<(), ElfError> {
    // SAFETY: this runs in ring 0 and merely adopts the currently valid CR3.
    let current = unsafe { AddressSpace::adopt_current() };
    if current.p4_frame() == space.p4_frame() {
        return Ok(());
    }
    let source_address = address_space::phys_to_virt(current.p4_frame().start_address()).as_u64();
    let destination_address =
        address_space::phys_to_virt(space.p4_frame().start_address()).as_u64();
    // SAFETY: both addresses are HHDM aliases of live PML4 frames.  The
    // destination is fresh and uniquely owned by the process under creation.
    let source = unsafe { &*(source_address as *const PageTable) };
    let destination = unsafe { &mut *(destination_address as *mut PageTable) };
    for raw_index in 256u16..512 {
        let index = PageTableIndex::new(raw_index).ok_or(ElfError::IntegerOverflow)?;
        *destination.entry_mut(index) = source.entry(index);
    }
    Ok(())
}

fn clear_kernel_half(space: &AddressSpace) {
    let address = address_space::phys_to_virt(space.p4_frame().start_address()).as_u64();
    // SAFETY: caller owns this inactive PML4 exclusively during teardown.
    let table = unsafe { &mut *(address as *mut PageTable) };
    for raw_index in 256u16..512 {
        if let Some(index) = PageTableIndex::new(raw_index) {
            *table.entry_mut(index) = PageTableEntry::empty();
        }
    }
}

fn rollback(space: &AddressSpace, mapped: &[UserPage]) {
    for mapping in mapped.iter().rev() {
        if let Ok(frame) = space.unmap(mapping.page) {
            let _ = physical::deallocate(frame);
        }
    }
    clear_kernel_half(space);
}

fn zero_frame(frame: PhysFrame) {
    let address = address_space::phys_to_virt(frame.start_address()).as_u64();
    // SAFETY: `frame` was freshly allocated and is exclusively owned by the
    // loader; its HHDM alias covers exactly one writable 4 KiB frame.
    unsafe { ptr::write_bytes(address as *mut u8, 0, PAGE_SIZE as usize) };
}

fn read_u16(bytes: &[u8], offset: usize) -> Result<u16, ElfError> {
    let raw = bytes
        .get(offset..offset.checked_add(2).ok_or(ElfError::IntegerOverflow)?)
        .ok_or(ElfError::TruncatedHeader)?;
    Ok(u16::from_le_bytes([raw[0], raw[1]]))
}

fn read_u32(bytes: &[u8], offset: usize) -> Result<u32, ElfError> {
    let raw = bytes
        .get(offset..offset.checked_add(4).ok_or(ElfError::IntegerOverflow)?)
        .ok_or(ElfError::TruncatedHeader)?;
    Ok(u32::from_le_bytes([raw[0], raw[1], raw[2], raw[3]]))
}

fn read_u64(bytes: &[u8], offset: usize) -> Result<u64, ElfError> {
    let raw = bytes
        .get(offset..offset.checked_add(8).ok_or(ElfError::IntegerOverflow)?)
        .ok_or(ElfError::TruncatedHeader)?;
    Ok(u64::from_le_bytes([
        raw[0], raw[1], raw[2], raw[3], raw[4], raw[5], raw[6], raw[7],
    ]))
}

fn usize_from_u64(value: u64) -> Result<usize, ElfError> {
    usize::try_from(value).map_err(|_| ElfError::IntegerOverflow)
}

/// ELF validation or mapping failure.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ElfError {
    TruncatedHeader,
    BadMagic,
    UnsupportedClass(u8),
    UnsupportedEndian(u8),
    UnsupportedVersion(u32),
    UnsupportedAbiVersion(u8),
    UnsupportedType(u16),
    UnsupportedMachine(u16),
    BadHeaderSize(usize),
    BadProgramHeaderSize(usize),
    BadProgramHeaderCount(usize),
    BadProgramHeaderIndex(usize),
    TruncatedProgramHeaders,
    NoLoadSegments,
    DynamicImage,
    BadSegmentFlags(u32),
    WritableExecutableSegment,
    WritableExecutablePage(u64),
    FileLargerThanMemory,
    TruncatedSegment,
    BadAlignment(u64),
    MisalignedSegment,
    NonCanonicalAddress(u64),
    AddressOutOfRange(u64),
    StackCollision,
    EntryNotExecutable(u64),
    IntegerOverflow,
    OutOfMemory,
    Map(MapError),
    UnmappedWrite(u64),
    ReadOnlyWrite(u64),
    UnownedInitializationWrite(u64),
}

impl fmt::Display for ElfError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::TruncatedHeader => f.write_str("truncated ELF header"),
            Self::BadMagic => f.write_str("bad ELF magic"),
            Self::UnsupportedClass(value) => write!(f, "unsupported ELF class {value}"),
            Self::UnsupportedEndian(value) => write!(f, "unsupported ELF byte order {value}"),
            Self::UnsupportedVersion(value) => write!(f, "unsupported ELF version {value}"),
            Self::UnsupportedAbiVersion(value) => write!(f, "unsupported ABI version {value}"),
            Self::UnsupportedType(value) => write!(f, "unsupported ELF type {value}"),
            Self::UnsupportedMachine(value) => write!(f, "unsupported ELF machine {value}"),
            Self::BadHeaderSize(value) => write!(f, "invalid ELF header size {value}"),
            Self::BadProgramHeaderSize(value) => write!(f, "invalid program-header size {value}"),
            Self::BadProgramHeaderCount(value) => write!(f, "invalid program-header count {value}"),
            Self::BadProgramHeaderIndex(value) => {
                write!(f, "program-header index {value} out of range")
            },
            Self::TruncatedProgramHeaders => f.write_str("truncated program-header table"),
            Self::NoLoadSegments => f.write_str("ELF has no loadable segments"),
            Self::DynamicImage => f.write_str("dynamically linked ELF is unsupported"),
            Self::BadSegmentFlags(value) => write!(f, "invalid segment flags {value:#x}"),
            Self::WritableExecutableSegment => f.write_str("writable executable segment rejected"),
            Self::WritableExecutablePage(address) => {
                write!(f, "page {address:#x} would be writable and executable")
            },
            Self::FileLargerThanMemory => f.write_str("segment file size exceeds memory size"),
            Self::TruncatedSegment => f.write_str("segment extends past end of image"),
            Self::BadAlignment(value) => write!(f, "invalid segment alignment {value}"),
            Self::MisalignedSegment => f.write_str("segment file and virtual offsets disagree"),
            Self::NonCanonicalAddress(address) => write!(f, "non-canonical address {address:#x}"),
            Self::AddressOutOfRange(address) => write!(f, "user address {address:#x} out of range"),
            Self::StackCollision => f.write_str("load segment collides with the user stack"),
            Self::EntryNotExecutable(address) => {
                write!(f, "entry {address:#x} is not in an executable segment")
            },
            Self::IntegerOverflow => f.write_str("ELF integer overflow"),
            Self::OutOfMemory => f.write_str("out of memory while loading ELF"),
            Self::Map(error) => write!(f, "page mapping failed: {error:?}"),
            Self::UnmappedWrite(address) => {
                write!(f, "write to unmapped user address {address:#x}")
            },
            Self::ReadOnlyWrite(address) => {
                write!(f, "write to read-only user address {address:#x}")
            },
            Self::UnownedInitializationWrite(address) => {
                write!(f, "loader write to unowned user address {address:#x}")
            },
        }
    }
}

#[cfg(test)]
mod tests {
    use alloc::vec;

    use super::*;

    fn minimal_elf(flags: u32) -> Vec<u8> {
        let mut image = vec![0u8; 0x1100];
        image[0..4].copy_from_slice(b"\x7FELF");
        image[4] = ELFCLASS64;
        image[5] = ELFDATA2LSB;
        image[6] = EV_CURRENT;
        image[16..18].copy_from_slice(&ET_EXEC.to_le_bytes());
        image[18..20].copy_from_slice(&EM_X86_64.to_le_bytes());
        image[20..24].copy_from_slice(&1u32.to_le_bytes());
        image[24..32].copy_from_slice(&0x401000u64.to_le_bytes());
        image[32..40].copy_from_slice(&(ELF_HEADER_SIZE as u64).to_le_bytes());
        image[52..54].copy_from_slice(&(ELF_HEADER_SIZE as u16).to_le_bytes());
        image[54..56].copy_from_slice(&(PROGRAM_HEADER_SIZE as u16).to_le_bytes());
        image[56..58].copy_from_slice(&1u16.to_le_bytes());
        let ph = ELF_HEADER_SIZE;
        image[ph..ph + 4].copy_from_slice(&PT_LOAD.to_le_bytes());
        image[ph + 4..ph + 8].copy_from_slice(&flags.to_le_bytes());
        image[ph + 8..ph + 16].copy_from_slice(&0x1000u64.to_le_bytes());
        image[ph + 16..ph + 24].copy_from_slice(&0x401000u64.to_le_bytes());
        image[ph + 32..ph + 40].copy_from_slice(&0x100u64.to_le_bytes());
        image[ph + 40..ph + 48].copy_from_slice(&0x200u64.to_le_bytes());
        image[ph + 48..ph + 56].copy_from_slice(&0x1000u64.to_le_bytes());
        image
    }

    #[test]
    fn parses_native_static_image() {
        let image = minimal_elf(PF_R | PF_X);
        let elf = ElfFile::parse(&image).unwrap();
        assert_eq!(elf.entry().as_u64(), 0x401000);
        assert_eq!(elf.program_count(), 1);
        assert!(elf.program_header(0).unwrap().executable());
    }

    #[test]
    fn rejects_writable_executable_segment() {
        let image = minimal_elf(PF_R | PF_W | PF_X);
        assert_eq!(
            ElfFile::parse(&image).err(),
            Some(ElfError::WritableExecutableSegment)
        );
    }

    #[test]
    fn rejects_entry_outside_executable_segment() {
        let mut image = minimal_elf(PF_R | PF_X);
        image[24..32].copy_from_slice(&0x500000u64.to_le_bytes());
        assert_eq!(
            ElfFile::parse(&image).err(),
            Some(ElfError::EntryNotExecutable(0x500000))
        );
    }

    #[test]
    fn rejects_truncated_segment() {
        let mut image = minimal_elf(PF_R | PF_X);
        image.truncate(0x1080);
        assert_eq!(
            ElfFile::parse(&image).err(),
            Some(ElfError::TruncatedSegment)
        );
    }

    #[test]
    fn loader_initialization_accepts_owned_read_only_page() {
        let page = Page::containing_addr(VirtAddr::new(0x401000).unwrap());
        let frame = PhysFrame::containing_addr(xenith_types::PhysAddr::new_truncate(0x2000));
        let owned = [UserPage { page, frame }];
        let flags = PageTableFlags::USER;

        assert_eq!(
            validate_write_mapping(
                WriteAccess::LoaderInitialization(&owned),
                page,
                frame,
                flags,
                0x401000,
            ),
            Ok(())
        );
        assert!(!flags.contains(PageTableFlags::WRITABLE));
    }

    #[test]
    fn runtime_write_still_rejects_read_only_page() {
        let page = Page::containing_addr(VirtAddr::new(0x401000).unwrap());
        let frame = PhysFrame::containing_addr(xenith_types::PhysAddr::new_truncate(0x2000));

        assert_eq!(
            validate_write_mapping(
                WriteAccess::Runtime,
                page,
                frame,
                PageTableFlags::USER,
                0x401000,
            ),
            Err(ElfError::ReadOnlyWrite(0x401000))
        );
    }

    #[test]
    fn loader_initialization_rejects_unowned_page() {
        let page = Page::containing_addr(VirtAddr::new(0x401000).unwrap());
        let frame = PhysFrame::containing_addr(xenith_types::PhysAddr::new_truncate(0x2000));

        assert_eq!(
            validate_write_mapping(
                WriteAccess::LoaderInitialization(&[]),
                page,
                frame,
                PageTableFlags::USER,
                0x401000,
            ),
            Err(ElfError::UnownedInitializationWrite(0x401000))
        );
    }

    #[test]
    fn signal_trampoline_page_is_user_read_execute_only() {
        let mut plan = Vec::new();
        add_page(
            &mut plan,
            Page::containing_addr(VirtAddr::new(USER_SIGNAL_TRAMPOLINE).unwrap()),
            false,
            true,
        )
        .unwrap();
        let flags = plan[0].flags();
        assert!(flags.contains(PageTableFlags::USER));
        assert!(!flags.contains(PageTableFlags::WRITABLE));
        assert!(!flags.contains(PageTableFlags::NO_EXECUTE));
    }

    #[test]
    fn rejects_elf_segment_overlapping_signal_trampoline() {
        let mut image = minimal_elf(PF_R | PF_X);
        image[24..32].copy_from_slice(&USER_SIGNAL_TRAMPOLINE.to_le_bytes());
        let ph = ELF_HEADER_SIZE;
        image[ph + 16..ph + 24].copy_from_slice(&USER_SIGNAL_TRAMPOLINE.to_le_bytes());
        assert_eq!(ElfFile::parse(&image).err(), Some(ElfError::StackCollision));
    }
}
