#![no_std]
#![no_main]

use core::arch::{asm, global_asm};
use core::panic::PanicInfo;
use core::ptr::{addr_of, addr_of_mut};
use core::slice;

use xenith_boot_common::{
    append_region_with_reservations, BootMemoryKind, DiskEntry, DiskEntryKind, DiskManifest, Elf64,
    Reservation, XenithBootInfo, XenithFramebuffer, XenithMemoryRegion, XenithModule, HHDM_OFFSET,
    KERNEL_VIRTUAL_BASE,
};
use xenith_stage2::{
    checked_buffer, INITRD_CAPACITY, INITRD_LOAD_ADDRESS, KERNEL_STAGING_ADDRESS,
    KERNEL_STAGING_CAPACITY,
};

global_asm!(include_str!("entry.S"));

const E820_BUFFER: usize = 0x50000;
const MAX_E820_ENTRIES: usize = 128;
const MAX_MEMORY_REGIONS: usize = 256;
const KERNEL_PHYSICAL_LIMIT: u64 = KERNEL_STAGING_ADDRESS;
const COMMAND_LINE: &[u8] = b"xenith.boot=bios";
const INITRD_PATH: &[u8] = b"/initrd.cpio";

const EMPTY_REGION: XenithMemoryRegion = XenithMemoryRegion {
    base: 0,
    length: 0,
    kind: BootMemoryKind::Reserved,
    reserved: 0,
};

static mut MANIFEST_SECTOR: [u8; 512] = [0; 512];
static mut MEMORY_REGIONS: [XenithMemoryRegion; MAX_MEMORY_REGIONS] =
    [EMPTY_REGION; MAX_MEMORY_REGIONS];
static mut MODULE: XenithModule = XenithModule {
    address: 0,
    length: 0,
    path: core::ptr::null(),
    path_length: 0,
    reserved: 0,
};
static mut BOOT_INFO: XenithBootInfo = XenithBootInfo::empty();

unsafe extern "C" {
    static bios_framebuffer: XenithFramebuffer;
    static bios_disk_mode: u8;
    static bios_preload_error: u8;
    static chs_lba: u32;
    static chs_status: u8;
    static chs_sectors_per_track: u8;
    static chs_head_count: u16;
}

#[repr(C, packed)]
#[derive(Clone, Copy)]
struct E820Entry {
    base: u64,
    length: u64,
    kind: u32,
    attributes: u32,
}

#[no_mangle]
pub extern "C" fn stage2_main(boot_drive: u64, e820_count: u32, bios_preloaded: u32) -> ! {
    serial_init();
    serial_write("xenith-stage2: long mode\r\n");
    if boot_drive < 0x80 {
        fatal("unsupported BIOS disk");
    }
    if bios_preloaded == 0 && boot_drive != 0x80 {
        fatal("ATA fallback requires drive 80h");
    }
    if bios_preloaded == 0 {
        // SAFETY: these single-byte assembly diagnostics are finalized before long mode.
        let mode = unsafe { core::ptr::read_volatile(addr_of!(bios_disk_mode)) };
        // SAFETY: same immutable loader diagnostic contract as `bios_disk_mode`.
        let error = unsafe { core::ptr::read_volatile(addr_of!(bios_preload_error)) };
        serial_write(match (mode, error) {
            (0, _) | (_, 2) => "xenith-stage2: firmware disk interface unavailable\r\n",
            (_, 3) => "xenith-stage2: CHS LBA exceeds 32 bits\r\n",
            (_, 4) => "xenith-stage2: CHS cylinder exceeds firmware geometry\r\n",
            (_, 5) => "xenith-stage2: CHS disk read failed\r\n",
            _ => "xenith-stage2: firmware preload failed\r\n",
        });
        if error == 5 {
            // SAFETY: CHS failure details are immutable once assembly enters long mode.
            let lba = unsafe { core::ptr::read_volatile(addr_of!(chs_lba)) };
            // SAFETY: same immutable diagnostic contract as `chs_lba`.
            let status = unsafe { core::ptr::read_volatile(addr_of!(chs_status)) };
            // SAFETY: geometry is captured once by the real-mode disk probe.
            let sectors = unsafe { core::ptr::read_volatile(addr_of!(chs_sectors_per_track)) };
            // SAFETY: same immutable geometry contract as `chs_sectors_per_track`.
            let heads = unsafe { core::ptr::read_volatile(addr_of!(chs_head_count)) };
            serial_write("xenith-stage2: CHS failure LBA=0x");
            serial_write_hex(u64::from(lba), 8);
            serial_write(" status=0x");
            serial_write_hex(u64::from(status), 2);
            serial_write(" geometry=0x");
            serial_write_hex(u64::from(sectors), 2);
            serial_write("x0x");
            serial_write_hex(u64::from(heads), 4);
            serial_write("\r\n");
        }
    }

    let manifest_buffer = if bios_preloaded != 0 {
        // SAFETY: stage1 placed the manifest at 0x600 and the transition page tables retain an
        // identity mapping for the complete sector.
        unsafe { slice::from_raw_parts_mut(0x600 as *mut u8, 512) }
    } else {
        // SAFETY: this static buffer is exclusively owned during single-core loader execution.
        let buffer =
            unsafe { slice::from_raw_parts_mut(addr_of_mut!(MANIFEST_SECTOR).cast::<u8>(), 512) };
        ata_read(1, buffer).unwrap_or_else(|_| fatal("manifest disk read"));
        buffer
    };
    let manifest =
        DiskManifest::parse(manifest_buffer).unwrap_or_else(|_| fatal("manifest invalid"));
    let kernel_entry = manifest
        .find(DiskEntryKind::Kernel)
        .unwrap_or_else(|_| fatal("kernel entry missing"));
    let initrd_entry = manifest
        .find(DiskEntryKind::Initrd)
        .unwrap_or_else(|_| fatal("initrd entry missing"));

    let kernel_len = checked_buffer(kernel_entry.byte_len, KERNEL_STAGING_CAPACITY)
        .unwrap_or_else(|_| fatal("kernel image too large"));
    let kernel_sectors =
        sector_bytes(kernel_entry).unwrap_or_else(|| fatal("kernel sectors invalid"));
    // SAFETY: the reserved staging interval is identity-mapped and bounded above.
    let kernel_storage =
        unsafe { slice::from_raw_parts_mut(KERNEL_STAGING_ADDRESS as *mut u8, kernel_sectors) };
    if bios_preloaded == 0 {
        ata_read(kernel_entry.start_lba, kernel_storage)
            .unwrap_or_else(|_| fatal("kernel disk read"));
    }
    kernel_entry
        .verify_payload(&kernel_storage[..kernel_len])
        .unwrap_or_else(|_| fatal("kernel checksum"));
    let elf = Elf64::parse(&kernel_storage[..kernel_len]).unwrap_or_else(|_| fatal("kernel ELF"));
    let kernel_span = load_kernel(&elf, &kernel_storage[..kernel_len]);

    let initrd_len = checked_buffer(initrd_entry.byte_len, INITRD_CAPACITY)
        .unwrap_or_else(|_| fatal("initrd too large"));
    let initrd_sectors =
        sector_bytes(initrd_entry).unwrap_or_else(|| fatal("initrd sectors invalid"));
    // SAFETY: the fixed initrd interval is disjoint from stage2, kernel, and staging memory.
    let initrd_storage =
        unsafe { slice::from_raw_parts_mut(INITRD_LOAD_ADDRESS as *mut u8, initrd_sectors) };
    if bios_preloaded == 0 {
        ata_read(initrd_entry.start_lba, initrd_storage)
            .unwrap_or_else(|_| fatal("initrd disk read"));
    }
    initrd_entry
        .verify_payload(&initrd_storage[..initrd_len])
        .unwrap_or_else(|_| fatal("initrd checksum"));

    // SAFETY: assembly owns and finalizes this naturally aligned descriptor before entering
    // long mode; it is immutable after the handoff begins.
    let framebuffer = unsafe { core::ptr::read_unaligned(addr_of!(bios_framebuffer)) };
    if framebuffer.address != 0 {
        serial_write("xenith-stage2: VBE framebuffer ready\r\n");
    }
    let map_count = build_memory_map(e820_count, kernel_span, initrd_entry.byte_len, framebuffer);
    // SAFETY: all handoff statics remain reserved and immutable after this initialization.
    let boot_info = unsafe {
        MODULE = XenithModule {
            address: INITRD_LOAD_ADDRESS,
            length: initrd_entry.byte_len,
            path: INITRD_PATH.as_ptr(),
            path_length: INITRD_PATH.len() as u32,
            reserved: 0,
        };
        BOOT_INFO = XenithBootInfo::empty();
        BOOT_INFO.hhdm_offset = HHDM_OFFSET;
        BOOT_INFO.memory_map = addr_of!(MEMORY_REGIONS).cast::<XenithMemoryRegion>();
        BOOT_INFO.memory_map_count = map_count as u32;
        BOOT_INFO.framebuffer = framebuffer;
        BOOT_INFO.rsdp = find_rsdp().unwrap_or(0);
        BOOT_INFO.modules = addr_of!(MODULE);
        BOOT_INFO.module_count = 1;
        BOOT_INFO.command_line = COMMAND_LINE.as_ptr();
        BOOT_INFO.command_line_length = COMMAND_LINE.len() as u32;
        BOOT_INFO.boot_cpu_apic_id = boot_apic_id();
        &*addr_of!(BOOT_INFO)
    };
    serial_write("xenith-stage2: entering kernel\r\n");
    // SAFETY: ELF validation proved the entry lies in an executable segment, and the assembly
    // page tables map identity, HHDM, and the conventional Xenith higher-half kernel window.
    unsafe { jump_to_kernel(elf.entry(), boot_info) }
}

fn sector_bytes(entry: DiskEntry) -> Option<usize> {
    entry
        .sector_count
        .checked_mul(512)
        .and_then(|bytes| usize::try_from(bytes).ok())
}

fn load_kernel(elf: &Elf64<'_>, image: &[u8]) -> (u64, u64) {
    let (physical_start, physical_end) = elf
        .physical_span()
        .unwrap_or_else(|_| fatal("kernel physical span"));
    if physical_start < 0x10_0000 || physical_end > KERNEL_PHYSICAL_LIMIT {
        fatal("kernel physical range");
    }
    for segment in elf.load_segments() {
        let segment = segment.unwrap_or_else(|_| fatal("kernel segment"));
        let conventional_high = segment
            .virtual_address
            .checked_sub(KERNEL_VIRTUAL_BASE)
            .is_some_and(|offset| offset == segment.physical_address);
        if segment.virtual_address != segment.physical_address && !conventional_high {
            fatal("kernel virtual layout");
        }
        let source = segment
            .file_bytes(image)
            .unwrap_or_else(|_| fatal("kernel segment bytes"));
        let memory_size =
            usize::try_from(segment.memory_size).unwrap_or_else(|_| fatal("kernel segment size"));
        // SAFETY: physical-span validation keeps this destination inside 1 MiB..32 MiB and
        // the source resides in the disjoint staging range starting at 32 MiB.
        unsafe {
            let destination = segment.physical_address as *mut u8;
            core::ptr::copy_nonoverlapping(source.as_ptr(), destination, source.len());
            core::ptr::write_bytes(destination.add(source.len()), 0, memory_size - source.len());
        }
    }
    (physical_start, physical_end)
}

fn build_memory_map(
    e820_count: u32,
    kernel: (u64, u64),
    initrd_len: u64,
    framebuffer: XenithFramebuffer,
) -> usize {
    let count = usize::try_from(e820_count)
        .unwrap_or(0)
        .min(MAX_E820_ENTRIES);
    let mut reservations = [
        Reservation::new(0, 0x10_0000, BootMemoryKind::Reserved),
        Reservation::new(
            kernel.0,
            kernel.1 - kernel.0,
            BootMemoryKind::KernelAndModules,
        ),
        Reservation::new(
            KERNEL_STAGING_ADDRESS,
            KERNEL_STAGING_CAPACITY,
            BootMemoryKind::BootloaderReclaimable,
        ),
        Reservation::new(
            INITRD_LOAD_ADDRESS,
            initrd_len,
            BootMemoryKind::KernelAndModules,
        ),
        Reservation::new(0, 0, BootMemoryKind::Framebuffer),
    ];
    let mut reservation_count = 4;
    if framebuffer.address != 0 {
        reservations[reservation_count] = Reservation::new(
            framebuffer.address,
            u64::from(framebuffer.pitch) * u64::from(framebuffer.height),
            BootMemoryKind::Framebuffer,
        );
        reservation_count += 1;
    }
    for index in 1..reservation_count {
        let mut cursor = index;
        while cursor != 0 && reservations[cursor].base < reservations[cursor - 1].base {
            reservations.swap(cursor, cursor - 1);
            cursor -= 1;
        }
    }
    let mut used = 0;
    for index in 0..count {
        // SAFETY: assembly capped the E820 array at 128 fixed-size records at 0x50000.
        let entry =
            unsafe { core::ptr::read_unaligned((E820_BUFFER as *const E820Entry).add(index)) };
        if entry.length == 0 || (entry.attributes & 1 == 0 && entry.attributes != 0) {
            continue;
        }
        let kind = match entry.kind {
            1 => BootMemoryKind::Usable,
            3 => BootMemoryKind::AcpiReclaimable,
            4 => BootMemoryKind::AcpiNvs,
            5 => BootMemoryKind::BadMemory,
            _ => BootMemoryKind::Reserved,
        };
        // SAFETY: single-core loader execution exclusively owns this fixed-capacity array.
        let output = unsafe {
            slice::from_raw_parts_mut(
                addr_of_mut!(MEMORY_REGIONS).cast::<XenithMemoryRegion>(),
                MAX_MEMORY_REGIONS,
            )
        };
        append_region_with_reservations(
            output,
            &mut used,
            entry.base,
            entry.length,
            kind,
            &reservations[..reservation_count],
        )
        .unwrap_or_else(|_| fatal("memory map capacity"));
    }
    if used == 0 {
        fatal("BIOS E820 unavailable");
    }
    used
}

#[derive(Clone, Copy)]
enum DiskError {
    Timeout,
    Device,
    Buffer,
}

fn ata_read(mut lba: u64, output: &mut [u8]) -> Result<(), DiskError> {
    let (sectors, remainder) = output.as_chunks_mut::<512>();
    if !remainder.is_empty() {
        return Err(DiskError::Buffer);
    }
    for sector in sectors {
        ata_wait(false)?;
        // SAFETY: these are the legacy primary-master ATA command ports; each transfer is one
        // sector and all status waits are bounded.
        unsafe {
            out8(0x1f6, 0x40);
            out8(0x1f2, 0);
            out8(0x1f3, (lba >> 24) as u8);
            out8(0x1f4, (lba >> 32) as u8);
            out8(0x1f5, (lba >> 40) as u8);
            out8(0x1f2, 1);
            out8(0x1f3, lba as u8);
            out8(0x1f4, (lba >> 8) as u8);
            out8(0x1f5, (lba >> 16) as u8);
            out8(0x1f7, 0x24);
        }
        ata_wait(true)?;
        // SAFETY: `sector` is writable for exactly 256 words and INS advances RDI by two.
        unsafe {
            asm!(
                "cld",
                "rep insw",
                in("dx") 0x1f0_u16,
                inout("rdi") sector.as_mut_ptr() => _,
                inout("rcx") 256_usize => _,
                options(nostack)
            );
        }
        lba = lba.checked_add(1).ok_or(DiskError::Buffer)?;
    }
    Ok(())
}

fn ata_wait(require_data: bool) -> Result<(), DiskError> {
    for _ in 0..1_000_000 {
        // SAFETY: status reads do not mutate memory and are valid after selecting primary ATA.
        let status = unsafe { in8(0x1f7) };
        if status & 0x21 != 0 {
            return Err(DiskError::Device);
        }
        if status & 0x80 == 0 && (!require_data || status & 0x08 != 0) {
            return Ok(());
        }
    }
    Err(DiskError::Timeout)
}

fn find_rsdp() -> Option<u64> {
    // SAFETY: the BIOS data area word at 0x40e is defined on PC-compatible firmware.
    let ebda_segment = unsafe { core::ptr::read_unaligned(0x40e as *const u16) };
    let ebda = u64::from(ebda_segment) << 4;
    scan_rsdp(ebda, 1024).or_else(|| scan_rsdp(0xe0000, 0x20000))
}

fn scan_rsdp(base: u64, length: usize) -> Option<u64> {
    for offset in (0..length).step_by(16) {
        let address = base.checked_add(offset as u64)?;
        // SAFETY: callers only scan conventional BIOS RSDP search windows, identity-mapped.
        let candidate = unsafe { slice::from_raw_parts(address as *const u8, 36) };
        let legacy_valid =
            candidate.get(..8) == Some(b"RSD PTR ".as_slice()) && checksum(&candidate[..20]) == 0;
        let extended_length = usize::from(candidate[20]);
        let extended_valid = candidate[15] < 2
            || (extended_length >= 36
                && candidate
                    .get(..extended_length)
                    .is_some_and(|table| checksum(table) == 0));
        if legacy_valid && extended_valid {
            return Some(address);
        }
    }
    None
}

fn checksum(bytes: &[u8]) -> u8 {
    bytes.iter().fold(0_u8, |sum, byte| sum.wrapping_add(*byte))
}

fn boot_apic_id() -> u32 {
    let mut ebx: u32;
    // SAFETY: CPUID leaf 1 is supported on every x86_64 processor.
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

unsafe fn jump_to_kernel(entry: u64, boot_info: &'static XenithBootInfo) -> ! {
    // SAFETY: caller validated the executable ELF entry and System V handoff contract.
    let kernel: extern "sysv64" fn(*const XenithBootInfo) -> ! =
        unsafe { core::mem::transmute(entry as usize) };
    kernel(boot_info)
}

fn serial_init() {
    // SAFETY: COM1 is the loader's diagnostic device and is initialized before use.
    unsafe {
        out8(0x3f9, 0x00);
        out8(0x3fb, 0x80);
        out8(0x3f8, 0x03);
        out8(0x3f9, 0x00);
        out8(0x3fb, 0x03);
        out8(0x3fa, 0xc7);
        out8(0x3fc, 0x0b);
    }
}

fn serial_write(text: &str) {
    for byte in text.bytes() {
        for _ in 0..100_000 {
            // SAFETY: COM1 line-status reads are side-effect free.
            if unsafe { in8(0x3fd) } & 0x20 != 0 {
                break;
            }
        }
        // SAFETY: COM1 was initialized by `serial_init`.
        unsafe { out8(0x3f8, byte) };
    }
}

fn serial_write_hex(value: u64, digits: u8) {
    for index in (0..digits).rev() {
        let nibble = ((value >> (u32::from(index) * 4)) & 0x0f) as u8;
        let byte = if nibble < 10 {
            b'0' + nibble
        } else {
            b'a' + nibble - 10
        };
        for _ in 0..100_000 {
            // SAFETY: COM1 line-status reads are side-effect free.
            if unsafe { in8(0x3fd) } & 0x20 != 0 {
                break;
            }
        }
        // SAFETY: COM1 was initialized by `serial_init`.
        unsafe { out8(0x3f8, byte) };
    }
}

fn fatal(message: &str) -> ! {
    serial_write("xenith-stage2: ");
    serial_write(message);
    serial_write("\r\n");
    loop {
        // SAFETY: fatal loader state cannot recover; halt until reset.
        unsafe { asm!("cli", "hlt", options(nomem, nostack)) };
    }
}

unsafe fn out8(port: u16, value: u8) {
    // SAFETY: caller owns the selected hardware port operation.
    unsafe { asm!("out dx, al", in("dx") port, in("al") value, options(nomem, nostack)) };
}

unsafe fn in8(port: u16) -> u8 {
    let value: u8;
    // SAFETY: caller owns the selected hardware port operation.
    unsafe { asm!("in al, dx", in("dx") port, out("al") value, options(nomem, nostack)) };
    value
}

#[panic_handler]
fn panic(_info: &PanicInfo<'_>) -> ! {
    fatal("panic")
}
