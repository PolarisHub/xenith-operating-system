//! x86_64 symmetric-multiprocessing bring-up and cross-CPU coordination.
//!
//! CPUs are discovered through the ACPI MADT and assigned compact logical
//! ids in `0..MAX_CPUS` (`0` is the BSP). Every AP receives permanent
//! per-CPU, GDT/TSS, bootstrap-stack, and critical-IST storage. Stack frames
//! are allocated only for discovered APs. One reserved low-memory trampoline
//! page is repopulated serially for each AP before the BSP sends the
//! architectural INIT-SIPI-SIPI sequence.

use core::ptr::{addr_of, addr_of_mut};
use core::sync::atomic::{
    compiler_fence, fence, AtomicBool, AtomicU32, AtomicU64, AtomicU8, Ordering,
};

use xenith_boot::BootInfo;
use xenith_types::{PhysAddr, PhysFrame};

use super::gdt::GlobalDescriptorTable;
use super::interrupts::apic::{self, LAPIC};
use super::percpu::{self, PerCpuArea};
use super::{
    asm as arch_asm, fpu, gdt, idt, invlpg, pause, read_cr3, read_cr4, tlb_flush_all, tss,
    write_cr4, InterruptGuard,
};
use crate::sync::MAX_CPUS;

/// Reschedule IPI vector. Kept below the LAPIC timer/error/spurious trio.
pub const RESCHEDULE_VECTOR: u8 = 0xF0;
/// TLB invalidation IPI vector.
pub const TLB_SHOOTDOWN_VECTOR: u8 = 0xF1;

const _: () = {
    assert!(RESCHEDULE_VECTOR != TLB_SHOOTDOWN_VECTOR);
    assert!(RESCHEDULE_VECTOR < apic::TIMER_VECTOR);
    assert!(TLB_SHOOTDOWN_VECTOR < apic::TIMER_VECTOR);
};

const INVALID_APIC_ID: u32 = u32::MAX;
const LOW_TRAMPOLINE_LIMIT: u64 = 0x000A_0000;
// BIOS stage2 uses 0x70000..0x77fff as its synchronous INT 13h payload
// bounce buffer, then permanently retires it before entering the kernel. Its
// handoff marks the whole first MiB reserved, so the physical allocator can
// never return this page and no ordinary kernel allocation can alias it.
const BIOS_BOUNCE_TRAMPOLINE_PHYS: u64 = 0x0007_0000;
const BIOS_BOOT_TOKEN: &str = "xenith.boot=bios";
const PAGE_SIZE: usize = 4096;
const AP_BOOT_STACK_SIZE: usize = 32 * 1024;
const AP_STACK_BYTES: usize = AP_BOOT_STACK_SIZE + tss::IST_STACK_SIZE;
const AP_STACK_FRAMES: usize = AP_STACK_BYTES / PAGE_SIZE;
const AP_START_TIMEOUT_MS: u64 = 250;
const CR3_ADDRESS_MASK: u64 = 0x000f_ffff_ffff_f000;

const _: () = assert!(AP_STACK_BYTES.is_multiple_of(PAGE_SIZE));

// CPU zero uses the BSP-owned statics in percpu/gdt/tss. Slots 1.. are
// prepared by the BSP before their corresponding INIT IPI is emitted.
static mut AP_PERCPU_AREAS: [PerCpuArea; MAX_CPUS] =
    [const { PerCpuArea::new_zeroed(0) }; MAX_CPUS];
static mut AP_GDTS: [GlobalDescriptorTable; MAX_CPUS] =
    [const { GlobalDescriptorTable::new(0) }; MAX_CPUS];
// Stack memory is allocated only for APs actually discovered. The physical
// runs remain checked out permanently: the boot stack can still be named by
// a delayed SIPI, and the IST stack remains installed in that CPU's TSS.
static AP_BOOT_STACK_TOPS: [AtomicU64; MAX_CPUS] = [const { AtomicU64::new(0) }; MAX_CPUS];

static CPU_APIC_IDS: [AtomicU32; MAX_CPUS] = [const { AtomicU32::new(INVALID_APIC_ID) }; MAX_CPUS];
static PRESENT_CPUS: AtomicU64 = AtomicU64::new(0);
static ONLINE_CPUS: AtomicU64 = AtomicU64::new(0);
static INIT_STARTED: AtomicBool = AtomicBool::new(false);
static SMP_READY: AtomicBool = AtomicBool::new(false);

#[repr(u8)]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum ShootdownKind {
    KernelPage = 1,
    AddressSpacePage = 2,
    KernelAll = 3,
    AddressSpaceAll = 4,
}

impl ShootdownKind {
    fn from_raw(raw: u8) -> Option<Self> {
        match raw {
            1 => Some(Self::KernelPage),
            2 => Some(Self::AddressSpacePage),
            3 => Some(Self::KernelAll),
            4 => Some(Self::AddressSpaceAll),
            _ => None,
        }
    }

    const fn is_address_space_specific(self) -> bool {
        matches!(self, Self::AddressSpacePage | Self::AddressSpaceAll)
    }

    const fn is_full_flush(self) -> bool {
        matches!(self, Self::KernelAll | Self::AddressSpaceAll)
    }
}

/// One shootdown mailbox owned by a single source CPU.
///
/// Per-source mailboxes avoid a global shootdown lock. That is essential for
/// page-fault paths, which may initiate an invalidation with IF clear: two
/// CPUs can publish concurrently and still service each other's IPI instead
/// of spinning on a lock while unable to acknowledge it.
struct TlbRequest {
    sequence: AtomicU64,
    published: AtomicU64,
    kind: AtomicU8,
    cr3: AtomicU64,
    address: AtomicU64,
    targets: AtomicU64,
}

impl TlbRequest {
    const fn new() -> Self {
        Self {
            sequence: AtomicU64::new(0),
            published: AtomicU64::new(0),
            kind: AtomicU8::new(0),
            cr3: AtomicU64::new(0),
            address: AtomicU64::new(0),
            targets: AtomicU64::new(0),
        }
    }
}

static TLB_REQUESTS: [TlbRequest; MAX_CPUS] = [const { TlbRequest::new() }; MAX_CPUS];
static TLB_ACK: [AtomicU64; MAX_CPUS * MAX_CPUS] =
    [const { AtomicU64::new(0) }; MAX_CPUS * MAX_CPUS];

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum TrampolinePageSource {
    Allocator,
    BiosBounce,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct TrampolinePage {
    frame: PhysFrame,
    source: TrampolinePageSource,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum StartupDisposition {
    ReuseTrampoline,
    Stop,
}

#[inline]
fn command_line_has_token(command_line: Option<&str>, token: &str) -> bool {
    command_line.is_some_and(|line| {
        line.split_ascii_whitespace()
            .any(|argument| argument == token)
    })
}

#[inline]
fn select_trampoline_page(
    allocated: Option<PhysFrame>,
    command_line: Option<&str>,
) -> Option<TrampolinePage> {
    if let Some(frame) = allocated {
        return Some(TrampolinePage {
            frame,
            source: TrampolinePageSource::Allocator,
        });
    }
    command_line_has_token(command_line, BIOS_BOOT_TOKEN).then(|| TrampolinePage {
        frame: PhysFrame::containing_addr(PhysAddr::new_truncate(BIOS_BOUNCE_TRAMPOLINE_PHYS)),
        source: TrampolinePageSource::BiosBounce,
    })
}

#[inline]
const fn startup_disposition(acknowledged: bool) -> StartupDisposition {
    if acknowledged {
        StartupDisposition::ReuseTrampoline
    } else {
        StartupDisposition::Stop
    }
}

#[inline]
const fn tlb_ack_index(source: usize, target: usize) -> usize {
    source * MAX_CPUS + target
}

#[inline]
fn ap_area(cpu: usize) -> *mut PerCpuArea {
    // `addr_of_mut!` obtains storage without creating a reference to the
    // mutable static. Bounds are checked by every caller before this helper.
    unsafe { addr_of_mut!(AP_PERCPU_AREAS).cast::<PerCpuArea>().add(cpu) }
}

#[inline]
fn ap_gdt(cpu: usize) -> *mut GlobalDescriptorTable {
    unsafe {
        addr_of_mut!(AP_GDTS)
            .cast::<GlobalDescriptorTable>()
            .add(cpu)
    }
}

fn stack_tops(base: u64) -> Option<(u64, u64)> {
    let boot = base.checked_add(AP_BOOT_STACK_SIZE as u64)?;
    let ist = boot.checked_add(tss::IST_STACK_SIZE as u64)?;
    Some((boot, ist))
}

/// Mask of logical CPUs that completed all CPU-local initialisation.
#[inline]
#[must_use]
pub fn online_mask() -> u64 {
    ONLINE_CPUS.load(Ordering::Acquire)
}

/// Number of fully-online logical CPUs, including the BSP.
#[inline]
#[must_use]
pub fn online_count() -> usize {
    online_mask().count_ones() as usize
}

/// Whether SMP discovery/startup has completed (possibly in BSP-only mode).
#[inline]
#[must_use]
pub fn is_ready() -> bool {
    SMP_READY.load(Ordering::Acquire)
}

/// Whether a logical CPU is currently online.
#[inline]
#[must_use]
pub fn is_online(cpu: usize) -> bool {
    cpu < MAX_CPUS && online_mask() & (1u64 << cpu) != 0
}

/// Resolve a compact logical CPU id to its physical APIC destination id.
#[must_use]
pub fn cpu_apic_id(cpu: usize) -> Option<u32> {
    if cpu >= MAX_CPUS || PRESENT_CPUS.load(Ordering::Acquire) & (1u64 << cpu) == 0 {
        return None;
    }
    let id = CPU_APIC_IDS[cpu].load(Ordering::Acquire);
    (id != INVALID_APIC_ID).then_some(id)
}

fn cpu_for_apic_id(apic_id: u32) -> Option<usize> {
    let present = PRESENT_CPUS.load(Ordering::Acquire);
    (0..MAX_CPUS).find(|cpu| {
        present & (1u64 << cpu) != 0 && CPU_APIC_IDS[*cpu].load(Ordering::Acquire) == apic_id
    })
}

fn prepare_ap_storage(cpu: usize) -> bool {
    debug_assert!((1..MAX_CPUS).contains(&cpu));
    // The backing frames need not be below 4 GiB: real mode touches only the
    // SIPI page and CR3. The trampoline loads this HHDM virtual stack address
    // after it has entered 64-bit paging, where the direct map is active.
    let Some(first) = crate::mm::physical::allocate_range(AP_STACK_FRAMES) else {
        return false;
    };
    let base = crate::mm::phys_to_virt(first.start_address()).as_u64();
    let Some((boot_stack_top, ist_stack_top)) = stack_tops(base) else {
        // A canonical HHDM base cannot overflow by this small amount. Keep the
        // run reserved if the boot contract was violated rather than making
        // it available while a partially prepared AP could reference it.
        return false;
    };

    // SAFETY: `allocate_range` returned this contiguous run exclusively, the
    // HHDM maps it writable, and no address is published until zeroing ends.
    unsafe { core::ptr::write_bytes(base as *mut u8, 0, AP_STACK_BYTES) };
    AP_BOOT_STACK_TOPS[cpu].store(boot_stack_top, Ordering::Release);

    let area = ap_area(cpu);
    // SAFETY: this CPU has not been started yet, so the BSP exclusively owns
    // its permanent slots. Both stack runs remain allocator-owned forever.
    unsafe {
        area.write(PerCpuArea::new_zeroed(cpu as u32));
        ap_gdt(cpu).write(GlobalDescriptorTable::new(0));
        tss::build_tss_with_ist(&mut (*area).tss, boot_stack_top, ist_stack_top);
    }
    true
}

fn trampoline_symbol_range() -> (usize, usize) {
    let start = addr_of!(arch_asm::ap_trampoline_start) as usize;
    let end = addr_of!(arch_asm::ap_trampoline_end) as usize;
    (start, end)
}

fn symbol_offset(symbol: *const u8, start: usize, len: usize) -> Option<usize> {
    let address = symbol as usize;
    let offset = address.checked_sub(start)?;
    (offset < len).then_some(offset)
}

unsafe fn patch_value<T: Copy>(page: *mut u8, offset: usize, value: T) {
    // SAFETY: the caller verified the symbol offset and copied a complete
    // trampoline into the writable page.
    unsafe { core::ptr::write_unaligned(page.add(offset).cast::<T>(), value) };
}

fn build_trampoline(cpu: usize, apic_id: u32, cr3: u64, frame: PhysFrame) -> Option<u8> {
    let phys = frame.start_address().as_u64();
    let start_page = u8::try_from(phys >> 12).ok()?;

    // SAFETY: assembly markers delimit one link-time contiguous block. The
    // destination is a newly allocated HHDM-writable frame.
    unsafe {
        let (start, end) = trampoline_symbol_range();
        let len = end.checked_sub(start)?;
        if len == 0 || len > PAGE_SIZE {
            ::log::error!("xenith.smp: AP trampoline size {} exceeds one page", len);
            return None;
        }
        let page = crate::mm::phys_to_virt(frame.start_address()).as_u64() as *mut u8;
        core::ptr::write_bytes(page, 0, PAGE_SIZE);
        core::ptr::copy_nonoverlapping(start as *const u8, page, len);

        macro_rules! off {
            ($symbol:ident) => {{
                symbol_offset(addr_of!(arch_asm::$symbol), start, len)?
            }};
        }

        let long_mode = phys.checked_add(off!(ap_trampoline_long_mode) as u64)?;
        let gdt_base = phys.checked_add(off!(ap_trampoline_gdt) as u64)?;
        if long_mode > u64::from(u32::MAX) || gdt_base > u64::from(u32::MAX) {
            return None;
        }

        let stack_top = AP_BOOT_STACK_TOPS[cpu].load(Ordering::Acquire);
        if stack_top == 0 {
            return None;
        }
        patch_value(page, off!(ap_trampoline_cr3), cr3 as u32);
        patch_value(page, off!(ap_trampoline_stack), stack_top);
        patch_value(
            page,
            off!(ap_trampoline_entry),
            xenith_ap_entry as *const () as usize as u64,
        );
        patch_value(page, off!(ap_trampoline_cpu_id), cpu as u32);
        patch_value(page, off!(ap_trampoline_apic_id), apic_id);
        patch_value(page, off!(ap_trampoline_gdtr_base), gdt_base as u32);
        patch_value(page, off!(ap_trampoline_far_target), long_mode as u32);
        compiler_fence(Ordering::Release);
    }

    Some(start_page)
}

/// Discover and start every enabled MADT processor supported by static
/// per-CPU capacity.
pub fn init(boot_info: BootInfo) {
    if INIT_STARTED.swap(true, Ordering::AcqRel) {
        return;
    }

    // IPI gates are safe to publish even when the machine ultimately remains
    // BSP-only; they are also required before the first AP enables IF.
    idt::install_ipi_handlers(RESCHEDULE_VECTOR, TLB_SHOOTDOWN_VECTOR);

    if !LAPIC.is_enabled() {
        PRESENT_CPUS.store(1, Ordering::Release);
        ONLINE_CPUS.store(1, Ordering::Release);
        SMP_READY.store(true, Ordering::Release);
        ::log::warn!("xenith.smp: local APIC unavailable; continuing BSP-only");
        return;
    }

    let bsp_apic_id = apic::current_id();
    CPU_APIC_IDS[0].store(bsp_apic_id, Ordering::Release);
    PRESENT_CPUS.store(1, Ordering::Release);
    ONLINE_CPUS.store(1, Ordering::Release);

    // The real-mode transition can only load a 32-bit CR3 value. Typical PC
    // boot firmware places the root below 4 GiB; refuse unsafe truncation on
    // platforms that do not.
    let cr3 = unsafe { read_cr3() } & CR3_ADDRESS_MASK;
    if cr3 > u64::from(u32::MAX) {
        SMP_READY.store(true, Ordering::Release);
        ::log::warn!(
            "xenith.smp: CR3 {:#x} is above 4 GiB; AP transition unavailable",
            cr3
        );
        return;
    }

    let mut next_cpu = 1usize;
    let mut trampoline_page = None;
    for entry in crate::acpi::madt_lapics()
        .iter()
        .filter(|entry| entry.enabled)
    {
        if entry.apic_id == bsp_apic_id || cpu_for_apic_id(entry.apic_id).is_some() {
            continue;
        }
        if !LAPIC.can_route_apic_id(entry.apic_id) {
            ::log::warn!(
                "xenith.smp: APIC id {} is not routable in {:?}; CPU ignored",
                entry.apic_id,
                LAPIC.mode()
            );
            continue;
        }
        if next_cpu == MAX_CPUS {
            ::log::warn!(
                "xenith.smp: CPU topology exceeds MAX_CPUS={}; remaining APs ignored",
                MAX_CPUS
            );
            break;
        }

        let cpu = next_cpu;
        if !prepare_ap_storage(cpu) {
            ::log::warn!(
                "xenith.smp: no memory for CPU {} bootstrap/IST stacks; remaining APs ignored",
                cpu
            );
            break;
        }
        next_cpu += 1;
        CPU_APIC_IDS[cpu].store(entry.apic_id, Ordering::Release);
        PRESENT_CPUS.fetch_or(1u64 << cpu, Ordering::AcqRel);

        let page = match trampoline_page {
            Some(page) => page,
            None => {
                let allocated = crate::mm::physical::allocate_frame_below(PhysAddr::new_truncate(
                    LOW_TRAMPOLINE_LIMIT,
                ));
                let Some(page) = select_trampoline_page(allocated, boot_info.kernel_cmdline())
                else {
                    ::log::warn!(
                        "xenith.smp: no conventional-memory trampoline page; remaining APs ignored"
                    );
                    break;
                };
                if page.source == TrampolinePageSource::BiosBounce {
                    ::log::info!(
                        "xenith.smp: using retired BIOS bounce page {:#x} for serialized AP startup",
                        page.frame.start_address().as_u64()
                    );
                }
                trampoline_page = Some(page);
                page
            },
        };

        let Some(start_page) = build_trampoline(cpu, entry.apic_id, cr3, page.frame) else {
            ::log::warn!(
                "xenith.smp: failed to prepare trampoline for AP {} (apic {}); remaining APs ignored",
                cpu,
                entry.apic_id
            );
            break;
        };

        // Intel's universal startup algorithm: INIT, 10 ms, SIPI, at least
        // 200 us, then a second SIPI. PIT polling works with IF clear.
        LAPIC.send_init_ipi(entry.apic_id);
        crate::time::pit::pit_sleep(10);
        LAPIC.send_startup_ipi(entry.apic_id, start_page);
        crate::time::pit::pit_sleep(1);
        LAPIC.send_startup_ipi(entry.apic_id, start_page);

        let mut waited = 0;
        while !is_online(cpu) && waited < AP_START_TIMEOUT_MS {
            crate::time::pit::pit_sleep(1);
            waited += 1;
        }
        let acknowledged = is_online(cpu);
        if acknowledged {
            let apic_mode = if LAPIC.is_x2apic() { "x2APIC" } else { "xAPIC" };
            ::log::info!(
                "xenith.smp: CPU {} online ({} {}, startup page {:#04x})",
                cpu,
                apic_mode,
                entry.apic_id,
                start_page
            );
        } else {
            let apic_mode = if LAPIC.is_x2apic() { "x2APIC" } else { "xAPIC" };
            ::log::warn!(
                "xenith.smp: CPU {} ({} {}) did not acknowledge startup in {} ms",
                cpu,
                apic_mode,
                entry.apic_id,
                AP_START_TIMEOUT_MS
            );
        }
        if startup_disposition(acknowledged) == StartupDisposition::Stop {
            // A timed-out AP may still consume a delayed SIPI. Never rewrite
            // its page for another CPU, because that could start the late AP
            // with the next CPU's logical id, stack, and expected APIC id.
            ::log::warn!(
                "xenith.smp: AP startup stopped after timeout; trampoline page quarantined"
            );
            break;
        }
    }

    SMP_READY.store(true, Ordering::Release);
    ::log::info!(
        "xenith.smp: {} CPU(s) online, {} discovered",
        online_count(),
        PRESENT_CPUS.load(Ordering::Acquire).count_ones()
    );
}

/// High-half entry reached after the copied trampoline enables long mode.
#[no_mangle]
pub extern "C" fn xenith_ap_entry(cpu_id: u32, expected_apic_id: u32) -> ! {
    let cpu = cpu_id as usize;
    if !(1..MAX_CPUS).contains(&cpu) {
        loop {
            unsafe { core::arch::asm!("cli; hlt", options(nomem, nostack)) };
        }
    }

    // No GS-relative or current_cpu-dependent operation may precede this
    // table/per-CPU setup: INIT reset the AP's segment/MSR state.
    super::early_init();
    unsafe {
        gdt::init_for_ap(ap_gdt(cpu), core::ptr::addr_of_mut!((*ap_area(cpu)).tss));
        percpu::init_for_ap(cpu_id, ap_area(cpu));
    }
    fpu::init_ap();
    idt::load();
    crate::syscall::init();
    apic::init();

    let actual_apic_id = apic::current_id();
    if actual_apic_id != expected_apic_id {
        ::log::error!(
            "xenith.smp: CPU {} expected APIC {}, hardware reports {}",
            cpu,
            expected_apic_id,
            actual_apic_id
        );
        loop {
            unsafe { core::arch::asm!("cli; hlt", options(nomem, nostack)) };
        }
    }

    crate::sched::scheduler::init_ap();
    crate::time::lapic_timer::init();
    crate::time::lapic_timer::set_tick(
        crate::sched::SCHED_TICK_HZ,
        crate::sched::LAPIC_TIMER_VECTOR,
    );

    ONLINE_CPUS.fetch_or(1u64 << cpu, Ordering::AcqRel);
    compiler_fence(Ordering::Release);

    // The CPU now has complete descriptor tables, an idle task, syscall MSRs,
    // an armed scheduler timer, and valid GS/TSS state.
    unsafe { core::arch::asm!("sti", options(nomem, nostack)) };
    crate::sched::schedule_next();

    loop {
        unsafe { core::arch::asm!("sti; hlt", options(nomem, nostack)) };
    }
}

/// Ask a logical CPU to enter the scheduler at its next preemptible point.
pub fn request_reschedule(cpu: usize) {
    if !is_online(cpu) {
        return;
    }
    if cpu == crate::sync::current_cpu() {
        crate::sched::preempt::set_need_resched();
        return;
    }
    if let Some(apic_id) = cpu_apic_id(cpu) {
        apic::send_ipi(apic_id, RESCHEDULE_VECTOR);
    }
}

/// Rust dispatch for [`RESCHEDULE_VECTOR`].
#[no_mangle]
pub extern "C" fn rust_reschedule_interrupt() {
    // EOI must precede a context switch: the interrupted task may not return
    // to this frame for an unbounded amount of time.
    apic::send_eoi();
    crate::sched::preempt::set_need_resched();
    if crate::sched::preempt::should_preempt() {
        crate::sched::schedule_next();
    }
}

#[inline]
const fn normalise_cr3(cr3: u64) -> u64 {
    cr3 & CR3_ADDRESS_MASK
}

fn apply_shootdown(kind: ShootdownKind, request_cr3: u64, address: u64) {
    if kind.is_address_space_specific() {
        let active = normalise_cr3(unsafe { read_cr3() });
        if active != normalise_cr3(request_cr3) {
            return;
        }
    }
    if kind == ShootdownKind::KernelAll {
        // A CR3 reload preserves GLOBAL entries while CR4.PGE is set. Toggle
        // PGE off and restore the exact CR4 image to invalidate those shared
        // kernel translations as well.
        let cr4 = unsafe { read_cr4() };
        unsafe {
            write_cr4(cr4 & !(1 << 7));
            write_cr4(cr4);
        }
    } else if kind.is_full_flush() {
        tlb_flush_all();
    } else {
        unsafe { invlpg(address) };
    }
}

fn shootdown(kind: ShootdownKind, cr3: u64, address: u64) {
    // A source CPU owns exactly one mailbox. Pin this operation against the
    // interrupt-driven scheduler so a second task cannot overwrite it while
    // the first is waiting. The wait loop below services peer mailboxes
    // synchronously, so two CPUs that entered with IF already clear can still
    // acknowledge one another without relying on interrupt delivery.
    let _interrupt_guard = unsafe { InterruptGuard::disable() };
    let current = crate::sync::current_cpu();
    debug_assert!(current < MAX_CPUS);
    let targets = online_mask() & !(1u64 << current);
    if targets == 0 || !is_ready() {
        apply_shootdown(kind, cr3, address);
        return;
    }

    let request = &TLB_REQUESTS[current];
    let mut generation = request
        .sequence
        .fetch_add(1, Ordering::Relaxed)
        .wrapping_add(1);
    if generation == 0 {
        // Zero means "never published" to the target-side scanner.
        generation = 1;
        request.sequence.store(generation, Ordering::Relaxed);
    }
    for cpu in 0..MAX_CPUS {
        if targets & (1u64 << cpu) != 0 {
            // Prevent a generation reused after u64 wrap from matching a
            // decades-old acknowledgement before the request is serviced.
            TLB_ACK[tlb_ack_index(current, cpu)]
                .store(generation.wrapping_sub(1), Ordering::Relaxed);
        }
    }
    request.cr3.store(normalise_cr3(cr3), Ordering::Relaxed);
    request.address.store(address, Ordering::Relaxed);
    request.targets.store(targets, Ordering::Relaxed);
    request.kind.store(kind as u8, Ordering::Relaxed);
    request.published.store(generation, Ordering::Release);
    fence(Ordering::SeqCst);

    for cpu in 0..MAX_CPUS {
        if targets & (1u64 << cpu) != 0 {
            if let Some(apic_id) = cpu_apic_id(cpu) {
                apic::send_ipi(apic_id, TLB_SHOOTDOWN_VECTOR);
            }
        }
    }
    apply_shootdown(kind, cr3, address);

    for cpu in 0..MAX_CPUS {
        if targets & (1u64 << cpu) == 0 {
            continue;
        }
        let ack = &TLB_ACK[tlb_ack_index(current, cpu)];
        while ack.load(Ordering::Acquire) != generation {
            service_tlb_requests(current);
            pause();
        }
    }
}

/// Invalidate one shared-kernel virtual address on every online CPU.
pub fn shootdown_kernel_page(address: u64) {
    shootdown(ShootdownKind::KernelPage, 0, address);
}

/// Flush all non-global translations on every online CPU.
pub fn shootdown_kernel_all() {
    shootdown(ShootdownKind::KernelAll, 0, 0);
}

/// Invalidate one address only on CPUs currently running `cr3`.
pub fn shootdown_page(cr3: u64, address: u64) {
    shootdown(ShootdownKind::AddressSpacePage, cr3, address);
}

/// Flush CPUs currently running `cr3` without disturbing other processes.
pub fn shootdown_address_space(cr3: u64) {
    shootdown(ShootdownKind::AddressSpaceAll, cr3, 0);
}

fn service_tlb_requests(cpu: usize) {
    debug_assert!(cpu < MAX_CPUS);
    for (source, request) in TLB_REQUESTS.iter().enumerate() {
        let generation = request.published.load(Ordering::Acquire);
        if generation == 0 || request.targets.load(Ordering::Relaxed) & (1u64 << cpu) == 0 {
            continue;
        }
        let ack = &TLB_ACK[tlb_ack_index(source, cpu)];
        if ack.load(Ordering::Relaxed) == generation {
            continue;
        }
        if let Some(kind) = ShootdownKind::from_raw(request.kind.load(Ordering::Relaxed)) {
            apply_shootdown(
                kind,
                request.cr3.load(Ordering::Relaxed),
                request.address.load(Ordering::Relaxed),
            );
        }
        ack.store(generation, Ordering::Release);
    }
}

/// Rust dispatch for [`TLB_SHOOTDOWN_VECTOR`].
#[no_mangle]
pub extern "C" fn rust_tlb_shootdown_interrupt() {
    let cpu = crate::sync::current_cpu();
    if cpu < MAX_CPUS {
        service_tlb_requests(cpu);
    }
    apic::send_eoi();
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn cr3_normalisation_removes_pcid_and_reserved_bits() {
        assert_eq!(normalise_cr3(0xffff_0000_1234_5abc), 0x000f_0000_1234_5000);
    }

    #[test]
    fn shootdown_kind_policy_is_exact() {
        assert!(!ShootdownKind::KernelPage.is_address_space_specific());
        assert!(ShootdownKind::AddressSpacePage.is_address_space_specific());
        assert!(ShootdownKind::KernelAll.is_full_flush());
        assert!(!ShootdownKind::AddressSpacePage.is_full_flush());
    }

    #[test]
    fn copied_trampoline_symbols_fit_one_page() {
        let (start, end) = trampoline_symbol_range();
        let len = end - start;
        assert!(len > 0 && len <= PAGE_SIZE);
        let symbols = [
            addr_of!(arch_asm::ap_trampoline_long_mode),
            addr_of!(arch_asm::ap_trampoline_cr3),
            addr_of!(arch_asm::ap_trampoline_stack),
            addr_of!(arch_asm::ap_trampoline_entry),
            addr_of!(arch_asm::ap_trampoline_cpu_id),
            addr_of!(arch_asm::ap_trampoline_apic_id),
            addr_of!(arch_asm::ap_trampoline_gdt),
            addr_of!(arch_asm::ap_trampoline_gdtr_base),
            addr_of!(arch_asm::ap_trampoline_far_target),
        ];
        for symbol in symbols {
            assert!(symbol_offset(symbol, start, len).is_some());
        }
    }

    #[test]
    fn acknowledgement_matrix_has_unique_source_target_slots() {
        assert_eq!(tlb_ack_index(0, 0), 0);
        assert_eq!(tlb_ack_index(1, 0), MAX_CPUS);
        assert_eq!(tlb_ack_index(MAX_CPUS - 1, MAX_CPUS - 1), TLB_ACK.len() - 1);
    }

    #[test]
    fn bios_bounce_fallback_requires_an_exact_command_line_token() {
        for command_line in [
            None,
            Some(""),
            Some("xenith.boot=uefi"),
            Some("prefix-xenith.boot=bios"),
            Some("xenith.boot=bios-suffix"),
        ] {
            assert_eq!(select_trampoline_page(None, command_line), None);
        }

        for command_line in [
            Some("xenith.boot=bios"),
            Some("quiet xenith.boot=bios splash"),
            Some("\t xenith.boot=bios\n"),
        ] {
            let page = select_trampoline_page(None, command_line).expect("BIOS fallback page");
            assert_eq!(page.source, TrampolinePageSource::BiosBounce);
            assert_eq!(
                page.frame.start_address().as_u64(),
                BIOS_BOUNCE_TRAMPOLINE_PHYS
            );
        }
    }

    #[test]
    fn allocator_page_wins_over_bios_fallback() {
        let allocated = PhysFrame::containing_addr(PhysAddr::new_truncate(0x80000));
        let page = select_trampoline_page(Some(allocated), Some(BIOS_BOOT_TOKEN)).unwrap();
        assert_eq!(page.frame, allocated);
        assert_eq!(page.source, TrampolinePageSource::Allocator);
    }

    #[test]
    fn trampoline_is_reused_only_after_online_acknowledgement() {
        assert_eq!(
            startup_disposition(true),
            StartupDisposition::ReuseTrampoline
        );
        assert_eq!(startup_disposition(false), StartupDisposition::Stop);
    }

    #[test]
    fn runtime_ap_stack_layout_is_contiguous_and_aligned() {
        let base = 0xffff_8000_1234_5000;
        let (boot, ist) = stack_tops(base).unwrap();
        assert_eq!(boot - base, AP_BOOT_STACK_SIZE as u64);
        assert_eq!(ist - boot, tss::IST_STACK_SIZE as u64);
        assert_eq!(ist - base, (AP_STACK_FRAMES * PAGE_SIZE) as u64);
        assert!(boot.is_multiple_of(16));
        assert!(ist.is_multiple_of(16));
    }
}
