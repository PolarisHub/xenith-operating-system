//! Local APIC timer driver — one-shot and periodic modes, calibration hook,
//! and the LAPIC-backed monotonic [`ClockSource`].
//!
//! The LAPIC timer is the per-CPU programmable timer built into every local
//! APIC. Unlike the PIT (a single system-wide timer) it is per logical CPU,
//! which makes it the natural source of the scheduler tick on SMP systems:
//! each CPU gets its own independent countdown, so a tick on one CPU never
//! delivers an interrupt to another. It is also the timer the kernel keeps
//! running for its monotonic clock once the HPET is unavailable.
//!
//! # Register access: xAPIC MMIO vs. x2APIC MSR
//!
//! The LAPIC exposes two access modes, selected by the IA32_APIC_BASE MSR:
//!
//! * **xAPIC** (legacy): the LAPIC's 4 KiB register window is memory-mapped at
//!   a physical base reported by the MSR (default `0xFEE0_0000`). Registers
//!   are 32-bit and sit on a 16-byte stride. We translate the physical page
//!   through the bootloader-provided HHDM before issuing volatile accesses.
//! * **x2APIC** (modern): the same registers are remapped to the MSR space at
//!   `0x800 + (offset >> 4)`, accessed with `rdmsr`/`wrmsr`. The data width
//!   widens to 64 bits and there is no MMIO window to map. x2APIC is
//!   preferred when available because it raises the APIC-ID width to 32 bits
//!   and avoids an MMIO TLB dependency.
//!
//! [`init`] probes `cpu::has_x2apic()`, enables the appropriate mode in
//! IA32_APIC_BASE, and records the mode in a static so [`read_reg`] /
//! [`write_reg`] dispatch correctly thereafter.
//!
//! # Timer modes
//!
//! The LVT Timer entry (offset `0x320`) selects the operating mode in bits
//! 17..18:
//!
//! * `00` — one-shot: the counter counts down from the initial count to zero,
//!   fires once, and stops. Used for calibration and for one-shot scheduler
//!   deadlines.
//! * `01` — periodic: the counter reloads to the initial count after each
//!   zero, firing an interrupt at `lapic_tick_rate / initial_count` Hz. Used
//!   for the steady scheduler tick.
//! * `10` — TSC-deadline: the timer fires when the TSC reaches a 64-bit
//!   deadline written to the initial-count register. Higher resolution and
//!   CPU-independent, but requires TSC calibration and a CPU that advertises
//!   the feature; not implemented in this phase.
//!
//! # Calibration
//!
//! The LAPIC timer's input clock is the APIC bus clock divided by the DCR
//! divisor. Its exact frequency is not knowable a priori — it varies with the
//! platform and the divisor — so it must be measured against a reference with
//! a known frequency. The PIT is the reference (its 1.193182 MHz input is
//! hard-wired). The actual measurement lives in [`super::calibration`]; this
//! module exposes the raw primitives ([`arm_one_shot_raw`], [`read_current_count`],
//! [`mask`]) the calibration routine drives.
//!
//! Because calibration measures the *effective* tick rate (post-divisor), the
//! exact DCR encoding does not affect correctness — only granularity. We
//! program the DCR once in [`init`] and leave it; calibration and runtime use
//! the same divisor, so the measured rate is the runtime rate.
//!
//! # Monotonic clock
//!
//! [`LapicClock`] implements [`ClockSource`] by accumulating the periodic-tick
//! count ([`LAPIC_TICKS`], bumped by [`on_tick`] from the timer's IRQ handler)
//! and adding the sub-tick elapsed count read from the current-count register.
//! The result is converted to nanoseconds with the calibrated
//! [`LAPIC_FREQ`]. The read is consistent against the IRQ race by a
//! double-read of the tick counter (a seqlock-free variant): if the tick
//! count changes between the two current-count samples, the read is retried.
//!
//! The clocksource is only meaningful while the timer is armed in periodic
//! mode with [`on_tick`] wired to the timer vector's handler. Before that
//! (e.g. immediately after [`init`], before the scheduler arms the tick) the
//! accumulator is zero and `read_ns` returns zero — matching the PIT
//! clocksource's behaviour before its IRQ handler is installed.
//!
//! # Safety
//!
//! LAPIC MMIO is reached through the HHDM direct map (kernel-owned, mapped by
//! Limine) and MSR access is privileged. All `rdmsr`/`wrmsr` and volatile
//! MMIO accesses are wrapped in `unsafe` blocks with a SAFETY comment naming
//! the invariant (ring 0, the LAPIC is enabled, the offset is a valid
//! register). The safe public API (`set_tick`, `arm_*`, `on_tick`) establishes
//! those invariants once in [`init`].

use core::ptr::{read_volatile, write_volatile};
use core::sync::atomic::{AtomicU64, AtomicU8, Ordering};

use xenith_types::PhysAddr;

use super::clock::ClockSource;
use crate::arch::x86_64::cpu::has_x2apic;
use crate::arch::x86_64::instructions::{rdmsr, wrmsr};
use crate::arch::x86_64::msr::IA32_LAPIC_BASE;

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

// LAPIC register offsets (xAPIC MMIO byte offsets; x2APIC MSR index is
// `0x800 + (offset >> 4)`). These are stable across every x86_64 part.
/// Spurious Interrupt Vector Register. Bit 8 is the APIC software-enable.
const REG_SVR: u16 = 0x0F0;
/// End-of-Interrupt register. A write of any value acknowledges the current
/// interrupt; the LAPIC drops the IRR bit and allows further interrupts.
const REG_EOI: u16 = 0x0B0;
/// LVT Timer register. Vector in bits 0..7, mask in bit 16, mode in 17..18.
const REG_LVT_TIMER: u16 = 0x320;
/// Timer Initial Count Register. Writing it (re)arms the timer.
const REG_TICR: u16 = 0x380;
/// Timer Current Count Register. Read-only down-counter; the elapsed count
/// within the current period is `init_count - current_count`.
const REG_CCR: u16 = 0x390;
/// Timer Divide Configuration Register. Selects the input-clock divisor.
const REG_DCR: u16 = 0x3E0;

/// Base MSR index for x2APIC registers: `0x800 + (offset >> 4)`.
const X2APIC_MSR_BASE: u32 = 0x800;

/// IA32_APIC_BASE MSR bit 11: APIC global enable. Must be set for any LAPIC
/// access (MMIO or MSR) to be valid.
const APIC_BASE_ENABLE: u64 = 1 << 11;
/// IA32_APIC_BASE MSR bit 10: x2APIC mode enable. Setting it switches the
/// register interface from MMIO to MSRs and disables MMIO access.
const APIC_BASE_X2APIC: u64 = 1 << 10;

/// Mask of the LAPIC MMIO physical base in IA32_APIC_BASE (bits 12..=35).
const APIC_BASE_PHYS_MASK: u64 = 0x0000_000F_FFFF_F000;

/// LVT Timer mask bit (bit 16). Set blocks timer-interrupt delivery.
const LVT_MASK: u64 = 1 << 16;
/// LVT Timer mode field shift (bits 17..18).
const LVT_MODE_SHIFT: u64 = 17;
/// One-shot mode: count to zero, fire once, stop.
const LVT_MODE_ONESHOT: u64 = 0b00 << LVT_MODE_SHIFT;
/// Periodic mode: count to zero, fire, reload, repeat.
const LVT_MODE_PERIODIC: u64 = 0b01 << LVT_MODE_SHIFT;

/// Divide Configuration Register value for "divide by 1". The DCR encoding is
/// notoriously inconsistent between sources; this value follows the common
/// OsDev interpretation used by most bare-metal kernels. Because calibration
/// measures the effective post-divisor rate, the exact divisor only affects
/// granularity, not the ns conversion — see the module docs.
const DCR_DIVIDE_1: u64 = 0b1011;

/// The spurious-interrupt vector programmed into SVR when the timer driver
/// enables the APIC. The full LAPIC bring-up (error vector, LVT entries) is
/// owned by the apic phase; this is the minimal SVR write that makes the
/// timer run, with spurious delivery routed to a harmless high vector.
const SPURIOUS_VECTOR: u64 = 0xFF;
/// SVR image: spurious vector + APIC software-enable (bit 8). Focus-processor
/// checking (bit 9) is left at its default.
const SVR_ENABLE: u64 = SPURIOUS_VECTOR | (1 << 8);

/// Build an LVT timer image from its vector, mode field, and mask state.
/// Keeping the packing in one pure helper makes the hardware bit positions
/// directly testable without touching privileged LAPIC registers.
#[inline]
const fn encode_lvt(vector: u8, mode: u64, masked: bool) -> u64 {
    vector as u64 | mode | if masked { LVT_MASK } else { 0 }
}

/// The maximum initial count used for calibration. With a ~1 GHz LAPIC tick
/// this represents ~4.3 s of countdown, far longer than the calibration
/// window (a few tens of milliseconds of PIT wraps), so the one-shot never
/// reaches zero and fires no interrupt during measurement.
#[allow(dead_code)]
const MAX_COUNT: u64 = 0xFFFF_FFFF;

// ---------------------------------------------------------------------------
// Access mode
// ---------------------------------------------------------------------------

/// How the LAPIC registers are reached on this CPU.
///
/// Stored as an `AtomicU8` so the static can be set once in [`init`] and read
/// lock-free from [`read_reg`] / [`write_reg`] (which are called from the
/// timer IRQ handler and the monotonic-clock read path).
#[repr(u8)]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum Mode {
    /// Legacy MMIO translated through the active HHDM, with 32-bit registers
    /// on a 16-byte stride.
    Xapic = 0,
    /// x2APIC MSR interface at `0x800 + (offset >> 4)`, 64-bit registers.
    X2apic = 1,
}

impl Mode {
    /// Decode the atomic representation. Defaults to xAPIC if the stored
    /// value is out of range, which is harmless because [`init`] always
    /// stores a valid discriminant before any register access.
    #[inline]
    fn from_u8(v: u8) -> Self {
        match v {
            1 => Mode::X2apic,
            _ => Mode::Xapic,
        }
    }
}

// ---------------------------------------------------------------------------
// State
// ---------------------------------------------------------------------------

/// The active access mode. `0` (xAPIC) until [`init`] selects x2APIC; reads
/// before [`init`] are guarded by [`is_ready`] and never reach the hardware.
static LAPIC_MODE: AtomicU8 = AtomicU8::new(0);

/// The virtual address of the LAPIC MMIO window (xAPIC only). `0` until
/// [`init`] translates the physical base through the HHDM. Unused in x2APIC
/// mode, where access is via MSR.
static LAPIC_BASE_VIRT: AtomicU64 = AtomicU64::new(0);

/// `1` once [`init`] has enabled the APIC and selected an access mode. Read
/// by [`is_ready`] so callers can short-circuit before the LAPIC is usable.
static LAPIC_READY: AtomicU8 = AtomicU8::new(0);

/// The calibrated LAPIC timer tick rate in ticks per second (post-divisor).
/// Set by [`set_frequency`] after [`super::calibration`] measures it, and
/// read by [`LapicClock::read_ns`] to convert accumulated ticks to ns.
static LAPIC_FREQ: AtomicU64 = AtomicU64::new(0);

/// The current periodic initial-count value. Used by [`LapicClock::read_ns`]
/// to turn the down-counter's current-count reading into an elapsed-tick
/// count within the current period. Only meaningful in periodic mode.
static LAPIC_INIT_COUNT: AtomicU64 = AtomicU64::new(0);

/// The accumulated periodic-tick count. Bumped by [`on_tick`] from the
/// timer's IRQ handler and read by [`LapicClock::read_ns`]. Relaxed ordering
/// is sufficient: the read path pairs it with a current-count sample and a
/// re-read to defeat the IRQ race.
static LAPIC_TICKS: AtomicU64 = AtomicU64::new(0);

// ---------------------------------------------------------------------------
// Low-level register access
// ---------------------------------------------------------------------------

/// Read the LAPIC register at `offset`, dispatching to MSR or MMIO per the
/// mode selected in [`init`].
///
/// For xAPIC the register is 32-bit and is zero-extended to `u64`. For x2APIC
/// the full 64-bit MSR value is returned.
///
/// # Panics
///
/// In debug builds, asserts that the LAPIC has been initialised so a
/// pre-init access is caught loudly rather than reading garbage through a
/// null MMIO base.
#[inline]
fn read_reg(offset: u16) -> u64 {
    debug_assert!(is_ready(), "xenith.lapic: register read before init");
    match Mode::from_u8(LAPIC_MODE.load(Ordering::Relaxed)) {
        Mode::X2apic => {
            let msr = X2APIC_MSR_BASE + u32::from(offset >> 4);
            // SAFETY: `init` enabled x2APIC and the MSR index is derived from
            // a valid LAPIC register offset. rdmsr is privileged; we run in
            // ring 0.
            unsafe { rdmsr(msr) }
        },
        Mode::Xapic => {
            let base = LAPIC_BASE_VIRT.load(Ordering::Acquire);
            // SAFETY: `base` is the HHDM virtual address of the LAPIC's 4 KiB
            // MMIO window, mapped by Limine and validated non-zero in `init`.
            // The offset is a documented 32-bit register offset; a volatile
            // 32-bit load at an aligned MMIO address is the correct access.
            unsafe { read_volatile((base + u64::from(offset)) as *const u32) as u64 }
        },
    }
}

/// Write `value` to the LAPIC register at `offset`, dispatching to MSR or
/// MMIO per the mode selected in [`init`].
///
/// For xAPIC the low 32 bits are written (the registers are 32-bit); for
/// x2APIC the full 64-bit MSR is written.
#[inline]
fn write_reg(offset: u16, value: u64) {
    debug_assert!(is_ready(), "xenith.lapic: register write before init");
    match Mode::from_u8(LAPIC_MODE.load(Ordering::Relaxed)) {
        Mode::X2apic => {
            let msr = X2APIC_MSR_BASE + u32::from(offset >> 4);
            // SAFETY: same invariant as `read_reg`; `init` enabled x2APIC and
            // the MSR index is valid. The caller is responsible for the
            // well-formedness of `value` for the target register.
            unsafe { wrmsr(msr, value) }
        },
        Mode::Xapic => {
            let base = LAPIC_BASE_VIRT.load(Ordering::Acquire);
            // SAFETY: same MMIO invariant as `read_reg`; a volatile 32-bit
            // store at the aligned register offset is the documented access.
            unsafe { write_volatile((base + u64::from(offset)) as *mut u32, value as u32) }
        },
    }
}

// ---------------------------------------------------------------------------
// Init
// ---------------------------------------------------------------------------

/// Whether [`init`] has enabled the LAPIC and the register accessors are safe
/// to use. Callers that may run before `time::init` (e.g. an early panic
/// path) should guard on this.
#[inline]
#[must_use]
pub fn is_ready() -> bool {
    LAPIC_READY.load(Ordering::Acquire) != 0
}

/// Bring up the LAPIC timer: choose xAPIC vs. x2APIC, enable the APIC, set
/// the divide configuration, and leave the timer masked and idle.
///
/// This performs the minimal LAPIC enablement the timer needs. The full
/// LAPIC bring-up — error vector, LVT entries for non-timer local sources,
/// logical destination mode — is owned by the apic phase
/// (`arch::x86_64::interrupts::apic`); the SVR write here is the subset
/// required to make the counter run and is idempotent with that later work.
///
/// After this returns, [`read_reg`] / [`write_reg`] are usable and the timer
/// can be calibrated ([`super::calibration`]) and armed ([`set_tick`] /
/// [`arm_one_shot`] / [`arm_periodic`]).
pub fn init() {
    // Read the current IA32_APIC_BASE to learn the MMIO physical base and the
    // existing enable state. SAFETY: IA32_LAPIC_BASE is a valid MSR on every
    // x86_64 part; ring 0.
    let base_msr = unsafe { IA32_LAPIC_BASE.read() };

    // Probe x2APIC once. CPUID is non-privileged; `has_x2apic` is a safe
    // wrapper that guards against parts without leaf 1.
    let x2 = has_x2apic();

    // Enable the APIC, selecting x2APIC if available. Setting bit 10 switches
    // the interface to MSRs and disables MMIO; we must do this before any
    // further access so the mode is consistent with what `write_reg` will use.
    let mut new_msr = (base_msr | APIC_BASE_ENABLE) & !APIC_BASE_X2APIC;
    if x2 {
        new_msr |= APIC_BASE_X2APIC;
    }
    // SAFETY: enabling the APIC is a standard bring-up step; the MSR value
    // keeps the existing physical base and only sets the enable bits. Ring 0.
    unsafe { IA32_LAPIC_BASE.write(new_msr) };

    // Refuse register access if the selected interface did not latch. The
    // architectural LAPIC driver performs the same check earlier; retaining
    // it here keeps this timer backend safe when initialized independently.
    // SAFETY: same architectural MSR at CPL0.
    let verify = unsafe { IA32_LAPIC_BASE.read() };
    let expected_mode = if x2 { APIC_BASE_X2APIC } else { 0 };
    if verify & APIC_BASE_ENABLE == 0 || verify & APIC_BASE_X2APIC != expected_mode {
        LAPIC_READY.store(0, Ordering::Release);
        ::log::error!(
            "xenith.time.lapic: IA32_APIC_BASE refused {} enable (read back {:#x})",
            if x2 { "x2APIC" } else { "xAPIC" },
            verify
        );
        return;
    }
    let phys_base = verify & APIC_BASE_PHYS_MASK;

    if x2 {
        LAPIC_MODE.store(Mode::X2apic as u8, Ordering::Release);
        // No MMIO window in x2APIC; store a non-zero sentinel so `is_ready`
        // and any diagnostic that reads the base does not mistake the 0 for
        // "uninitialised". The value is never dereferenced in this mode.
        LAPIC_BASE_VIRT.store(0x1, Ordering::Release);
    } else {
        if phys_base == 0 {
            LAPIC_READY.store(0, Ordering::Release);
            ::log::error!(
                "xenith.time.lapic: invalid zero xAPIC base in IA32_APIC_BASE={:#x}",
                verify
            );
            return;
        }
        LAPIC_MODE.store(Mode::Xapic as u8, Ordering::Release);
        let virt = crate::mm::phys_to_virt(PhysAddr::new_truncate(phys_base)).as_u64();
        LAPIC_BASE_VIRT.store(virt, Ordering::Release);
    }

    // Mark the LAPIC usable before the first register write so the
    // debug_assert in read_reg/write_reg is satisfied.
    LAPIC_READY.store(1, Ordering::Release);

    // Enable the APIC via the Spurious Interrupt Vector Register. Until bit 8
    // of SVR is set the LAPIC is in software-disabled state and the timer
    // does not count. The spurious vector is a harmless high vector; the apic
    // phase may rewrite SVR later with its own spurious-handler routing.
    write_reg(REG_SVR, SVR_ENABLE);

    // Program the divide configuration once. The divisor is the same for
    // calibration and runtime, so the calibrated rate is the runtime rate.
    write_reg(REG_DCR, DCR_DIVIDE_1);

    // Leave the timer masked and idle. Calibration arms it temporarily;
    // `set_tick` / `arm_*` arm it for real.
    write_reg(REG_LVT_TIMER, encode_lvt(0, LVT_MODE_ONESHOT, true));
    write_reg(REG_TICR, 0);

    ::log::info!(
        "xenith.time.lapic: APIC {} at phys {:#x}, timer ready (masked)",
        if x2 { "x2APIC" } else { "xAPIC" },
        phys_base,
    );
}

// ---------------------------------------------------------------------------
// Calibration primitives
// ---------------------------------------------------------------------------

/// Read the timer's current down-count.
///
/// The counter counts down from the initial count towards zero; the elapsed
/// count within the current period is `init_count - read_current_count()`.
/// Used by the calibration routine and by [`LapicClock::read_ns`].
#[inline]
#[must_use]
pub fn read_current_count() -> u64 {
    read_reg(REG_CCR)
}

/// Arm a one-shot countdown of `count` LAPIC ticks, delivering `vector` on
/// expiry. The timer is left **unmasked** so the counter actually runs; the
/// caller is responsible for ensuring `vector` has a handler installed or
/// that the count is large enough that expiry will not occur within the
/// intended window (the calibration path relies on the latter).
///
/// This is the raw primitive the calibration routine drives; the typed
/// [`arm_one_shot`] is the public scheduler-facing API.
pub fn arm_one_shot_raw(count: u64, vector: u8) {
    // Program the LVT entry first (mode + vector, unmasked), then the initial
    // count. Writing TICR (re)starts the countdown, so it must come last.
    write_reg(REG_LVT_TIMER, encode_lvt(vector, LVT_MODE_ONESHOT, false));
    write_reg(REG_TICR, count);
}

/// Mask (disarm) the timer. A masked timer stops counting and cannot fire;
/// used by calibration to quiesce the counter after measurement.
pub fn mask() {
    write_reg(REG_LVT_TIMER, encode_lvt(0, LVT_MODE_ONESHOT, true));
    write_reg(REG_TICR, 0);
}

/// Record the calibrated LAPIC tick rate, in ticks per second. Called by
/// [`super::calibration`] once the rate has been measured against the PIT.
/// Also used by [`LapicClock::read_ns`] for the ns conversion.
pub fn set_frequency(ticks_per_sec: u64) {
    LAPIC_FREQ.store(ticks_per_sec, Ordering::Release);
}

/// The calibrated LAPIC tick rate in ticks per second, or zero if not yet
/// calibrated.
#[inline]
#[must_use]
pub fn frequency() -> u64 {
    LAPIC_FREQ.load(Ordering::Acquire)
}

// ---------------------------------------------------------------------------
// Public arming API
// ---------------------------------------------------------------------------

/// Programme a periodic tick at `freq_hz` Hz, delivering `vector` on each
/// expiry.
///
/// The initial count is `frequency() / freq_hz`, where `frequency()` is the
/// calibrated LAPIC tick rate. The timer is armed unmasked, so the first
/// tick fires after one full period. [`LAPIC_INIT_COUNT`] is updated so
/// [`LapicClock::read_ns`] can resolve sub-tick elapsed time.
///
/// # Panics
///
/// In debug builds, asserts the LAPIC has been calibrated (frequency != 0)
/// so a pre-calibration arm is caught. A zero `freq_hz` is a no-op.
pub fn set_tick(freq_hz: u64, vector: u8) {
    if freq_hz == 0 {
        return;
    }
    let freq = frequency();
    debug_assert!(freq != 0, "xenith.time.lapic: set_tick before calibration");
    let count = freq / freq_hz;
    arm_periodic(vector, count);
}

/// Arm a periodic countdown of `count` LAPIC ticks, delivering `vector` on
/// each expiry and reloading `count` after each zero. The timer is left
/// unmasked. Updates [`LAPIC_INIT_COUNT`] for the monotonic clocksource.
pub fn arm_periodic(vector: u8, count: u64) {
    let count = if count == 0 { 1 } else { count };
    LAPIC_INIT_COUNT.store(count, Ordering::Release);
    write_reg(REG_LVT_TIMER, encode_lvt(vector, LVT_MODE_PERIODIC, false));
    write_reg(REG_TICR, count);
}

/// Arm a one-shot countdown of `count` LAPIC ticks, delivering `vector` once.
/// The timer is left unmasked; after expiry the counter halts at zero until
/// re-armed. This is the scheduler's deadline primitive.
///
/// Note: a one-shot armed timer does not advance [`LAPIC_TICKS`], so the
/// [`LapicClock`] monotonic read is only meaningful while a periodic tick is
/// running. Callers that need monotonic time across a one-shot window should
/// read the clock before re-arming.
pub fn arm_one_shot(vector: u8, count: u64) {
    let count = if count == 0 { 1 } else { count };
    write_reg(REG_LVT_TIMER, encode_lvt(vector, LVT_MODE_ONESHOT, false));
    write_reg(REG_TICR, count);
}

// ---------------------------------------------------------------------------
// IRQ-handler hooks
// ---------------------------------------------------------------------------

/// Record one periodic timer tick. Called by the timer-vector IRQ handler
/// (wired by the scheduler phase) **before** sending EOI. The increment is
/// `Relaxed`: the monotonic read path defeats the IRQ race with a
/// double-read, so no stronger ordering is needed here.
pub fn on_tick() {
    LAPIC_TICKS.fetch_add(1, Ordering::Relaxed);
}

/// Send End-of-Interrupt to the LAPIC, acknowledging the current interrupt.
/// Called by the timer-vector IRQ handler after [`on_tick`]. A write of any
/// value to the EOI register clears the IRR bit; zero is conventional.
pub fn send_eoi() {
    write_reg(REG_EOI, 0);
}

// ---------------------------------------------------------------------------
// LAPIC monotonic clocksource
// ---------------------------------------------------------------------------

/// A [`ClockSource`] backed by the LAPIC timer's periodic-tick accumulator.
///
/// `read_ns` combines the accumulated tick count ([`LAPIC_TICKS`]) with the
/// sub-tick elapsed count read from the current-count register, producing a
/// monotonic nanosecond count via the calibrated [`LAPIC_FREQ`]. The read is
/// made consistent against the IRQ race by sampling the tick counter before
/// and after the current-count read and retrying if it changed.
///
/// The clocksource is only meaningful while the timer is armed in periodic
/// mode with [`on_tick`] wired to the timer vector. Before that it returns
/// zero (or a stale value), matching the PIT clocksource's pre-IRQ behaviour.
pub struct LapicClock;

impl ClockSource for LapicClock {
    fn read_ns(&self) -> u64 {
        let freq = LAPIC_FREQ.load(Ordering::Acquire);
        let init = LAPIC_INIT_COUNT.load(Ordering::Acquire);
        if freq == 0 || init == 0 {
            // Not calibrated or not armed in periodic mode yet.
            return 0;
        }

        // Seqlock-free consistent read: sample the tick counter, read the
        // down-counter, then re-sample the tick counter. If an IRQ fired
        // between the two samples the counts disagree and we retry — the
        // current-count reading would otherwise straddle a period boundary
        // and produce a value that jumps backwards. The window is one MMIO
        // read, so the loop almost always exits on the first iteration.
        for _ in 0..8 {
            let ticks0 = LAPIC_TICKS.load(Ordering::Relaxed);
            let ccr = read_reg(REG_CCR);
            let ticks1 = LAPIC_TICKS.load(Ordering::Relaxed);
            if ticks0 == ticks1 {
                // Elapsed ticks within the current period. ccr counts down
                // from init to 0, so the elapsed portion is init - ccr. A ccr
                // reading of init (just reloaded) yields zero elapsed, which
                // is correct.
                let sub = init.saturating_sub(ccr);
                let total_ticks = ticks0.saturating_mul(init).saturating_add(sub);
                return total_ticks.saturating_mul(1_000_000_000) / freq;
            }
            core::hint::spin_loop();
        }
        // Degenerate case: the IRQ rate is so high that 8 retries all raced
        // (effectively impossible for a scheduler tick). Return the best
        // estimate from the last samples rather than spinning indefinitely.
        let ticks = LAPIC_TICKS.load(Ordering::Relaxed);
        ticks.saturating_mul(1_000_000_000) / freq
    }

    fn name(&self) -> &'static str {
        "lapic"
    }
}

/// The single LAPIC-backed clocksource instance. Installed as the active
/// monotonic source by `time::init` when no HPET is available.
pub static LAPIC_CLOCK: LapicClock = LapicClock;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn lvt_timer_encoding_uses_architectural_bit_positions() {
        let periodic = encode_lvt(0xFD, LVT_MODE_PERIODIC, false);
        assert_eq!(periodic & 0xFF, 0xFD);
        assert_eq!(periodic & (0b11 << 17), 0b01 << 17);
        assert_eq!(periodic & (1 << 16), 0);

        let masked = encode_lvt(0, LVT_MODE_ONESHOT, true);
        assert_ne!(masked & (1 << 16), 0);
        assert_eq!(masked & (0b11 << 17), 0);
    }
}
