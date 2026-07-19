//! Local APIC (LAPIC) driver — x2APIC MSRs with an xAPIC MMIO fallback.
//!
//! The local APIC is the per-CPU interrupt controller that delivers timer
//! ticks, inter-processor interrupts, and locally-routed IRQs. Modern x86
//! exposes two programming interfaces for it:
//!
//! * **xAPIC** — the classic MMIO interface at physical `0xFEE0_0000`, where
//!   each register is a 32-bit window accessed through a 4 KiB mapping. The
//!   APIC ID is 8 bits, exposing at most 256 physical destination IDs.
//! * **x2APIC** — the MSR interface at `0x800..=0x8FF`, available when
//!   CPUID.01H:ECX[21] is set. The APIC ID widens to 32 bits and every
//!   register becomes a single `rdmsr`/`wrmsr` pair, so no MMIO mapping is
//!   required. The Interrupt Command Register collapses from two 32-bit
//!   MMIO words into one 64-bit MSR.
//!
//! Xenith prefers x2APIC whenever the CPU advertises it: it removes the
//! 255-CPU ceiling and avoids MMIO traffic. Otherwise it enables legacy
//! xAPIC, validates the page-aligned physical base from `IA32_APIC_BASE`, and
//! reaches that 4 KiB register window through the kernel HHDM. xAPIC routing
//! explicitly rejects destination IDs above 255 rather than truncating them.
//!
//! # MSR address derivation
//!
//! Every x2APIC register lives at `MSR 0x800 + (xAPIC_mmio_offset >> 4)`.
//! Thus the APIC ID (xAPIC offset `0x020`) is MSR `0x802`, the EOI (xAPIC
//! offset `0x0B0`) is MSR `0x80B`, the Spurious Vector Register (offset
//! `0x0F0`) is MSR `0x80F`, and so on. See Intel SDM Vol 3A §10.12.1,
//! Table 10-12. The constants below are `Msr` newtypes so an index can
//! never be confused with a value at the call site.
//!
//! # Bring-up sequence
//!
//! [`init`] runs once per CPU (the BSP during normal boot and APs from the SMP
//! entry path) and performs:
//!
//! 1. Detect x2APIC via CPUID.01H:ECX[21] and read `IA32_APIC_BASE`
//!    (MSR `0x1B`) to confirm the APIC is present.
//! 2. Enable the global APIC bit and select x2APIC when available; otherwise
//!    retain xAPIC and translate its physical register page through the HHDM.
//! 3. Programme the Spurious Interrupt Vector Register (SVR)
//!    with vector `0xFF` and the APIC-software-enable bit (bit 8). Until
//!    SVR is enabled the LAPIC silently drops every interrupt.
//! 4. Mask and vector every LVT entry: the timer, LINT0, LINT1, and the
//!    error register. Masking here prevents a spurious LVT interrupt from
//!    firing before its handler is wired up; scheduler timer setup later
//!    installs the gate and unmasks the timer.
//! 5. Clear the Error Status Register (ESR) so any stale firmware error
//!    bits do not trigger an immediate error interrupt once that LVT entry
//!    is unmasked.
//! 6. Park the timer (zero initial count, divide-by-1) until the scheduler
//!    timer setup arms it.
//!
//! After [`init`] returns, [`send_eoi`] and [`send_ipi`] are usable on the
//! calling CPU. Maskable IRQs are still off at this point; `sti` happens
//! later in the boot sequence.
//!
//! # Safety
//!
//! MSR access is privileged and xAPIC registers are volatile 32-bit MMIO.
//! The driver selects exactly one interface before touching controller
//! registers. The MMIO path additionally requires the boot HHDM to cover the
//! physical APIC page with device-compatible memory attributes. Each `unsafe`
//! block below cites the specific invariant it relies on.

use core::ptr::{read_volatile, write_volatile};
use core::sync::atomic::{AtomicU64, AtomicU8, Ordering};

use xenith_bitflags::bitflags;
use xenith_types::PhysAddr;

use super::super::cpu::has_x2apic;
use super::super::msr::{Msr, IA32_LAPIC_BASE};

// ---------------------------------------------------------------------------
// IA32_APIC_BASE MSR (0x1B) bit encoding
// ---------------------------------------------------------------------------

/// IA32_APIC_BASE bit 8 — boot strap processor flag. Set by the CPU on the
/// BSP; read-only from ring 0. Preserved across the x2APIC enable write.
const APIC_BASE_BSP: u64 = 1 << 8;
/// IA32_APIC_BASE bit 10 — x2APIC enable. Setting this (with bit 11 also
/// set) switches the LAPIC from MMIO to MSR access. The two enable bits
/// must transition APIC-disabled → xAPIC (bit 11 only) → x2APIC (bits 10
/// and 11); because firmware leaves the APIC globally enabled, ORing bit
/// 10 in is the correct single-step move into x2APIC mode.
const APIC_BASE_X2APIC: u64 = 1 << 10;
/// IA32_APIC_BASE bit 11 — APIC global enable. Must be set for either xAPIC
/// or x2APIC mode to function; clearing it disables the LAPIC entirely.
const APIC_BASE_ENABLE: u64 = 1 << 11;

/// Physical xAPIC register-page address in `IA32_APIC_BASE` (bits 12..=35).
const APIC_BASE_PHYS_MASK: u64 = 0x0000_000F_FFFF_F000;
/// Size and alignment of the legacy xAPIC MMIO register window.
const XAPIC_MMIO_PAGE_SIZE: u64 = 4096;

// ---------------------------------------------------------------------------
// xAPIC MMIO register map (32-bit registers on 16-byte boundaries)
// ---------------------------------------------------------------------------

const XAPIC_APICID: u16 = 0x020;
const XAPIC_VERSION: u16 = 0x030;
const XAPIC_TPR: u16 = 0x080;
const XAPIC_EOI: u16 = 0x0B0;
const XAPIC_LDR: u16 = 0x0D0;
const XAPIC_SVR: u16 = 0x0F0;
const XAPIC_ESR: u16 = 0x280;
const XAPIC_ICR_LOW: u16 = 0x300;
const XAPIC_ICR_HIGH: u16 = 0x310;
const XAPIC_LVT_TIMER: u16 = 0x320;
const XAPIC_LVT_LINT0: u16 = 0x350;
const XAPIC_LVT_LINT1: u16 = 0x360;
const XAPIC_LVT_ERROR: u16 = 0x370;
const XAPIC_TIMER_INIT: u16 = 0x380;
const XAPIC_TIMER_CUR: u16 = 0x390;
const XAPIC_TIMER_DIV: u16 = 0x3E0;

/// ICR-low bit 12: set while an xAPIC IPI is pending delivery.
const XAPIC_ICR_DELIVERY_PENDING: u32 = 1 << 12;
/// Bound a failed controller instead of spinning forever with interrupts off.
const XAPIC_ICR_POLL_LIMIT: usize = 1_000_000;

/// Validate a bare legacy-APIC physical base.
#[inline]
const fn validate_xapic_phys_base(base: u64) -> Option<u64> {
    if base == 0 || base & (XAPIC_MMIO_PAGE_SIZE - 1) != 0 || base & !APIC_BASE_PHYS_MASK != 0 {
        None
    } else {
        Some(base)
    }
}

/// Extract the page-aligned xAPIC physical base from `IA32_APIC_BASE`.
#[inline]
const fn xapic_phys_base_from_msr(msr: u64) -> Option<u64> {
    validate_xapic_phys_base(msr & APIC_BASE_PHYS_MASK)
}

/// Resolve one documented xAPIC register to its physical MMIO address.
#[inline]
const fn xapic_register_phys(base: u64, offset: u16) -> Option<u64> {
    if validate_xapic_phys_base(base).is_none()
        || offset & 0xF != 0
        || offset as u64 >= XAPIC_MMIO_PAGE_SIZE
    {
        return None;
    }
    base.checked_add(offset as u64)
}

// ---------------------------------------------------------------------------
// x2APIC MSR address map (Intel SDM Vol 3A, §10.12.1, Table 10-12)
// ---------------------------------------------------------------------------

/// Local APIC ID register (read-only). Holds the 32-bit x2APIC ID in
/// bits 0..31; the upper 32 bits are reserved zero. Mapped from xAPIC
/// MMIO offset `0x020`.
const X2APIC_APICID: Msr = Msr::new(0x802);
/// Local APIC version register (read-only). Low byte = version, bits 16..23
/// = maximum LVT entry index (count = field + 1), bit 31 = EOI-broadcast
/// suppression support. Mapped from xAPIC offset `0x030`.
const X2APIC_VERSION: Msr = Msr::new(0x803);
/// Task Priority Register (read/write). Bits 4..7 are the interrupt class,
/// bits 0..3 the sub-priority; the LAPIC will not deliver an interrupt
/// whose vector's class is strictly lower than the TPR class, so writing a
/// high TPR masks low-priority IRQs. Mapped from xAPIC offset `0x080`.
const X2APIC_TPR: Msr = Msr::new(0x808);
/// End-of-Interrupt register (write-only). Writing any value —
/// conventionally zero — signals that the current in-service interrupt is
/// handled. Mapped from xAPIC MMIO offset `0x0B0`, i.e. MSR `0x80B`.
const X2APIC_EOI: Msr = Msr::new(0x80B);
/// Logical Destination Register (read-only in x2APIC). The system assigns a
/// 32-bit logical ID at enable time; unlike xAPIC it cannot be written.
/// Mapped from xAPIC offset `0x0D0`.
const X2APIC_LDR: Msr = Msr::new(0x80D);
/// Spurious Interrupt Vector Register (read/write). Bits 0..7 are the
/// spurious vector, bit 8 is the APIC software-enable. Every other bit is
/// reserved. Mapped from xAPIC offset `0x0F0`.
const X2APIC_SVR: Msr = Msr::new(0x80F);
/// Error Status Register (read/write). Read to obtain the last error
/// bitmap; write 0 to clear. The error LVT entry vectors the resulting
/// interrupt. Mapped from xAPIC offset `0x280`.
const X2APIC_ESR: Msr = Msr::new(0x828);
/// Interrupt Command Register (64-bit, read/write). Writing this MSR sends
/// an IPI: bits 0..7 vector, 8..10 delivery mode, 11 dest mode, 18..19
/// shorthand, 32..63 the 32-bit destination. Unlike xAPIC the destination
/// is a single 32-bit field in the upper half. Mapped from xAPIC offsets
/// `0x300`/`0x310`.
const X2APIC_ICR: Msr = Msr::new(0x830);
/// LVT Timer register (read/write). Vector in 0..7, mask in bit 16, timer
/// mode in bits 17..18 (00 one-shot, 01 periodic, 10 TSC-deadline). Mapped
/// from xAPIC offset `0x320`.
const X2APIC_LVT_TIMER: Msr = Msr::new(0x832);
/// LVT LINT0 register. Routes the legacy LINT0 pin (typically the 8259 PIC
/// pass-through when ExtINT delivery is selected). Mapped from offset
/// `0x350`.
const X2APIC_LVT_LINT0: Msr = Msr::new(0x835);
/// LVT LINT1 register. Routes the legacy LINT1 pin (typically NMI). Mapped
/// from offset `0x360`.
const X2APIC_LVT_LINT1: Msr = Msr::new(0x836);
/// LVT Error register. Vectors the interrupt raised when the LAPIC detects
/// an internal error (illegal register access, receive checksum, ...).
/// Mapped from offset `0x370`.
const X2APIC_LVT_ERROR: Msr = Msr::new(0x837);
/// Timer initial count (read/write). The timer counts down from this
/// value; on reaching zero it fires the LVT-timer vector and, in periodic
/// mode, reloads. Mapped from offset `0x380`.
const X2APIC_TIMER_INIT: Msr = Msr::new(0x838);
/// Timer current count (read-only). Returns the live countdown value.
/// Mapped from offset `0x390`.
const X2APIC_TIMER_CUR: Msr = Msr::new(0x839);
/// Timer divide configuration (read/write). Bits 0..1 and bit 3 together
/// encode the divide value (1, 2, 4, 8, 16, 32, 64, 128). Mapped from
/// offset `0x3E0`.
const X2APIC_TIMER_DIV: Msr = Msr::new(0x83E);
/// Self-IPI register (write-only). Writing the vector sends a fixed,
/// edge-triggered IPI to the current CPU — a faster, single-MSR alternative
/// to building an ICR value with the self shorthand. Mapped from offset
/// `0x3F0`.
const X2APIC_SELF_IPI: Msr = Msr::new(0x83F);

// ---------------------------------------------------------------------------
// Fixed vector assignments
// ---------------------------------------------------------------------------
//
// These fixed assignments live at the top of the IRQ range (32..=255). The
// scheduler imports TIMER_VECTOR as its LAPIC tick ABI; the other two remain
// local-controller reservations.

/// Spurious-interrupt vector. The LAPIC delivers this vector when an
/// interrupt is raised but its source has been retracted before delivery
/// (e.g. a device de-asserts between the IRR and IRR-to-ISR promotion).
/// `0xFF` is the architectural convention (Linux, KVM, OVMF all use it).
pub const SPURIOUS_VECTOR: u8 = 0xFF;
/// Reserved LVT error vector. The error LVT remains masked because Xenith does
/// not yet install an ESR-reporting handler.
pub const ERROR_VECTOR: u8 = 0xFE;
/// LVT timer vector. The scheduler tick handler is installed at this vector
/// during scheduler initialization; the timer LVT is left masked here so no
/// tick fires before that gate exists.
pub const TIMER_VECTOR: u8 = 0xFD;

/// SVR bit 8 — APIC software enable. Without this bit the LAPIC drops every
/// incoming interrupt regardless of the LVT configuration.
const SVR_APIC_ENABLE: u64 = 1 << 8;

// ---------------------------------------------------------------------------
// Timer divide encodings (bits 0, 1, 3 of the divide config register)
// ---------------------------------------------------------------------------

/// Divide the timer input clock by 1 (encoding `0b1011`).
pub const TIMER_DIV_1: u8 = 0b1011;
/// Divide by 2 (encoding `0b0000`).
pub const TIMER_DIV_2: u8 = 0b0000;
/// Divide by 4 (encoding `0b0001`).
pub const TIMER_DIV_4: u8 = 0b0001;
/// Divide by 8 (encoding `0b0010`).
pub const TIMER_DIV_8: u8 = 0b0010;
/// Divide by 16 (encoding `0b0011`).
pub const TIMER_DIV_16: u8 = 0b0011;
/// Divide by 32 (encoding `0b1000`).
pub const TIMER_DIV_32: u8 = 0b1000;
/// Divide by 64 (encoding `0b1001`).
pub const TIMER_DIV_64: u8 = 0b1001;
/// Divide by 128 (encoding `0b1010`).
pub const TIMER_DIV_128: u8 = 0b1010;

// ---------------------------------------------------------------------------
// LVT field encodings
// ---------------------------------------------------------------------------

bitflags! {
    /// Mode bits shared by every LVT entry (timer, LINT0, LINT1, error).
    ///
    /// The 64-bit LVT layout (Intel SDM §10.8.1) places the vector in
    /// bits 0..7, the delivery mode in 8..10, the mask in bit 16, and — for
    /// the timer — the mode in bits 17..18. LINT entries additionally carry
    /// polarity (bit 14) and trigger mode (bit 15). Only the bits the kernel
    /// actually programmes are named here; reserved fields stay zero.
    pub struct LvtFlags: u64 {
        /// Delivery Mode = Fixed (bits 8..10 = 000). The default for the
        /// timer and error entries.
        const DELIVERY_FIXED     = 0b000 << 8;
        /// Delivery Mode = SMI (bits 8..10 = 010).
        const DELIVERY_SMI       = 0b010 << 8;
        /// Delivery Mode = NMI (bits 8..10 = 100). Used for LINT1.
        const DELIVERY_NMI       = 0b100 << 8;
        /// Delivery Mode = INIT (bits 8..10 = 101).
        const DELIVERY_INIT      = 0b101 << 8;
        /// Delivery Mode = ExtINT (bits 8..10 = 111). Used for LINT0 when
        /// the 8259 PIC is the interrupt source.
        const DELIVERY_EXTINT    = 0b111 << 8;
        /// Pin polarity active-low (bit 14). Absence means active-high.
        /// Only meaningful for LINT entries.
        const POLARITY_LOW       = 1 << 14;
        /// Trigger mode level (bit 15). Absence means edge. Only meaningful
        /// for LINT entries.
        const TRIGGER_LEVEL      = 1 << 15;
        /// Mask the entry (bit 16). Set to block the LVT source from
        /// delivering; mandatory during bring-up before the handler is wired.
        const MASKED             = 1 << 16;
        /// Timer mode = periodic (bits 17..18 = 01). Absence means one-shot.
        const TIMER_PERIODIC     = 0b01 << 17;
        /// Timer mode = TSC-deadline (bits 17..18 = 10). The timer fires
        /// when the IA32_TSC_DEADLINE MSR is reached instead of counting
        /// down a bus-clock divisor.
        const TIMER_TSC_DEADLINE = 0b10 << 17;
    }
}

/// A fully-encoded LVT entry value: vector plus mode flags.
///
/// Construct with [`LvtEntry::new`]; [`to_u64`](Self::to_u64) produces the
/// value written to the matching x2APIC MSR or xAPIC MMIO register.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct LvtEntry {
    /// The 8-bit interrupt vector. Must be `>= 0x20` to avoid the
    /// CPU-exception range.
    vector: u8,
    /// Delivery mode, polarity, trigger mode, mask, and timer-mode bits.
    flags: LvtFlags,
}

impl LvtEntry {
    /// Build an LVT entry from a vector and a flag set.
    #[inline]
    #[must_use]
    pub const fn new(vector: u8, flags: LvtFlags) -> Self {
        Self { vector, flags }
    }

    /// The 64-bit MSR value for this entry.
    #[inline]
    #[must_use]
    pub const fn to_u64(self) -> u64 {
        self.vector as u64 | self.flags.bits()
    }

    /// A copy of this entry with the mask bit set.
    #[inline]
    #[must_use]
    pub fn masked(self) -> Self {
        let mut f = self.flags;
        f.insert(LvtFlags::MASKED);
        Self { flags: f, ..self }
    }

    /// A copy of this entry with the mask bit cleared.
    #[inline]
    #[must_use]
    pub fn unmasked(self) -> Self {
        let mut f = self.flags;
        f.remove(LvtFlags::MASKED);
        Self { flags: f, ..self }
    }

    /// Whether the mask bit is currently set.
    #[inline]
    #[must_use]
    pub const fn is_masked(self) -> bool {
        self.flags.contains(LvtFlags::MASKED)
    }
}

// ---------------------------------------------------------------------------
// ICR field encodings
// ---------------------------------------------------------------------------

bitflags! {
    /// Control bits shared by xAPIC ICR-low and the 64-bit x2APIC ICR.
    ///
    /// The ICR low 32 bits mirror the xAPIC ICR-low layout (vector,
    /// delivery mode, destination mode, shorthand); the upper 32 bits carry
    /// the full 32-bit destination, replacing xAPIC's 8-bit high-word
    /// destination. Trigger mode (bit 15) is preserved for INIT-level IPIs
    /// but left edge (0) for normal fixed delivery. The vector itself is
    /// not a flag and is ORed in separately by the send helpers.
    pub struct IcrFlags: u64 {
        /// Delivery Mode = Fixed (bits 8..10 = 000). The default IPI.
        const DELIVERY_FIXED          = 0b000 << 8;
        /// Delivery Mode = Lowest-priority (bits 8..10 = 001). Pick the
        /// least-busy CPU in the destination set.
        const DELIVERY_LOWEST         = 0b001 << 8;
        /// Delivery Mode = SMI (bits 8..10 = 010).
        const DELIVERY_SMI            = 0b010 << 8;
        /// Delivery Mode = NMI (bits 8..10 = 100).
        const DELIVERY_NMI            = 0b100 << 8;
        /// Delivery Mode = INIT (bits 8..10 = 101). Used by SMP bring-up.
        const DELIVERY_INIT           = 0b101 << 8;
        /// Delivery Mode = Startup (bits 8..10 = 110). The SIPI delivery
        /// mode; the vector field carries the real-mode start page >> 12.
        const DELIVERY_STARTUP        = 0b110 << 8;
        /// Destination Mode = Logical (bit 11). Absence means physical.
        const DEST_LOGICAL            = 1 << 11;
        /// Level = Assert (bit 14). Used with level-triggered xAPIC INIT.
        const LEVEL_ASSERT            = 1 << 14;
        /// Trigger Mode = Level (bit 15). Absence means edge. Xenith emits
        /// only the architecturally supported INIT assert sequence.
        const TRIGGER_LEVEL           = 1 << 15;
        /// Shorthand = Self (bits 18..19 = 01). Send to the current CPU.
        const SHORTHAND_SELF          = 0b01 << 18;
        /// Shorthand = All (bits 18..19 = 10). Broadcast to every CPU.
        const SHORTHAND_ALL           = 0b10 << 18;
        /// Shorthand = All excluding self (bits 18..19 = 11).
        const SHORTHAND_ALL_EXCL_SELF = 0b11 << 18;
    }
}

/// Ordered xAPIC ICR-high/ICR-low write pair.
///
/// xAPIC starts transmission when ICR-low is written, so the 8-bit physical
/// destination in ICR-high must be published first. `destination = None` is
/// used for shorthand commands, whose destination field is ignored.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct XapicIcrWrite {
    high: u32,
    low: u32,
}

impl XapicIcrWrite {
    #[inline]
    const fn new(destination: Option<u32>, low: u64) -> Option<Self> {
        if low > u32::MAX as u64 {
            return None;
        }
        let high = match destination {
            Some(id) if id <= u8::MAX as u32 => id << 24,
            Some(_) => return None,
            None => 0,
        };
        Some(Self {
            high,
            low: low as u32,
        })
    }

    /// Hardware write order: destination first, command last (which sends).
    #[inline]
    const fn writes(self) -> [(u16, u32); 2] {
        [(XAPIC_ICR_HIGH, self.high), (XAPIC_ICR_LOW, self.low)]
    }
}

/// Volatile read from an already-validated HHDM xAPIC window.
#[inline]
unsafe fn xapic_read_at(mmio_virt: u64, offset: u16) -> u32 {
    debug_assert!(mmio_virt != 0);
    debug_assert!(offset & 0xF == 0);
    debug_assert!(u64::from(offset) < XAPIC_MMIO_PAGE_SIZE);
    // SAFETY: the caller supplies the HHDM base of the architectural xAPIC
    // page. Registers are aligned 32-bit MMIO cells on 16-byte boundaries.
    unsafe { read_volatile((mmio_virt + u64::from(offset)) as *const u32) }
}

/// Volatile write to an already-validated HHDM xAPIC window.
#[inline]
unsafe fn xapic_write_at(mmio_virt: u64, offset: u16, value: u32) {
    debug_assert!(mmio_virt != 0);
    debug_assert!(offset & 0xF == 0);
    debug_assert!(u64::from(offset) < XAPIC_MMIO_PAGE_SIZE);
    // SAFETY: same validated MMIO-window invariant as [`xapic_read_at`].
    unsafe { write_volatile((mmio_virt + u64::from(offset)) as *mut u32, value) };
}

// ---------------------------------------------------------------------------
// Operating mode
// ---------------------------------------------------------------------------

/// The LAPIC operating mode detected by [`LocalApic::init`].
///
/// Stored as a `u8` inside an [`AtomicU8`] so the static [`LAPIC`] can be
/// read without a lock. Every online CPU runs the same capability check and
/// publishes the selected backend while enabling its own local controller.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(u8)]
pub enum ApicMode {
    /// The LAPIC has not been initialised (or the CPU has no APIC at all).
    Disabled = 0,
    /// x2APIC MSR mode with 32-bit physical destination IDs.
    X2Apic = 1,
    /// Legacy xAPIC MMIO mode with 8-bit physical destination IDs.
    XApic = 2,
}

impl ApicMode {
    /// Encode the mode as an atomically-storable byte.
    #[inline]
    const fn as_u8(self) -> u8 {
        self as u8
    }

    /// Decode a stored mode byte, defaulting to [`ApicMode::Disabled`] for
    /// any value outside the enum's repr range.
    #[inline]
    fn from_u8(raw: u8) -> Self {
        match raw {
            1 => ApicMode::X2Apic,
            2 => ApicMode::XApic,
            _ => ApicMode::Disabled,
        }
    }
}

// ---------------------------------------------------------------------------
// LocalApic — the driver singleton
// ---------------------------------------------------------------------------

/// The local APIC driver.
///
/// The selected [`ApicMode`] and xAPIC HHDM base are stored atomically so the
/// same static handle can be used from every CPU and IRQ context without a
/// lock. MSR accesses and the architectural xAPIC MMIO page both address the
/// controller local to the calling CPU.
pub struct LocalApic {
    mode: AtomicU8,
    xapic_mmio_virt: AtomicU64,
}

impl LocalApic {
    /// Construct an uninitialised LAPIC handle. `const` so it can live in
    /// the [`LAPIC`] static.
    #[inline]
    #[must_use]
    pub const fn new() -> Self {
        Self {
            mode: AtomicU8::new(ApicMode::Disabled.as_u8()),
            xapic_mmio_virt: AtomicU64::new(0),
        }
    }

    /// The current operating mode. Returns [`ApicMode::Disabled`] before
    /// [`init`](Self::init) has run on this CPU.
    #[inline]
    #[must_use]
    pub fn mode(&self) -> ApicMode {
        ApicMode::from_u8(self.mode.load(Ordering::Acquire))
    }

    /// Whether x2APIC MSR mode is active on this CPU.
    #[inline]
    #[must_use]
    pub fn is_x2apic(&self) -> bool {
        matches!(self.mode(), ApicMode::X2Apic)
    }

    /// Whether either hardware backend completed initialization.
    #[inline]
    #[must_use]
    pub fn is_enabled(&self) -> bool {
        !matches!(self.mode(), ApicMode::Disabled)
    }

    /// Whether `id` can be represented by the selected physical-routing ABI.
    #[inline]
    #[must_use]
    pub fn can_route_apic_id(&self, id: u32) -> bool {
        match self.mode() {
            ApicMode::X2Apic => true,
            ApicMode::XApic => id <= u8::MAX as u32,
            ApicMode::Disabled => false,
        }
    }

    /// Bring up the local APIC on the current CPU.
    ///
    /// Detects x2APIC via CPUID and otherwise selects the legacy xAPIC MMIO
    /// interface. Both paths enable the controller, program SVR/TPR, mask all
    /// LVT entries, clear ESR, and park the timer before publishing the mode.
    /// Safe to call from ring 0 after the HHDM has been initialized.
    ///
    /// On a CPU that advertises x2APIC in CPUID but refuses the
    /// `IA32_APIC_BASE` enable write (a misconfigured hypervisor), the
    /// driver logs an error and leaves the mode [`ApicMode::Disabled`]; the
    /// kernel cannot route interrupts without a LAPIC, so the first IRQ
    /// will fault, but the failure is reported rather than panicking before
    /// the console is fully usable.
    pub fn init(&self) {
        // SAFETY: IA32_LAPIC_BASE is valid on every x86_64 CPU with a local
        // APIC. This function runs at CPL0 during BSP/AP bring-up.
        let base = unsafe { IA32_LAPIC_BASE.read() };
        let svr = u64::from(SPURIOUS_VECTOR) | SVR_APIC_ENABLE;
        let timer = LvtEntry::new(TIMER_VECTOR, LvtFlags::DELIVERY_FIXED | LvtFlags::MASKED);
        let lint0 = LvtEntry::new(0, LvtFlags::DELIVERY_EXTINT | LvtFlags::MASKED);
        let lint1 = LvtEntry::new(0, LvtFlags::DELIVERY_NMI | LvtFlags::MASKED);
        let error = LvtEntry::new(ERROR_VECTOR, LvtFlags::DELIVERY_FIXED | LvtFlags::MASKED);
        let is_bsp = (base & APIC_BASE_BSP) != 0;

        if has_x2apic() {
            let requested = base | APIC_BASE_ENABLE | APIC_BASE_X2APIC;
            // SAFETY: only the documented global/x2APIC enable bits are set;
            // every other field is preserved from the architectural MSR.
            unsafe { IA32_LAPIC_BASE.write(requested) };
            // SAFETY: same architectural MSR at CPL0.
            let verify = unsafe { IA32_LAPIC_BASE.read() };
            if verify & (APIC_BASE_ENABLE | APIC_BASE_X2APIC)
                != (APIC_BASE_ENABLE | APIC_BASE_X2APIC)
            {
                ::log::error!(
                    "xenith.apic: IA32_APIC_BASE refused x2APIC enable (read back 0x{:x})",
                    verify
                );
                self.mode
                    .store(ApicMode::Disabled.as_u8(), Ordering::Release);
                return;
            }

            // SAFETY: x2APIC is enabled and every value has reserved bits 0.
            unsafe {
                X2APIC_SVR.write(svr);
                X2APIC_TPR.write(0);
                X2APIC_LVT_TIMER.write(timer.to_u64());
                X2APIC_LVT_LINT0.write(lint0.to_u64());
                X2APIC_LVT_LINT1.write(lint1.to_u64());
                X2APIC_LVT_ERROR.write(error.to_u64());
                X2APIC_ESR.write(0);
                let _ = X2APIC_ESR.read();
                X2APIC_TIMER_DIV.write(u64::from(TIMER_DIV_1));
                X2APIC_TIMER_INIT.write(0);
            }
            self.xapic_mmio_virt.store(0, Ordering::Release);
            self.mode.store(ApicMode::X2Apic.as_u8(), Ordering::Release);
            // SAFETY: APIC ID is readable after x2APIC enablement.
            let id = unsafe { X2APIC_APICID.read() as u32 };
            ::log::info!(
                "xenith.apic: x2APIC online on {} (apic id {}), spurious vec 0x{:02X}, LVT masked",
                if is_bsp { "bsp" } else { "ap" },
                id,
                SPURIOUS_VECTOR
            );
            return;
        }

        let requested = (base | APIC_BASE_ENABLE) & !APIC_BASE_X2APIC;
        // SAFETY: preserve the architectural base/BSP fields, set global
        // enable, and explicitly keep the unsupported x2APIC bit clear.
        unsafe { IA32_LAPIC_BASE.write(requested) };
        // SAFETY: same architectural MSR at CPL0.
        let verify = unsafe { IA32_LAPIC_BASE.read() };
        if verify & APIC_BASE_ENABLE == 0 || verify & APIC_BASE_X2APIC != 0 {
            ::log::error!(
                "xenith.apic: IA32_APIC_BASE refused xAPIC enable (read back 0x{:x})",
                verify
            );
            self.mode
                .store(ApicMode::Disabled.as_u8(), Ordering::Release);
            return;
        }
        let Some(phys_base) = xapic_phys_base_from_msr(verify) else {
            ::log::error!(
                "xenith.apic: invalid xAPIC physical base in IA32_APIC_BASE=0x{:x}",
                verify
            );
            self.mode
                .store(ApicMode::Disabled.as_u8(), Ordering::Release);
            return;
        };
        if xapic_register_phys(phys_base, XAPIC_TIMER_DIV).is_none() {
            ::log::error!(
                "xenith.apic: xAPIC register page at {:#x} failed bounds validation",
                phys_base
            );
            self.mode
                .store(ApicMode::Disabled.as_u8(), Ordering::Release);
            return;
        }
        let mmio_virt = crate::mm::phys_to_virt(PhysAddr::new_truncate(phys_base)).as_u64();

        // SAFETY: `phys_base` is a non-zero, page-aligned architectural APIC
        // window and `mmio_virt` is its HHDM mapping. All accesses are aligned
        // 32-bit volatile operations to documented offsets.
        unsafe {
            xapic_write_at(mmio_virt, XAPIC_SVR, svr as u32);
            xapic_write_at(mmio_virt, XAPIC_TPR, 0);
            xapic_write_at(mmio_virt, XAPIC_LVT_TIMER, timer.to_u64() as u32);
            xapic_write_at(mmio_virt, XAPIC_LVT_LINT0, lint0.to_u64() as u32);
            xapic_write_at(mmio_virt, XAPIC_LVT_LINT1, lint1.to_u64() as u32);
            xapic_write_at(mmio_virt, XAPIC_LVT_ERROR, error.to_u64() as u32);
            xapic_write_at(mmio_virt, XAPIC_ESR, 0);
            let _ = xapic_read_at(mmio_virt, XAPIC_ESR);
            xapic_write_at(mmio_virt, XAPIC_TIMER_DIV, u32::from(TIMER_DIV_1));
            xapic_write_at(mmio_virt, XAPIC_TIMER_INIT, 0);
        }

        self.xapic_mmio_virt.store(mmio_virt, Ordering::Release);
        self.mode.store(ApicMode::XApic.as_u8(), Ordering::Release);
        // SAFETY: the xAPIC ID register is in the validated live MMIO page.
        let id = unsafe { xapic_read_at(mmio_virt, XAPIC_APICID) >> 24 };
        ::log::info!(
            "xenith.apic: xAPIC online on {} (apic id {}, phys {:#x}), spurious vec 0x{:02X}, LVT masked",
            if is_bsp { "bsp" } else { "ap" },
            id,
            phys_base,
            SPURIOUS_VECTOR
        );
    }

    #[inline]
    fn xapic_mmio_virt(&self) -> u64 {
        let base = self.xapic_mmio_virt.load(Ordering::Acquire);
        debug_assert!(base != 0, "xenith.apic: xAPIC MMIO base not published");
        base
    }

    #[inline]
    fn read_register(&self, x2apic_msr: Msr, xapic_offset: u16) -> u64 {
        match self.mode() {
            ApicMode::X2Apic => {
                // SAFETY: the selected backend guarantees this is a valid
                // x2APIC register MSR on the calling CPU.
                unsafe { x2apic_msr.read() }
            },
            ApicMode::XApic => {
                // SAFETY: initialization published the validated HHDM window
                // before publishing XApic mode.
                unsafe { xapic_read_at(self.xapic_mmio_virt(), xapic_offset) as u64 }
            },
            ApicMode::Disabled => {
                debug_assert!(self.is_enabled(), "xenith.apic: register read before init");
                0
            },
        }
    }

    #[inline]
    fn write_register(&self, x2apic_msr: Msr, xapic_offset: u16, value: u64) {
        match self.mode() {
            ApicMode::X2Apic => {
                // SAFETY: the selected backend guarantees this is a valid
                // x2APIC register MSR and the caller supplies its encoding.
                unsafe { x2apic_msr.write(value) };
            },
            ApicMode::XApic => {
                debug_assert!(value <= u64::from(u32::MAX));
                // SAFETY: initialization published the validated HHDM window
                // before publishing XApic mode; xAPIC registers are 32-bit.
                unsafe {
                    xapic_write_at(self.xapic_mmio_virt(), xapic_offset, value as u32);
                }
            },
            ApicMode::Disabled => {
                debug_assert!(self.is_enabled(), "xenith.apic: register write before init");
            },
        }
    }

    fn wait_xapic_icr_idle(&self) -> bool {
        for _ in 0..XAPIC_ICR_POLL_LIMIT {
            // SAFETY: only called in XApic mode with the validated MMIO base.
            let low = unsafe { xapic_read_at(self.xapic_mmio_virt(), XAPIC_ICR_LOW) };
            if low & XAPIC_ICR_DELIVERY_PENDING == 0 {
                return true;
            }
            core::hint::spin_loop();
        }
        false
    }

    /// Serialize one xAPIC ICR command around the delivery-status bit.
    fn send_xapic_icr(&self, destination: Option<u32>, low: u64) -> bool {
        let Some(command) = XapicIcrWrite::new(destination, low) else {
            if let Some(id) = destination {
                ::log::error!(
                    "xenith.apic: xAPIC destination {} exceeds the 8-bit routing limit",
                    id
                );
            } else {
                ::log::error!("xenith.apic: malformed xAPIC ICR command {:#x}", low);
            }
            return false;
        };
        if !self.wait_xapic_icr_idle() {
            ::log::error!("xenith.apic: xAPIC ICR remained busy before send");
            return false;
        }
        // ICR-high must be written first; ICR-low starts transmission.
        for (offset, value) in command.writes() {
            // SAFETY: both offsets are documented ICR cells in the validated
            // xAPIC page and the pure command builder bounds the destination.
            unsafe { xapic_write_at(self.xapic_mmio_virt(), offset, value) };
        }
        if !self.wait_xapic_icr_idle() {
            ::log::error!("xenith.apic: xAPIC ICR delivery did not complete");
            return false;
        }
        true
    }

    // -- register reads ---------------------------------------------------

    /// Physical APIC ID of the current CPU.
    ///
    /// x2APIC returns all 32 bits from MSR `0x802`; xAPIC returns the legacy
    /// 8-bit ID from MMIO APICID bits 24..31.
    ///
    /// # Panics (debug only)
    ///
    /// Debug-asserts that either backend completed initialization.
    #[inline]
    #[must_use]
    pub fn id(&self) -> u32 {
        debug_assert!(self.is_enabled(), "xenith.apic: id() before init");
        let raw = self.read_register(X2APIC_APICID, XAPIC_APICID) as u32;
        match self.mode() {
            ApicMode::X2Apic => raw,
            ApicMode::XApic => raw >> 24,
            ApicMode::Disabled => 0,
        }
    }

    /// The local APIC version register (low byte = version, bits 16..23 =
    /// max LVT index). Useful for capability checks; not currently used in
    /// bring-up because every x2APIC part exposes enough LVT entries.
    #[inline]
    #[must_use]
    pub fn version(&self) -> u32 {
        debug_assert!(self.is_enabled(), "xenith.apic: version() before init");
        self.read_register(X2APIC_VERSION, XAPIC_VERSION) as u32
    }

    /// Logical APIC ID assigned by the system. x2APIC returns the 32-bit LDR;
    /// xAPIC returns its legacy logical byte from bits 24..31. Xenith routes
    /// IPIs physically, so this is primarily diagnostic.
    #[inline]
    #[must_use]
    pub fn logical_id(&self) -> u32 {
        debug_assert!(self.is_enabled(), "xenith.apic: logical_id() before init");
        let raw = self.read_register(X2APIC_LDR, XAPIC_LDR) as u32;
        match self.mode() {
            ApicMode::X2Apic => raw,
            ApicMode::XApic => raw >> 24,
            ApicMode::Disabled => 0,
        }
    }

    // -- end-of-interrupt -------------------------------------------------

    /// Signal end-of-interrupt for the in-service interrupt.
    ///
    /// Every IRQ handler must call this exactly once before returning;
    /// omitting it leaves the interrupt in-service and blocks further
    /// delivery of the same vector. Both interfaces acknowledge by writing
    /// zero to EOI (MSR `0x80B` or MMIO offset `0x0B0`).
    #[inline]
    pub fn send_eoi(&self) {
        debug_assert!(self.is_enabled(), "xenith.apic: send_eoi() before init");
        self.write_register(X2APIC_EOI, XAPIC_EOI, 0);
    }

    // -- inter-processor interrupts ---------------------------------------

    /// Send a fixed, edge-triggered IPI carrying `vector` to physical APIC ID
    /// `dest`.
    ///
    /// x2APIC accepts all 32 destination bits. xAPIC accepts only `0..=255`;
    /// larger IDs are rejected without touching ICR-high. A self-target uses
    /// the backend's self-IPI mechanism.
    #[inline]
    pub fn send_ipi(&self, dest: u32, vector: u8) {
        debug_assert!(self.is_enabled(), "xenith.apic: send_ipi() before init");
        if !self.can_route_apic_id(dest) {
            ::log::error!(
                "xenith.apic: destination {} is not routable in {:?}",
                dest,
                self.mode()
            );
            return;
        }
        if dest == self.id() {
            self.send_ipi_self(vector);
            return;
        }
        let low = u64::from(vector) | IcrFlags::DELIVERY_FIXED.bits();
        match self.mode() {
            ApicMode::X2Apic => {
                // SAFETY: x2APIC ICR accepts the full 32-bit destination.
                unsafe { X2APIC_ICR.write(low | (u64::from(dest) << 32)) };
            },
            ApicMode::XApic => {
                let _ = self.send_xapic_icr(Some(dest), low);
            },
            ApicMode::Disabled => {},
        }
    }

    /// Send a fixed IPI to the current CPU.
    ///
    /// x2APIC uses its dedicated Self-IPI MSR; xAPIC serializes an ICR command
    /// with the self shorthand.
    #[inline]
    pub fn send_ipi_self(&self, vector: u8) {
        debug_assert!(
            self.is_enabled(),
            "xenith.apic: send_ipi_self() before init"
        );
        match self.mode() {
            ApicMode::X2Apic => {
                // SAFETY: SELF_IPI is valid and write-only in x2APIC mode.
                unsafe { X2APIC_SELF_IPI.write(u64::from(vector)) };
            },
            ApicMode::XApic => {
                let low = u64::from(vector)
                    | IcrFlags::DELIVERY_FIXED.bits()
                    | IcrFlags::SHORTHAND_SELF.bits();
                let _ = self.send_xapic_icr(None, low);
            },
            ApicMode::Disabled => {},
        }
    }

    /// Broadcast a fixed IPI carrying `vector` to every CPU in the system
    /// (including the sender).
    #[inline]
    pub fn send_ipi_all(&self, vector: u8) {
        debug_assert!(self.is_enabled(), "xenith.apic: send_ipi_all() before init");
        let icr =
            u64::from(vector) | IcrFlags::DELIVERY_FIXED.bits() | IcrFlags::SHORTHAND_ALL.bits();
        match self.mode() {
            ApicMode::X2Apic => {
                // SAFETY: ICR write with all shorthand and no destination.
                unsafe { X2APIC_ICR.write(icr) };
            },
            ApicMode::XApic => {
                let _ = self.send_xapic_icr(None, icr);
            },
            ApicMode::Disabled => {},
        }
    }

    /// Broadcast a fixed IPI carrying `vector` to every CPU except the
    /// sender. This is the canonical "wake all APs" broadcast.
    #[inline]
    pub fn send_ipi_all_excluding_self(&self, vector: u8) {
        debug_assert!(self.is_enabled(), "xenith.apic: broadcast before init");
        let icr = u64::from(vector)
            | IcrFlags::DELIVERY_FIXED.bits()
            | IcrFlags::SHORTHAND_ALL_EXCL_SELF.bits();
        match self.mode() {
            ApicMode::X2Apic => {
                // SAFETY: ICR write with all-excluding-self shorthand.
                unsafe { X2APIC_ICR.write(icr) };
            },
            ApicMode::XApic => {
                let _ = self.send_xapic_icr(None, icr);
            },
            ApicMode::Disabled => {},
        }
    }

    /// Send an INIT IPI to `dest`. Used by the SMP bring-up sequence to put
    /// an AP into the wait-for-SIPI state. The INIT de-assert sequence is
    /// deprecated in x2APIC and not issued here.
    #[inline]
    pub fn send_init_ipi(&self, dest: u32) {
        debug_assert!(
            self.is_enabled(),
            "xenith.apic: send_init_ipi() before init"
        );
        if !self.can_route_apic_id(dest) {
            ::log::error!(
                "xenith.apic: INIT destination {} is not routable in {:?}",
                dest,
                self.mode()
            );
            return;
        }
        match self.mode() {
            ApicMode::X2Apic => {
                let icr = IcrFlags::DELIVERY_INIT.bits() | (u64::from(dest) << 32);
                // SAFETY: x2APIC INIT with a full physical destination.
                unsafe { X2APIC_ICR.write(icr) };
            },
            ApicMode::XApic => {
                let low = IcrFlags::DELIVERY_INIT.bits()
                    | IcrFlags::LEVEL_ASSERT.bits()
                    | IcrFlags::TRIGGER_LEVEL.bits();
                let _ = self.send_xapic_icr(Some(dest), low);
            },
            ApicMode::Disabled => {},
        }
    }

    /// Send a Startup IPI (SIPI) to `dest` with the real-mode start page
    /// `start_page` (the physical 4 KiB page number, i.e. `start_addr >> 12`).
    /// The AP begins execution at `start_page << 12` in real mode. Issued
    /// twice per Intel's recommended INIT-SIPI-SIPI sequence.
    ///
    /// `start_page` must be below `0xA0` so the target address stays within
    /// the first 1 MiB of physical memory (the real-mode addressable range).
    #[inline]
    pub fn send_startup_ipi(&self, dest: u32, start_page: u8) {
        debug_assert!(self.is_enabled(), "xenith.apic: SIPI before init");
        debug_assert!(
            start_page < 0xA0,
            "xenith.apic: SIPI start page must be below 0xA0 (real-mode 1 MiB limit)"
        );
        if !self.can_route_apic_id(dest) {
            ::log::error!(
                "xenith.apic: SIPI destination {} is not routable in {:?}",
                dest,
                self.mode()
            );
            return;
        }
        let low = u64::from(start_page) | IcrFlags::DELIVERY_STARTUP.bits();
        match self.mode() {
            ApicMode::X2Apic => {
                // SAFETY: x2APIC SIPI with a full physical destination.
                unsafe { X2APIC_ICR.write(low | (u64::from(dest) << 32)) };
            },
            ApicMode::XApic => {
                let _ = self.send_xapic_icr(Some(dest), low);
            },
            ApicMode::Disabled => {},
        }
    }

    // -- task priority ----------------------------------------------------

    /// Set the Task Priority Register.
    ///
    /// `prio` is the full 8-bit TPR value: bits 4..7 are the interrupt
    /// class, bits 0..3 the sub-priority. The LAPIC will not deliver an
    /// interrupt whose vector's class is strictly lower than the TPR class,
    /// so writing `0x80` blocks everything below vector `0x80` and writing
    /// `0x00` allows all vectors.
    #[inline]
    pub fn set_task_priority(&self, prio: u8) {
        debug_assert!(self.is_enabled(), "xenith.apic: TPR write before init");
        self.write_register(X2APIC_TPR, XAPIC_TPR, u64::from(prio));
    }

    // -- timer control ----------------------------------------------------

    /// Configure the LVT timer: `vector` to deliver, `periodic` selects
    /// periodic vs one-shot mode, `masked` gates delivery.
    ///
    /// The timer is left masked after [`init`](Self::init); scheduler timer
    /// setup calls this with `masked = false` after installing the tick gate,
    /// then arms the countdown with [`arm_timer`](Self::arm_timer).
    #[inline]
    pub fn configure_timer(&self, vector: u8, periodic: bool, masked: bool) {
        debug_assert!(self.is_enabled(), "xenith.apic: timer config before init");
        let mut flags = LvtFlags::DELIVERY_FIXED;
        if periodic {
            flags.insert(LvtFlags::TIMER_PERIODIC);
        }
        if masked {
            flags.insert(LvtFlags::MASKED);
        }
        let entry = LvtEntry::new(vector, flags);
        self.write_register(X2APIC_LVT_TIMER, XAPIC_LVT_TIMER, entry.to_u64());
    }

    /// Set the timer divide value (one of the [`TIMER_DIV_*`] constants)
    /// and the initial count; the timer begins counting down immediately.
    /// A count of zero parks the timer.
    #[inline]
    pub fn arm_timer(&self, divide_encoding: u8, initial_count: u32) {
        debug_assert!(self.is_enabled(), "xenith.apic: arm_timer() before init");
        self.write_register(
            X2APIC_TIMER_DIV,
            XAPIC_TIMER_DIV,
            u64::from(divide_encoding),
        );
        self.write_register(
            X2APIC_TIMER_INIT,
            XAPIC_TIMER_INIT,
            u64::from(initial_count),
        );
    }

    /// The timer's current countdown value.
    #[inline]
    #[must_use]
    pub fn timer_current_count(&self) -> u32 {
        debug_assert!(self.is_enabled(), "xenith.apic: timer read before init");
        self.read_register(X2APIC_TIMER_CUR, XAPIC_TIMER_CUR) as u32
    }

    // -- error status -----------------------------------------------------

    /// Read the Error Status Register. Bit positions correspond to the
    /// error causes in Intel SDM §10.8.5 (illegal register access, receive
    /// checksum error, send checksum error, ...).
    #[inline]
    #[must_use]
    pub fn error_status(&self) -> u32 {
        debug_assert!(self.is_enabled(), "xenith.apic: ESR read before init");
        self.read_register(X2APIC_ESR, XAPIC_ESR) as u32
    }

    /// Clear the Error Status Register by writing 0.
    #[inline]
    pub fn clear_error_status(&self) {
        debug_assert!(self.is_enabled(), "xenith.apic: ESR clear before init");
        self.write_register(X2APIC_ESR, XAPIC_ESR, 0);
    }
}

impl Default for LocalApic {
    fn default() -> Self {
        Self::new()
    }
}

impl core::fmt::Debug for LocalApic {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("LocalApic")
            .field("mode", &self.mode())
            .finish()
    }
}

// ---------------------------------------------------------------------------
// The global LAPIC handle + module entry point
// ---------------------------------------------------------------------------

/// The kernel's local APIC handle.
///
/// A single static serves the BSP and every AP. Both x2APIC MSRs and the
/// legacy xAPIC MMIO window select the controller local to the CPU issuing
/// the access. Shared state records only the backend and HHDM window address.
pub static LAPIC: LocalApic = LocalApic::new();

/// Bring up the local APIC on the current CPU.
///
/// Thin wrapper around [`LAPIC.init`](LocalApic::init). Runs with interrupts
/// disabled during BSP and AP bring-up and is safe to call from any ring-0
/// CPU context.
pub fn init() {
    LAPIC.init();
}

// ---------------------------------------------------------------------------
// Convenience: a free-standing EOI for IRQ trampolines
// ---------------------------------------------------------------------------

/// Signal end-of-interrupt on the current CPU via the static [`LAPIC`].
///
/// This is the entry point IRQ trampolines call after their handler returns;
/// it is a free function rather than a method so asm trampolines can reference
/// it by symbol without going through the [`LAPIC`] static's address.
#[inline]
pub fn send_eoi() {
    LAPIC.send_eoi();
}

/// The physical APIC ID of the current CPU via the static [`LAPIC`].
#[inline]
#[must_use]
pub fn current_id() -> u32 {
    LAPIC.id()
}

/// Send a fixed IPI to `dest` carrying `vector` via the static [`LAPIC`].
#[inline]
pub fn send_ipi(dest: u32, vector: u8) {
    LAPIC.send_ipi(dest, vector);
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn lvt_entry_packs_vector_and_mask() {
        let e = LvtEntry::new(0x40, LvtFlags::DELIVERY_FIXED | LvtFlags::MASKED);
        // Vector in bits 0..7.
        assert_eq!(e.to_u64() & 0xFF, 0x40);
        // Mask is bit 16.
        assert_ne!(e.to_u64() & (1 << 16), 0);
        // Fixed delivery is zero in 8..10, so those bits are clear.
        assert_eq!(e.to_u64() & (0b111 << 8), 0);
        assert!(e.is_masked());
    }

    #[test]
    fn lvt_entry_masked_unmasked_toggles_bit_16() {
        let base = LvtEntry::new(0x40, LvtFlags::DELIVERY_FIXED);
        assert_eq!(base.to_u64() & (1 << 16), 0);
        assert!(!base.is_masked());
        assert_ne!(base.masked().to_u64() & (1 << 16), 0);
        assert!(base.masked().is_masked());
        // unmasked() clears it again.
        assert_eq!(base.masked().unmasked().to_u64() & (1 << 16), 0);
        assert!(!base.masked().unmasked().is_masked());
    }

    #[test]
    fn lvt_timer_periodic_sets_bit_17() {
        let e = LvtEntry::new(
            TIMER_VECTOR,
            LvtFlags::DELIVERY_FIXED | LvtFlags::TIMER_PERIODIC,
        );
        // Periodic = 01 in bits 17..18 → bit 17 set, bit 18 clear.
        assert_ne!(e.to_u64() & (1 << 17), 0);
        assert_eq!(e.to_u64() & (1 << 18), 0);
    }

    #[test]
    fn lvt_nmi_and_extint_delivery_bits_8_10() {
        let nmi = LvtEntry::new(2, LvtFlags::DELIVERY_NMI);
        // NMI = 100 → bit 10 set, bits 8 and 9 clear.
        assert_eq!(nmi.to_u64() & (0b111 << 8), 0b100 << 8);

        let ext = LvtEntry::new(0, LvtFlags::DELIVERY_EXTINT);
        // ExtINT = 111.
        assert_eq!(ext.to_u64() & (0b111 << 8), 0b111 << 8);
    }

    #[test]
    fn icr_fixed_ipi_packs_vector_and_destination() {
        let v = u64::from(0x41u8) | IcrFlags::DELIVERY_FIXED.bits() | (u64::from(0x10u32) << 32);
        // Vector in 0..7.
        assert_eq!(v & 0xFF, 0x41);
        // Destination in 32..63.
        assert_eq!((v >> 32) & 0xFFFF_FFFF, 0x10);
        // Fixed delivery = zero in 8..10.
        assert_eq!(v & (0b111 << 8), 0);
        // No shorthand → bits 18..19 clear.
        assert_eq!(v & (0b11 << 18), 0);
    }

    #[test]
    fn icr_delivery_mode_encodings() {
        assert_eq!(IcrFlags::DELIVERY_FIXED.bits(), 0b000 << 8);
        assert_eq!(IcrFlags::DELIVERY_LOWEST.bits(), 0b001 << 8);
        assert_eq!(IcrFlags::DELIVERY_INIT.bits(), 0b101 << 8);
        assert_eq!(IcrFlags::DELIVERY_STARTUP.bits(), 0b110 << 8);
        assert_eq!(IcrFlags::DELIVERY_NMI.bits(), 0b100 << 8);
    }

    #[test]
    fn icr_shorthand_bits_18_19() {
        assert_eq!(IcrFlags::SHORTHAND_SELF.bits(), 0b01 << 18);
        assert_eq!(IcrFlags::SHORTHAND_ALL.bits(), 0b10 << 18);
        assert_eq!(IcrFlags::SHORTHAND_ALL_EXCL_SELF.bits(), 0b11 << 18);
    }

    #[test]
    fn xapic_base_extraction_validates_alignment_and_width() {
        let msr = 0xFEE0_0000 | APIC_BASE_BSP | APIC_BASE_ENABLE;
        assert_eq!(xapic_phys_base_from_msr(msr), Some(0xFEE0_0000));
        let high_base = 0x0000_0001_2345_6000;
        assert_eq!(
            xapic_phys_base_from_msr(high_base | APIC_BASE_ENABLE),
            Some(high_base)
        );
        assert_eq!(validate_xapic_phys_base(0xFEE0_0000), Some(0xFEE0_0000));
        assert_eq!(validate_xapic_phys_base(0), None);
        assert_eq!(validate_xapic_phys_base(0xFEE0_0001), None);
        assert_eq!(validate_xapic_phys_base(1 << 40), None);
    }

    #[test]
    fn xapic_register_addresses_stay_in_the_mmio_page() {
        let base = 0xFEE0_0000;
        assert_eq!(xapic_register_phys(base, XAPIC_APICID), Some(base + 0x20));
        assert_eq!(
            xapic_register_phys(base, XAPIC_TIMER_DIV),
            Some(base + 0x3E0)
        );
        assert_eq!(xapic_register_phys(base, 0x024), None);
        assert_eq!(xapic_register_phys(base, 0x1000), None);
    }

    #[test]
    fn xapic_icr_writes_destination_high_before_command_low() {
        let low = u64::from(0x41u8) | IcrFlags::DELIVERY_FIXED.bits();
        let command = XapicIcrWrite::new(Some(0xAB), low).expect("8-bit destination");
        assert_eq!(command.writes(), [
            (XAPIC_ICR_HIGH, 0xAB00_0000),
            (XAPIC_ICR_LOW, low as u32)
        ]);
        assert_eq!(XAPIC_ICR_DELIVERY_PENDING, 1 << 12);
    }

    #[test]
    fn xapic_icr_rejects_wide_destinations_and_encodes_init_assert() {
        assert!(XapicIcrWrite::new(Some(255), IcrFlags::DELIVERY_FIXED.bits()).is_some());
        assert!(XapicIcrWrite::new(Some(256), IcrFlags::DELIVERY_FIXED.bits()).is_none());

        let init = IcrFlags::DELIVERY_INIT.bits()
            | IcrFlags::LEVEL_ASSERT.bits()
            | IcrFlags::TRIGGER_LEVEL.bits();
        let command = XapicIcrWrite::new(Some(7), init).expect("valid INIT command");
        assert_eq!(command.high, 7 << 24);
        assert_ne!(command.low & (1 << 14), 0);
        assert_ne!(command.low & (1 << 15), 0);
    }

    #[test]
    fn apic_mode_round_trips_through_u8() {
        assert_eq!(
            ApicMode::from_u8(ApicMode::X2Apic.as_u8()),
            ApicMode::X2Apic
        );
        assert_eq!(ApicMode::from_u8(ApicMode::XApic.as_u8()), ApicMode::XApic);
        assert_eq!(
            ApicMode::from_u8(ApicMode::Disabled.as_u8()),
            ApicMode::Disabled
        );
        // Out-of-range decodes to Disabled.
        assert_eq!(ApicMode::from_u8(0xFF), ApicMode::Disabled);
    }

    #[test]
    fn local_apic_starts_disabled() {
        let lapic = LocalApic::new();
        assert_eq!(lapic.mode(), ApicMode::Disabled);
        assert!(!lapic.is_x2apic());
        assert!(!lapic.is_enabled());
        assert_eq!(lapic.xapic_mmio_virt.load(Ordering::Relaxed), 0);
    }

    #[test]
    fn routing_limit_depends_on_selected_backend() {
        let lapic = LocalApic::new();
        lapic.mode.store(ApicMode::XApic.as_u8(), Ordering::Relaxed);
        assert!(lapic.can_route_apic_id(255));
        assert!(!lapic.can_route_apic_id(256));
        lapic
            .mode
            .store(ApicMode::X2Apic.as_u8(), Ordering::Relaxed);
        assert!(lapic.can_route_apic_id(u32::MAX));
    }

    #[test]
    fn spurious_vector_is_architectural_convention() {
        // 0xFF is the conventional spurious vector used by Linux/KVM/OVMF.
        assert_eq!(SPURIOUS_VECTOR, 0xFF);
        // SVR value = vector | bit 8 (APIC enable).
        let svr = u64::from(SPURIOUS_VECTOR) | SVR_APIC_ENABLE;
        assert_eq!(svr, 0x1FF);
    }

    #[test]
    fn x2apic_msr_indices_follow_the_architectural_mmio_mapping() {
        assert_eq!(X2APIC_TPR.addr(), 0x800 + (0x080 >> 4));
        assert_eq!(X2APIC_EOI.addr(), 0x800 + (0x0B0 >> 4));
        assert_eq!(X2APIC_LDR.addr(), 0x800 + (0x0D0 >> 4));
        assert_eq!(X2APIC_SVR.addr(), 0x800 + (0x0F0 >> 4));
        assert_eq!(X2APIC_ESR.addr(), 0x800 + (0x280 >> 4));
    }

    #[test]
    fn timer_divide_encodings_are_distinct() {
        let all = [
            TIMER_DIV_1,
            TIMER_DIV_2,
            TIMER_DIV_4,
            TIMER_DIV_8,
            TIMER_DIV_16,
            TIMER_DIV_32,
            TIMER_DIV_64,
            TIMER_DIV_128,
        ];
        // Every encoding must be unique.
        for i in 0..all.len() {
            for j in (i + 1)..all.len() {
                assert_ne!(all[i], all[j], "duplicate timer divide encoding");
            }
        }
        // Each fits in the 4-bit field (bits 0,1,3).
        for &e in &all {
            assert!(e <= 0b1011);
        }
    }
}
