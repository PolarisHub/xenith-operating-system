//! Local APIC (LAPIC) driver — x2APIC MSR mode.
//!
//! The local APIC is the per-CPU interrupt controller that delivers timer
//! ticks, inter-processor interrupts, and locally-routed IRQs. Modern x86
//! exposes two programming interfaces for it:
//!
//! * **xAPIC** — the classic MMIO interface at physical `0xFEE0_0000`, where
//!   each register is a 32-bit window accessed through a 4 KiB mapping. The
//!   APIC ID is 8 bits, capping a system at 255 logical processors.
//! * **x2APIC** — the MSR interface at `0x800..=0x8FF`, available when
//!   CPUID.01H:ECX[21] is set. The APIC ID widens to 32 bits and every
//!   register becomes a single `rdmsr`/`wrmsr` pair, so no MMIO mapping is
//!   required. The Interrupt Command Register collapses from two 32-bit
//!   MMIO words into one 64-bit MSR.
//!
//! Xenith prefers x2APIC whenever the CPU advertises it: it removes the
//! 255-CPU ceiling, avoids an early MMIO map, and is the only mode KVM and
//! modern firmware expose by default. When x2APIC is unavailable the driver
//! logs a warning and leaves the LAPIC disabled — the legacy xAPIC MMIO
//! bring-up depends on the `mm` subsystem to map the `0xFEE0_0000` window
//! and is wired up by a later phase.
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
//! [`init`] runs once per CPU (the BSP via [`super::init`], APs via their
//! own bring-up path in a later phase) and performs:
//!
//! 1. Detect x2APIC via CPUID.01H:ECX[21] and read `IA32_APIC_BASE`
//!    (MSR `0x1B`) to confirm the APIC is present.
//! 2. Set `IA32_APIC_BASE` bit 10 (x2APIC enable) alongside bit 11 (global
//!    enable). After this write the MMIO window is inaccessible and all
//!    register access must go through the `0x800` MSR block.
//! 3. Programme the Spurious Interrupt Vector Register (SVR, MSR `0x80F`)
//!    with vector `0xFF` and the APIC-software-enable bit (bit 8). Until
//!    SVR is enabled the LAPIC silently drops every interrupt.
//! 4. Mask and vector every LVT entry: the timer, LINT0, LINT1, and the
//!    error register. Masking here prevents a spurious LVT interrupt from
//!    firing before its handler is wired up; a later phase unmasks the
//!    timer once the tick handler is installed.
//! 5. Clear the Error Status Register (ESR) so any stale firmware error
//!    bits do not trigger an immediate error interrupt once that LVT entry
//!    is unmasked.
//! 6. Park the timer (zero initial count, divide-by-1) so it does not run
//!    until a later phase arms it.
//!
//! After [`init`] returns, [`send_eoi`] and [`send_ipi`] are usable on the
//! calling CPU. Maskable IRQs are still off at this point; `sti` happens
//! later in the boot sequence.
//!
//! # Safety
//!
//! Every MSR access in this module is `rdmsr`/`wrmsr`, which are privileged
//! (CPL 0) and raise #GP on a reserved index or a write to a read-only
//! register. The driver only touches the x2APIC MSR block after confirming
//! x2APIC support via CPUID and enabling the mode in `IA32_APIC_BASE`, so
//! every access is architecturally valid. Each `unsafe` block below cites
//! the specific invariant it relies on.

use core::sync::atomic::{AtomicU8, Ordering};

use xenith_bitflags::bitflags;

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
// These vectors live at the top of the IRQ range (32..=255). They are
// provisional constants; the IRQ subsystem will centralise vector allocation
// and re-reference them when the timer and error handlers are installed.

/// Spurious-interrupt vector. The LAPIC delivers this vector when an
/// interrupt is raised but its source has been retracted before delivery
/// (e.g. a device de-asserts between the IRR and IRR-to-ISR promotion).
/// `0xFF` is the architectural convention (Linux, KVM, OVMF all use it).
pub const SPURIOUS_VECTOR: u8 = 0xFF;
/// LVT error vector. Fired when the LAPIC reports an internal error via the
/// ESR; the handler reads ESR and logs the cause.
pub const ERROR_VECTOR: u8 = 0xFE;
/// LVT timer vector. The scheduler tick handler is installed at this vector
/// by a later phase; the timer LVT is left masked here so no tick fires
/// before the handler exists.
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
/// value written to the matching `X2APIC_LVT_*` MSR.
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
    /// Control bits for the 64-bit x2APIC Interrupt Command Register.
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
        /// Trigger Mode = Level (bit 15). Absence means edge. x2APIC only
        /// supports the assert level; the de-assert shorthand is deprecated.
        const TRIGGER_LEVEL           = 1 << 15;
        /// Shorthand = Self (bits 18..19 = 01). Send to the current CPU.
        const SHORTHAND_SELF          = 0b01 << 18;
        /// Shorthand = All (bits 18..19 = 10). Broadcast to every CPU.
        const SHORTHAND_ALL           = 0b10 << 18;
        /// Shorthand = All excluding self (bits 18..19 = 11).
        const SHORTHAND_ALL_EXCL_SELF = 0b11 << 18;
    }
}

// ---------------------------------------------------------------------------
// Operating mode
// ---------------------------------------------------------------------------

/// The LAPIC operating mode detected by [`LocalApic::init`].
///
/// Stored as a `u8` inside an [`AtomicU8`] so the static [`LAPIC`] can be
/// read without a lock; the BSP is the only writer during boot. When the
/// SMP phase lands this becomes per-CPU state — each CPU enables its own
/// x2APIC — at which point it migrates onto the `PerCpu` control block.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(u8)]
pub enum ApicMode {
    /// The LAPIC has not been initialised (or the CPU has no APIC at all).
    Disabled = 0,
    /// x2APIC MSR mode — the only mode this driver fully brings up.
    X2Apic = 1,
    /// Legacy xAPIC MMIO mode — detected but not yet driven; requires the
    /// `mm` subsystem to map the `0xFEE0_0000` window. Logged as a warning
    /// when encountered.
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
/// Because x2APIC registers are MSRs, every access is per-CPU and the
/// driver holds no MMIO pointer. The only state kept here is the operating
/// [`ApicMode`], stored atomically so the rest of the kernel can ask "is
/// the LAPIC up?" without a lock. Methods on this type execute the
/// corresponding `rdmsr`/`wrmsr` pair on *the calling CPU*; callers are
/// responsible for ensuring they run on the CPU they intend to address
/// (which, for IPI senders, is "the one running this code").
pub struct LocalApic {
    mode: AtomicU8,
}

impl LocalApic {
    /// Construct an uninitialised LAPIC handle. `const` so it can live in
    /// the [`LAPIC`] static.
    #[inline]
    #[must_use]
    pub const fn new() -> Self {
        Self {
            mode: AtomicU8::new(ApicMode::Disabled.as_u8()),
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

    /// Bring up the local APIC on the current CPU.
    ///
    /// Detects x2APIC via CPUID, enables it in `IA32_APIC_BASE`, programmes
    /// the Spurious Vector Register, and masks every LVT entry so no
    /// interrupt can fire before its handler is registered. Safe to call
    /// from any ring-0 context; idempotent in the sense that re-running it
    /// on an already-x2APIC CPU rewrites the same values.
    ///
    /// On a CPU that advertises x2APIC in CPUID but refuses the
    /// `IA32_APIC_BASE` enable write (a misconfigured hypervisor), the
    /// driver logs an error and leaves the mode [`ApicMode::Disabled`]; the
    /// kernel cannot route interrupts without a LAPIC, so the first IRQ
    /// will fault, but the failure is reported rather than panicking before
    /// the console is fully usable.
    pub fn init(&self) {
        if !has_x2apic() {
            ::log::warn!(
                "xenith.apic: x2APIC not available; xAPIC MMIO bring-up is a future phase"
            );
            self.mode.store(ApicMode::XApic.as_u8(), Ordering::Release);
            return;
        }

        // 1. Enable x2APIC in IA32_APIC_BASE. Preserve the existing base
        //    address (bits 12..=35) and BSP flag (bit 8); OR in the global
        //    enable (bit 11) and x2APIC enable (bit 10). The SDM requires
        //    bit 11 set when setting bit 10, so we set both in one write.
        // SAFETY: IA32_LAPIC_BASE (0x1B) is a valid MSR on every x86_64
        // part; reading it in ring 0 is always permitted. No reserved bits
        // are touched because we only OR in the two defined enable bits.
        let base = unsafe { IA32_LAPIC_BASE.read() };
        let new_base = base | APIC_BASE_ENABLE | APIC_BASE_X2APIC;
        // SAFETY: same MSR; we only set the two defined enable bits and
        // preserve the rest, so no reserved bit is written. The BSP bit and
        // the base-address field pass through unchanged.
        unsafe { IA32_LAPIC_BASE.write(new_base) };

        // Read back and confirm the x2APIC enable bit latched. A
        // hypervisor that advertises x2APIC in CPUID but refuses the MSR
        // write leaves the bit clear; there is no recovery path.
        // SAFETY: same MSR, ring 0.
        let verify = unsafe { IA32_LAPIC_BASE.read() };
        if (verify & (APIC_BASE_ENABLE | APIC_BASE_X2APIC)) != (APIC_BASE_ENABLE | APIC_BASE_X2APIC)
        {
            ::log::error!(
                "xenith.apic: IA32_APIC_BASE refused x2APIC enable (read back 0x{:x})",
                verify
            );
            self.mode
                .store(ApicMode::Disabled.as_u8(), Ordering::Release);
            return;
        }

        // 2. Spurious Interrupt Vector Register: vector 0xFF + APIC enable.
        //    Without SVR bit 8 the LAPIC silently drops every interrupt, so
        //    this is the single most important write in bring-up.
        let svr = u64::from(SPURIOUS_VECTOR) | SVR_APIC_ENABLE;
        // SAFETY: SVR (0x80F) is a read/write MSR in the x2APIC block; the
        // value has the vector in 0..7 and bit 8 set, all other bits zero.
        unsafe { X2APIC_SVR.write(svr) };

        // 3. Task Priority Register = 0 so no interrupt class is masked.
        // SAFETY: TPR (0x808) is read/write; writing 0 is always valid.
        unsafe { X2APIC_TPR.write(0) };

        // 4. LVT entries. All start masked so nothing fires before its
        //    handler is installed; the timer/error vectors are pre-assigned
        //    so a later phase only has to unmask. LINT0 is set to ExtINT
        //    delivery (the legacy PIC pass-through mode) but masked, and
        //    LINT1 to NMI delivery but masked — in x2APIC mode the 8259
        //    PIC is parked by the `pic` module and these entries stay
        //    masked forever.
        let timer = LvtEntry::new(TIMER_VECTOR, LvtFlags::DELIVERY_FIXED | LvtFlags::MASKED);
        let lint0 = LvtEntry::new(0, LvtFlags::DELIVERY_EXTINT | LvtFlags::MASKED);
        let lint1 = LvtEntry::new(0, LvtFlags::DELIVERY_NMI | LvtFlags::MASKED);
        let error = LvtEntry::new(ERROR_VECTOR, LvtFlags::DELIVERY_FIXED | LvtFlags::MASKED);
        // SAFETY: each LVT MSR is read/write in the x2APIC block; the values
        // are well-formed (vector + delivery mode + mask, reserved bits 0).
        unsafe { X2APIC_LVT_TIMER.write(timer.to_u64()) };
        unsafe { X2APIC_LVT_LINT0.write(lint0.to_u64()) };
        unsafe { X2APIC_LVT_LINT1.write(lint1.to_u64()) };
        unsafe { X2APIC_LVT_ERROR.write(error.to_u64()) };

        // 5. Clear the Error Status Register by writing 0, then read it back
        //    to drain any stale firmware error bits. The error LVT is
        //    currently masked, so no error interrupt is raised yet.
        // SAFETY: ESR (0x828) is read/write; writing 0 clears all error
        // bits per the SDM.
        unsafe { X2APIC_ESR.write(0) };
        let _esr = unsafe { X2APIC_ESR.read() };

        // 6. Park the timer: divide-by-1 and zero initial count so it does
        //    not run even if a later unmask races. The scheduler phase
        //    retunes both via `arm_timer`.
        // SAFETY: divide config (0x83E) and initial count (0x838) are
        // read/write; 0 is the quiescent value for the count, and
        // TIMER_DIV_1 is the documented divide-by-1 encoding.
        unsafe { X2APIC_TIMER_DIV.write(u64::from(TIMER_DIV_1)) };
        unsafe { X2APIC_TIMER_INIT.write(0) };

        self.mode.store(ApicMode::X2Apic.as_u8(), Ordering::Release);

        let id = self.id();
        // Report whether this CPU is the BSP from the IA32_APIC_BASE bit we
        // captured before the enable write — useful for telling the boot
        // log apart from the per-AP log when the SMP phase starts printing
        // one line per CPU.
        let is_bsp = (base & APIC_BASE_BSP) != 0;
        ::log::info!(
            "xenith.apic: x2APIC online on {} (apic id {}), spurious vec 0x{:02X}, LVT masked",
            if is_bsp { "bsp" } else { "ap" },
            id,
            SPURIOUS_VECTOR
        );
    }

    // -- register reads ---------------------------------------------------

    /// The 32-bit x2APIC ID of the current CPU (MSR `0x802`).
    ///
    /// This is the identity the IPI destination field and the per-CPU
    /// subsystem key off of. Unlike the 8-bit xAPIC ID returned by
    /// `cpu::current_cpu_apic_id`, the x2APIC ID is 32 bits and supports
    /// more than 255 logical processors.
    ///
    /// # Panics (debug only)
    ///
    /// Debug-asserts that x2APIC is active, since the MSR is only valid
    /// after [`init`](Self::init) enables the mode.
    #[inline]
    #[must_use]
    pub fn id(&self) -> u32 {
        debug_assert!(self.is_x2apic(), "xenith.apic: id() before init");
        // SAFETY: X2APIC_APICID (0x802) is read-only and valid in x2APIC
        // mode, which the caller has established via init().
        let raw = unsafe { X2APIC_APICID.read() };
        // The ID occupies bits 0..31; upper bits are reserved zero.
        raw as u32
    }

    /// The local APIC version register (low byte = version, bits 16..23 =
    /// max LVT index). Useful for capability checks; not currently used in
    /// bring-up because every x2APIC part exposes enough LVT entries.
    #[inline]
    #[must_use]
    pub fn version(&self) -> u32 {
        debug_assert!(self.is_x2apic(), "xenith.apic: version() before init");
        // SAFETY: VERSION (0x803) is read-only and valid in x2APIC mode.
        unsafe { X2APIC_VERSION.read() as u32 }
    }

    /// The 32-bit logical APIC ID assigned by the system (read-only MSR
    /// `0x80D`). Unlike the physical [`id`](Self::id), which is fixed at
    /// reset, the logical ID is chosen by firmware/OS policy and is the
    /// destination used when an IPI is sent with logical destination mode.
    /// Xenith uses physical destination mode for all IPIs today, so this is
    /// primarily diagnostic.
    #[inline]
    #[must_use]
    pub fn logical_id(&self) -> u32 {
        debug_assert!(self.is_x2apic(), "xenith.apic: logical_id() before init");
        // SAFETY: LDR (0x80D) is read-only in x2APIC and valid after init.
        unsafe { X2APIC_LDR.read() as u32 }
    }

    // -- end-of-interrupt -------------------------------------------------

    /// Signal end-of-interrupt for the in-service interrupt.
    ///
    /// Every IRQ handler must call this exactly once before returning;
    /// omitting it leaves the interrupt in-service and blocks further
    /// delivery of the same vector. In x2APIC the EOI is a write of any
    /// value (conventionally 0) to MSR `0x80B`.
    #[inline]
    pub fn send_eoi(&self) {
        debug_assert!(self.is_x2apic(), "xenith.apic: send_eoi() before init");
        // SAFETY: X2APIC_EOI (0x80B) is a write-only MSR; writing 0 is the
        // documented EOI protocol. Valid in x2APIC mode after init().
        unsafe { X2APIC_EOI.write(0) };
    }

    // -- inter-processor interrupts ---------------------------------------

    /// Send a fixed, edge-triggered IPI carrying `vector` to the CPU whose
    /// x2APIC ID is `dest`.
    ///
    /// If `dest` is the current CPU, the driver uses the dedicated Self-IPI
    /// MSR (`0x83F`), which is a single write instead of a full ICR build.
    /// For every other destination it constructs an ICR value with physical
    /// destination mode and the no-shorthand delivery, then writes ICR
    /// (`0x830`) — the write itself is what dispatches the IPI.
    #[inline]
    pub fn send_ipi(&self, dest: u32, vector: u8) {
        debug_assert!(self.is_x2apic(), "xenith.apic: send_ipi() before init");
        if dest == self.id() {
            self.send_ipi_self(vector);
            return;
        }
        let icr = u64::from(vector) | IcrFlags::DELIVERY_FIXED.bits() | (u64::from(dest) << 32);
        // SAFETY: writing ICR (0x830) dispatches the IPI. The value is
        // well-formed: vector in 0..7, fixed delivery (000), physical
        // destination mode (bit 11 clear), no shorthand (bits 18..19 clear),
        // and the 32-bit destination in the upper half.
        unsafe { X2APIC_ICR.write(icr) };
    }

    /// Send a fixed IPI to the current CPU via the Self-IPI MSR (`0x83F`).
    ///
    /// Cheaper than [`send_ipi`](Self::send_ipi) with the self shorthand
    /// because it is a single write of the vector rather than a 64-bit ICR
    /// build, and the CPU does not have to arbitrate the delivery path.
    #[inline]
    pub fn send_ipi_self(&self, vector: u8) {
        debug_assert!(self.is_x2apic(), "xenith.apic: send_ipi_self() before init");
        // SAFETY: SELF_IPI (0x83F) is write-only; writing the vector sends a
        // fixed, edge-triggered IPI to the current CPU. Valid in x2APIC mode.
        unsafe { X2APIC_SELF_IPI.write(u64::from(vector)) };
    }

    /// Broadcast a fixed IPI carrying `vector` to every CPU in the system
    /// (including the sender).
    #[inline]
    pub fn send_ipi_all(&self, vector: u8) {
        debug_assert!(self.is_x2apic(), "xenith.apic: send_ipi_all() before init");
        let icr =
            u64::from(vector) | IcrFlags::DELIVERY_FIXED.bits() | IcrFlags::SHORTHAND_ALL.bits();
        // SAFETY: ICR write with the all-shorthand; the destination field is
        // ignored by the shorthand and left zero.
        unsafe { X2APIC_ICR.write(icr) };
    }

    /// Broadcast a fixed IPI carrying `vector` to every CPU except the
    /// sender. This is the canonical "wake all APs" broadcast.
    #[inline]
    pub fn send_ipi_all_excluding_self(&self, vector: u8) {
        debug_assert!(
            self.is_x2apic(),
            "xenith.apic: send_ipi_all_excluding_self() before init"
        );
        let icr = u64::from(vector)
            | IcrFlags::DELIVERY_FIXED.bits()
            | IcrFlags::SHORTHAND_ALL_EXCL_SELF.bits();
        // SAFETY: ICR write with the all-excluding-self shorthand.
        unsafe { X2APIC_ICR.write(icr) };
    }

    /// Send an INIT IPI to `dest`. Used by the SMP bring-up sequence to put
    /// an AP into the wait-for-SIPI state. The INIT de-assert sequence is
    /// deprecated in x2APIC and not issued here.
    #[inline]
    pub fn send_init_ipi(&self, dest: u32) {
        debug_assert!(self.is_x2apic(), "xenith.apic: send_init_ipi() before init");
        let icr = IcrFlags::DELIVERY_INIT.bits() | (u64::from(dest) << 32);
        // SAFETY: ICR write with INIT delivery, physical destination, edge
        // trigger (the x2APIC-supported default for INIT assert). The vector
        // field is ignored for INIT delivery and left zero.
        unsafe { X2APIC_ICR.write(icr) };
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
        debug_assert!(
            self.is_x2apic(),
            "xenith.apic: send_startup_ipi() before init"
        );
        debug_assert!(
            start_page < 0xA0,
            "xenith.apic: SIPI start page must be below 0xA0 (real-mode 1 MiB limit)"
        );
        let icr =
            u64::from(start_page) | IcrFlags::DELIVERY_STARTUP.bits() | (u64::from(dest) << 32);
        // SAFETY: ICR write with Startup delivery; the vector field carries
        // the start page number, which is the SIPI convention. Destination
        // is in the upper 32 bits.
        unsafe { X2APIC_ICR.write(icr) };
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
        debug_assert!(
            self.is_x2apic(),
            "xenith.apic: set_task_priority() before init"
        );
        // SAFETY: TPR (0x808) is read/write; the low 8 bits are the priority
        // and the rest are reserved zero.
        unsafe { X2APIC_TPR.write(u64::from(prio)) };
    }

    // -- timer control ----------------------------------------------------

    /// Configure the LVT timer: `vector` to deliver, `periodic` selects
    /// periodic vs one-shot mode, `masked` gates delivery.
    ///
    /// The timer is left masked after [`init`](Self::init); a later phase
    /// calls this with `masked = false` once the tick handler is installed,
    /// then arms the countdown with [`arm_timer`](Self::arm_timer).
    #[inline]
    pub fn configure_timer(&self, vector: u8, periodic: bool, masked: bool) {
        debug_assert!(
            self.is_x2apic(),
            "xenith.apic: configure_timer() before init"
        );
        let mut flags = LvtFlags::DELIVERY_FIXED;
        if periodic {
            flags.insert(LvtFlags::TIMER_PERIODIC);
        }
        if masked {
            flags.insert(LvtFlags::MASKED);
        }
        let entry = LvtEntry::new(vector, flags);
        // SAFETY: LVT_TIMER (0x832) is read/write; the value is a valid LVT
        // entry (vector + fixed delivery + optional periodic + mask).
        unsafe { X2APIC_LVT_TIMER.write(entry.to_u64()) };
    }

    /// Set the timer divide value (one of the [`TIMER_DIV_*`] constants)
    /// and the initial count; the timer begins counting down immediately.
    /// A count of zero parks the timer.
    #[inline]
    pub fn arm_timer(&self, divide_encoding: u8, initial_count: u32) {
        debug_assert!(self.is_x2apic(), "xenith.apic: arm_timer() before init");
        // SAFETY: TIMER_DIV (0x83E) is read/write; only bits 0..1 and bit 3
        // are defined, and the TIMER_DIV_* encodings fit in those bits.
        unsafe { X2APIC_TIMER_DIV.write(u64::from(divide_encoding)) };
        // SAFETY: TIMER_INIT (0x838) is read/write; the full 32-bit count is
        // a valid value.
        unsafe { X2APIC_TIMER_INIT.write(u64::from(initial_count)) };
    }

    /// The timer's current countdown value (read-only MSR `0x839`).
    #[inline]
    #[must_use]
    pub fn timer_current_count(&self) -> u32 {
        debug_assert!(
            self.is_x2apic(),
            "xenith.apic: timer_current_count() before init"
        );
        // SAFETY: TIMER_CUR (0x839) is read-only and valid in x2APIC mode.
        unsafe { X2APIC_TIMER_CUR.read() as u32 }
    }

    // -- error status -----------------------------------------------------

    /// Read the Error Status Register. Bit positions correspond to the
    /// error causes in Intel SDM §10.8.5 (illegal register access, receive
    /// checksum error, send checksum error, ...).
    #[inline]
    #[must_use]
    pub fn error_status(&self) -> u32 {
        debug_assert!(self.is_x2apic(), "xenith.apic: error_status() before init");
        // SAFETY: ESR (0x828) is read/write; a read returns the current
        // error bitmap and does not clear it (a write of 0 does).
        unsafe { X2APIC_ESR.read() as u32 }
    }

    /// Clear the Error Status Register by writing 0.
    #[inline]
    pub fn clear_error_status(&self) {
        debug_assert!(
            self.is_x2apic(),
            "xenith.apic: clear_error_status() before init"
        );
        // SAFETY: writing 0 to ESR clears all error bits per the SDM.
        unsafe { X2APIC_ESR.write(0) };
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
/// A single static serves the BSP and every AP: because x2APIC register
/// access is through per-CPU MSRs, the same handle reached from any CPU
/// drives *that* CPU's LAPIC. The `mode` field is the only shared state,
/// and it migrates onto per-CPU storage when the SMP/PerCpu phase lands.
pub static LAPIC: LocalApic = LocalApic::new();

/// Bring up the local APIC on the current CPU.
///
/// Thin wrapper around [`LAPIC.init`](LocalApic::init) so the boot sequence
/// in [`super::init`] keeps calling `apic::init()` unchanged from the stub
/// era. Runs with interrupts disabled (the caller has not executed `sti`
/// yet) and is safe to call from any ring-0 CPU context.
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

/// The x2APIC ID of the current CPU via the static [`LAPIC`].
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
