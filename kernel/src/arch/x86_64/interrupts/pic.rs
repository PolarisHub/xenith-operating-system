//! Legacy 8259 Programmable Interrupt Controller (PIC) — remap, mask, EOI.
//!
//! Every PC-AT compatible machine has two cascaded 8259 PICs: a master at
//! I/O ports `0x20`/`0x21` and a slave at `0xA0`/`0xA1`, wired so the slave's
//! INT output feeds the master's IRQ2. Together they expose the 16 legacy ISA
//! IRQ lines. On boot the BIOS leaves them programmed to deliver IRQs into
//! vectors `0x08..0x0F` (master) and `0x70..0x77` (slave) — which collides
//! with the CPU's architecture exceptions (`#DF` is 8, `#PF` is 14, etc.) and
//! would misroute a hardware IRQ into an exception handler.
//!
//! Xenith, like every modern x86 kernel, does **not** use the 8259 for device
//! delivery: the local APIC and I/O APIC own IRQ routing. The PIC is still
//! physically present and powered, though, so an unmasked line will still
//! raise an interrupt on the CPU's INTR pin and bypass the APIC entirely.
//! The right thing to do is *remap then mask*: move the PIC's vectors out of
//! the exception range (so any stray IRQ that does get through lands in a
//! harmless vector instead of impersonating `#GP`), then mask every line so
//! none is delivered at all. That is exactly what [`init`] does.
//!
//! # Why remap before mask
//!
//! Masking alone is not quite enough: the 8259's mask register (OCW1) can be
//! cleared by a stray write or by SMM, and on some firmware the PIC is left
//! unmasked for the timer (IRQ0) before the OS takes over. Remapping the
//! vectors to `0x20..0x2F` first means that even if a line does fire during
//! the window between `init` and APIC takeover, it lands in an IDT slot Xenith
//! controls (a device-handler vector) rather than re-entering a CPU-exception
//! gate and triple-faulting.
//!
//! # The legacy EOI path
//!
//! When the APIC is active, end-of-interrupt is the LAPIC's EOI register, not
//! the PIC. [`end_of_interrupt`] exists for the rare case where a handler runs
//! while the PIC is still the active controller — e.g. a very early trap
//! before the APIC is mapped, or an SMI/BIOS hand-off. Sending a PIC EOI when
//! the APIC owns delivery is harmless (the PIC's ISR bit is already clear),
//! so the function is safe to call unconditionally from a handler that is
//! unsure which controller fired it.
//!
//! # Register access
//!
//! The 8259 is programmed entirely through port I/O. Each chip has a
//! command port (written with OCW2/OCW3 and ICW1) and a data port (written
//! with ICW2/ICW3/ICW4 and OCW1, the mask register). The init sequence is a
//! strict four-word ladder (ICW1 → ICW2 → ICW3 → ICW4) on both chips; the
//! chip counts the writes to know which word it is receiving, so the order
//! is load-bearing and must not be rearranged.

use crate::arch::x86_64::port::{io_wait, Port8};

// ---------------------------------------------------------------------------
// I/O ports
// ---------------------------------------------------------------------------

/// Master PIC command port. Holds OCW2/OCW3 on writes and the IRR/ISR on
/// reads (selected by OCW3). Also the port that receives ICW1 to begin an
/// init sequence.
const MASTER_CMD: Port8 = Port8::new(0x20);

/// Master PIC data port. Holds the mask register (OCW1) in normal operation
/// and ICW2/ICW3/ICW4 in sequence during init.
const MASTER_DATA: Port8 = Port8::new(0x21);

/// Slave PIC command port — the slave's analogue of [`MASTER_CMD`].
const SLAVE_CMD: Port8 = Port8::new(0xA0);

/// Slave PIC data port — the slave's analogue of [`MASTER_DATA`].
const SLAVE_DATA: Port8 = Port8::new(0xA1);

// ---------------------------------------------------------------------------
// Command word encodings
// ---------------------------------------------------------------------------

// ICW1 — sent to the command port. Bit 4 must be set so the chip recognises
// the write as ICW1 (rather than an OCW2/OCW3). The remaining bits select
// edge/level triggering, address interval, single/cascade, and whether ICW4
// follows.
//
//   bit 0 (IC4)    = 1  -> ICW4 will be sent
//   bit 1 (SNGL)   = 0  -> cascade mode (two chips)
//   bit 3 (LTIM)   = 0  -> edge-triggered (legacy ISA default)
//   bit 4 (ICW1)   = 1  -> this is ICW1
//
// 0x11 = 0b0001_0001.
const ICW1_ICW4_NEEDED: u8 = 0x01;
const ICW1_CASCADE: u8 = 0x00;
const ICW1_EDGE_TRIGGERED: u8 = 0x00;
const ICW1_INIT: u8 = 0x10;
const ICW1: u8 = ICW1_INIT | ICW1_ICW4_NEEDED | ICW1_CASCADE | ICW1_EDGE_TRIGGERED;

/// Master PIC vector offset. IRQ0..7 on the master map to vectors
/// `0x20..=0x27`. `0x20` is the lowest vector outside the CPU-exception
/// range (`0..=0x1F`), so this choice keeps the legacy IRQs clear of every
/// architecture exception.
const MASTER_OFFSET: u8 = 0x20;

/// Slave PIC vector offset. IRQ8..15 on the slave map to vectors
/// `0x28..=0x2F`, continuing immediately above the master's range so the 16
/// legacy IRQs occupy a single contiguous block `0x20..=0x2F`.
const SLAVE_OFFSET: u8 = 0x28;

// ICW3 — cascade wiring. The two chips get *different* encodings.
//
// Master: a bit per IRQ input; the bit that is wired to the slave's INT
// output is set. The slave hangs off IRQ2, so bit 2 = 0x04.
//
// Slave: a 3-bit slave ID identifying which master IRQ input this chip
// drives. IRQ2 corresponds to slave ID 2 = 0x02.
const ICW3_MASTER_SLAVE_ON_IRQ2: u8 = 0x04;
const ICW3_SLAVE_ID_IS_IRQ2: u8 = 0x02;

// ICW4 — operating mode. The only bit Xenith cares about is bit 0 (µP mode),
// which selects 8086-family interrupt sequencing (call-gate-style vectors)
// over 8080/MCS-85 sequencing. Auto-EOI is left off (bit 1 = 0) so handlers
// issue an explicit EOI via [`end_of_interrupt`]; this is required for any
// nested IRQ handling and matches what the APIC path expects.
const ICW4_8086_MODE: u8 = 0x01;
const ICW4: u8 = ICW4_8086_MODE;

/// OCW2 non-specific EOI: sent to a command port to clear the highest-priority
/// bit in the chip's In-Service Register. The value `0x20` is the canonical
/// "send EOI" command (bit 5 = EOI, no specific IRQ level).
const OCW2_NON_SPECIFIC_EOI: u8 = 0x20;

/// The all-masked OCW1 value: every bit set means every IRQ line masked.
/// Written to each chip's data port to quiesce it.
const ALL_MASKED: u8 = 0xFF;

/// The number of IRQ lines a single 8259 exposes.
const IRQS_PER_CHIP: u8 = 8;

/// The legacy PIC's full IRQ count: 16 lines across the two cascaded chips.
pub const LEGACY_IRQ_COUNT: u8 = 16;

/// Map a legacy PIC IRQ number (0..15) to the remapped CPU vector it would
/// deliver into.
///
/// IRQ 0..7 come from the master (offset `0x20`); IRQ 8..15 come from the
/// slave (offset `0x28`). This is the inverse of the vector the IDT sees, and
/// is useful for wiring an early IDT slot for a stray PIC interrupt before
/// the APIC fully takes over.
#[inline]
#[must_use]
pub const fn irq_to_vector(irq: u8) -> u8 {
    if irq < IRQS_PER_CHIP {
        MASTER_OFFSET + irq
    } else {
        SLAVE_OFFSET + (irq - IRQS_PER_CHIP)
    }
}

/// Inverse of [`irq_to_vector`]: map a remapped vector back to the legacy IRQ
/// number, or `None` if the vector is outside the PIC's `0x20..=0x2F` range.
#[inline]
#[must_use]
pub const fn vector_to_irq(vector: u8) -> Option<u8> {
    if vector >= MASTER_OFFSET && vector < MASTER_OFFSET + LEGACY_IRQ_COUNT {
        Some(vector - MASTER_OFFSET)
    } else {
        None
    }
}

// ---------------------------------------------------------------------------
// Low-level chip access
// ---------------------------------------------------------------------------

/// Send one ICW/OCW byte to a chip's command port and wait an ISA-bus cycle.
///
/// The 8259 is an old, slow part: back-to-back writes to the command port can
/// be dropped on vintage hardware if the bus cycle is not given time to
/// complete. [`io_wait`] inserts that delay by posting a dummy write to the
/// POST debug port 0x80, which is guaranteed to consume one ISA cycle. On
/// modern chipsets the wait is a no-op in practice but is kept for
/// correctness on real PC hardware — this is a bare-metal kernel and the
/// extra microsecond costs nothing at boot.
#[inline]
fn cmd_write(port: Port8, value: u8) {
    port.write(value);
    io_wait();
}

/// Send one ICW byte to a chip's data port and wait an ISA-bus cycle. Same
/// rationale as [`cmd_write`]: the data port accepts ICW2/ICW3/ICW4 in
/// sequence during init, and the chip counts writes, so each must land.
#[inline]
fn data_write(port: Port8, value: u8) {
    port.write(value);
    io_wait();
}

/// Programme both chips with the ICW1 → ICW2 → ICW3 → ICW4 init ladder.
///
/// The 8259 init sequence is a state machine: writing ICW1 to the command
/// port resets the chip and starts it counting the next data-port writes as
/// ICW2, ICW3, ICW4 in that order. The two chips are initialised in parallel
/// (each ICW step is issued to both before moving to the next) so the slave
/// is never in a half-initialised state relative to the master. The sequence
/// must run with maskable interrupts disabled, which is the case during
/// boot before `sti`.
fn program_icws() {
    // ICW1: start the init ladder on both chips. Sent to the command port.
    cmd_write(MASTER_CMD, ICW1);
    cmd_write(SLAVE_CMD, ICW1);

    // ICW2: vector offsets. Master IRQ0..7 -> 0x20..0x27, slave IRQ8..15 ->
    // 0x28..0x2F. The chip uses the high 5 bits of this byte as the vector
    // base and ORs the low 3 bits with the IRQ level at delivery time, so
    // the value must be 8-aligned — both offsets above are.
    data_write(MASTER_DATA, MASTER_OFFSET);
    data_write(SLAVE_DATA, SLAVE_OFFSET);

    // ICW3: cascade wiring. The master learns a slave is attached to its
    // IRQ2 line; the slave learns it is the slave on IRQ2. Mismatched ICW3
    // values break cascade delivery silently, so the pair is documented.
    data_write(MASTER_DATA, ICW3_MASTER_SLAVE_ON_IRQ2);
    data_write(SLAVE_DATA, ICW3_SLAVE_ID_IS_IRQ2);

    // ICW4: 8086 mode, no auto-EOI. After this write the chips leave init
    // and the data ports return to accepting OCW1 (the mask register).
    data_write(MASTER_DATA, ICW4);
    data_write(SLAVE_DATA, ICW4);
}

/// Write `mask` to both chips' mask registers (OCW1).
///
/// Bit `n` set in the mask register blocks IRQ `n` on that chip. Writing
/// `0xFF` masks all eight lines; writing `0x00` unmasks all. The data port
/// is the mask register in normal (post-init) operation.
#[inline]
fn set_mask_register(mask: u8) {
    MASTER_DATA.write(mask);
    io_wait();
    SLAVE_DATA.write(mask);
    io_wait();
}

/// Mask every line on both chips. The standard quiescent state for the PIC
/// once the APIC owns delivery.
#[inline]
fn mask_all() {
    set_mask_register(ALL_MASKED);
}

/// Read the master's mask register. Useful for diagnostics and for
/// save/restore across a temporary PIC re-enable.
#[inline]
#[must_use]
fn master_mask() -> u8 {
    MASTER_DATA.read()
}

/// Read the slave's mask register.
#[inline]
#[must_use]
fn slave_mask() -> u8 {
    SLAVE_DATA.read()
}

// ---------------------------------------------------------------------------
// Public surface
// ---------------------------------------------------------------------------

/// Initialise the legacy 8259 PIC: remap its vectors to `0x20..0x2F` and
/// mask all 16 IRQ lines.
///
/// This is called from [`super::init`] early in interrupt bring-up, before
/// the local APIC is enabled. The remap moves the PIC's default vectors
/// (`0x08..0x0F` / `0x70..0x77`) out of the CPU-exception range so a stray
/// IRQ during the APIC hand-off cannot impersonate an architecture fault;
/// the all-mask then ensures no legacy line is actually delivered, since
/// device IRQs are routed through the I/O APIC instead.
///
/// # Safety of calling
///
/// Safe to call exactly once on the BSP, with maskable interrupts disabled
/// (the boot state). Touching the 8259 with interrupts enabled risks taking
/// a PIC-delivered interrupt mid-sequence, which would find the chip
/// half-initialised.
pub fn init() {
    // Run the four-word init ladder on both chips. After this the vectors
    // are remapped and the data ports accept the mask register.
    program_icws();

    // Quiesce: mask every line so no legacy IRQ fires. The APIC owns device
    // delivery; an unmasked PIC line would double-deliver or route to the
    // wrong handler.
    mask_all();

    ::log::info!(
        "xenith.pic: 8259 remapped master=0x{:02x} slave=0x{:02x}, all 16 IRQs masked",
        MASTER_OFFSET,
        SLAVE_OFFSET
    );
}

/// Fully disable the legacy 8259 PIC by masking all lines.
///
/// Distinct from [`init`] in intent rather than effect: [`init`] is the
/// one-time bring-up that also remaps the vectors; [`pic_disable`] is the
/// "we are handing the platform to the APIC now" step called once the local
/// and I/O APICs are online and routing. It writes the all-mask again (the
/// PIC may have been touched by SMM or by an early handler in the meantime)
/// and logs the takeover so the boot log makes the hand-off visible.
///
/// After this returns, the PIC is present and masked but inert; the only
/// remaining reason to touch it is a legacy [`end_of_interrupt`].
pub fn pic_disable() {
    mask_all();
    ::log::info!("xenith.pic: legacy 8259 masked, APIC owns IRQ delivery");
}

/// Send a non-specific End-Of-Interrupt to both 8259 chips.
///
/// A non-specific EOI clears the highest-priority bit in the chip's
/// In-Service Register, which is correct for any handler that does not need
/// to identify the exact IRQ it serviced. The slave is EOI'd first, then the
/// master: if the interrupt came from the slave, the master's ISR bit for
/// IRQ2 (the cascade line) is still set and must be cleared after the slave
/// has dropped its own in-service bit; clearing the master first could let a
/// second slave IRQ be lost. For a master-only IRQ the slave EOI is a no-op
/// (its ISR is empty), so issuing both unconditionally is safe.
///
/// This is the *legacy* EOI path. When the local APIC is the active
/// controller — the normal case after [`pic_disable`] — a handler must EOI
/// the LAPIC's EOI register instead, not this function. Calling this with
/// the APIC active is harmless (the PIC's ISR is already clear) but does
/// not satisfy the LAPIC's EOI requirement, so the caller must know which
/// controller fired it. The function exists for the rare early-boot or
/// SMI-hand-off path where the PIC is still in charge.
pub fn end_of_interrupt() {
    // Slave first, then master — see the function-level docs for why the
    // order matters for cascaded slave IRQs.
    SLAVE_CMD.write(OCW2_NON_SPECIFIC_EOI);
    MASTER_CMD.write(OCW2_NON_SPECIFIC_EOI);
}

/// Mask a single legacy IRQ line by number (0..15), leaving the others as
/// they were.
///
/// Reads the relevant chip's mask register, sets the bit for `irq`, and
/// writes it back. Out-of-range `irq` values are logged and ignored rather
/// than panicking: a driver probing a device it mistakenly believes is on a
/// legacy IRQ should not bring the kernel down.
pub fn mask_irq(irq: u8) {
    if irq >= LEGACY_IRQ_COUNT {
        ::log::warn!("xenith.pic: mask_irq out of range ({})", irq);
        return;
    }
    if irq < IRQS_PER_CHIP {
        let mask = master_mask() | (1 << irq);
        MASTER_DATA.write(mask);
    } else {
        let bit = 1 << (irq - IRQS_PER_CHIP);
        let mask = slave_mask() | bit;
        SLAVE_DATA.write(mask);
    }
}

/// Unmask a single legacy IRQ line by number (0..15), leaving the others as
/// they were.
///
/// This is rarely used — Xenith routes device IRQs through the I/O APIC, not
/// the PIC — but is provided for completeness and for the rare early-boot
/// path that observes a legacy line before APIC routing is up. Out-of-range
/// `irq` values are logged and ignored.
pub fn unmask_irq(irq: u8) {
    if irq >= LEGACY_IRQ_COUNT {
        ::log::warn!("xenith.pic: unmask_irq out of range ({})", irq);
        return;
    }
    if irq < IRQS_PER_CHIP {
        let mask = master_mask() & !(1 << irq);
        MASTER_DATA.write(mask);
    } else {
        let bit = 1 << (irq - IRQS_PER_CHIP);
        let mask = slave_mask() & !bit;
        SLAVE_DATA.write(mask);
    }
}

/// Snapshot the combined 16-bit mask: bit `n` set means legacy IRQ `n` is
/// masked. Bits 0..7 come from the master, bits 8..15 from the slave.
///
/// Pure read, no side effects. Useful for diagnostics and for asserting at
/// runtime that the PIC is in the quiescent all-masked state after boot.
#[must_use]
pub fn mask_snapshot() -> u16 {
    let master = u16::from(master_mask());
    let slave = u16::from(slave_mask());
    master | (slave << 8)
}

/// Whether the legacy PIC is fully quiescent (all 16 lines masked).
///
/// Convenience wrapper over [`mask_snapshot`] for the common boot-time
/// assertion that the PIC has been parked before APIC routing is enabled.
#[inline]
#[must_use]
pub fn is_fully_masked() -> bool {
    mask_snapshot() == 0xFFFF
}

// ---------------------------------------------------------------------------
// Tests — pure logic, no hardware touched
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn icw1_packs_init_and_icw4_bits() {
        // bit 4 (init) + bit 0 (ICW4 needed) = 0x11.
        assert_eq!(ICW1, 0x11);
        assert_eq!(ICW1 & 0x10, 0x10);
        assert_eq!(ICW1 & 0x01, 0x01);
    }

    #[test]
    fn icw3_cascade_values_match_irq2_wiring() {
        // Master: bit 2 set (slave wired to IRQ2). Slave: ID = 2.
        assert_eq!(ICW3_MASTER_SLAVE_ON_IRQ2, 1 << 2);
        assert_eq!(ICW3_SLAVE_ID_IS_IRQ2, 2);
    }

    #[test]
    fn icw4_is_8086_mode_without_auto_eoi() {
        // bit 0 = 8086 mode; bit 1 (auto-EOI) must be clear.
        assert_eq!(ICW4 & 0x01, 0x01);
        assert_eq!(ICW4 & 0x02, 0x00);
    }

    #[test]
    fn offsets_are_eight_aligned_and_outside_exception_range() {
        // Both offsets must be 8-aligned (the chip ORs the low 3 bits with
        // the IRQ level) and must lie above the 0x20 CPU-exception ceiling.
        assert_eq!(MASTER_OFFSET % 8, 0);
        assert_eq!(SLAVE_OFFSET % 8, 0);
        const {
            assert!(MASTER_OFFSET >= 0x20);
            assert!(SLAVE_OFFSET >= 0x20);
        }
        // Slave continues immediately above the master: 0x28 = 0x20 + 8.
        assert_eq!(SLAVE_OFFSET, MASTER_OFFSET + IRQS_PER_CHIP);
    }

    #[test]
    fn irq_to_vector_covers_all_16_legacy_lines() {
        // Master IRQs 0..7 -> vectors 0x20..0x27.
        for irq in 0..IRQS_PER_CHIP {
            assert_eq!(irq_to_vector(irq), MASTER_OFFSET + irq);
        }
        // Slave IRQs 8..15 -> vectors 0x28..0x2F.
        for irq in IRQS_PER_CHIP..LEGACY_IRQ_COUNT {
            assert_eq!(irq_to_vector(irq), SLAVE_OFFSET + (irq - IRQS_PER_CHIP));
        }
    }

    #[test]
    fn vector_to_irq_round_trips_inside_pic_range() {
        for irq in 0..LEGACY_IRQ_COUNT {
            let v = irq_to_vector(irq);
            assert_eq!(vector_to_irq(v), Some(irq));
        }
        // Vectors outside 0x20..=0x2F are not PIC lines.
        assert_eq!(vector_to_irq(0x1F), None);
        assert_eq!(vector_to_irq(0x30), None);
        assert_eq!(vector_to_irq(0x00), None);
    }

    #[test]
    fn all_masked_is_every_bit_set() {
        assert_eq!(ALL_MASKED, 0xFF);
    }

    #[test]
    fn eoi_command_is_non_specific() {
        // bit 5 = EOI; no specific level bits -> non-specific.
        assert_eq!(OCW2_NON_SPECIFIC_EOI, 0x20);
        assert_eq!(OCW2_NON_SPECIFIC_EOI & 0x20, 0x20);
        // specific-EOI would have bits 0..2 set; non-specific has them clear.
        assert_eq!(OCW2_NON_SPECIFIC_EOI & 0x07, 0x00);
    }
}
