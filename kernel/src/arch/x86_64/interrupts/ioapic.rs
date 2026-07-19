//! I/O APIC driver — redirection-table programming and IRQ routing.
//!
//! The I/O APIC is the platform interrupt router that forwards device IRQs to
//! the local APIC of a chosen CPU. Each I/O APIC owns a contiguous range of
//! Global System Interrupt (GSI) lines and maps each GSI to a vector + CPU via
//! a 64-bit Redirection Table Entry (IOREDTBL). A modern PC has one I/O APIC
//! covering GSI 0..23 (the legacy 16 PIC IRQs plus 8 more for PCI), and the
//! ACPI MADT may enumerate additional I/O APICs to cover larger GSI ranges on
//! big-SMP or server systems.
//!
//! # Register access
//!
//! The I/O APIC is memory-mapped at a 4 KiB window reported by the MADT
//! (default `0xFEC0_0000`). Two 32-bit registers are exposed in that window:
//!
//!   * `IOREGSEL` at offset `0x00` — the index register, written to select
//!     the 32-bit register the next access hits.
//!   * `IOWIN`    at offset `0x10` — the data window, read or written to
//!     access the selected register.
//!
//! Every access is a two-step `select → read/write` pair. The 64-bit
//! IOREDTBL entries are split across two 32-bit accesses: the low 32 bits at
//! `0x10 + 2*n` and the high 32 bits at `0x11 + 2*n`.
//!
//! # Discovery
//!
//! The set of I/O APICs is enumerated from validated ACPI MADT type-1 entries.
//! An ACPI-less legacy handoff retains the conventional single-controller
//! fallback used by Xenith's direct emulator loader.
//!
//! # Address translation
//!
//! The MADT reports the I/O APIC's MMIO base as a *physical* address. Limine
//! direct-maps all physical memory at the HHDM base `0xFFFF_8000_0000_0000`,
//! so converting a physical MMIO base to the dereferenceable virtual address
//! is plain additive arithmetic. The constant mirrors [`crate::panic`]'s
//! `HHDM_BASE`; a future `mm::phys_to_virt` helper replaces both call sites.

use core::ptr::{read_volatile, write_volatile};

use xenith_bitflags::bitflags;
use xenith_types::{PhysAddr, VirtAddr};

pub use crate::acpi::madt::MadtIoApicEntry;
use crate::acpi::madt::{IsaIrqPolarity, IsaIrqTriggerMode};
use crate::sync::SpinLock;

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

/// The Limine higher-half direct-map base. Adding a physical address to this
/// yields the canonical virtual address that dereferences to that physical
/// byte. Mirrors `crate::panic::HHDM_BASE`; a shared `mm::phys_to_virt` will
/// consolidate the two.
const HHDM_BASE: u64 = 0xFFFF_8000_0000_0000;

/// The default I/O APIC MMIO base on a PC-AT compatible system. The MADT
/// normally reports this exact value; the ACPI-less direct-emulator fallback
/// uses it for the conventional single-controller layout.
const DEFAULT_IOAPIC_MMIO: u32 = 0xFEC0_0000;

/// The number of redirection entries the classic single-IOAPIC PC layout
/// exposes (24). Real hardware reports the actual count in the version
/// register's `max_redir` field; this is only the fallback's initial value.
const DEFAULT_MAX_ENTRIES: u8 = 24;

/// IOREGSEL: the 8-bit index register, written to select which 32-bit
/// register the next IOWIN access hits. Although the field is 8 bits, it
/// occupies a 32-bit aligned slot; we always access it as a 32-bit write.
#[allow(dead_code)]
const IOREGSEL_OFFSET: u64 = 0x00;

/// IOWIN: the 32-bit data window. A read or write here hits the register
/// currently selected by IOREGSEL. The window is at offset 0x10, not 0x04 —
/// a common mistake when porting from the local APIC's 0x10 stride.
const IOWIN_OFFSET: u64 = 0x10;

// I/O APIC register indices (written to IOREGSEL).
/// IOAPIC ID register. Bits 24..27 hold the 4-bit APIC ID.
const REG_IOAPIC_ID: u8 = 0x00;
/// IOAPIC Version register. Bits 0..7 = version, bits 16..23 = max redir
/// entry index (the count is this value + 1).
const REG_IOAPIC_VER: u8 = 0x01;
/// IOAPIC Arbitration ID register (legacy, read-only on modern parts).
#[allow(dead_code)]
const REG_IOAPIC_ARB: u8 = 0x02;
/// Base index of the first IOREDTBL entry. Entry `n`'s low 32 bits are at
/// `REG_IOREDTBL + 2*n` and its high 32 bits at `REG_IOREDTBL + 2*n + 1`.
const REG_IOREDTBL: u8 = 0x10;

// ---------------------------------------------------------------------------
// ACPI MADT discovery
// ---------------------------------------------------------------------------

/// The platform's I/O APIC set, as enumerated by the ACPI MADT.
///
/// A successfully parsed ACPI table set is authoritative, including an empty
/// result. The fixed PC layout is used only when ACPI did not initialize, as
/// happens under the direct emulator handoff.
fn madt_ioapics() -> &'static [MadtIoApicEntry] {
    let discovered = crate::acpi::madt_ioapics();
    if crate::acpi::initialised() || !discovered.is_empty() {
        return discovered;
    }
    static LEGACY: [MadtIoApicEntry; 1] = [MadtIoApicEntry {
        id: 1,
        mmio_base: DEFAULT_IOAPIC_MMIO,
        gsi_base: 0,
    }];
    &LEGACY
}

// ---------------------------------------------------------------------------
// Redirection entry field types
// ---------------------------------------------------------------------------

/// Delivery mode for a redirection entry — how the interrupt is signalled to
/// the destination CPU(s).
///
/// Encoded in IOREDTBL bits 8..10. The three-bit encoding is fixed by the
/// Intel 82093AA IOAPIC datasheet and inherited by every later IOAPIC; the
/// numeric values are stable so they can be packed directly.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(u8)]
pub enum DeliveryMode {
    /// Deliver to all CPUs listed in the destination (lowest-priority among
    /// them). The default for ordinary device IRQs.
    Fixed = 0b000,
    /// System Management Interrupt. Routed to the SMI handler; vector is
    /// ignored. Rarely used by generic devices.
    Smi = 0b010,
    /// Non-Maskable Interrupt. Bypasses the CPU's IF flag; vector is taken
    /// from the NMI vector (2), not this entry's vector field.
    Nmi = 0b100,
    /// INIT delivery — asserts the INIT pin of the destination CPU. Used by
    /// the SMP bring-up path, not by device IRQs.
    Init = 0b101,
    /// External INT — defers vector selection to the 8259 PIC. Used only for
    /// the legacy PIC pass-through entry (GSI 0..15 wired to the PIC).
    ExtInt = 0b111,
}

impl DeliveryMode {
    /// The 3-bit encoding packed into IOREDTBL bits 8..10.
    #[inline]
    #[must_use]
    pub const fn bits(self) -> u32 {
        self as u32
    }
}

/// Destination mode — how the `destination` field is interpreted.
///
/// Encoded in IOREDTBL bit 11. Physical mode addresses a single CPU by its
/// local APIC ID; logical mode addresses a set of CPUs by their logical APIC
/// ID (a bitmap shaped by the DFR/LDR registers in the local APIC).
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(u8)]
pub enum DestMode {
    /// `destination` is a physical local APIC ID. One CPU receives the
    /// interrupt. The safe default for kernels that do not set up logical
    /// APIC clustering.
    Physical = 0,
    /// `destination` is a logical APIC ID (8-bit set in flat or cluster
    /// model). Allows broadcasting to a group of CPUs.
    Logical = 1,
}

impl DestMode {
    /// The 1-bit encoding packed into IOREDTBL bit 11.
    #[inline]
    #[must_use]
    pub const fn bit(self) -> u32 {
        (self as u32) << 11
    }
}

/// Pin polarity — the active level of the IRQ line.
///
/// Encoded in IOREDTBL bit 13. Legacy ISA IRQs and most PCI interrupt lines
/// are active-low (level-triggered) on modern hardware; the legacy PIC
/// pass-through entries are active-high edge.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(u8)]
pub enum PinPolarity {
    /// Active-high. The legacy default for edge-triggered ISA IRQs.
    ActiveHigh = 0,
    /// Active-low. The PCI default; also the level-triggered default for
    /// modern ACPI interrupt specs.
    ActiveLow = 1,
}

impl PinPolarity {
    /// The 1-bit encoding packed into IOREDTBL bit 13.
    #[inline]
    #[must_use]
    pub const fn bit(self) -> u32 {
        (self as u32) << 13
    }
}

/// Trigger mode — edge vs. level.
///
/// Encoded in IOREDTBL bit 15. Edge-triggered lines fire on the transition;
/// level-triggered lines fire while the level is asserted and must be
/// de-asserted by the device's EOI path.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(u8)]
pub enum TriggerMode {
    /// Edge-triggered. The legacy ISA default.
    Edge = 0,
    /// Level-triggered. The PCI / modern ACPI default.
    Level = 1,
}

impl TriggerMode {
    /// The 1-bit encoding packed into IOREDTBL bit 15.
    #[inline]
    #[must_use]
    pub const fn bit(self) -> u32 {
        (self as u32) << 15
    }
}

// Flag bits packed into a redirection entry's low 32 bits beyond the vector.
bitflags! {
    /// Mode flags for an I/O APIC redirection entry.
    ///
    /// Backed by `u32` because these bits all live in the low 32-bit half of
    /// the 64-bit IOREDTBL register. The high 32 bits carry only the
    /// destination field and are handled directly in [`RedirEntry`].
    pub struct RedirFlags: u32 {
        /// Delivery Mode = Fixed (bits 8..10 = 000). The default for
        /// ordinary device IRQs.
        const DELIVERY_FIXED  = 0b000 << 8;
        /// Delivery Mode = SMI (bits 8..10 = 010).
        const DELIVERY_SMI    = 0b010 << 8;
        /// Delivery Mode = NMI (bits 8..10 = 100).
        const DELIVERY_NMI    = 0b100 << 8;
        /// Delivery Mode = INIT (bits 8..10 = 101).
        const DELIVERY_INIT   = 0b101 << 8;
        /// Delivery Mode = ExtINT (bits 8..10 = 111).
        const DELIVERY_EXTINT = 0b111 << 8;
        /// Destination Mode = Logical (bit 11). Absence means Physical.
        const DEST_LOGICAL    = 1 << 11;
        /// Pin Polarity = Active Low (bit 13). Absence means Active High.
        const POLARITY_LOW    = 1 << 13;
        /// Trigger Mode = Level (bit 15). Absence means Edge.
        const TRIGGER_LEVEL   = 1 << 15;
        /// Mask the entry (bit 16). Set to block the IRQ from being delivered.
        const MASKED          = 1 << 16;
    }
}

impl RedirFlags {
    /// Build a flag set from the typed enum values, the canonical way to
    /// construct a redirection entry's mode bits. Vector and destination are
    /// packed by [`RedirEntry::new`].
    #[inline]
    #[must_use]
    pub const fn from_mode(
        delivery: DeliveryMode,
        dest: DestMode,
        polarity: PinPolarity,
        trigger: TriggerMode,
        masked: bool,
    ) -> Self {
        // OR the delivery mode bits into place, then the single-bit fields.
        let mut bits = delivery.bits() << 8;
        if matches!(dest, DestMode::Logical) {
            bits |= Self::DEST_LOGICAL.0;
        }
        if matches!(polarity, PinPolarity::ActiveLow) {
            bits |= Self::POLARITY_LOW.0;
        }
        if matches!(trigger, TriggerMode::Level) {
            bits |= Self::TRIGGER_LEVEL.0;
        }
        if masked {
            bits |= Self::MASKED.0;
        }
        Self(bits)
    }
}

/// A fully-decoded I/O APIC redirection table entry, ready to be split into
/// the low and high 32-bit halves the hardware expects.
///
/// The 64-bit IOREDTBL layout (Intel 82093AA, shared by all later IOAPICs):
///
/// ```text
///   bits  0..7   vector              (low word)
///   bits  8..10  delivery mode       (low word)
///   bit   11     destination mode    (low word)
///   bit   12     delivery status RO  (low word, ignored on write)
///   bit   13     pin polarity        (low word)
///   bit   14     remote IRR RO       (low word, ignored on write)
///   bit   15     trigger mode        (low word)
///   bit   16     mask                (low word)
///   bits 17..63  reserved            (low word 17..31 reserved;
///                                     high word 0..23 reserved,
///                                     high word 24..31 = destination)
/// ```
///
/// The destination field is the local APIC ID (physical mode) or logical ID
/// (logical mode) placed in the *high* word's top byte.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct RedirEntry {
    /// The 8-bit interrupt vector. Must be in `0x20..=0xFF` to avoid the
    /// CPU-exception range and the LAPIC's spurious-vector convention.
    vector: u8,
    /// Mode flags (delivery, dest mode, polarity, trigger, mask).
    flags: RedirFlags,
    /// The destination APIC ID (physical) or logical-ID set (logical),
    /// placed in the high word's bits 24..31.
    destination: u8,
}

impl RedirEntry {
    /// Construct a redirection entry from its typed parts.
    ///
    /// `vector` is stored verbatim; callers are responsible for keeping it
    /// out of the `0..0x20` CPU-exception range.
    #[inline]
    #[must_use]
    pub const fn new(
        vector: u8,
        delivery: DeliveryMode,
        dest: DestMode,
        polarity: PinPolarity,
        trigger: TriggerMode,
        masked: bool,
        destination: u8,
    ) -> Self {
        Self {
            vector,
            flags: RedirFlags::from_mode(delivery, dest, polarity, trigger, masked),
            destination,
        }
    }

    /// The low 32 bits of the IOREDTBL register.
    #[inline]
    #[must_use]
    pub const fn low(self) -> u32 {
        (self.vector as u32) | self.flags.bits()
    }

    /// The high 32 bits of the IOREDTBL register. The destination occupies
    /// bits 24..31; everything else is reserved zero.
    #[inline]
    #[must_use]
    pub const fn high(self) -> u32 {
        (self.destination as u32) << 24
    }

    /// Whether the entry is currently masked.
    #[inline]
    #[must_use]
    pub const fn is_masked(self) -> bool {
        self.flags.contains(RedirFlags::MASKED)
    }

    /// A copy of this entry with the mask bit set (IRQ blocked).
    #[inline]
    #[must_use]
    pub fn masked(self) -> Self {
        let mut f = self.flags;
        f.insert(RedirFlags::MASKED);
        Self { flags: f, ..self }
    }

    /// A copy of this entry with the mask bit cleared (IRQ enabled).
    #[inline]
    #[must_use]
    pub fn unmasked(self) -> Self {
        let mut f = self.flags;
        f.remove(RedirFlags::MASKED);
        Self { flags: f, ..self }
    }
}

// ---------------------------------------------------------------------------
// IoApic — one controller instance
// ---------------------------------------------------------------------------

/// One I/O APIC, addressed by its MMIO register window.
///
/// Each instance owns the MMIO base pointer (already translated to a virtual
/// address through the HHDM), the first GSI it handles, and the number of
/// redirection entries it exposes. All register access goes through the
/// two-step `select → read/write` protocol; the methods here serialise that
/// protocol so callers never have to touch IOREGSEL directly.
pub struct IoApic {
    /// The virtual address of the I/O APIC's 4 KiB MMIO window. Stored as a
    /// `u64` rather than a `*mut` so the struct stays `Send`/`Sync`-able
    /// inside the global registry without a raw-pointer `unsafe impl`.
    mmio_virt: u64,
    /// The first GSI this IOAPIC handles. GSI `gsi_base + n` maps to
    /// redirection entry `n`.
    gsi_base: u32,
    /// The APIC ID programmed into the IOAPIC ID register during bring-up.
    id: u8,
    /// The number of redirection entries, read from the version register at
    /// init. Capped at 24 for the classic layout but the hardware value is
    /// authoritative.
    max_entries: u8,
}

impl IoApic {
    /// Construct a handle to the I/O APIC whose MMIO window is at `mmio_phys`
    /// and whose first GSI is `gsi_base`.
    ///
    /// Does not touch the hardware — the caller (the module-level [`init`])
    /// drives bring-up by calling [`set_id`](Self::set_id),
    /// [`read_version`](Self::read_version), and [`mask_all`](Self::mask_all)
    /// before any redirection programming. The physical MMIO base is
    /// translated to the HHDM virtual address here so later accesses are pure
    /// volatile loads/stores with no per-access arithmetic.
    #[must_use]
    pub fn new(mmio_phys: u32, gsi_base: u32, id: u8) -> Self {
        // Translate the physical MMIO base through the HHDM direct map.
        // Limine maps all physical memory 1:1 at HHDM_BASE, so the IOAPIC's
        // 4 KiB register window is reachable at `HHDM_BASE + mmio_phys`
        // without allocating any page tables of our own.
        //
        // Route the raw u32 through `PhysAddr`/`VirtAddr` so the typed
        // constructors validate the address (PhysAddr rejects bits above 52,
        // VirtAddr canonicalises) before we flatten back to the u64 the
        // volatile accesses want. Storing a u64 — not a `*mut` — keeps the
        // struct `Send`+`Sync` without an `unsafe impl` at the registry.
        let phys = PhysAddr::new_truncate(u64::from(mmio_phys));
        let virt = VirtAddr::new_truncate(HHDM_BASE + phys.as_u64());
        Self {
            mmio_virt: virt.as_u64(),
            gsi_base,
            id,
            max_entries: DEFAULT_MAX_ENTRIES,
        }
    }

    /// The first GSI this IOAPIC handles.
    #[inline]
    #[must_use]
    pub const fn gsi_base(&self) -> u32 {
        self.gsi_base
    }

    /// One past the last GSI this IOAPIC handles (`gsi_base + max_entries`).
    #[inline]
    #[must_use]
    pub const fn gsi_end(&self) -> u32 {
        self.gsi_base + self.max_entries as u32
    }

    /// The number of redirection entries this IOAPIC exposes.
    #[inline]
    #[must_use]
    pub const fn max_entries(&self) -> u8 {
        self.max_entries
    }

    /// Select the register indexed by `reg` for the next IOWIN access.
    ///
    /// IOREGSEL is a 32-bit aligned slot holding an 8-bit index; we write the
    /// full 32 bits for simplicity. The write is volatile because it has a
    /// side effect on the IOWIN window — the compiler must not elide it.
    #[inline]
    fn select(&self, reg: u8) {
        // SAFETY: `mmio_virt` points at the I/O APIC's MMIO window, which
        // Limine direct-mapped and which the MADT enumerated as a device
        // MMIO region. The offset 0x00 is IOREGSEL. A 32-bit volatile store
        // to an aligned MMIO address is the documented access width.
        unsafe {
            write_volatile(self.mmio_virt as *mut u32, u32::from(reg));
        }
    }

    /// Read the 32-bit register currently selected by IOREGSEL via IOWIN.
    ///
    /// # Safety
    ///
    /// The caller must have just called [`select`](Self::select) with the
    /// intended register index. IOWIN always reads the last-selected
    /// register, so a stale selection reads the wrong register.
    #[inline]
    unsafe fn read_win(&self) -> u32 {
        // SAFETY: `mmio_virt + 0x10` is IOWIN. The caller guarantees a
        // selection was just made.
        unsafe { read_volatile((self.mmio_virt + IOWIN_OFFSET) as *const u32) }
    }

    /// Write `value` to the 32-bit register currently selected by IOREGSEL.
    ///
    /// # Safety
    ///
    /// Same invariant as [`read_win`](Self::read_win): the caller must have
    /// just selected the intended register.
    #[inline]
    unsafe fn write_win(&self, value: u32) {
        // SAFETY: IOWIN write; caller guarantees a selection was just made.
        unsafe {
            write_volatile((self.mmio_virt + IOWIN_OFFSET) as *mut u32, value);
        }
    }

    /// Read the 32-bit register at `reg`.
    #[inline]
    fn read_reg(&self, reg: u8) -> u32 {
        self.select(reg);
        // SAFETY: we just selected `reg`, so IOWIN reads that register.
        unsafe { self.read_win() }
    }

    /// Write `value` to the 32-bit register at `reg`.
    #[inline]
    fn write_reg(&self, reg: u8, value: u32) {
        self.select(reg);
        // SAFETY: we just selected `reg`, so IOWIN writes that register.
        unsafe { self.write_win(value) }
    }

    /// Programme the IOAPIC ID register with this instance's APIC ID.
    ///
    /// The 4-bit APIC ID occupies bits 24..27 of the ID register; the rest
    /// is reserved zero. Setting the ID lets local APICs address this IOAPIC
    /// by ID when delivering with logical destination mode.
    pub fn set_id(&self) {
        let id_word = u32::from(self.id) << 24;
        self.write_reg(REG_IOAPIC_ID, id_word);
    }

    /// Read the version register and cache the redirection-entry count.
    ///
    /// Bits 16..23 of the version register hold the *maximum redirection
    /// entry index*, which is `count - 1`. We store the count so
    /// [`route`](Self::route) and [`mask`](Self::mask) can bounds-check GSI
    /// arguments against the real hardware capacity rather than the fallback
    /// default.
    pub fn read_version(&mut self) {
        let ver = self.read_reg(REG_IOAPIC_VER);
        // The max-redir field is the top byte of the low word; +1 for count.
        let max_idx = ((ver >> 16) & 0xFF) as u8;
        self.max_entries = max_idx + 1;
    }

    /// Read the full 64-bit redirection entry for GSI `gsi`.
    ///
    /// Returns `None` if `gsi` is outside this IOAPIC's range. The low and
    /// high 32-bit halves are read in two separate `select → read` cycles,
    /// which the hardware guarantees are individually atomic.
    #[must_use]
    pub fn get_redir(&self, gsi: u32) -> Option<RedirEntry> {
        let idx = self.gsi_to_entry(gsi)?;
        // Two 32-bit reads at consecutive register indices. We read low
        // then high; the hardware does not require the pair to be atomic.
        let low = self.read_reg(REG_IOREDTBL + 2 * idx);
        let high = self.read_reg(REG_IOREDTBL + 2 * idx + 1);
        let vector = (low & 0xFF) as u8;
        let flags = RedirFlags::from_bits_truncate(low & !0xFF);
        let destination = ((high >> 24) & 0xFF) as u8;
        Some(RedirEntry {
            vector,
            flags,
            destination,
        })
    }

    /// Programme the full 64-bit redirection entry for GSI `gsi`.
    ///
    /// Returns `None` if `gsi` is outside this IOAPIC's range. The entry is
    /// written low-half then high-half; masking is honoured per the
    /// `entry.is_masked()` flag, so callers can pre-mask a line before
    /// wiring up its handler and unmask it later via [`unmask`](Self::unmask).
    pub fn set_redir(&self, gsi: u32, entry: RedirEntry) -> Option<()> {
        let idx = self.gsi_to_entry(gsi)?;
        // Write the low half first so the mask bit (bit 16) lands before
        // the destination — this avoids a transient where the entry is
        // unmasked with a stale destination. The high half is reserved
        // except for the destination field.
        self.write_reg(REG_IOREDTBL + 2 * idx, entry.low());
        self.write_reg(REG_IOREDTBL + 2 * idx + 1, entry.high());
        Some(())
    }

    /// Translate a GSI to a redirection-entry index on this IOAPIC.
    ///
    /// Returns `None` if the GSI is not owned by this IOAPIC.
    #[inline]
    fn gsi_to_entry(&self, gsi: u32) -> Option<u8> {
        if gsi < self.gsi_base || gsi >= self.gsi_end() {
            return None;
        }
        // We checked bounds above and max_entries is u8, so the subtraction
        // is in range and the cast is sound.
        Some((gsi - self.gsi_base) as u8)
    }

    /// Mask a GSI: set the mask bit in its redirection entry without
    /// disturbing the rest of the configuration. Returns `None` if the GSI
    /// is not on this IOAPIC.
    pub fn mask(&self, gsi: u32) -> Option<()> {
        let entry = self.get_redir(gsi)?.masked();
        self.set_redir(gsi, entry)
    }

    /// Unmask a GSI: clear the mask bit. Returns `None` if the GSI is not
    /// on this IOAPIC.
    pub fn unmask(&self, gsi: u32) -> Option<()> {
        let entry = self.get_redir(gsi)?.unmasked();
        self.set_redir(gsi, entry)
    }

    /// Route `gsi` to `vector` on the CPU whose local APIC ID is `cpu`.
    ///
    /// The default delivery mode is `Fixed`, physical destination, active-low
    /// level-triggered — the modern ACPI default for PCI-style device IRQs.
    /// The entry is written masked, then unmasked, so the line is never
    /// briefly live with a stale vector while the write completes.
    pub fn route(&self, gsi: u32, vector: u8, cpu: u8) -> Option<()> {
        self.route_with_mode(gsi, vector, cpu, PinPolarity::ActiveLow, TriggerMode::Level)
    }

    /// Route a GSI with an explicit electrical polarity and trigger mode.
    /// Legacy ISA lines use active-high/edge while PCI INTx uses
    /// active-low/level, so device owners must be able to select the mode.
    pub fn route_with_mode(
        &self,
        gsi: u32,
        vector: u8,
        cpu: u8,
        polarity: PinPolarity,
        trigger: TriggerMode,
    ) -> Option<()> {
        // Write the entry masked first so the hardware never fires the IRQ
        // at an intermediate (partially-written) state. Then unmask once
        // both halves are stable.
        let masked = RedirEntry::new(
            vector,
            DeliveryMode::Fixed,
            DestMode::Physical,
            polarity,
            trigger,
            true,
            cpu,
        );
        self.set_redir(gsi, masked)?;
        self.unmask(gsi)
    }

    /// Mask every redirection entry this IOAPIC owns.
    ///
    /// Called during bring-up so no device IRQ can fire before its handler
    /// is registered and routed. Each entry's existing configuration is
    /// preserved; only the mask bit is set.
    pub fn mask_all(&self) {
        for gsi in self.gsi_base..self.gsi_end() {
            // If get_redir fails for some entry (e.g. the hardware reports
            // a larger count than it actually has), mask it with a default
            // masked entry so it still cannot fire.
            let entry = self.get_redir(gsi).map_or(
                RedirEntry::new(
                    0,
                    DeliveryMode::Fixed,
                    DestMode::Physical,
                    PinPolarity::ActiveHigh,
                    TriggerMode::Edge,
                    true,
                    0,
                ),
                |e| e.masked(),
            );
            self.set_redir(gsi, entry);
        }
    }
}

impl core::fmt::Debug for IoApic {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("IoApic")
            .field("id", &self.id)
            .field("gsi_base", &self.gsi_base)
            .field("max_entries", &self.max_entries)
            .field("mmio_virt", &format_args!("0x{:016x}", self.mmio_virt))
            .finish()
    }
}

// ---------------------------------------------------------------------------
// Global registry
// ---------------------------------------------------------------------------

/// The set of I/O APICs discovered at boot, guarded by a spinlock because
/// `route`/`mask`/`unmask` may be called from interrupt-handler registration
/// paths that race with each other on different CPUs.
///
/// Stored as a fixed-size array because the count is tiny in practice (1 on
/// a desktop, up to ~8 on a large server) and the heap is not guaranteed up
/// at the point [`init`] runs. `MAX_IOAPICS` is deliberately generous.
static IOAPICS: SpinLock<IoApicRegistry> = SpinLock::new(IoApicRegistry::new());

/// Maximum number of I/O APICs the registry holds. The ACPI specification
/// does not cap this, but in practice no platform exceeds a handful; 16 is
/// comfortably above any realistic server layout.
const MAX_IOAPICS: usize = 16;

/// A fixed-capacity array of I/O APIC handles, populated at boot.
struct IoApicRegistry {
    /// The IOAPIC slots. `count` tracks how many are live; the rest are
    /// `None` and never indexed.
    entries: [Option<IoApic>; MAX_IOAPICS],
    count: usize,
}

impl IoApicRegistry {
    /// Construct an empty registry. `const` so it can live in a `static`.
    const fn new() -> Self {
        // `Option::<IoApic>::None` is not const-constructible in a way that
        // fills an array without an explicit initializer on every slot, so
        // we build the array via a repeat of the None variant. This is the
        // idiomatic fixed-capacity-no-alloc pattern.
        const NONE: Option<IoApic> = None;
        Self {
            entries: [NONE; MAX_IOAPICS],
            count: 0,
        }
    }

    /// Append an IOAPIC to the registry. Silently drops beyond capacity;
    /// `MAX_IOAPICS` is sized so this never happens on real hardware.
    fn push(&mut self, ioapic: IoApic) {
        if self.count >= MAX_IOAPICS {
            ::log::warn!(
                "xenith.ioapic: registry full ({}), dropping IOAPIC id {}",
                MAX_IOAPICS,
                ioapic.id
            );
            return;
        }
        self.entries[self.count] = Some(ioapic);
        self.count += 1;
    }

    /// Find the IOAPIC that owns `gsi`, if any.
    fn find(&self, gsi: u32) -> Option<&IoApic> {
        self.entries[..self.count].iter().find_map(|opt| {
            opt.as_ref()
                .filter(|io| gsi >= io.gsi_base() && gsi < io.gsi_end())
        })
    }

    /// Iterate over the live IOAPICs.
    #[allow(dead_code)]
    fn iter(&self) -> impl Iterator<Item = &IoApic> {
        self.entries[..self.count].iter().filter_map(Option::as_ref)
    }
}

// ---------------------------------------------------------------------------
// Public routing surface
// ---------------------------------------------------------------------------

/// Route `gsi` to `vector` on the local APIC whose ID is `cpu`.
///
/// Returns `Some(())` if the GSI was found on a registered IOAPIC and routed,
/// or `None` if no IOAPIC owns that GSI. The entry is configured with the
/// modern ACPI defaults (fixed delivery, physical destination, active-low,
/// level-triggered) and written masked-then-unmasked so the line is never
/// transiently live with a partial configuration.
pub fn route(gsi: u32, vector: u8, cpu: u8) -> Option<()> {
    let reg = IOAPICS.lock();
    let io = reg.find(gsi)?;
    io.route(gsi, vector, cpu)
}

/// Route a legacy ISA IRQ through its ACPI Interrupt Source Override.
///
/// With no override (the VMware 8042 layout), ISA remains identity-mapped,
/// active-high, and edge-triggered. A MADT type-2 entry can independently
/// replace the GSI, polarity, and trigger mode. Using PCI's unconditional
/// low/level defaults here leaves VMware's 8042 line asserted and causes an
/// interrupt storm as soon as IF is enabled.
pub fn route_isa(irq: u8, vector: u8, cpu: u8) -> Option<()> {
    let route = crate::acpi::resolve_isa_irq(irq);
    let polarity = match route.polarity {
        IsaIrqPolarity::ActiveHigh => PinPolarity::ActiveHigh,
        IsaIrqPolarity::ActiveLow => PinPolarity::ActiveLow,
    };
    let trigger = match route.trigger {
        IsaIrqTriggerMode::Edge => TriggerMode::Edge,
        IsaIrqTriggerMode::Level => TriggerMode::Level,
    };
    let reg = IOAPICS.lock();
    let io = reg.find(route.gsi)?;
    io.route_with_mode(route.gsi, vector, cpu, polarity, trigger)
}

/// Mask a GSI: block it from being delivered without disturbing its routing.
pub fn mask(gsi: u32) -> Option<()> {
    let reg = IOAPICS.lock();
    let io = reg.find(gsi)?;
    io.mask(gsi)
}

/// Unmask a GSI: re-enable delivery of a previously-masked line.
pub fn unmask(gsi: u32) -> Option<()> {
    let reg = IOAPICS.lock();
    let io = reg.find(gsi)?;
    io.unmask(gsi)
}

/// The number of I/O APICs currently registered. Useful for diagnostics.
pub fn count() -> usize {
    IOAPICS.lock().count
}

// ---------------------------------------------------------------------------
// Bring-up
// ---------------------------------------------------------------------------

/// Bring up the I/O APIC redirection table.
///
/// Discovers the platform's I/O APIC(s) via the ACPI MADT, translates each
/// MMIO base into the HHDM,
/// programmes its APIC ID register, reads the version register to learn the
/// real redirection-entry count, and masks every entry so no device IRQ can
/// fire before its handler is registered. After this returns the IOAPICs are
/// quiescent and ready for explicit [`route`] calls from device drivers.
///
/// Called from [`super::init`] after ACPI and local APIC bring-up.
pub fn init() {
    let entries = madt_ioapics();
    if entries.is_empty() {
        ::log::warn!("xenith.ioapic: MADT reports no I/O APICs — IRQs disabled");
        return;
    }

    let mut reg = IOAPICS.lock();
    for entry in entries {
        // Validate the MMIO base before we touch it: a zero base would map
        // onto the first physical page through the HHDM and is never a real
        // IOAPIC. Log and skip rather than panic so a malformed MADT does
        // not bring the whole boot down.
        if entry.mmio_base == 0 {
            ::log::warn!(
                "xenith.ioapic: skipping IOAPIC id {} with zero MMIO base",
                entry.id
            );
            continue;
        }

        let mut io = IoApic::new(entry.mmio_base, entry.gsi_base, entry.id);
        // Programme the APIC ID first so the chip is addressable for
        // logical-destination delivery later.
        io.set_id();
        // Read the version register to learn the real entry count; the
        // constructor default is overwritten with the hardware value.
        io.read_version();
        // Mask every entry so no device IRQ fires before its driver has
        // called `route`. This is the single most important bring-up step:
        // an unmasked line with a stale or zero vector will deliver a
        // spurious interrupt to whatever vector happens to be programmed,
        // which on a freshly-booted kernel is usually the CPU-exception
        // range and triple-faults the machine.
        io.mask_all();

        ::log::info!(
            "xenith.ioapic: id {} at mmio 0x{:08x}, GSI {}..{}, {} entries",
            io.id,
            entry.mmio_base,
            io.gsi_base(),
            io.gsi_end(),
            io.max_entries()
        );

        reg.push(io);
    }

    ::log::info!(
        "xenith.ioapic: {} controller(s) online, all entries masked",
        reg.count
    );
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn redir_entry_packs_vector_and_flags() {
        let e = RedirEntry::new(
            0x40,
            DeliveryMode::Fixed,
            DestMode::Physical,
            PinPolarity::ActiveLow,
            TriggerMode::Level,
            false,
            0x0F,
        );
        // Vector in bits 0..7.
        assert_eq!(e.low() & 0xFF, 0x40);
        // Active-low -> bit 13 set.
        assert!(e.flags.contains(RedirFlags::POLARITY_LOW));
        // Level -> bit 15 set.
        assert!(e.flags.contains(RedirFlags::TRIGGER_LEVEL));
        // Not masked.
        assert!(!e.is_masked());
        // Destination in the high word's top byte.
        assert_eq!((e.high() >> 24) & 0xFF, 0x0F);
    }

    #[test]
    fn masked_and_unmasked_toggle_bit_16() {
        let base = RedirEntry::new(
            0x40,
            DeliveryMode::Fixed,
            DestMode::Physical,
            PinPolarity::ActiveHigh,
            TriggerMode::Edge,
            false,
            0,
        );
        assert!(!base.is_masked());
        assert!(base.masked().is_masked());
        // Mask bit is bit 16 of the low word.
        assert_ne!(base.low() & (1 << 16), base.masked().low() & (1 << 16));
        // unmasked() clears it again.
        assert!(!base.masked().unmasked().is_masked());
    }

    #[test]
    fn delivery_mode_bits_are_in_range_8_10() {
        assert_eq!(DeliveryMode::Fixed.bits(), 0b000);
        assert_eq!(DeliveryMode::Smi.bits(), 0b010);
        assert_eq!(DeliveryMode::Nmi.bits(), 0b100);
        assert_eq!(DeliveryMode::Init.bits(), 0b101);
        assert_eq!(DeliveryMode::ExtInt.bits(), 0b111);
    }

    #[test]
    fn gsi_to_entry_bounds_check() {
        let io = IoApic::new(DEFAULT_IOAPIC_MMIO, 16, 1);
        // GSI 16 is the first entry on this IOAPIC.
        assert_eq!(io.gsi_to_entry(16), Some(0));
        // GSI 39 is the last entry (16 + 24 - 1 = 39).
        assert_eq!(io.gsi_to_entry(39), Some(23));
        // GSI 15 is below the base.
        assert_eq!(io.gsi_to_entry(15), None);
        // GSI 40 is past the end.
        assert_eq!(io.gsi_to_entry(40), None);
    }

    #[test]
    fn registry_find_by_gsi() {
        let mut reg = IoApicRegistry::new();
        reg.push(IoApic::new(0xFEC0_0000, 0, 1));
        reg.push(IoApic::new(0xFEC8_0000, 24, 2));
        assert!(reg.find(0).is_some());
        assert!(reg.find(23).is_some());
        assert!(reg.find(24).is_some());
        // GSI 48 is past the second IOAPIC's range (24 + 24 = 48).
        assert!(reg.find(48).is_none());
    }

    #[test]
    fn high_word_destination_only_in_top_byte() {
        let e = RedirEntry::new(
            0x20,
            DeliveryMode::Fixed,
            DestMode::Physical,
            PinPolarity::ActiveHigh,
            TriggerMode::Edge,
            true,
            0xAB,
        );
        // High word: only bits 24..31 carry the destination.
        assert_eq!(e.high(), 0xAB_00_00_00);
        assert_eq!(e.high() & 0x00_FF_FF_FF, 0);
    }
}
