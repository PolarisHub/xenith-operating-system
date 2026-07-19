//! Control-register flag types: `Cr0`, `Cr3`, `Cr4`.
//!
//! The x86_64 control registers gate the major operating modes of the CPU.
//! Rather than pass raw `u64` values to `read_cr0` / `write_cr0` and hope the
//! caller remembers which bit is which, this module defines a bitflag type
//! per register using the [`xenith_bitflags::bitflags`] macro. Each type
//! carries the architecturally-defined flag constants plus `read` / `write`
//! helpers that bridge to the raw instruction wrappers in
//! [`instructions`](super::instructions).
//!
//! # Layout
//!
//! * [`Cr0`] — system control flags: paging, write-protect, x87 emulation,
//!   cache disable, etc.
//! * [`Cr3`] — the page-table root. Mostly an address (bits 12..=51) with a
//!   couple of cacheability bits; the flag set is small but the type also
//!   carries [`Cr3::frame`] / [`Cr3::with_frame`] address helpers.
//! * [`Cr4`] — feature enablement: PAE, PGE, OSFXSR, SMEP/SMAP, PCID,
//!   FSGSBASE, XSAVE, and the rest of the growing feature-enable surface.
//!
//! # Reserved bits
//!
//! Every control register has reserved bits that must be zero; writing a 1
//! to a reserved bit raises #GP. The `from_bits_truncate` constructor (from
//! the bitflags macro) masks off any bits not in the defined flag set, so a
//! `Cr0::read()` followed by `Cr0::write()` round-trips safely even if the
//! CPU sets a bit Xenith does not name. The trade-off is that an unknown
//! feature bit the CPU sets will be silently cleared on write-back — which is
//! the correct behaviour for a kernel that has not explicitly enabled that
//! feature.

use xenith_bitflags::bitflags;
use xenith_types::PhysAddr;

use super::instructions::{read_cr0, read_cr3, read_cr4, write_cr0, write_cr3, write_cr4};

// ---------------------------------------------------------------------------
// CR0
// ---------------------------------------------------------------------------

bitflags! {
    /// CR0 — the primary system control register.
    ///
    /// Gates protected mode, paging, write-protect, x87 emulation, and cache
    /// behaviour. Most bits are set once during boot and never touched again;
    /// the kernel's interest is in the x87/SSE enablement (MP/EM/NE) and
    /// write-protect (WP), which user-space memory protection relies on.
    ///
    /// Reserved bits are not named here, so `from_bits_truncate` (used by
    /// [`Cr0::read`]) drops them. Writing the result back is therefore always
    /// safe — it can only clear features the kernel has not opted into.
    pub struct Cr0: u64 {
        /// Protection Enable (bit 0). Set by Limine before the kernel runs;
        /// clearing it in long mode is fatal. Named so that `read` can assert
        /// it is set.
        const PROTECTION_ENABLE = 1 << 0;

        /// Monitor Coprocessor (bit 1). With EM clear, MP=1 means `wait`/`fwait`
        /// check TS; SSE instructions are native. Set by `early_init`.
        const MONITOR_COPROCESSOR = 1 << 1;

        /// Emulation (bit 2). When set, x87/MMX/SSE instructions trap to #NM.
        /// The kernel clears this so SIMD instructions run natively.
        const EMULATION = 1 << 2;

        /// Task Switched (bit 3). Set by the CPU on a hardware task switch;
        /// the kernel uses a software scheduler, so TS is only relevant for
        /// the lazy-FPU save/restore path, which sets it on context switch
        /// and clears it (via `clts`) when a task first touches the FPU.
        const TASK_SWITCHED = 1 << 3;

        /// Extension Type (bit 4). Hardwired to 1 on all modern CPUs;
        /// included for completeness so `read` does not truncate it away.
        const EXTENSION_TYPE = 1 << 4;

        /// Numeric Error (bit 5). Native x87 error reporting via #MF instead
        /// of the legacy PIC IRQ 13 chain. Set by `early_init`.
        const NUMERIC_ERROR = 1 << 5;

        /// Write Protect (bit 16). When set, ring 0 cannot write to
        /// read-only pages — a critical invariant for the kernel's
        /// copy-on-write and self-protection logic. Enabled after paging is
        /// up so early-boot page-table mutation is not blocked.
        const WRITE_PROTECT = 1 << 16;

        /// Alignment Mask (bit 18). When set, alignment checking is enabled
        /// for ring 3 when EFLAGS.AC is set. The kernel leaves this clear
        /// (kernel code does not set AC) so unaligned accesses do not fault.
        const ALIGNMENT_MASK = 1 << 18;

        /// Not Write-through (bit 29). Together with CD, controls caching.
        /// The kernel leaves both clear so memory is write-back cached.
        const NOT_WRITE_THROUGH = 1 << 29;

        /// Cache Disable (bit 30). Set to disable caching entirely; the
        /// kernel never sets this.
        const CACHE_DISABLE = 1 << 30;

        /// Paging Enable (bit 31). Set by Limine; the kernel never clears it.
        /// `early_init` asserts it is set as a boot-sanity check.
        const PAGING = 1 << 31;
    }
}

impl Cr0 {
    /// Read the current CR0 image.
    ///
    /// The raw `u64` is passed through `from_bits_truncate`, so any bit the
    /// CPU sets that Xenith does not name is dropped — writing the result
    /// back can therefore only clear unnamed features, never enable new ones.
    ///
    /// # Safety
    ///
    /// `mov cr0, reg` is privileged. The read has no side effects but the
    /// caller must be in ring 0. The safety is delegated to
    /// [`read_cr0`](super::instructions::read_cr0).
    #[inline]
    #[must_use]
    pub fn read() -> Self {
        // SAFETY: We are in ring 0 (kernel context). The read touches no
        // memory and has no side effects beyond returning the register value.
        let raw = unsafe { read_cr0() };
        Self::from_bits_truncate(raw)
    }

    /// Write this CR0 image back to the register.
    ///
    /// # Safety
    ///
    /// The caller must ensure the new image is a valid CR0 value: paging
    /// (bit 31) must not be cleared while running in a paged context, and
    /// protected-mode enable (bit 0) must not be cleared in long mode. Most
    /// other bits have architectural constraints documented in the SDM
    /// Vol. 3, Ch. 2. Writes to reserved bits #GP; `from_bits_truncate` in
    /// [`Cr0::read`] and the defined-flag-only constructors guarantee no
    /// reserved bits are ever set through this type.
    #[inline]
    pub unsafe fn write(self) {
        // SAFETY: Forwarded to `write_cr0`; the caller vouches for the value.
        unsafe { write_cr0(self.bits()) };
    }
}

// ---------------------------------------------------------------------------
// CR3
// ---------------------------------------------------------------------------

bitflags! {
    /// CR3 — the page-table root register.
    ///
    /// The bulk of CR3 is the physical address of the PML4 table
    /// (bits 12..=51, since PML4 is 4 KiB-aligned). The low bits carry two
    /// cacheability flags (PWT, PCD) and, when CR4.PCIDE is set, a 12-bit
    /// PCID. The high bits (52..=62) are reserved, and bit 63 is reserved on
    /// non-PCID configurations.
    ///
    /// Because the address field is not a "flag", the bitflag set here only
    /// names PWT and PCD; the address is manipulated through [`Cr3::frame`]
    /// and [`Cr3::with_frame`], which mask it out cleanly.
    pub struct Cr3: u64 {
        /// Page-Level Write-Through (bit 3). When set, the PML4 is mapped
        /// write-through rather than write-back. The kernel leaves this
        /// clear (write-back) for the page tables themselves.
        const PAGE_WRITE_THROUGH = 1 << 3;

        /// Page-Level Cache Disable (bit 4). When set, the PML4 is uncached.
        /// The kernel leaves this clear.
        const PAGE_CACHE_DISABLE = 1 << 4;
    }
}

/// The bit position of the PML4 physical address within CR3. Bits 12..=51
/// hold the address (40 bits), since the PML4 is always 4 KiB-aligned.
const CR3_ADDR_SHIFT: u64 = 12;

/// The mask covering the PML4 physical address bits within CR3.
const CR3_ADDR_MASK: u64 = ((1u64 << 40) - 1) << CR3_ADDR_SHIFT;

impl Cr3 {
    /// Read the current CR3 image, returning only the flag bits.
    ///
    /// The PML4 address field (bits 12..=51) is *not* part of the defined
    /// flag set, so `from_bits_truncate` drops it. Use this when you only
    /// care about the cacheability flags (PWT/PCD); use [`Cr3::current_frame`]
    /// or [`Cr3::read_raw`] plus [`Cr3::frame_from_raw`] when you need the
    /// page-table root address.
    ///
    /// # Safety
    ///
    /// `mov cr3, reg` is privileged. The read has no side effects (it does
    /// not flush the TLB) but the caller must be in ring 0.
    #[inline]
    #[must_use]
    pub fn read() -> Self {
        // SAFETY: Ring-0 read of CR3; no side effects.
        let raw = unsafe { read_cr3() };
        Self::from_bits_truncate(raw)
    }

    /// Read the raw CR3, preserving the address bits.
    ///
    /// Unlike [`Cr3::read`], this returns the full register value including
    /// the PML4 address, so the caller can extract the page-table root with
    /// [`frame_from_raw`]. Use this when you need the address; use
    /// [`Cr3::read`] when you only care about the cacheability flags.
    ///
    /// # Safety
    ///
    /// See [`Cr3::read`].
    #[inline]
    #[must_use]
    pub unsafe fn read_raw() -> u64 {
        // SAFETY: Ring-0 read of CR3; no side effects. Forwarded.
        unsafe { read_cr3() }
    }

    /// Write this CR3 image back to the register, switching address spaces.
    ///
    /// # Safety
    ///
    /// The caller must ensure the address bits point at a valid, present
    /// PML4 table and that the reserved bits are zero. Writing CR3 flushes
    /// non-global TLB entries on the local core, which can disrupt any
    /// in-flight memory access — callers must ensure no such access is
    /// depending on the old translation.
    #[inline]
    pub unsafe fn write(self) {
        // SAFETY: Forwarded to `write_cr3`; the caller vouches for the value.
        unsafe { write_cr3(self.bits()) };
    }

    /// Write a raw CR3 value (including address bits) to the register.
    ///
    /// Use this when switching address spaces: construct the new CR3 from a
    /// frame with [`Cr3::from_frame`] or pass a previously-saved raw value
    /// back. Unlike [`Cr3::write`], this preserves the address field because
    /// the bitflag type's `bits()` would strip it.
    ///
    /// # Safety
    ///
    /// See [`Cr3::write`].
    #[inline]
    pub unsafe fn write_raw(raw: u64) {
        // SAFETY: Forwarded to `write_cr3`; the caller vouches for the value.
        unsafe { write_cr3(raw) };
    }

    /// Extract the PML4 physical address from a raw CR3 value.
    ///
    /// Returns the 4 KiB-aligned physical address of the page-map level-4
    /// table, with the flag bits stripped. This is a free function rather
    /// than a method because the bitflag `Cr3` type does not retain the
    /// address bits (they are outside the defined flag set).
    #[inline]
    #[must_use]
    pub fn frame_from_raw(raw: u64) -> PhysAddr {
        PhysAddr::new_truncate(raw & CR3_ADDR_MASK)
    }

    /// Build a raw CR3 value from a PML4 physical address and a flag set.
    ///
    /// The address must be 4 KiB-aligned; only its bits 12..=51 are used.
    /// The resulting `u64` is suitable for [`Cr3::write_raw`].
    #[inline]
    #[must_use]
    pub fn from_frame(frame: PhysAddr, flags: Cr3) -> u64 {
        // Mask the address into the CR3 address field and OR in the flag
        // bits. We deliberately use the address as a raw u64 rather than
        // going through the bitflag type, since the address bits are not
        // part of the defined flag set.
        let addr = frame.as_u64() & CR3_ADDR_MASK;
        addr | flags.bits()
    }

    /// Convenience: read the current PML4 physical address.
    ///
    /// Equivalent to `Cr3::frame_from_raw(unsafe { Cr3::read_raw() })` but
    /// in a single call. The most common use of CR3 in the mm subsystem is
    /// "where is the current page-table root?", which this answers directly.
    ///
    /// # Safety
    ///
    /// See [`Cr3::read`].
    #[inline]
    #[must_use]
    pub unsafe fn current_frame() -> PhysAddr {
        // SAFETY: Ring-0 read of CR3; no side effects.
        let raw = unsafe { read_cr3() };
        Self::frame_from_raw(raw)
    }
}

// ---------------------------------------------------------------------------
// CR4
// ---------------------------------------------------------------------------

bitflags! {
    /// CR4 — the architectural feature-enable register.
    ///
    /// Each bit gates a CPU feature: PAE, PGE, OSFXSR, SMEP/SMAP, PCID,
    /// FSGSBASE, XSAVE, and so on. The kernel sets bits here as it enables
    /// features during bring-up; the named set below covers everything Xenith
    /// currently uses plus the commonly-gated features so that `read` does
    /// not silently drop a bit the CPU set that the kernel needs to preserve.
    ///
    /// Bits that are reserved on a given CPU model (e.g. LA57 on a part that
    /// does not support 57-bit virtual addressing) will read as 0, so
    /// including them in the flag set is harmless. Setting a reserved bit
    /// would #GP, but the kernel never writes a bit it has not first
    /// confirmed via CPUID.
    pub struct Cr4: u64 {
        /// Virtual-8086 Mode Extensions (bit 0). Unused in long mode; named
        /// so `read` preserves it if the firmware set it.
        const VME = 1 << 0;

        /// Protected-Mode Virtual Interrupts (bit 1). Unused by Xenith.
        const PVI = 1 << 1;

        /// Time Stamp Disable (bit 2). When set, `rdtsc` is privileged.
        /// Xenith leaves this clear so user code can read the TSC directly.
        const TSD = 1 << 2;

        /// Debugging Extensions (bit 3). Enables I/O breakpoints via the DR
        /// registers. The kernel leaves this at its default.
        const DE = 1 << 3;

        /// Page Size Extension (bit 4). Enables 4 MiB pages in 32-bit mode;
        /// irrelevant in long mode but named for preservation.
        const PSE = 1 << 4;

        /// Physical Address Extension (bit 5). Required for the 4-level
        /// paging used by long mode; set by Limine before entry and never
        /// cleared by the kernel.
        const PAE = 1 << 5;

        /// Machine Check Enable (bit 6). Enables #MC delivery. The kernel
        /// leaves this at its firmware default.
        const MCE = 1 << 6;

        /// Page Global Enable (bit 7). Enables the global-page bit in PTEs
        /// so the HHDM and kernel code translations survive CR3 writes.
        /// Set by `early_init`.
        const PAGE_GLOBAL = 1 << 7;

        /// Performance-Monitoring Counter Enable (bit 8). When set, ring 3
        /// can read the PMC MSRs. The kernel leaves this clear.
        const PCE = 1 << 8;

        /// OS FXSAVE/FXRSTOR Support (bit 9). When set, `fxsave`/`fxrstor`
        /// save and restore the full SSE state. Set by `early_init`.
        const OSFXSR = 1 << 9;

        /// OS Unmasked SIMD Exception Support (bit 10). When set, SIMD
        /// exceptions go to #XF instead of #GP. Set by `early_init`.
        const OSXMMEXCPT_ENABLE = 1 << 10;

        /// User-Mode Instruction Prevention (bit 11). When set, `sgdt`/`sidt`
        ////`slgt`/`str`/`smsw`/`cpuid` (for some) in ring 3 raise #UD. The
        /// kernel may set this later for hardening; named so `read`
        /// preserves it.
        const UMIP = 1 << 11;

        /// 57-bit Virtual Addressing (bit 12). Enables 5-level paging.
        /// Xenith currently targets 4-level paging and does not set this;
        /// named so `read` does not strip it if the firmware set it.
        const LA57 = 1 << 12;

        /// VMX Enable (bit 13). Set to enter VMX operation; Xenith does not
        /// use VMX today.
        const VMXE = 1 << 13;

        /// SMX Enable (bit 14). Safer Mode Extensions; unused by Xenith.
        const SMXE = 1 << 14;

        /// FSGSBASE Enable (bit 16). When set, `rdfsbase`/`wrfsbase`/
        /// `rdgsbase`/`wrgsbase` are non-privileged. The kernel enables this
        /// if present so the per-CPU base can be accessed without `rdmsr`.
        const FSGSBASE = 1 << 16;

        /// PCID Enable (bit 17). When set, CR3 carries a 12-bit PCID and
        /// CR3 writes can be made non-flushing. The kernel enables PCID if
        /// the CPU advertises it, to cut TLB flushes on context switch.
        const PCIDE = 1 << 17;

        /// XSAVE and Processor Extended States Enable (bit 18). Enables
        /// `xsave`/`xrstor` and `xgetbv`/`xsetbv`; set by the FPU initialiser
        /// only after CPUID advertises XSAVE support.
        const OSXSAVE = 1 << 18;

        /// Supervisor Mode Execution Prevention (bit 20). When set, ring 0
        /// cannot execute from a user page. The kernel sets this for
        /// self-protection once paging is fully up.
        const SMEP = 1 << 20;

        /// Supervisor Mode Access Prevention (bit 21). When set, ring 0
        /// cannot read or write a user page unless RFLAGS.AC is set. Set
        /// together with SMEP.
        const SMAP = 1 << 21;

        /// Protection Keys for User Pages (bit 22). Enables the PKRU
        /// register and the page-table PK field. Unused by Xenith today.
        const PKE = 1 << 22;

        /// Control-flow Enforcement Technology (bit 23). This is the master
        /// enable for shadow stacks and indirect-branch tracking. Xenith does
        /// not initialise CET state and clears inherited firmware enablement.
        const CET = 1 << 23;

        /// Protection Keys for Supervisor Pages (bit 24). Enables IA32_PKRS
        /// enforcement for supervisor mappings. Xenith does not provision a
        /// PKRS policy and clears inherited firmware enablement.
        const PKS = 1 << 24;
    }
}

impl Cr4 {
    /// Read the current CR4 image.
    ///
    /// As with [`Cr0::read`], `from_bits_truncate` drops any bit the CPU
    /// sets that Xenith does not name. The named set is broad enough that
    /// this only affects genuinely reserved bits on current hardware.
    ///
    /// # Safety
    ///
    /// `mov cr4, reg` is privileged. The read has no side effects.
    #[inline]
    #[must_use]
    pub fn read() -> Self {
        // SAFETY: Ring-0 read of CR4; no side effects.
        let raw = unsafe { read_cr4() };
        Self::from_bits_truncate(raw)
    }

    /// Write this CR4 image back to the register.
    ///
    /// # Safety
    ///
    /// The caller must ensure every bit set in `self` corresponds to a
    /// feature the CPU advertises via CPUID. Setting an unsupported bit
    /// raises #GP. The ordering relative to other enablement (e.g. setting
    /// CR4.PAE before EFER.LME) is documented in the SDM and is the caller's
    /// responsibility. Because the type's constructors only ever produce
    /// defined flag bits, reserved bits can never be set through `write`.
    #[inline]
    pub unsafe fn write(self) {
        // SAFETY: Forwarded to `write_cr4`; the caller vouches for the value.
        unsafe { write_cr4(self.bits()) };
    }
}

#[cfg(test)]
mod tests {
    use super::Cr4;

    #[test]
    fn cr4_extended_feature_bits_match_the_architecture() {
        assert_eq!(Cr4::FSGSBASE.bits(), 1 << 16);
        assert_eq!(Cr4::PCIDE.bits(), 1 << 17);
        assert_eq!(Cr4::OSXSAVE.bits(), 1 << 18);
        assert_eq!(Cr4::PKE.bits(), 1 << 22);
        assert_eq!(Cr4::CET.bits(), 1 << 23);
        assert_eq!(Cr4::PKS.bits(), 1 << 24);
    }
}
