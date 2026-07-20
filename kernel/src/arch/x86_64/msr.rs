//! Model-Specific Register handle and named MSR constants.
//!
//! x86_64 exposes per-core configuration registers addressed by a 32-bit
//! index and accessed through the `rdmsr` / `wrmsr` instructions. There are
//! several thousand defined MSRs; this module provides a typed handle
//! ([`Msr`]) that fixes the index at the type level and offers `read` /
//! `write` methods, plus a curated set of named constants for the MSRs the
//! kernel touches during bring-up: the syscall entry surface
//! (`IA32_STAR` / `IA32_LSTAR` / `IA32_FMASK`), the long-mode enable
//! (`IA32_EFER`), the per-CPU base pointers (`IA32_GS_BASE` /
//! `IA32_KERNEL_GS_BASE`), the local-APIC base (`IA32_LAPIC_BASE`), and the
//! `rdtsc`-auxiliary MSR (`IA32_TSC_AUX`).
//!
//! # Why a newtype
//!
//! A bare `u32` does not distinguish an MSR index from any other integer.
//! Wrapping it in `Msr(u32)` makes every MSR access self-documenting and
//! prevents an index from being passed where, say, a CPUID leaf is expected.
//! The named constants below are `Msr` values, so `IA32_EFER.read()` reads
//! EFER and `IA32_EFER.write(value)` writes it — there is no chance of
//! transposing the index and the value.
//!
//! # Safety
//!
//! `rdmsr` / `wrmsr` are privileged (CPL 0) and raise #GP on a reserved or
//! unknown index. The `read` / `write` methods on [`Msr`] are therefore
//! `unsafe`; the named constants here are all valid on every x86_64 part that
//! supports long mode, so using them is safe *provided the feature they gate
//! is enabled*. Individual constants document the feature requirement.

use super::instructions::{rdmsr, wrmsr};

/// A model-specific register, addressed by a 32-bit index.
///
/// The inner `u32` is public so callers can construct an `Msr` for an index
/// not yet named here (`Msr(0x123)`) without going through a constructor.
/// Prefer adding a named constant to this module when an MSR is used more
/// than once, so the magic number is recorded once with its documentation.
#[derive(Copy, Clone, Debug, Eq, PartialEq, Ord, PartialOrd, Hash)]
pub struct Msr(pub u32);

impl Msr {
    /// Construct an `Msr` for the given index. `const` so named constants
    /// can be defined as `pub const X: Msr = Msr::new(0x...)`.
    #[inline]
    #[must_use]
    pub const fn new(addr: u32) -> Self {
        Self(addr)
    }

    /// The raw 32-bit MSR index, suitable for passing to `rdmsr` / `wrmsr`
    /// directly when the typed `read` / `write` methods are not wanted.
    #[inline]
    #[must_use]
    pub const fn addr(self) -> u32 {
        self.0
    }

    /// Read the 64-bit value of this MSR.
    ///
    /// # Safety
    ///
    /// `rdmsr` is privileged (CPL 0). The caller must ensure `self` is a
    /// valid MSR index for the running CPU model and that the CPU supports
    /// the feature the MSR gates. Reading a reserved or non-existent MSR
    /// raises #GP.
    #[inline]
    #[must_use]
    pub unsafe fn read(self) -> u64 {
        // SAFETY: Forwarded to the raw `rdmsr` wrapper; the caller vouches
        // for the index.
        unsafe { rdmsr(self.0) }
    }

    /// Write `value` to this MSR.
    ///
    /// # Safety
    ///
    /// `wrmsr` is privileged (CPL 0). The caller must ensure `self` is a
    /// valid MSR index and that `value` has zeros in every reserved bit for
    /// that MSR. Setting a reserved bit raises #GP; many MSRs also have
    /// ordering constraints against other enablement bits (e.g. EFER.LME
    /// must be set before EFER.LMA takes effect, and only after CR0.PG).
    #[inline]
    pub unsafe fn write(self, value: u64) {
        // SAFETY: Forwarded to the raw `wrmsr` wrapper; the caller vouches
        // for the index and value.
        unsafe { wrmsr(self.0, value) }
    }
}

// ---------------------------------------------------------------------------
// Named MSR constants
// ---------------------------------------------------------------------------

/// IA32_LAPIC_BASE (`0x1B`) — Local APIC base address and enable.
///
/// Holds the physical base address of the local APIC registers (bits 12..=35)
/// plus the global enable bit (bit 11) and the x2APIC enable bit (bit 10).
/// The BSP initialises this early so the LAPIC register block can be mapped
/// into the HHDM; APs inherit the same base.
///
/// Valid on every x86_64 part with a local APIC, which is all of them.
pub const IA32_LAPIC_BASE: Msr = Msr::new(0x1B);

/// IA32_PAT (`0x277`) — Page Attribute Table memory-type selectors.
///
/// Each byte describes one of the eight PTE-selected memory types. Xenith
/// reserves entry 4 for write-combining framebuffer mappings on CPUs that
/// advertise PAT through CPUID.01H:EDX[16].
pub const IA32_PAT: Msr = Msr::new(0x277);

/// IA32_EFER (`0xC0000080`) — Extended Feature Enable Register.
///
/// Gates long mode (LME, bit 8), active long mode (LMA, bit 10, read-only),
/// the NX-enable bit (NXE, bit 11), and the SVC/AVX enable bits. The kernel
/// never writes LME itself — Limine enables long mode before jumping to the
/// kernel — but NXE must be set by the kernel to allow the NX page-table bit
/// to take effect, and SVME/VMX bits are left clear.
pub const IA32_EFER: Msr = Msr::new(0xC000_0080);

/// IA32_STAR (`0xC0000081`) — System Call Target.
///
/// Holds the CS/SS selectors for the kernel (bits 32..=47) and the user
/// data/code selectors (bits 48..=63) used by `syscall`/`sysret`. The
/// syscall entry point itself is in [`IA32_LSTAR`]. The kernel writes STAR
/// once during arch bring-up and never changes it afterwards.
pub const IA32_STAR: Msr = Msr::new(0xC000_0081);

/// IA32_LSTAR (`0xC0000082`) — Long-mode System Call Target RIP.
///
/// The 64-bit RIP that `syscall` jumps to. Loaded once during arch bring-up
/// with the address of the kernel's syscall entry trampoline. The trampoline
/// is responsible for saving user state, loading the kernel stack, and
/// dispatching to the syscall handler table.
pub const IA32_LSTAR: Msr = Msr::new(0xC000_0082);

/// IA32_FMASK (`0xC0000084`) — System Call Flag Mask.
///
/// The EFLAGS mask applied on `syscall` entry: every bit set here is cleared
/// in RFLAGS when the syscall handler starts running. The kernel sets this to
/// the IF bit (bit 9) so interrupts are masked on entry and the handler can
/// re-enable them when ready.
pub const IA32_FMASK: Msr = Msr::new(0xC000_0084);

/// IA32_GS_BASE (`0xC0000101`) — the 64-bit base address of the GS segment.
///
/// In the Xenith kernel GS points at the per-CPU control block
/// ([`percpu`](super::percpu)). Writing this MSR directly sets the base
/// used by kernel code; the swap to the user GS on entry/exit is done via
/// [`IA32_KERNEL_GS_BASE`]. Unlike `IA32_KERNEL_GS_BASE`, this MSR is the
/// *currently active* GS base.
pub const IA32_GS_BASE: Msr = Msr::new(0xC000_0101);

/// IA32_KERNEL_GS_BASE (`0xC0000102`) — the shadow GS base swapped by `swapgs`.
///
/// `swapgs` exchanges `IA32_GS_BASE` and `IA32_KERNEL_GS_BASE` in a single
/// instruction. The convention is: on syscall entry, `swapgs` is executed so
/// GS points at the kernel per-CPU block (which was parked in
/// `IA32_KERNEL_GS_BASE` while user code ran with its own GS in
/// `IA32_GS_BASE`); on exit, `swapgs` is executed again to restore the user
/// GS. The kernel therefore writes the per-CPU address to
/// `IA32_KERNEL_GS_BASE` at boot and lets `swapgs` pull it into
/// `IA32_GS_BASE` on entry.
pub const IA32_KERNEL_GS_BASE: Msr = Msr::new(0xC000_0102);

/// IA32_TSC_AUX (`0xC0000103`) — auxiliary value returned by `rdtscp`.
///
/// `rdtscp` atomically reads the TSC and this MSR, so the kernel can tag each
/// TSC sample with the CPU number it came from. Written once per CPU during
/// bring-up; the per-CPU topology phase fills in the value. The low 32 bits
/// are the only ones architecturally defined.
pub const IA32_TSC_AUX: Msr = Msr::new(0xC000_0103);
