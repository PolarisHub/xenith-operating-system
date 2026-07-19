//! Scheduler-facing FPU state.
//!
//! Architecture code owns CPUID probing, XSAVE/FXSAVE area sizing, CR0.TS,
//! and the actual save/restore instructions. This module intentionally stays
//! a thin scheduler adapter so those privileged details have one source of
//! truth.

pub use arch_fpu::{FpuAreaError, FpuInfo};

use crate::arch::x86_64::fpu as arch_fpu;

/// Per-thread floating-point/SIMD state.
pub struct FpuState {
    context: arch_fpu::FpuContext,
}

impl FpuState {
    /// Allocate a pristine XSAVE (or FXSAVE fallback) image for a new thread.
    pub fn new() -> Result<Self, FpuAreaError> {
        Ok(Self {
            context: arch_fpu::FpuContext::new()?,
        })
    }

    /// Save the outgoing thread if it currently owns the hardware FPU and arm
    /// CR0.TS for lazy restoration by the incoming thread.
    #[inline]
    pub fn save_state(&self) {
        self.context.switch_out();
    }

    /// Mark this state as the incoming thread's state.
    ///
    /// Restoration is deliberately lazy: this only sets CR0.TS. The first
    /// x87/SIMD instruction traps through `#NM`, where
    /// [`handle_device_not_available`] restores the image.
    #[inline]
    pub fn restore_state(&self) {
        self.context.switch_in();
    }

    /// Handle this thread's first FPU instruction after a context switch.
    ///
    /// # Safety
    ///
    /// Must be called only by the `#NM` handler for the thread currently
    /// executing on this CPU. No other CPU may manipulate this state.
    #[inline]
    pub unsafe fn handle_device_not_available(&self) {
        // SAFETY: forwarded from the caller; the architecture layer owns the
        // CR0.TS clear and the XSAVE/FXSAVE state-machine invariants.
        unsafe { self.context.handle_device_not_available() };
    }

    /// Whether this thread's state is currently live in hardware registers.
    #[inline]
    #[must_use]
    pub fn is_live(&self) -> bool {
        self.context.is_live()
    }

    /// Size of the CPU-specific save image.
    #[inline]
    #[must_use]
    pub fn area_size(&self) -> usize {
        self.context.area_size()
    }
}

impl core::fmt::Debug for FpuState {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("FpuState")
            .field("area_size", &self.area_size())
            .field("live", &self.is_live())
            .finish()
    }
}

/// Enable native x87/SSE operation and initialise XSAVE support.
///
/// `early_init` sets CR0.MP, clears CR0.EM, and sets CR4.OSFXSR plus
/// CR4.OSXMMEXCPT. The architecture FPU initialiser then probes CPUID, enables
/// CR4.OSXSAVE when supported, programs XCR0, and caches the required area
/// size. Both operations are idempotent for AP bring-up.
pub fn init_fpu() {
    crate::arch::x86_64::early_init();
    arch_fpu::init();
}

/// Save an outgoing thread's FPU state.
#[inline]
pub fn save_state(state: &FpuState) {
    state.save_state();
}

/// Arm lazy restoration for an incoming thread's FPU state.
#[inline]
pub fn restore_state(state: &FpuState) {
    state.restore_state();
}

/// Entry used by a scheduler-aware `#NM` exception handler.
///
/// # Safety
///
/// `state` must belong to the current thread and the call must originate from
/// the ring-0 device-not-available handler.
#[inline]
pub unsafe fn handle_device_not_available(state: &FpuState) {
    // SAFETY: forwarded to the method with the same contract.
    unsafe { state.handle_device_not_available() };
}
