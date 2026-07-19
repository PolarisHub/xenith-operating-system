//! FPU / x87 / SSE / AVX state management for the Xenith kernel.
//!
//! This module owns everything below the scheduler that touches the floating
//! point and SIMD register file:
//!
//! * **CR0 / CR4 enablement** — CR0.MP/EM/NE and CR4.OSFXSR/OSXMMEXCPT are
//!   already set by [`super::early_init`]; [`init`] adds CR4.OSXSAVE and
//!   programs XCR0 on parts that advertise XSAVE, so `xsave`/`xrstor` become
//!   usable for state management.
//! * **Area sizing** — CPUID leaf `0x0D` reports the contiguous XSAVE area
//!   size the OS must reserve per task. [`probe`] reads it once at boot and
//!   the result is cached in [`FPU_INFO`] for every later allocation.
//! * **Per-task state** — [`FpuSaveArea`] is an owned, 64-byte-aligned buffer
//!   holding one task's XSAVE image; [`FpuContext`] wraps it with the
//!   lazy-save state machine the scheduler drives.
//! * **Context switch** — [`FpuContext::switch_out`] saves the outgoing
//!   task's state and sets CR0.TS; [`FpuContext::switch_in`] just sets
//!   CR0.TS, deferring the restore to the first FPU instruction.
//! * **Lazy #NM path** — [`handle_device_not_available`] is the entry the
//!   `#NM` (device-not-available) exception handler calls: it runs `clts`
//!   and either restores the saved image (via `xrstor`) or initialises the
//!   FPU to a pristine state (for a task that has never touched it).
//!
//! # The lazy-FPU model
//!
//! Switching the XSAVE state on every context switch is expensive on
//! bandwidth-rich parts (AVX-512 images run to multiple KiB), and most tasks
//! never touch the FPU. Xenith therefore uses the classic lazy scheme:
//!
//! 1. On switch-out, if the outgoing task *owns* the FPU (its state is live
//!    in the registers), `xsave` it into the task's area and set CR0.TS.
//! 2. On switch-in, set CR0.TS. The FPU is now "not owned" by anyone.
//! 3. The first FPU/SIMD instruction the new task executes traps with `#NM`
//!    because CR0.TS is set. The handler runs `clts` and `xrstor`s the task's
//!    saved image (or initialises a fresh FPU for a task that has never used
//!    it), making the task the new owner.
//!
//! The state machine has three states per task: [`State::Fresh`] (never used
//! the FPU), [`State::Live`] (registers currently hold this task's state), and
//! [`State::Saved`] (image is in the area, registers do not). Only one task
//! per CPU can be `Live` at a time.
//!
//! # Non-XSAVE fallback
//!
//! On parts without XSAVE the module falls back to `fxsave`/`fxrstor` with a
//! 512-byte, 16-byte-aligned area. The public API is identical; only the
//! buffer size and the save/restore instruction differ.
//!
//! # Safety posture
//!
//! `xsave`, `xrstor`, `xsetbv`, `clts`, `fxsave`, `fxrstor`, and `fninit`
//! each execute privileged or state-mutating instructions and are `unsafe`
//! with a `# Safety` doc. The safe surface above them ([`FpuContext`],
//! [`init`], [`probe`]) establishes the invariants once at boot and then
//! presents a safe API to the scheduler and the `#NM` handler.

use core::alloc::Layout;
use core::mem::MaybeUninit;
use core::ptr::NonNull;
use core::sync::atomic::{AtomicBool, AtomicU8, Ordering};

use xenith_bitflags::bitflags;

use super::cpu::{cpuid, cpuid_with};
use super::instructions::{read_cr0, read_cr4, write_cr0, write_cr4};

// ---------------------------------------------------------------------------
// CPUID leaf and bit constants
// ---------------------------------------------------------------------------

/// CPUID leaf `0x0D`: the XSAVE feature leaf. Sub-leaf 0 reports the
/// state-component bitmap (EAX), the contiguous area size the OS should
/// allocate (EBX), and the maximal area size the CPU can fill (ECX).
/// Sub-leaf 1 reports the extended XSAVE instruction support (XSAVEOPT,
/// XSAVEC, XSAVES) in EAX.
const LEAF_XSAVE: u32 = 0x0000_000D;

/// CPUID leaf 1, used for the XSAVE / OSXSAVE feature bits in ECX[26..27].
const LEAF_FEATURE_INFO: u32 = 0x0000_0001;

/// CR4.OSXSAVE is bit 18. The `Cr4` flag type in [`registers`](super::registers)
/// does not name this bit, so we manipulate it through the raw
/// [`read_cr4`]/[`write_cr4`] wrappers with this literal. Setting it enables
/// `xsave`/`xrstor`/`xsetbv`/`xgetbv`; without it those instructions #GP.
const CR4_OSXSAVE: u64 = 1 << 18;

/// CR0.TS (Task Switched) is bit 3. We program it through the raw
/// [`read_cr0`]/[`write_cr0`] wrappers rather than the `Cr0` flag type so this
/// module stays self-contained: the `Cr0` consts in `registers` are private to
/// that module, and reaching into them from here would couple the modules at
/// the visibility level. Setting TS arms the lazy `#NM` path; `clts` clears it.
const CR0_TASK_SWITCHED: u64 = 1 << 3;

/// XCR0 is always index 0; `xsetbv`/`xgetbv` take the XCR index in ECX.
const XCR0_INDEX: u32 = 0;

/// Hard upper bound for the standard-format user-visible XSAVE image. Xenith
/// currently enables only x87, SSE, and YMM state (normally 832 bytes), so a
/// larger value indicates malformed CPUID data rather than a useful layout.
pub const MAX_SIGNAL_XSTATE_SIZE: usize = xenith_abi::SIGNAL_XSTATE_MAX;

bitflags! {
    /// XSAVE state components, mirroring the XCR0 / CPUID.0DH:EAX bit layout.
    ///
    /// Each bit names one state component the CPU knows how to save and
    /// restore. The bits we set in XCR0 select which components `xsave` will
    /// record and `xrstor` will reload; the same bitmap is passed as the
    /// EDX:EAX mask to the save/restore instructions.
    pub struct XsaveComponents: u64 {
        /// x87 + FPU control registers (legacy region, bytes 0..=511). Always
        /// enabled on any XSAVE-capable part.
        const X87        = 1 << 0;
        /// XMM registers + MXCSR (SSE state, legacy region). Paired with X87
        /// in the legacy 512-byte region.
        const SSE        = 1 << 1;
        /// Upper YMM halves (AVX state, first extended region). Only enabled
        /// when the CPU advertises AVX via CPUID.0DH:EAX[2].
        const YMM        = 1 << 2;
        /// MPX bound registers (BNDREGS).
        const BNDREGS    = 1 << 3;
        /// MPX bound-control state (BNDCSR).
        const BNDCSR     = 1 << 4;
        /// AVX-512 opmask registers (k0..k7).
        const OPMASK     = 1 << 5;
        /// AVX-512 upper ZMM halves (ZMM_Hi256).
        const ZMM_HI256  = 1 << 6;
        /// AVX-512 high ZMM halves (Hi16_ZMM).
        const HI16_ZMM   = 1 << 7;
        /// Processor trace (PT) state.
        const PT         = 1 << 8;
        /// Protection keys for user pages (PKRU) register.
        const PKRU       = 1 << 9;
    }
}

bitflags! {
    /// XSAVE-family instruction support, decoded from CPUID.0DH sub-leaf 1
    /// EAX. These determine which save/restore variant [`FpuSaveArea`] uses;
    /// `xsaveopt` is preferred when available because it can elide writes of
    /// unmodified state.
    pub struct XsaveInstructions: u32 {
        /// `xsave` is available (CPUID.01H:ECX[26]). Implied by any other bit.
        const XSAVE    = 1 << 0;
        /// `xsaveopt` is available (CPUID.0DH.1:EAX[0]).
        const XSAVEOPT = 1 << 1;
        /// `xsavec` is available (CPUID.0DH.1:EAX[1]) — compacted save format.
        const XSAVEC   = 1 << 2;
        /// `xrstors`/`xsaves` are available (CPUID.0DH.1:EAX[3]) — supervisor
        /// state, not used by Xenith today.
        const XSAVES   = 1 << 3;
    }
}

// ---------------------------------------------------------------------------
// Per-CPU FPU capability snapshot
// ---------------------------------------------------------------------------

/// A boot-time snapshot of the FPU/XSAVE capabilities the running CPU
/// exposes. Probed once by [`probe`] and cached in [`FPU_INFO`]; every
/// per-task [`FpuSaveArea`] is sized from `area_size` and every save/restore
/// uses `xcr0` as the component mask.
#[derive(Copy, Clone, Debug)]
pub struct FpuInfo {
    /// Whether the CPU supports the XSAVE family at all. When `false`, the
    /// module falls back to `fxsave`/`fxrstor` and `area_size` is 512.
    pub xsave_supported: bool,
    /// Which XSAVE instructions are available (`xsaveopt`, `xsavec`, ...).
    pub instructions: XsaveInstructions,
    /// The contiguous XSAVE area size in bytes, from CPUID.0DH:EBX (sub-leaf
    /// 0). Allocations are this size with 64-byte alignment. For the
    /// non-XSAVE path this is 512 with 16-byte alignment.
    pub area_size: usize,
    /// The maximal area size the CPU could fill (CPUID.0DH:ECX). Diagnostic
    /// only; `area_size` is the value the OS must actually reserve.
    pub max_area_size: usize,
    /// The component bitmap programmed into XCR0 and passed to every
    /// `xsave`/`xrstor` as the EDX:EAX mask. Always includes X87 + SSE; AVX
    /// and beyond are added only when the CPU advertises them.
    pub xcr0: XsaveComponents,
    /// CPU-supported MXCSR bits, captured with FXSAVE after feature enablement.
    /// `fxrstor`/`xrstor` #GP if a userspace signal frame sets any other bit.
    pub mxcsr_mask: u32,
}

/// The set of components the kernel is willing to enable in XCR0. We always
/// take X87 and SSE; AVX (YMM) is added when CPUID.0DH:EAX[2] is set. Higher
/// components (MPX, AVX-512, PT, PKRU) are left to a future feature phase.
fn desired_components(leaf0_eax: u32) -> XsaveComponents {
    let mut c = XsaveComponents::X87 | XsaveComponents::SSE;
    if (leaf0_eax >> 2) & 1 == 1 {
        c.insert(XsaveComponents::YMM);
    }
    c
}

/// Probe the FPU/XSAVE capabilities of the running CPU.
///
/// Runs three `cpuid` queries (leaf 1 for the XSAVE/OSXSAVE bits, leaf 0xD
/// sub-leaf 0 for the area size and component bitmap, leaf 0xD sub-leaf 1 for
/// the instruction variants) and folds them into an [`FpuInfo`]. Safe to call
/// from any context; the result reflects whichever CPU executes it.
///
/// On parts without XSAVE the returned [`FpuInfo`] describes the `fxsave`
/// fallback: `xsave_supported` is `false`, `area_size` is 512, and `xcr0` is
/// empty (XCR0 does not exist without XSAVE).
#[must_use]
pub fn probe() -> FpuInfo {
    let feat = cpuid(LEAF_FEATURE_INFO);
    // CPUID.01H:ECX[26] = XSAVE supported, ECX[27] = OSXSAVE enabled.
    let xsave_supported = (feat.ecx >> 26) & 1 == 1;

    if !xsave_supported {
        // No XSAVE: fall back to fxsave/fxrstor with a 512-byte, 16-byte
        // aligned area. CR4.OSFXSR is already set by early_init, so fxsave is
        // safe to use. XCR0 does not exist on these parts.
        return FpuInfo {
            xsave_supported: false,
            instructions: XsaveInstructions::empty(),
            area_size: 512,
            max_area_size: 512,
            xcr0: XsaveComponents::empty(),
            mxcsr_mask: 0x0000_ffbf,
        };
    }

    let l0 = cpuid_with(LEAF_XSAVE, 0);
    // EBX is the size the OS should use *given the XCR0 it has programmed*;
    // ECX is the max the CPU would fill if every supported component were
    // enabled. We program a subset (see `desired_components`), so EBX is the
    // correct reservation. The spec guarantees EBX >= 576 (512 legacy + 64
    // XSAVE header) on any XSAVE-capable part.
    let max_area_size = l0.ecx as usize;
    let mut xcr0 = desired_components(l0.eax);
    // CPUID.0DH:EBX reflects the *currently* enabled XCR0, which is not yet
    // Xenith's desired mask during early boot. Derive the standard-format
    // size from each selected component's architectural offset instead.
    let mut area_size = 576usize; // 512-byte legacy region + 64-byte header.
    for component in 2..64 {
        if xcr0.bits() & (1u64 << component) == 0 {
            continue;
        }
        let leaf = cpuid_with(LEAF_XSAVE, component);
        let Some(end) = (leaf.ebx as usize).checked_add(leaf.eax as usize) else {
            xcr0.remove(XsaveComponents::from_bits_truncate(1u64 << component));
            continue;
        };
        if leaf.eax == 0 || end > max_area_size || end > MAX_SIGNAL_XSTATE_SIZE {
            xcr0.remove(XsaveComponents::from_bits_truncate(1u64 << component));
            continue;
        }
        area_size = area_size.max(end);
    }

    // Sub-leaf 1 reports the extended instruction variants in EAX. If the
    // CPU does not implement sub-leaf 1 (it always does when XSAVE is
    // present, but guard for robustness), cpuid returns zeros and we get the
    // plain `xsave` behaviour.
    let l1 = cpuid_with(LEAF_XSAVE, 1);
    let mut instructions = XsaveInstructions::XSAVE;
    if l1.eax & 1 == 1 {
        instructions.insert(XsaveInstructions::XSAVEOPT);
    }
    if (l1.eax >> 1) & 1 == 1 {
        instructions.insert(XsaveInstructions::XSAVEC);
    }
    if (l1.eax >> 3) & 1 == 1 {
        instructions.insert(XsaveInstructions::XSAVES);
    }

    FpuInfo {
        xsave_supported: true,
        instructions,
        area_size,
        max_area_size,
        xcr0,
        mxcsr_mask: 0x0000_ffbf,
    }
}

// ---------------------------------------------------------------------------
// Global boot-time snapshot
// ---------------------------------------------------------------------------

/// The cached [`FpuInfo`] written once by [`init`] and read by every later
/// allocation. Stored as `MaybeUninit` because the value is produced at boot
/// and the type is not `const`-constructible; [`FPU_INITIALIZED`] gates reads.
static mut FPU_INFO: MaybeUninit<FpuInfo> = MaybeUninit::uninit();

/// Set to `true` with `Release` semantics after [`FPU_INFO`] is written; read
/// with `Acquire` by [`info`]. The acquire/release pair establishes the
/// happens-before edge between the boot CPU's write and any later reader.
static FPU_INITIALIZED: AtomicBool = AtomicBool::new(false);

/// Return the cached FPU capability snapshot, or `None` before [`init`] has
/// run. The returned reference is valid for the kernel's lifetime once
/// non-`None`, so callers can hold it across `await`-free code freely.
#[must_use]
pub fn info() -> Option<&'static FpuInfo> {
    if FPU_INITIALIZED.load(Ordering::Acquire) {
        // SAFETY: `FPU_INFO` was fully written by `init` on the BSP before
        // `FPU_INITIALIZED` was set with `Release`. The acquire load above
        // synchronises with that release, so the write is visible and the
        // reference is valid. The value is never mutated again after init.
        // We go through `addr_of!` rather than `FPU_INFO.as_ptr()` so no
        // mutable reference to the `static mut` is ever materialised (the
        // 2024 edition warns on those). `MaybeUninit<FpuInfo>` and `FpuInfo`
        // share a representation, so a single cast to `*const FpuInfo` lets
        // us return a `&'static FpuInfo` tied to the static's storage.
        let p = core::ptr::addr_of!(FPU_INFO) as *const FpuInfo;
        Some(unsafe { &*p })
    } else {
        None
    }
}

// ---------------------------------------------------------------------------
// Raw instruction wrappers
// ---------------------------------------------------------------------------

/// `clts` — clear the Task Switched bit in CR0.
///
/// After `clts`, FPU/SIMD instructions execute without trapping. The lazy
/// `#NM` handler calls this before restoring the task's saved state.
///
/// # Safety
///
/// `clts` is privileged (CPL 0). The caller must be in ring 0.
#[inline]
pub unsafe fn clts() {
    // SAFETY: `clts` clears CR0.TS. It reads/writes no memory and no stack,
    // and does not modify EFLAGS, so `preserves_flags` is sound. The caller
    // guarantees ring 0.
    unsafe {
        core::arch::asm!("clts", options(nostack, nomem, preserves_flags));
    }
}

/// `xsetbv` — write `EDX:EAX` to the extended control register named by `ECX`.
///
/// Used by [`enable_xsave`] to program XCR0 with the component bitmap. The
/// value selects which state components `xsave` will record and `xrstor` will
/// reload.
///
/// # Safety
///
/// `xsetbv` is privileged and requires CR4.OSXSAVE to be set, else it #GPs.
/// The caller must be in ring 0, must have already set CR4.OSXSAVE, and must
/// ensure `cr` is a valid XCR index (0 for XCR0) and `value` only sets
/// component bits the CPU advertises via CPUID.0DH:EAX.
#[inline]
pub unsafe fn xsetbv(cr: u32, value: u64) {
    let lo = value as u32;
    let hi = (value >> 32) as u32;
    // SAFETY: `xsetbv` writes EDX:EAX to XCR[ECX]. It touches no memory or
    // stack and does not modify EFLAGS. Caller guarantees ring 0, OSXSAVE,
    // and a valid index/value.
    unsafe {
        core::arch::asm!(
            "xsetbv",
            in("ecx") cr,
            in("eax") lo,
            in("edx") hi,
            options(nostack, preserves_flags),
        );
    }
}

/// `xgetbv` — read the extended control register named by `ECX` into
/// `EDX:EAX`. Read-only diagnostic helper; not required for the save/restore
/// path but useful for confirming XCR0 took effect.
///
/// # Safety
///
/// `xgetbv` requires CR4.OSXSAVE; without it the instruction #GPs. The
/// caller must be in ring 0 with OSXSAVE enabled.
#[inline]
#[must_use]
pub unsafe fn xgetbv(cr: u32) -> u64 {
    let lo: u32;
    let hi: u32;
    // SAFETY: `xgetbv` reads XCR[ECX] into EDX:EAX. No memory or stack access;
    // EFLAGS untouched. Caller guarantees ring 0 and OSXSAVE.
    unsafe {
        core::arch::asm!(
            "xgetbv",
            in("ecx") cr,
            out("eax") lo,
            out("edx") hi,
            options(nostack, preserves_flags),
        );
    }
    ((hi as u64) << 32) | (lo as u64)
}

/// `xsave` — save the FPU/SSE/AVX state selected by `mask` (EDX:EAX) into the
/// 64-byte-aligned area at `area`.
///
/// # Safety
///
/// The caller must guarantee:
/// * `area` is 64-byte aligned and points to at least `FpuInfo::area_size`
///   bytes of writable memory.
/// * CR4.OSXSAVE is set and XCR0 has been programmed (else #GP).
/// * `mask` is a subset of the components enabled in XCR0.
/// * The caller is in ring 0.
#[inline]
unsafe fn xsave(area: *mut u8, mask: u64) {
    let lo = mask as u32;
    let hi = (mask >> 32) as u32;
    // SAFETY: `xsave [mem]` writes the XSAVE image to the aligned area. It
    // touches memory (the area) so we do NOT set `nomem`; it does not touch
    // the stack or EFLAGS. Caller guarantees alignment, size, OSXSAVE, mask,
    // and ring 0.
    unsafe {
        core::arch::asm!(
            "xsave [{p}]",
            p = in(reg) area,
            in("eax") lo,
            in("edx") hi,
            options(nostack, preserves_flags),
        );
    }
}

/// `xsaveopt` — optimised save that may skip writing unmodified components.
/// Same safety contract as [`xsave`]; preferred when available.
#[inline]
unsafe fn xsaveopt(area: *mut u8, mask: u64) {
    let lo = mask as u32;
    let hi = (mask >> 32) as u32;
    // SAFETY: same as `xsave`; the only difference is the CPU may elide
    // writes of components whose state has not changed since the last save.
    unsafe {
        core::arch::asm!(
            "xsaveopt [{p}]",
            p = in(reg) area,
            in("eax") lo,
            in("edx") hi,
            options(nostack, preserves_flags),
        );
    }
}

/// `xrstor` — restore the FPU/SSE/AVX state selected by `mask` (EDX:EAX) from
/// the 64-byte-aligned area at `area`.
///
/// # Safety
///
/// The caller must guarantee:
/// * `area` is 64-byte aligned and points to at least `FpuInfo::area_size`
///   bytes of readable memory containing a valid XSAVE image.
/// * CR4.OSXSAVE is set and XCR0 programmed.
/// * `mask` is a subset of XCR0.
/// * The caller is in ring 0.
#[inline]
unsafe fn xrstor(area: *const u8, mask: u64) {
    let lo = mask as u32;
    let hi = (mask >> 32) as u32;
    // SAFETY: `xrstor [mem]` reads an XSAVE image and loads the selected
    // components into the register file. It reads memory (the area); no stack
    // or EFLAGS effect. Caller guarantees alignment, size, validity, OSXSAVE,
    // mask, and ring 0.
    unsafe {
        core::arch::asm!(
            "xrstor [{p}]",
            p = in(reg) area,
            in("eax") lo,
            in("edx") hi,
            options(nostack, preserves_flags),
        );
    }
}

/// `fxsave` — legacy 512-byte save into a 16-byte-aligned area. Used on
/// parts without XSAVE.
///
/// # Safety
///
/// `area` must be 16-byte aligned and point to 512 bytes of writable memory.
/// CR4.OSFXSR must be set (it is, by `early_init`). Ring 0.
#[inline]
unsafe fn fxsave(area: *mut u8) {
    // SAFETY: `fxsave [mem]` writes 512 bytes to the aligned area. Touches
    // memory; no stack or EFLAGS effect. Caller guarantees alignment, size,
    // OSFXSR, and ring 0.
    unsafe {
        core::arch::asm!(
            "fxsave [{p}]",
            p = in(reg) area,
            options(nostack, preserves_flags),
        );
    }
}

/// `fxrstor` — legacy 512-byte restore from a 16-byte-aligned area. Used on
/// parts without XSAVE.
///
/// # Safety
///
/// See [`fxsave`]; `area` must point to 512 readable bytes of a valid image.
#[inline]
unsafe fn fxrstor(area: *const u8) {
    unsafe {
        core::arch::asm!(
            "fxrstor [{p}]",
            p = in(reg) area,
            options(nostack, preserves_flags),
        );
    }
}

/// `fninit` — initialise the x87 FPU to its default state (clear exceptions,
/// set control word to 0x037F, tag word to all-empty). Used by the
/// first-use path for tasks that have never touched the FPU.
///
/// # Safety
///
/// `fninit` is privileged only in the sense that it touches FPU state; it is
/// not ring-gated. It modifies no memory or stack. Marked unsafe for surface
/// uniformity with the rest of this module.
#[inline]
unsafe fn fninit() {
    // SAFETY: `fninit` reinitialises the x87; no memory, stack, or EFLAGS
    // effect.
    unsafe {
        core::arch::asm!("fninit", options(nostack, nomem, preserves_flags));
    }
}

/// Zero the SSE/AVX register file in place.
///
/// Emits `xorps` on XMM0..XMM15 to clear the SSE state, then `vzeroupper` to
/// drop the upper halves of any YMM registers (a no-op on non-AVX parts,
/// which #UD on `vzeroupper` — so only emit it when AVX is enabled). This is
/// the SIMD counterpart of [`fninit`] used on the first-use path: it leaves
/// the task with a clean, deterministic SIMD register file rather than
/// whatever the previous owner left behind.
///
/// # Safety
///
/// `xorps`/`vzeroupper` are not privileged. They modify the XMM/YMM
/// registers and MXCSR-equivalent state but no memory or stack. Marked unsafe
/// for surface uniformity; safe to call from ring 0.
#[inline]
unsafe fn zero_simd_registers(avx: bool) {
    // SAFETY: each `xorps xmmN, xmmN` zeroes one XMM register. No memory,
    // stack, or EFLAGS effect. `vzeroupper` (if emitted) zeroes the upper
    // 128 bits of every YMM and is a no-op on the logical state if no YMM
    // upper bits were live.
    unsafe {
        core::arch::asm!(
            "xorps xmm0, xmm0",
            "xorps xmm1, xmm1",
            "xorps xmm2, xmm2",
            "xorps xmm3, xmm3",
            "xorps xmm4, xmm4",
            "xorps xmm5, xmm5",
            "xorps xmm6, xmm6",
            "xorps xmm7, xmm7",
            "xorps xmm8, xmm8",
            "xorps xmm9, xmm9",
            "xorps xmm10, xmm10",
            "xorps xmm11, xmm11",
            "xorps xmm12, xmm12",
            "xorps xmm13, xmm13",
            "xorps xmm14, xmm14",
            "xorps xmm15, xmm15",
            options(nostack, nomem, preserves_flags),
        );
        if avx {
            core::arch::asm!("vzeroupper", options(nostack, nomem, preserves_flags),);
        }
    }
}

// ---------------------------------------------------------------------------
// Boot-time enablement
// ---------------------------------------------------------------------------

/// Enable CR4.OSXSAVE and program XCR0 with the component bitmap in `info`.
///
/// Must run after [`super::early_init`] (which sets CR4.OSFXSR) and before
/// any `xsave`/`xrstor`/`xsetbv` use. Idempotent: re-running on an AP sets
/// the same bits. On non-XSAVE parts this is a no-op.
///
/// # Safety
///
/// `xsetbv` and the CR4 write are privileged; the caller must be in ring 0.
/// The function itself is safe to call from the boot path because the
/// preconditions (ring 0, post-early_init) are established by the boot
/// contract.
pub fn enable_xsave(info: &FpuInfo) {
    if !info.xsave_supported {
        return;
    }

    // Set CR4.OSXSAVE (bit 18) via the raw wrappers. We bypass the `Cr4`
    // flag type because its bit-18 slot is not named `OSXSAVE` in
    // `registers.rs`; touching that file is out of this module's scope, so we
    // program the architectural bit directly.
    //
    // SAFETY: Ring 0; bit 18 is OSXSAVE on every XSAVE-capable part. Setting
    // it before `xsetbv` is the required ordering (xsetbv #GPs without it).
    let cr4 = unsafe { read_cr4() };
    unsafe { write_cr4(cr4 | CR4_OSXSAVE) };

    // Program XCR0 with the desired component bitmap. The value is a subset
    // of CPUID.0DH:EAX, which `probe` already verified, so xsetbv will not
    // #GP on an unsupported bit.
    //
    // SAFETY: Ring 0, OSXSAVE now set, XCR0_INDEX is valid, and the value is
    // a subset of the CPU-advertised components.
    unsafe { xsetbv(XCR0_INDEX, info.xcr0.bits()) };
}

/// Finalise FPU/XSAVE bring-up on the running CPU.
///
/// Probes the CPU's capabilities, enables CR4.OSXSAVE and programs XCR0 if
/// XSAVE is present, and caches the result in [`FPU_INFO`] so later
/// [`FpuSaveArea`] allocations know the area size. Called once from
/// [`super::init`] on the BSP. APs apply this published snapshot through
/// [`init_ap`] without racing a second write to the global cache.
pub fn init() {
    let mut info = probe();
    enable_xsave(&info);
    // Boot starts without a userspace FPU owner. Clear a firmware-left TS bit
    // before the one FXSAVE used to discover the processor's MXCSR mask.
    clear_task_switched();
    info.mxcsr_mask = detect_mxcsr_mask();

    // Publish the snapshot. The store to `FPU_INFO` happens before the
    // `Release` store to `FPU_INITIALIZED`, so any reader that observes the
    // flag via an `Acquire` load also observes the initialised info.
    //
    // SAFETY: On the BSP this runs single-threaded before the scheduler
    // starts, so the write races with nothing. On APs the same write
    // reproduces the same value; the worst case is two CPUs writing the same
    // `Copy` value concurrently, which is benign for `MaybeUninit` writes of
    // a `Copy` type under the boot contract. The flag load/store pair keeps
    // readers safe.
    unsafe {
        // SAFETY: See comment above — single-threaded BSP write, or an AP
        // reproducing the same `Copy` value. We go through `addr_of_mut!`
        // rather than `FPU_INFO.as_mut_ptr()` so no mutable reference to the
        // `static mut` is materialised (the 2024 edition warns on those).
        let p = core::ptr::addr_of_mut!(FPU_INFO) as *mut FpuInfo;
        core::ptr::write(p, info);
    }
    FPU_INITIALIZED.store(true, Ordering::Release);

    ::log::info!(
        "xenith.fpu: xsave={} area_size={}B xcr0={:#x} insns={:#x}",
        info.xsave_supported,
        info.area_size,
        info.xcr0.bits(),
        info.instructions.bits(),
    );
}

#[repr(align(16))]
struct LegacyProbeArea([u8; 512]);

/// Capture the CPU's MXCSR capability mask from the architectural FXSAVE
/// image. Older CPUs may report zero, for which Intel specifies the baseline
/// `0x0000_ffbf` mask.
fn detect_mxcsr_mask() -> u32 {
    let mut area = LegacyProbeArea([0; 512]);
    // SAFETY: early_init enabled OSFXSR, TS was cleared by init, and the
    // destination is a writable, 16-byte-aligned 512-byte area.
    unsafe { fxsave(area.0.as_mut_ptr()) };
    let mask = u32::from_le_bytes(area.0[28..32].try_into().expect("four-byte MXCSR mask"));
    if mask == 0 { 0x0000_ffbf } else { mask }
}

/// Apply the BSP-selected XSAVE policy to an application processor.
///
/// XSAVE enablement and XCR0 are CPU-local register state, while the probed
/// save-area layout is system-wide immutable metadata. APs therefore reuse
/// the snapshot published by [`init`] instead of racing to rewrite it.
pub fn init_ap() {
    if let Some(info) = info() {
        enable_xsave(info);
    } else {
        // Defensive fallback for an incorrectly ordered bring-up. Normal SMP
        // startup always runs after the BSP has published the snapshot.
        init();
    }
}

// ---------------------------------------------------------------------------
// CR0.TS manipulation
// ---------------------------------------------------------------------------

/// Set CR0.TS (Task Switched). After this, the next FPU/SIMD instruction
/// traps with `#NM`. Called by [`FpuContext::switch_in`] and
/// [`FpuContext::switch_out`] to arm the lazy restore.
///
/// # Safety
///
/// `write_cr0` is privileged; the caller must be in ring 0. The function is
/// safe to call from the scheduler because the scheduler always runs in ring
/// 0 and only toggles the one defined bit.
pub fn set_task_switched() {
    // SAFETY: Ring 0 (scheduler context). We read-modify-write CR0 setting
    // only bit 3 (TS); every other bit — paging, MP, EM-clear, NE, WP — is
    // preserved verbatim because we OR the single bit into the raw image we
    // just read. The raw read/write wrappers are the ones from `instructions`,
    // bypassing the `Cr0` flag type so this module does not depend on the
    // visibility of `Cr0::TASK_SWITCHED`.
    let cr0 = unsafe { read_cr0() };
    unsafe { write_cr0(cr0 | CR0_TASK_SWITCHED) };
}

/// Clear CR0.TS via `clts`. After this, FPU/SIMD instructions execute without
/// trapping. Called by [`handle_device_not_available`] before restoring state.
///
/// # Safety
///
/// `clts` is privileged; the caller must be in ring 0. Exposed as a safe
/// wrapper because the `#NM` handler always runs in ring 0.
pub fn clear_task_switched() {
    // SAFETY: The #NM handler and any explicit lazy-restore path run in ring
    // 0. `clts` only clears CR0.TS and has no other effect.
    unsafe { clts() };
}

// ---------------------------------------------------------------------------
// Per-task save area
// ---------------------------------------------------------------------------

/// A failure while creating a [`FpuSaveArea`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FpuAreaError {
    /// [`info`] has not been initialised yet — [`init`] has not run. The
    /// scheduler must not allocate FPU areas before arch bring-up completes.
    NotInitialised,
    /// The layout computed from the probed area size was invalid. This
    /// indicates a CPU reporting a nonsensical XSAVE area size and is
    /// effectively impossible on real hardware.
    BadLayout,
    /// The kernel heap could not satisfy the allocation.
    OutOfMemory,
}

impl core::fmt::Display for FpuAreaError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::NotInitialised => f.write_str("FPU area requested before fpu::init"),
            Self::BadLayout => f.write_str("invalid XSAVE area layout"),
            Self::OutOfMemory => f.write_str("out of memory for XSAVE area"),
        }
    }
}

/// An owned, correctly-aligned buffer holding one task's XSAVE (or FXSAVE)
/// image. Allocated from the kernel heap with the size and alignment
/// [`FpuInfo`] reports; freed on drop.
///
/// The buffer is zeroed at allocation so a brand-new task's image is the
/// architectural "initial" state: `xrstor` from a zeroed legacy region with
/// `XSTATE_BV == 0` loads the x87/SSE default state, which is exactly what a
/// task that has never used the FPU should see on its first `#NM`.
pub struct FpuSaveArea {
    ptr: NonNull<u8>,
    layout: Layout,
    /// The component mask passed to `xsave`/`xrstor`. Cached from [`FpuInfo`]
    /// at construction so save/restore do not need to re-read the global.
    mask: u64,
    /// Whether to use the XSAVE (`true`) or FXSAVE (`false`) instruction
    /// path. Mirrors `FpuInfo::xsave_supported`.
    xsave: bool,
    /// Whether `xsaveopt` is available (preferred over `xsave`).
    xsaveopt: bool,
}

impl FpuSaveArea {
    /// Allocate a zeroed save area sized for the current CPU's FPU state.
    ///
    /// Requires [`init`] to have run (so [`info`] is available). The area is
    /// 64-byte aligned for XSAVE or 16-byte aligned for the FXSAVE fallback.
    ///
    /// `Result` is already `#[must_use]`, so no explicit attribute is needed.
    pub fn new() -> Result<Self, FpuAreaError> {
        let info = info().ok_or(FpuAreaError::NotInitialised)?;
        let align = if info.xsave_supported { 64 } else { 16 };
        let layout =
            Layout::from_size_align(info.area_size, align).map_err(|_| FpuAreaError::BadLayout)?;

        // Use the kernel's raw zeroed allocator so the area starts in the
        // architectural initial state (all state components cleared).
        // `kmalloc_zeroed` returns `Option` (OOM → `None`), so we turn the
        // `None` into our `OutOfMemory` error with `ok_or`.
        let ptr =
            crate::mm::kmalloc::kmalloc_zeroed(layout).map_err(|_| FpuAreaError::OutOfMemory)?;

        Ok(Self {
            ptr,
            layout,
            mask: info.xcr0.bits(),
            xsave: info.xsave_supported,
            xsaveopt: info.instructions.contains(XsaveInstructions::XSAVEOPT),
        })
    }

    /// The area size in bytes (matches `FpuInfo::area_size`).
    #[inline]
    #[must_use]
    pub fn size(&self) -> usize {
        self.layout.size()
    }

    /// XSAVE component mask represented by this image. The FXSAVE fallback
    /// still exposes the architectural x87/SSE pair as bits zero and one.
    #[inline]
    #[must_use]
    pub fn feature_mask(&self) -> u64 {
        if self.xsave {
            self.mask
        } else {
            (XsaveComponents::X87 | XsaveComponents::SSE).bits()
        }
    }

    /// Immutable view used to copy an aligned kernel image to a user signal
    /// frame. The allocation remains owned by `self`.
    #[inline]
    #[must_use]
    pub fn as_bytes(&self) -> &[u8] {
        // SAFETY: `ptr` names `layout.size()` live bytes for `self`'s lifetime.
        unsafe { core::slice::from_raw_parts(self.ptr.as_ptr(), self.layout.size()) }
    }

    /// Mutable view used to stage a user-edited signal image before validated
    /// restore. Callers must validate with [`validate_user_image`] first.
    #[inline]
    pub fn as_bytes_mut(&mut self) -> &mut [u8] {
        // SAFETY: `&mut self` proves exclusive access to the live allocation.
        unsafe { core::slice::from_raw_parts_mut(self.ptr.as_ptr(), self.layout.size()) }
    }

    /// Save the currently live hardware register file for a signal frame.
    /// Returns `false` if CR0.TS says no task owns a live register image.
    pub fn capture_current(&mut self) -> bool {
        // SAFETY: CPL0 architectural read. Saving with TS set would #NM.
        if unsafe { read_cr0() } & CR0_TASK_SWITCHED != 0 {
            return false;
        }
        // SAFETY: TS is clear, the buffer is correctly sized/aligned, and
        // `&mut self` excludes aliases.
        unsafe { self.save() };
        true
    }

    /// Validate every privilege-sensitive field in a user-edited image.
    /// This keeps XRSTOR/FXRSTOR from turning malformed signal data into #GP.
    #[must_use]
    pub fn validate_user_image(&self) -> bool {
        let bytes = self.as_bytes();
        if bytes.len() < 32 {
            return false;
        }
        let mxcsr = u32::from_le_bytes(bytes[24..28].try_into().expect("four-byte MXCSR"));
        let Some(info) = info() else { return false };
        if mxcsr & !info.mxcsr_mask != 0 {
            return false;
        }
        if !self.xsave {
            return bytes.len() == 512;
        }
        if bytes.len() < 576 {
            return false;
        }
        let xstate_bv = u64::from_le_bytes(bytes[512..520].try_into().expect("XSAVE bitmap"));
        let xcomp_bv = u64::from_le_bytes(bytes[520..528].try_into().expect("XSAVE format"));
        xstate_bv & !self.mask == 0
            && xcomp_bv == 0
            && bytes[528..576].iter().all(|byte| *byte == 0)
    }

    /// Restore a validated signal image into the hardware register file.
    /// The caller remains responsible for ensuring this is the current task.
    pub fn restore_user_image(&self) -> bool {
        if !self.validate_user_image() {
            return false;
        }
        clear_task_switched();
        // SAFETY: validation above constrains XSAVE header/MXCSR fields, the
        // area has the boot-time size/alignment, and TS is clear.
        unsafe { self.restore() };
        true
    }

    /// Save the current FPU/SIMD state into this area.
    ///
    /// Uses `xsaveopt` when available, else `xsave`; falls back to `fxsave`
    /// on non-XSAVE parts. The caller must currently be the FPU owner (i.e.
    /// CR0.TS is clear and the register file holds the state to save).
    ///
    /// # Safety
    ///
    /// The caller must be in ring 0 and must not have CR0.TS set (else the
    /// save instruction itself #NMs). The area must not be aliased by any
    /// other reference during the save.
    #[inline]
    pub unsafe fn save(&mut self) {
        // SAFETY: The area is aligned and sized per `FpuInfo` (verified at
        // construction), `mask` is a subset of XCR0, and the caller
        // guarantees ring 0 and that CR0.TS is clear. The `&mut self` borrow
        // proves no aliasing for the duration of the call.
        if self.xsave {
            if self.xsaveopt {
                unsafe { xsaveopt(self.ptr.as_ptr(), self.mask) };
            } else {
                unsafe { xsave(self.ptr.as_ptr(), self.mask) };
            }
        } else {
            unsafe { fxsave(self.ptr.as_ptr()) };
        }
    }

    /// Restore the FPU/SIMD state from this area into the register file.
    ///
    /// Uses `xrstor` on XSAVE parts, `fxrstor` otherwise. The caller must
    /// have cleared CR0.TS (via [`clear_task_switched`]) first.
    ///
    /// # Safety
    ///
    /// The caller must be in ring 0 and must have cleared CR0.TS. The area
    /// must contain a valid XSAVE image (a freshly-allocated zeroed area is
    /// valid and yields the initial FPU state).
    #[inline]
    pub unsafe fn restore(&self) {
        // SAFETY: Same alignment/size/mask/ring-0 invariants as `save`; the
        // area holds a valid image (zeroed at construction, overwritten by
        // `save` thereafter). `&self` is enough because `xrstor` only reads.
        if self.xsave {
            unsafe { xrstor(self.ptr.as_ptr(), self.mask) };
        } else {
            unsafe { fxrstor(self.ptr.as_ptr()) };
        }
    }
}

impl Drop for FpuSaveArea {
    fn drop(&mut self) {
        // SAFETY: `self.ptr` was returned by `kmalloc_zeroed` with exactly
        // `self.layout` and has not been freed yet (Drop runs once). The
        // area is not accessed after this point.
        unsafe { crate::mm::kmalloc::kfree(self.ptr, self.layout) };
    }
}

// The area owns a heap buffer that is only touched by the CPU currently
// running the owning task; it is safe to move across CPUs during task
// migration. The buffer itself is not `Sync` (no internal locking), so we
// implement only `Send`.
unsafe impl Send for FpuSaveArea {}

// ---------------------------------------------------------------------------
// Per-task FPU context (the lazy state machine)
// ---------------------------------------------------------------------------

/// The lazy-FPU state of a single task.
///
/// `Fresh` means the task has never touched the FPU; the save area is still
/// in its zeroed initial state and no `xsave` has ever run for it. `Live`
/// means the CPU's register file currently holds this task's state (this
/// task is the FPU owner). `Saved` means the image is in the area and the
/// register file holds some other task's state (or nothing).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
enum State {
    /// Never used the FPU; area is the zeroed initial image.
    Fresh = 0,
    /// Register file currently holds this task's state.
    Live = 1,
    /// Image is in the area; registers hold something else.
    Saved = 2,
}

impl State {
    /// Encode to the `AtomicU8` backing value.
    #[inline]
    const fn as_u8(self) -> u8 {
        self as u8
    }
    /// Decode from the `AtomicU8` backing value, defaulting to `Fresh` for any
    /// out-of-range value (which is impossible by construction but keeps the
    /// decode total).
    #[inline]
    fn from_u8(v: u8) -> Self {
        match v {
            1 => State::Live,
            2 => State::Saved,
            _ => State::Fresh,
        }
    }
}

/// A per-task FPU context: an owned save area plus the lazy state machine.
///
/// The scheduler embeds one of these per task. It drives the context through
/// [`switch_out`], [`switch_in`], and (from the `#NM` handler)
/// [`handle_device_not_available`].
///
/// # Concurrency
///
/// Only the CPU currently running the owning task touches a given context,
/// and the scheduler guarantees a task runs on at most one CPU at a time.
/// The `state` field is an `AtomicU8` only so it can be read and updated
/// through a shared reference during the switch paths; `Relaxed` ordering is
/// sufficient because the state machine is per-task and the scheduler's own
/// synchronisation already provides the necessary happens-before edges.
pub struct FpuContext {
    area: FpuSaveArea,
    state: AtomicU8,
    /// Whether AVX is enabled, remembered at construction so the first-use
    /// path knows whether to emit `vzeroupper`.
    avx: bool,
}

impl FpuContext {
    /// Allocate a fresh context for a new task. The area is zeroed (the
    /// architectural initial state) and the state is `Fresh`.
    ///
    /// `Result` is already `#[must_use]`, so no explicit attribute is needed.
    pub fn new() -> Result<Self, FpuAreaError> {
        let area = FpuSaveArea::new()?;
        let avx = info()
            .map(|i| i.xcr0.contains(XsaveComponents::YMM))
            .unwrap_or(false);
        Ok(Self {
            area,
            state: AtomicU8::new(State::Fresh.as_u8()),
            avx,
        })
    }

    /// Call from the scheduler when this task is being switched out.
    ///
    /// If the task is currently the FPU owner (`Live`), saves its state into
    /// the area and transitions to `Saved`. Then arms the lazy restore by
    /// setting CR0.TS, so the next task's first FPU instruction traps.
    /// A `Fresh` or already-`Saved` task needs no save — only the TS arm.
    pub fn switch_out(&self) {
        let prev = self.state.load(Ordering::Relaxed);
        if State::from_u8(prev) == State::Live {
            // SAFETY: We are the FPU owner (state == Live implies CR0.TS is
            // clear and the register file holds our state), we are in ring 0
            // (scheduler context), and the `&mut`-style access is safe
            // because no other CPU touches this task's area. We cast away
            // immutability for the raw pointer write; the scheduler
            // guarantees exclusivity.
            unsafe {
                (&self.area as *const FpuSaveArea as *mut FpuSaveArea)
                    .as_mut()
                    .expect("FpuSaveArea pointer is non-null")
                    .save()
            };
            self.state.store(State::Saved.as_u8(), Ordering::Relaxed);
        }
        set_task_switched();
    }

    /// Call from the scheduler when this task is being switched in.
    ///
    /// Does not restore the FPU state — it only arms CR0.TS so the first FPU
    /// instruction the task executes traps into the lazy `#NM` handler, which
    /// is where the (possibly expensive) `xrstor` happens.
    pub fn switch_in(&self) {
        set_task_switched();
    }

    /// The `#NM` (device-not-available) handler entry point.
    ///
    /// Clears CR0.TS, then either restores this task's saved image (if the
    /// state is `Saved`) or initialises a pristine FPU (if `Fresh`, i.e. the
    /// task has never used the FPU before). After this the task is `Live` and
    /// owns the FPU until its next `switch_out`.
    ///
    /// The exception handler in `interrupts::exceptions` is expected to call
    /// this with the current task's [`FpuContext`] before returning. If the
    /// scheduler is not yet running (early boot FPU use), the BSP's own
    /// context (or a one-shot `clts` + `fninit`) handles it; this path is
    /// only reached once per-task contexts exist.
    ///
    /// # Safety
    ///
    /// Must be called from the `#NM` exception handler in ring 0 with
    /// `ctx` being the current task's FPU context. The caller must guarantee
    /// no other CPU is concurrently manipulating `ctx`.
    pub unsafe fn handle_device_not_available(&self) {
        clear_task_switched();
        let prev = self.state.load(Ordering::Relaxed);
        match State::from_u8(prev) {
            State::Saved => {
                // SAFETY: CR0.TS is now clear, the area holds a valid image
                // (saved on switch-out or zeroed at construction), ring 0.
                unsafe { self.area.restore() };
                self.state.store(State::Live.as_u8(), Ordering::Relaxed);
            },
            State::Fresh => {
                // First-ever FPU use: give the task a clean register file.
                // SAFETY: ring 0; `fninit` and the XMM zeroing touch only FPU
                // state, no memory. `avx` was captured at construction so we
                // only emit `vzeroupper` on AVX-enabled parts.
                unsafe {
                    fninit();
                    zero_simd_registers(self.avx);
                }
                self.state.store(State::Live.as_u8(), Ordering::Relaxed);
            },
            State::Live => {
                // We were already Live but CR0.TS was set — this happens
                // only if something set TS without switching out (e.g. an
                // explicit `clts`-avoiding path). Restoring is a no-op; just
                // stay Live. The register file already holds our state.
            },
        }
    }

    /// Whether this task currently owns the FPU (state == `Live`). Diagnostic
    /// only; not used by the state machine.
    #[inline]
    #[must_use]
    pub fn is_live(&self) -> bool {
        State::from_u8(self.state.load(Ordering::Relaxed)) == State::Live
    }

    /// The size of the underlying save area in bytes.
    #[inline]
    #[must_use]
    pub fn area_size(&self) -> usize {
        self.area.size()
    }
}

/// Convenience free function invoked by the `#NM` exception handler.
///
/// Equivalent to `ctx.handle_device_not_available()` but exported under the
/// name the exception dispatch code reaches for. See
/// [`FpuContext::handle_device_not_available`] for the contract.
///
/// # Safety
///
/// See [`FpuContext::handle_device_not_available`].
#[inline]
pub unsafe fn handle_device_not_available(ctx: &FpuContext) {
    unsafe { ctx.handle_device_not_available() };
}
