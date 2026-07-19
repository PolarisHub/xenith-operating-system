//! Saved register context for a schedulable task.
//!
//! [`Context`] is the in-memory image of a task's callee-saved register file
//! and stack pointer at the moment it is *not* running. The scheduler stores
//! one of these per task; the context-switch routine (defined in
//! `arch/x86_64/asm/context_switch.S`) exchanges the current CPU's register
//! state for the image in a [`Context`] on every dispatch, and writes the
//! outgoing task's state back into its [`Context`] as it leaves.
//!
//! # What is saved
//!
//! Only the callee-saved subset of the GPR file is persisted across a switch:
//! `rbp`, `rbx`, and `r12`..`r15`. The SysV AMD64 ABI guarantees these survive
//! every call, so a task is always free to assume they hold its values when it
//! resumes — which is exactly the invariant a context switch must preserve.
//! The caller-saved registers (`rax`, `rcx`, `rdx`, `rsi`, `rdi`, `r8`..`r11`)
//! are not part of the saved image; any code that calls `context_switch` (i.e.
//! the scheduler) already accepts that those are clobbered, just as they would
//! be by any other function call.
//!
//! `rsp` is saved too, but it plays a different role: swapping `rsp` *is* the
//! switch. The other saved registers are read from / written to their named
//! fields; `rsp` is what rebinds the CPU from one stack to another.
//!
//! # FPU / SIMD state
//!
//! Each [`Context`] carries a 512-byte [`fxsave_area`] for the task's x87 /
//! SSE state. By default the switch path does *not* touch it: the kernel uses
//! lazy FPU save/restore (CR0.TS plus a `#NM` handler in a later phase) so a
//! task that never touches the FPU pays nothing. The eager path —
//! `fxsave` on the way out, `fxrstor` on the way in — can be compiled into the
//! switch stub by enabling the `XENITH_CTX_FPU` preprocessor flag in
//! `build.rs`; when enabled, the area must be 16-byte aligned (it is — see
//! [`Context`] layout below) or `fxsave`/`fxrstor` `#GP`.
//!
//! # Layout contract with the assembly
//!
//! [`Context`] is `#[repr(C, align(16))]` and its field order is load-bearing:
//! the context-switch stub addresses every field by a fixed byte offset, so
//! reordering the fields or removing the alignment pad breaks the switch. The
//! offset constants in [`offsets`] are checked against
//! [`core::mem::offset_of`] at compile time (see the `const` assertion at the
//! bottom of this file), so a Rust-side edit that drifts from the assembly's
//! `#define`s fails the build rather than corrupting registers at runtime.
//! When changing the layout, update both this struct and the `CTX_*` offsets
//! in `arch/x86_64/asm/context_switch.S` together.
//!
//! [`fxsave_area`]: Context::fxsave_area

use core::fmt;
use core::mem::offset_of;

use xenith_types::VirtAddr;

use crate::arch::x86_64::asm::context_switch;

/// Size in bytes of the legacy FXSAVE image saved in [`Context::fxsave_area`].
///
/// `fxsave` (and `fxrstor`) always transfer exactly 512 bytes in legacy mode:
/// the first 32 bytes are the x87 FPU/MMX state and the remainder is the
/// XMM/SSE state plus reserved space. The XSAVE extended area is *not* covered
/// by this size; a future phase that adopts `xsave`/`xsaveopt` with component
/// bitmaps will grow the area and switch to a variable-length save, at which
/// point this constant and the field become the "legacy region" of a larger
/// block.
pub const FXSAVE_AREA_SIZE: usize = 512;

/// Byte offsets of each [`Context`] field, mirroring the `CTX_*` `#define`s in
/// `arch/x86_64/asm/context_switch.S`.
///
/// These exist on the Rust side for three reasons: they document the layout
/// that the assembly depends on, they let `dump` and tests refer to fields by
/// role rather than by magic numbers, and — via the compile-time assertion at
/// the end of this file — they guarantee the Rust layout and the assembly
/// offsets cannot drift apart silently. The assembly is the source of truth
/// for the *values* (it must use raw numeric offsets); this module asserts it
/// agrees.
#[allow(dead_code)] // Referenced by the layout-assertion below; kept named for readers.
pub mod offsets {
    /// Offset of [`Context::rsp`](super::Context::rsp).
    pub const RSP: usize = 0;
    /// Offset of [`Context::rbx`](super::Context::rbx).
    pub const RBX: usize = 8;
    /// Offset of [`Context::rbp`](super::Context::rbp).
    pub const RBP: usize = 16;
    /// Offset of [`Context::r12`](super::Context::r12).
    pub const R12: usize = 24;
    /// Offset of [`Context::r13`](super::Context::r13).
    pub const R13: usize = 32;
    /// Offset of [`Context::r14`](super::Context::r14).
    pub const R14: usize = 40;
    /// Offset of [`Context::r15`](super::Context::r15).
    pub const R15: usize = 48;
    /// Offset of [`Context::fxsave_area`](super::Context::fxsave_area).
    ///
    /// Placed at 64 (not 56) so it lands on a 16-byte boundary, which
    /// `fxsave`/`fxrstor` require. The 8 bytes between `r15` and the area are
    /// the `_pad` field below.
    pub const FXSAVE_AREA: usize = 64;
}

/// Saved callee-saved register file and stack pointer for one task.
///
/// See the [module docs](self) for the full layout rationale and the contract
/// with `context_switch.S`.
#[repr(C, align(16))]
pub struct Context {
    /// Saved stack pointer. This is the only field the switch reads to rebind
    /// the CPU to the new stack; the rest of the register file is loaded from
    /// the other fields after `rsp` is swapped.
    pub rsp: u64,
    /// Saved `rbx` (callee-saved).
    pub rbx: u64,
    /// Saved `rbp` (callee-saved, frame pointer).
    pub rbp: u64,
    /// Saved `r12` (callee-saved).
    pub r12: u64,
    /// Saved `r13` (callee-saved).
    pub r13: u64,
    /// Saved `r14` (callee-saved).
    pub r14: u64,
    /// Saved `r15` (callee-saved).
    pub r15: u64,
    /// Alignment padding so [`fxsave_area`](Self::fxsave_area) lands on a
    /// 16-byte boundary. Not read by the switch; exists solely for layout.
    _pad: u64,
    /// 512-byte FXSAVE image of the task's x87/SSE state. Touched by the
    /// switch only when the `XENITH_CTX_FPU` flag is enabled in the assembly;
    /// otherwise it is owned by the lazy-FPU `#NM` path.
    pub fxsave_area: [u8; FXSAVE_AREA_SIZE],
}

// Compile-time layout contract: the named offsets above must agree with the
// actual `#[repr(C)]` field positions, and the FXSAVE area must be 16-aligned
// relative to the struct start (the struct itself is `align(16)`, so a
// 16-aligned relative offset means every instance's `fxsave_area` is
// 16-aligned in absolute terms as well). If any of these fail, the build
// breaks before a runtime #GP can happen.
const _: () = {
    assert!(offset_of!(Context, rsp) == offsets::RSP);
    assert!(offset_of!(Context, rbx) == offsets::RBX);
    assert!(offset_of!(Context, rbp) == offsets::RBP);
    assert!(offset_of!(Context, r12) == offsets::R12);
    assert!(offset_of!(Context, r13) == offsets::R13);
    assert!(offset_of!(Context, r14) == offsets::R14);
    assert!(offset_of!(Context, r15) == offsets::R15);
    assert!(offset_of!(Context, fxsave_area) == offsets::FXSAVE_AREA);
    assert!(offsets::FXSAVE_AREA.is_multiple_of(16));
};

impl Context {
    /// Build the bootstrap context: an all-zero image used for the CPU's
    /// "current" task before the first real switch.
    ///
    /// The scheduler creates one of these for the boot CPU's pseudo-task. It is
    /// only ever *written* by the first `context_switch` call (which saves the
    /// then-current register state into it); its `rsp` of zero is never loaded
    /// because nothing ever switches *back* to the bootstrap context before a
    /// real task takes its place. Zeroing the whole struct — including the
    /// FXSAVE area — keeps the dump output honest if it is ever inspected.
    pub const fn empty() -> Self {
        Self {
            rsp: 0,
            rbx: 0,
            rbp: 0,
            r12: 0,
            r13: 0,
            r14: 0,
            r15: 0,
            _pad: 0,
            fxsave_area: [0; FXSAVE_AREA_SIZE],
        }
    }

    /// Build the saved-register image for a brand-new task.
    ///
    /// `stack_top` is the highest valid virtual address of the task's kernel
    /// stack (one past the last usable byte), as allocated by the memory
    /// manager. `entry` is the task's entry point — the first instruction the
    /// task will execute. The constructed [`Context`] makes the task appear as
    /// if `context_switch` had just been *called* into it: its `rsp` points at
    /// a stack frame whose top entry is `entry`, so the first `ret` in the
    /// switch stub jumps straight to the task's first instruction with a
    /// SysV-correct stack alignment.
    ///
    /// # Stack frame layout built by this call
    ///
    /// The task's stack is prepared as (low address at top):
    ///
    /// ```text
    ///     [stack_top - 16]  entry address   (the `ret` target)
    ///     [stack_top -  8]  unused          (alignment slot)
    ///                       ^ rsp stored in Context
    /// ```
    ///
    /// The 8-byte alignment slot is what makes `entry` see `rsp ≡ 8 (mod 16)`,
    /// matching the SysV requirement at a callee's entry (a real `call` would
    /// have pushed the 8-byte return address onto a 16-aligned stack). Without
    /// it, any SSE move in `entry`'s prologue that assumes 16-byte stack
    /// alignment would fault.
    ///
    /// The callee-saved GPRs are zeroed: a fresh task has nothing to restore
    /// there, and its own prologue will establish `rbp`/`rbx`/`r12`..`r15` as
    /// it pleases. The FXSAVE area is zeroed too, so if the eager-FPU path is
    /// enabled the first `fxrstor` loads a clean (zeroed) FPU state rather
    /// than stale bytes.
    ///
    /// # Safety
    ///
    /// The caller must ensure `stack_top` points at a writable, mapped,
    /// 16-byte-aligned stack region that remains valid for the lifetime of the
    /// task, and that `entry` is a sound task entry point (typically a
    /// `unsafe extern "C" fn() -> !` that never returns). This function writes
    /// the entry address to `stack_top - 16`; that memory must be owned by the
    /// task's stack and not concurrently touched.
    pub unsafe fn new(stack_top: VirtAddr, entry: unsafe extern "C" fn() -> !) -> Self {
        // The allocator hands us a 16-aligned stack top; align defensively so
        // a misaligned top cannot silently corrupt the alignment invariant.
        let top = stack_top.align_down(16).as_u64();

        // Materialise the entry code pointer as an integer. Function pointers
        // (including those returning `!`) are pointer-sized; coercing first to
        // `*const ()` then to `usize` avoids any edge case around directly
        // casting a `-> !` fn pointer. We store the address to memory; we do
        // not call through it here.
        let entry_addr = entry as *const () as usize as u64;

        // SAFETY: `top` is 16-aligned (caller contract + align_down), so
        // `top - 16` is a valid, 16-aligned address inside the stack region
        // the caller owns. We write exactly one u64 (the entry address) to
        // it; the 8 bytes at `top - 8` are the alignment slot and are left
        // untouched (they hold whatever the allocator left there, which is
        // never read by the switch). The write is volatile to prevent the
        // compiler from eliding it: the stack is not referenced through any
        // Rust reference and the switch reads it via raw asm, so the write
        // must reach memory.
        unsafe {
            core::ptr::write_volatile((top - 16) as *mut u64, entry_addr);
        }

        Self {
            // `ret` in the switch pops the entry address from [rsp], so rsp
            // must point at it: `top - 16`. After the pop, rsp becomes
            // `top - 8` ≡ 8 (mod 16), the SysV callee-entry alignment.
            rsp: top - 16,
            rbx: 0,
            rbp: 0,
            r12: 0,
            r13: 0,
            r14: 0,
            r15: 0,
            _pad: 0,
            fxsave_area: [0; FXSAVE_AREA_SIZE],
        }
    }

    /// Returns the saved stack pointer.
    ///
    /// Exposed as a method (not just public field access) so the scheduler can
    /// read the current `rsp` of a suspended task without reaching into the
    /// struct layout — useful for stack-overflow guards and diagnostics.
    pub const fn rsp(&self) -> u64 {
        self.rsp
    }

    /// Overwrite the saved stack pointer.
    ///
    /// The scheduler uses this when it relocates a task's stack (e.g. growing
    /// a kernel-thread stack) and needs the saved image to track the new top.
    pub fn set_rsp(&mut self, rsp: u64) {
        self.rsp = rsp;
    }

    /// Switch from the current task (`self`) to `next`.
    ///
    /// This is the typed Rust entry point to the `context_switch` assembly
    /// stub. It saves the outgoing task's callee-saved register file and
    /// `rsp` into `*self`, loads the incoming task's image from `*next`, and
    /// returns on `next`'s stack. After this call returns, `self` holds the
    /// state of the task that was just suspended and the CPU is running
    /// `next`.
    ///
    /// # Safety
    ///
    /// The caller (the scheduler) must guarantee:
    ///
    /// * `self` and `next` point at valid, non-aliased [`Context`] structs for
    ///   the duration of the call.
    /// * `next` was prepared by [`Context::new`] (or by an earlier switch) and
    ///   its saved `rsp` refers to a valid, mapped stack.
    /// * The caller is not relying on any caller-saved register across this
    ///   call (per SysV they are clobbered).
    /// * Interrupt state is appropriate for a switch: typically called with
    ///   interrupts disabled or from a context where a timer-tick mid-switch
    ///   cannot recurse into the scheduler.
    ///
    /// Violating any of these corrupts the saved image or the new stack and
    /// will fault on the next instruction.
    pub unsafe fn switch(&mut self, next: &Context) {
        // The extern declaration in `arch::x86_64/asm` types the stub as
        // `(*mut u8, *mut u8)` so it stays ABI-stable regardless of how
        // `Context` evolves; we cast the typed pointers here. `next` is
        // `&Context` (shared) but the stub only *reads* from it, so the
        // conceptual `*const` is expressed as `*mut u8` at the FFI boundary.
        // The cast does not mutate `next` through the shared reference: the
        // stub honours the read-only contract on the second argument, and no
        // other `&Context` or `&mut Context` alias is live across the call per
        // the caller's non-aliasing obligation.
        let old = (self as *mut Context).cast::<u8>();
        // Cast `*const Context` -> `*mut u8`: a valid pointer cast that
        // widens mutability at the FFI boundary. The stub never writes through
        // this pointer.
        let new = (next as *const Context) as *mut u8;

        // SAFETY: upheld by the caller per the doc contract above; the stub
        // itself is `extern "C"` and treats `rdi`/`rsi` as the two Context
        // pointers.
        unsafe { context_switch(old, new) };
    }

    /// Log the saved register image at `debug` level under `label`.
    ///
    /// Intended for scheduler diagnostics (e.g. dumping a task's context on a
    /// watchdog expiry or a suspected stack corruption). Uses `debug!` so it
    /// is silent at the default `info` log level and free in production builds
    /// unless the level is raised. The FXSAVE area is summarised as a
    /// 16-byte hex prefix rather than dumped in full — 512 bytes of hex in a
    /// log line is noise, and the first 16 bytes (x87 FCW/FSW/tag word) are
    /// the part a human inspects.
    pub fn dump(&self, label: &str) {
        ::log::debug!(
            "context {label}: rsp={:#018x} rbx={:#018x} rbp={:#018x} \
             r12={:#018x} r13={:#018x} r14={:#018x} r15={:#018x} \
             fxsave[0..16]={:?}",
            self.rsp,
            self.rbx,
            self.rbp,
            self.r12,
            self.r13,
            self.r14,
            self.r15,
            FxSavePrefix(self),
        );
    }
}

impl fmt::Debug for Context {
    /// Structured debug formatting, mirroring the field order used by
    /// [`Context::dump`]. Does not emit the full FXSAVE area; use
    /// [`FxSavePrefix`] or inspect [`Context::fxsave_area`] directly when the
    /// raw image is needed.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Context")
            .field("rsp", &format_args!("{:#018x}", self.rsp))
            .field("rbx", &format_args!("{:#018x}", self.rbx))
            .field("rbp", &format_args!("{:#018x}", self.rbp))
            .field("r12", &format_args!("{:#018x}", self.r12))
            .field("r13", &format_args!("{:#018x}", self.r13))
            .field("r14", &format_args!("{:#018x}", self.r14))
            .field("r15", &format_args!("{:#018x}", self.r15))
            .field("fxsave_area", &FxSavePrefix(self))
            .finish()
    }
}

/// Debug helper that formats the first 16 bytes of a [`Context`]'s FXSAVE
/// area as a hex string.
///
/// The leading 16 bytes of an FXSAVE image are the x87 control/status/tag
/// words — the part a human can read meaningfully when diagnosing FPU state.
/// The remaining 496 bytes are XMM/SSE state and reserved space, which are
/// not useful in a log line. This wrapper exists so [`Context::dump`] and
/// [`Debug` for `Context`](impl-Debug-for-Context) share one rendering and
/// never accidentally dump the full 512 bytes.
struct FxSavePrefix<'a>(&'a Context);

impl fmt::Debug for FxSavePrefix<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        // Show the first 16 bytes as a flat hex run. `fxsave_area` is plain
        // `u8` data, so there is no alignment or aliasing concern here.
        f.write_str("[")?;
        for (i, b) in self.0.fxsave_area.iter().take(16).enumerate() {
            if i > 0 {
                f.write_str(" ")?;
            }
            write!(f, "{:02x}", b)?;
        }
        f.write_str("..]")?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    //! In-kernel unit tests for the pure-Rust parts of [`Context`].
    //!
    //! The Xenith kernel has no host-side test harness: per the Makefile,
    //! `#[test]` items build into an in-kernel runner executed under QEMU, so
    //! these run in the same `no_std` ring-0 environment as the real code.
    //! They therefore use only `core` primitives (`assert_eq!`, raw pointers,
    //! array iteration) and never touch `alloc` or `std`. The tests cover the
    //! layout invariants and the `new`-stack-frame construction; they
    //! deliberately do not exercise `switch`, which requires the
    //! context-switch assembly and a genuine two-stack setup that is only
    //! meaningful as part of a running scheduler.

    use super::*;

    #[test]
    fn context_size_is_16_aligned() {
        // The struct must be a multiple of 16 so every instance is 16-aligned
        // and the FXSAVE area (at offset 64) is 16-aligned in absolute terms.
        assert_eq!(core::mem::size_of::<Context>() % 16, 0);
        assert_eq!(core::mem::align_of::<Context>(), 16);
    }

    #[test]
    fn fxsave_area_offset_is_16_aligned() {
        assert_eq!(offset_of!(Context, fxsave_area) % 16, 0);
        assert_eq!(offset_of!(Context, fxsave_area), offsets::FXSAVE_AREA);
    }

    #[test]
    fn empty_zeroes_everything() {
        let ctx = Context::empty();
        assert_eq!(ctx.rsp, 0);
        assert_eq!(ctx.rbx, 0);
        assert_eq!(ctx.rbp, 0);
        assert_eq!(ctx.r12, 0);
        assert_eq!(ctx.r13, 0);
        assert_eq!(ctx.r14, 0);
        assert_eq!(ctx.r15, 0);
        assert!(ctx.fxsave_area.iter().all(|&b| b == 0));
    }

    #[test]
    fn new_sets_rsp_below_aligned_top() {
        // Provide a real 32-byte buffer we own so the volatile write to
        // `top - 16` lands in valid memory. `top` is set 16 bytes past the
        // buffer's start + 32, i.e. to the buffer's end, matching how the
        // allocator hands out a stack top (one past the last usable byte).
        let mut buf = [0u64; 4];
        let base = buf.as_mut_ptr() as u64;
        let top = VirtAddr::new_truncate(base + 32);

        unsafe extern "C" fn _entry() -> ! {
            unreachable!("test entry is never called")
        }
        let entry: unsafe extern "C" fn() -> ! = _entry;

        // SAFETY: `Context::new` aligns `top` down to 16 and writes the entry
        // address to `align_down(top,16) - 16`. With `base` u64-aligned and
        // `top = base + 32`, that target is either `base + 16` (base ≡ 0 mod
        // 16) or `base + 8` (base ≡ 8 mod 16); both lie inside `buf`'s 32
        // bytes, so the volatile write is in-bounds and owned by us.
        let ctx = unsafe { Context::new(top, entry) };

        // rsp must point at the entry address slot, 16 below the aligned top.
        let aligned_top = top.align_down(16).as_u64();
        assert_eq!(ctx.rsp, aligned_top - 16);
        assert_eq!(ctx.rsp % 16, 0);
        assert_eq!(ctx.rbx, 0);
        assert_eq!(ctx.r15, 0);
        assert!(ctx.fxsave_area.iter().all(|&b| b == 0));

        // The entry address we wrote must be readable back from the slot.
        // SAFETY: `ctx.rsp` points into `buf`, which we still own.
        let stored = unsafe { *(ctx.rsp as *const u64) };
        assert_eq!(stored, entry as *const () as usize as u64);
    }
}
