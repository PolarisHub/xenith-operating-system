//! Kernel-thread spawner.
//!
//! [`spawn_kernel_thread`] is the kernel's analogue of `pthread_create`: it
//! allocates a private stack, builds an initial CPU context whose entry point
//! is a small trampoline, registers the new thread with the scheduler, and
//! returns a [`TaskId`] the caller can use to refer to it. The trampoline
//! invokes the user-supplied body `f(arg)` and, when `f` returns, calls the
//! scheduler's exit path so the thread's resources are reclaimed.
//!
//! # The trampoline
//!
//! `context_switch` restores a task's callee-saved registers and stack pointer
//! and `ret`s into the saved instruction pointer. For a brand-new thread there
//! is no "real" caller to return to, so the initial context's instruction
//! pointer is set to [`kthread_trampoline`] — a tiny `extern "C"` function
//! whose job is to recover the body pointer, call it, and then exit. The body
//! pointer is delivered to the trampoline in `rdi` (the SysV first-argument
//! register) by the sibling `Context::new_kernel` constructor, which arranges
//! the initial saved register set so the first switch into the task loads
//! `rdi` before the `ret`. This keeps the trampoline free of any per-Task
//! lookup: everything it needs arrives in its first argument.
//!
//! # Stack ownership
//!
//! [`KthreadStack`] owns the 16 KiB allocation and frees it on `Drop`. The
//! sibling `Task` type stores the stack (by value or behind a `Kbox`) so that
//! when the scheduler drops a finished task the stack is reclaimed with it.
//! The stack is zeroed on allocation so a stale kernel-stack read never leaks
//! data from a previous thread.
//!
//! # Lifecycle
//!
//! ```text
//!   spawn_kernel_thread
//!     ├─ KthreadStack::new            // 16 KiB zeroed, 16-byte aligned
//!     ├─ Kbox::new(KthreadStart)      // { f, arg }, leaked to a raw pointer
//!     ├─ Context::new_kernel(trampoline, stack.top(), start_ptr)
//!     ├─ Task::new_kernel(name, context, stack)   // sibling module
//!     └─ scheduler::enqueue(task) -> TaskId        // sibling module
//!
//!   ... scheduler dispatches the task ...
//!
//!   kthread_trampoline(start_ptr)
//!     ├─ recover KthreadStart from start_ptr
//!     ├─ ret = f(arg)                              // the body
//!     └─ scheduler::exit_current(ret) -> !         // sibling module
//! ```

use core::alloc::Layout;
use core::ptr::NonNull;

// Sibling scheduler modules (landing in this same phase). The contract each
// `use` assumes is documented at the call site; the integration pass wires the
// exact paths. These types are the public surface of `sched::task`,
// `sched::context`, and `sched::scheduler`.
use super::task::ExitStatus;
use super::{scheduler, TaskId};
use crate::mm::kmalloc::{kfree, kmalloc_zeroed, KmallocError};
use crate::mm::{KString, Kbox};

/// The stack size allocated for a kernel thread.
///
/// 16 KiB is the conventional kernel-thread stack size (4 pages on a 4 KiB
/// page): large enough for the typical kernel workload — a few nested calls,
/// an interrupt frame, and a small amount of local storage — but small enough
/// that thousands of kernel threads cost at most tens of megabytes. Workloads
/// that need more stack should call a future `spawn_kernel_thread_with_stack`
/// variant; for now this constant is the single source of truth.
pub const KTHREAD_STACK_SIZE: usize = 16 * 1024;

/// The alignment required for a kernel thread stack.
///
/// The x86_64 SysV ABI requires the stack to be 16-byte aligned at function
/// entry. Allocating the stack 16-byte aligned lets the sibling
/// `Context::new_kernel` compute the initial `rsp` with a simple alignment
/// adjustment, with no further padding needed.
const KTHREAD_STACK_ALIGN: usize = 16;

/// An owned, zeroed kernel-thread stack.
///
/// Allocated from the kernel heap with [`kmalloc_zeroed`] so the bytes start
/// clean (no leak of a previous thread's stack contents to a new one) and freed
/// on [`Drop`] so a finished task's stack is reclaimed automatically when the
/// scheduler drops the owning [`Task`].
///
/// The stack grows down, so the usable high address is [`top`](Self::top)
/// (`base + size`); the initial `rsp` is computed from that by the sibling
/// `Context::new_kernel`, which subtracts space for the saved-register frame
/// and aligns the result.
pub struct KthreadStack {
    /// The base (lowest address) of the allocation. `top` is `base + size`.
    base: NonNull<u8>,
    /// The layout the block was allocated with, required by [`kfree`] on drop.
    layout: Layout,
}

impl KthreadStack {
    /// Allocate a new 16 KiB, 16-byte-aligned, zeroed kernel stack.
    ///
    /// Returns [`KmallocError::OutOfMemory`] if the heap cannot satisfy the
    /// request — the caller decides whether that is fatal (boot-time spawn) or
    /// retryable (a dynamic `spawn` syscall).
    ///
    /// # Panics
    ///
    /// Never; allocation failure is propagated as `Err`, not a panic.
    pub fn new() -> Result<Self, KmallocError> {
        // `from_size_align` checks the power-of-two alignment and non-zero size
        // invariants; both are constants here, so this never returns Err. The
        // `expect` is retained for defensiveness against a future edit that
        // changes the constants to a non-power-of-two alignment.
        let layout = Layout::from_size_align(KTHREAD_STACK_SIZE, KTHREAD_STACK_ALIGN)
            .expect("KTHREAD_STACK layout: size/align are valid constants");
        // SAFETY: `kmalloc_zeroed` requires a valid, non-zero-size Layout with a
        // power-of-two alignment. `layout` satisfies both (see above), so the
        // precondition holds.
        let base = kmalloc_zeroed(layout)?;
        Ok(Self { base, layout })
    }

    /// The highest valid address in the stack (`base + size`).
    ///
    /// This is the value the sibling `Context::new_kernel` uses as the starting
    /// point for the initial `rsp` (after it subtracts the saved-frame size and
    /// applies the 16-byte entry alignment). Stacks grow down, so `top` is the
    /// first address a push writes to.
    #[must_use]
    pub fn top(&self) -> *mut u8 {
        // `base` is a valid, aligned, heap allocation of `KTHREAD_STACK_SIZE`
        // bytes that we own for `&self`. The pointer one-past-the-end is valid
        // for arithmetic (but not for dereference); the sibling Context code
        // subtracts from it before any write.
        self.base.as_ptr().wrapping_add(self.layout.size())
    }

    /// The base (lowest address) of the stack allocation, for diagnostics.
    #[must_use]
    pub fn base(&self) -> *mut u8 {
        self.base.as_ptr()
    }

    /// The stack size in bytes.
    #[must_use]
    pub const fn size(&self) -> usize {
        KTHREAD_STACK_SIZE
    }
}

impl Drop for KthreadStack {
    fn drop(&mut self) {
        // SAFETY: `self.base` was returned by `kmalloc_zeroed` with exactly
        // `self.layout`, and we have not freed it yet (the only path to a
        // second free is a double-drop, which `Drop` prevents by taking
        // `&mut self`). `kfree` requires exactly this precondition.
        unsafe { kfree(self.base, self.layout) };
    }
}

// `KthreadStack` is `Send` because the allocation it owns has no per-CPU
// affinity: it is safe to move the owning handle to another CPU before the
// thread runs. It is NOT `Sync` — two CPUs sharing a stack would corrupt it —
// but `Sync` is not required for the spawner's single-owner usage.
unsafe impl Send for KthreadStack {}

/// The startup record handed to a kernel thread's trampoline.
///
/// This is allocated on the heap by [`spawn_kernel_thread`], leaked to a raw
/// pointer, and recovered by [`kthread_trampoline`] on the new thread's first
/// dispatch. The trampoline drops the [`Kbox`] after extracting `f` and `arg`,
/// so the record lives only for the brief window between spawn and first run —
/// it does not persist for the thread's lifetime.
///
/// `repr(C)` is not required (we never lay it out against an ABI), but it keeps
/// the field order stable for `debug!` dumps and any future gdb script.
#[repr(C)]
pub struct KthreadStart {
    /// The body function. Called as `f(arg)`; its return value is passed to
    /// [`exit_current`] as the thread's exit status.
    pub f: extern "C" fn(usize) -> usize,
    /// The opaque argument forwarded to `f`.
    pub arg: usize,
}

/// The kernel-thread trampoline.
///
/// This is the entry point the sibling `Context::new_kernel` installs for a new
/// kernel thread. It receives the [`KthreadStart`] pointer in `rdi` (delivered
/// by the initial saved-register frame), recovers the body `f` and its
/// `arg`, drops the startup record, calls `f(arg)`, and then calls
/// [`exit_current`] — which removes the current task from the scheduler and
/// context-switches to the next runnable one, never returning.
///
/// # Safety
///
/// [`spawn_kernel_thread`] creates the `KthreadStart` with [`Kbox::new`] and
/// leaks it with [`Kbox::into_raw`], producing a `*mut KthreadStart` that owns
/// the allocation. The trampoline receives that pointer as a `usize` (the SysV
/// integer-argument view of `rdi`), casts it back, and reconstructs the
/// [`Kbox`] with [`Kbox::from_raw`] so the record is freed before the body
/// runs. The round-trip is sound because there is exactly one producer (the
/// spawner) and exactly one consumer (this trampoline, on the thread's first
/// dispatch), and the scheduler guarantees the thread runs at most once.
///
/// Marked `extern "C"` so its address can be taken as a plain `usize` code
/// pointer and stored in the initial context; the body is ordinary Rust.
pub unsafe extern "C" fn kthread_trampoline(start_ptr: u64) -> ! {
    // Cast the integer argument back to the typed pointer. `start_ptr` is the
    // exact value produced by `Kbox::into_raw` in `spawn_kernel_thread`, so the
    // cast is lossless and the pointer is valid for the reconstruction below.
    let raw = start_ptr as usize as *mut KthreadStart;

    // Reconstruct the owning `Kbox` and immediately read out `f` and `arg` so
    // the record can be freed before the body runs (the body may block for an
    // unbounded time, and there is no reason to keep the startup record alive
    // across that).
    //
    // SAFETY: `raw` was produced by `Kbox::into_raw` in `spawn_kernel_thread`
    // and has not been freed or reconstructed yet — the trampoline runs exactly
    // once, on the thread's first dispatch. `Kbox::from_raw` requires exactly
    // that precondition, so the reconstruction is sound.
    let start = unsafe { Kbox::from_raw(raw) };
    let f = start.f;
    let arg = start.arg;
    // Dropping `start` frees the `KthreadStart` record now that `f` and `arg`
    // have been copied onto this stack.
    drop(start);

    // Run the body. `f` is `extern "C" fn(usize) -> usize`, so calling it is a
    // normal Rust call; its return value is the thread's exit status.
    let exit_status = f(arg);

    // Tear down the current thread. `exit_current` is the sibling scheduler's
    // "current task is finished" primitive: it removes the task from the
    // scheduler, frees the `Task` (and with it the `KthreadStack` via `Drop`),
    // and context-switches to the next runnable task. It never returns, which
    // is why this function is `-> !`.
    scheduler::exit(ExitStatus::Code(exit_status as i64));
}

/// Spawn a new kernel thread.
///
/// Allocates a 16 KiB stack, builds an initial [`Context`] whose entry point
/// is [`kthread_trampoline`] and whose `rdi` is a leaked pointer to a
/// [`KthreadStart`] carrying `f` and `arg`, wraps both in a [`Task`], and
/// enqueues the task on the current CPU's run queue. When the scheduler next
/// dispatches the task, the trampoline runs `f(arg)` and then exits.
///
/// # Arguments
///
/// * `name` — a diagnostic name for the task (used in `log::debug!` and any
///   future `ps`/task-list surface). Copied into the `Task`'s owned name
///   storage by the sibling constructor, so the caller may pass a non-`'static`
///   `&str` (e.g. one built on a small stack buffer).
/// * `f` — the thread body. Called as `f(arg)`; its return value becomes the
///   thread's exit status, forwarded to [`exit_current`].
/// * `arg` — an opaque word forwarded to `f`. For richer arguments the caller
///   allocates a struct on the heap and passes its address here, the same
///   convention as `pthread_create`.
///
/// # Returns
///
/// The [`TaskId`] of the new thread. The thread is *runnable* the moment this
/// returns; it may be dispatched before the caller continues, so any shared
/// state the thread reads must be initialised before the call.
///
/// # Errors / panics
///
/// Panics if the stack allocation fails. A kernel thread without a stack
/// cannot exist, and at the call sites we have today (idle task, boot-time
/// workers) an OOM is fatal. A future dynamic-spawn path can add a
/// `try_spawn_kernel_thread` variant that returns `Result` instead.
pub fn spawn_kernel_thread(name: &str, f: extern "C" fn(usize) -> usize, arg: usize) -> TaskId {
    // Build a startup record and pass its pointer through the scheduler's
    // canonical task constructor. That constructor owns stack allocation and
    // the asm-compatible initial context.
    // trampoline can reconstruct and free it. The pointer is passed to the
    // entry point as the `arg` that lands in `rdi` on first dispatch.
    let start = Kbox::new(KthreadStart { f, arg });
    // SAFETY: `Kbox::into_raw` consumes the box and returns a pointer that
    // keeps the allocation alive. The pointer is recovered exactly once by
    // `kthread_trampoline` via `Kbox::from_raw`, so there is no leak.
    let start_ptr = Kbox::into_raw(start) as u64;
    let Some(id) = scheduler::spawn(KString::from(name), kthread_trampoline, start_ptr) else {
        // SAFETY: spawn failed before publishing the argument, so ownership
        // of this exact Kbox pointer is still ours to reclaim.
        drop(unsafe { Kbox::from_raw(start_ptr as usize as *mut KthreadStart) });
        panic!("sched.kthread: stack allocation failed for {name:?}");
    };

    ::log::debug!("sched.kthread: spawned {name:?} (tid={id:?})",);

    id
}
