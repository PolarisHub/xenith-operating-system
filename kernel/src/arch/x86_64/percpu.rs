//! Per-CPU control block reached via the GS segment base.
//!
//! On x86_64 the `gs` segment provides a per-CPU base address: each logical
//! CPU has its own `IA32_GS_BASE` MSR, and every `gs:`-prefixed memory access
//! is relative to that base. Xenith exploits this to give each CPU a private
//! [`PerCpuArea`] — a small control block holding the running task pointer,
//! the CPU's identity, its TSS, and the saved kernel RSP — reachable in a
//! single instruction from any ring-0 context.
//!
//! This is the kernel analogue of thread-local storage, keyed to the CPU
//! instead of the thread. The SMP rule that makes it sound is: **CPU *i*
//! only ever reads and writes its own per-CPU area**, so no lock is required
//! to access it. Every accessor below obtains the area through `gs:` and is
//! therefore lock-free and safe to call from interrupt handlers, scheduler
//! context-switch code, and the syscall entry path alike.
//!
//! # SWAPGS usage
//!
//! `swapgs` is a single privileged instruction that atomically exchanges
//! `IA32_GS_BASE` and `IA32_KERNEL_GS_BASE`. The Xenith convention follows
//! the operating-system standard:
//!
//! 1. **At CPU bring-up** ([`init_for_bsp`] / [`init_for_ap`]) the kernel
//!    writes the per-CPU area's linear address into *both* MSRs. While the
//!    CPU runs kernel code, `IA32_GS_BASE` holds the per-CPU area and
//!    `IA32_KERNEL_GS_BASE` holds the same value (the "shadow").
//! 2. **Before entering ring 3** the kernel executes `swapgs`: the per-CPU
//!    address moves into the shadow and the user thread's GS base moves into
//!    `IA32_GS_BASE`. User code now runs with its own GS.
//! 3. **On `syscall`/interrupt entry from ring 3** the first instruction
//!    executes `swapgs`, pulling the kernel per-CPU base back into
//!    `IA32_GS_BASE` so every `gs:` access in the handler reaches the
//!    per-CPU area.
//! 4. **On `sysret`/`iretq` back to ring 3** the kernel executes `swapgs`
//!    again to restore the user GS base.
//!
//! **Critical invariant**: `swapgs` must run *exactly once* on the
//! kernel-entry path and *exactly once* on the kernel-exit path for a given
//! ring transition. Running it twice (or zero times) leaves `IA32_GS_BASE`
//! holding the user base while kernel code runs, so `gs:` accesses hit the
//! wrong memory — a silent, almost-always-fatal corruption.
//!
//! **NMI / SMI hazard**: a non-maskable interrupt can fire *between* the
//! `swapgs` and the ring transition that brackets it, while
//! `IA32_GS_BASE` still holds the user base. An NMI handler that
//! unconditionally `swapgs`-es on entry would swap the wrong pair and
//! corrupt state. The robust fix — used by Linux and required here — is for
//! the NMI entry stub to test whether it interrupted user or kernel mode
//! (by inspecting the saved `CS` in the interrupt frame) and only `swapgs`
//! when coming from user mode. That stub lives in `asm/isr.S`; this
//! module's [`swapgs`] wrapper is the building block it uses.
//!
//! # Pre-init safety
//!
//! Before [`init_for_bsp`] runs, `IA32_GS_BASE` is whatever Limine left it
//! at (typically zero) and `gs:` accesses would fault. To keep the
//! array-backed [`crate::sync::percpu::PerCpu`] storage working during early
//! boot, [`current_cpu`] and [`get`] consult an [`AtomicU32`] "initialised"
//! flag: before init they return a safe BSP-default (CPU 0 / the static BSP
//! area), and after init they read `gs:`. The flag is set *after* the GS
//! base MSRs are written, so any caller that observes it is guaranteed a
//! valid GS base.
//!
//! The MSR writes and `gs:` accesses are privileged (ring 0) and are
//! `unsafe` at the leaf level. The safe wrappers above them establish the
//! ring-0 + initialised-GS invariants once at boot and then present a safe
//! API to the rest of the kernel, mirroring how `gdt` and `early_init`
//! handle their privileged primitives.

use core::arch::asm;
use core::ptr::{addr_of, addr_of_mut};
use core::sync::atomic::{AtomicU32, Ordering};

use super::gdt::TaskStateSegment;
use super::msr::{IA32_GS_BASE, IA32_KERNEL_GS_BASE};
// ---------------------------------------------------------------------------
// Scheduler task type
// ---------------------------------------------------------------------------
/// Real scheduler task type stored by pointer in [`PerCpuArea`].
///
/// Keeping the architecture field typed avoids accepting unrelated pointers
/// while preserving the per-CPU ABI: `current_task` is still one machine word
/// and this module never dereferences it.
pub use crate::sched::task::Task;

// ---------------------------------------------------------------------------
// PerCpuArea
// ---------------------------------------------------------------------------

/// The per-CPU control block.
///
/// One of these exists per logical CPU. The BSP's area is a statically
/// allocated [`BSP_PERCPU`]; each AP receives a permanent static area from
/// the SMP bring-up code and installs it via [`init_for_ap`]. In both cases
/// the area's linear address is loaded
/// into `IA32_GS_BASE` so every `gs:`-prefixed access reaches it.
///
/// # Field layout
///
/// The struct is `#[repr(C)]` and the fields are ordered so the hot
/// accessors hit fixed, easily-encoded offsets:
///
/// | Offset | Field           | Purpose                                  |
/// |--------|-----------------|------------------------------------------|
/// | 0      | `self_ptr`      | GS-relative self-reference (`mov gs:[0]`)|
/// | 8      | `cpu_id`        | 32-bit logical CPU index                 |
/// | 12     | `_pad0`         | Align `current_task` to 8 bytes          |
/// | 16     | `current_task`  | Pointer to the running `Task` (or null)  |
/// | 24     | `kernel_rsp`    | Saved kernel RSP for this CPU            |
/// | 32     | `tss`           | This CPU's Task State Segment (104 B)    |
/// | 136    | `reserved`      | Growth room (preempt count, stats, ...)  |
///
/// The `reserved` tail keeps the layout stable when later phases add
/// fields (a per-CPU preempt counter, a local-APIC timer deadline, an
/// allocator free-list cache) without shifting the offsets the asm
/// encoders depend on.
#[repr(C)]
pub struct PerCpuArea {
    /// GS-relative self-pointer: always holds the linear address of this
    /// area. `mov rax, gs:[0]` recovers the area's address in one
    /// instruction, avoiding an `rdmsr` on every [`get`] call. Written once
    /// during bring-up before GS_BASE is published.
    pub self_ptr: *mut PerCpuArea,
    /// The 32-bit logical CPU index this area belongs to. Read via
    /// [`current_cpu`] (`mov eax, gs:[8]`).
    pub cpu_id: u32,
    /// Padding so `current_task` lands on an 8-byte boundary.
    _pad0: u32,
    /// Pointer to the task currently running on this CPU, or null when the
    /// CPU is idle. The scheduler updates this on every context switch via
    /// [`set_current_task`]. Read via [`current_task`] (`mov rax, gs:[16]`).
    pub current_task: *mut Task,
    /// Saved kernel RSP for this CPU. Used by the syscall entry path to pick
    /// a kernel stack when entering from ring 3, and by the scheduler as a
    /// scratch for the context-switch dance. Read via [`kernel_rsp`].
    pub kernel_rsp: u64,
    /// This CPU's Task State Segment. The CPU loads `RSP0` from here on
    /// every ring-3 -> ring-0 transition and the IST entries on
    /// IST-armed interrupts. The scheduler writes `rsp0` on every context
    /// switch; the IDT phase writes `ist[6]` (IST7) for the double-fault
    /// stack. AP GDT descriptors point directly at this field; the BSP keeps
    /// the GDT module's static TSS synchronized for boot compatibility.
    pub tss: TaskStateSegment,
    /// Reserved growth room. Future phases add per-CPU fields here (a
    /// preempt counter, an allocator free-list cache, ...) without
    /// disturbing the offsets above. Always zero-initialised.
    pub reserved: [u64; 8],
}

// `PerCpuArea` holds raw pointers, which are `!Send + !Sync` by default.
// The BSP area is a `static mut` (no `Sync` requirement) and AP areas are
// heap/frame-allocated and never shared across CPUs, so we do not need a
// manual `Sync` impl. If a future phase stores a `PerCpuArea` behind a
// shared static handle it must add `unsafe impl Sync` with the per-CPU
// ownership argument documented in the module header.

impl PerCpuArea {
    /// Construct a zeroed per-CPU area for `cpu_id`.
    ///
    /// `const` so the BSP static can be initialised at load time. The
    /// `self_ptr` is left null here — it cannot be known at const-evaluation
    /// time — and is patched in by [`init_for_bsp`] / [`init_for_ap`] before
    /// the area is published via GS_BASE.
    pub const fn new_zeroed(cpu_id: u32) -> Self {
        Self {
            self_ptr: core::ptr::null_mut(),
            cpu_id,
            _pad0: 0,
            current_task: core::ptr::null_mut(),
            kernel_rsp: 0,
            tss: TaskStateSegment::new(),
            reserved: [0; 8],
        }
    }
}

// ---------------------------------------------------------------------------
// Field offsets — kept in sync with the struct above by the assertions at
// the bottom of this file. The asm accessors interpolate these as `const`
// immediates so the encoder produces `gs:[<offset>]`.
// ---------------------------------------------------------------------------

/// Offset of `self_ptr` (0). Used by [`get`] and the internal self-pointer read.
const OFF_SELF_PTR: u64 = 0;
/// Offset of `cpu_id` (8). Used by [`current_cpu`].
const OFF_CPU_ID: u64 = 8;
/// Offset of `current_task` (16). Used by [`current_task`] / [`set_current_task`].
const OFF_CURRENT_TASK: u64 = 16;
/// Offset of `kernel_rsp` (24). Used by [`kernel_rsp`] / [`set_kernel_rsp`].
const OFF_KERNEL_RSP: u64 = 24;
/// Offset of `tss` (32). Used by the TSS accessors.
const OFF_TSS: u64 = 32;

// ---------------------------------------------------------------------------
// Statics
// ---------------------------------------------------------------------------

/// The BSP's per-CPU area.
///
/// Statically allocated so its address is known at link time and stable for
/// the kernel's lifetime — a hard requirement, because `IA32_GS_BASE`
/// stores the address and the CPU reads from it on every `gs:` access. The
/// area is `static mut` because [`init_for_bsp`] patches `self_ptr` and the
/// scheduler mutates `current_task` / `kernel_rsp` / `tss.rsp0` on every
/// context switch. All access goes through raw pointers (`addr_of_mut!`)
/// to avoid forming references to a `static mut`, which the 2024 edition
/// flags under `static_mut_refs`. APs use separate permanent areas installed
/// via [`init_for_ap`].
static mut BSP_PERCPU: PerCpuArea = PerCpuArea::new_zeroed(0);

/// One-way "GS base is valid" flag.
///
/// `0` while [`init_for_bsp`] has not yet run (or is in progress), `1` once
/// the GS base MSRs have been written. [`current_cpu`] / [`get`] consult
/// this before issuing a `gs:` access so that pre-init callers — including
/// array-backed [`crate::sync::percpu::PerCpu`] values during early boot
/// — get a safe BSP-default instead of faulting on an uninitialised GS
/// base. See "Pre-init safety" in the module docs.
static INITIALIZED: AtomicU32 = AtomicU32::new(0);

// ---------------------------------------------------------------------------
// GS base MSR access
// ---------------------------------------------------------------------------

/// Load `IA32_GS_BASE` (the *currently active* GS base) with `gs_base`.
///
/// After this call, every `gs:`-prefixed memory access is relative to
/// `gs_base`. The caller must ensure `gs_base` is the linear address of a
/// valid, naturally-aligned [`PerCpuArea`] that outlives the CPU's use of
/// it (in practice: a `static` or a frame referenced through the HHDM
/// direct map).
///
/// # Safety
///
/// `wrmsr` is privileged (CPL 0). The caller must be in ring 0 and
/// `gs_base` must be a canonical linear address pointing at a valid
/// per-CPU area. Setting a bad GS base turns the next `gs:` access into a
/// fault, which in ring 0 is fatal.
#[inline]
pub unsafe fn set_gs_base(gs_base: u64) {
    // SAFETY: `IA32_GS_BASE` is a valid MSR on every x86_64 part; the
    // caller vouches for ring 0 and a well-formed `gs_base`.
    unsafe {
        IA32_GS_BASE.write(gs_base);
    }
}

/// Load `IA32_KERNEL_GS_BASE` (the shadow GS base swapped in by `swapgs`)
/// with `gs_base`.
///
/// The kernel writes the per-CPU area's address here at bring-up so that a
/// `swapgs` on syscall entry pulls it into the active GS. See "SWAPGS
/// usage" in the module docs.
///
/// # Safety
///
/// `wrmsr` is privileged (CPL 0). Same contract as [`set_gs_base`].
#[inline]
pub unsafe fn set_kernel_gs_base(gs_base: u64) {
    // SAFETY: `IA32_KERNEL_GS_BASE` is a valid MSR on every x86_64 part;
    // the caller vouches for ring 0 and a well-formed `gs_base`.
    unsafe {
        IA32_KERNEL_GS_BASE.write(gs_base);
    }
}

/// Read the currently active GS base (`IA32_GS_BASE`).
///
/// Returns the linear address the per-CPU area is anchored at, or whatever
/// Limine left in the MSR before bring-up. Primarily a diagnostic: the
/// fast accessors below never need it because `gs:` is cheaper than
/// `rdmsr`.
///
/// # Safety
///
/// `rdmsr` is privileged (CPL 0).
#[inline]
#[must_use]
pub unsafe fn get_gs_base() -> u64 {
    // SAFETY: caller vouches for ring 0; `IA32_GS_BASE` is always valid.
    unsafe { IA32_GS_BASE.read() }
}

/// Read the shadow GS base (`IA32_KERNEL_GS_BASE`).
///
/// # Safety
///
/// `rdmsr` is privileged (CPL 0).
#[inline]
#[must_use]
pub unsafe fn get_kernel_gs_base() -> u64 {
    // SAFETY: caller vouches for ring 0; `IA32_KERNEL_GS_BASE` is always
    // valid.
    unsafe { IA32_KERNEL_GS_BASE.read() }
}

/// Atomically exchange `IA32_GS_BASE` and `IA32_KERNEL_GS_BASE`.
///
/// This is the `swapgs` instruction. It is the building block of the
/// ring-transition entry/exit stubs; see "SWAPGS usage" in the module docs
/// for the pairing rules and the NMI hazard. Never call this from arbitrary
/// Rust — it belongs in hand-written asm entry stubs that know whether they
/// interrupted user or kernel mode.
///
/// # Safety
///
/// `swapgs` is privileged (CPL 0) and corrupts the GS base pairing if
/// called an even number of times across a single ring transition. The
/// caller must be in ring 0 and must follow the exactly-once-on-entry /
/// exactly-once-on-exit convention documented above.
#[inline]
pub unsafe fn swapgs() {
    // SAFETY: `swapgs` exchanges the two GS-base MSRs. It touches no
    // memory, no stack, and no EFLAGS, so `nostack`/`nomem`/
    // `preserves_flags` are all sound. The caller vouches for ring 0 and
    // the pairing invariant.
    unsafe {
        asm!("swapgs", options(nostack, nomem, preserves_flags));
    }
}

// ---------------------------------------------------------------------------
// Per-CPU access
// ---------------------------------------------------------------------------

/// Return whether [`init_for_bsp`] has published a valid GS base.
///
/// `Acquire` so that a caller observing `1` also observes the GS-base
/// `wrmsr` that [`init_for_bsp`] performed before its `Release` store.
#[inline]
fn is_initialized() -> bool {
    INITIALIZED.load(Ordering::Acquire) != 0
}

/// Mark the per-CPU subsystem initialised. Called only by [`init_for_bsp`]
/// and [`init_for_ap`] after the GS base MSRs are written.
#[inline]
fn mark_initialized() {
    INITIALIZED.store(1, Ordering::Release);
}

/// Read the running CPU's [`PerCpuArea`] address via `gs:[0]`.
///
/// This is the fast path used by every accessor below: a single `mov` from
/// the self-pointer at offset 0. The caller must guarantee the GS base is
/// valid (i.e. [`is_initialized`] is true or the caller is the bring-up
/// path running after the `wrmsr` but before the flag store).
///
/// # Safety
///
/// `IA32_GS_BASE` must point at a valid, initialised [`PerCpuArea`] whose
/// `self_ptr` field has been patched to point at itself. Ring 0 only.
#[inline]
unsafe fn read_self_ptr() -> *mut PerCpuArea {
    let ptr: u64;
    // SAFETY: `mov rax, gs:[0]` reads the 8-byte self-pointer through the
    // GS segment. The caller guarantees GS_BASE is valid. `mov` does not
    // touch EFLAGS (`preserves_flags`) or the stack (`nostack`); we do not
    // set `nomem` because the instruction reads memory.
    unsafe {
        asm!(
            "mov {ptr}, gs:[{off}]",
            ptr = out(reg) ptr,
            off = const OFF_SELF_PTR,
            options(nostack, preserves_flags),
        );
    }
    ptr as *mut PerCpuArea
}

/// Borrow the running CPU's [`PerCpuArea`] as a shared reference.
///
/// Safe to call from any ring-0 context after [`init_for_bsp`]. Before
/// bring-up completes, returns a reference to the static [`BSP_PERCPU`]
/// area (with `cpu_id == 0` and null task pointer) so pre-init callers —
/// notably the array-backed [`crate::sync::percpu::PerCpu`] stub — get a
/// sensible BSP default instead of faulting on an uninitialised GS base.
///
/// The returned reference is `'static` because per-CPU areas outlive every
/// other kernel allocation (the BSP's is a `static`; APs' are never freed).
#[inline]
#[must_use]
pub fn get() -> &'static PerCpuArea {
    if !is_initialized() {
        // Pre-init: hand back the static BSP area. It is zero-initialised
        // except for `cpu_id == 0`, which is the correct BSP identity.
        //
        // SAFETY: `BSP_PERCPU` is a `static mut` whose storage lives for
        // the program's lifetime. We form a shared reference through a raw
        // pointer (`addr_of!`) to avoid `static_mut_refs`. No other CPU is
        // running yet (we are pre-init on the BSP), so there is no race.
        return unsafe { &*addr_of!(BSP_PERCPU) };
    }
    // SAFETY: the initialised flag is set, so GS_BASE points at a valid
    // per-CPU area and `self_ptr` has been patched. The reference is
    // 'static because per-CPU areas are never freed.
    unsafe { &*read_self_ptr() }
}

/// Run `f` with a mutable reference to the running CPU's [`PerCpuArea`].
///
/// This is the primary mutation entry point: it hands out `&mut` for the
/// area belonging to the CPU the caller is running on, so no other CPU can
/// be touching the same area and the access is race-free by construction.
/// The soundness argument is the per-CPU ownership invariant ("CPU *i*
/// only touches area *i*"), the same one that backs
/// [`crate::sync::percpu::PerCpu`]; interrupt handlers running on the same
/// CPU that access the same fields must use the IRQ-safe discipline
/// (disable interrupts around read-modify-write sequences that must be
/// consistent), which the per-CPU area itself does not provide.
#[inline]
pub fn with<R, F>(f: F) -> R
where
    F: FnOnce(&mut PerCpuArea) -> R,
{
    let area: &mut PerCpuArea = if !is_initialized() {
        // Pre-init: mutate the static BSP area. Only the BSP is running,
        // so the exclusive borrow is sound.
        //
        // SAFETY: single-threaded BSP boot; storage lives for the program
        // lifetime. Accessed through `addr_of_mut!` to avoid
        // `static_mut_refs`.
        unsafe { &mut *addr_of_mut!(BSP_PERCPU) }
    } else {
        // SAFETY: GS_BASE is valid and `self_ptr` is patched; the per-CPU
        // ownership invariant gives us exclusive access to this CPU's
        // area.
        unsafe { &mut *read_self_ptr() }
    };
    f(area)
}

// ---------------------------------------------------------------------------
// Hot per-CPU field accessors
// ---------------------------------------------------------------------------

/// Return the index of the CPU the caller is currently running on.
///
/// Post-init this is a single `mov eax, gs:[8]` — cheaper than an `rdmsr`
/// and safe to call from any ring-0 context, including interrupt handlers
/// and the context-switch path. Pre-init (before [`init_for_bsp`]) it
/// returns `0`, matching the early BSP boot assumption. Every online AP gets
/// a GS base before it enables interrupts, so post-init reads return that
/// CPU's compact logical id.
///
/// This is the arch-side primitive that
/// [`crate::sync::percpu::current_cpu`] delegates to.
#[inline]
#[must_use]
pub fn current_cpu() -> usize {
    if !is_initialized() {
        return 0;
    }
    let cpu: u32;
    // SAFETY: GS_BASE is valid (flag is set). `mov eax, gs:[8]` reads the
    // 32-bit `cpu_id` field. Ring 0 only; `mov` does not touch EFLAGS.
    unsafe {
        asm!(
            "mov {cpu:e}, gs:[{off}]",
            cpu = out(reg) cpu,
            off = const OFF_CPU_ID,
            options(nostack, preserves_flags),
        );
    }
    cpu as usize
}

/// Return the task currently running on this CPU, or null if idle.
///
/// A single `mov rax, gs:[16]`. The scheduler installs this value on every
/// context switch via [`set_current_task`].
#[inline]
#[must_use]
pub fn current_task() -> *mut Task {
    if !is_initialized() {
        // Pre-init the BSP has no task; return null.
        return core::ptr::null_mut();
    }
    let task: u64;
    // SAFETY: GS_BASE is valid; reads the 8-byte `current_task` pointer.
    unsafe {
        asm!(
            "mov {task}, gs:[{off}]",
            task = out(reg) task,
            off = const OFF_CURRENT_TASK,
            options(nostack, preserves_flags),
        );
    }
    task as *mut Task
}

/// Set the task currently running on this CPU.
///
/// Called by the scheduler on the context-switch path. A single
/// `mov gs:[16], <ptr>`.
///
/// # Safety
///
/// The caller must be in ring 0 and `task` must be a valid `*mut Task`
/// (or null for "idle"). The per-CPU ownership invariant requires that
/// this only touch the *current* CPU's area, which it does by construction
/// (the write is `gs:`-relative).
#[inline]
pub unsafe fn set_current_task(task: *mut Task) {
    if !is_initialized() {
        // Pre-init: write the static BSP area directly. Only the BSP is
        // running, so the write is race-free.
        //
        // SAFETY: single-threaded BSP boot; `BSP_PERCPU` storage is valid.
        unsafe {
            (*addr_of_mut!(BSP_PERCPU)).current_task = task;
        }
        return;
    }
    let value = task as u64;
    // SAFETY: GS_BASE is valid; writes the 8-byte `current_task` field.
    // `mov` does not touch EFLAGS. The caller vouches for `task`'s
    // validity.
    unsafe {
        asm!(
            "mov gs:[{off}], {val}",
            off = const OFF_CURRENT_TASK,
            val = in(reg) value,
            options(nostack, preserves_flags),
        );
    }
}

/// Return this CPU's saved kernel RSP.
#[inline]
#[must_use]
pub fn kernel_rsp() -> u64 {
    if !is_initialized() {
        return 0;
    }
    let rsp: u64;
    // SAFETY: GS_BASE is valid; reads the 8-byte `kernel_rsp` field.
    unsafe {
        asm!(
            "mov {rsp}, gs:[{off}]",
            rsp = out(reg) rsp,
            off = const OFF_KERNEL_RSP,
            options(nostack, preserves_flags),
        );
    }
    rsp
}

/// Set this CPU's saved kernel RSP.
///
/// # Safety
///
/// Ring 0. `rsp` must be a valid kernel-virtual stack pointer (or 0).
#[inline]
pub unsafe fn set_kernel_rsp(rsp: u64) {
    if !is_initialized() {
        // SAFETY: single-threaded BSP boot; storage is valid.
        unsafe {
            (*addr_of_mut!(BSP_PERCPU)).kernel_rsp = rsp;
        }
        return;
    }
    // SAFETY: GS_BASE is valid; writes the 8-byte `kernel_rsp` field.
    unsafe {
        asm!(
            "mov gs:[{off}], {val}",
            off = const OFF_KERNEL_RSP,
            val = in(reg) rsp,
            options(nostack, preserves_flags),
        );
    }
}

/// Read this CPU's `cpu_id` field directly from the static area.
///
/// Unlike [`current_cpu`], this does *not* go through `gs:` and therefore
/// does not require the GS base to be initialised. It is intended for the
/// bring-up path itself (which needs the cpu_id while it is in the middle
/// of publishing the GS base) and for diagnostics. Most callers should use
/// [`current_cpu`] instead.
///
/// # Safety
///
/// `area` must be a valid pointer to a [`PerCpuArea`].
#[inline]
pub unsafe fn cpu_id_of(area: *const PerCpuArea) -> u32 {
    // SAFETY: caller guarantees `area` is valid. `cpu_id` is at a fixed
    // offset in a `#[repr(C)]` struct; a plain field read through a raw
    // pointer is sound.
    unsafe { (*area).cpu_id }
}

// ---------------------------------------------------------------------------
// Bring-up
// ---------------------------------------------------------------------------

/// Initialise the per-CPU subsystem on the boot strap processor.
///
/// Patches the BSP area's self-pointer, then loads the area's linear
/// address into both `IA32_GS_BASE` and `IA32_KERNEL_GS_BASE`. After this
/// returns, [`get`], [`with`], [`current_cpu`], and the rest read the BSP
/// area via `gs:` and array-backed [`crate::sync::percpu::PerCpu`] values
/// index slot 0 correctly.
///
/// Safe because the invariants (ring 0, single BSP call, post-GDT load so
/// the kernel selectors are in place) are established by the boot contract,
/// not by something the caller can check at runtime — the same reasoning
/// that makes [`super::early_init`] a safe function. Calling it more than
/// once on the BSP is harmless (idempotent MSRs + flag). APs use
/// [`init_for_ap`].
pub fn init_for_bsp() {
    // SAFETY: we are single-threaded on the BSP in ring 0 at this point
    // (the scheduler has not started), so the exclusive access to
    // `BSP_PERCPU` is sound. The GDT has already been loaded by
    // `gdt::init_bsp`, so the kernel segment selectors are in place and
    // the `wrmsr` for GS_BASE will take effect cleanly.
    unsafe {
        let area = addr_of_mut!(BSP_PERCPU);
        // Patch the self-pointer: `mov rax, gs:[0]` must return `area`.
        (*area).self_ptr = area;
        // cpu_id is already 0 from `new_zeroed`, but set it explicitly so
        // the intent is clear and a future change to the const initialiser
        // cannot silently break the BSP identity.
        (*area).cpu_id = 0;

        // Load both GS-base MSRs with the BSP area's linear address. The
        // static lives in the higher-half kernel image, so its address is
        // already a canonical kernel-virtual address — no HHDM conversion
        // is needed. APs likewise publish permanent higher-half static
        // storage through `init_for_ap`.
        let gs_base = area as u64;
        set_gs_base(gs_base);
        set_kernel_gs_base(gs_base);
    }

    // Publish the initialised flag *after* the MSRs are written. The
    // `Release` ordering pairs with the `Acquire` load in `is_initialized`,
    // so any caller that observes the flag also observes the GS-base
    // writes. On x86 the `wrmsr` is serialising and stores are TSO, so the
    // ordering is already guaranteed by the hardware; the atomic orderings
    // are here for portability and readability.
    mark_initialized();

    ::log::info!(
        "percpu: BSP area online, GS_BASE={:#018x} (cpu_id=0)",
        // SAFETY: we just wrote GS_BASE, so reading it back is safe in
        // ring 0.
        unsafe { get_gs_base() },
    );
}

/// Initialise the per-CPU subsystem on an application processor.
///
/// Used by the SMP bring-up path. The caller prepares permanent
/// [`PerCpuArea`] storage, passes its address and CPU id, and this
/// function patches the self-pointer, sets `cpu_id`, and loads the GS-base
/// MSRs. After it returns, AP-local `gs:` access reaches the new area and
/// [`current_cpu`] returns `cpu_id`.
///
/// # Safety
///
/// * Caller must be in ring 0 on the AP being brought up.
/// * `area` must be a valid, naturally-aligned, writeable
///   [`PerCpuArea`] whose storage outlives the CPU (never freed).
/// * `cpu_id` must be the AP's actual logical CPU index and must not
///   collide with another CPU's id.
/// * The AP's GDT must already be loaded so the `wrmsr` takes effect in a
///   sane segment context.
pub unsafe fn init_for_ap(cpu_id: u32, area: *mut PerCpuArea) {
    // SAFETY: caller guarantees `area` is valid and we are in ring 0.
    unsafe {
        (*area).self_ptr = area;
        (*area).cpu_id = cpu_id;
        // `current_task` / `kernel_rsp` / `tss` are left as initialised by
        // the caller (typically zeroed via `new_zeroed`); the scheduler
        // fills `current_task` on the AP's first context switch and the
        // IDT/GDT phases fill `tss.rsp0` / `tss.ist`.

        let gs_base = area as u64;
        set_gs_base(gs_base);
        set_kernel_gs_base(gs_base);
    }

    // AP bring-up runs after the BSP has already set the global flag, so
    // we do not need to touch `INITIALIZED` here — it is already `1`. The
    // flag is global and one-way; once any CPU has initialised, the
    // pre-init fast paths are disabled for every CPU, which is correct
    // because every CPU either has its own GS base by this point or is
    // about to.
    ::log::info!(
        "percpu: AP area online, GS_BASE={:#018x} (cpu_id={})",
        // SAFETY: we just wrote GS_BASE on this AP.
        unsafe { get_gs_base() },
        cpu_id,
    );
}

// ---------------------------------------------------------------------------
// Compile-time layout assertions
// ---------------------------------------------------------------------------

/// The field offsets the asm encoders depend on must match the `#[repr(C)]`
/// layout. These assertions catch any drift at compile time — if a field is
/// reordered or a padding change shifts an offset, the build fails here
/// instead of producing a silently-wrong `gs:` access.
const _: () = assert!(core::mem::offset_of!(PerCpuArea, self_ptr) as u64 == OFF_SELF_PTR);
const _: () = assert!(core::mem::offset_of!(PerCpuArea, cpu_id) as u64 == OFF_CPU_ID);
const _: () = assert!(core::mem::offset_of!(PerCpuArea, current_task) as u64 == OFF_CURRENT_TASK);
const _: () = assert!(core::mem::offset_of!(PerCpuArea, kernel_rsp) as u64 == OFF_KERNEL_RSP);
const _: () = assert!(core::mem::offset_of!(PerCpuArea, tss) as u64 == OFF_TSS);

/// Total size: 8 + 4 + 4 (pad) + 8 + 8 + 104 (tss) + 64 (reserved) = 200
/// bytes. The struct's alignment is 8 (driven by the u64 / pointer fields;
/// the packed TSS has alignment 1), and 200 is a multiple of 8, so there is
/// no tail padding. A size change means a field was added or resized —
/// update the offsets and this assertion together.
const _: () = assert!(core::mem::size_of::<PerCpuArea>() == 200);

/// `PerCpuArea` must be 8-byte aligned so the u64 / pointer fields are
/// naturally accessible through `gs:`.
const _: () = assert!(core::mem::align_of::<PerCpuArea>() == 8);

// ---------------------------------------------------------------------------
// Tests (host target — exercise only the non-asm surface)
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn new_zeroed_initialises_cpu_id_and_nulls() {
        let area = PerCpuArea::new_zeroed(3);
        assert!(area.self_ptr.is_null());
        assert_eq!(area.cpu_id, 3);
        assert!(area.current_task.is_null());
        assert_eq!(area.kernel_rsp, 0);
        assert_eq!(area.reserved, [0u64; 8]);
    }

    #[test]
    fn bsp_area_is_for_cpu_zero() {
        // The BSP static is const-initialised for cpu_id 0. We read it
        // through a raw pointer to avoid `static_mut_refs` and to match
        // the production access pattern.
        //
        // SAFETY: `BSP_PERCPU` is a `static mut` whose storage is always
        // valid; reading a field through a raw pointer is sound under the
        // single-threaded test harness.
        let cpu_id = unsafe { (*addr_of!(BSP_PERCPU)).cpu_id };
        assert_eq!(cpu_id, 0);
    }

    #[test]
    fn offsets_match_repr_c_layout() {
        // The const assertions above already enforce this at compile time;
        // this test makes the same check explicit at run time so a failure
        // surfaces with a message rather than a build error.
        assert_eq!(OFF_SELF_PTR, 0);
        assert_eq!(OFF_CPU_ID, 8);
        assert_eq!(OFF_CURRENT_TASK, 16);
        assert_eq!(OFF_KERNEL_RSP, 24);
        assert_eq!(OFF_TSS, 32);
    }

    #[test]
    fn size_is_200_bytes() {
        assert_eq!(core::mem::size_of::<PerCpuArea>(), 200);
    }

    #[test]
    fn current_task_points_at_the_real_scheduler_task() {
        // Per-CPU current-task tracking is wired directly to the scheduler's
        // concrete task object, not an old zero-sized bring-up marker.
        assert!(core::mem::size_of::<Task>() > 0);
        assert_eq!(
            core::mem::size_of::<*mut Task>(),
            core::mem::size_of::<u64>()
        );
    }

    #[test]
    fn pre_init_current_cpu_returns_zero() {
        // `INITIALIZED` starts at 0, so `current_cpu` must take the
        // pre-init fast path and return 0 without touching `gs:`. This
        // matches the stub behaviour the array-backed `PerCpu<T>` expects.
        // We do not call the post-init path here because it would execute
        // `gs:`-relative asm, which is only valid on an x86_64 target with
        // a real GS base.
        assert_eq!(current_cpu(), 0);
    }

    #[test]
    fn pre_init_get_returns_bsp_area() {
        // Same pre-init argument: `get` must hand back the static BSP area
        // with cpu_id 0 rather than issuing a `gs:` read.
        let area = get();
        assert_eq!(area.cpu_id, 0);
    }
}
