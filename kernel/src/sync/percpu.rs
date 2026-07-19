//! Array-backed per-CPU storage.
//!
//! [`PerCpu<T>`] gives each logical CPU its own private slot of type `T`,
//! accessed without locks because — by construction — only the owning CPU
//! touches its slot. This is the kernel analogue of thread-local storage,
//! adapted to the SMP rule "CPU *i* only reads and writes slot *i*."
//!
//! The storage is a fixed-size array of [`UnsafeCell<T>`] indexed by the
//! compact logical CPU id. `arch/x86_64/percpu.rs` publishes that id from
//! each CPU's GS-based control block; before BSP GS setup it safely falls
//! back to CPU zero for early boot.
//!
//! # Sizing
//!
//! The array is sized to [`MAX_CPUS`]. Every `PerCpu<T>` therefore costs
//! `MAX_CPUS * size_of::<T>()` bytes. This trades some static footprint for
//! allocation-free access and stable addresses during AP bring-up.
//!
//! # Safety argument
//!
//! Each slot is a plain `UnsafeCell<T>`, so we opt out of Rust's automatic
//! `!Sync` and then re-implement `Sync` manually. The invariant that makes
//! that sound is: **slot *i* is only ever accessed while running on CPU
//! *i***. As long as every accessor first obtains the current CPU id and
//! indexes only that slot, no two CPUs ever touch the same cell, so there
//! is no data race despite the `UnsafeCell`. `current_cpu` is the single
//! bridge between "the CPU I'm on" and "the slot I may touch," which is why
//! it is the one arch-dependent piece.

use core::cell::UnsafeCell;
use core::fmt;

/// Maximum number of logical CPUs supported by the static topology.
///
/// Sized to cover any realistic desktop/server Xenith target with headroom.
/// The ACPI MADT determines which subset is present and online at boot.
pub const MAX_CPUS: usize = 64;

/// Fixed-capacity per-CPU storage indexed by the GS-derived logical CPU id.
pub struct PerCpu<T> {
    /// One slot per possible CPU. Indexed by [`current_cpu`].
    ///
    /// `UnsafeCell` is the Rust idiom for "I will mutate this through a
    /// shared reference, and I take responsibility for the synchronization
    /// invariant that makes that safe." Here the invariant is the per-CPU
    /// ownership rule described in the module docs.
    slots: [UnsafeCell<T>; MAX_CPUS],
}

// `Send` is auto-derived: `[UnsafeCell<T>; N]: Send where T: Send`, so
// `PerCpu<T>` is `Send` when `T: Send` without a manual impl. We only
// spell out `Sync`, which the auto trait refuses because `UnsafeCell` is
// `!Sync`.
//
// SAFETY: The structure is `Sync` because the per-CPU ownership invariant
// (slot i is only touched on CPU i) means a shared `&PerCpu<T>` handed to
// many CPUs does not let two CPUs touch the same cell. We require `T: Send`
// rather than `T: Sync` because the *pattern* is single-writer-per-CPU, not
// multi-reader: a slot is mutated in place by its owner, which is the same
// contract that makes `thread_local!` safe.
unsafe impl<T: Send> Sync for PerCpu<T> {}

impl<T> PerCpu<T> {
    /// Create a per-CPU store where every slot starts at `T::default()`.
    ///
    /// `T: Default` is required because all possible CPU slots are prepared
    /// together, before the runtime topology is necessarily known.
    #[must_use]
    pub fn new() -> Self
    where
        T: Default,
    {
        // `from_fn` builds the array without requiring `T: Copy`, which
        // matters because per-CPU data is often non-Copy (structs of
        // pointers, locks, etc.).
        Self {
            slots: core::array::from_fn(|_| UnsafeCell::new(T::default())),
        }
    }

    /// Create a per-CPU store where every slot starts at a clone of `value`.
    ///
    /// Prefer this over [`new`](Self::new) when `T` has a cheap `Clone` but
    /// an expensive or unavailable `Default`. The original `value` is cloned
    /// once per slot, so the cost is `MAX_CPUS` clones.
    #[must_use]
    pub fn with_value(value: T) -> Self
    where
        T: Clone,
    {
        // The closure captures `value` by shared reference and clones it for
        // each slot. We cannot move `value` into the first slot and clone
        // for the rest, because `from_fn`'s closure is `FnMut` and cannot
        // move out of its captured environment on one call and then reuse
        // it on the next. Cloning every slot is the simplest correct shape
        // and the cost is bounded by `MAX_CPUS`.
        Self {
            slots: core::array::from_fn(|_| UnsafeCell::new(value.clone())),
        }
    }

    /// Run `f` with a mutable reference to the current CPU's slot.
    ///
    /// This is the primary accessor: it hands out `&mut T` for the slot
    /// belonging to the CPU the caller is running on, so no other CPU can
    /// be touching the same slot and the access is race-free by
    /// construction.
    #[inline]
    pub fn with<R, F>(&self, f: F) -> R
    where
        F: FnOnce(&mut T) -> R,
    {
        let slot = self.current_slot();
        // SAFETY: `slot` is the cell for the current CPU, and the per-CPU
        // ownership invariant guarantees no other CPU accesses this cell
        // concurrently. We are the sole accessor for the duration of `f`,
        // so a mutable borrow is sound.
        let value: &mut T = unsafe { &mut *slot.get() };
        f(value)
    }

    /// Return a copy of the current CPU's slot.
    ///
    /// Requires `T: Copy` because we return by value without moving out of
    /// the slot. For non-`Copy` per-CPU data, use [`with`](Self::with) and
    /// clone inside the closure.
    #[inline]
    pub fn get(&self) -> T
    where
        T: Copy,
    {
        let slot = self.current_slot();
        // SAFETY: Same per-CPU ownership invariant as `with`. We only read
        // the current CPU's slot, which no other CPU can be mutating.
        unsafe { *slot.get() }
    }

    /// Overwrite the current CPU's slot with `value`.
    ///
    /// Drops the previous contents of the slot in place.
    #[inline]
    pub fn set(&self, value: T) {
        let slot = self.current_slot();
        // SAFETY: Same per-CPU ownership invariant. We are the sole accessor
        // of the current CPU's slot, so replacing its value is sound.
        unsafe {
            *slot.get() = value;
        }
    }

    /// Return a raw pointer to the current CPU's slot.
    ///
    /// Intended for subsystems that need to hand the slot to arch code (for
    /// example, installing it as the gs-base per-Cpu area). The pointer is
    /// valid as long as `self` is alive; dereferencing it is subject to the
    /// same per-CPU ownership invariant as the safe accessors.
    #[inline]
    #[must_use]
    pub fn current_ptr(&self) -> *mut T {
        self.current_slot().get()
    }

    /// Return a raw pointer to slot `cpu`, without checking that `cpu` is
    /// the current CPU or even in range.
    ///
    /// The caller is responsible for upholding the per-CPU ownership
    /// invariant (only access slot `cpu` while running on CPU `cpu`) and
    /// for keeping `cpu < MAX_CPUS`. Primarily intended for bring-up code
    /// that initializes another CPU's slot before that CPU is online.
    ///
    /// # Safety
    ///
    /// `cpu` must be less than [`MAX_CPUS`]. The caller must ensure no other
    /// CPU is concurrently accessing slot `cpu`.
    #[inline]
    pub unsafe fn slot_ptr(&self, cpu: usize) -> *mut T {
        debug_assert!(cpu < MAX_CPUS, "cpu index {cpu} out of range");
        // SAFETY: The caller guarantees `cpu < MAX_CPUS` and exclusive
        // access to the slot.
        unsafe { self.slots.get_unchecked(cpu).get() }
    }

    /// Return the `UnsafeCell` for the current CPU.
    #[inline]
    fn current_slot(&self) -> &UnsafeCell<T> {
        let cpu = current_cpu();
        // SMP assigns compact ids in `0..MAX_CPUS`; pre-init falls back to
        // zero. An out-of-range value would therefore be an arch bug.
        &self.slots[cpu]
    }
}

impl<T: Default> Default for PerCpu<T> {
    fn default() -> Self {
        Self::new()
    }
}

impl<T: fmt::Debug> fmt::Debug for PerCpu<T> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        // We must not read the slots through a shared reference without
        // upholding the per-CPU invariant — doing so could race with the
        // owning CPU. Report only the current CPU's slot, which we are
        // allowed to read, plus the capacity.
        let cpu = current_cpu();
        // SAFETY: We are on `cpu`, so reading its slot does not race with
        // any other CPU. A shared `&self` borrow is fine because we read
        // only our own cell.
        let current: &T = unsafe { &*self.slots[cpu].get() };
        f.debug_struct("PerCpu")
            .field("cpu", &cpu)
            .field("current", current)
            .field("capacity", &MAX_CPUS)
            .finish()
    }
}

/// Return the index of the CPU the caller is currently running on.
///
/// Delegates to [`arch::x86_64::percpu::current_cpu`], which reads the
/// `cpu_id` field of the running CPU's per-CPU control block via a single
/// `gs:`-relative `mov`. That read is safe from any ring-0 context,
/// including interrupt handlers and the context-switch path.
///
/// Before the arch per-CPU subsystem is initialised — i.e. before
/// [`arch::x86_64::percpu::init_for_bsp`] has run — the arch side returns
/// `0` (the BSP identity) so early boot can use array-backed [`PerCpu`]
/// values. Once each CPU's GS base is published, this returns its compact
/// logical CPU index.
///
/// [`arch::x86_64::percpu::current_cpu`]: crate::arch::x86_64::percpu::current_cpu
/// [`arch::x86_64::percpu::init_for_bsp`]: crate::arch::x86_64::percpu::init_for_bsp
#[inline]
pub fn current_cpu() -> usize {
    // Forward to the arch implementation. The arch side handles the
    // pre-init fallback (returns 0 before GS_BASE is published) and the
    // post-init `gs:` read.
    crate::arch::x86_64::percpu::current_cpu()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn default_initializes_all_slots() {
        let p: PerCpu<u32> = PerCpu::new();
        // Host tests have no GS-based kernel setup, so current_cpu() is 0.
        assert_eq!(p.get(), 0);
        p.set(42);
        assert_eq!(p.get(), 42);
    }

    #[test]
    fn with_value_clones_into_slots() {
        let p: PerCpu<u32> = PerCpu::with_value(7);
        assert_eq!(p.get(), 7);
    }

    #[test]
    fn with_runs_closure_on_current_slot() {
        let p: PerCpu<u32> = PerCpu::new();
        let result = p.with(|v| {
            *v = 99;
            *v + 1
        });
        assert_eq!(result, 100);
        assert_eq!(p.get(), 99);
    }

    #[test]
    fn current_cpu_preinit_returns_zero() {
        assert_eq!(current_cpu(), 0);
    }
}
