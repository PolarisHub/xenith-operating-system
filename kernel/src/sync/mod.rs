//! Synchronisation primitives for the Xenith kernel.
//!
//! This module is the single home for every lock and per-CPU storage
//! primitive the rest of the kernel uses. Everything here is built on
//! [`core::sync::atomic`] and, for the IRQ-aware variant, on an in-tree
//! `pushfq`/`cli`/`popfq` save-and-restore sequence. No external crate is
//! involved, so the kernel's locking behaviour is fully auditable in-tree.
//!
//! # Available primitives
//!
//! | Type | Use when |
//! |------|----------|
//! | [`SpinLock<T>`] | Short, data-only critical sections. Never blocks interrupts. |
//! | [`SpinLockIRQ<T>`] | Critical sections reachable from interrupt handlers on the same CPU. |
//! | [`Mutex<T>`] | Task-context critical sections; yields when safe and spins during early boot or critical contexts. |
//! | [`RwLock<T>`] | Read-heavy data with rare, short writes (module list, device tables). |
//! | [`PerCpu<T>`] | Per-CPU private data accessed without locks. |
//!
//! # Ordering and memory model
//!
//! All primitives use `Acquire` on the successful lock-acquire CAS and
//! `Release` on unlock. This is the minimal ordering that publishes a
//! critical section's writes to the next acquirer and makes the prior
//! holder's writes visible to the current one. `Relaxed` is used for
//! non-synchronizing observations (`is_locked`, spin-loop re-reads).
//!
//! # Layering
//!
//! Most of `sync` sits below `sched` and `mm` and above `arch`. The mutex slow
//! path may call the scheduler after checking that it is online; scheduler
//! internals themselves use [`SpinLock`] so this dependency cannot recurse.
//! Standalone short critical sections use
//! [`crate::arch::x86_64::InterruptGuard`]. The IRQ-safe spinlock retains its
//! coupled save/lock and unlock/restore implementation so it can release the
//! lock bit before restoring IF.
//!
//! # No bring-up step
//!
//! None of these primitives require initialization. They are all
//! `const`-constructible (the locks via [`SpinLock::new`] etc., `PerCpu`
//! via [`PerCpu::new`]) and can be placed in `static`s directly. The
//! `init` module therefore does not call into `sync`; subsystems create
//! the locks they need at their own definition sites.

pub mod mutex;
pub mod percpu;
pub mod rwlock;
pub mod spinlock;
pub mod spinlock_irq;

// Flat re-exports so callers can write `use crate::sync::SpinLock` instead
// of drilling into submodules. The submodule paths remain available for
// callers that want to scope imports explicitly.
pub use mutex::{Mutex, MutexGuard};
pub use percpu::{current_cpu, PerCpu, MAX_CPUS};
pub use rwlock::{RwLock, RwLockReadGuard, RwLockWriteGuard};
pub use spinlock::{SpinLock, SpinLockGuard};
pub use spinlock_irq::{SpinLockIRQ, SpinLockIRQGuard};
