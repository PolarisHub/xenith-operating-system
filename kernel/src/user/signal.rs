//! POSIX-style signal delivery for Xenith user processes.
//!
//! This module owns the kernel side of asynchronous signal delivery: the
//! signal numbering, the per-process pending/blocked state, the disposition
//! table, the frame built on the user stack when a caught signal is
//! dispatched, the default-action policy, and the signal trampoline the
//! handler returns to.
//!
//! # Architecture coupling
//!
//! Delivery happens on the return-to-user path: the interrupt subsystem's
//! trampoline has already saved the faulting/interrupted user register state
//! into an [`ExceptionContext`]. [`check_and_dispatch`] receives a
//! `&mut ExceptionContext`, and — if a deliverable, caught signal is pending —
//! rewrites that frame so `iretq` enters the user handler instead of the
//! originally-interrupted code. The original frame is pushed onto the user
//! stack as a [`SignalFrame`]; the handler returns to the signal trampoline,
//! which performs the `sigreturn` syscall, and [`sigreturn`] restores the
//! saved frame from the stack.
//!
//! # Per-process state
//!
//! Every `user::process::UserProcess` owns a [`SignalState`] by composition.
//! Core entry points take `&SignalState`, keeping signal policy separate from
//! process-table locking. The pending
//! and blocked sets are each guarded by an IRQ-safe spinlock because
//! [`deliver_signal`] is reachable from interrupt context (a timer-driven
//! `SIGALRM`, an IPI, a `kill` from another CPU) while [`check_and_dispatch`]
//! and [`sigreturn`] run on the return-to-user path.
//!
//! # Numbering
//!
//! Signals are 1-based to match POSIX `signal(7)`. Bit `n` of a
//! [`SignalSet`]/[`SignalMask`] corresponds to signal number `n`; bit 0 is
//! unused (there is no signal 0 — POSIX reserves it for "signal 0 == probe").
//! The standard set is `1..=NSIG_STANDARD` (31); real-time signals occupy
//! `RT_MIN..=RT_MAX` (32..=63). The whole range fits in one `u64`, so a
//! signal set is a single word — atomic, copyable, and allocation-free.

use core::mem::size_of;
use core::slice;

pub use xenith_abi::SignalFrame;

use crate::arch::x86_64::gdt;
use crate::arch::x86_64::interrupts::exceptions::ExceptionContext;
use crate::sync::{SpinLock, SpinLockIRQ, SpinLockIRQGuard};

// ---------------------------------------------------------------------------
// Numbering constants
// ---------------------------------------------------------------------------

/// Highest standard (non-real-time) signal number. Matches POSIX's fixed
/// 1..=31 range; numbers above this are real-time signals.
pub const NSIG_STANDARD: u32 = 31;

/// Lowest real-time signal number. Unlike standard signals, every real-time
/// delivery retains its own queued [`xenith_abi::SigInfo`] payload.
pub const RT_MIN: u32 = 32;

/// Highest real-time signal number. The full 1..=63 range occupies bits 1..63
/// of a `u64`; bit 0 is reserved for "no signal".
pub const RT_MAX: u32 = 63;

/// Total number of signals the kernel tracks, inclusive: 1..=63.
pub const NSIG: u32 = RT_MAX;

/// Number of distinct real-time signal numbers.
const RT_COUNT: usize = (RT_MAX - RT_MIN + 1) as usize;

/// Hard per-process limit across all pending real-time signal deliveries.
///
/// The queue is embedded in [`SignalState`], so delivery remains allocation
/// free and safe from interrupt context. Standard signals do not consume this
/// capacity because they retain their existing one-bit coalescing semantics.
pub const REALTIME_QUEUE_CAPACITY: usize = RT_COUNT * 4;

/// The syscall number the signal trampoline issues to request
/// [`sigreturn`]. This is derived from the canonical shared ABI enum so the
/// mapped trampoline, kernel table, and userspace wrappers cannot drift.
pub const SIGRETURN_SYSCALL_NR: u32 = xenith_abi::SyscallNumber::Sigreturn as u32;

/// The RPL bits of a segment selector occupy the low two bits. `cs & RPL_MASK
/// == 3` means the interrupted context was running in ring 3 (user mode), and
/// is therefore a candidate for signal delivery.
const RPL_MASK: u64 = 0x3;

/// The trap flag (TF, bit 8 of RFLAGS). We clear it on entry to a handler so
/// single-step does not re-fire inside the handler; the saved frame preserves
/// the original TF so [`sigreturn`] restores it.
const RFLAGS_TF: u64 = 1 << 8;

/// The interrupt-enable flag (IF, bit 9 of RFLAGS). User space always runs
/// with IF set; the handler frame we build inherits this so `iretq` re-enters
/// user mode with interrupts enabled.
const RFLAGS_IF: u64 = 1 << 9;

const EMPTY_SIGINFO: xenith_abi::SigInfo = xenith_abi::SigInfo {
    signo: 0,
    code: 0,
    errno: 0,
    trapno: 0,
    address: 0,
    sender_pid: 0,
    sender_uid: 0,
    status: 0,
    value: 0,
    reserved: 0,
};

// ---------------------------------------------------------------------------
// Signal enum
// ---------------------------------------------------------------------------

/// A signal number, named after its POSIX mnemonic.
///
/// The `repr(u32)` keeps the discriminant a full word so `as u32` is free and
/// the value is exactly the POSIX signal number (1-based). `from_number` is
/// the safe inverse and rejects 0 and numbers above [`RT_MAX`].
///
/// Real-time signals are represented by [`Signal::Rt`] carrying the offset
/// from [`RT_MIN`]; this keeps the enum small while still distinguishing every
/// real-time number. Use [`Signal::as_number`] / [`Signal::from_number`] to
/// cross the number boundary.
#[repr(u32)]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Signal {
    /// SIGHUP — hangup detected on controlling terminal.
    Hup = 1,
    /// SIGINT — interrupt from keyboard (Ctrl-C).
    Int = 2,
    /// SIGQUIT — quit from keyboard (Ctrl-\), produces a core dump.
    Quit = 3,
    /// SIGILL — illegal instruction.
    Ill = 4,
    /// SIGTRAP — trace/breakpoint trap.
    Trap = 5,
    /// SIGABRT — abort from `abort()`.
    Abrt = 6,
    /// SIGBUS — bus error (bad memory access alignment/object).
    Bus = 7,
    /// SIGFPE — floating-point exception (div-by-zero, overflow).
    Fpe = 8,
    /// SIGKILL — kill (cannot be caught, blocked, or ignored).
    Kill = 9,
    /// SIGUSR1 — user-defined signal 1.
    Usr1 = 10,
    /// SIGSEGV — invalid memory reference (segmentation fault).
    Segv = 11,
    /// SIGUSR2 — user-defined signal 2.
    Usr2 = 12,
    /// SIGPIPE — write to a pipe with no readers.
    Pipe = 13,
    /// SIGALRM — timer alarm from `alarm()`.
    Alrm = 14,
    /// SIGTERM — termination signal (the polite `kill`).
    Term = 15,
    /// SIGCHLD — child process stopped or terminated.
    Chld = 17,
    /// SIGCONT — continue if stopped.
    Cont = 18,
    /// SIGSTOP — stop (cannot be caught, blocked, or ignored).
    Stop = 19,
    /// SIGTSTP — stop typed at terminal (Ctrl-Z).
    Tstp = 20,
    /// SIGTTIN — background read from controlling terminal.
    Ttin = 21,
    /// SIGTTOU — background write to controlling terminal.
    Ttou = 22,
    /// A real-time signal. The payload is the *offset* from [`RT_MIN`], so
    /// `Rt(0)` is signal number 32, `Rt(1)` is 33, and so on up to
    /// `Rt(RT_COUNT - 1)` which is 63.
    Rt(u32),
}

impl Signal {
    /// The POSIX signal number (1-based) for this signal.
    ///
    /// Real-time signals compute `RT_MIN + offset`; standard signals use their
    /// discriminant directly. The result is always in `1..=RT_MAX`.
    #[inline]
    #[must_use]
    pub const fn as_number(self) -> u32 {
        match self {
            // The explicit discriminants above are the signal numbers; `as u32`
            // on a `repr(u32)` enum is a no-op at runtime.
            Signal::Hup => 1,
            Signal::Int => 2,
            Signal::Quit => 3,
            Signal::Ill => 4,
            Signal::Trap => 5,
            Signal::Abrt => 6,
            Signal::Bus => 7,
            Signal::Fpe => 8,
            Signal::Kill => 9,
            Signal::Usr1 => 10,
            Signal::Segv => 11,
            Signal::Usr2 => 12,
            Signal::Pipe => 13,
            Signal::Alrm => 14,
            Signal::Term => 15,
            Signal::Chld => 17,
            Signal::Cont => 18,
            Signal::Stop => 19,
            Signal::Tstp => 20,
            Signal::Ttin => 21,
            Signal::Ttou => 22,
            Signal::Rt(off) => RT_MIN + off,
        }
    }

    /// Recover a [`Signal`] from its POSIX number.
    ///
    /// Returns `None` for `0` (the POSIX "no signal" sentinel) and for numbers
    /// above [`RT_MAX`]. The standard numbers 16 (SIGSTKFLT) and the gap
    /// between 15 and 17 are not modelled as named variants; they round-trip
    /// as real-time-equivalent `Rt` entries only if they fall in the real-time
    /// range, otherwise they are rejected. In practice the only unmodelled
    /// standard slot is 16, which Xenith treats as reserved (returns `None`).
    #[inline]
    #[must_use]
    pub const fn from_number(n: u32) -> Option<Self> {
        match n {
            0 => None,
            1 => Some(Signal::Hup),
            2 => Some(Signal::Int),
            3 => Some(Signal::Quit),
            4 => Some(Signal::Ill),
            5 => Some(Signal::Trap),
            6 => Some(Signal::Abrt),
            7 => Some(Signal::Bus),
            8 => Some(Signal::Fpe),
            9 => Some(Signal::Kill),
            10 => Some(Signal::Usr1),
            11 => Some(Signal::Segv),
            12 => Some(Signal::Usr2),
            13 => Some(Signal::Pipe),
            14 => Some(Signal::Alrm),
            15 => Some(Signal::Term),
            17 => Some(Signal::Chld),
            18 => Some(Signal::Cont),
            19 => Some(Signal::Stop),
            20 => Some(Signal::Tstp),
            21 => Some(Signal::Ttin),
            22 => Some(Signal::Ttou),
            32..=RT_MAX => Some(Signal::Rt(n - RT_MIN)),
            // 16 (SIGSTKFLT) and 23..=31 are unmodelled standard slots; the
            // kernel does not deliver them, so they do not round-trip.
            _ => None,
        }
    }

    /// `true` for real-time signals ([`RT_MIN`]..=[`RT_MAX`]).
    #[inline]
    #[must_use]
    pub const fn is_realtime(self) -> bool {
        matches!(self, Signal::Rt(_))
    }

    /// The two signals that POSIX forbids catching, blocking, or ignoring.
    /// [`deliver_signal`] and [`check_and_dispatch`] bypass dispositions for
    /// these so a process can never install a handler for its own death.
    #[inline]
    #[must_use]
    pub const fn is_uncatchable(self) -> bool {
        matches!(self, Signal::Kill | Signal::Stop)
    }

    /// The default action taken when no handler is installed. See
    /// [`DefaultAction`] for the policy.
    #[inline]
    #[must_use]
    pub const fn default_action(self) -> DefaultAction {
        match self {
            Signal::Kill
            | Signal::Term
            | Signal::Hup
            | Signal::Int
            | Signal::Alrm
            | Signal::Pipe
            | Signal::Usr1
            | Signal::Usr2 => DefaultAction::Terminate,
            Signal::Quit
            | Signal::Ill
            | Signal::Trap
            | Signal::Abrt
            | Signal::Bus
            | Signal::Fpe
            | Signal::Segv => DefaultAction::TerminateCoreDump,
            Signal::Chld => DefaultAction::Ignore,
            Signal::Cont => DefaultAction::Continue,
            Signal::Stop | Signal::Tstp | Signal::Ttin | Signal::Ttou => DefaultAction::Stop,
            Signal::Rt(_) => DefaultAction::Terminate,
        }
    }
}

// ---------------------------------------------------------------------------
// Default action
// ---------------------------------------------------------------------------

/// What the kernel does with a signal that has no user-installed handler.
///
/// `Terminate` and `TerminateCoreDump` both end the process; the core-dump
/// variant additionally records a crash dump (once the `fs`/`user` core dump
/// path exists). `Stop` parks the process until a `SIGCONT`; `Continue`
/// resumes a stopped process and is otherwise a no-op. `Ignore` clears the
/// pending bit and returns to user code.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DefaultAction {
    /// End the process. No core dump.
    Terminate,
    /// End the process and produce a core dump.
    TerminateCoreDump,
    /// Discard the signal; resume user code.
    Ignore,
    /// Stop the process until a `SIGCONT`.
    Stop,
    /// Resume the process if stopped; otherwise discard.
    Continue,
}

// ---------------------------------------------------------------------------
// Signal set and mask
// ---------------------------------------------------------------------------

/// A 64-bit set of signal numbers, used for the pending set.
///
/// Bit `n` (1-based signal number) corresponds to the mask `1u64 << n`. Bit 0
/// is unused. The type is a distinct newtype from [`SignalMask`] so the
/// pending set and the blocked mask cannot be accidentally swapped at a call
/// site — they share representation but not semantics.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
#[repr(transparent)]
pub struct SignalSet(u64);

impl SignalSet {
    /// An empty set (no signals pending).
    #[inline]
    #[must_use]
    pub const fn empty() -> Self {
        Self(0)
    }

    /// Build a set containing exactly `sig`.
    #[inline]
    #[must_use]
    pub const fn from_signal(sig: Signal) -> Self {
        Self(1u64 << sig.as_number())
    }

    /// Add `sig` to the set. Idempotent: adding a signal already present is a
    /// no-op. Returns the previous membership state so callers (notably
    /// [`deliver_signal`]) can detect a first delivery for standard signals.
    #[inline]
    pub fn add(&mut self, sig: Signal) -> bool {
        let bit = 1u64 << sig.as_number();
        let was = (self.0 & bit) != 0;
        self.0 |= bit;
        was
    }

    /// Remove `sig` from the set.
    #[inline]
    pub fn remove(&mut self, sig: Signal) {
        self.0 &= !(1u64 << sig.as_number());
    }

    /// `true` if `sig` is in the set.
    #[inline]
    #[must_use]
    pub const fn contains(&self, sig: Signal) -> bool {
        (self.0 & (1u64 << sig.as_number())) != 0
    }

    /// `true` if no signal is in the set.
    #[inline]
    #[must_use]
    pub const fn is_empty(&self) -> bool {
        self.0 == 0
    }

    /// Remove and return the lowest-numbered signal in the set, or `None` if
    /// empty. Lowest-first matches POSIX delivery order: standard signals are
    /// delivered before real-time signals, and within each range by number.
    ///
    /// Bits that correspond to unmodelled signal numbers (e.g. 16) are
    /// cleared and skipped: they can never be introduced through the public
    /// API (there is no `from_bits` constructor and `add` only accepts a
    /// validated [`Signal`]), but the function stays correct under any input
    /// rather than stranding higher-numbered real signals behind a dead bit.
    pub fn pop_lowest(&mut self) -> Option<Signal> {
        loop {
            if self.0 == 0 {
                return None;
            }
            // `trailing_zeros` on the mask gives the 0-based bit index, which
            // is exactly the 1-based signal number (bit 0 is unused). `1 << 0`
            // would correspond to signal 0, which `from_number` rejects — but
            // bit 0 is never set because no `add` call ever sets it (all
            // signal numbers are >= 1), so `trailing_zeros` here is always
            // >= 1 for a non-zero mask.
            let n = self.0.trailing_zeros();
            // Clear the bit regardless: either we return the signal, or it is
            // an unmodelled slot we want to drop so the next iteration can
            // reach a higher, modelled signal.
            self.0 &= !(1u64 << n);
            if let Some(sig) = Signal::from_number(n) {
                return Some(sig);
            }
            // Unmodelled slot — loop and try the next-lowest set bit.
        }
    }

    /// Mask off every signal in `other` (set intersection with the complement
    /// of `other`). Used to drop blocked signals from the pending set when
    /// selecting a deliverable signal.
    #[inline]
    pub fn difference(&mut self, other: SignalMask) {
        self.0 &= !other.0;
    }

    /// The raw bitmask. Exposed for the trampoline/sigreturn path and for
    /// diagnostics; callers should prefer the named helpers above.
    #[inline]
    #[must_use]
    pub const fn bits(self) -> u64 {
        self.0
    }
}

/// The blocked-signal mask. Same representation as [`SignalSet`] but a
/// distinct type: a signal in the mask is *not delivered* until unblocked
/// (except for [`Signal::Kill`] and [`Signal::Stop`], which are always
/// deliverable). See [`SignalSet`] for the bit layout.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
#[repr(transparent)]
pub struct SignalMask(u64);

impl SignalMask {
    /// An empty mask (no signals blocked).
    #[inline]
    #[must_use]
    pub const fn empty() -> Self {
        Self(0)
    }

    /// Build a mask from the userspace bit representation while enforcing
    /// the POSIX rule that `SIGKILL` and `SIGSTOP` can never be blocked.
    #[inline]
    #[must_use]
    pub const fn from_bits_sanitized(bits: u64) -> Self {
        let unmaskable = (1u64 << Signal::Kill.as_number()) | (1u64 << Signal::Stop.as_number());
        Self((bits & !1) & !unmaskable)
    }

    /// Block `sig`.
    #[inline]
    pub fn block(&mut self, sig: Signal) {
        self.0 |= 1u64 << sig.as_number();
    }

    /// Unblock `sig`.
    #[inline]
    pub fn unblock(&mut self, sig: Signal) {
        self.0 &= !(1u64 << sig.as_number());
    }

    /// `true` if `sig` is blocked. [`check_and_dispatch`] treats a blocked
    /// standard signal as not-yet-deliverable; [`Signal::Kill`] and
    /// [`Signal::Stop`] bypass this check.
    #[inline]
    #[must_use]
    pub const fn is_blocked(&self, sig: Signal) -> bool {
        (self.0 & (1u64 << sig.as_number())) != 0
    }

    /// The raw bitmask.
    #[inline]
    #[must_use]
    pub const fn bits(self) -> u64 {
        self.0
    }

    /// Return the union of this mask and `other`.
    #[inline]
    #[must_use]
    pub const fn union(self, other: Self) -> Self {
        Self::from_bits_sanitized(self.0 | other.0)
    }

    /// Return this mask with all bits in `other` removed.
    #[inline]
    #[must_use]
    pub const fn without(self, other: Self) -> Self {
        Self::from_bits_sanitized(self.0 & !other.0)
    }
}

// ---------------------------------------------------------------------------
// Dispositions
// ---------------------------------------------------------------------------

/// What a process does with a delivered signal.
///
/// `Default` falls back to [`Signal::default_action`]; `Ignore` discards the
/// signal; `Catch` enters a user-space handler. `SIGKILL` and `SIGSTOP` are
/// always handled as `Default` regardless of what the process installs —
/// [`set_handler`] enforces this, and [`check_and_dispatch`] re-checks it on
/// delivery so a stale disposition can never let a process catch its own
/// termination.
#[derive(Debug, Clone, Copy, Eq, PartialEq)]
pub enum SignalAction {
    /// Apply the POSIX default action for this signal.
    Default,
    /// Discard the signal; do nothing.
    Ignore,
    /// Enter the user-space handler at `entry`. While the handler runs, the
    /// signals in `mask` are added to the blocked set (POSIX `sa_mask`);
    /// `flags` carries the `SA_*` flag bits the handler requested. The
    /// handler's return address is the signal trampoline.
    Catch {
        /// User-space virtual address of the handler entry point.
        entry: u64,
        /// Additional signals to block while the handler runs.
        mask: SignalMask,
        /// Flag bits. `SA_NODEFER` and `SA_RESETHAND` are enforced by the
        /// delivery path; `SA_RESTART` is retained for blocking-I/O policy.
        flags: u64,
    },
}

impl Default for SignalAction {
    #[inline]
    fn default() -> Self {
        Self::Default
    }
}

// ---------------------------------------------------------------------------
// Per-process signal state
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Copy, Default, Eq, PartialEq)]
struct AltStack {
    sp: u64,
    size: u64,
}

impl AltStack {
    #[inline]
    const fn enabled(self) -> bool {
        self.size != 0
    }

    #[inline]
    fn contains(self, rsp: u64) -> bool {
        self.enabled()
            && self
                .sp
                .checked_add(self.size)
                .is_some_and(|end| rsp >= self.sp && rsp < end)
    }

    fn wire(self, current_rsp: u64) -> xenith_abi::SigAltStack {
        xenith_abi::SigAltStack {
            sp: self.sp,
            size: self.size,
            flags: if !self.enabled() {
                xenith_abi::SS_DISABLE
            } else if self.contains(current_rsp) {
                xenith_abi::SS_ONSTACK
            } else {
                0
            },
            reserved: 0,
        }
    }
}

/// Validation failure returned by [`SignalState::sigaltstack`].
#[derive(Debug, Clone, Copy, Eq, PartialEq)]
pub enum AltStackError {
    /// Only zero and `SS_DISABLE` are accepted on install.
    InvalidFlags,
    /// The requested range was non-canonical, overflowed, or outside bounds.
    InvalidRange,
    /// POSIX forbids replacing/disabling the alternate stack while using it.
    AlreadyOnStack,
}

/// The per-process signal state.
///
/// Embedded in each `UserProcess` by composition. Three pieces of state are
/// kept here:
///
/// * `pending` — the set of signals that have been delivered to the process
///   but not yet dispatched to a handler or default action. IRQ-safe lock:
///   [`deliver_signal`] runs in interrupt context (timer, IPI, cross-CPU
///   `kill`).
/// * `blocked` — the signal mask the process has installed with `sigprocmask`.
///   IRQ-safe for the same reason: a signal may be delivered and checked on
///   different CPUs.
/// * `dispositions` — one [`SignalAction`] per signal number, indexed by
///   `signal_number - 1`. Guarded by a plain [`SpinLock`] because dispositions
///   are only ever touched in process context via the `sigaction` syscall.
/// * The bounded real-time queue lives under `pending`, so every accepted
///   delivery retains its own payload and enqueue/select/consume are atomic
///   with respect to one another.
///
/// The lock splitting (three locks) keeps the hot delivery path — take
/// `pending`, set a bit, release — from contending with `sigaction` calls
/// that only touch `dispositions`.
pub struct SignalState {
    /// Pending standard-signal set + bounded real-time queue, taken together
    /// under one IRQ-safe lock.
    pending: SpinLockIRQ<PendingState>,
    /// The blocked-signal mask.
    blocked: SpinLockIRQ<SignalMask>,
    /// One disposition per signal number, index `n - 1`.
    dispositions: SpinLock<[SignalAction; NSIG as usize]>,
    /// Alternate signal stack. Xenith currently schedules one userspace
    /// thread per process, so this process-owned slot is also the calling
    /// thread's slot; fork copies it and exec disables it.
    alt_stack: SpinLock<AltStack>,
}

/// One queued real-time delivery and its stable payload.
#[derive(Debug, Clone, Copy)]
struct RealtimePending {
    signal: Signal,
    info: xenith_abi::SigInfo,
}

/// Internal pending state, guarded as one unit so real-time enqueue, selection,
/// and consumption are atomic with respect to concurrent dispatch.
#[derive(Debug)]
struct PendingState {
    /// The pending bitmask.
    set: SignalSet,
    /// Arrival-ordered real-time deliveries. Selection still prioritizes the
    /// lowest deliverable signal number, then the oldest matching entry.
    realtime: [Option<RealtimePending>; REALTIME_QUEUE_CAPACITY],
    /// Number of occupied entries at the start of `realtime`.
    realtime_len: usize,
    /// Stable first payload retained for each coalesced standard signal.
    standard_info: [xenith_abi::SigInfo; NSIG as usize],
}

impl Default for PendingState {
    fn default() -> Self {
        Self {
            set: SignalSet::empty(),
            realtime: [None; REALTIME_QUEUE_CAPACITY],
            realtime_len: 0,
            standard_info: [EMPTY_SIGINFO; NSIG as usize],
        }
    }
}

impl PendingState {
    /// Append one real-time delivery, returning its per-signal queue depth.
    fn enqueue_realtime(
        &mut self,
        signal: Signal,
        info: xenith_abi::SigInfo,
    ) -> Option<u16> {
        debug_assert!(signal.is_realtime());
        if self.realtime_len == REALTIME_QUEUE_CAPACITY {
            return None;
        }

        let count = self.realtime[..self.realtime_len]
            .iter()
            .flatten()
            .filter(|pending| pending.signal == signal)
            .count()
            + 1;
        self.realtime[self.realtime_len] = Some(RealtimePending { signal, info });
        self.realtime_len += 1;
        self.set.add(signal);
        Some(count as u16)
    }

    /// Oldest queued payload for one real-time signal.
    fn first_realtime_info(&self, signal: Signal) -> Option<xenith_abi::SigInfo> {
        self.realtime[..self.realtime_len]
            .iter()
            .flatten()
            .find(|pending| pending.signal == signal)
            .map(|pending| pending.info)
    }

    /// Remove the oldest queued instance of one real-time signal.
    fn consume_realtime(&mut self, signal: Signal) {
        let Some(remove_at) = self.realtime[..self.realtime_len]
            .iter()
            .position(|entry| entry.is_some_and(|pending| pending.signal == signal))
        else {
            debug_assert!(false, "pending real-time bit has no queued payload");
            self.set.remove(signal);
            return;
        };

        for index in remove_at..self.realtime_len - 1 {
            self.realtime[index] = self.realtime[index + 1];
        }
        self.realtime_len -= 1;
        self.realtime[self.realtime_len] = None;
        if !self.realtime[..self.realtime_len]
            .iter()
            .flatten()
            .any(|pending| pending.signal == signal)
        {
            self.set.remove(signal);
        }
    }
}

impl SignalState {
    /// Construct a fresh signal state: nothing pending, nothing blocked, all
    /// dispositions `Default`. `const`-friendly enough to build at compile
    /// time for a static idle-process if needed.
    #[must_use]
    pub const fn new() -> Self {
        Self {
            pending: SpinLockIRQ::new(PendingState {
                set: SignalSet::empty(),
                realtime: [None; REALTIME_QUEUE_CAPACITY],
                realtime_len: 0,
                standard_info: [EMPTY_SIGINFO; NSIG as usize],
            }),
            blocked: SpinLockIRQ::new(SignalMask::empty()),
            dispositions: SpinLock::new([SignalAction::Default; NSIG as usize]),
            alt_stack: SpinLock::new(AltStack { sp: 0, size: 0 }),
        }
    }

    /// Install a handler disposition for `sig`. Refuses to install `Catch` or
    /// `Ignore` for [`Signal::Kill`] / [`Signal::Stop`] (POSIX mandates these
    /// always use the default action); returns `false` in that case so the
    /// caller (`sigaction` syscall) can return `EINVAL`.
    pub fn set_handler(&self, sig: Signal, action: SignalAction) -> bool {
        if sig.is_uncatchable() && !matches!(action, SignalAction::Default) {
            return false;
        }
        let idx = (sig.as_number() - 1) as usize;
        self.dispositions.lock()[idx] = action;
        true
    }

    /// Read the current disposition for `sig`.
    pub fn disposition(&self, sig: Signal) -> SignalAction {
        let idx = (sig.as_number() - 1) as usize;
        self.dispositions.lock()[idx]
    }

    /// Replace the blocked mask wholesale (the `sigprocmask` `SIG_SETMASK`
    /// op). Returns the previous mask so the caller can save/restore.
    pub fn set_blocked(&self, mask: SignalMask) -> SignalMask {
        let mut g = self.blocked.lock();
        let prev = *g;
        *g = mask;
        prev
    }

    /// Atomically read the current blocked mask.
    pub fn blocked_mask(&self) -> SignalMask {
        *self.blocked.lock()
    }

    /// Install/disable/query the alternate stack for the calling userspace
    /// thread. The old value is always computed before a successful update.
    pub fn sigaltstack(
        &self,
        current_rsp: u64,
        new: Option<xenith_abi::SigAltStack>,
    ) -> Result<xenith_abi::SigAltStack, AltStackError> {
        let mut slot = self.alt_stack.lock();
        let old = slot.wire(current_rsp);
        let Some(request) = new else { return Ok(old) };
        if slot.contains(current_rsp) {
            return Err(AltStackError::AlreadyOnStack);
        }
        if request.reserved != 0
            || request.flags & !(xenith_abi::SS_DISABLE) != 0
            || request.flags == xenith_abi::SS_ONSTACK
        {
            return Err(AltStackError::InvalidFlags);
        }
        if request.flags & xenith_abi::SS_DISABLE != 0 {
            *slot = AltStack::default();
            return Ok(old);
        }
        if request.size < xenith_abi::MINSIGSTKSZ
            || request.size > xenith_abi::MAXSIGSTKSZ
            || request.sp == 0
            || request.sp > crate::mm::r#virtual::USER_MAX
            || request
                .sp
                .checked_add(request.size)
                .is_none_or(|end| end == 0 || end - 1 > crate::mm::r#virtual::USER_MAX)
        {
            return Err(AltStackError::InvalidRange);
        }
        *slot = AltStack {
            sp: request.sp,
            size: request.size,
        };
        Ok(old)
    }

    /// Snapshot the state inherited across `fork`: dispositions and the
    /// blocked mask are copied, while pending deliveries start empty in the
    /// child as required by process creation semantics.
    #[must_use]
    pub fn clone_for_fork(&self) -> Self {
        let state = Self::new();
        *state.blocked.lock() = *self.blocked.lock();
        *state.dispositions.lock() = *self.dispositions.lock();
        *state.alt_stack.lock() = *self.alt_stack.lock();
        state
    }

    /// Build the signal state for a successful `exec`. The blocked mask,
    /// pending deliveries, and ignored dispositions survive; caught handlers
    /// are reset because their code addresses belonged to the old image.
    #[must_use]
    pub fn clone_for_exec(&self) -> Self {
        let state = Self::new();
        *state.blocked.lock() = *self.blocked.lock();
        {
            let old_pending = self.pending.lock();
            let mut new_pending = state.pending.lock();
            new_pending.set = old_pending.set;
            new_pending.realtime = old_pending.realtime;
            new_pending.realtime_len = old_pending.realtime_len;
            new_pending.standard_info = old_pending.standard_info;
        }
        let old = self.dispositions.lock();
        let mut new = state.dispositions.lock();
        for (destination, source) in new.iter_mut().zip(old.iter()) {
            if matches!(source, SignalAction::Ignore) {
                *destination = SignalAction::Ignore;
            }
        }
        drop(new);
        drop(old);
        state
    }
}

impl Default for SignalState {
    #[inline]
    fn default() -> Self {
        Self::new()
    }
}

// ---------------------------------------------------------------------------
// Delivery: mark a signal pending
// ---------------------------------------------------------------------------

/// Result of [`deliver_signal`]: whether delivery was accepted, coalesced, or
/// rejected because the bounded real-time queue was full.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DeliverOutcome {
    /// A standard signal was newly marked pending (bit was previously clear).
    NewlyPending,
    /// A standard signal was already pending; the second delivery is a no-op
    /// (POSIX coalesces standard signals).
    AlreadyPending,
    /// A real-time delivery and its payload were queued. `count` is the queue
    /// depth for this signal number after the enqueue.
    RealtimeQueued {
        /// Per-signal queue depth after this delivery.
        count: u16,
    },
    /// The process-wide real-time queue was already full. No pending state or
    /// payload was changed.
    RealtimeQueueFull {
        /// The fixed process-wide queue capacity.
        capacity: usize,
    },
    /// `sig` was out of range or otherwise not recorded.
    Invalid,
}

/// Mark `sig` as pending for the process whose state is `state`.
///
/// This is the kernel-internal half of `kill` / `raise` / `tgkill` and of
/// timer- and fault-driven signals. It does **not** dispatch the signal: it
/// only records that the signal is pending. Dispatch happens on the next
/// return-to-user via [`check_and_dispatch`]. Delivering a signal that the
/// process has blocked is legal — the bit is set; the signal simply waits in
/// `pending` until unblocked.
///
/// Real-time signals preserve one payload per delivery up to
/// [`REALTIME_QUEUE_CAPACITY`] total entries per process. Standard signals
/// coalesce. [`Signal::Kill`] and [`Signal::Stop`] are always recorded even if
/// blocked — their default action is unblockable.
///
/// # Safety of calling context
///
/// Safe to call from interrupt context: the pending state is under an
/// IRQ-safe spinlock, and the function performs no allocation and touches no
/// per-CPU state beyond the lock.
pub fn deliver_signal(state: &SignalState, sig: Signal) -> DeliverOutcome {
    deliver_signal_with_info(state, sig, xenith_abi::SigInfo {
        signo: sig.as_number(),
        code: xenith_abi::SI_KERNEL,
        ..EMPTY_SIGINFO
    })
}

/// Mark `sig` pending together with a stable source/fault payload. Standard
/// signals retain the first payload until dispatch; real-time signals retain
/// every accepted payload in arrival order.
pub fn deliver_signal_with_info(
    state: &SignalState,
    sig: Signal,
    mut info: xenith_abi::SigInfo,
) -> DeliverOutcome {
    let mut g = state.pending.lock();
    info.signo = sig.as_number();
    info.reserved = 0;

    if sig.is_realtime() {
        match g.enqueue_realtime(sig, info) {
            Some(count) => DeliverOutcome::RealtimeQueued { count },
            None => DeliverOutcome::RealtimeQueueFull {
                capacity: REALTIME_QUEUE_CAPACITY,
            },
        }
    } else {
        let was = g.set.add(sig);
        if was {
            DeliverOutcome::AlreadyPending
        } else {
            g.standard_info[(sig.as_number() - 1) as usize] = info;
            DeliverOutcome::NewlyPending
        }
    }
}

// ---------------------------------------------------------------------------
// Dispatch: on return-to-user, pick and enter a handler
// ---------------------------------------------------------------------------

/// What [`check_and_dispatch`] did (or did not) do.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DispatchOutcome {
    /// No deliverable signal was pending; the trap frame is unchanged and
    /// `iretq` resumes the interrupted user code.
    NothingDeliverable,
    /// A signal was delivered and the trap frame was rewritten to enter a
    /// user handler. `iretq` will run the handler; the original frame is on
    /// the user stack and will be restored by [`sigreturn`].
    HandlerEntered(Signal),
    /// A signal's default action was taken. `Terminated` means the caller
    /// must now destroy the process; `Stopped` means park it; `Ignored`
    /// means the pending bit was cleared and execution continues.
    DefaultActionTaken {
        /// Which signal.
        sig: Signal,
        /// Which default action was applied.
        action: DefaultAction,
    },
    /// The interrupted context was not user mode (kernel context), so no
    /// signal dispatch was attempted. Signals remain pending and will be
    /// dispatched at the next return-to-user.
    KernelContext,
}

/// Exact syscall image that may be replayed after a caught signal returns.
/// The architecture entry path supplies this only for a blocking operation
/// that returned `EINTR` before transferring any data.
#[derive(Debug, Clone, Copy, Eq, PartialEq)]
pub struct RestartContext {
    pub syscall_number: u64,
    pub syscall_ip: u64,
}

/// Pick the highest-priority deliverable signal from `pending`, honouring the
/// blocked mask and the uncatchable-signal rules.
///
/// Returns the signal and a guard on the pending state so the caller can
/// atomically clear it / decrement its count after deciding what to do. The
/// caller drops the guard once the frame is built or the default action is
/// recorded.
fn select_deliverable<'a>(
    state: &'a SignalState,
) -> Option<(
    Signal,
    xenith_abi::SigInfo,
    SpinLockIRQGuard<'a, PendingState>,
)> {
    let blocked = *state.blocked.lock();
    let g = state.pending.lock();

    // Standard signals first (low numbers), then real-time. `pop_lowest`
    // already walks in numeric order; we just skip blocked signals that are
    // not uncatchable. We cannot pop-then-restore cleanly because popping
    // mutates the count, so instead we scan bits without consuming.
    let mut scan = g.set;
    while let Some(sig) = scan.pop_lowest() {
        let deliverable = sig.is_uncatchable() || !blocked.is_blocked(sig);
        if deliverable {
            // Found one. Do *not* consume yet — the caller may need to back
            // out if the disposition is `Ignore` and we want to clear rather
            // than re-pend. We hand back the guard; the caller consumes via
            // `consume_delivered`.
            let info = if sig.is_realtime() {
                let Some(info) = g.first_realtime_info(sig) else {
                    debug_assert!(false, "pending real-time bit has no queued payload");
                    continue;
                };
                info
            } else {
                g.standard_info[(sig.as_number() - 1) as usize]
            };
            return Some((sig, info, g));
        }
    }
    None
}

/// Consume one instance of `sig` from the pending state held by `guard`.
fn consume_delivered(guard: &mut SpinLockIRQGuard<'_, PendingState>, sig: Signal) {
    if sig.is_realtime() {
        guard.consume_realtime(sig);
    } else {
        guard.set.remove(sig);
        guard.standard_info[(sig.as_number() - 1) as usize] = EMPTY_SIGINFO;
    }
}

/// Entry point called from the return-to-user path with the interrupted
/// register frame.
///
/// If the interrupted context was user mode (`cs & RPL_MASK == 3`) and a
/// non-blocked signal is pending, this either rewrites `ctx` to enter a
/// user-space handler ([`DispatchOutcome::HandlerEntered`]) or applies the
/// signal's default action ([`DispatchOutcome::DefaultActionTaken`]). If no
/// signal is deliverable, or the interrupted context was kernel mode, the
/// frame is left untouched.
///
/// The caller (the interrupt trampoline's return path) must invoke this on
/// every return to user space, with interrupts disabled and a borrow on the
/// current process's [`SignalState`]. The function is idempotent: calling it
/// when nothing is pending is cheap (one blocked-mask read + one pending-set
/// check) and leaves the frame unchanged.
pub fn check_and_dispatch(state: &SignalState, ctx: &mut ExceptionContext) -> DispatchOutcome {
    check_and_dispatch_with_restart(state, ctx, None)
}

/// Signal dispatch variant used by syscall return when a proven-safe restart
/// image is available. `SA_RESTART` is ignored for every other path.
pub fn check_and_dispatch_with_restart(
    state: &SignalState,
    ctx: &mut ExceptionContext,
    restart: Option<RestartContext>,
) -> DispatchOutcome {
    // Only deliver on the kernel-to-user transition. A signal raised while
    // in kernel mode stays pending until the next return-to-user.
    if (ctx.cs & RPL_MASK) != 3 {
        return DispatchOutcome::KernelContext;
    }

    let (sig, info, mut pend) = match select_deliverable(state) {
        Some(x) => x,
        None => return DispatchOutcome::NothingDeliverable,
    };

    let disposition = state.disposition(sig);

    // SIGKILL/SIGSTOP always use the default action even if a stale `Catch`
    // disposition is installed.
    let effective = if sig.is_uncatchable() {
        SignalAction::Default
    } else {
        disposition
    };

    match effective {
        SignalAction::Ignore => {
            // Discard and continue. Consume so an ignored signal does not
            // busy-loop the dispatch path.
            consume_delivered(&mut pend, sig);
            drop(pend);
            DispatchOutcome::DefaultActionTaken {
                sig,
                action: DefaultAction::Ignore,
            }
        },
        SignalAction::Default => {
            let action = sig.default_action();
            // For Terminate/Stop the caller destroys/parks the process, so
            // consuming the bit is moot, but consuming keeps the pending set
            // honest if a future resurrection path inspects it.
            consume_delivered(&mut pend, sig);
            drop(pend);
            DispatchOutcome::DefaultActionTaken { sig, action }
        },
        SignalAction::Catch { entry, mask, flags } => {
            // Build the on-user-stack frame, then rewrite the trap frame to
            // enter the handler. Failure to write the frame (bad user stack)
            // falls back to the default action — a process with a broken
            // stack gets SIGSEGV semantics, not a kernel panic.
            let restart = (flags & xenith_abi::SA_RESTART != 0)
                .then_some(restart)
                .flatten();
            match build_signal_frame(state, ctx, sig, info, mask, flags, restart) {
                Ok(()) => {
                    consume_delivered(&mut pend, sig);
                    drop(pend);
                    if flags & xenith_abi::SA_RESETHAND != 0 {
                        let _ = state.set_handler(sig, SignalAction::Default);
                    }
                    ctx.rip = entry;
                    // Clear TF so the handler does not single-step immediately;
                    // IF stays set so user mode runs with interrupts enabled.
                    ctx.rflags &= !RFLAGS_TF;
                    ctx.rflags |= RFLAGS_IF;
                    DispatchOutcome::HandlerEntered(sig)
                },
                Err(frame_err) => {
                    ::log::warn!(
                        "signal: frame build for {} failed ({:?}); falling back to default",
                        sig.as_number(),
                        frame_err
                    );
                    consume_delivered(&mut pend, sig);
                    drop(pend);
                    let action = sig.default_action();
                    DispatchOutcome::DefaultActionTaken { sig, action }
                },
            }
        },
    }
}

// ---------------------------------------------------------------------------
// The signal frame and the user-stack build
// ---------------------------------------------------------------------------

const _: () = assert!(size_of::<SignalFrame>() == 34 * size_of::<u64>());

/// Error returned by [`build_signal_frame`] when the user stack cannot hold
/// the frame. Stored as a small enum (not a string) so the warning in
/// [`check_and_dispatch`] is allocation-free.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FrameError {
    /// The user `rsp` was non-canonical or zero.
    BadStack,
    /// The user-memory write failed because the stack range was not mapped,
    /// user-accessible, or writable.
    WriteFailed,
    /// The per-CPU XSAVE policy was unavailable or hardware state was not
    /// live, so delivering a handler would lose FP/SIMD registers.
    XstateUnavailable,
    /// The CPU reported an XSAVE layout outside Xenith's signal ABI bound.
    XstateTooLarge,
}

/// Build the signal frame on the user stack and rewrite `ctx` so `iretq`
/// enters the handler.
///
/// On success `ctx.rsp` points at the trampoline return address (16-byte
/// aligned per the SysV AMD64 ABI), `ctx.rip` is left to the caller to set to
/// the handler entry, and the original `rip`/`rsp`/`rflags`/`cs`/`ss` plus
/// the GPRs are saved in the on-stack [`SignalFrame`]. The handler's `sa_mask`
/// is applied to the blocked set for the duration of the handler.
///
/// User-memory writes go through the checked, SMAP-aware architecture copy
/// path. Unmapped, supervisor-only, read-only, and overflowing ranges fail
/// without turning a bad process stack into a kernel page fault.
fn build_signal_frame(
    state: &SignalState,
    ctx: &mut ExceptionContext,
    sig: Signal,
    info: xenith_abi::SigInfo,
    handler_mask: SignalMask,
    action_flags: u64,
    restart: Option<RestartContext>,
) -> Result<(), FrameError> {
    // Reject an obviously-broken user stack. A non-canonical rsp would #GP on
    // the next memory access; a zero rsp means the process has no user stack
    // mapped. The full validity check (mapped, writable, in user range)
    // belongs to `copy_to_user`; this is the cheap pre-flight.
    if ctx.rsp == 0 || (ctx.rsp & 0xFFFF_8000_0000_0000) == 0xFFFF_8000_0000_0000 {
        return Err(FrameError::BadStack);
    }

    let mut xstate =
        crate::arch::x86_64::fpu::FpuSaveArea::new().map_err(|_| FrameError::XstateUnavailable)?;
    if xstate.size() > xenith_abi::SIGNAL_XSTATE_MAX {
        return Err(FrameError::XstateTooLarge);
    }
    let first_capture = xstate.capture_current();
    if !retry_capture_after_materialize(
        first_capture,
        crate::sched::scheduler::materialize_current_fpu,
        || xstate.capture_current(),
    ) {
        return Err(FrameError::XstateUnavailable);
    }

    let alt_stack = *state.alt_stack.lock();
    let already_on_altstack = alt_stack.contains(ctx.rsp);
    let use_altstack =
        action_flags & xenith_abi::SA_ONSTACK != 0 && alt_stack.enabled() && !already_on_altstack;
    let stack_top = if use_altstack {
        alt_stack
            .sp
            .checked_add(alt_stack.size)
            .ok_or(FrameError::BadStack)?
    } else {
        ctx.rsp
    };

    let (saved_rip, saved_rax, restarted) = restart.map_or((ctx.rip, ctx.rax, false), |restart| {
        (restart.syscall_ip, restart.syscall_number, true)
    });
    let mut frame_flags = xenith_abi::SIGNAL_FRAME_XSTATE;
    if use_altstack || already_on_altstack {
        frame_flags |= xenith_abi::SIGNAL_FRAME_ALTSTACK;
    }
    if restarted {
        frame_flags |= xenith_abi::SIGNAL_FRAME_RESTART;
    }

    let mut frame = SignalFrame {
        signo: u64::from(sig.as_number()),
        saved_mask: xenith_abi::SigSet(state.blocked_mask().bits()),
        rip: saved_rip,
        cs: ctx.cs,
        rflags: ctx.rflags,
        rsp: ctx.rsp,
        ss: ctx.ss,
        rax: saved_rax,
        rbx: ctx.rbx,
        rcx: ctx.rcx,
        rdx: ctx.rdx,
        rsi: ctx.rsi,
        rdi: ctx.rdi,
        rbp: ctx.rbp,
        r8: ctx.r8,
        r9: ctx.r9,
        r10: ctx.r10,
        r11: ctx.r11,
        r12: ctx.r12,
        r13: ctx.r13,
        r14: ctx.r14,
        r15: ctx.r15,
        info,
        xstate_ptr: 0,
        xstate_size: xstate.size() as u64,
        xstate_features: xstate.feature_mask(),
        frame_flags,
    };

    // SysV AMD64 requires rsp to be 16-byte aligned *at the call site*, i.e.
    // (rsp + 8) % 16 == 0 on entry to a function (because the call pushes the
    // return address). We lay out: [trampoline_retaddr][SignalFrame]. Reserve
    // space for both, align the final rsp down to 16, then write.
    let frame_bytes = size_of::<SignalFrame>() as u64;
    let xstate_bytes = xstate.size() as u64;
    // Include the worst-case 63-byte XSAVE alignment gap and 15-byte stack
    // alignment adjustment so every later checked addition stays below top.
    let need = 8u64
        .checked_add(frame_bytes)
        .and_then(|value| value.checked_add(63))
        .and_then(|value| value.checked_add(xstate_bytes))
        .and_then(|value| value.checked_add(15))
        .ok_or(FrameError::BadStack)?;
    let Some(mut new_rsp) = stack_top.checked_sub(need) else {
        return Err(FrameError::BadStack);
    };
    // Align the *final* rsp (which points at the return address) down to 16.
    // After `iretq` the handler sees rsp == new_rsp + 8 (we "return" into it),
    // so we want (new_rsp + 8) to be 16-aligned => new_rsp % 16 == 8. Round
    // to that.
    new_rsp &= !0xFu64;
    new_rsp |= 0x8u64;

    let frame_addr = new_rsp + 8;
    let retaddr_addr = new_rsp;
    let xstate_addr = frame_addr
        .checked_add(frame_bytes)
        .and_then(|address| address.checked_add(63))
        .map(|address| address & !63)
        .ok_or(FrameError::BadStack)?;
    let xstate_end = xstate_addr
        .checked_add(xstate_bytes)
        .ok_or(FrameError::BadStack)?;
    if xstate_end > stack_top || (use_altstack && new_rsp < alt_stack.sp) {
        return Err(FrameError::BadStack);
    }
    frame.xstate_ptr = xstate_addr;

    // Write the aligned XSAVE payload, frame record, then trampoline return
    // address. All use
    // the checked user-copy path and split COW stack pages when necessary.
    if !crate::arch::x86_64::usercopy::copy_to_user_slice(xstate_addr, xstate.as_bytes()) {
        return Err(FrameError::WriteFailed);
    }
    if !copy_to_user(frame_addr, &frame) {
        return Err(FrameError::WriteFailed);
    }
    let trampoline_entry = signal_trampoline_user_entry();
    if !copy_to_user_u64(retaddr_addr, trampoline_entry) {
        return Err(FrameError::WriteFailed);
    }

    // Apply the handler's sa_mask: block the listed signals (plus the signal
    // itself, per POSIX, unless SA_NODEFER was requested).
    {
        let mut g = state.blocked.lock();
        if action_flags & xenith_abi::SA_NODEFER == 0 {
            g.block(sig);
        }
        // `handler_mask` is the user-requested additional mask; OR it in.
        let mut combined = *g;
        combined.0 |= handler_mask.0;
        *g = combined;
    }

    // Rewrite the trap frame: handler runs on the new stack, returns to the
    // trampoline. `rip` is set by the caller (so the match arm can also clear
    // TF/IF uniformly). Set rsi to the frame address (second SysV argument)
    // and rdi to the signal number (first argument).
    ctx.rsp = new_rsp;
    ctx.rdi = u64::from(sig.as_number());
    if action_flags & xenith_abi::SA_SIGINFO != 0 {
        ctx.rsi = frame_addr + core::mem::offset_of!(SignalFrame, info) as u64;
        ctx.rdx = frame_addr;
    } else {
        // Preserve Xenith's original two-argument caught-handler convention.
        ctx.rsi = frame_addr;
    }
    // The handler's user-stack return address is already at `new_rsp`; the
    // SysV ABI leaves the return slot in place, so no further stack fixup.
    Ok(())
}

fn retry_capture_after_materialize(
    first_capture: bool,
    materialize: impl FnOnce() -> bool,
    retry: impl FnOnce() -> bool,
) -> bool {
    first_capture || (materialize() && retry())
}

/// Restore the saved frame on `sigreturn` and unblock the handler mask.
///
/// The trampoline invokes the `SIGRETURN_SYSCALL_NR` syscall with `rsp`
/// pointing at the [`SignalFrame`] the handler's `ret` landed on. The syscall
/// path locates `state` for the current process, reads the frame back from
/// user memory, copies its saved registers into `ctx`, restores the saved
/// blocked mask, and returns to the interrupted user code via `iretq`.
///
/// Returns `true` if the frame was restored and `ctx` is now valid for
/// `iretq`; `false` if the user `rsp` did not point at a valid frame (the
/// syscall path then converts this to `EINVAL`).
pub fn sigreturn(state: &SignalState, ctx: &mut ExceptionContext) -> bool {
    // The frame sits at the user rsp the trampoline was at when it issued the
    // syscall. By the SysV ABI, on syscall entry rsp points at the return
    // address the trampoline's `ret` would consume — but the trampoline does
    // *not* `ret`; it `syscall`s, so the frame is exactly at `ctx.rsp`.
    let frame_addr = ctx.rsp;

    let mut frame = SignalFrame {
        signo: 0,
        saved_mask: xenith_abi::SigSet(0),
        rip: 0,
        cs: 0,
        rflags: 0,
        rsp: 0,
        ss: 0,
        rax: 0,
        rbx: 0,
        rcx: 0,
        rdx: 0,
        rsi: 0,
        rdi: 0,
        rbp: 0,
        r8: 0,
        r9: 0,
        r10: 0,
        r11: 0,
        r12: 0,
        r13: 0,
        r14: 0,
        r15: 0,
        info: EMPTY_SIGINFO,
        xstate_ptr: 0,
        xstate_size: 0,
        xstate_features: 0,
        frame_flags: 0,
    };
    if !copy_from_user(frame_addr, &mut frame) {
        return false;
    }

    if !valid_sigreturn_frame(&frame) {
        return false;
    }
    frame.rflags = sanitize_user_rflags(frame.rflags);
    let restored_mask = SignalMask::from_bits_sanitized(frame.saved_mask.0);

    // The variable xstate record is frame-owned: neither its pointer, size,
    // feature mask, nor reserved metadata may be redirected by userspace.
    let Ok(mut xstate) = crate::arch::x86_64::fpu::FpuSaveArea::new() else {
        return false;
    };
    if !valid_xstate_metadata(frame_addr, &frame, xstate.size(), xstate.feature_mask()) {
        return false;
    }
    if !crate::arch::x86_64::usercopy::copy_from_user_slice(xstate.as_bytes_mut(), frame.xstate_ptr)
        || !xstate.restore_user_image()
    {
        return false;
    }

    // Restore the blocked mask the handler saved, unwinding its sa_mask.
    state.set_blocked(restored_mask);

    // Restore the interrupted register frame. `r11` is overwritten by
    // `syscall` with RFLAGS, but the saved value is what user code expects on
    // resume, so we restore it too.
    ctx.rip = frame.rip;
    ctx.cs = frame.cs;
    ctx.rflags = frame.rflags;
    ctx.rsp = frame.rsp;
    ctx.ss = frame.ss;
    ctx.rax = frame.rax;
    ctx.rbx = frame.rbx;
    ctx.rcx = frame.rcx;
    ctx.rdx = frame.rdx;
    ctx.rsi = frame.rsi;
    ctx.rdi = frame.rdi;
    ctx.rbp = frame.rbp;
    ctx.r8 = frame.r8;
    ctx.r9 = frame.r9;
    ctx.r10 = frame.r10;
    ctx.r11 = frame.r11;
    ctx.r12 = frame.r12;
    ctx.r13 = frame.r13;
    ctx.r14 = frame.r14;
    ctx.r15 = frame.r15;
    true
}

#[inline]
fn valid_xstate_metadata(
    frame_addr: u64,
    frame: &SignalFrame,
    expected_size: usize,
    expected_features: u64,
) -> bool {
    let expected_pointer = frame_addr
        .checked_add(size_of::<SignalFrame>() as u64)
        .and_then(|address| address.checked_add(63))
        .map(|address| address & !63);
    let supported_frame_flags = xenith_abi::SIGNAL_FRAME_XSTATE
        | xenith_abi::SIGNAL_FRAME_ALTSTACK
        | xenith_abi::SIGNAL_FRAME_RESTART;
    expected_pointer.is_some_and(|pointer| {
        frame.frame_flags & xenith_abi::SIGNAL_FRAME_XSTATE != 0
            && frame.frame_flags & !supported_frame_flags == 0
            && frame.xstate_ptr == pointer
            && frame.xstate_ptr & 63 == 0
            && frame.xstate_size == expected_size as u64
            && expected_size <= xenith_abi::SIGNAL_XSTATE_MAX
            && frame.xstate_features == expected_features
    })
}

/// Validate the privilege-sensitive portion of a user-supplied signal frame.
/// Segment selectors are fixed by Xenith's 64-bit ring-3 ABI, while RIP and
/// RSP must stay in the canonical low half.
#[inline]
fn valid_sigreturn_frame(frame: &SignalFrame) -> bool {
    frame.rip != 0
        && frame.rip <= crate::mm::r#virtual::USER_MAX
        && frame.rsp != 0
        && frame.rsp <= crate::mm::r#virtual::USER_MAX
        && frame.cs == user_code_selector()
        && frame.ss == user_data_selector()
        && Signal::from_number(frame.signo as u32).is_some()
        && frame.signo <= u64::from(NSIG)
        && frame.info.signo == frame.signo as u32
        && frame.info.reserved == 0
}

/// Keep arithmetic/debug status that ring 3 may legitimately control, force
/// the architectural fixed bit and IF, and clear IOPL, NT, VM, VIF, VIP, and
/// every reserved or kernel-owned flag.
#[inline]
#[must_use]
const fn sanitize_user_rflags(flags: u64) -> u64 {
    const USER_VISIBLE: u64 = (1 << 0) // CF
        | (1 << 2) // PF
        | (1 << 4) // AF
        | (1 << 6) // ZF
        | (1 << 7) // SF
        | (1 << 8) // TF
        | (1 << 10) // DF
        | (1 << 11) // OF
        | (1 << 16) // RF
        | (1 << 18) // AC
        | (1 << 21); // ID
    (flags & USER_VISIBLE) | RFLAGS_IF | 2
}

// ---------------------------------------------------------------------------
// Checked user-memory access
// ---------------------------------------------------------------------------

/// Copy `val` to user virtual address `dst`.
///
/// The shared primitive validates the complete range against the pinned
/// active address space, resolves copy-on-write destinations, and converts a
/// late page fault into `false` through the user-copy exception fixup.
fn copy_to_user<T>(dst: u64, val: &T) -> bool {
    // SAFETY: current callers use padding-free SignalFrame and u64 layouts.
    let bytes = unsafe { slice::from_raw_parts(core::ptr::from_ref(val).cast(), size_of::<T>()) };
    crate::arch::x86_64::usercopy::copy_to_user_slice(dst, bytes)
}

/// Copy a trampoline return address to user virtual address `dst`.
fn copy_to_user_u64(dst: u64, val: u64) -> bool {
    copy_to_user(dst, &val)
}

/// Copy `size_of::<T>()` bytes from user virtual address `src` into `out`.
/// Inverse of [`copy_to_user`]; used by [`sigreturn`] to read the saved frame.
fn copy_from_user<T>(src: u64, out: &mut T) -> bool {
    // SAFETY: current callers use the padding-free SignalFrame layout, and
    // the destination is overwritten in full before its fields are observed.
    let bytes =
        unsafe { slice::from_raw_parts_mut(core::ptr::from_mut(out).cast(), size_of::<T>()) };
    crate::arch::x86_64::usercopy::copy_from_user_slice(bytes, src)
}

// ---------------------------------------------------------------------------
// Signal trampoline
// ---------------------------------------------------------------------------

/// The default signal trampoline: the bytes a handler `ret`s into, which
/// issue the `sigreturn` syscall to restore the saved frame.
///
/// The trampoline is a tiny position-independent snippet:
///
/// ```text
///   mov eax, SIGRETURN_SYSCALL_NR   ; B8 <nr> <nr> <nr> <nr>
///   syscall                          ; 0F 05
///   ud2                              ; 0F 0B  (unreachable: syscall does not return)
/// ```
///
/// `mov eax, imm32` is 5 bytes (`B8` + LE imm32), `syscall` is 2 bytes, and
/// `ud2` is 2 bytes as a defensive guard so a buggy `sigreturn` that *did*
/// return traps instead of running off into user memory. Total: 9 bytes.
///
/// The ELF loader copies these bytes into each process's fixed read/execute
/// trampoline page. [`signal_trampoline_user_entry`] is the return address
/// installed below each caught-signal frame.
pub const SIGNAL_TRAMPOLINE: [u8; 9] = {
    let nr = SIGRETURN_SYSCALL_NR;
    [
        0xB8,
        (nr & 0xFF) as u8,
        ((nr >> 8) & 0xFF) as u8,
        ((nr >> 16) & 0xFF) as u8,
        ((nr >> 24) & 0xFF) as u8,
        0x0F,
        0x05,
        0x0F,
        0x0B,
    ]
};

/// The user-space virtual address at which the signal trampoline is mapped.
///
/// The ELF loader reserves and maps this page immediately above the exclusive
/// user-stack limit, keeping it outside both loadable segments and stack data.
pub const SIGNAL_TRAMPOLINE_USER_ENTRY: u64 = super::elf::USER_SIGNAL_TRAMPOLINE;

/// Return the fixed user-space entry address of the signal trampoline.
#[inline]
#[must_use]
pub fn signal_trampoline_user_entry() -> u64 {
    SIGNAL_TRAMPOLINE_USER_ENTRY
}

/// Copy the default trampoline bytes into `out`. The process-creation path
/// calls this when initializing the trampoline page so the bytes do not have
/// to be re-derived at the call site.
pub fn trampoline_bytes(out: &mut [u8]) {
    let n = out.len().min(SIGNAL_TRAMPOLINE.len());
    out[..n].copy_from_slice(&SIGNAL_TRAMPOLINE[..n]);
}

/// User-mode segment selectors, re-exported so the signal path can sanity-check
/// a frame it is about to restore via [`sigreturn`] without reaching into the
/// arch module directly. `cs` for a 64-bit user process is `USER_CODE_SELECTOR`.
pub fn user_code_selector() -> u64 {
    u64::from(gdt::USER_CODE_SELECTOR)
}

/// User-mode data selector (`USER_DATA_SELECTOR`).
pub fn user_data_selector() -> u64 {
    u64::from(gdt::USER_DATA_SELECTOR)
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    fn test_frame() -> SignalFrame {
        SignalFrame {
            signo: u64::from(xenith_abi::SIGUSR1),
            saved_mask: xenith_abi::SigSet(0),
            rip: 0x401000,
            cs: user_code_selector(),
            rflags: 0x202,
            rsp: 0x7fff_f000,
            ss: user_data_selector(),
            rax: 0,
            rbx: 0,
            rcx: 0,
            rdx: 0,
            rsi: 0,
            rdi: 0,
            rbp: 0,
            r8: 0,
            r9: 0,
            r10: 0,
            r11: 0,
            r12: 0,
            r13: 0,
            r14: 0,
            r15: 0,
            info: xenith_abi::SigInfo {
                signo: xenith_abi::SIGUSR1,
                ..xenith_abi::SigInfo::default()
            },
            xstate_ptr: 0,
            xstate_size: 832,
            xstate_features: 7,
            frame_flags: xenith_abi::SIGNAL_FRAME_XSTATE,
        }
    }

    #[test]
    fn signal_round_trip_standard() {
        for n in [1u32, 2, 9, 11, 15, 22] {
            let s = Signal::from_number(n).unwrap();
            assert_eq!(s.as_number(), n);
            assert!(!s.is_realtime());
        }
    }

    #[test]
    fn signal_zero_is_none() {
        assert!(Signal::from_number(0).is_none());
        assert!(Signal::from_number(NSIG + 1).is_none());
    }

    #[test]
    fn realtime_round_trip() {
        let s = Signal::from_number(RT_MIN).unwrap();
        assert!(s.is_realtime());
        assert_eq!(s.as_number(), RT_MIN);
        assert_eq!(Signal::Rt(0), s);
        let s2 = Signal::from_number(RT_MAX).unwrap();
        assert_eq!(s2.as_number(), RT_MAX);
    }

    #[test]
    fn kill_and_stop_are_uncatchable() {
        assert!(Signal::Kill.is_uncatchable());
        assert!(Signal::Stop.is_uncatchable());
        assert!(!Signal::Term.is_uncatchable());
    }

    #[test]
    fn default_actions_match_posix() {
        assert_eq!(Signal::Term.default_action(), DefaultAction::Terminate);
        assert_eq!(
            Signal::Segv.default_action(),
            DefaultAction::TerminateCoreDump
        );
        assert_eq!(Signal::Chld.default_action(), DefaultAction::Ignore);
        assert_eq!(Signal::Stop.default_action(), DefaultAction::Stop);
        assert_eq!(Signal::Cont.default_action(), DefaultAction::Continue);
    }

    #[test]
    fn signal_set_add_contains_remove() {
        let mut set = SignalSet::empty();
        assert!(!set.contains(Signal::Int));
        assert!(!set.add(Signal::Int));
        assert!(set.contains(Signal::Int));
        assert!(set.add(Signal::Int));
        set.remove(Signal::Int);
        assert!(!set.contains(Signal::Int));
    }

    #[test]
    fn signal_set_pop_lowest_orders_by_number() {
        let mut set = SignalSet::empty();
        set.add(Signal::Rt(0));
        set.add(Signal::Int);
        set.add(Signal::Term);
        assert_eq!(set.pop_lowest(), Some(Signal::Int));
        assert_eq!(set.pop_lowest(), Some(Signal::Term));
        assert_eq!(set.pop_lowest(), Some(Signal::Rt(0)));
        assert_eq!(set.pop_lowest(), None);
    }

    #[test]
    fn mask_block_unblock() {
        let mut m = SignalMask::empty();
        assert!(!m.is_blocked(Signal::Int));
        m.block(Signal::Int);
        assert!(m.is_blocked(Signal::Int));
        m.unblock(Signal::Int);
        assert!(!m.is_blocked(Signal::Int));
    }

    #[test]
    fn userspace_masks_cannot_block_kill_or_stop() {
        let mask = SignalMask::from_bits_sanitized(
            (1 << Signal::Int.as_number())
                | (1 << Signal::Kill.as_number())
                | (1 << Signal::Stop.as_number()),
        );
        assert!(mask.is_blocked(Signal::Int));
        assert!(!mask.is_blocked(Signal::Kill));
        assert!(!mask.is_blocked(Signal::Stop));
    }

    #[test]
    fn sigreturn_flags_drop_privilege_controls() {
        let requested = u64::MAX;
        let sanitized = sanitize_user_rflags(requested);
        assert_eq!(sanitized & (3 << 12), 0); // IOPL
        assert_eq!(sanitized & (1 << 14), 0); // NT
        assert_eq!(sanitized & (1 << 17), 0); // VM
        assert_eq!(sanitized & (1 << 19), 0); // VIF
        assert_eq!(sanitized & (1 << 20), 0); // VIP
        assert_ne!(sanitized & RFLAGS_IF, 0);
        assert_ne!(sanitized & 2, 0);
    }

    #[test]
    fn set_handler_refuses_kill() {
        let st = SignalState::new();
        assert!(!st.set_handler(Signal::Kill, SignalAction::Ignore));
        assert!(st.set_handler(Signal::Kill, SignalAction::Default));
        assert!(st.set_handler(Signal::Int, SignalAction::Ignore));
        assert_eq!(st.disposition(Signal::Int), SignalAction::Ignore);
    }

    #[test]
    fn deliver_standard_coalesces() {
        let st = SignalState::new();
        assert_eq!(
            deliver_signal(&st, Signal::Int),
            DeliverOutcome::NewlyPending
        );
        assert_eq!(
            deliver_signal(&st, Signal::Int),
            DeliverOutcome::AlreadyPending
        );
    }

    #[test]
    fn deliver_realtime_counts() {
        let st = SignalState::new();
        assert_eq!(
            deliver_signal(&st, Signal::Rt(0)),
            DeliverOutcome::RealtimeQueued { count: 1 }
        );
        assert_eq!(
            deliver_signal(&st, Signal::Rt(0)),
            DeliverOutcome::RealtimeQueued { count: 2 }
        );
    }

    #[test]
    fn fork_and_exec_signal_snapshots_follow_process_rules() {
        let parent = SignalState::new();
        let mut mask = SignalMask::empty();
        mask.block(Signal::Usr1);
        parent.set_blocked(mask);
        let catch = SignalAction::Catch {
            entry: 0x1234,
            mask: SignalMask::empty(),
            flags: 0,
        };
        assert!(parent.set_handler(Signal::Int, catch));
        assert!(parent.set_handler(Signal::Term, SignalAction::Ignore));
        assert_eq!(
            deliver_signal(&parent, Signal::Usr2),
            DeliverOutcome::NewlyPending
        );
        parent
            .sigaltstack(
                0x400000,
                Some(xenith_abi::SigAltStack {
                    sp: 0x700000,
                    size: xenith_abi::MINSIGSTKSZ,
                    flags: 0,
                    reserved: 0,
                }),
            )
            .unwrap();

        let child = parent.clone_for_fork();
        assert!(child.blocked_mask().is_blocked(Signal::Usr1));
        assert_eq!(child.disposition(Signal::Int), catch);
        assert!(child.pending.lock().set.is_empty());
        assert_eq!(child.sigaltstack(0x400000, None).unwrap().sp, 0x700000);

        let replaced = parent.clone_for_exec();
        assert!(replaced.blocked_mask().is_blocked(Signal::Usr1));
        assert_eq!(replaced.disposition(Signal::Int), SignalAction::Default);
        assert_eq!(replaced.disposition(Signal::Term), SignalAction::Ignore);
        assert!(replaced.pending.lock().set.is_empty());
        assert_eq!(
            replaced.sigaltstack(0x400000, None).unwrap().flags,
            xenith_abi::SS_DISABLE
        );
    }

    #[test]
    fn alternate_stack_bounds_and_onstack_edges_are_exact() {
        let state = SignalState::new();
        let stack = xenith_abi::SigAltStack {
            sp: 0x700000,
            size: xenith_abi::MINSIGSTKSZ,
            flags: 0,
            reserved: 0,
        };
        assert_eq!(
            state.sigaltstack(0x400000, None).unwrap().flags,
            xenith_abi::SS_DISABLE
        );
        state.sigaltstack(0x400000, Some(stack)).unwrap();
        assert_eq!(
            state.sigaltstack(stack.sp, None).unwrap().flags,
            xenith_abi::SS_ONSTACK
        );
        assert_eq!(
            state
                .sigaltstack(stack.sp + stack.size - 1, None)
                .unwrap()
                .flags,
            xenith_abi::SS_ONSTACK
        );
        assert_eq!(
            state
                .sigaltstack(stack.sp + stack.size, None)
                .unwrap()
                .flags,
            0
        );
        assert_eq!(
            state.sigaltstack(stack.sp, Some(stack)),
            Err(AltStackError::AlreadyOnStack)
        );

        let too_small = xenith_abi::SigAltStack {
            size: xenith_abi::MINSIGSTKSZ - 1,
            ..stack
        };
        assert_eq!(
            SignalState::new().sigaltstack(0x400000, Some(too_small)),
            Err(AltStackError::InvalidRange)
        );
        let overflowing = xenith_abi::SigAltStack {
            sp: crate::mm::r#virtual::USER_MAX - 8,
            ..stack
        };
        assert_eq!(
            SignalState::new().sigaltstack(0x400000, Some(overflowing)),
            Err(AltStackError::InvalidRange)
        );
        let query_only_flag = xenith_abi::SigAltStack {
            flags: xenith_abi::SS_ONSTACK,
            ..stack
        };
        assert_eq!(
            SignalState::new().sigaltstack(0x400000, Some(query_only_flag)),
            Err(AltStackError::InvalidFlags)
        );
    }

    #[test]
    fn siginfo_payload_survives_pending_delivery() {
        let state = SignalState::new();
        let info = xenith_abi::SigInfo {
            signo: xenith_abi::SIGUSR1,
            code: xenith_abi::SI_USER,
            sender_pid: 42,
            value: 0xfeed,
            ..xenith_abi::SigInfo::default()
        };
        assert_eq!(
            deliver_signal_with_info(&state, Signal::Usr1, info),
            DeliverOutcome::NewlyPending
        );
        let (signal, retained, _guard) = select_deliverable(&state).unwrap();
        assert_eq!(signal, Signal::Usr1);
        assert_eq!(retained, info);
    }

    #[test]
    fn hostile_sigreturn_xstate_metadata_cannot_redirect_restore() {
        let frame_addr = 0x700008;
        let mut frame = test_frame();
        frame.xstate_ptr = (frame_addr + size_of::<SignalFrame>() as u64 + 63) & !63;
        assert!(valid_xstate_metadata(frame_addr, &frame, 832, 7));

        let mut redirected = frame;
        redirected.xstate_ptr += 64;
        assert!(!valid_xstate_metadata(frame_addr, &redirected, 832, 7));
        let mut oversized = frame;
        oversized.xstate_size = xenith_abi::SIGNAL_XSTATE_MAX as u64 + 1;
        assert!(!valid_xstate_metadata(frame_addr, &oversized, 832, 7));
        let mut features = frame;
        features.xstate_features |= 1 << 9;
        assert!(!valid_xstate_metadata(frame_addr, &features, 832, 7));
        let mut flags = frame;
        flags.frame_flags |= 1 << 63;
        assert!(!valid_xstate_metadata(frame_addr, &flags, 832, 7));
    }

    #[test]
    fn ts_set_signal_capture_materializes_then_retries_exactly_once() {
        use core::cell::Cell;

        let materialized = Cell::new(false);
        let retries = Cell::new(0);
        assert!(retry_capture_after_materialize(
            false,
            || {
                materialized.set(true);
                true
            },
            || {
                retries.set(retries.get() + 1);
                materialized.get()
            },
        ));
        assert_eq!(retries.get(), 1);

        let materialize_calls = Cell::new(0);
        assert!(retry_capture_after_materialize(
            true,
            || {
                materialize_calls.set(1);
                false
            },
            || false,
        ));
        assert_eq!(materialize_calls.get(), 0);
    }

    #[test]
    fn trampoline_bytes_decode_to_mov_eax_syscall() {
        // mov eax, imm32 ; syscall ; ud2
        assert_eq!(SIGNAL_TRAMPOLINE[0], 0xB8);
        assert_eq!(&SIGNAL_TRAMPOLINE[5..7], &[0x0F, 0x05]);
        assert_eq!(&SIGNAL_TRAMPOLINE[7..9], &[0x0F, 0x0B]);
        // The imm32 is little-endian SIGRETURN_SYSCALL_NR.
        let nr = SIGRETURN_SYSCALL_NR;
        assert_eq!(nr, xenith_abi::SyscallNumber::Sigreturn as u32);
        assert_eq!(SIGNAL_TRAMPOLINE[1], (nr & 0xFF) as u8);
    }
}
