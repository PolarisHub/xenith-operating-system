//! Allocation-free state machines for the supported waitable object subset.
//!
//! These types implement deterministic object semantics only. They do not park
//! Xenith tasks, create threads, deliver APCs, or claim Windows scheduler
//! compatibility. Blocking service calls remain unsupported until a scheduler
//! bridge exists.

use crate::{NtStatus, NtThreadId};

/// Event reset policy.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum EventKind {
    /// Remains signaled until explicitly reset.
    Notification,
    /// Satisfies one waiter and then resets automatically.
    Synchronization,
}

/// Bounded event state.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct EventState {
    kind: EventKind,
    signaled: bool,
}

impl EventState {
    /// Creates an event with an explicit reset policy and initial state.
    #[must_use]
    pub const fn new(kind: EventKind, signaled: bool) -> Self {
        Self { kind, signaled }
    }

    /// Returns the event reset policy.
    #[must_use]
    pub const fn kind(self) -> EventKind {
        self.kind
    }

    /// Returns whether the event is currently signaled.
    #[must_use]
    pub const fn is_signaled(self) -> bool {
        self.signaled
    }

    /// Signals the event and returns its previous state.
    pub fn set(&mut self) -> bool {
        let previous = self.signaled;
        self.signaled = true;
        previous
    }

    /// Resets the event and returns its previous state.
    pub fn reset(&mut self) -> bool {
        let previous = self.signaled;
        self.signaled = false;
        previous
    }

    /// Attempts one wait without parking a task.
    pub fn try_wait(&mut self) -> WaitSatisfaction {
        if !self.signaled {
            return WaitSatisfaction::WouldBlock;
        }
        if self.kind == EventKind::Synchronization {
            self.signaled = false;
        }
        WaitSatisfaction::Satisfied
    }
}

/// Recursive mutant ownership state.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct MutantState {
    owner: Option<NtThreadId>,
    recursion: u32,
    abandoned: bool,
}

impl MutantState {
    /// Creates an unowned mutant or one initially owned by `owner`.
    #[must_use]
    pub const fn new(owner: Option<NtThreadId>) -> Self {
        Self {
            owner,
            recursion: if owner.is_some() { 1 } else { 0 },
            abandoned: false,
        }
    }

    /// Returns the current owner.
    #[must_use]
    pub const fn owner(self) -> Option<NtThreadId> {
        self.owner
    }

    /// Returns the current recursive acquisition count.
    #[must_use]
    pub const fn recursion(self) -> u32 {
        self.recursion
    }

    /// Attempts one acquisition without parking a task.
    pub fn try_wait(&mut self, thread: NtThreadId) -> Result<WaitSatisfaction, SyncError> {
        match self.owner {
            None => {
                self.owner = Some(thread);
                self.recursion = 1;
                if self.abandoned {
                    self.abandoned = false;
                    Ok(WaitSatisfaction::Abandoned)
                } else {
                    Ok(WaitSatisfaction::Satisfied)
                }
            },
            Some(owner) if owner == thread => {
                self.recursion = self
                    .recursion
                    .checked_add(1)
                    .ok_or(SyncError::MutantLimitExceeded)?;
                Ok(WaitSatisfaction::Satisfied)
            },
            Some(_) => Ok(WaitSatisfaction::WouldBlock),
        }
    }

    /// Releases one recursive acquisition and returns the previous count.
    pub fn release(&mut self, thread: NtThreadId) -> Result<u32, SyncError> {
        if self.owner != Some(thread) || self.recursion == 0 {
            return Err(SyncError::MutantNotOwned);
        }
        let previous = self.recursion;
        self.recursion -= 1;
        if self.recursion == 0 {
            self.owner = None;
        }
        Ok(previous)
    }

    /// Marks the mutant abandoned when `thread` owns it.
    ///
    /// Returns whether ownership changed.
    pub fn abandon_if_owned(&mut self, thread: NtThreadId) -> bool {
        if self.owner != Some(thread) {
            return false;
        }
        self.owner = None;
        self.recursion = 0;
        self.abandoned = true;
        true
    }
}

/// Counting-semaphore state.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct SemaphoreState {
    count: u32,
    limit: u32,
}

impl SemaphoreState {
    /// Creates a semaphore after validating `initial <= limit` and nonzero limit.
    pub const fn try_new(initial: u32, limit: u32) -> Result<Self, SyncError> {
        if limit == 0 || initial > limit {
            return Err(SyncError::InvalidParameter);
        }
        Ok(Self {
            count: initial,
            limit,
        })
    }

    /// Returns the current count.
    #[must_use]
    pub const fn count(self) -> u32 {
        self.count
    }

    /// Returns the configured maximum count.
    #[must_use]
    pub const fn limit(self) -> u32 {
        self.limit
    }

    /// Attempts one decrement without parking a task.
    pub fn try_wait(&mut self) -> WaitSatisfaction {
        if self.count == 0 {
            return WaitSatisfaction::WouldBlock;
        }
        self.count -= 1;
        WaitSatisfaction::Satisfied
    }

    /// Adds `release_count` transactionally and returns the previous count.
    pub fn release(&mut self, release_count: u32) -> Result<u32, SyncError> {
        if release_count == 0 {
            return Err(SyncError::InvalidParameter);
        }
        let next = self
            .count
            .checked_add(release_count)
            .filter(|next| *next <= self.limit)
            .ok_or(SyncError::SemaphoreLimitExceeded)?;
        let previous = self.count;
        self.count = next;
        Ok(previous)
    }
}

/// Timer reset policy.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum TimerKind {
    /// Remains signaled until canceled or set again.
    Notification,
    /// Satisfies one waiter and then clears the signal state.
    Synchronization,
}

/// Deterministic timer state driven by caller-supplied monotonic ticks.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct TimerState {
    kind: TimerKind,
    active: bool,
    signaled: bool,
    deadline_ticks: u64,
    period_ticks: u64,
}

impl TimerState {
    /// Creates an inactive timer.
    #[must_use]
    pub const fn new(kind: TimerKind) -> Self {
        Self {
            kind,
            active: false,
            signaled: false,
            deadline_ticks: 0,
            period_ticks: 0,
        }
    }

    /// Returns whether a deadline is active.
    #[must_use]
    pub const fn is_active(self) -> bool {
        self.active
    }

    /// Returns the current deadline when active.
    #[must_use]
    pub const fn deadline_ticks(self) -> Option<u64> {
        if self.active {
            Some(self.deadline_ticks)
        } else {
            None
        }
    }

    /// Sets a relative deadline and optional period transactionally.
    ///
    /// A zero delay is an immediate deadline. A zero period selects one-shot
    /// behavior. The caller chooses the monotonic tick unit and must use it
    /// consistently for later polls.
    pub fn set_relative(
        &mut self,
        now_ticks: u64,
        delay_ticks: u64,
        period_ticks: u64,
    ) -> Result<bool, SyncError> {
        let deadline = now_ticks
            .checked_add(delay_ticks)
            .ok_or(SyncError::IntegerOverflow)?;
        let previous = self.active;
        self.active = true;
        self.signaled = false;
        self.deadline_ticks = deadline;
        self.period_ticks = period_ticks;
        Ok(previous)
    }

    /// Cancels the timer, clears its signal state, and returns prior activity.
    pub fn cancel(&mut self) -> bool {
        let previous = self.active;
        self.active = false;
        self.signaled = false;
        self.deadline_ticks = 0;
        self.period_ticks = 0;
        previous
    }

    /// Refreshes signal state from a caller-supplied monotonic time.
    pub fn refresh(&mut self, now_ticks: u64) -> Result<bool, SyncError> {
        if !self.active || now_ticks < self.deadline_ticks {
            return Ok(self.signaled);
        }

        let next_deadline = if self.period_ticks == 0 {
            None
        } else {
            let elapsed = now_ticks - self.deadline_ticks;
            let periods = elapsed
                .checked_div(self.period_ticks)
                .ok_or(SyncError::IntegerOverflow)?
                .checked_add(1)
                .ok_or(SyncError::IntegerOverflow)?;
            let advance = periods
                .checked_mul(self.period_ticks)
                .ok_or(SyncError::IntegerOverflow)?;
            Some(
                self.deadline_ticks
                    .checked_add(advance)
                    .ok_or(SyncError::IntegerOverflow)?,
            )
        };

        self.signaled = true;
        if let Some(next) = next_deadline {
            self.deadline_ticks = next;
        } else {
            self.active = false;
        }
        Ok(true)
    }

    /// Attempts one timer wait without parking a task.
    pub fn try_wait(&mut self, now_ticks: u64) -> Result<WaitSatisfaction, SyncError> {
        self.refresh(now_ticks)?;
        if !self.signaled {
            return Ok(WaitSatisfaction::WouldBlock);
        }
        if self.kind == TimerKind::Synchronization {
            self.signaled = false;
        }
        Ok(WaitSatisfaction::Satisfied)
    }
}

/// Result of a nonblocking wait-state transition.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum WaitSatisfaction {
    /// The object satisfied the wait.
    Satisfied,
    /// The object was acquired but its previous owner had abandoned it.
    Abandoned,
    /// The object is not currently signaled.
    WouldBlock,
}

/// Synchronization state-machine failure.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum SyncError {
    /// A count, limit, or identity argument was invalid.
    InvalidParameter,
    /// The calling thread did not own the mutant.
    MutantNotOwned,
    /// Recursive mutant acquisition overflowed.
    MutantLimitExceeded,
    /// A semaphore release exceeded its configured limit.
    SemaphoreLimitExceeded,
    /// Deadline or periodic arithmetic overflowed.
    IntegerOverflow,
}

impl SyncError {
    /// Converts the state-machine error to a stable NT status.
    #[must_use]
    pub const fn status(self) -> NtStatus {
        match self {
            Self::InvalidParameter => NtStatus::INVALID_PARAMETER,
            Self::MutantNotOwned => NtStatus::MUTANT_NOT_OWNED,
            Self::MutantLimitExceeded => NtStatus::MUTANT_LIMIT_EXCEEDED,
            Self::SemaphoreLimitExceeded => NtStatus::SEMAPHORE_LIMIT_EXCEEDED,
            Self::IntegerOverflow => NtStatus::INTEGER_OVERFLOW,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn mutant_recursion_overflow_is_transactional() {
        let owner = NtThreadId::try_from_raw(1).unwrap();
        let mut mutant = MutantState::new(Some(owner));
        mutant.recursion = u32::MAX;

        assert_eq!(mutant.try_wait(owner), Err(SyncError::MutantLimitExceeded));
        assert_eq!(mutant.owner(), Some(owner));
        assert_eq!(mutant.recursion(), u32::MAX);
    }
}
