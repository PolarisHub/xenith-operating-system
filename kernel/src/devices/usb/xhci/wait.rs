//! Real-time-bounded polling that remains live before `sti`.
//!
//! Xenith's HPET clock advances with interrupts masked, but the LAPIC fallback
//! uptime accumulator does not. xHCI bring-up therefore cannot use uptime as
//! its only deadline. These budgets combine a short low-latency poll burst
//! with a polled PIT millisecond, whose hardware counter advances regardless
//! of RFLAGS.IF.

/// Cheap polls performed before each real millisecond delay slot.
pub const FAST_POLLS_PER_MILLISECOND: usize = 256;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct MillisecondBudget {
    remaining: u16,
}

/// Iteration gate that checks elapsed wall time after each fast burst, even
/// when the caller continuously receives unrelated events.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct PollingBudget {
    milliseconds: MillisecondBudget,
    fast_remaining: usize,
    monotonic_deadline_ns: Option<u64>,
}

impl PollingBudget {
    #[must_use]
    pub fn new(milliseconds: u16) -> Self {
        // PIT channel 0 is a global programming interface, so use it only in
        // the single-CPU pre-STI bring-up path. Once interrupts are enabled,
        // HPET/LAPIC uptime advances and provides an SMP-safe non-destructive
        // deadline for hotplug and recovery waits.
        let interrupts_enabled = crate::arch::x86_64::interrupts_enabled();
        let now_ns = if interrupts_enabled {
            crate::time::uptime_ns()
        } else {
            0
        };
        Self::from_clock_state(milliseconds, interrupts_enabled, now_ns)
    }

    const fn from_clock_state(milliseconds: u16, interrupts_enabled: bool, now_ns: u64) -> Self {
        let monotonic_deadline_ns = if interrupts_enabled {
            Some(now_ns.saturating_add((milliseconds as u64).saturating_mul(1_000_000)))
        } else {
            None
        };
        Self {
            milliseconds: MillisecondBudget::new(milliseconds),
            fast_remaining: FAST_POLLS_PER_MILLISECOND,
            monotonic_deadline_ns,
        }
    }

    /// Permit one poll or return false after the elapsed budget is exhausted.
    pub fn poll_again(&mut self) -> bool {
        if self.fast_remaining == 0 {
            if let Some(deadline) = self.monotonic_deadline_ns {
                if crate::time::uptime_ns() >= deadline {
                    return false;
                }
            } else if !self.milliseconds.wait_one() {
                return false;
            }
            self.fast_remaining = FAST_POLLS_PER_MILLISECOND;
        }
        self.fast_remaining -= 1;
        true
    }
}

impl MillisecondBudget {
    #[must_use]
    pub const fn new(milliseconds: u16) -> Self {
        Self {
            remaining: milliseconds,
        }
    }

    const fn consume_one(&mut self) -> bool {
        if self.remaining == 0 {
            false
        } else {
            self.remaining -= 1;
            true
        }
    }

    /// Consume and wait one real millisecond. Returns false once exhausted.
    pub fn wait_one(&mut self) -> bool {
        if !self.consume_one() {
            return false;
        }
        crate::time::pit::pit_sleep(1);
        true
    }
}

/// Poll immediately in bounded fast bursts until the predicate succeeds or
/// wall time expires. Pre-STI bursts use PIT slots; runtime bursts check the
/// non-destructive monotonic clock.
pub fn until(milliseconds: u16, mut ready: impl FnMut() -> bool) -> bool {
    let mut budget = PollingBudget::new(milliseconds);
    while budget.poll_again() {
        if ready() {
            return true;
        }
        core::hint::spin_loop();
    }
    false
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn millisecond_budget_is_exact_and_cannot_underflow() {
        let mut budget = MillisecondBudget::new(3);
        for expected in [2, 1, 0] {
            assert!(budget.consume_one());
            assert_eq!(budget.remaining, expected);
        }
        assert!(!budget.consume_one());
        assert_eq!(budget.remaining, 0);
    }

    #[test]
    fn zero_budget_starts_expired() {
        assert_eq!(MillisecondBudget::new(0).remaining, 0);
    }

    #[test]
    fn pre_sti_budget_selects_pit_slots() {
        let budget = PollingBudget::from_clock_state(25, false, 9_000_000);
        assert_eq!(budget.milliseconds.remaining, 25);
        assert_eq!(budget.monotonic_deadline_ns, None);
    }

    #[test]
    fn post_sti_budget_selects_non_destructive_monotonic_deadline() {
        let budget = PollingBudget::from_clock_state(25, true, 9_000_000);
        assert_eq!(budget.milliseconds.remaining, 25);
        assert_eq!(budget.monotonic_deadline_ns, Some(34_000_000));

        let saturated = PollingBudget::from_clock_state(1_000, true, u64::MAX - 5);
        assert_eq!(saturated.monotonic_deadline_ns, Some(u64::MAX));
    }
}
