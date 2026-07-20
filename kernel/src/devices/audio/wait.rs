//! Wall-time-bounded polling for HDA hardware transitions.
//!
//! The PIT remains available before `sti`, while runtime waits must not
//! reprogram its global channel from one CPU underneath another. Pre-STI
//! waits therefore use polled PIT slots; post-STI waits use Xenith's
//! non-destructive monotonic clock.

/// Minimum timeout used for controller and stream state transitions.
///
/// Intel HDA errata recommends allowing at least 10 ms for RUN bits to clear.
pub const HARDWARE_TIMEOUT_MS: u16 = 10;

/// Cheap register polls between wall-clock deadline checks.
const FAST_POLLS_PER_MILLISECOND: usize = 256;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct MillisecondBudget {
    remaining: u16,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct PollingBudget {
    milliseconds: MillisecondBudget,
    fast_remaining: usize,
    monotonic_deadline_ns: Option<u64>,
}

impl PollingBudget {
    fn new(milliseconds: u16) -> Self {
        let interrupts_enabled = crate::arch::x86_64::interrupts_enabled();
        let now_ns = if interrupts_enabled {
            crate::time::uptime_ns()
        } else {
            0
        };
        Self::from_clock_state(milliseconds, interrupts_enabled, now_ns)
    }

    const fn from_clock_state(milliseconds: u16, interrupts_enabled: bool, now_ns: u64) -> Self {
        Self {
            milliseconds: MillisecondBudget::new(milliseconds),
            fast_remaining: if milliseconds == 0 {
                0
            } else {
                FAST_POLLS_PER_MILLISECOND
            },
            monotonic_deadline_ns: if interrupts_enabled {
                Some(now_ns.saturating_add((milliseconds as u64).saturating_mul(1_000_000)))
            } else {
                None
            },
        }
    }

    fn poll_again(&mut self) -> bool {
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
    const fn new(milliseconds: u16) -> Self {
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

    fn wait_one(&mut self) -> bool {
        if !self.consume_one() {
            return false;
        }
        crate::time::pit::pit_sleep(1);
        true
    }
}

/// Poll immediately in bounded bursts until `ready` or the wall-time timeout.
pub fn until(milliseconds: u16, mut ready: impl FnMut() -> bool) -> bool {
    if ready() {
        return true;
    }
    let mut budget = PollingBudget::new(milliseconds);
    while budget.poll_again() {
        if ready() {
            return true;
        }
        core::hint::spin_loop();
    }
    false
}

/// Delay for at least `milliseconds` without reprogramming the PIT at runtime.
pub fn delay(milliseconds: u16) {
    if milliseconds == 0 {
        return;
    }
    if crate::arch::x86_64::interrupts_enabled() {
        let deadline = crate::time::uptime_ns()
            .saturating_add((milliseconds as u64).saturating_mul(1_000_000));
        while crate::time::uptime_ns() < deadline {
            core::hint::spin_loop();
        }
    } else {
        for _ in 0..milliseconds {
            crate::time::pit::pit_sleep(1);
        }
    }
}

/// Delay one millisecond using the same pre-STI/runtime clock policy.
pub fn one_millisecond() {
    delay(1);
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn millisecond_budget_is_exact_and_cannot_underflow() {
        let mut budget = MillisecondBudget::new(10);
        for _ in 0..10 {
            assert!(budget.consume_one());
        }
        assert!(!budget.consume_one());
        assert!(!budget.consume_one());
        assert_eq!(budget.remaining, 0);
    }

    #[test]
    fn zero_budget_expires_without_a_delay_slot() {
        let mut budget = MillisecondBudget::new(0);
        assert!(!budget.consume_one());
    }

    #[test]
    fn pre_sti_budget_selects_pit_slots() {
        let budget = PollingBudget::from_clock_state(10, false, 9_000_000);
        assert_eq!(budget.milliseconds.remaining, 10);
        assert_eq!(budget.monotonic_deadline_ns, None);
    }

    #[test]
    fn post_sti_budget_selects_non_destructive_monotonic_deadline() {
        let budget = PollingBudget::from_clock_state(10, true, 9_000_000);
        assert_eq!(budget.monotonic_deadline_ns, Some(19_000_000));

        let saturated = PollingBudget::from_clock_state(1_000, true, u64::MAX - 5);
        assert_eq!(saturated.monotonic_deadline_ns, Some(u64::MAX));
    }

    #[test]
    fn zero_polling_budget_starts_expired() {
        let budget = PollingBudget::from_clock_state(0, false, 0);
        assert_eq!(budget.fast_remaining, 0);
        assert_eq!(budget.milliseconds.remaining, 0);
    }
}
