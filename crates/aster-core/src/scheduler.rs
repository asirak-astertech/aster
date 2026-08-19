//! Priority, expiry, retry, and emission scheduling.

use crate::model::{ItemId, Priority};
use std::cmp::Ordering;
use std::collections::BinaryHeap;
use std::time::{Duration, Instant};

/// Operator-visible emission policy.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum EmissionPolicy {
    /// Transmit all unexpired items.
    Normal,
    /// Transmit only items at or above the given precedence.
    Threshold(Priority),
    /// Emit no framework inventory or item data. A connection-oriented adapter
    /// may still produce mandatory authentication or link acknowledgements.
    ReceiveOnly,
    /// Emit no framework-originated bytes; only passive protected broadcast can
    /// be ingested.
    PassiveOnly,
}

impl EmissionPolicy {
    /// Returns whether an outbound item is eligible.
    pub const fn permits(self, priority: Priority) -> bool {
        match self {
            Self::Normal => true,
            Self::Threshold(minimum) => priority as u8 >= minimum as u8,
            Self::ReceiveOnly | Self::PassiveOnly => false,
        }
    }

    /// Returns whether active discovery is permitted.
    pub const fn permits_discovery(self) -> bool {
        matches!(self, Self::Normal)
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct Candidate {
    item: ItemId,
    priority: Priority,
    expires_at: Option<Instant>,
    sequence: u64,
    attempt: u16,
}

impl Ord for Candidate {
    fn cmp(&self, other: &Self) -> Ordering {
        self.priority
            .cmp(&other.priority)
            .then_with(|| other.attempt.cmp(&self.attempt))
            .then_with(|| other.sequence.cmp(&self.sequence))
            .then_with(|| self.item.cmp(&other.item))
    }
}

impl PartialOrd for Candidate {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

/// A bounded-work outbound queue. It has no internal polling loop.
#[derive(Debug)]
pub struct Scheduler {
    queue: BinaryHeap<Candidate>,
    next_sequence: u64,
    policy: EmissionPolicy,
}

impl Scheduler {
    /// Creates an empty scheduler.
    pub const fn new(policy: EmissionPolicy) -> Self {
        Self {
            queue: BinaryHeap::new(),
            next_sequence: 0,
            policy,
        }
    }

    /// Applies a new operator emission policy.
    pub const fn set_policy(&mut self, policy: EmissionPolicy) {
        self.policy = policy;
    }

    /// Enqueues an object using a remaining lifetime measured by a monotonic clock.
    pub fn enqueue(
        &mut self,
        item: ItemId,
        priority: Priority,
        ttl: Option<Duration>,
        now: Instant,
    ) {
        let expires_at = ttl.and_then(|value| now.checked_add(value));
        self.queue.push(Candidate {
            item,
            priority,
            expires_at,
            sequence: self.next_sequence,
            attempt: 0,
        });
        self.next_sequence = self.next_sequence.wrapping_add(1);
    }

    /// Returns the next permitted, unexpired item, discarding expired work.
    pub fn pop(&mut self, now: Instant) -> Option<ItemId> {
        if matches!(
            self.policy,
            EmissionPolicy::ReceiveOnly | EmissionPolicy::PassiveOnly
        ) {
            return None;
        }
        let mut deferred = Vec::new();
        while let Some(candidate) = self.queue.pop() {
            if candidate.expires_at.is_some_and(|expiry| expiry <= now) {
                continue;
            }
            if self.policy.permits(candidate.priority) {
                self.queue.extend(deferred);
                return Some(candidate.item);
            }
            deferred.push(candidate);
        }
        self.queue.extend(deferred);
        None
    }

    /// Priority-sensitive retry delay with a bounded exponential factor.
    pub fn retry_delay(priority: Priority, attempt: u16) -> Duration {
        let base_ms = match priority {
            Priority::Flash => 125_u64,
            Priority::Immediate => 250,
            Priority::Priority => 500,
            Priority::Routine => 1_000,
        };
        let exponent = u32::from(attempt.min(6));
        Duration::from_millis(base_ms.saturating_mul(1_u64 << exponent))
    }

    /// Priority-sensitive retry delay clamped to a transport's safe floor.
    ///
    /// The link floor prevents an adapter from being driven faster than its
    /// framing or medium can tolerate, while precedence still controls the
    /// retry rate whenever the link permits it.
    pub fn retry_delay_with_floor(
        priority: Priority,
        attempt: u16,
        link_floor: Duration,
    ) -> Duration {
        Self::retry_delay(priority, attempt).max(link_floor)
    }
}

#[cfg(test)]
mod tests {
    use super::{EmissionPolicy, Scheduler};
    use crate::model::Priority;
    use std::time::{Duration, Instant};

    #[test]
    fn precedence_orders_transmission() {
        let now = Instant::now();
        let mut queue = Scheduler::new(EmissionPolicy::Normal);
        queue.enqueue([1; 32], Priority::Routine, None, now);
        queue.enqueue([2; 32], Priority::Flash, None, now);
        assert_eq!(queue.pop(now), Some([2; 32]));
    }

    #[test]
    fn expiry_is_independent_of_priority() {
        let now = Instant::now();
        let mut queue = Scheduler::new(EmissionPolicy::Normal);
        queue.enqueue([3; 32], Priority::Flash, Some(Duration::ZERO), now);
        queue.enqueue([4; 32], Priority::Routine, None, now);
        assert_eq!(queue.pop(now), Some([4; 32]));
    }

    #[test]
    fn receive_only_emits_nothing() {
        let now = Instant::now();
        let mut queue = Scheduler::new(EmissionPolicy::ReceiveOnly);
        queue.enqueue([5; 32], Priority::Flash, None, now);
        assert_eq!(queue.pop(now), None);
    }

    #[test]
    fn threshold_suppression_does_not_discard_work() {
        let now = Instant::now();
        let mut queue = Scheduler::new(EmissionPolicy::Threshold(Priority::Immediate));
        queue.enqueue([6; 32], Priority::Routine, None, now);
        assert_eq!(queue.pop(now), None);
        queue.set_policy(EmissionPolicy::Normal);
        assert_eq!(queue.pop(now), Some([6; 32]));
    }

    #[test]
    fn retry_floor_is_respected_without_erasing_precedence() {
        let floor = Duration::from_millis(200);
        assert_eq!(
            Scheduler::retry_delay_with_floor(Priority::Flash, 0, floor),
            floor
        );
        assert_eq!(
            Scheduler::retry_delay_with_floor(Priority::Routine, 0, floor),
            Duration::from_secs(1)
        );
        assert!(
            Scheduler::retry_delay_with_floor(Priority::Flash, 2, floor)
                < Scheduler::retry_delay_with_floor(Priority::Routine, 2, floor)
        );
    }
}
