//! Deterministic causality and projection helpers.

use crate::model::{CausalStamp, ItemId, VersionVector};

/// Relationship between two causal histories.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum CausalOrder {
    /// Both histories contain identical observations.
    Equal,
    /// The left history happened before the right history.
    Before,
    /// The left history happened after the right history.
    After,
    /// Neither history observes the other completely.
    Concurrent,
}

/// Compares two version vectors without consulting wall-clock time.
pub fn compare(left: &VersionVector, right: &VersionVector) -> CausalOrder {
    let mut left_greater = false;
    let mut right_greater = false;

    for (publisher, left_counter) in left.iter() {
        match (*left_counter).cmp(&right.counter(publisher)) {
            std::cmp::Ordering::Greater => left_greater = true,
            std::cmp::Ordering::Less => right_greater = true,
            std::cmp::Ordering::Equal => {}
        }
    }
    for (publisher, right_counter) in right.iter() {
        if !left.iter().any(|(candidate, _)| candidate == publisher) && *right_counter > 0 {
            right_greater = true;
        }
    }

    match (left_greater, right_greater) {
        (false, false) => CausalOrder::Equal,
        (false, true) => CausalOrder::Before,
        (true, false) => CausalOrder::After,
        (true, true) => CausalOrder::Concurrent,
    }
}

/// Compares complete stamps, including their own dots.
pub fn compare_stamps(left: &CausalStamp, right: &CausalStamp) -> CausalOrder {
    compare(&left.clock(), &right.clock())
}

/// Selects a deterministic current State projection while retaining both source
/// versions in storage. Causality wins first; a bytewise item-id tie-break is
/// used only for equal or concurrent histories.
pub fn state_projection(left: (&ItemId, &CausalStamp), right: (&ItemId, &CausalStamp)) -> ItemId {
    match compare_stamps(left.1, right.1) {
        CausalOrder::Before => *right.0,
        CausalOrder::After => *left.0,
        CausalOrder::Equal | CausalOrder::Concurrent => *left.0.max(right.0),
    }
}

#[cfg(test)]
mod tests {
    use super::{CausalOrder, compare, compare_stamps, state_projection};
    use crate::model::{CausalStamp, Dot, VersionVector};

    const A: [u8; 32] = [0x0a; 32];
    const B: [u8; 32] = [0x0b; 32];

    #[test]
    fn vector_comparison_detects_concurrency() {
        let mut left = VersionVector::default();
        left.observe(Dot {
            publisher: A,
            counter: 2,
        });
        let mut right = VersionVector::default();
        right.observe(Dot {
            publisher: B,
            counter: 1,
        });
        assert_eq!(compare(&left, &right), CausalOrder::Concurrent);
    }

    #[test]
    fn sequential_stamps_order_without_clocks() {
        let first = CausalStamp {
            dot: Dot {
                publisher: A,
                counter: 1,
            },
            context: VersionVector::default(),
        };
        let mut context = VersionVector::default();
        context.observe(first.dot);
        let second = CausalStamp {
            dot: Dot {
                publisher: B,
                counter: 1,
            },
            context,
        };
        assert_eq!(compare_stamps(&first, &second), CausalOrder::Before);
    }

    #[test]
    fn state_tie_break_is_deterministic() {
        let stamp_a = CausalStamp {
            dot: Dot {
                publisher: A,
                counter: 1,
            },
            context: VersionVector::default(),
        };
        let stamp_b = CausalStamp {
            dot: Dot {
                publisher: B,
                counter: 1,
            },
            context: VersionVector::default(),
        };
        let low = [1_u8; 32];
        let high = [2_u8; 32];
        assert_eq!(state_projection((&low, &stamp_a), (&high, &stamp_b)), high);
        assert_eq!(state_projection((&high, &stamp_b), (&low, &stamp_a)), high);
    }
}
