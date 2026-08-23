//! Aggregate process-level resource accounting for concurrent mesh contacts.
//!
//! Provider connection limits and per-channel bounds remain useful defenses,
//! but they do not prove a node-wide ceiling when several contacts are active.
//! This module supplies one provider-neutral budget whose RAII leases account
//! candidate, connection, task, frame, byte, descriptor, and relay resources
//! across every transport in the process.

use std::error::Error;
use std::fmt;
use std::sync::{Arc, Mutex};

const MAX_COUNT_LIMIT: usize = 1_048_576;
const MAX_BYTE_LIMIT: usize = 256 * 1_024 * 1_024;

/// Configurable node-wide ceilings. A zero ceiling explicitly disables that
/// resource class; zero-sized claims remain valid.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct NodeResourceLimits {
    pub candidates: usize,
    pub pending_connections: usize,
    pub pre_authentication_contacts: usize,
    pub admitted_contacts: usize,
    pub streams: usize,
    pub tasks: usize,
    pub frames: usize,
    pub inbound_bytes: usize,
    pub outbound_bytes: usize,
    pub descriptors: usize,
    pub relay_reservations: usize,
}

impl Default for NodeResourceLimits {
    fn default() -> Self {
        Self {
            candidates: 256,
            pending_connections: 32,
            pre_authentication_contacts: 8,
            admitted_contacts: 8,
            streams: 16,
            tasks: 64,
            frames: 8_192,
            inbound_bytes: 8 * 1_024 * 1_024,
            outbound_bytes: 8 * 1_024 * 1_024,
            descriptors: 128,
            relay_reservations: 8,
        }
    }
}

impl NodeResourceLimits {
    fn validate(self) -> Result<Self, ResourceBudgetError> {
        for (name, value) in self.count_fields() {
            if value > MAX_COUNT_LIMIT {
                return Err(ResourceBudgetError::InvalidLimit(name));
            }
        }
        if self.inbound_bytes > MAX_BYTE_LIMIT {
            return Err(ResourceBudgetError::InvalidLimit("inbound bytes"));
        }
        if self.outbound_bytes > MAX_BYTE_LIMIT {
            return Err(ResourceBudgetError::InvalidLimit("outbound bytes"));
        }
        Ok(self)
    }

    fn count_fields(self) -> [(&'static str, usize); 9] {
        [
            ("candidates", self.candidates),
            ("pending connections", self.pending_connections),
            (
                "pre-authentication contacts",
                self.pre_authentication_contacts,
            ),
            ("admitted contacts", self.admitted_contacts),
            ("streams", self.streams),
            ("tasks", self.tasks),
            ("frames", self.frames),
            ("descriptors", self.descriptors),
            ("relay reservations", self.relay_reservations),
        ]
    }
}

/// One exact resource reservation. Claims are intentionally plain values so a
/// provider can atomically transition a contact from pre-authentication to
/// admitted state without briefly releasing or double-reserving capacity.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct NodeResourceClaim {
    pub candidates: usize,
    pub pending_connections: usize,
    pub pre_authentication_contacts: usize,
    pub admitted_contacts: usize,
    pub streams: usize,
    pub tasks: usize,
    pub frames: usize,
    pub inbound_bytes: usize,
    pub outbound_bytes: usize,
    pub descriptors: usize,
    pub relay_reservations: usize,
}

impl NodeResourceClaim {
    fn checked_add(self, other: Self) -> Option<Self> {
        Some(Self {
            candidates: self.candidates.checked_add(other.candidates)?,
            pending_connections: self
                .pending_connections
                .checked_add(other.pending_connections)?,
            pre_authentication_contacts: self
                .pre_authentication_contacts
                .checked_add(other.pre_authentication_contacts)?,
            admitted_contacts: self
                .admitted_contacts
                .checked_add(other.admitted_contacts)?,
            streams: self.streams.checked_add(other.streams)?,
            tasks: self.tasks.checked_add(other.tasks)?,
            frames: self.frames.checked_add(other.frames)?,
            inbound_bytes: self.inbound_bytes.checked_add(other.inbound_bytes)?,
            outbound_bytes: self.outbound_bytes.checked_add(other.outbound_bytes)?,
            descriptors: self.descriptors.checked_add(other.descriptors)?,
            relay_reservations: self
                .relay_reservations
                .checked_add(other.relay_reservations)?,
        })
    }

    fn checked_sub(self, other: Self) -> Option<Self> {
        Some(Self {
            candidates: self.candidates.checked_sub(other.candidates)?,
            pending_connections: self
                .pending_connections
                .checked_sub(other.pending_connections)?,
            pre_authentication_contacts: self
                .pre_authentication_contacts
                .checked_sub(other.pre_authentication_contacts)?,
            admitted_contacts: self
                .admitted_contacts
                .checked_sub(other.admitted_contacts)?,
            streams: self.streams.checked_sub(other.streams)?,
            tasks: self.tasks.checked_sub(other.tasks)?,
            frames: self.frames.checked_sub(other.frames)?,
            inbound_bytes: self.inbound_bytes.checked_sub(other.inbound_bytes)?,
            outbound_bytes: self.outbound_bytes.checked_sub(other.outbound_bytes)?,
            descriptors: self.descriptors.checked_sub(other.descriptors)?,
            relay_reservations: self
                .relay_reservations
                .checked_sub(other.relay_reservations)?,
        })
    }

    fn first_excess(self, limits: NodeResourceLimits) -> Option<ResourceKind> {
        [
            (ResourceKind::Candidates, self.candidates, limits.candidates),
            (
                ResourceKind::PendingConnections,
                self.pending_connections,
                limits.pending_connections,
            ),
            (
                ResourceKind::PreAuthenticationContacts,
                self.pre_authentication_contacts,
                limits.pre_authentication_contacts,
            ),
            (
                ResourceKind::AdmittedContacts,
                self.admitted_contacts,
                limits.admitted_contacts,
            ),
            (ResourceKind::Streams, self.streams, limits.streams),
            (ResourceKind::Tasks, self.tasks, limits.tasks),
            (ResourceKind::Frames, self.frames, limits.frames),
            (
                ResourceKind::InboundBytes,
                self.inbound_bytes,
                limits.inbound_bytes,
            ),
            (
                ResourceKind::OutboundBytes,
                self.outbound_bytes,
                limits.outbound_bytes,
            ),
            (
                ResourceKind::Descriptors,
                self.descriptors,
                limits.descriptors,
            ),
            (
                ResourceKind::RelayReservations,
                self.relay_reservations,
                limits.relay_reservations,
            ),
        ]
        .into_iter()
        .find_map(|(resource, used, limit)| (used > limit).then_some(resource))
    }

    fn increment(&mut self, resource: ResourceKind) {
        let counter = match resource {
            ResourceKind::Candidates => &mut self.candidates,
            ResourceKind::PendingConnections => &mut self.pending_connections,
            ResourceKind::PreAuthenticationContacts => &mut self.pre_authentication_contacts,
            ResourceKind::AdmittedContacts => &mut self.admitted_contacts,
            ResourceKind::Streams => &mut self.streams,
            ResourceKind::Tasks => &mut self.tasks,
            ResourceKind::Frames => &mut self.frames,
            ResourceKind::InboundBytes => &mut self.inbound_bytes,
            ResourceKind::OutboundBytes => &mut self.outbound_bytes,
            ResourceKind::Descriptors => &mut self.descriptors,
            ResourceKind::RelayReservations => &mut self.relay_reservations,
        };
        *counter = counter.saturating_add(1);
    }

    fn component_max(self, other: Self) -> Self {
        Self {
            candidates: self.candidates.max(other.candidates),
            pending_connections: self.pending_connections.max(other.pending_connections),
            pre_authentication_contacts: self
                .pre_authentication_contacts
                .max(other.pre_authentication_contacts),
            admitted_contacts: self.admitted_contacts.max(other.admitted_contacts),
            streams: self.streams.max(other.streams),
            tasks: self.tasks.max(other.tasks),
            frames: self.frames.max(other.frames),
            inbound_bytes: self.inbound_bytes.max(other.inbound_bytes),
            outbound_bytes: self.outbound_bytes.max(other.outbound_bytes),
            descriptors: self.descriptors.max(other.descriptors),
            relay_reservations: self.relay_reservations.max(other.relay_reservations),
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum ResourceKind {
    Candidates,
    PendingConnections,
    PreAuthenticationContacts,
    AdmittedContacts,
    Streams,
    Tasks,
    Frames,
    InboundBytes,
    OutboundBytes,
    Descriptors,
    RelayReservations,
}

impl ResourceKind {
    fn name(self) -> &'static str {
        match self {
            Self::Candidates => "candidates",
            Self::PendingConnections => "pending connections",
            Self::PreAuthenticationContacts => "pre-authentication contacts",
            Self::AdmittedContacts => "admitted contacts",
            Self::Streams => "streams",
            Self::Tasks => "tasks",
            Self::Frames => "frames",
            Self::InboundBytes => "inbound bytes",
            Self::OutboundBytes => "outbound bytes",
            Self::Descriptors => "descriptors",
            Self::RelayReservations => "relay reservations",
        }
    }
}

/// Stable node-wide usage and high-water evidence.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct NodeResourceSnapshot {
    pub limits: NodeResourceLimits,
    pub current: NodeResourceClaim,
    pub high_water: NodeResourceClaim,
    /// Saturating rejection counters with the same resource-shaped fields as
    /// a claim. These are evidence counters, not an active reservation.
    pub rejections: NodeResourceClaim,
    /// Aggregate rejection count retained for receipt/API compatibility.
    pub rejected_claims: u64,
}

/// A bounded resource-accounting failure.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum ResourceBudgetError {
    InvalidLimit(&'static str),
    Capacity(&'static str),
    Arithmetic,
    Poisoned,
    Released,
}

impl fmt::Display for ResourceBudgetError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidLimit(resource) => write!(formatter, "invalid {resource} limit"),
            Self::Capacity(resource) => write!(formatter, "node-wide {resource} budget exhausted"),
            Self::Arithmetic => formatter.write_str("node resource accounting overflow"),
            Self::Poisoned => formatter.write_str("node resource budget lock is poisoned"),
            Self::Released => formatter.write_str("node resource lease was already released"),
        }
    }
}

impl Error for ResourceBudgetError {}

#[derive(Debug)]
struct BudgetState {
    limits: NodeResourceLimits,
    current: NodeResourceClaim,
    high_water: NodeResourceClaim,
    rejections: NodeResourceClaim,
    rejected_claims: u64,
}

/// Cloneable handle to one process-level resource authority.
#[derive(Clone, Debug)]
pub struct NodeResourceBudget {
    state: Arc<Mutex<BudgetState>>,
}

impl NodeResourceBudget {
    pub fn new(limits: NodeResourceLimits) -> Result<Self, ResourceBudgetError> {
        Ok(Self {
            state: Arc::new(Mutex::new(BudgetState {
                limits: limits.validate()?,
                current: NodeResourceClaim::default(),
                high_water: NodeResourceClaim::default(),
                rejections: NodeResourceClaim::default(),
                rejected_claims: 0,
            })),
        })
    }

    /// Atomically reserves the whole claim or changes no counters.
    pub fn try_reserve(
        &self,
        claim: NodeResourceClaim,
    ) -> Result<NodeResourceLease, ResourceBudgetError> {
        let mut state = self
            .state
            .lock()
            .map_err(|_| ResourceBudgetError::Poisoned)?;
        let next = state
            .current
            .checked_add(claim)
            .ok_or(ResourceBudgetError::Arithmetic)?;
        if let Some(resource) = next.first_excess(state.limits) {
            state.rejections.increment(resource);
            state.rejected_claims = state.rejected_claims.saturating_add(1);
            return Err(ResourceBudgetError::Capacity(resource.name()));
        }
        state.current = next;
        state.high_water = state.high_water.component_max(next);
        Ok(NodeResourceLease {
            state: Arc::clone(&self.state),
            claim,
            active: true,
        })
    }

    pub fn snapshot(&self) -> Result<NodeResourceSnapshot, ResourceBudgetError> {
        let state = self
            .state
            .lock()
            .map_err(|_| ResourceBudgetError::Poisoned)?;
        Ok(NodeResourceSnapshot {
            limits: state.limits,
            current: state.current,
            high_water: state.high_water,
            rejections: state.rejections,
            rejected_claims: state.rejected_claims,
        })
    }
}

/// RAII reservation against one [`NodeResourceBudget`].
#[derive(Debug)]
pub struct NodeResourceLease {
    state: Arc<Mutex<BudgetState>>,
    claim: NodeResourceClaim,
    active: bool,
}

impl NodeResourceLease {
    pub fn claim(&self) -> NodeResourceClaim {
        self.claim
    }

    /// Atomically transitions this lease, for example from a pre-authentication
    /// contact to an admitted contact, without creating a release/reacquire gap.
    pub fn replace(&mut self, claim: NodeResourceClaim) -> Result<(), ResourceBudgetError> {
        if !self.active {
            return Err(ResourceBudgetError::Released);
        }
        let mut state = self
            .state
            .lock()
            .map_err(|_| ResourceBudgetError::Poisoned)?;
        let base = state
            .current
            .checked_sub(self.claim)
            .ok_or(ResourceBudgetError::Arithmetic)?;
        let next = base
            .checked_add(claim)
            .ok_or(ResourceBudgetError::Arithmetic)?;
        if let Some(resource) = next.first_excess(state.limits) {
            state.rejections.increment(resource);
            state.rejected_claims = state.rejected_claims.saturating_add(1);
            return Err(ResourceBudgetError::Capacity(resource.name()));
        }
        state.current = next;
        state.high_water = state.high_water.component_max(next);
        self.claim = claim;
        Ok(())
    }

    pub fn release(mut self) -> Result<(), ResourceBudgetError> {
        self.release_inner()
    }

    fn release_inner(&mut self) -> Result<(), ResourceBudgetError> {
        if !self.active {
            return Err(ResourceBudgetError::Released);
        }
        let mut state = self
            .state
            .lock()
            .map_err(|_| ResourceBudgetError::Poisoned)?;
        state.current = state
            .current
            .checked_sub(self.claim)
            .ok_or(ResourceBudgetError::Arithmetic)?;
        self.active = false;
        self.claim = NodeResourceClaim::default();
        Ok(())
    }
}

impl Drop for NodeResourceLease {
    fn drop(&mut self) {
        if self.active {
            // A poisoned accounting authority cannot safely be repaired by a
            // lease destructor. Preserve fail-closed behavior for all future
            // operations rather than inventing usage after an unwind.
            let _ = self.release_inner();
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::panic::{AssertUnwindSafe, catch_unwind};
    use std::sync::Barrier;
    use std::thread;

    fn limits() -> NodeResourceLimits {
        NodeResourceLimits {
            candidates: 2,
            pending_connections: 2,
            pre_authentication_contacts: 2,
            admitted_contacts: 1,
            streams: 2,
            tasks: 4,
            frames: 4,
            inbound_bytes: 100,
            outbound_bytes: 80,
            descriptors: 4,
            relay_reservations: 1,
        }
    }

    fn unit_limits() -> NodeResourceLimits {
        NodeResourceLimits {
            candidates: 1,
            pending_connections: 1,
            pre_authentication_contacts: 1,
            admitted_contacts: 1,
            streams: 1,
            tasks: 1,
            frames: 1,
            inbound_bytes: 1,
            outbound_bytes: 1,
            descriptors: 1,
            relay_reservations: 1,
        }
    }

    fn unit_resource_cases() -> [(&'static str, NodeResourceClaim); 11] {
        [
            (
                "candidates",
                NodeResourceClaim {
                    candidates: 1,
                    ..NodeResourceClaim::default()
                },
            ),
            (
                "pending connections",
                NodeResourceClaim {
                    pending_connections: 1,
                    ..NodeResourceClaim::default()
                },
            ),
            (
                "pre-authentication contacts",
                NodeResourceClaim {
                    pre_authentication_contacts: 1,
                    ..NodeResourceClaim::default()
                },
            ),
            (
                "admitted contacts",
                NodeResourceClaim {
                    admitted_contacts: 1,
                    ..NodeResourceClaim::default()
                },
            ),
            (
                "streams",
                NodeResourceClaim {
                    streams: 1,
                    ..NodeResourceClaim::default()
                },
            ),
            (
                "tasks",
                NodeResourceClaim {
                    tasks: 1,
                    ..NodeResourceClaim::default()
                },
            ),
            (
                "frames",
                NodeResourceClaim {
                    frames: 1,
                    ..NodeResourceClaim::default()
                },
            ),
            (
                "inbound bytes",
                NodeResourceClaim {
                    inbound_bytes: 1,
                    ..NodeResourceClaim::default()
                },
            ),
            (
                "outbound bytes",
                NodeResourceClaim {
                    outbound_bytes: 1,
                    ..NodeResourceClaim::default()
                },
            ),
            (
                "descriptors",
                NodeResourceClaim {
                    descriptors: 1,
                    ..NodeResourceClaim::default()
                },
            ),
            (
                "relay reservations",
                NodeResourceClaim {
                    relay_reservations: 1,
                    ..NodeResourceClaim::default()
                },
            ),
        ]
    }

    #[test]
    fn parallel_barrier_race_is_atomic_at_every_resource_limit() {
        for (resource, claim) in unit_resource_cases() {
            let budget = NodeResourceBudget::new(unit_limits()).unwrap();
            let start = Arc::new(Barrier::new(3));
            let attempted = Arc::new(Barrier::new(3));
            let mut contenders = Vec::new();
            for _ in 0..2 {
                let contender_budget = budget.clone();
                let contender_start = Arc::clone(&start);
                let contender_attempted = Arc::clone(&attempted);
                contenders.push(thread::spawn(move || {
                    contender_start.wait();
                    let outcome = contender_budget.try_reserve(claim);
                    contender_attempted.wait();
                    outcome
                }));
            }

            start.wait();
            attempted.wait();
            let outcomes = contenders
                .into_iter()
                .map(|contender| contender.join().unwrap())
                .collect::<Vec<_>>();
            assert_eq!(outcomes.iter().filter(|outcome| outcome.is_ok()).count(), 1);
            assert_eq!(
                outcomes
                    .iter()
                    .filter_map(|outcome| outcome.as_ref().err())
                    .collect::<Vec<_>>(),
                vec![&ResourceBudgetError::Capacity(resource)]
            );

            let during = budget.snapshot().unwrap();
            assert_eq!(during.current, claim);
            assert_eq!(during.high_water, claim);
            assert_eq!(during.rejections, claim);
            assert_eq!(during.rejected_claims, 1);
            assert_eq!(during.high_water.first_excess(during.limits), None);

            drop(outcomes);
            assert_eq!(
                budget.snapshot().unwrap().current,
                NodeResourceClaim::default()
            );
        }
    }

    #[test]
    fn lease_drop_during_unwind_releases_capacity_for_recovery() {
        let budget = NodeResourceBudget::new(unit_limits()).unwrap();
        let unwind_budget = budget.clone();
        let panic = catch_unwind(AssertUnwindSafe(move || {
            let _lease = unwind_budget
                .try_reserve(NodeResourceClaim {
                    tasks: 1,
                    descriptors: 1,
                    ..NodeResourceClaim::default()
                })
                .unwrap();
            panic!("injected provider task termination");
        }));
        assert!(panic.is_err());
        assert_eq!(
            budget.snapshot().unwrap().current,
            NodeResourceClaim::default()
        );
        assert!(
            budget
                .try_reserve(NodeResourceClaim {
                    tasks: 1,
                    descriptors: 1,
                    ..NodeResourceClaim::default()
                })
                .is_ok()
        );
    }

    #[test]
    fn repeated_full_vector_connection_churn_never_leaks_or_exceeds_limits() {
        let budget = NodeResourceBudget::new(unit_limits()).unwrap();
        let full = NodeResourceClaim {
            candidates: 1,
            pending_connections: 1,
            pre_authentication_contacts: 1,
            admitted_contacts: 1,
            streams: 1,
            tasks: 1,
            frames: 1,
            inbound_bytes: 1,
            outbound_bytes: 1,
            descriptors: 1,
            relay_reservations: 1,
        };
        for _ in 0..4_096 {
            let lease = budget.try_reserve(full).unwrap();
            assert_eq!(lease.claim(), full);
            drop(lease);
        }
        let snapshot = budget.snapshot().unwrap();
        assert_eq!(snapshot.current, NodeResourceClaim::default());
        assert_eq!(snapshot.high_water, full);
        assert_eq!(snapshot.high_water.first_excess(snapshot.limits), None);
        assert_eq!(snapshot.rejections, NodeResourceClaim::default());
        assert_eq!(snapshot.rejected_claims, 0);
    }

    #[test]
    fn lifecycle_replace_is_atomic_under_capacity_failure_and_churn() {
        let budget = NodeResourceBudget::new(unit_limits()).unwrap();
        let existing = budget
            .try_reserve(NodeResourceClaim {
                admitted_contacts: 1,
                ..NodeResourceClaim::default()
            })
            .unwrap();
        let pre_authentication = NodeResourceClaim {
            pre_authentication_contacts: 1,
            streams: 1,
            tasks: 1,
            frames: 1,
            inbound_bytes: 1,
            outbound_bytes: 1,
            descriptors: 1,
            ..NodeResourceClaim::default()
        };
        let admitted = NodeResourceClaim {
            pre_authentication_contacts: 0,
            admitted_contacts: 1,
            ..pre_authentication
        };
        let mut contact = budget.try_reserve(pre_authentication).unwrap();
        assert_eq!(
            contact.replace(admitted),
            Err(ResourceBudgetError::Capacity("admitted contacts"))
        );
        assert_eq!(contact.claim(), pre_authentication);
        let failed = budget.snapshot().unwrap();
        assert_eq!(
            failed.current,
            pre_authentication
                .checked_add(NodeResourceClaim {
                    admitted_contacts: 1,
                    ..NodeResourceClaim::default()
                })
                .unwrap()
        );
        assert_eq!(failed.high_water.first_excess(failed.limits), None);

        drop(existing);
        for _ in 0..4_096 {
            contact.replace(admitted).unwrap();
            assert_eq!(contact.claim(), admitted);
            contact.replace(pre_authentication).unwrap();
        }
        drop(contact);
        let recovered = budget.snapshot().unwrap();
        assert_eq!(recovered.current, NodeResourceClaim::default());
        assert_eq!(recovered.high_water.first_excess(recovered.limits), None);
        assert_eq!(recovered.rejections.admitted_contacts, 1);
        assert_eq!(recovered.rejected_claims, 1);
    }

    #[test]
    fn leases_enforce_one_aggregate_byte_ceiling_and_release_on_drop() {
        let budget = NodeResourceBudget::new(limits()).unwrap();
        let first = budget
            .try_reserve(NodeResourceClaim {
                frames: 1,
                inbound_bytes: 60,
                ..NodeResourceClaim::default()
            })
            .unwrap();
        let error = budget
            .try_reserve(NodeResourceClaim {
                frames: 1,
                inbound_bytes: 41,
                ..NodeResourceClaim::default()
            })
            .unwrap_err();
        assert_eq!(error, ResourceBudgetError::Capacity("inbound bytes"));
        assert_eq!(budget.snapshot().unwrap().current.inbound_bytes, 60);
        drop(first);
        assert_eq!(budget.snapshot().unwrap().current.inbound_bytes, 0);
        assert!(
            budget
                .try_reserve(NodeResourceClaim {
                    inbound_bytes: 100,
                    ..NodeResourceClaim::default()
                })
                .is_ok()
        );
    }

    #[test]
    fn contact_admission_transition_is_atomic_and_preserves_old_claim_on_failure() {
        let budget = NodeResourceBudget::new(limits()).unwrap();
        let _existing = budget
            .try_reserve(NodeResourceClaim {
                admitted_contacts: 1,
                ..NodeResourceClaim::default()
            })
            .unwrap();
        let mut pending = budget
            .try_reserve(NodeResourceClaim {
                pre_authentication_contacts: 1,
                streams: 1,
                tasks: 2,
                ..NodeResourceClaim::default()
            })
            .unwrap();
        let error = pending
            .replace(NodeResourceClaim {
                admitted_contacts: 1,
                streams: 1,
                tasks: 2,
                ..NodeResourceClaim::default()
            })
            .unwrap_err();
        assert_eq!(error, ResourceBudgetError::Capacity("admitted contacts"));
        assert_eq!(pending.claim().pre_authentication_contacts, 1);
        let snapshot = budget.snapshot().unwrap();
        assert_eq!(snapshot.current.pre_authentication_contacts, 1);
        assert_eq!(snapshot.current.admitted_contacts, 1);
        assert_eq!(snapshot.rejections.admitted_contacts, 1);
        assert_eq!(snapshot.rejected_claims, 1);
    }

    #[test]
    fn high_water_and_rejections_are_process_wide_across_clones() {
        let budget = NodeResourceBudget::new(limits()).unwrap();
        let clone = budget.clone();
        let first = budget
            .try_reserve(NodeResourceClaim {
                tasks: 2,
                outbound_bytes: 50,
                ..NodeResourceClaim::default()
            })
            .unwrap();
        let second = clone
            .try_reserve(NodeResourceClaim {
                tasks: 2,
                outbound_bytes: 30,
                ..NodeResourceClaim::default()
            })
            .unwrap();
        assert!(
            clone
                .try_reserve(NodeResourceClaim {
                    tasks: 1,
                    ..NodeResourceClaim::default()
                })
                .is_err()
        );
        drop(first);
        drop(second);
        let snapshot = budget.snapshot().unwrap();
        assert_eq!(snapshot.current, NodeResourceClaim::default());
        assert_eq!(snapshot.high_water.tasks, 4);
        assert_eq!(snapshot.high_water.outbound_bytes, 80);
        assert_eq!(snapshot.rejections.tasks, 1);
        assert_eq!(snapshot.rejected_claims, 1);
    }

    #[test]
    fn invalid_limits_fail_before_the_budget_is_shared() {
        let mut invalid = limits();
        invalid.inbound_bytes = MAX_BYTE_LIMIT + 1;
        assert_eq!(
            NodeResourceBudget::new(invalid).unwrap_err(),
            ResourceBudgetError::InvalidLimit("inbound bytes")
        );
    }

    #[test]
    fn every_accounted_resource_rejects_a_claim_above_its_node_limit() {
        let exact = limits();
        let claims = [
            (
                "candidates",
                NodeResourceClaim {
                    candidates: exact.candidates + 1,
                    ..NodeResourceClaim::default()
                },
                NodeResourceClaim {
                    candidates: 1,
                    ..NodeResourceClaim::default()
                },
            ),
            (
                "pending connections",
                NodeResourceClaim {
                    pending_connections: exact.pending_connections + 1,
                    ..NodeResourceClaim::default()
                },
                NodeResourceClaim {
                    pending_connections: 1,
                    ..NodeResourceClaim::default()
                },
            ),
            (
                "pre-authentication contacts",
                NodeResourceClaim {
                    pre_authentication_contacts: exact.pre_authentication_contacts + 1,
                    ..NodeResourceClaim::default()
                },
                NodeResourceClaim {
                    pre_authentication_contacts: 1,
                    ..NodeResourceClaim::default()
                },
            ),
            (
                "admitted contacts",
                NodeResourceClaim {
                    admitted_contacts: exact.admitted_contacts + 1,
                    ..NodeResourceClaim::default()
                },
                NodeResourceClaim {
                    admitted_contacts: 1,
                    ..NodeResourceClaim::default()
                },
            ),
            (
                "streams",
                NodeResourceClaim {
                    streams: exact.streams + 1,
                    ..NodeResourceClaim::default()
                },
                NodeResourceClaim {
                    streams: 1,
                    ..NodeResourceClaim::default()
                },
            ),
            (
                "tasks",
                NodeResourceClaim {
                    tasks: exact.tasks + 1,
                    ..NodeResourceClaim::default()
                },
                NodeResourceClaim {
                    tasks: 1,
                    ..NodeResourceClaim::default()
                },
            ),
            (
                "frames",
                NodeResourceClaim {
                    frames: exact.frames + 1,
                    ..NodeResourceClaim::default()
                },
                NodeResourceClaim {
                    frames: 1,
                    ..NodeResourceClaim::default()
                },
            ),
            (
                "inbound bytes",
                NodeResourceClaim {
                    inbound_bytes: exact.inbound_bytes + 1,
                    ..NodeResourceClaim::default()
                },
                NodeResourceClaim {
                    inbound_bytes: 1,
                    ..NodeResourceClaim::default()
                },
            ),
            (
                "outbound bytes",
                NodeResourceClaim {
                    outbound_bytes: exact.outbound_bytes + 1,
                    ..NodeResourceClaim::default()
                },
                NodeResourceClaim {
                    outbound_bytes: 1,
                    ..NodeResourceClaim::default()
                },
            ),
            (
                "descriptors",
                NodeResourceClaim {
                    descriptors: exact.descriptors + 1,
                    ..NodeResourceClaim::default()
                },
                NodeResourceClaim {
                    descriptors: 1,
                    ..NodeResourceClaim::default()
                },
            ),
            (
                "relay reservations",
                NodeResourceClaim {
                    relay_reservations: exact.relay_reservations + 1,
                    ..NodeResourceClaim::default()
                },
                NodeResourceClaim {
                    relay_reservations: 1,
                    ..NodeResourceClaim::default()
                },
            ),
        ];
        for (resource, claim, expected_rejections) in claims {
            let budget = NodeResourceBudget::new(exact).unwrap();
            assert_eq!(
                budget.try_reserve(claim).unwrap_err(),
                ResourceBudgetError::Capacity(resource)
            );
            let snapshot = budget.snapshot().unwrap();
            assert_eq!(snapshot.current, NodeResourceClaim::default());
            assert_eq!(snapshot.rejections, expected_rejections);
            assert_eq!(snapshot.rejected_claims, 1);
        }
    }

    #[test]
    fn one_failed_claim_counts_only_the_first_exhausted_resource() {
        let exact = limits();
        let budget = NodeResourceBudget::new(exact).unwrap();
        assert_eq!(
            budget
                .try_reserve(NodeResourceClaim {
                    candidates: exact.candidates + 1,
                    frames: exact.frames + 1,
                    ..NodeResourceClaim::default()
                })
                .unwrap_err(),
            ResourceBudgetError::Capacity("candidates")
        );
        let snapshot = budget.snapshot().unwrap();
        assert_eq!(snapshot.rejections.candidates, 1);
        assert_eq!(snapshot.rejections.frames, 0);
        assert_eq!(snapshot.rejected_claims, 1);
    }
}
