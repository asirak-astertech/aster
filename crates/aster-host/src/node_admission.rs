//! Atomic composition of host policy, node-wide capacity, and durable runtime
//! admission.
//!
//! Carrier authentication is only a prerequisite. A contact becomes admitted
//! after [`MeshHost`] prepares a single-use decision, its process-wide resource
//! lease is upgraded, and the live Aster authority accepts it. Until the final
//! host commit, no carrier identity or authenticated peer binding is visible.

use crate::{
    ContactId, HostAction, MeshHost, MeshHostError, NodeResourceClaim, NodeResourceLease,
    ResourceBudgetError,
};
use aster_mesh::NodeId;
use std::error::Error;
use std::fmt;
use std::panic::{AssertUnwindSafe, catch_unwind, resume_unwind};
use std::time::Instant;

/// Result of one complete admission transaction.
#[derive(Debug)]
pub(crate) enum AdmissionTransaction {
    /// Policy requires one or more contacts to close before this contact may
    /// be reconsidered. Durable authorization was not called.
    Rejected { actions: Vec<HostAction> },
    /// Resource and durable authorization succeeded and host state committed.
    Admitted { actions: Vec<HostAction> },
}

/// Fail-closed admission-composition error.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum AdmissionTransactionError {
    Host(MeshHostError),
    Resource(ResourceBudgetError),
    Authorization(String),
    ResourceRollback(ResourceBudgetError),
}

impl fmt::Display for AdmissionTransactionError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Host(error) => write!(formatter, "mesh host admission failed: {error}"),
            Self::Resource(error) => write!(formatter, "node resource admission failed: {error}"),
            Self::Authorization(error) => {
                write!(formatter, "durable Aster admission failed: {error}")
            }
            Self::ResourceRollback(error) => {
                write!(
                    formatter,
                    "node resource admission rollback failed: {error}"
                )
            }
        }
    }
}

impl Error for AdmissionTransactionError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        match self {
            Self::Host(error) => Some(error),
            Self::Resource(error) | Self::ResourceRollback(error) => Some(error),
            Self::Authorization(_) => None,
        }
    }
}

/// Performs one non-yielding admission transaction.
///
/// The callback is invoked only after host policy prepared a token and the
/// aggregate lease upgraded successfully. On callback failure, host state and
/// resource accounting are restored. On a late host-commit failure, the
/// callback result is discarded and the caller must drop the unadmitted
/// session before pumping it again.
pub(crate) fn transact_authenticated<F>(
    host: &mut MeshHost,
    lease: &mut NodeResourceLease,
    admitted_claim: NodeResourceClaim,
    contact: ContactId,
    peer: NodeId,
    now: Instant,
    authorize: F,
) -> Result<AdmissionTransaction, AdmissionTransactionError>
where
    F: FnOnce() -> Result<(), String>,
{
    let (token, actions) = host
        .prepare_authenticated(contact, peer)
        .map_err(AdmissionTransactionError::Host)?
        .into_parts();
    let Some(token) = token else {
        return Ok(AdmissionTransaction::Rejected { actions });
    };

    let pre_authentication_claim = lease.claim();
    if let Err(error) = lease.replace(admitted_claim) {
        host.abort_authenticated(token)
            .map_err(AdmissionTransactionError::Host)?;
        return Err(AdmissionTransactionError::Resource(error));
    }

    match catch_unwind(AssertUnwindSafe(authorize)) {
        Ok(Ok(())) => {}
        Ok(Err(error)) => {
            host.abort_authenticated(token)
                .map_err(AdmissionTransactionError::Host)?;
            lease
                .replace(pre_authentication_claim)
                .map_err(AdmissionTransactionError::ResourceRollback)?;
            return Err(AdmissionTransactionError::Authorization(error));
        }
        Err(payload) => {
            // Both rollback operations are fail-closed and non-panicking. If
            // either authority is already poisoned/stale, its subsequent API
            // calls will continue to reject work; preserve the original panic
            // after making the best possible deterministic cleanup.
            let _ = host.abort_authenticated(token);
            let _ = lease.replace(pre_authentication_claim);
            resume_unwind(payload);
        }
    }

    match host.commit_authenticated(token, now) {
        Ok(commit_actions) => Ok(AdmissionTransaction::Admitted {
            actions: commit_actions,
        }),
        Err(error) => {
            lease
                .replace(pre_authentication_claim)
                .map_err(AdmissionTransactionError::ResourceRollback)?;
            Err(AdmissionTransactionError::Host(error))
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        CandidateId, CandidateLocator, CandidateProvenance, CarrierIdentity, ContactDirection,
        ContactPath, HostConfig, HostEvent, NodeResourceBudget, NodeResourceLimits,
    };
    use aster_mesh::EmissionPolicy;
    use std::cell::{Cell, RefCell};
    use std::time::Duration;

    fn fixture() -> (
        MeshHost,
        NodeResourceBudget,
        NodeResourceLease,
        Instant,
        NodeId,
    ) {
        let now = Instant::now();
        let peer = [44; 32];
        let candidate = CandidateId::new("candidate-044").unwrap();
        let locator = CandidateLocator::new("/ip4/192.0.2.44/tcp/4000").unwrap();
        let mut host = MeshHost::new(
            HostConfig {
                max_candidates: 4,
                max_active_contacts: 1,
                candidate_ttl: Duration::from_secs(60),
                contact_quantum: Duration::from_secs(10),
                reconnect_initial: Duration::from_millis(100),
                reconnect_max: Duration::from_secs(1),
            },
            EmissionPolicy::default(),
        )
        .unwrap();
        host.handle_event(
            HostEvent::CandidateObserved {
                candidate: candidate.clone(),
                locator: locator.clone(),
                provenance: CandidateProvenance::Manual,
                path: ContactPath::Direct,
                expected_peer: Some(peer),
            },
            now,
        )
        .unwrap();
        host.handle_event(
            HostEvent::ContactOpened {
                contact: ContactId(44),
                candidate,
                locator,
                carrier_identity: Some(CarrierIdentity::new(vec![44; 32]).unwrap()),
                direction: ContactDirection::Inbound,
                path: ContactPath::Direct,
            },
            now,
        )
        .unwrap();
        let budget = NodeResourceBudget::new(NodeResourceLimits {
            pre_authentication_contacts: 1,
            admitted_contacts: 1,
            ..NodeResourceLimits::default()
        })
        .unwrap();
        let lease = budget
            .try_reserve(NodeResourceClaim {
                pre_authentication_contacts: 1,
                ..NodeResourceClaim::default()
            })
            .unwrap();
        (host, budget, lease, now, peer)
    }

    fn admitted_claim() -> NodeResourceClaim {
        NodeResourceClaim {
            admitted_contacts: 1,
            ..NodeResourceClaim::default()
        }
    }

    #[test]
    fn authorization_failure_restores_host_and_resource_state() {
        let (mut host, _budget, mut lease, now, peer) = fixture();
        let called = Cell::new(false);
        assert!(matches!(
            transact_authenticated(
                &mut host,
                &mut lease,
                admitted_claim(),
                ContactId(44),
                peer,
                now,
                || {
                    called.set(true);
                    Err::<(), _>("denied".into())
                },
            ),
            Err(AdmissionTransactionError::Authorization(message)) if message == "denied"
        ));
        assert!(called.get());
        assert_eq!(
            lease.claim(),
            NodeResourceClaim {
                pre_authentication_contacts: 1,
                ..NodeResourceClaim::default()
            }
        );
        let snapshot = host.snapshot();
        assert_eq!(snapshot.pending_admissions, 0);
        assert_eq!(snapshot.authenticated_contacts, 0);
        assert_eq!(snapshot.carrier_binding_count, 0);
    }

    #[test]
    fn concurrent_claim_makes_resource_rollback_fail_closed_without_host_admission() {
        let (mut host, budget, mut lease, now, peer) = fixture();
        let blocking_lease = RefCell::new(None);
        assert!(matches!(
            transact_authenticated(
                &mut host,
                &mut lease,
                admitted_claim(),
                ContactId(44),
                peer,
                now,
                || {
                    *blocking_lease.borrow_mut() = Some(
                        budget
                            .try_reserve(NodeResourceClaim {
                                pre_authentication_contacts: 1,
                                ..NodeResourceClaim::default()
                            })
                            .unwrap(),
                    );
                    Err::<(), _>("denied after competing claim".into())
                },
            ),
            Err(AdmissionTransactionError::ResourceRollback(
                ResourceBudgetError::Capacity("pre-authentication contacts")
            ))
        ));

        // The failed replacement is atomic: the original lease remains on
        // the admitted claim, while the competing lease owns the only
        // pre-authentication slot. Host authority was aborted before rollback.
        assert_eq!(lease.claim(), admitted_claim());
        let snapshot = budget.snapshot().unwrap();
        assert_eq!(snapshot.current.admitted_contacts, 1);
        assert_eq!(snapshot.current.pre_authentication_contacts, 1);
        assert_eq!(snapshot.rejections.pre_authentication_contacts, 1);
        assert_eq!(snapshot.rejected_claims, 1);
        let host_snapshot = host.snapshot();
        assert_eq!(host_snapshot.pending_admissions, 0);
        assert_eq!(host_snapshot.authenticated_contacts, 0);
        assert_eq!(host_snapshot.carrier_binding_count, 0);

        drop(blocking_lease.into_inner());
        drop(lease);
        assert_eq!(
            budget.snapshot().unwrap().current,
            NodeResourceClaim::default()
        );
    }

    #[test]
    fn successful_transaction_commits_host_and_admitted_budget_together() {
        let (mut host, _budget, mut lease, now, peer) = fixture();
        let called = Cell::new(false);
        let outcome = transact_authenticated(
            &mut host,
            &mut lease,
            admitted_claim(),
            ContactId(44),
            peer,
            now,
            || {
                called.set(true);
                Ok(())
            },
        )
        .unwrap();
        match outcome {
            AdmissionTransaction::Admitted { actions } => assert!(actions.is_empty()),
            AdmissionTransaction::Rejected { .. } => panic!("admission unexpectedly rejected"),
        }
        assert!(called.get());
        assert_eq!(lease.claim(), admitted_claim());
        let snapshot = host.snapshot();
        assert_eq!(snapshot.pending_admissions, 0);
        assert_eq!(snapshot.authenticated_contacts, 1);
        assert_eq!(snapshot.carrier_binding_count, 1);
    }

    #[test]
    fn resource_failure_never_invokes_durable_authorization() {
        let (mut host, _budget, mut lease, now, peer) = fixture();
        let called = Cell::new(false);
        let over_budget = NodeResourceClaim {
            admitted_contacts: 2,
            ..NodeResourceClaim::default()
        };
        assert!(matches!(
            transact_authenticated(
                &mut host,
                &mut lease,
                over_budget,
                ContactId(44),
                peer,
                now,
                || {
                    called.set(true);
                    Ok(())
                },
            ),
            Err(AdmissionTransactionError::Resource(
                ResourceBudgetError::Capacity("admitted contacts")
            ))
        ));
        assert!(!called.get());
        let snapshot = host.snapshot();
        assert_eq!(snapshot.pending_admissions, 0);
        assert_eq!(snapshot.authenticated_contacts, 0);
        assert_eq!(snapshot.carrier_binding_count, 0);
    }

    #[test]
    fn panicking_authorization_rolls_back_before_resuming_unwind() {
        let (mut host, _budget, mut lease, now, peer) = fixture();
        let panic = catch_unwind(AssertUnwindSafe(|| {
            let _ = transact_authenticated(
                &mut host,
                &mut lease,
                admitted_claim(),
                ContactId(44),
                peer,
                now,
                || panic!("injected authorization panic"),
            );
        }));
        assert!(panic.is_err());
        assert_eq!(
            lease.claim(),
            NodeResourceClaim {
                pre_authentication_contacts: 1,
                ..NodeResourceClaim::default()
            }
        );
        let snapshot = host.snapshot();
        assert_eq!(snapshot.pending_admissions, 0);
        assert_eq!(snapshot.authenticated_contacts, 0);
        assert_eq!(snapshot.carrier_binding_count, 0);
    }
}
