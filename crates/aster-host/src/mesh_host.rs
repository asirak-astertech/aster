//! Provider-neutral operational mesh-host policy.
//!
//! The host is deliberately an event/action state machine. Connectivity
//! providers translate [`HostAction`] values into their own dial, discovery,
//! and close operations and feed the resulting [`HostEvent`] values back. The
//! carrier identity and locator remain untrusted until the existing Aster
//! session authenticates a mission [`NodeId`]. This module never handles Aster
//! frames, keys, durable objects, or application data.

use aster_mesh::{EmissionPolicy, NodeId};
use std::collections::{BTreeMap, BTreeSet};
use std::error::Error;
use std::fmt;
use std::time::{Duration, Instant};

const MAX_CANDIDATES_HARD: usize = 4_096;
const MAX_ACTIVE_CONTACTS_HARD: usize = 256;
const MAX_CANDIDATE_ID_BYTES: usize = 256;
const MAX_CARRIER_ID_BYTES: usize = 512;
const MAX_LOCATOR_BYTES: usize = 1_024;

/// Provider-owned stable handle for one candidate.
///
/// A candidate ID is an opaque scheduling key, not a mission identity. A
/// provider may derive it from a transport identity or a bounded locator.
#[derive(Clone, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct CandidateId(String);

impl CandidateId {
    pub fn new(value: impl Into<String>) -> Result<Self, MeshHostError> {
        let value = value.into();
        validate_text("candidate ID", &value, MAX_CANDIDATE_ID_BYTES)?;
        Ok(Self(value))
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }
}

/// Provider-specific address or dialing capability.
#[derive(Clone, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct CandidateLocator(String);

impl CandidateLocator {
    pub fn new(value: impl Into<String>) -> Result<Self, MeshHostError> {
        let value = value.into();
        validate_text("candidate locator", &value, MAX_LOCATOR_BYTES)?;
        Ok(Self(value))
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }
}

/// Cryptographic identity authenticated by the connectivity provider.
///
/// This is supplemental channel evidence. It never grants Aster membership,
/// topic access, scope access, or permission to synchronize.
#[derive(Clone, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct CarrierIdentity(Vec<u8>);

impl CarrierIdentity {
    pub fn new(value: Vec<u8>) -> Result<Self, MeshHostError> {
        if value.is_empty() || value.len() > MAX_CARRIER_ID_BYTES {
            return Err(MeshHostError::Invalid(
                "carrier identity must contain 1-512 bytes".into(),
            ));
        }
        Ok(Self(value))
    }

    pub fn as_bytes(&self) -> &[u8] {
        &self.0
    }
}

/// How a locator entered the bounded candidate table.
#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub enum CandidateProvenance {
    /// Acquired through an enabled provider discovery mechanism.
    Automatic,
    /// Supplied by deployment provisioning or an operator.
    Manual,
}

/// Connectivity path used by a contact.
#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub enum ContactPath {
    /// Direct peer-to-peer path.
    Direct,
    /// Live, non-durable connectivity-relay path.
    ConnectivityRelay,
}

/// Which side opened a connectivity contact.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ContactDirection {
    Inbound,
    Outbound,
}

/// Provider-owned stable handle for an open connection.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct ContactId(pub u64);

/// Opaque, single-use authorization prepared by [`MeshHost`] after Aster's
/// cryptographic handshake and committed only after the durable runtime and
/// node-wide resource ledger accept the contact.
#[derive(Debug)]
pub(crate) struct AdmissionToken {
    id: u64,
}

/// Fail-closed result of preparing an authenticated contact. A missing token
/// means the listed close actions must complete before the contact can be
/// considered again; no carrier binding or authenticated peer state changed.
#[derive(Debug)]
pub(crate) struct AdmissionPreparation {
    token: Option<AdmissionToken>,
    actions: Vec<HostAction>,
}

impl AdmissionPreparation {
    pub(crate) fn into_parts(self) -> (Option<AdmissionToken>, Vec<HostAction>) {
        (self.token, self.actions)
    }
}

/// Why the host asks a provider to close a contact.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ContactCloseReason {
    Capacity,
    Duplicate,
    FairnessQuantum,
    AuthenticationRejected,
    EmissionPolicy,
}

/// Provider-neutral policy bounds.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct HostConfig {
    pub max_candidates: usize,
    pub max_active_contacts: usize,
    pub candidate_ttl: Duration,
    pub contact_quantum: Duration,
    pub reconnect_initial: Duration,
    pub reconnect_max: Duration,
}

impl Default for HostConfig {
    fn default() -> Self {
        Self {
            max_candidates: 256,
            max_active_contacts: 8,
            candidate_ttl: Duration::from_secs(120),
            contact_quantum: Duration::from_secs(30),
            reconnect_initial: Duration::from_millis(250),
            reconnect_max: Duration::from_secs(30),
        }
    }
}

impl HostConfig {
    pub fn validate(self) -> Result<Self, MeshHostError> {
        if self.max_candidates == 0 || self.max_candidates > MAX_CANDIDATES_HARD {
            return Err(MeshHostError::Invalid(
                "candidate capacity must be between 1 and 4096".into(),
            ));
        }
        if self.max_active_contacts == 0
            || self.max_active_contacts > self.max_candidates
            || self.max_active_contacts > MAX_ACTIVE_CONTACTS_HARD
        {
            return Err(MeshHostError::Invalid(
                "active-contact capacity must be nonzero, at most 256, and no larger than candidate capacity"
                    .into(),
            ));
        }
        if self.candidate_ttl.is_zero()
            || self.contact_quantum.is_zero()
            || self.reconnect_initial.is_zero()
            || self.reconnect_max < self.reconnect_initial
        {
            return Err(MeshHostError::Invalid(
                "host durations must be nonzero and reconnect_max must cover reconnect_initial"
                    .into(),
            ));
        }
        Ok(self)
    }
}

/// One provider observation or contact-lifecycle result.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum HostEvent {
    CandidateObserved {
        candidate: CandidateId,
        locator: CandidateLocator,
        provenance: CandidateProvenance,
        path: ContactPath,
        expected_peer: Option<NodeId>,
    },
    CandidateExpired {
        candidate: CandidateId,
        locator: CandidateLocator,
    },
    /// Refreshes the Host-owned lifetime of an already observed automatic
    /// locator without changing its retry failures or next-attempt deadline.
    CandidateRefreshed {
        candidate: CandidateId,
        locator: CandidateLocator,
    },
    /// A provider reached a carrier previously used by an admitted contact
    /// through a second candidate/locator. The resulting peer value is only a
    /// non-authoritative scheduling hint: every new contact must still perform
    /// a fresh Aster handshake and atomic admission transaction.
    CandidateCarrierMatched {
        candidate: CandidateId,
        locator: CandidateLocator,
        carrier_identity: CarrierIdentity,
    },
    DialFailed {
        candidate: CandidateId,
        locator: CandidateLocator,
    },
    ContactOpened {
        contact: ContactId,
        candidate: CandidateId,
        locator: CandidateLocator,
        carrier_identity: Option<CarrierIdentity>,
        direction: ContactDirection,
        path: ContactPath,
    },
    ContactClosed {
        contact: ContactId,
        failed: bool,
    },
    AsterAuthenticationFailed {
        contact: ContactId,
    },
}

/// Work for a connectivity provider. No action contains application data.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum HostAction {
    SetDiscovery {
        enabled: bool,
    },
    Dial {
        candidate: CandidateId,
        locator: CandidateLocator,
    },
    /// The Host expired a locator. Providers must release any corresponding
    /// bounded address/handle cache; they do not own a second TTL policy.
    ForgetCandidateLocator {
        candidate: CandidateId,
        locator: CandidateLocator,
    },
    Close {
        contact: ContactId,
        reason: ContactCloseReason,
    },
}

/// Stable candidate state for operator status and acceptance evidence.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CandidateStatus {
    pub candidate: CandidateId,
    pub provenances: BTreeSet<CandidateProvenance>,
    pub locator_count: usize,
    pub has_direct_locator: bool,
    pub has_relay_locator: bool,
    pub expected_peer: Option<NodeId>,
    /// Non-authoritative grouping hint learned from a prior admitted contact.
    /// This is never evidence that this candidate or a new contact is
    /// authenticated.
    pub previously_bound_peer_hint: Option<NodeId>,
    pub active_contacts: usize,
    pub pending_dial: bool,
    pub rejected: bool,
    pub failures: u16,
}

/// Bounded host status. This is not a global convergence claim.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct HostSnapshot {
    pub discovery_enabled: bool,
    pub candidate_count: usize,
    pub locator_count: usize,
    pub carrier_binding_count: usize,
    pub active_contacts: usize,
    pub active_inbound_contacts: usize,
    pub active_outbound_contacts: usize,
    pub authenticated_contacts: usize,
    pub pending_admissions: usize,
    pub pending_dials: usize,
    pub rejected_candidates: usize,
    pub candidates: Vec<CandidateStatus>,
}

/// Contract validation or state-transition failure.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum MeshHostError {
    Invalid(String),
    Capacity(&'static str),
    UnknownCandidate,
    UnknownCarrierBinding,
    UnknownContact,
    DuplicateContact,
    AdmissionIdExhausted,
    StaleAdmission,
}

impl fmt::Display for MeshHostError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Invalid(message) => formatter.write_str(message),
            Self::Capacity(kind) => write!(formatter, "{kind} capacity reached"),
            Self::UnknownCandidate => formatter.write_str("unknown mesh candidate"),
            Self::UnknownCarrierBinding => {
                formatter.write_str("carrier has no live authenticated Aster binding")
            }
            Self::UnknownContact => formatter.write_str("unknown mesh contact"),
            Self::DuplicateContact => formatter.write_str("duplicate mesh contact ID"),
            Self::AdmissionIdExhausted => {
                formatter.write_str("mesh admission token identifier space exhausted")
            }
            Self::StaleAdmission => formatter.write_str("stale or replayed admission token"),
        }
    }
}

impl Error for MeshHostError {}

#[derive(Clone, Debug)]
struct LocatorState {
    provenance: CandidateProvenance,
    path: ContactPath,
    expires_at: Option<Instant>,
    next_attempt: Instant,
    failures: u16,
}

#[derive(Clone, Debug)]
struct CandidateState {
    locators: BTreeMap<CandidateLocator, LocatorState>,
    expected_peer: Option<NodeId>,
    previously_bound_peer_hint: Option<NodeId>,
    pending_dial: Option<CandidateLocator>,
    rejected: bool,
    failures: u16,
    last_service: u64,
}

#[derive(Clone, Debug)]
struct ActiveContact {
    candidate: CandidateId,
    locator: CandidateLocator,
    carrier_identity: Option<CarrierIdentity>,
    direction: ContactDirection,
    opened_at: Instant,
    authenticated_peer: Option<NodeId>,
    close_requested: bool,
}

#[derive(Clone, Copy, Debug)]
struct CarrierBinding {
    peer: NodeId,
    expires_at: Option<Instant>,
}

#[derive(Clone, Debug)]
struct PendingAdmission {
    contact: ContactId,
    peer: NodeId,
    candidate: CandidateId,
    carrier_identity: Option<CarrierIdentity>,
}

#[derive(Clone, Debug, Eq, Ord, PartialEq, PartialOrd)]
enum CandidateGroupKey {
    Peer(NodeId),
    Unidentified(CandidateId),
}

struct OpenedContact {
    contact: ContactId,
    candidate: CandidateId,
    locator: CandidateLocator,
    carrier_identity: Option<CarrierIdentity>,
    direction: ContactDirection,
    path: ContactPath,
}

/// Bounded, provider-neutral contact lifecycle and fairness controller.
pub struct MeshHost {
    config: HostConfig,
    emission: EmissionPolicy,
    provider_discovery: Option<bool>,
    candidates: BTreeMap<CandidateId, CandidateState>,
    contacts: BTreeMap<ContactId, ActiveContact>,
    carrier_bindings: BTreeMap<CarrierIdentity, CarrierBinding>,
    pending_admissions: BTreeMap<u64, PendingAdmission>,
    next_admission: Option<u64>,
    next_service: u64,
    #[cfg(test)]
    fail_next_authenticated_commit: bool,
}

impl MeshHost {
    pub fn new(config: HostConfig, emission: EmissionPolicy) -> Result<Self, MeshHostError> {
        Ok(Self {
            config: config.validate()?,
            emission,
            provider_discovery: None,
            candidates: BTreeMap::new(),
            contacts: BTreeMap::new(),
            carrier_bindings: BTreeMap::new(),
            pending_admissions: BTreeMap::new(),
            next_admission: Some(1),
            next_service: 1,
            #[cfg(test)]
            fail_next_authenticated_commit: false,
        })
    }

    #[cfg(test)]
    pub(crate) fn fail_next_authenticated_commit_for_test(&mut self) {
        self.fail_next_authenticated_commit = true;
    }

    pub fn emission_policy(&self) -> EmissionPolicy {
        self.emission
    }

    pub fn set_emission_policy(&mut self, policy: EmissionPolicy) {
        self.emission = policy;
    }

    /// Earliest instant at which [`Self::plan`] can produce different work
    /// without a new provider event.
    ///
    /// Providers should select on this deadline alongside socket, stream, and
    /// application readiness. Returning `now` means policy work is already
    /// available; it is not an instruction to enter a polling loop.
    pub fn next_wakeup(&self, now: Instant) -> Option<Instant> {
        let discovery = self.emission.allows_discovery();
        if self.provider_discovery != Some(discovery) {
            return Some(now);
        }

        let mut deadlines = Vec::new();
        let active_locators = self
            .contacts
            .values()
            .map(|contact| (contact.candidate.clone(), contact.locator.clone()))
            .collect::<BTreeSet<_>>();
        for (candidate_id, candidate) in &self.candidates {
            deadlines.extend(candidate.locators.iter().filter_map(|(name, locator)| {
                (candidate.pending_dial.as_ref() != Some(name)
                    && !active_locators.contains(&(candidate_id.clone(), name.clone())))
                .then_some(locator.expires_at)
                .flatten()
            }));
        }
        let active_carriers = self
            .contacts
            .values()
            .filter_map(|contact| contact.carrier_identity.as_ref())
            .collect::<BTreeSet<_>>();
        deadlines.extend(
            self.carrier_bindings
                .iter()
                .filter_map(|(identity, binding)| {
                    (!active_carriers.contains(identity))
                        .then_some(binding.expires_at)
                        .flatten()
                }),
        );
        deadlines.extend(self.contacts.values().filter_map(|contact| {
            (!contact.close_requested)
                .then(|| contact.opened_at.checked_add(self.config.contact_quantum))
                .flatten()
        }));

        if self.emission.minimum_priority.is_some() {
            let pending = self
                .candidates
                .values()
                .filter(|candidate| candidate.pending_dial.is_some())
                .count();
            let slots = self
                .config
                .max_active_contacts
                .saturating_sub(self.contacts.len().saturating_add(pending));
            if slots > 0 {
                let active = self
                    .contacts
                    .values()
                    .map(|contact| &contact.candidate)
                    .collect::<BTreeSet<_>>();
                let active_peers = self
                    .contacts
                    .values()
                    .filter_map(|contact| {
                        contact.authenticated_peer.or_else(|| {
                            self.candidates
                                .get(&contact.candidate)
                                .and_then(candidate_scheduling_peer)
                        })
                    })
                    .collect::<BTreeSet<_>>();
                let occupied_peers = active_peers
                    .into_iter()
                    .chain(
                        self.candidates
                            .values()
                            .filter(|candidate| candidate.pending_dial.is_some())
                            .filter_map(candidate_scheduling_peer),
                    )
                    .collect::<BTreeSet<_>>();
                for (id, candidate) in &self.candidates {
                    if candidate.rejected
                        || candidate.pending_dial.is_some()
                        || active.contains(id)
                        || candidate
                            .expected_peer
                            .or(candidate.previously_bound_peer_hint)
                            .is_some_and(|peer| occupied_peers.contains(&peer))
                    {
                        continue;
                    }
                    if let Some(next) = candidate
                        .locators
                        .values()
                        .map(|locator| locator.next_attempt)
                        .min()
                    {
                        if next <= now {
                            return Some(now);
                        }
                        deadlines.push(next);
                    }
                }
            }
        }

        deadlines.into_iter().min()
    }

    /// Applies one bounded provider/Aster event and returns immediate close
    /// actions required to remain fail-closed.
    pub fn handle_event(
        &mut self,
        event: HostEvent,
        now: Instant,
    ) -> Result<Vec<HostAction>, MeshHostError> {
        match event {
            HostEvent::CandidateObserved {
                candidate,
                locator,
                provenance,
                path,
                expected_peer,
            } => {
                if provenance == CandidateProvenance::Automatic && !self.emission.allows_discovery()
                {
                    return Ok(Vec::new());
                }
                self.observe_candidate(candidate, locator, provenance, path, expected_peer, now)?;
                Ok(Vec::new())
            }
            HostEvent::CandidateExpired { candidate, locator } => {
                self.remove_locator(&candidate, &locator, now);
                Ok(Vec::new())
            }
            HostEvent::CandidateRefreshed { candidate, locator } => {
                if !self.emission.allows_discovery() {
                    return Ok(Vec::new());
                }
                self.refresh_candidate(&candidate, &locator, now)?;
                Ok(Vec::new())
            }
            HostEvent::CandidateCarrierMatched {
                candidate,
                locator,
                carrier_identity,
            } => {
                self.candidate_carrier_matched(candidate, locator, carrier_identity, now)?;
                Ok(Vec::new())
            }
            HostEvent::DialFailed { candidate, locator } => {
                let state = self
                    .candidates
                    .get_mut(&candidate)
                    .ok_or(MeshHostError::UnknownCandidate)?;
                if state.pending_dial.as_ref() == Some(&locator) {
                    state.pending_dial = None;
                }
                state.failures = state.failures.saturating_add(1);
                let locator_state = state
                    .locators
                    .get_mut(&locator)
                    .ok_or(MeshHostError::UnknownCandidate)?;
                locator_state.failures = locator_state.failures.saturating_add(1);
                locator_state.next_attempt = now
                    .checked_add(backoff(&self.config, locator_state.failures))
                    .unwrap_or(now);
                Ok(Vec::new())
            }
            HostEvent::ContactOpened {
                contact,
                candidate,
                locator,
                carrier_identity,
                direction,
                path,
            } => self.contact_opened(
                OpenedContact {
                    contact,
                    candidate,
                    locator,
                    carrier_identity,
                    direction,
                    path,
                },
                now,
            ),
            HostEvent::ContactClosed { contact, failed } => {
                self.pending_admissions
                    .retain(|_, pending| pending.contact != contact);
                let active = self
                    .contacts
                    .remove(&contact)
                    .ok_or(MeshHostError::UnknownContact)?;
                let serviced_peer = active.authenticated_peer.or_else(|| {
                    self.candidates
                        .get(&active.candidate)
                        .and_then(candidate_scheduling_peer)
                });
                let service = self.next_service;
                self.next_service = self.next_service.saturating_add(1);
                if let Some(state) = self.candidates.get_mut(&active.candidate) {
                    // An inbound/alias contact can coexist with a distinct
                    // provider-owned outbound locator. Closing that contact
                    // must not settle or erase the unrelated in-flight dial.
                    if state.pending_dial.as_ref() == Some(&active.locator) {
                        state.pending_dial = None;
                    }
                    if failed {
                        state.failures = state.failures.saturating_add(1);
                        if let Some(locator) = state.locators.get_mut(&active.locator) {
                            locator.failures = locator.failures.saturating_add(1);
                            locator.next_attempt = now
                                .checked_add(backoff(&self.config, locator.failures))
                                .unwrap_or(now);
                        }
                    }
                }
                if let Some(peer) = serviced_peer {
                    for state in self.candidates.values_mut() {
                        if candidate_scheduling_peer(state) == Some(peer) {
                            state.last_service = service;
                        }
                    }
                } else if let Some(state) = self.candidates.get_mut(&active.candidate) {
                    state.last_service = service;
                }
                self.remove_empty_candidate(&active.candidate);
                Ok(Vec::new())
            }
            HostEvent::AsterAuthenticationFailed { contact } => {
                self.pending_admissions
                    .retain(|_, pending| pending.contact != contact);
                let active = self
                    .contacts
                    .get_mut(&contact)
                    .ok_or(MeshHostError::UnknownContact)?;
                active.close_requested = true;
                if let Some(candidate) = self.candidates.get_mut(&active.candidate) {
                    candidate.rejected = true;
                }
                Ok(vec![HostAction::Close {
                    contact,
                    reason: ContactCloseReason::AuthenticationRejected,
                }])
            }
        }
    }

    /// Reconciles discovery state, expiry, fairness, and dial capacity.
    pub fn plan(&mut self, now: Instant) -> Vec<HostAction> {
        let mut actions = self.expire(now);
        let discovery = self.emission.allows_discovery();
        if self.provider_discovery != Some(discovery) {
            self.provider_discovery = Some(discovery);
            actions.push(HostAction::SetDiscovery { enabled: discovery });
        }

        let quantum_contacts = self
            .contacts
            .iter()
            .filter_map(|(contact, state)| {
                (!state.close_requested
                    && now.saturating_duration_since(state.opened_at)
                        >= self.config.contact_quantum)
                    .then_some(*contact)
            })
            .collect::<Vec<_>>();
        for contact in quantum_contacts {
            if let Some(active) = self.contacts.get_mut(&contact) {
                active.close_requested = true;
            }
            actions.push(HostAction::Close {
                contact,
                reason: ContactCloseReason::FairnessQuantum,
            });
        }

        // Receive-only permits inbound authentication/link acknowledgements but
        // must not initiate a new contact. The core emission policy separately
        // filters framework inventory and item data.
        if self.emission.minimum_priority.is_none() {
            return actions;
        }

        let pending = self
            .candidates
            .values()
            .filter(|candidate| candidate.pending_dial.is_some())
            .count();
        let unavailable = self.contacts.len().saturating_add(pending);
        let slots = self.config.max_active_contacts.saturating_sub(unavailable);
        if slots == 0 {
            return actions;
        }
        let active_candidates = self
            .contacts
            .values()
            .map(|contact| contact.candidate.clone())
            .collect::<BTreeSet<_>>();
        let mut occupied_peers = self
            .contacts
            .values()
            .filter_map(|contact| {
                contact.authenticated_peer.or_else(|| {
                    self.candidates
                        .get(&contact.candidate)
                        .and_then(candidate_scheduling_peer)
                })
            })
            .collect::<BTreeSet<_>>();
        occupied_peers.extend(
            self.candidates
                .values()
                .filter(|candidate| candidate.pending_dial.is_some())
                .filter_map(candidate_scheduling_peer),
        );
        let mut peer_last_service = BTreeMap::<NodeId, u64>::new();
        let mut peer_has_manual = BTreeMap::<NodeId, bool>::new();
        for state in self.candidates.values().filter(|state| !state.rejected) {
            let Some(peer) = candidate_scheduling_peer(state) else {
                continue;
            };
            peer_last_service
                .entry(peer)
                .and_modify(|service| *service = (*service).max(state.last_service))
                .or_insert(state.last_service);
            if state
                .locators
                .values()
                .any(|locator| locator.provenance == CandidateProvenance::Manual)
            {
                peer_has_manual.insert(peer, true);
            }
        }

        // Candidates remain provenance-distinct records, but known aliases
        // compete as one logical NodeID group. Within a group, direct paths
        // precede relays, then lower locator failures, then manual provenance,
        // followed by stable candidate/locator tie-breaks.
        type DialRank = (ContactPath, u16, bool, CandidateId, CandidateLocator);
        let mut group_choices =
            BTreeMap::<CandidateGroupKey, (DialRank, CandidateId, CandidateLocator)>::new();
        for (id, state) in &self.candidates {
            let peer = candidate_scheduling_peer(state);
            if state.rejected
                || state.pending_dial.is_some()
                || active_candidates.contains(id)
                || peer.is_some_and(|peer| occupied_peers.contains(&peer))
            {
                continue;
            }
            let Some((locator, locator_state)) = state
                .locators
                .iter()
                .filter(|(_, locator)| now >= locator.next_attempt)
                .min_by_key(|(name, locator)| {
                    (
                        locator.path,
                        locator.failures,
                        locator.provenance != CandidateProvenance::Manual,
                        *name,
                    )
                })
            else {
                continue;
            };
            let group = peer.map_or_else(
                || CandidateGroupKey::Unidentified(id.clone()),
                CandidateGroupKey::Peer,
            );
            let rank = (
                locator_state.path,
                locator_state.failures,
                locator_state.provenance != CandidateProvenance::Manual,
                id.clone(),
                locator.clone(),
            );
            let replace = group_choices
                .get(&group)
                .is_none_or(|(existing, _, _)| rank < *existing);
            if replace {
                group_choices.insert(group, (rank, id.clone(), locator.clone()));
            }
        }
        let mut eligible = group_choices
            .into_iter()
            .map(|(group, (_, candidate, locator))| {
                let (last_service, lacks_manual, peer) = match &group {
                    CandidateGroupKey::Peer(peer) => (
                        peer_last_service.get(peer).copied().unwrap_or(0),
                        !peer_has_manual.get(peer).copied().unwrap_or(false),
                        Some(*peer),
                    ),
                    CandidateGroupKey::Unidentified(candidate) => {
                        let state = &self.candidates[candidate];
                        (
                            state.last_service,
                            !state
                                .locators
                                .values()
                                .any(|locator| locator.provenance == CandidateProvenance::Manual),
                            None,
                        )
                    }
                };
                (last_service, lacks_manual, group, candidate, locator, peer)
            })
            .collect::<Vec<_>>();
        eligible.sort();
        let mut selected = 0_usize;
        for (_, _, _, candidate, locator, peer) in eligible {
            if selected >= slots {
                break;
            }
            if peer.is_some_and(|peer| !occupied_peers.insert(peer)) {
                continue;
            }
            let Some(state) = self.candidates.get_mut(&candidate) else {
                continue;
            };
            state.pending_dial = Some(locator.clone());
            actions.push(HostAction::Dial { candidate, locator });
            selected = selected.saturating_add(1);
        }
        actions
    }

    pub fn snapshot(&self) -> HostSnapshot {
        let mut candidates = Vec::with_capacity(self.candidates.len());
        for (candidate, state) in &self.candidates {
            let provenances = state
                .locators
                .values()
                .map(|locator| locator.provenance)
                .collect();
            let active_contacts = self
                .contacts
                .values()
                .filter(|contact| &contact.candidate == candidate)
                .count();
            candidates.push(CandidateStatus {
                candidate: candidate.clone(),
                provenances,
                locator_count: state.locators.len(),
                has_direct_locator: state
                    .locators
                    .values()
                    .any(|locator| locator.path == ContactPath::Direct),
                has_relay_locator: state
                    .locators
                    .values()
                    .any(|locator| locator.path == ContactPath::ConnectivityRelay),
                expected_peer: state.expected_peer,
                previously_bound_peer_hint: state.previously_bound_peer_hint,
                active_contacts,
                pending_dial: state.pending_dial.is_some(),
                rejected: state.rejected,
                failures: state.failures,
            });
        }
        HostSnapshot {
            discovery_enabled: self.provider_discovery.unwrap_or(false),
            candidate_count: self.candidates.len(),
            locator_count: self
                .candidates
                .values()
                .map(|candidate| candidate.locators.len())
                .sum(),
            carrier_binding_count: self.carrier_bindings.len(),
            active_contacts: self.contacts.len(),
            active_inbound_contacts: self
                .contacts
                .values()
                .filter(|contact| contact.direction == ContactDirection::Inbound)
                .count(),
            active_outbound_contacts: self
                .contacts
                .values()
                .filter(|contact| contact.direction == ContactDirection::Outbound)
                .count(),
            authenticated_contacts: self
                .contacts
                .values()
                .filter(|contact| contact.authenticated_peer.is_some())
                .count(),
            pending_admissions: self.pending_admissions.len(),
            pending_dials: self
                .candidates
                .values()
                .filter(|candidate| candidate.pending_dial.is_some())
                .count(),
            rejected_candidates: self
                .candidates
                .values()
                .filter(|candidate| candidate.rejected)
                .count(),
            candidates,
        }
    }

    /// Prepares, but does not commit, an authenticated carrier-to-Aster
    /// binding. Duplicate teardown, resource-lease transition, and durable
    /// runtime admission happen outside this state machine; callers commit the
    /// returned token only after all of them succeed.
    ///
    /// This method never sets an authenticated peer, installs a carrier
    /// binding, clears retry state, or rejects a candidate. If a duplicate or
    /// policy conflict requires closure it returns actions and no token.
    pub(crate) fn prepare_authenticated(
        &mut self,
        contact: ContactId,
        peer: NodeId,
    ) -> Result<AdmissionPreparation, MeshHostError> {
        if self
            .pending_admissions
            .values()
            .any(|pending| pending.contact == contact)
        {
            return Err(MeshHostError::StaleAdmission);
        }
        let active = self
            .contacts
            .get(&contact)
            .ok_or(MeshHostError::UnknownContact)?;
        let candidate = self
            .candidates
            .get(&active.candidate)
            .ok_or(MeshHostError::UnknownCandidate)?;
        let conflict = candidate
            .expected_peer
            .is_some_and(|expected| expected != peer)
            || active.carrier_identity.as_ref().is_some_and(|identity| {
                self.pending_admissions.values().any(|pending| {
                    pending.carrier_identity.as_ref() == Some(identity) && pending.peer != peer
                })
            });
        if conflict {
            return Ok(AdmissionPreparation {
                token: None,
                actions: vec![HostAction::Close {
                    contact,
                    reason: ContactCloseReason::AuthenticationRejected,
                }],
            });
        }
        if let Some(other) = self
            .contacts
            .iter()
            .filter_map(|(other_id, other)| {
                (*other_id != contact && other.authenticated_peer == Some(peer))
                    .then_some(*other_id)
            })
            .min()
        {
            let loser = other.max(contact);
            return Ok(AdmissionPreparation {
                token: None,
                actions: vec![HostAction::Close {
                    contact: loser,
                    reason: ContactCloseReason::Duplicate,
                }],
            });
        }
        if self
            .pending_admissions
            .values()
            .any(|pending| pending.peer == peer && pending.contact != contact)
        {
            return Ok(AdmissionPreparation {
                token: None,
                actions: vec![HostAction::Close {
                    contact,
                    reason: ContactCloseReason::Duplicate,
                }],
            });
        }
        let needs_carrier_slot = active.carrier_identity.as_ref().is_some_and(|identity| {
            !self.carrier_bindings.contains_key(identity)
                && !self
                    .pending_admissions
                    .values()
                    .any(|pending| pending.carrier_identity.as_ref() == Some(identity))
        });
        let pending_carrier_slots = self
            .pending_admissions
            .values()
            .filter_map(|pending| pending.carrier_identity.as_ref())
            .filter(|identity| !self.carrier_bindings.contains_key(*identity))
            .collect::<BTreeSet<_>>()
            .len();
        if needs_carrier_slot
            && self
                .carrier_bindings
                .len()
                .saturating_add(pending_carrier_slots)
                >= self.config.max_candidates
        {
            return Ok(AdmissionPreparation {
                token: None,
                actions: vec![HostAction::Close {
                    contact,
                    reason: ContactCloseReason::Capacity,
                }],
            });
        }
        let id = self
            .next_admission
            .ok_or(MeshHostError::AdmissionIdExhausted)?;
        self.next_admission = id.checked_add(1);
        self.pending_admissions.insert(
            id,
            PendingAdmission {
                contact,
                peer,
                candidate: active.candidate.clone(),
                carrier_identity: active.carrier_identity.clone(),
            },
        );
        Ok(AdmissionPreparation {
            token: Some(AdmissionToken { id }),
            actions: Vec::new(),
        })
    }

    /// Commits a prepared binding after runtime admission and resource
    /// reservation have succeeded. A missing, closed, changed, or replayed
    /// contact fails without installing authority.
    pub(crate) fn commit_authenticated(
        &mut self,
        token: AdmissionToken,
        now: Instant,
    ) -> Result<Vec<HostAction>, MeshHostError> {
        let pending = self
            .pending_admissions
            .remove(&token.id)
            .ok_or(MeshHostError::StaleAdmission)?;
        #[cfg(test)]
        if std::mem::take(&mut self.fail_next_authenticated_commit) {
            return Err(MeshHostError::StaleAdmission);
        }
        let active = self
            .contacts
            .get(&pending.contact)
            .ok_or(MeshHostError::StaleAdmission)?;
        if active.candidate != pending.candidate
            || active.carrier_identity != pending.carrier_identity
            || active.authenticated_peer.is_some()
        {
            return Err(MeshHostError::StaleAdmission);
        }
        let candidate = self
            .candidates
            .get(&pending.candidate)
            .ok_or(MeshHostError::StaleAdmission)?;
        if candidate
            .expected_peer
            .is_some_and(|expected| expected != pending.peer)
            || self.contacts.iter().any(|(other_id, other)| {
                *other_id != pending.contact && other.authenticated_peer == Some(pending.peer)
            })
        {
            return Err(MeshHostError::StaleAdmission);
        }
        self.commit_prepared_admission(&pending, now)?;
        Ok(Vec::new())
    }

    /// Cancels a prepared admission after a resource or durable-runtime
    /// failure. This is idempotent only in effect; replayed tokens are errors so
    /// evidence cannot silently treat a double completion as success.
    pub(crate) fn abort_authenticated(
        &mut self,
        token: AdmissionToken,
    ) -> Result<(), MeshHostError> {
        self.pending_admissions
            .remove(&token.id)
            .map(|_| ())
            .ok_or(MeshHostError::StaleAdmission)
    }

    fn commit_prepared_admission(
        &mut self,
        pending: &PendingAdmission,
        now: Instant,
    ) -> Result<(), MeshHostError> {
        let active = self
            .contacts
            .get_mut(&pending.contact)
            .ok_or(MeshHostError::StaleAdmission)?;
        let candidate = self
            .candidates
            .get_mut(&pending.candidate)
            .ok_or(MeshHostError::StaleAdmission)?;
        if let Some(identity) = pending.carrier_identity.clone() {
            if !self.carrier_bindings.contains_key(&identity)
                && self.carrier_bindings.len() >= self.config.max_candidates
            {
                return Err(MeshHostError::StaleAdmission);
            }
            let manual = candidate
                .locators
                .values()
                .any(|locator| locator.provenance == CandidateProvenance::Manual);
            self.carrier_bindings.insert(
                identity,
                CarrierBinding {
                    peer: pending.peer,
                    expires_at: (!manual)
                        .then(|| now.checked_add(self.config.candidate_ttl).unwrap_or(now)),
                },
            );
        }
        candidate.previously_bound_peer_hint = Some(pending.peer);
        candidate.failures = 0;
        for locator in candidate.locators.values_mut() {
            locator.failures = 0;
        }
        active.authenticated_peer = Some(pending.peer);
        Ok(())
    }

    fn observe_candidate(
        &mut self,
        candidate: CandidateId,
        locator: CandidateLocator,
        provenance: CandidateProvenance,
        path: ContactPath,
        expected_peer: Option<NodeId>,
        now: Instant,
    ) -> Result<(), MeshHostError> {
        if !self.candidates.contains_key(&candidate)
            && self.candidates.len() >= self.config.max_candidates
        {
            return Err(MeshHostError::Capacity("candidate"));
        }
        let locator_is_new = self
            .candidates
            .get(&candidate)
            .is_none_or(|state| !state.locators.contains_key(&locator));
        let locator_count = self
            .candidates
            .values()
            .map(|state| state.locators.len())
            .sum::<usize>();
        if locator_is_new && locator_count >= self.config.max_candidates {
            return Err(MeshHostError::Capacity("locator"));
        }
        let state = self
            .candidates
            .entry(candidate)
            .or_insert_with(|| CandidateState {
                locators: BTreeMap::new(),
                expected_peer,
                previously_bound_peer_hint: None,
                pending_dial: None,
                rejected: false,
                failures: 0,
                last_service: 0,
            });
        if let (Some(previous), Some(next)) = (state.expected_peer, expected_peer)
            && previous != next
        {
            state.rejected = true;
            return Err(MeshHostError::Invalid(
                "candidate was manually bound to conflicting Aster identities".into(),
            ));
        }
        state.expected_peer = state.expected_peer.or(expected_peer);
        let expires_at = (provenance == CandidateProvenance::Automatic)
            .then(|| now.checked_add(self.config.candidate_ttl).unwrap_or(now));
        state.locators.insert(
            locator,
            LocatorState {
                provenance,
                path,
                expires_at,
                next_attempt: now,
                failures: 0,
            },
        );
        Ok(())
    }

    fn candidate_carrier_matched(
        &mut self,
        candidate: CandidateId,
        locator: CandidateLocator,
        carrier_identity: CarrierIdentity,
        now: Instant,
    ) -> Result<(), MeshHostError> {
        let carrier_is_active = self.contacts.values().any(|contact| {
            contact.carrier_identity.as_ref() == Some(&carrier_identity)
                && contact.authenticated_peer.is_some()
        });
        let peer = self
            .carrier_bindings
            .get(&carrier_identity)
            .filter(|binding| {
                carrier_is_active || binding.expires_at.is_none_or(|expires| now < expires)
            })
            .map(|binding| binding.peer)
            .ok_or(MeshHostError::UnknownCarrierBinding)?;
        let group_last_service = self
            .candidates
            .values()
            .filter(|candidate| candidate_scheduling_peer(candidate) == Some(peer))
            .map(|candidate| candidate.last_service)
            .max()
            .unwrap_or(0);
        let state = self
            .candidates
            .get_mut(&candidate)
            .ok_or(MeshHostError::UnknownCandidate)?;
        let locator_state = state
            .locators
            .get_mut(&locator)
            .ok_or(MeshHostError::UnknownCandidate)?;
        // This hint may be stale or shared by a provider across sessions. It
        // deliberately does not participate in admission policy: only a fresh
        // Aster-authenticated session plus an explicit `expected_peer` policy
        // can decide whether the contact is admitted.
        state.previously_bound_peer_hint = Some(peer);
        state.last_service = state.last_service.max(group_last_service);
        // A cached carrier binding alone is not Host-visible occupancy. Keep
        // the exact outbound locator pending until this carrier is backed by
        // a currently authenticated contact; provider precontact lifecycles
        // then suppress aliases without opening a redial window.
        if carrier_is_active && state.pending_dial.as_ref() == Some(&locator) {
            state.pending_dial = None;
        }
        state.failures = 0;
        locator_state.failures = 0;
        locator_state.next_attempt = now;
        Ok(())
    }

    fn refresh_candidate(
        &mut self,
        candidate: &CandidateId,
        locator: &CandidateLocator,
        now: Instant,
    ) -> Result<(), MeshHostError> {
        let state = self
            .candidates
            .get_mut(candidate)
            .ok_or(MeshHostError::UnknownCandidate)?;
        let locator = state
            .locators
            .get_mut(locator)
            .ok_or(MeshHostError::UnknownCandidate)?;
        if locator.provenance != CandidateProvenance::Automatic {
            return Err(MeshHostError::Invalid(
                "only an automatic candidate locator can be refreshed".into(),
            ));
        }
        locator.expires_at = Some(now.checked_add(self.config.candidate_ttl).unwrap_or(now));
        Ok(())
    }

    fn remove_locator(
        &mut self,
        candidate: &CandidateId,
        locator: &CandidateLocator,
        now: Instant,
    ) {
        if let Some(state) = self.candidates.get_mut(candidate) {
            // An in-flight dial retains its exact locator until completion so
            // a late result cannot clear or overwrite a newer pending dial.
            if state.pending_dial.as_ref() == Some(locator) {
                if let Some(locator) = state.locators.get_mut(locator) {
                    locator.expires_at = Some(now);
                }
                return;
            }
            state.locators.remove(locator);
        }
        self.remove_empty_candidate(candidate);
    }

    fn remove_empty_candidate(&mut self, candidate: &CandidateId) {
        let active = self
            .contacts
            .values()
            .any(|contact| &contact.candidate == candidate);
        if !active
            && self
                .candidates
                .get(candidate)
                .is_some_and(|state| state.locators.is_empty())
        {
            self.candidates.remove(candidate);
        }
    }

    fn expire(&mut self, now: Instant) -> Vec<HostAction> {
        let mut actions = Vec::new();
        let active_locators = self
            .contacts
            .values()
            .map(|contact| (contact.candidate.clone(), contact.locator.clone()))
            .collect::<BTreeSet<_>>();
        let ids = self.candidates.keys().cloned().collect::<Vec<_>>();
        for candidate in ids {
            if let Some(state) = self.candidates.get_mut(&candidate) {
                let pending = state.pending_dial.clone();
                let expired = state
                    .locators
                    .iter()
                    .filter_map(|(locator, state)| {
                        (pending.as_ref() != Some(locator)
                            && !active_locators.contains(&(candidate.clone(), locator.clone()))
                            && state.expires_at.is_some_and(|expires| now >= expires))
                        .then_some(locator.clone())
                    })
                    .collect::<Vec<_>>();
                for locator in expired {
                    state.locators.remove(&locator);
                    actions.push(HostAction::ForgetCandidateLocator {
                        candidate: candidate.clone(),
                        locator,
                    });
                }
            }
            self.remove_empty_candidate(&candidate);
        }
        let active_carriers = self
            .contacts
            .values()
            .filter_map(|contact| contact.carrier_identity.clone())
            .collect::<BTreeSet<_>>();
        self.carrier_bindings.retain(|identity, binding| {
            active_carriers.contains(identity)
                || binding.expires_at.is_none_or(|expires| now < expires)
        });
        actions
    }

    fn contact_opened(
        &mut self,
        opened: OpenedContact,
        now: Instant,
    ) -> Result<Vec<HostAction>, MeshHostError> {
        let OpenedContact {
            contact,
            candidate,
            locator,
            carrier_identity,
            direction,
            path,
        } = opened;
        if self.contacts.contains_key(&contact) {
            return Err(MeshHostError::DuplicateContact);
        }
        if !self.candidates.contains_key(&candidate) {
            if direction == ContactDirection::Outbound {
                return Err(MeshHostError::UnknownCandidate);
            }
            self.observe_candidate(
                candidate.clone(),
                locator.clone(),
                CandidateProvenance::Automatic,
                path,
                None,
                now,
            )?;
        }
        if direction == ContactDirection::Outbound {
            let state = self
                .candidates
                .get(&candidate)
                .ok_or(MeshHostError::UnknownCandidate)?;
            if !state.locators.contains_key(&locator)
                || state.pending_dial.as_ref() != Some(&locator)
            {
                return Err(MeshHostError::UnknownCandidate);
            }
        }
        if let Some(state) = self.candidates.get_mut(&candidate)
            && state.pending_dial.as_ref() == Some(&locator)
        {
            state.pending_dial = None;
        }
        if self.contacts.len() >= self.config.max_active_contacts {
            return Ok(vec![HostAction::Close {
                contact,
                reason: ContactCloseReason::Capacity,
            }]);
        }
        if self
            .contacts
            .values()
            .any(|active| active.candidate == candidate)
        {
            return Ok(vec![HostAction::Close {
                contact,
                reason: ContactCloseReason::Duplicate,
            }]);
        }
        self.contacts.insert(
            contact,
            ActiveContact {
                candidate,
                locator,
                carrier_identity,
                direction,
                opened_at: now,
                authenticated_peer: None,
                close_requested: false,
            },
        );
        Ok(Vec::new())
    }
}

fn candidate_scheduling_peer(state: &CandidateState) -> Option<NodeId> {
    state.expected_peer.or(state.previously_bound_peer_hint)
}

fn backoff(config: &HostConfig, failures: u16) -> Duration {
    let shifts = failures.saturating_sub(1).min(20);
    let multiplier = 1_u32.checked_shl(u32::from(shifts)).unwrap_or(u32::MAX);
    config
        .reconnect_initial
        .saturating_mul(multiplier)
        .min(config.reconnect_max)
}

fn validate_text(kind: &str, value: &str, maximum: usize) -> Result<(), MeshHostError> {
    if value.is_empty()
        || value.len() > maximum
        || value
            .bytes()
            .any(|byte| byte.is_ascii_control() || byte == 0x7f)
    {
        return Err(MeshHostError::Invalid(format!(
            "{kind} must contain 1-{maximum} non-control UTF-8 bytes"
        )));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use aster_mesh::Priority;

    fn candidate(value: usize) -> CandidateId {
        CandidateId::new(format!("candidate-{value:03}")).unwrap()
    }

    fn locator(value: usize) -> CandidateLocator {
        CandidateLocator::new(format!("/ip4/192.0.2.{}/tcp/4000", value + 1)).unwrap()
    }

    fn normal_host(max_candidates: usize, max_active: usize) -> MeshHost {
        MeshHost::new(
            HostConfig {
                max_candidates,
                max_active_contacts: max_active,
                candidate_ttl: Duration::from_secs(60),
                contact_quantum: Duration::from_secs(1),
                reconnect_initial: Duration::from_millis(100),
                reconnect_max: Duration::from_secs(2),
            },
            EmissionPolicy::default(),
        )
        .unwrap()
    }

    fn observe(
        host: &mut MeshHost,
        id: CandidateId,
        address: CandidateLocator,
        provenance: CandidateProvenance,
        path: ContactPath,
        peer: Option<NodeId>,
        now: Instant,
    ) {
        host.handle_event(
            HostEvent::CandidateObserved {
                candidate: id,
                locator: address,
                provenance,
                path,
                expected_peer: peer,
            },
            now,
        )
        .unwrap();
    }

    fn commit_host_admission_for_test(
        host: &mut MeshHost,
        contact: ContactId,
        peer: NodeId,
        now: Instant,
    ) -> Result<Vec<HostAction>, MeshHostError> {
        let (token, actions) = host.prepare_authenticated(contact, peer)?.into_parts();
        let Some(token) = token else {
            return Ok(actions);
        };
        assert!(actions.is_empty());
        host.commit_authenticated(token, now)
    }

    #[test]
    fn emission_policy_drives_discovery_and_receive_only_dials_nothing() {
        let now = Instant::now();
        let mut host = normal_host(4, 1);
        assert_eq!(
            host.plan(now),
            vec![HostAction::SetDiscovery { enabled: true }]
        );
        host.set_emission_policy(EmissionPolicy::receive_only());
        observe(
            &mut host,
            candidate(1),
            locator(1),
            CandidateProvenance::Manual,
            ContactPath::Direct,
            Some([1; 32]),
            now,
        );
        assert_eq!(
            host.plan(now),
            vec![HostAction::SetDiscovery { enabled: false }]
        );
        let inbound = host
            .handle_event(
                HostEvent::ContactOpened {
                    contact: ContactId(1),
                    candidate: candidate(1),
                    locator: locator(1),
                    carrier_identity: None,
                    direction: ContactDirection::Inbound,
                    path: ContactPath::Direct,
                },
                now,
            )
            .unwrap();
        assert!(inbound.is_empty());
    }

    #[test]
    fn next_wakeup_reports_policy_backoff_expiry_and_contact_quantum() {
        let now = Instant::now();
        let mut host = normal_host(4, 1);
        assert_eq!(host.next_wakeup(now), Some(now));
        assert_eq!(
            host.plan(now),
            vec![HostAction::SetDiscovery { enabled: true }]
        );
        observe(
            &mut host,
            candidate(1),
            locator(1),
            CandidateProvenance::Automatic,
            ContactPath::Direct,
            None,
            now,
        );
        assert_eq!(host.next_wakeup(now), Some(now));
        let dial = host.plan(now).pop().unwrap();
        let HostAction::Dial { candidate, locator } = dial else {
            panic!("candidate should be immediately dialable");
        };
        host.handle_event(
            HostEvent::ContactOpened {
                contact: ContactId(1),
                candidate,
                locator,
                carrier_identity: None,
                direction: ContactDirection::Outbound,
                path: ContactPath::Direct,
            },
            now,
        )
        .unwrap();
        assert_eq!(
            host.next_wakeup(now),
            now.checked_add(Duration::from_secs(1))
        );
    }

    #[test]
    fn next_wakeup_ignores_expired_deadlines_that_cannot_change_policy() {
        let now = Instant::now();
        let mut host = normal_host(4, 1);
        assert_eq!(
            host.plan(now),
            vec![HostAction::SetDiscovery { enabled: true }]
        );
        observe(
            &mut host,
            candidate(1),
            locator(1),
            CandidateProvenance::Automatic,
            ContactPath::Direct,
            None,
            now,
        );
        assert!(matches!(
            host.plan(now).as_slice(),
            [HostAction::Dial { .. }]
        ));

        let after_expiry = now.checked_add(Duration::from_secs(61)).unwrap();
        assert_eq!(host.next_wakeup(after_expiry), None);
        host.handle_event(
            HostEvent::DialFailed {
                candidate: candidate(1),
                locator: locator(1),
            },
            after_expiry,
        )
        .unwrap();
        assert!(
            host.next_wakeup(after_expiry)
                .is_some_and(|due| due <= after_expiry)
        );
        assert_eq!(
            host.plan(after_expiry),
            vec![HostAction::ForgetCandidateLocator {
                candidate: candidate(1),
                locator: locator(1),
            }]
        );
        assert_eq!(host.snapshot().candidate_count, 0);
    }

    #[test]
    fn closing_contact_prunes_candidate_whose_automatic_locator_expired_in_flight() {
        let now = Instant::now();
        let mut host = normal_host(1, 1);
        let id = candidate(1);
        let address = locator(1);
        observe(
            &mut host,
            id.clone(),
            address.clone(),
            CandidateProvenance::Automatic,
            ContactPath::Direct,
            None,
            now,
        );
        let dial = host
            .plan(now)
            .into_iter()
            .find(|action| matches!(action, HostAction::Dial { .. }))
            .expect("automatic candidate should be dialed");
        let HostAction::Dial {
            candidate: dial_candidate,
            locator: dial_locator,
        } = dial
        else {
            unreachable!();
        };
        host.handle_event(
            HostEvent::ContactOpened {
                contact: ContactId(1),
                candidate: dial_candidate,
                locator: dial_locator,
                carrier_identity: None,
                direction: ContactDirection::Outbound,
                path: ContactPath::Direct,
            },
            now,
        )
        .unwrap();

        host.handle_event(
            HostEvent::CandidateExpired {
                candidate: id.clone(),
                locator: address,
            },
            now.checked_add(Duration::from_secs(61)).unwrap(),
        )
        .unwrap();
        let active = host.snapshot();
        assert_eq!(active.candidate_count, 1);
        assert_eq!(active.locator_count, 0);
        assert_eq!(active.active_contacts, 1);

        host.handle_event(
            HostEvent::ContactClosed {
                contact: ContactId(1),
                failed: false,
            },
            now.checked_add(Duration::from_secs(61)).unwrap(),
        )
        .unwrap();
        assert_eq!(host.snapshot().candidate_count, 0);
        assert!(
            host.plan(now.checked_add(Duration::from_secs(61)).unwrap())
                .is_empty()
        );

        observe(
            &mut host,
            candidate(2),
            locator(2),
            CandidateProvenance::Automatic,
            ContactPath::Direct,
            None,
            now.checked_add(Duration::from_secs(61)).unwrap(),
        );
        assert_eq!(host.snapshot().candidate_count, 1);
    }

    #[test]
    fn fairness_close_is_requested_only_once_while_provider_confirms() {
        let now = Instant::now();
        let mut host = normal_host(4, 1);
        let _ = host.plan(now);
        observe(
            &mut host,
            candidate(1),
            locator(1),
            CandidateProvenance::Manual,
            ContactPath::Direct,
            None,
            now,
        );
        let _ = host.plan(now);
        host.handle_event(
            HostEvent::ContactOpened {
                contact: ContactId(1),
                candidate: candidate(1),
                locator: locator(1),
                carrier_identity: None,
                direction: ContactDirection::Outbound,
                path: ContactPath::Direct,
            },
            now,
        )
        .unwrap();
        let quantum = now.checked_add(Duration::from_secs(1)).unwrap();
        assert_eq!(
            host.plan(quantum),
            vec![HostAction::Close {
                contact: ContactId(1),
                reason: ContactCloseReason::FairnessQuantum,
            }]
        );
        assert!(host.plan(quantum).is_empty());
        assert_eq!(host.next_wakeup(quantum), None);
    }

    #[test]
    fn prior_admission_hint_coalesces_scheduling_without_authenticating_a_candidate() {
        let now = Instant::now();
        let peer = [9_u8; 32];
        let mut host = normal_host(4, 2);
        let _ = host.plan(now);
        observe(
            &mut host,
            candidate(1),
            locator(1),
            CandidateProvenance::Manual,
            ContactPath::Direct,
            Some(peer),
            now,
        );
        assert!(matches!(
            host.plan(now).as_slice(),
            [HostAction::Dial { .. }]
        ));

        host.handle_event(
            HostEvent::ContactOpened {
                contact: ContactId(2),
                candidate: candidate(2),
                locator: locator(2),
                carrier_identity: Some(CarrierIdentity::new(vec![2]).unwrap()),
                direction: ContactDirection::Inbound,
                path: ContactPath::Direct,
            },
            now,
        )
        .unwrap();
        assert!(
            commit_host_admission_for_test(&mut host, ContactId(2), peer, now)
                .unwrap()
                .is_empty()
        );
        host.handle_event(
            HostEvent::DialFailed {
                candidate: candidate(1),
                locator: locator(1),
            },
            now,
        )
        .unwrap();
        let retry_due = now.checked_add(Duration::from_millis(100)).unwrap();
        assert!(host.plan(retry_due).is_empty());

        host.handle_event(
            HostEvent::ContactClosed {
                contact: ContactId(2),
                failed: false,
            },
            retry_due,
        )
        .unwrap();
        assert_eq!(
            host.plan(retry_due),
            vec![HostAction::Dial {
                candidate: candidate(2),
                locator: locator(2),
            }]
        );
        assert!(host.plan(retry_due).is_empty());
    }

    #[test]
    fn active_pre_auth_manual_candidate_suppresses_same_peer_alias() {
        let now = Instant::now();
        let peer = [8_u8; 32];
        let mut host = normal_host(4, 2);
        let _ = host.plan(now);
        for index in [1, 2] {
            observe(
                &mut host,
                candidate(index),
                locator(index),
                CandidateProvenance::Manual,
                ContactPath::Direct,
                Some(peer),
                now,
            );
        }
        assert_eq!(
            host.plan(now),
            vec![HostAction::Dial {
                candidate: candidate(1),
                locator: locator(1),
            }]
        );
        host.handle_event(
            HostEvent::ContactOpened {
                contact: ContactId(1),
                candidate: candidate(1),
                locator: locator(1),
                carrier_identity: Some(CarrierIdentity::new(vec![1]).unwrap()),
                direction: ContactDirection::Outbound,
                path: ContactPath::Direct,
            },
            now,
        )
        .unwrap();
        assert!(host.plan(now).is_empty());
    }

    #[test]
    fn carrier_match_is_only_a_scheduling_hint_and_fresh_admission_remains_required() {
        let now = Instant::now();
        let peer = [9_u8; 32];
        let carrier = CarrierIdentity::new(vec![7; 32]).unwrap();
        let mut host = normal_host(4, 2);
        let _ = host.plan(now);
        observe(
            &mut host,
            candidate(1),
            locator(1),
            CandidateProvenance::Automatic,
            ContactPath::Direct,
            None,
            now,
        );
        assert!(matches!(
            host.plan(now).as_slice(),
            [HostAction::Dial { .. }]
        ));
        host.handle_event(
            HostEvent::ContactOpened {
                contact: ContactId(2),
                candidate: candidate(2),
                locator: locator(2),
                carrier_identity: Some(carrier.clone()),
                direction: ContactDirection::Inbound,
                path: ContactPath::Direct,
            },
            now,
        )
        .unwrap();
        commit_host_admission_for_test(&mut host, ContactId(2), peer, now).unwrap();
        host.handle_event(
            HostEvent::CandidateCarrierMatched {
                candidate: candidate(1),
                locator: locator(1),
                carrier_identity: carrier,
            },
            now,
        )
        .unwrap();

        let alias = host
            .snapshot()
            .candidates
            .into_iter()
            .find(|status| status.candidate == candidate(1))
            .unwrap();
        assert_eq!(alias.previously_bound_peer_hint, Some(peer));
        assert_eq!(alias.active_contacts, 0);
        assert_eq!(host.snapshot().authenticated_contacts, 1);
        assert_eq!(
            alias.provenances,
            BTreeSet::from([CandidateProvenance::Automatic])
        );
        assert!(host.plan(now).is_empty());

        host.handle_event(
            HostEvent::ContactClosed {
                contact: ContactId(2),
                failed: false,
            },
            now,
        )
        .unwrap();
        assert_eq!(
            host.plan(now),
            vec![HostAction::Dial {
                candidate: candidate(1),
                locator: locator(1),
            }]
        );
        assert_eq!(host.snapshot().authenticated_contacts, 0);

        host.handle_event(
            HostEvent::ContactOpened {
                contact: ContactId(3),
                candidate: candidate(1),
                locator: locator(1),
                carrier_identity: Some(CarrierIdentity::new(vec![7; 32]).unwrap()),
                direction: ContactDirection::Outbound,
                path: ContactPath::Direct,
            },
            now,
        )
        .unwrap();
        assert_eq!(host.snapshot().authenticated_contacts, 0);

        let freshly_authenticated_peer = [10_u8; 32];
        commit_host_admission_for_test(&mut host, ContactId(3), freshly_authenticated_peer, now)
            .unwrap();
        let admitted = host.snapshot();
        assert_eq!(admitted.authenticated_contacts, 1);
        assert_eq!(
            admitted
                .candidates
                .into_iter()
                .find(|status| status.candidate == candidate(1))
                .unwrap()
                .previously_bound_peer_hint,
            Some(freshly_authenticated_peer)
        );
    }

    #[test]
    fn node_identity_groups_share_fairness_across_candidate_aliases() {
        let now = Instant::now();
        let peer_p = [1; 32];
        let peer_q = [2; 32];
        let mut host = normal_host(4, 1);
        let _ = host.plan(now);
        for (index, peer) in [(1, peer_p), (2, peer_p), (3, peer_q)] {
            observe(
                &mut host,
                candidate(index),
                locator(index),
                CandidateProvenance::Manual,
                ContactPath::Direct,
                Some(peer),
                now,
            );
        }
        assert_eq!(
            host.plan(now),
            vec![HostAction::Dial {
                candidate: candidate(1),
                locator: locator(1),
            }]
        );
        host.handle_event(
            HostEvent::ContactOpened {
                contact: ContactId(1),
                candidate: candidate(1),
                locator: locator(1),
                carrier_identity: None,
                direction: ContactDirection::Outbound,
                path: ContactPath::Direct,
            },
            now,
        )
        .unwrap();
        host.handle_event(
            HostEvent::ContactClosed {
                contact: ContactId(1),
                failed: false,
            },
            now,
        )
        .unwrap();
        assert_eq!(
            host.plan(now),
            vec![HostAction::Dial {
                candidate: candidate(3),
                locator: locator(3),
            }]
        );
    }

    #[test]
    fn node_identity_group_chooses_direct_alias_then_relay_during_backoff() {
        let now = Instant::now();
        let peer = [3; 32];
        let mut host = normal_host(4, 1);
        let _ = host.plan(now);
        observe(
            &mut host,
            candidate(1),
            locator(1),
            CandidateProvenance::Manual,
            ContactPath::ConnectivityRelay,
            Some(peer),
            now,
        );
        observe(
            &mut host,
            candidate(2),
            locator(2),
            CandidateProvenance::Manual,
            ContactPath::Direct,
            Some(peer),
            now,
        );
        assert_eq!(
            host.plan(now),
            vec![HostAction::Dial {
                candidate: candidate(2),
                locator: locator(2),
            }]
        );
        host.handle_event(
            HostEvent::DialFailed {
                candidate: candidate(2),
                locator: locator(2),
            },
            now,
        )
        .unwrap();
        assert_eq!(
            host.plan(now),
            vec![HostAction::Dial {
                candidate: candidate(1),
                locator: locator(1),
            }]
        );
        host.handle_event(
            HostEvent::DialFailed {
                candidate: candidate(1),
                locator: locator(1),
            },
            now,
        )
        .unwrap();
        assert_eq!(
            host.plan(now + Duration::from_millis(100)),
            vec![HostAction::Dial {
                candidate: candidate(2),
                locator: locator(2),
            }]
        );
    }

    #[test]
    fn expired_served_alias_carries_group_fairness_to_surviving_alias() {
        let now = Instant::now();
        let peer_p = [1; 32];
        let peer_q = [2; 32];
        let mut host = normal_host(4, 1);
        let _ = host.plan(now);
        for (index, peer) in [(1, peer_p), (2, peer_p), (3, peer_q)] {
            observe(
                &mut host,
                candidate(index),
                locator(index),
                CandidateProvenance::Automatic,
                ContactPath::Direct,
                Some(peer),
                now,
            );
        }
        let _ = host.plan(now);
        host.handle_event(
            HostEvent::ContactOpened {
                contact: ContactId(1),
                candidate: candidate(1),
                locator: locator(1),
                carrier_identity: None,
                direction: ContactDirection::Outbound,
                path: ContactPath::Direct,
            },
            now,
        )
        .unwrap();
        host.handle_event(
            HostEvent::CandidateExpired {
                candidate: candidate(1),
                locator: locator(1),
            },
            now,
        )
        .unwrap();
        host.handle_event(
            HostEvent::ContactClosed {
                contact: ContactId(1),
                failed: false,
            },
            now,
        )
        .unwrap();
        assert_eq!(
            host.plan(now),
            vec![HostAction::Dial {
                candidate: candidate(3),
                locator: locator(3),
            }]
        );
    }

    #[test]
    fn carrier_matched_alias_inherits_existing_group_service_watermark() {
        let now = Instant::now();
        let peer_p = [1; 32];
        let peer_q = [2; 32];
        let carrier = CarrierIdentity::new(vec![4; 32]).unwrap();
        let mut host = normal_host(4, 1);
        let _ = host.plan(now);
        observe(
            &mut host,
            candidate(1),
            locator(1),
            CandidateProvenance::Manual,
            ContactPath::Direct,
            Some(peer_p),
            now,
        );
        observe(
            &mut host,
            candidate(3),
            locator(3),
            CandidateProvenance::Manual,
            ContactPath::Direct,
            Some(peer_q),
            now,
        );
        let _ = host.plan(now);
        host.handle_event(
            HostEvent::ContactOpened {
                contact: ContactId(1),
                candidate: candidate(1),
                locator: locator(1),
                carrier_identity: Some(carrier.clone()),
                direction: ContactDirection::Outbound,
                path: ContactPath::Direct,
            },
            now,
        )
        .unwrap();
        commit_host_admission_for_test(&mut host, ContactId(1), peer_p, now).unwrap();
        host.handle_event(
            HostEvent::ContactClosed {
                contact: ContactId(1),
                failed: false,
            },
            now,
        )
        .unwrap();
        observe(
            &mut host,
            candidate(2),
            locator(2),
            CandidateProvenance::Automatic,
            ContactPath::Direct,
            None,
            now,
        );
        host.handle_event(
            HostEvent::CandidateCarrierMatched {
                candidate: candidate(2),
                locator: locator(2),
                carrier_identity: carrier,
            },
            now,
        )
        .unwrap();
        host.handle_event(
            HostEvent::CandidateExpired {
                candidate: candidate(1),
                locator: locator(1),
            },
            now,
        )
        .unwrap();
        assert_eq!(
            host.plan(now),
            vec![HostAction::Dial {
                candidate: candidate(3),
                locator: locator(3),
            }]
        );
    }

    #[test]
    fn expired_locator_late_completions_cannot_clear_new_pending_locator() {
        let now = Instant::now();
        let id = candidate(1);
        let old = locator(1);
        let current = locator(2);
        let mut host = normal_host(4, 2);
        let _ = host.plan(now);
        for address in [old.clone(), current.clone()] {
            observe(
                &mut host,
                id.clone(),
                address,
                CandidateProvenance::Automatic,
                ContactPath::Direct,
                None,
                now,
            );
        }
        assert_eq!(
            host.plan(now),
            vec![HostAction::Dial {
                candidate: id.clone(),
                locator: old.clone(),
            }]
        );
        host.handle_event(
            HostEvent::CandidateExpired {
                candidate: id.clone(),
                locator: old.clone(),
            },
            now,
        )
        .unwrap();
        assert!(host.plan(now).is_empty());
        host.handle_event(
            HostEvent::DialFailed {
                candidate: id.clone(),
                locator: old.clone(),
            },
            now,
        )
        .unwrap();
        assert_eq!(
            host.plan(now),
            vec![
                HostAction::ForgetCandidateLocator {
                    candidate: id.clone(),
                    locator: old.clone(),
                },
                HostAction::Dial {
                    candidate: id.clone(),
                    locator: current.clone(),
                },
            ]
        );
        assert_eq!(
            host.handle_event(
                HostEvent::ContactOpened {
                    contact: ContactId(9),
                    candidate: id.clone(),
                    locator: old.clone(),
                    carrier_identity: None,
                    direction: ContactDirection::Outbound,
                    path: ContactPath::Direct,
                },
                now,
            ),
            Err(MeshHostError::UnknownCandidate)
        );
        assert_eq!(host.snapshot().pending_dials, 1);

        let carrier = CarrierIdentity::new(vec![5; 32]).unwrap();
        host.handle_event(
            HostEvent::ContactOpened {
                contact: ContactId(10),
                candidate: candidate(3),
                locator: locator(3),
                carrier_identity: Some(carrier.clone()),
                direction: ContactDirection::Inbound,
                path: ContactPath::Direct,
            },
            now,
        )
        .unwrap();
        commit_host_admission_for_test(&mut host, ContactId(10), [7; 32], now).unwrap();
        observe(
            &mut host,
            id.clone(),
            old.clone(),
            CandidateProvenance::Automatic,
            ContactPath::Direct,
            None,
            now,
        );
        host.handle_event(
            HostEvent::CandidateCarrierMatched {
                candidate: id,
                locator: old,
                carrier_identity: carrier,
            },
            now,
        )
        .unwrap();
        assert_eq!(host.snapshot().pending_dials, 1);
    }

    #[test]
    fn closing_inbound_alias_preserves_distinct_pending_outbound_locator() {
        let now = Instant::now();
        let id = candidate(1);
        let inbound = locator(1);
        let outbound = locator(2);
        let mut host = normal_host(4, 2);
        let _ = host.plan(now);
        for address in [inbound.clone(), outbound.clone()] {
            observe(
                &mut host,
                id.clone(),
                address,
                CandidateProvenance::Manual,
                ContactPath::Direct,
                None,
                now,
            );
        }
        assert_eq!(
            host.plan(now),
            vec![HostAction::Dial {
                candidate: id.clone(),
                locator: inbound.clone(),
            }]
        );
        host.handle_event(
            HostEvent::DialFailed {
                candidate: id.clone(),
                locator: inbound.clone(),
            },
            now,
        )
        .unwrap();
        assert_eq!(
            host.plan(now),
            vec![HostAction::Dial {
                candidate: id.clone(),
                locator: outbound.clone(),
            }]
        );
        host.handle_event(
            HostEvent::ContactOpened {
                contact: ContactId(51),
                candidate: id.clone(),
                locator: inbound,
                carrier_identity: None,
                direction: ContactDirection::Inbound,
                path: ContactPath::Direct,
            },
            now,
        )
        .unwrap();
        host.handle_event(
            HostEvent::ContactClosed {
                contact: ContactId(51),
                failed: false,
            },
            now,
        )
        .unwrap();

        assert_eq!(host.snapshot().pending_dials, 1);
        assert!(host.plan(now).is_empty());
        assert!(
            host.handle_event(
                HostEvent::ContactOpened {
                    contact: ContactId(52),
                    candidate: id,
                    locator: outbound,
                    carrier_identity: None,
                    direction: ContactDirection::Outbound,
                    path: ContactPath::Direct,
                },
                now,
            )
            .is_ok()
        );
    }

    #[test]
    fn manual_binding_mismatch_fails_closed() {
        let now = Instant::now();
        let mut host = normal_host(4, 1);
        observe(
            &mut host,
            candidate(1),
            locator(1),
            CandidateProvenance::Manual,
            ContactPath::Direct,
            Some([1; 32]),
            now,
        );
        let _ = host.plan(now);
        host.handle_event(
            HostEvent::ContactOpened {
                contact: ContactId(9),
                candidate: candidate(1),
                locator: locator(1),
                carrier_identity: None,
                direction: ContactDirection::Outbound,
                path: ContactPath::Direct,
            },
            now,
        )
        .unwrap();
        assert_eq!(
            commit_host_admission_for_test(&mut host, ContactId(9), [2; 32], now).unwrap(),
            vec![HostAction::Close {
                contact: ContactId(9),
                reason: ContactCloseReason::AuthenticationRejected,
            }]
        );
        let snapshot = host.snapshot();
        assert_eq!(snapshot.rejected_candidates, 0);
        assert_eq!(snapshot.authenticated_contacts, 0);
        assert_eq!(snapshot.carrier_binding_count, 0);
        assert_eq!(snapshot.pending_admissions, 0);
    }

    #[test]
    fn constrained_mode_suppresses_automatic_discovery_but_keeps_manual_peers() {
        let now = Instant::now();
        let mut host = normal_host(4, 1);
        host.set_emission_policy(EmissionPolicy {
            minimum_priority: Some(Priority::Immediate),
        });
        observe(
            &mut host,
            candidate(1),
            locator(1),
            CandidateProvenance::Automatic,
            ContactPath::Direct,
            None,
            now,
        );
        observe(
            &mut host,
            candidate(2),
            locator(2),
            CandidateProvenance::Manual,
            ContactPath::Direct,
            Some([2; 32]),
            now,
        );
        assert_eq!(host.snapshot().candidate_count, 1);
        assert_eq!(
            host.plan(now),
            vec![
                HostAction::SetDiscovery { enabled: false },
                HostAction::Dial {
                    candidate: candidate(2),
                    locator: locator(2),
                },
            ]
        );
    }

    #[test]
    fn carrier_identity_neither_authorizes_nor_rejects_a_fresh_aster_peer() {
        let now = Instant::now();
        let mut host = normal_host(4, 2);
        let identity = CarrierIdentity::new(vec![7; 32]).unwrap();
        for index in 1..=2 {
            observe(
                &mut host,
                candidate(index),
                locator(index),
                CandidateProvenance::Automatic,
                ContactPath::Direct,
                None,
                now,
            );
        }
        let _ = host.plan(now);
        for index in 1..=2 {
            host.handle_event(
                HostEvent::ContactOpened {
                    contact: ContactId(index as u64),
                    candidate: candidate(index),
                    locator: locator(index),
                    carrier_identity: Some(identity.clone()),
                    direction: ContactDirection::Outbound,
                    path: ContactPath::Direct,
                },
                now,
            )
            .unwrap();
        }
        assert!(
            commit_host_admission_for_test(&mut host, ContactId(1), [1; 32], now)
                .unwrap()
                .is_empty()
        );
        assert!(
            commit_host_admission_for_test(&mut host, ContactId(2), [2; 32], now)
                .unwrap()
                .is_empty()
        );
        let snapshot = host.snapshot();
        assert_eq!(snapshot.authenticated_contacts, 2);
        assert_eq!(snapshot.carrier_binding_count, 1);
        assert_eq!(snapshot.rejected_candidates, 0);
    }

    #[test]
    fn duplicate_candidate_never_publishes_peer_or_carrier_before_admission_commit() {
        let now = Instant::now();
        let peer = [6; 32];
        let mut host = normal_host(4, 2);
        for index in 1..=2 {
            observe(
                &mut host,
                candidate(index),
                locator(index),
                CandidateProvenance::Automatic,
                ContactPath::Direct,
                None,
                now,
            );
        }
        let _ = host.plan(now);
        for index in 1..=2 {
            host.handle_event(
                HostEvent::ContactOpened {
                    contact: ContactId(index as u64),
                    candidate: candidate(index),
                    locator: locator(index),
                    carrier_identity: Some(CarrierIdentity::new(vec![index as u8; 32]).unwrap()),
                    direction: ContactDirection::Outbound,
                    path: ContactPath::Direct,
                },
                now,
            )
            .unwrap();
        }
        assert!(
            commit_host_admission_for_test(&mut host, ContactId(1), peer, now)
                .unwrap()
                .is_empty()
        );
        assert_eq!(
            commit_host_admission_for_test(&mut host, ContactId(2), peer, now).unwrap(),
            vec![HostAction::Close {
                contact: ContactId(2),
                reason: ContactCloseReason::Duplicate,
            }]
        );

        let snapshot = host.snapshot();
        assert_eq!(snapshot.carrier_binding_count, 1);
        let loser = snapshot
            .candidates
            .into_iter()
            .find(|status| status.candidate == candidate(2))
            .unwrap();
        assert_eq!(loser.previously_bound_peer_hint, None);
        assert_eq!(loser.active_contacts, 1);
        assert!(host.plan(now).is_empty());
    }

    #[test]
    fn prepared_admission_is_invisible_until_commit_and_abort_is_fail_closed() {
        let now = Instant::now();
        let peer = [31; 32];
        let identity = CarrierIdentity::new(vec![31; 32]).unwrap();
        let mut host = normal_host(4, 1);
        observe(
            &mut host,
            candidate(1),
            locator(1),
            CandidateProvenance::Manual,
            ContactPath::Direct,
            Some(peer),
            now,
        );
        host.handle_event(
            HostEvent::ContactOpened {
                contact: ContactId(1),
                candidate: candidate(1),
                locator: locator(1),
                carrier_identity: Some(identity),
                direction: ContactDirection::Inbound,
                path: ContactPath::Direct,
            },
            now,
        )
        .unwrap();

        let (token, actions) = host
            .prepare_authenticated(ContactId(1), peer)
            .unwrap()
            .into_parts();
        assert!(actions.is_empty());
        let token = token.unwrap();
        let prepared = host.snapshot();
        assert_eq!(prepared.pending_admissions, 1);
        assert_eq!(prepared.authenticated_contacts, 0);
        assert_eq!(prepared.carrier_binding_count, 0);
        assert_eq!(prepared.candidates[0].previously_bound_peer_hint, None);

        let token_id = token.id;
        host.abort_authenticated(token).unwrap();
        assert_eq!(
            host.abort_authenticated(AdmissionToken { id: token_id }),
            Err(MeshHostError::StaleAdmission)
        );
        assert_eq!(
            host.commit_authenticated(AdmissionToken { id: token_id }, now),
            Err(MeshHostError::StaleAdmission)
        );
        let aborted = host.snapshot();
        assert_eq!(aborted.pending_admissions, 0);
        assert_eq!(aborted.authenticated_contacts, 0);
        assert_eq!(aborted.carrier_binding_count, 0);
        assert_eq!(aborted.candidates[0].previously_bound_peer_hint, None);
    }

    #[test]
    fn prepared_admission_commits_once_after_durable_authorization() {
        let now = Instant::now();
        let peer = [32; 32];
        let identity = CarrierIdentity::new(vec![32; 32]).unwrap();
        let mut host = normal_host(4, 1);
        observe(
            &mut host,
            candidate(1),
            locator(1),
            CandidateProvenance::Manual,
            ContactPath::Direct,
            Some(peer),
            now,
        );
        host.handle_event(
            HostEvent::ContactOpened {
                contact: ContactId(1),
                candidate: candidate(1),
                locator: locator(1),
                carrier_identity: Some(identity),
                direction: ContactDirection::Inbound,
                path: ContactPath::Direct,
            },
            now,
        )
        .unwrap();

        let (token, actions) = host
            .prepare_authenticated(ContactId(1), peer)
            .unwrap()
            .into_parts();
        assert!(actions.is_empty());
        let token = token.unwrap();
        let token_id = token.id;
        assert!(host.commit_authenticated(token, now).unwrap().is_empty());
        assert_eq!(
            host.commit_authenticated(AdmissionToken { id: token_id }, now),
            Err(MeshHostError::StaleAdmission)
        );
        assert_eq!(
            host.abort_authenticated(AdmissionToken { id: token_id }),
            Err(MeshHostError::StaleAdmission)
        );

        let committed = host.snapshot();
        assert_eq!(committed.pending_admissions, 0);
        assert_eq!(committed.authenticated_contacts, 1);
        assert_eq!(committed.carrier_binding_count, 1);
        assert_eq!(
            committed.candidates[0].previously_bound_peer_hint,
            Some(peer)
        );
    }

    #[test]
    fn closing_contact_invalidates_prepared_admission_without_binding_identity() {
        let now = Instant::now();
        let peer = [33; 32];
        let mut host = normal_host(4, 1);
        observe(
            &mut host,
            candidate(1),
            locator(1),
            CandidateProvenance::Manual,
            ContactPath::Direct,
            Some(peer),
            now,
        );
        host.handle_event(
            HostEvent::ContactOpened {
                contact: ContactId(1),
                candidate: candidate(1),
                locator: locator(1),
                carrier_identity: Some(CarrierIdentity::new(vec![33; 32]).unwrap()),
                direction: ContactDirection::Inbound,
                path: ContactPath::Direct,
            },
            now,
        )
        .unwrap();
        let (token, actions) = host
            .prepare_authenticated(ContactId(1), peer)
            .unwrap()
            .into_parts();
        assert!(actions.is_empty());
        host.handle_event(
            HostEvent::ContactClosed {
                contact: ContactId(1),
                failed: true,
            },
            now,
        )
        .unwrap();

        let token_id = token.unwrap().id;
        assert_eq!(
            host.commit_authenticated(AdmissionToken { id: token_id }, now),
            Err(MeshHostError::StaleAdmission)
        );
        assert_eq!(
            host.abort_authenticated(AdmissionToken { id: token_id }),
            Err(MeshHostError::StaleAdmission)
        );
        let snapshot = host.snapshot();
        assert_eq!(snapshot.pending_admissions, 0);
        assert_eq!(snapshot.authenticated_contacts, 0);
        assert_eq!(snapshot.carrier_binding_count, 0);
    }

    #[test]
    fn simultaneous_preparations_for_one_peer_issue_exactly_one_live_token() {
        let now = Instant::now();
        let peer = [34; 32];
        let mut host = normal_host(4, 2);
        for ordinal in 1..=2 {
            observe(
                &mut host,
                candidate(ordinal),
                locator(ordinal),
                CandidateProvenance::Manual,
                ContactPath::Direct,
                Some(peer),
                now,
            );
            host.handle_event(
                HostEvent::ContactOpened {
                    contact: ContactId(ordinal as u64),
                    candidate: candidate(ordinal),
                    locator: locator(ordinal),
                    carrier_identity: Some(CarrierIdentity::new(vec![ordinal as u8; 32]).unwrap()),
                    direction: ContactDirection::Inbound,
                    path: ContactPath::Direct,
                },
                now,
            )
            .unwrap();
        }

        let (first, first_actions) = host
            .prepare_authenticated(ContactId(1), peer)
            .unwrap()
            .into_parts();
        assert!(first_actions.is_empty());
        let (second, second_actions) = host
            .prepare_authenticated(ContactId(2), peer)
            .unwrap()
            .into_parts();
        assert!(second.is_none());
        assert_eq!(
            second_actions,
            vec![HostAction::Close {
                contact: ContactId(2),
                reason: ContactCloseReason::Duplicate,
            }]
        );
        assert_eq!(host.snapshot().pending_admissions, 1);

        host.abort_authenticated(first.unwrap()).unwrap();
        assert_eq!(host.snapshot().pending_admissions, 0);
    }

    #[test]
    fn admission_identifier_exhaustion_is_checked_without_pending_state_mutation() {
        let now = Instant::now();
        let mut host = normal_host(4, 2);
        for ordinal in 1..=2 {
            let peer = [40 + ordinal as u8; 32];
            observe(
                &mut host,
                candidate(ordinal),
                locator(ordinal),
                CandidateProvenance::Manual,
                ContactPath::Direct,
                Some(peer),
                now,
            );
            host.handle_event(
                HostEvent::ContactOpened {
                    contact: ContactId(ordinal as u64),
                    candidate: candidate(ordinal),
                    locator: locator(ordinal),
                    carrier_identity: Some(
                        CarrierIdentity::new(vec![40 + ordinal as u8; 32]).unwrap(),
                    ),
                    direction: ContactDirection::Inbound,
                    path: ContactPath::Direct,
                },
                now,
            )
            .unwrap();
        }

        host.next_admission = Some(u64::MAX);
        let (last, actions) = host
            .prepare_authenticated(ContactId(1), [41; 32])
            .unwrap()
            .into_parts();
        assert!(actions.is_empty());
        let last = last.unwrap();
        assert_eq!(last.id, u64::MAX);
        assert_eq!(host.next_admission, None);
        assert_eq!(host.snapshot().pending_admissions, 1);

        assert_eq!(
            host.prepare_authenticated(ContactId(2), [42; 32])
                .unwrap_err(),
            MeshHostError::AdmissionIdExhausted
        );
        assert_eq!(host.snapshot().pending_admissions, 1);
        host.abort_authenticated(last).unwrap();
        assert_eq!(host.snapshot().pending_admissions, 0);
        assert_eq!(
            host.prepare_authenticated(ContactId(2), [42; 32])
                .unwrap_err(),
            MeshHostError::AdmissionIdExhausted
        );
        assert_eq!(host.snapshot().pending_admissions, 0);
    }

    #[test]
    fn locator_and_carrier_binding_state_are_bounded_and_expire() {
        let now = Instant::now();
        let mut host = normal_host(2, 1);
        observe(
            &mut host,
            candidate(1),
            locator(1),
            CandidateProvenance::Automatic,
            ContactPath::Direct,
            None,
            now,
        );
        observe(
            &mut host,
            candidate(1),
            locator(2),
            CandidateProvenance::Automatic,
            ContactPath::Direct,
            None,
            now,
        );
        assert_eq!(host.snapshot().locator_count, 2);
        assert_eq!(
            host.handle_event(
                HostEvent::CandidateObserved {
                    candidate: candidate(1),
                    locator: locator(3),
                    provenance: CandidateProvenance::Automatic,
                    path: ContactPath::Direct,
                    expected_peer: None,
                },
                now,
            ),
            Err(MeshHostError::Capacity("locator"))
        );

        let _ = host.plan(now);
        host.handle_event(
            HostEvent::ContactOpened {
                contact: ContactId(1),
                candidate: candidate(1),
                locator: locator(1),
                carrier_identity: Some(CarrierIdentity::new(vec![9; 32]).unwrap()),
                direction: ContactDirection::Outbound,
                path: ContactPath::Direct,
            },
            now,
        )
        .unwrap();
        commit_host_admission_for_test(&mut host, ContactId(1), [1; 32], now).unwrap();
        assert_eq!(host.snapshot().carrier_binding_count, 1);
        host.handle_event(
            HostEvent::ContactClosed {
                contact: ContactId(1),
                failed: false,
            },
            now,
        )
        .unwrap();
        let _ = host.plan(now + Duration::from_secs(61));
        let snapshot = host.snapshot();
        assert_eq!(snapshot.candidate_count, 0);
        assert_eq!(snapshot.locator_count, 0);
        assert_eq!(snapshot.carrier_binding_count, 0);
    }

    #[test]
    fn direct_failure_uses_relay_then_retries_direct_after_backoff() {
        let now = Instant::now();
        let mut host = normal_host(4, 1);
        let id = candidate(1);
        let direct = locator(1);
        let relay = CandidateLocator::new("/p2p-circuit/relay-1").unwrap();
        observe(
            &mut host,
            id.clone(),
            direct.clone(),
            CandidateProvenance::Manual,
            ContactPath::Direct,
            Some([1; 32]),
            now,
        );
        observe(
            &mut host,
            id.clone(),
            relay.clone(),
            CandidateProvenance::Manual,
            ContactPath::ConnectivityRelay,
            Some([1; 32]),
            now,
        );
        let actions = host.plan(now);
        assert!(actions.contains(&HostAction::Dial {
            candidate: id.clone(),
            locator: direct.clone(),
        }));
        host.handle_event(
            HostEvent::DialFailed {
                candidate: id.clone(),
                locator: direct.clone(),
            },
            now,
        )
        .unwrap();
        assert_eq!(
            host.plan(now),
            vec![HostAction::Dial {
                candidate: id.clone(),
                locator: relay.clone(),
            }]
        );
        host.handle_event(
            HostEvent::DialFailed {
                candidate: id.clone(),
                locator: relay,
            },
            now,
        )
        .unwrap();
        assert_eq!(
            host.plan(now + Duration::from_millis(100)),
            vec![HostAction::Dial {
                candidate: id,
                locator: direct,
            }]
        );
    }

    #[test]
    fn duplicate_contact_is_closed_and_quantum_is_enforced() {
        let now = Instant::now();
        let mut host = normal_host(4, 2);
        observe(
            &mut host,
            candidate(1),
            locator(1),
            CandidateProvenance::Manual,
            ContactPath::Direct,
            Some([1; 32]),
            now,
        );
        let _ = host.plan(now);
        host.handle_event(
            HostEvent::ContactOpened {
                contact: ContactId(1),
                candidate: candidate(1),
                locator: locator(1),
                carrier_identity: None,
                direction: ContactDirection::Outbound,
                path: ContactPath::Direct,
            },
            now,
        )
        .unwrap();
        assert_eq!(
            host.handle_event(
                HostEvent::ContactOpened {
                    contact: ContactId(2),
                    candidate: candidate(1),
                    locator: locator(1),
                    carrier_identity: None,
                    direction: ContactDirection::Inbound,
                    path: ContactPath::Direct,
                },
                now,
            )
            .unwrap(),
            vec![HostAction::Close {
                contact: ContactId(2),
                reason: ContactCloseReason::Duplicate,
            }]
        );
        assert!(
            host.plan(now + Duration::from_secs(1))
                .contains(&HostAction::Close {
                    contact: ContactId(1),
                    reason: ContactCloseReason::FairnessQuantum,
                })
        );
    }

    #[test]
    fn address_change_replaces_expired_locator_without_inheriting_authorization() {
        let now = Instant::now();
        let mut host = normal_host(4, 1);
        let id = candidate(1);
        let old = locator(1);
        let new = locator(2);
        observe(
            &mut host,
            id.clone(),
            old.clone(),
            CandidateProvenance::Automatic,
            ContactPath::Direct,
            None,
            now,
        );
        host.handle_event(
            HostEvent::CandidateExpired {
                candidate: id.clone(),
                locator: old,
            },
            now,
        )
        .unwrap();
        observe(
            &mut host,
            id.clone(),
            new.clone(),
            CandidateProvenance::Automatic,
            ContactPath::Direct,
            None,
            now,
        );
        assert!(host.plan(now).contains(&HostAction::Dial {
            candidate: id,
            locator: new,
        }));
        assert_eq!(host.snapshot().authenticated_contacts, 0);
    }

    #[test]
    fn hundred_candidates_receive_fair_bounded_contact_opportunities() {
        let start = Instant::now();
        let mut host = normal_host(100, 4);
        for index in 0..100 {
            observe(
                &mut host,
                candidate(index),
                locator(index),
                CandidateProvenance::Manual,
                ContactPath::Direct,
                Some([u8::try_from(index % 250).unwrap(); 32]),
                start,
            );
        }
        let mut served = BTreeMap::<CandidateId, usize>::new();
        let mut contact_id = 1_u64;
        for round in 0..25 {
            let now = start + Duration::from_secs(round * 2);
            let actions = host.plan(now);
            let dials = actions
                .into_iter()
                .filter_map(|action| match action {
                    HostAction::Dial { candidate, locator } => Some((candidate, locator)),
                    _ => None,
                })
                .collect::<Vec<_>>();
            assert!(dials.len() <= 4);
            let mut opened = Vec::new();
            for (id, address) in dials {
                let contact = ContactId(contact_id);
                contact_id += 1;
                host.handle_event(
                    HostEvent::ContactOpened {
                        contact,
                        candidate: id.clone(),
                        locator: address,
                        carrier_identity: None,
                        direction: ContactDirection::Outbound,
                        path: ContactPath::Direct,
                    },
                    now,
                )
                .unwrap();
                *served.entry(id).or_default() += 1;
                opened.push(contact);
            }
            assert!(host.snapshot().active_contacts <= 4);
            for contact in opened {
                host.handle_event(
                    HostEvent::ContactClosed {
                        contact,
                        failed: false,
                    },
                    now + Duration::from_secs(1),
                )
                .unwrap();
            }
        }
        assert_eq!(served.len(), 100);
        assert_eq!(served.values().min(), served.values().max());
    }

    #[test]
    fn automatic_candidates_expire_while_manual_candidates_persist() {
        let now = Instant::now();
        let mut host = normal_host(4, 1);
        observe(
            &mut host,
            candidate(1),
            locator(1),
            CandidateProvenance::Automatic,
            ContactPath::Direct,
            None,
            now,
        );
        observe(
            &mut host,
            candidate(2),
            locator(2),
            CandidateProvenance::Manual,
            ContactPath::Direct,
            Some([2; 32]),
            now,
        );
        let _ = host.plan(now + Duration::from_secs(61));
        let snapshot = host.snapshot();
        assert_eq!(snapshot.candidate_count, 1);
        assert_eq!(snapshot.candidates[0].candidate, candidate(2));
    }

    #[test]
    fn automatic_refresh_extends_host_expiry_without_resetting_retry_backoff() {
        let now = Instant::now();
        let id = candidate(1);
        let address = locator(1);
        let mut host = normal_host(4, 1);
        let _ = host.plan(now);
        observe(
            &mut host,
            id.clone(),
            address.clone(),
            CandidateProvenance::Automatic,
            ContactPath::Direct,
            None,
            now,
        );
        assert!(matches!(
            host.plan(now).as_slice(),
            [HostAction::Dial { .. }]
        ));
        host.handle_event(
            HostEvent::DialFailed {
                candidate: id.clone(),
                locator: address.clone(),
            },
            now,
        )
        .unwrap();

        let refreshed = now + Duration::from_millis(50);
        host.handle_event(
            HostEvent::CandidateRefreshed {
                candidate: id.clone(),
                locator: address.clone(),
            },
            refreshed,
        )
        .unwrap();
        assert!(host.plan(refreshed).is_empty());
        assert_eq!(
            host.plan(now + Duration::from_millis(100)),
            vec![HostAction::Dial {
                candidate: id.clone(),
                locator: address.clone(),
            }]
        );
        host.handle_event(
            HostEvent::DialFailed {
                candidate: id,
                locator: address,
            },
            now + Duration::from_millis(100),
        )
        .unwrap();
        assert_eq!(host.snapshot().candidates[0].failures, 2);
    }
}
