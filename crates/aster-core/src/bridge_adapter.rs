//! Selected, store-independent Event bridge adapter.
//!
//! This module composes the existing canonical semantic-v2 bridge objects with
//! the selected reference provider. It does not define a transport frame,
//! persistence model, runtime, or new cryptographic format. Exact authorization,
//! wrapper, and source bytes remain opaque; callers may persist those bytes and
//! must ask this adapter to authenticate them again before promotion.

use crate::bridge::{
    self, AuthorizationEnvelope, BridgeAuthorization, BridgeHop, BridgeNarrowing, BridgeRoute,
    EnabledAuthorization,
};
use crate::crypto::{
    BridgeCryptoProvider, BridgeEdgeEnrollment, BridgeEdgeEnrollmentClaims,
    ReferenceEnvelopeSealer, VerifiedBridgeAuthorization as ProviderVerifiedAuthorization,
    VerifiedBridgeSourceRoute as ProviderVerifiedSource,
    VerifiedBridgeWrapper as ProviderVerifiedWrapper,
};
use crate::envelope::EnvelopeSealer;
use crate::model::{DataClass, ItemId, NodeId, Priority, Scope, Topic};
use std::collections::{BTreeMap, BTreeSet};
use std::error::Error;
use std::fmt;

type ProviderVerifiedEnrollment =
    <ReferenceEnvelopeSealer as BridgeCryptoProvider>::VerifiedEdgeEnrollment;

/// Maximum byte length of one exact selected bridge route wrapper.
pub const MAX_SELECTED_BRIDGE_WRAPPER_BYTES: usize = bridge::MAX_WRAPPER_TOTAL_BYTES;

struct AuthorizationMaps<'a> {
    records: BTreeMap<[u8; 32], &'a AuthorizationEnvelope>,
    active: BTreeMap<[u8; 32], [u8; 32]>,
}

/// Sanitized selected-bridge failure.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SelectedBridgeError {
    message: &'static str,
}

impl SelectedBridgeError {
    fn invalid(message: &'static str) -> Self {
        Self { message }
    }

    fn authentication() -> Self {
        Self::invalid("bridge authentication or canonical validation failed")
    }
}

impl fmt::Display for SelectedBridgeError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.message)
    }
}

impl Error for SelectedBridgeError {}

/// Caller-retained position in the authority's contiguous bridge-control chain.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct BridgeAuthorizationLink {
    sequence: u64,
    previous: Option<[u8; 32]>,
    generation: u64,
}

impl BridgeAuthorizationLink {
    /// Creates one canonical control-chain link.
    pub fn new(
        sequence: u64,
        previous: Option<[u8; 32]>,
        generation: u64,
    ) -> Result<Self, SelectedBridgeError> {
        if sequence == 0 || generation == 0 || (sequence == 1) != previous.is_none() {
            return Err(SelectedBridgeError::invalid(
                "bridge authorization link is not a canonical nonzero chain position",
            ));
        }
        Ok(Self {
            sequence,
            previous,
            generation,
        })
    }

    /// Mission-wide bridge-control sequence.
    pub const fn sequence(&self) -> u64 {
        self.sequence
    }

    /// Exact predecessor in the mission-wide bridge-control chain.
    pub const fn previous(&self) -> Option<[u8; 32]> {
        self.previous
    }

    /// Monotonic generation for one directed bridge edge.
    pub const fn generation(&self) -> u64 {
        self.generation
    }
}

/// Authority-owned topic, priority, and total-hop limits for one edge.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SelectedBridgeAuthorizationPolicy {
    topics: BTreeSet<Topic>,
    priorities: BTreeSet<Priority>,
    max_total_hops: u8,
}

impl SelectedBridgeAuthorizationPolicy {
    /// Builds a canonical, nonempty authorization policy.
    pub fn new(
        topics: Vec<Topic>,
        priorities: Vec<Priority>,
        max_total_hops: u8,
    ) -> Result<Self, SelectedBridgeError> {
        let topic_count = topics.len();
        let topics = topics.into_iter().collect::<BTreeSet<_>>();
        let priority_count = priorities.len();
        let priorities = priorities.into_iter().collect::<BTreeSet<_>>();
        if topics.is_empty()
            || topics.len() != topic_count
            || topics.len() > bridge::MAX_TOPICS
            || priorities.is_empty()
            || priorities.len() != priority_count
            || max_total_hops == 0
            || usize::from(max_total_hops) > bridge::MAX_HOPS
        {
            return Err(SelectedBridgeError::invalid(
                "bridge authorization policy is empty, duplicate, or out of bounds",
            ));
        }
        Ok(Self {
            topics,
            priorities,
            max_total_hops,
        })
    }
}

/// Bridge-local policy which may only narrow an authority policy.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SelectedBridgeNarrowingPolicy {
    topics: BTreeSet<Topic>,
    priorities: BTreeSet<Priority>,
}

impl SelectedBridgeNarrowingPolicy {
    /// Builds a canonical local narrowing. An empty topic set means every
    /// authority-allowed topic; priorities are always explicit and nonempty.
    pub fn new(topics: Vec<Topic>, priorities: Vec<Priority>) -> Result<Self, SelectedBridgeError> {
        let topic_count = topics.len();
        let topics = topics.into_iter().collect::<BTreeSet<_>>();
        let priority_count = priorities.len();
        let priorities = priorities.into_iter().collect::<BTreeSet<_>>();
        if topics.len() != topic_count
            || topics.len() > bridge::MAX_TOPICS
            || priorities.is_empty()
            || priorities.len() != priority_count
        {
            return Err(SelectedBridgeError::invalid(
                "bridge narrowing is duplicate or out of bounds",
            ));
        }
        Ok(Self { topics, priorities })
    }

    /// Exact locally selected topics in canonical order.
    ///
    /// An empty iterator means every topic allowed by the authority record.
    pub fn topics(&self) -> impl ExactSizeIterator<Item = &Topic> {
        self.topics.iter()
    }

    /// Exact locally selected priorities in canonical order.
    pub fn priorities(&self) -> impl ExactSizeIterator<Item = &Priority> {
        self.priorities.iter()
    }

    fn canonical(&self) -> BridgeNarrowing {
        BridgeNarrowing {
            topics: self.topics.clone(),
            allowed_priority_mask: priority_mask(&self.priorities),
        }
    }
}

/// Provider-owned bridge enrollment. Credential and route-grant material never
/// crosses this opaque boundary.
pub struct SelectedBridgeEnrollment {
    inner: BridgeEdgeEnrollment,
}

impl fmt::Debug for SelectedBridgeEnrollment {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("SelectedBridgeEnrollment")
            .field("authenticated_artifact", &"[PROVIDER-OWNED]")
            .finish()
    }
}

/// Authority-authenticated enrollment for one exact directed scope/epoch edge.
pub struct VerifiedSelectedBridgeEnrollment {
    inner: ProviderVerifiedEnrollment,
    claims: BridgeEdgeEnrollmentClaims,
}

impl VerifiedSelectedBridgeEnrollment {
    pub const fn bridge_node_id(&self) -> NodeId {
        self.claims.bridge_node_id
    }

    pub const fn source_scope(&self) -> &Scope {
        &self.claims.source_scope
    }

    pub const fn source_route_epoch(&self) -> u64 {
        self.claims.source_route_epoch
    }

    pub const fn target_scope(&self) -> &Scope {
        &self.claims.target_scope
    }

    pub const fn target_route_epoch(&self) -> u64 {
        self.claims.target_route_epoch
    }
}

impl fmt::Debug for VerifiedSelectedBridgeEnrollment {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("VerifiedSelectedBridgeEnrollment")
            .field("bridge_node_id", &self.claims.bridge_node_id)
            .field("source_scope", &self.claims.source_scope)
            .field("source_route_epoch", &self.claims.source_route_epoch)
            .field("target_scope", &self.claims.target_scope)
            .field("target_route_epoch", &self.claims.target_route_epoch)
            .field("credential", &"[AUTHORITY-VERIFIED]")
            .finish()
    }
}

/// Fresh provider-authenticated bridge authorization suitable for durable commit.
pub struct VerifiedSelectedBridgeAuthorization {
    inner: ProviderVerifiedAuthorization,
    exact_bytes: Vec<u8>,
}

impl VerifiedSelectedBridgeAuthorization {
    fn envelope(&self) -> &AuthorizationEnvelope {
        self.inner.envelope()
    }

    /// Exact opaque authorization bytes authenticated by this capability.
    pub fn exact_bytes(&self) -> &[u8] {
        &self.exact_bytes
    }

    pub fn envelope_id(&self) -> [u8; 32] {
        self.envelope().envelope_id
    }

    pub fn authority_id(&self) -> NodeId {
        self.envelope().authorization.authority_id
    }

    pub fn control_signer(&self) -> NodeId {
        self.inner.control_signer()
    }

    pub fn control_sequence(&self) -> u64 {
        self.envelope().authorization.control_sequence
    }

    pub fn previous_control_id(&self) -> Option<[u8; 32]> {
        self.envelope().authorization.previous_control_id
    }

    pub fn authorization_key(&self) -> [u8; 32] {
        self.envelope().authorization.authorization_key
    }

    pub fn generation(&self) -> u64 {
        self.envelope().authorization.generation
    }

    pub fn is_enabled(&self) -> bool {
        self.envelope().authorization.enabled.is_some()
    }

    /// Exact bridge identity authorized for this directed edge.
    pub fn bridge_node_id(&self) -> NodeId {
        self.envelope().authorization.bridge_node_id
    }

    /// Exact source scope of this directed edge.
    pub fn source_scope(&self) -> &Scope {
        &self.envelope().authorization.source_scope
    }

    /// Exact target scope of this directed edge.
    pub fn target_scope(&self) -> &Scope {
        &self.envelope().authorization.target_scope
    }

    /// Enabled source route epoch, or `None` for a disabled record.
    pub fn source_route_epoch(&self) -> Option<u64> {
        self.envelope()
            .authorization
            .enabled
            .as_ref()
            .map(|enabled| enabled.source_route_epoch)
    }

    /// Enabled target route epoch, or `None` for a disabled record.
    pub fn target_route_epoch(&self) -> Option<u64> {
        self.envelope()
            .authorization
            .enabled
            .as_ref()
            .map(|enabled| enabled.target_route_epoch)
    }

    /// Authority-allowed topics, or `None` for a disabled record.
    pub fn allowed_topics(&self) -> Option<&[Topic]> {
        self.envelope()
            .authorization
            .enabled
            .as_ref()
            .map(|enabled| enabled.topics.as_slice())
    }

    /// Returns whether the supplied bridge-local policy is a valid narrowing
    /// of this currently enabled authority record.
    pub fn validate_narrowing(
        &self,
        narrowing: &SelectedBridgeNarrowingPolicy,
    ) -> Result<(), SelectedBridgeError> {
        let enabled = self
            .envelope()
            .authorization
            .enabled
            .as_ref()
            .ok_or_else(SelectedBridgeError::authentication)?;
        narrowing
            .canonical()
            .validate_subset(enabled)
            .map_err(|_| SelectedBridgeError::authentication())
    }
}

impl fmt::Debug for VerifiedSelectedBridgeAuthorization {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("VerifiedSelectedBridgeAuthorization")
            .field("envelope_id", &self.envelope_id())
            .field("authorization_key", &self.authorization_key())
            .field("generation", &self.generation())
            .field("enabled", &self.is_enabled())
            .field("sealed_len", &self.exact_bytes.len())
            .finish()
    }
}

/// Freshly authenticated Event route plus the exact opaque bytes required for
/// durable custody. No payload plaintext is retained or exposed here.
pub struct VerifiedSelectedBridgeEventRoute {
    wrapper: ProviderVerifiedWrapper,
    source: ProviderVerifiedSource,
    verifier_id: NodeId,
    exact_wrapper_bytes: Vec<u8>,
    exact_source_bytes: Vec<u8>,
    authorization_ids: Vec<[u8; 32]>,
}

impl VerifiedSelectedBridgeEventRoute {
    pub fn exact_wrapper_bytes(&self) -> &[u8] {
        &self.exact_wrapper_bytes
    }

    pub fn exact_source_bytes(&self) -> &[u8] {
        &self.exact_source_bytes
    }

    pub fn wrapper_envelope_id(&self) -> [u8; 32] {
        self.wrapper.wrapper_envelope_id()
    }

    pub fn bridge_route_id(&self) -> [u8; 32] {
        self.wrapper.route().bridge_route_id
    }

    pub fn origin_envelope_id(&self) -> [u8; 32] {
        self.wrapper.route().origin_envelope_id
    }

    pub fn source_item_id(&self) -> ItemId {
        self.wrapper.route().source_item_id
    }

    pub fn publisher(&self) -> NodeId {
        self.source.header().stamp.dot.publisher
    }

    pub fn origin_scope(&self) -> &Scope {
        &self.wrapper.route().origin_scope
    }

    pub fn origin_route_epoch(&self) -> u64 {
        self.wrapper.route().origin_route_epoch
    }

    pub fn current_scope(&self) -> &Scope {
        &self.wrapper.route().current_scope
    }

    pub fn current_route_epoch(&self) -> u64 {
        self.wrapper.route().current_route_epoch
    }

    pub fn topic(&self) -> &Topic {
        &self.source.header().topic
    }

    pub fn priority(&self) -> Priority {
        self.source.header().priority
    }

    /// Source-authenticated nonzero position in the publisher's Event stream.
    pub fn event_sequence(&self) -> u64 {
        self.source
            .header()
            .event_sequence
            .expect("selected bridge routes authenticate Event sources")
    }

    /// Source-authenticated finite custody lifetime, when present.
    pub fn ttl_ms(&self) -> Option<u64> {
        self.source.header().ttl_ms
    }

    /// Whether the source-authenticated Event is a tombstone.
    pub fn is_tombstone(&self) -> bool {
        self.source.header().tombstone
    }

    pub fn hop_count(&self) -> u8 {
        u8::try_from(self.wrapper.route().hops.len())
            .expect("canonical bridge routes contain at most eight hops")
    }

    pub fn authorization_envelope_ids(&self) -> &[[u8; 32]] {
        &self.authorization_ids
    }
}

impl fmt::Debug for VerifiedSelectedBridgeEventRoute {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("VerifiedSelectedBridgeEventRoute")
            .field("wrapper_envelope_id", &self.wrapper_envelope_id())
            .field("bridge_route_id", &self.bridge_route_id())
            .field("origin_envelope_id", &self.origin_envelope_id())
            .field("source_item_id", &self.source_item_id())
            .field("origin_scope", &self.origin_scope())
            .field("current_scope", &self.current_scope())
            .field("hop_count", &self.hop_count())
            .field("source_sealed_len", &self.exact_source_bytes.len())
            .field("wrapper_sealed_len", &self.exact_wrapper_bytes.len())
            .field("payload", &"[NONE]")
            .finish()
    }
}

/// Store-, runtime-, and transport-independent selected Event bridge operations.
pub struct SelectedEventBridgeAdapter;

impl SelectedEventBridgeAdapter {
    /// Creates an opaque bridge-node-signed enrollment for one exact edge.
    pub fn create_enrollment(
        bridge_provider: &ReferenceEnvelopeSealer,
        source_scope: &Scope,
        source_route_epoch: u64,
        target_scope: &Scope,
        target_route_epoch: u64,
    ) -> Result<SelectedBridgeEnrollment, SelectedBridgeError> {
        bridge_provider
            .create_bridge_edge_enrollment(
                source_scope,
                source_route_epoch,
                target_scope,
                target_route_epoch,
            )
            .map(|inner| SelectedBridgeEnrollment { inner })
            .map_err(|_| SelectedBridgeError::authentication())
    }

    /// Authenticates an enrollment through the mission authority provider.
    pub fn verify_enrollment(
        authority_provider: &ReferenceEnvelopeSealer,
        enrollment: &SelectedBridgeEnrollment,
    ) -> Result<VerifiedSelectedBridgeEnrollment, SelectedBridgeError> {
        let inner = authority_provider
            .open_bridge_edge_enrollment(&enrollment.inner)
            .map_err(|_| SelectedBridgeError::authentication())?;
        let claims = ReferenceEnvelopeSealer::bridge_edge_enrollment_claims(&inner);
        if claims.mission_id != authority_provider.bridge_mission_id() {
            return Err(SelectedBridgeError::authentication());
        }
        Ok(VerifiedSelectedBridgeEnrollment { inner, claims })
    }

    /// Issues and reopens one enabled authorization without crossing a store boundary.
    pub fn issue_authorization(
        authority_provider: &mut ReferenceEnvelopeSealer,
        enrollment: &VerifiedSelectedBridgeEnrollment,
        link: BridgeAuthorizationLink,
        policy: &SelectedBridgeAuthorizationPolicy,
    ) -> Result<VerifiedSelectedBridgeAuthorization, SelectedBridgeError> {
        let principal = authority_provider
            .control_principal()
            .ok_or_else(SelectedBridgeError::authentication)?;
        if enrollment.claims.mission_id != authority_provider.bridge_mission_id() {
            return Err(SelectedBridgeError::authentication());
        }
        let authorization_key = bridge::bridge_authorization_key(
            &enrollment.claims.mission_id,
            &enrollment.claims.bridge_node_id,
            &enrollment.claims.source_scope,
            &enrollment.claims.target_scope,
        )
        .map_err(|_| SelectedBridgeError::authentication())?;
        let mut authorization = BridgeAuthorization {
            mission_id: enrollment.claims.mission_id,
            authority_id: principal.authority,
            control_sequence: link.sequence,
            previous_control_id: link.previous,
            authorization_key,
            generation: link.generation,
            bridge_node_id: enrollment.claims.bridge_node_id,
            source_scope: enrollment.claims.source_scope.clone(),
            target_scope: enrollment.claims.target_scope.clone(),
            enabled: Some(EnabledAuthorization {
                source_route_epoch: enrollment.claims.source_route_epoch,
                target_route_epoch: enrollment.claims.target_route_epoch,
                source_route_commitment: [0; 32],
                target_route_commitment: [0; 32],
                allowed_priority_mask: priority_mask(&policy.priorities),
                max_total_hops: policy.max_total_hops,
                topics: policy.topics.iter().cloned().collect(),
                bridge_credential: Vec::new(),
                authority_credential_signature: Vec::new(),
            }),
            authority_control_signature: Vec::new(),
        };
        authority_provider
            .bind_bridge_edge_enrollment(&enrollment.inner, &mut authorization)
            .map_err(|_| SelectedBridgeError::authentication())?;
        let exact_bytes = authority_provider
            .seal_bridge_authorization(authorization)
            .map_err(|_| SelectedBridgeError::authentication())?;
        Self::verify_authorization(authority_provider, &exact_bytes)
    }

    /// Issues a higher-generation disabled record for the same exact edge.
    pub fn issue_disabled_authorization(
        authority_provider: &mut ReferenceEnvelopeSealer,
        current: &VerifiedSelectedBridgeAuthorization,
        link: BridgeAuthorizationLink,
    ) -> Result<VerifiedSelectedBridgeAuthorization, SelectedBridgeError> {
        let principal = authority_provider
            .control_principal()
            .ok_or_else(SelectedBridgeError::authentication)?;
        let current_record = &current.envelope().authorization;
        if current_record.mission_id != authority_provider.bridge_mission_id()
            || current_record.authority_id != principal.authority
            || current_record.enabled.is_none()
            || current_record
                .generation
                .checked_add(1)
                .is_none_or(|next| next != link.generation)
        {
            return Err(SelectedBridgeError::authentication());
        }
        let authorization = BridgeAuthorization {
            mission_id: current_record.mission_id,
            authority_id: current_record.authority_id,
            control_sequence: link.sequence,
            previous_control_id: link.previous,
            authorization_key: current_record.authorization_key,
            generation: link.generation,
            bridge_node_id: current_record.bridge_node_id,
            source_scope: current_record.source_scope.clone(),
            target_scope: current_record.target_scope.clone(),
            enabled: None,
            authority_control_signature: Vec::new(),
        };
        let exact_bytes = authority_provider
            .seal_bridge_authorization(authorization)
            .map_err(|_| SelectedBridgeError::authentication())?;
        Self::verify_authorization(authority_provider, &exact_bytes)
    }

    /// Freshly authenticates persisted candidate authorization bytes.
    pub fn verify_authorization(
        provider: &ReferenceEnvelopeSealer,
        exact_bytes: &[u8],
    ) -> Result<VerifiedSelectedBridgeAuthorization, SelectedBridgeError> {
        let inner = provider
            .open_bridge_authorization(exact_bytes)
            .map_err(|_| SelectedBridgeError::authentication())?;
        if inner.envelope().authorization.mission_id != provider.bridge_mission_id()
            || inner.envelope().envelope_id != bridge::exact_object_id(exact_bytes)
        {
            return Err(SelectedBridgeError::authentication());
        }
        Ok(VerifiedSelectedBridgeAuthorization {
            inner,
            exact_bytes: exact_bytes.to_vec(),
        })
    }

    /// Creates and reauthenticates the first target-scope wrapper around one
    /// ordinary source-sealed Event. The adapter never opens Event plaintext.
    #[allow(clippy::too_many_arguments)]
    pub fn create_first_hop(
        bridge_provider: &mut ReferenceEnvelopeSealer,
        exact_source_bytes: &[u8],
        authorization_envelope_id: [u8; 32],
        authorization_chain: &[&VerifiedSelectedBridgeAuthorization],
        narrowing: &SelectedBridgeNarrowingPolicy,
        cumulative_custody_age_ms: u64,
        age_continuity_unknown: bool,
    ) -> Result<VerifiedSelectedBridgeEventRoute, SelectedBridgeError> {
        let source = bridge_provider
            .open_source_route_for_bridge(exact_source_bytes)
            .map_err(|_| SelectedBridgeError::authentication())?;
        require_event_source(&source)?;
        require_live_age(&source, cumulative_custody_age_ms, age_continuity_unknown)?;
        let authorizations = authorization_maps(authorization_chain)?;
        let authorization = require_new_edge(
            bridge_provider,
            &source,
            authorization_envelope_id,
            &authorizations.records,
            &authorizations.active,
            &source.header().scope,
            source.header().key_epoch,
            1,
            narrowing,
        )?;
        let enabled = authorization
            .authorization
            .enabled
            .as_ref()
            .ok_or_else(SelectedBridgeError::authentication)?;
        let mut route = BridgeRoute {
            mission_id: bridge_provider.bridge_mission_id(),
            origin_envelope_id: source.origin_envelope_id(),
            source_item_id: source.source_item_id(),
            origin_scope: source.header().scope.clone(),
            origin_route_epoch: source.header().key_epoch,
            current_scope: authorization.authorization.target_scope.clone(),
            current_route_epoch: enabled.target_route_epoch,
            source_route_descriptor: source.copy_exact_route_descriptor(),
            hops: vec![BridgeHop {
                authorization_envelope_id,
                bridge_node_id: bridge_provider.identity(),
                from_scope: source.header().scope.clone(),
                from_route_epoch: source.header().key_epoch,
                to_scope: authorization.authorization.target_scope.clone(),
                to_route_epoch: enabled.target_route_epoch,
                cumulative_custody_age_ms,
                age_continuity_unknown,
                previous_hop_digest: [0; 32],
                bridge_hybrid_signature: Vec::new(),
            }],
            bridge_route_id: [0; 32],
        };
        bridge_provider
            .sign_bridge_hop(&mut route, 0)
            .map_err(|_| SelectedBridgeError::authentication())?;
        let exact_wrapper_bytes = bridge_provider
            .seal_bridge_wrapper(
                &route,
                &source,
                &route.current_scope,
                route.current_route_epoch,
            )
            .map_err(|_| SelectedBridgeError::authentication())?;
        verify_event_route_inner(
            bridge_provider,
            &exact_wrapper_bytes,
            exact_source_bytes,
            authorization_chain,
            Some((0, narrowing)),
        )
    }

    /// Reauthenticates an existing route and appends exactly one narrower hop.
    #[allow(clippy::too_many_arguments)]
    pub fn create_nested_hop(
        bridge_provider: &mut ReferenceEnvelopeSealer,
        current: &VerifiedSelectedBridgeEventRoute,
        authorization_envelope_id: [u8; 32],
        authorization_chain: &[&VerifiedSelectedBridgeAuthorization],
        narrowing: &SelectedBridgeNarrowingPolicy,
        cumulative_custody_age_ms: u64,
        age_continuity_unknown: bool,
    ) -> Result<VerifiedSelectedBridgeEventRoute, SelectedBridgeError> {
        let reverified = verify_event_route_inner(
            bridge_provider,
            current.exact_wrapper_bytes(),
            current.exact_source_bytes(),
            authorization_chain,
            None,
        )?;
        let mut route = reverified.wrapper.route().clone();
        if route.hops.len() >= bridge::MAX_HOPS {
            return Err(SelectedBridgeError::invalid(
                "bridge route already has the maximum hop count",
            ));
        }
        require_live_age(
            &reverified.source,
            cumulative_custody_age_ms,
            age_continuity_unknown,
        )?;
        let authorizations = authorization_maps(authorization_chain)?;
        let next_hop_count = route
            .hops
            .len()
            .checked_add(1)
            .ok_or_else(SelectedBridgeError::authentication)?;
        let authorization = require_new_edge(
            bridge_provider,
            &reverified.source,
            authorization_envelope_id,
            &authorizations.records,
            &authorizations.active,
            &route.current_scope,
            route.current_route_epoch,
            next_hop_count,
            narrowing,
        )?;
        let enabled = authorization
            .authorization
            .enabled
            .as_ref()
            .ok_or_else(SelectedBridgeError::authentication)?;
        let previous_hop_digest = route
            .hops
            .last()
            .ok_or_else(SelectedBridgeError::authentication)?
            .digest(
                u8::try_from(route.hops.len())
                    .map_err(|_| SelectedBridgeError::authentication())?,
            )
            .map_err(|_| SelectedBridgeError::authentication())?;
        let from_scope = route.current_scope.clone();
        let from_route_epoch = route.current_route_epoch;
        route.current_scope = authorization.authorization.target_scope.clone();
        route.current_route_epoch = enabled.target_route_epoch;
        route.hops.push(BridgeHop {
            authorization_envelope_id,
            bridge_node_id: bridge_provider.identity(),
            from_scope,
            from_route_epoch,
            to_scope: authorization.authorization.target_scope.clone(),
            to_route_epoch: enabled.target_route_epoch,
            cumulative_custody_age_ms,
            age_continuity_unknown,
            previous_hop_digest,
            bridge_hybrid_signature: Vec::new(),
        });
        let new_hop_index = route.hops.len() - 1;
        bridge_provider
            .sign_bridge_hop(&mut route, new_hop_index)
            .map_err(|_| SelectedBridgeError::authentication())?;
        let exact_wrapper_bytes = bridge_provider
            .seal_bridge_wrapper(
                &route,
                &reverified.source,
                &route.current_scope,
                route.current_route_epoch,
            )
            .map_err(|_| SelectedBridgeError::authentication())?;
        verify_event_route_inner(
            bridge_provider,
            &exact_wrapper_bytes,
            current.exact_source_bytes(),
            authorization_chain,
            Some((new_hop_index, narrowing)),
        )
    }

    /// Freshly authenticates persisted wrapper/source candidates against the
    /// caller-supplied complete current authorization chain.
    pub fn verify_event_route(
        provider: &ReferenceEnvelopeSealer,
        exact_wrapper_bytes: &[u8],
        exact_source_bytes: &[u8],
        authorization_chain: &[&VerifiedSelectedBridgeAuthorization],
    ) -> Result<VerifiedSelectedBridgeEventRoute, SelectedBridgeError> {
        verify_event_route_inner(
            provider,
            exact_wrapper_bytes,
            exact_source_bytes,
            authorization_chain,
            None,
        )
    }

    /// Opens the exact source payload only after the route capability has been
    /// freshly target-verified. Route-only bridge providers fail closed here.
    pub fn open_event_payload(
        provider: &ReferenceEnvelopeSealer,
        route: &VerifiedSelectedBridgeEventRoute,
    ) -> Result<Vec<u8>, SelectedBridgeError> {
        if provider.identity() != route.verifier_id {
            return Err(SelectedBridgeError::authentication());
        }
        provider
            .open_bridged_payload(&route.source, &route.exact_source_bytes)
            .map_err(|_| SelectedBridgeError::authentication())
    }
}

fn priority_mask(priorities: &BTreeSet<Priority>) -> u8 {
    priorities
        .iter()
        .fold(0u8, |mask, priority| mask | (1 << *priority as u8))
}

fn require_event_source(source: &ProviderVerifiedSource) -> Result<(), SelectedBridgeError> {
    if source.header().class != DataClass::Event || source.header().event_sequence.is_none() {
        return Err(SelectedBridgeError::invalid(
            "selected bridge adapter accepts Event sources only",
        ));
    }
    Ok(())
}

fn require_live_age(
    source: &ProviderVerifiedSource,
    cumulative_age_ms: u64,
    continuity_unknown: bool,
) -> Result<(), SelectedBridgeError> {
    if !source.header().tombstone
        && source
            .header()
            .ttl_ms
            .is_some_and(|ttl| continuity_unknown || cumulative_age_ms >= ttl)
    {
        return Err(SelectedBridgeError::invalid(
            "finite-TTL bridge source is expired or has unknown custody continuity",
        ));
    }
    Ok(())
}

fn authorization_maps<'a>(
    chain: &'a [&'a VerifiedSelectedBridgeAuthorization],
) -> Result<AuthorizationMaps<'a>, SelectedBridgeError> {
    let first = chain
        .first()
        .ok_or_else(|| SelectedBridgeError::invalid("bridge authorization chain is empty"))?;
    let mission = first.envelope().authorization.mission_id;
    let authority = first.envelope().authorization.authority_id;
    let mut expected_sequence = 1u64;
    let mut previous = None;
    let mut generations = BTreeMap::<[u8; 32], u64>::new();
    let mut records = BTreeMap::new();
    let mut active = BTreeMap::new();
    for verified in chain {
        let envelope = verified.envelope();
        let authorization = &envelope.authorization;
        if authorization.mission_id != mission
            || authorization.authority_id != authority
            || authorization.control_sequence != expected_sequence
            || authorization.previous_control_id != previous
            || bridge::exact_object_id(verified.exact_bytes()) != envelope.envelope_id
            || records.insert(envelope.envelope_id, envelope).is_some()
            || generations
                .get(&authorization.authorization_key)
                .is_some_and(|prior| *prior >= authorization.generation)
        {
            return Err(SelectedBridgeError::invalid(
                "bridge authorization chain is forked, stale, or noncanonical",
            ));
        }
        generations.insert(authorization.authorization_key, authorization.generation);
        active.insert(authorization.authorization_key, envelope.envelope_id);
        previous = Some(envelope.envelope_id);
        expected_sequence = expected_sequence
            .checked_add(1)
            .ok_or_else(SelectedBridgeError::authentication)?;
    }
    Ok(AuthorizationMaps { records, active })
}

#[allow(clippy::too_many_arguments)]
fn require_new_edge<'a>(
    provider: &ReferenceEnvelopeSealer,
    source: &ProviderVerifiedSource,
    authorization_envelope_id: [u8; 32],
    records: &'a BTreeMap<[u8; 32], &AuthorizationEnvelope>,
    active: &BTreeMap<[u8; 32], [u8; 32]>,
    from_scope: &Scope,
    from_route_epoch: u64,
    resulting_hop_count: usize,
    narrowing: &SelectedBridgeNarrowingPolicy,
) -> Result<&'a AuthorizationEnvelope, SelectedBridgeError> {
    let record = records
        .get(&authorization_envelope_id)
        .copied()
        .ok_or_else(SelectedBridgeError::authentication)?;
    let authorization = &record.authorization;
    let enabled = authorization
        .enabled
        .as_ref()
        .ok_or_else(SelectedBridgeError::authentication)?;
    let local = narrowing.canonical();
    local
        .validate_subset(enabled)
        .map_err(|_| SelectedBridgeError::authentication())?;
    if active.get(&authorization.authorization_key) != Some(&record.envelope_id)
        || authorization.mission_id != provider.bridge_mission_id()
        || authorization.bridge_node_id != provider.identity()
        || &authorization.source_scope != from_scope
        || enabled.source_route_epoch != from_route_epoch
        || resulting_hop_count > usize::from(enabled.max_total_hops)
        || enabled
            .topics
            .binary_search(&source.header().topic)
            .is_err()
        || !bridge::priority_allowed(enabled.allowed_priority_mask, source.header().priority)
        || (!local.topics.is_empty() && !local.topics.contains(&source.header().topic))
        || !bridge::priority_allowed(local.allowed_priority_mask, source.header().priority)
    {
        return Err(SelectedBridgeError::authentication());
    }
    Ok(record)
}

fn verify_event_route_inner(
    provider: &ReferenceEnvelopeSealer,
    exact_wrapper_bytes: &[u8],
    exact_source_bytes: &[u8],
    authorization_chain: &[&VerifiedSelectedBridgeAuthorization],
    local_new_hop: Option<(usize, &SelectedBridgeNarrowingPolicy)>,
) -> Result<VerifiedSelectedBridgeEventRoute, SelectedBridgeError> {
    let wrapper = provider
        .open_bridge_wrapper_for_any_local_route(exact_wrapper_bytes)
        .map_err(|_| SelectedBridgeError::authentication())?;
    if wrapper.wrapper_envelope_id() != bridge::exact_object_id(exact_wrapper_bytes) {
        return Err(SelectedBridgeError::authentication());
    }
    let source = provider
        .verify_bridge_wrapper_source(&wrapper, exact_source_bytes)
        .map_err(|_| SelectedBridgeError::authentication())?;
    require_event_source(&source)?;
    let authorizations = authorization_maps(authorization_chain)?;
    let records = authorizations
        .records
        .iter()
        .map(|(id, record)| (*id, (*record).clone()))
        .collect::<BTreeMap<_, _>>();
    for (index, hop) in wrapper.route().hops.iter().enumerate() {
        let verified = authorization_chain
            .iter()
            .find(|record| record.envelope_id() == hop.authorization_envelope_id)
            .ok_or_else(SelectedBridgeError::authentication)?;
        provider
            .verify_bridge_hop(wrapper.route(), index, &verified.inner)
            .map_err(|_| SelectedBridgeError::authentication())?;
    }
    wrapper
        .route()
        .validate_authority_path(
            &source.header().topic,
            source.header().priority,
            &records,
            &authorizations.active,
        )
        .map_err(|_| SelectedBridgeError::authentication())?;
    if let Some((index, narrowing)) = local_new_hop {
        wrapper
            .route()
            .validate_local_new_hop(
                index,
                &source.header().topic,
                source.header().priority,
                &records,
                &authorizations.active,
                &narrowing.canonical(),
            )
            .map_err(|_| SelectedBridgeError::authentication())?;
    }
    let (age, unknown) = wrapper
        .route()
        .hops
        .last()
        .map(|hop| (hop.cumulative_custody_age_ms, hop.age_continuity_unknown))
        .ok_or_else(SelectedBridgeError::authentication)?;
    require_live_age(&source, age, unknown)?;
    let authorization_ids = wrapper
        .route()
        .hops
        .iter()
        .map(|hop| hop.authorization_envelope_id)
        .collect();
    Ok(VerifiedSelectedBridgeEventRoute {
        wrapper,
        source,
        verifier_id: provider.identity(),
        exact_wrapper_bytes: exact_wrapper_bytes.to_vec(),
        exact_source_bytes: exact_source_bytes.to_vec(),
        authorization_ids,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto::{ProvisioningAccess, ReferenceProvisioner};
    use crate::envelope::EnvelopeHeader;
    use crate::model::{CausalStamp, Dot, VersionVector};

    fn scope(value: &str) -> Scope {
        Scope::new(value).unwrap_or_else(|error| panic!("scope failed: {error}"))
    }

    fn topic(value: &str) -> Topic {
        Topic::new(value).unwrap_or_else(|error| panic!("topic failed: {error}"))
    }

    fn relay(value: &str, epoch: u64) -> ProvisioningAccess {
        ProvisioningAccess::relay(scope(value), vec![epoch])
            .unwrap_or_else(|error| panic!("relay access failed: {error}"))
    }

    fn member(value: &str, epoch: u64, topics: Vec<Topic>) -> ProvisioningAccess {
        ProvisioningAccess::member(scope(value), vec![epoch], topics)
            .unwrap_or_else(|error| panic!("member access failed: {error}"))
    }

    struct Services {
        authority: ReferenceEnvelopeSealer,
        publisher: ReferenceEnvelopeSealer,
        first_bridge: ReferenceEnvelopeSealer,
        second_bridge: ReferenceEnvelopeSealer,
        target: ReferenceEnvelopeSealer,
    }

    fn services(seed: u8) -> Services {
        let mut provisioner = ReferenceProvisioner::from_seed([seed; 32])
            .unwrap_or_else(|error| panic!("provisioner failed: {error}"));
        let alpha = relay("demo/alpha", 1);
        let parent = relay("demo/parent", 2);
        let bravo = relay("demo/bravo", 3);
        let authority = provisioner
            .issue_control_authority(1, &[alpha.clone(), parent.clone(), bravo.clone()])
            .and_then(ReferenceEnvelopeSealer::open)
            .unwrap_or_else(|error| panic!("authority failed: {error}"));
        let publisher = provisioner
            .issue_node(2, &[member("demo/alpha", 1, vec![topic("ops")])])
            .and_then(ReferenceEnvelopeSealer::open)
            .unwrap_or_else(|error| panic!("publisher failed: {error}"));
        let first_bridge = provisioner
            .issue_node(3, &[alpha.clone(), parent.clone()])
            .and_then(ReferenceEnvelopeSealer::open)
            .unwrap_or_else(|error| panic!("first bridge failed: {error}"));
        let second_bridge = provisioner
            .issue_node(4, &[alpha, parent, bravo])
            .and_then(ReferenceEnvelopeSealer::open)
            .unwrap_or_else(|error| panic!("second bridge failed: {error}"));
        let target = provisioner
            .issue_node(
                5,
                &[
                    member("demo/bravo", 3, vec![topic("ops")]),
                    ProvisioningAccess::content_only(
                        scope("demo/alpha"),
                        vec![1],
                        vec![topic("ops")],
                    )
                    .unwrap_or_else(|error| panic!("target content failed: {error}")),
                ],
            )
            .and_then(ReferenceEnvelopeSealer::open)
            .unwrap_or_else(|error| panic!("target failed: {error}"));
        Services {
            authority,
            publisher,
            first_bridge,
            second_bridge,
            target,
        }
    }

    fn event_header(publisher: NodeId, payload: &[u8]) -> EnvelopeHeader {
        EnvelopeHeader {
            class: DataClass::Event,
            topic: topic("ops"),
            scope: scope("demo/alpha"),
            priority: Priority::Immediate,
            stamp: CausalStamp {
                dot: Dot {
                    publisher,
                    counter: 1,
                },
                context: VersionVector::default(),
            },
            event_sequence: Some(1),
            logical_key: b"selected-bridge-event".to_vec(),
            blob_route: None,
            ttl_ms: None,
            content_len: payload.len() as u64,
            tombstone: false,
            key_epoch: 1,
        }
    }

    fn authorize_edge(
        authority: &mut ReferenceEnvelopeSealer,
        bridge_provider: &ReferenceEnvelopeSealer,
        source: (&str, u64),
        target: (&str, u64),
        link: BridgeAuthorizationLink,
    ) -> (
        VerifiedSelectedBridgeEnrollment,
        VerifiedSelectedBridgeAuthorization,
    ) {
        let enrollment = SelectedEventBridgeAdapter::create_enrollment(
            bridge_provider,
            &scope(source.0),
            source.1,
            &scope(target.0),
            target.1,
        )
        .unwrap_or_else(|error| panic!("enrollment failed: {error}"));
        let verified = SelectedEventBridgeAdapter::verify_enrollment(authority, &enrollment)
            .unwrap_or_else(|error| panic!("enrollment verification failed: {error}"));
        assert_eq!(verified.bridge_node_id(), bridge_provider.identity());
        assert_eq!(verified.source_scope(), &scope(source.0));
        assert_eq!(verified.source_route_epoch(), source.1);
        assert_eq!(verified.target_scope(), &scope(target.0));
        assert_eq!(verified.target_route_epoch(), target.1);
        let policy = SelectedBridgeAuthorizationPolicy::new(
            vec![topic("other"), topic("ops")],
            vec![Priority::Immediate, Priority::Flash],
            2,
        )
        .unwrap_or_else(|error| panic!("authorization policy failed: {error}"));
        let authorization =
            SelectedEventBridgeAdapter::issue_authorization(authority, &verified, link, &policy)
                .unwrap_or_else(|error| panic!("authorization failed: {error}"));
        (verified, authorization)
    }

    #[test]
    fn selected_event_bridge_two_hop_is_filtered_payload_blind_and_target_openable() {
        let Services {
            mut authority,
            mut publisher,
            mut first_bridge,
            mut second_bridge,
            target,
        } = services(0xc1);
        let (first_enrollment, first_authorization) = authorize_edge(
            &mut authority,
            &first_bridge,
            ("demo/alpha", 1),
            ("demo/parent", 2),
            BridgeAuthorizationLink::new(1, None, 1).expect("first link"),
        );
        let (_second_enrollment, second_authorization) = authorize_edge(
            &mut authority,
            &second_bridge,
            ("demo/parent", 2),
            ("demo/bravo", 3),
            BridgeAuthorizationLink::new(2, Some(first_authorization.envelope_id()), 1)
                .expect("second link"),
        );
        assert_eq!(first_enrollment.bridge_node_id(), first_bridge.identity());
        assert_eq!(first_authorization.control_sequence(), 1);
        assert_eq!(first_authorization.previous_control_id(), None);
        assert_eq!(first_authorization.generation(), 1);
        assert!(first_authorization.is_enabled());
        assert!(!first_authorization.exact_bytes().is_empty());

        let payload = b"payload visible only at the authorized target";
        let header = event_header(publisher.identity(), payload);
        let source = publisher
            .seal_event(&header, payload)
            .unwrap_or_else(|error| panic!("source seal failed: {error}"));
        let chain = [&first_authorization, &second_authorization];
        let narrowing =
            SelectedBridgeNarrowingPolicy::new(vec![topic("ops")], vec![Priority::Immediate])
                .expect("exact narrowing");
        let first = SelectedEventBridgeAdapter::create_first_hop(
            &mut first_bridge,
            &source.bytes,
            first_authorization.envelope_id(),
            &chain,
            &narrowing,
            5,
            false,
        )
        .unwrap_or_else(|error| panic!("first hop failed: {error}"));
        assert_eq!(first.origin_scope(), &scope("demo/alpha"));
        assert_eq!(first.current_scope(), &scope("demo/parent"));
        assert_eq!(first.hop_count(), 1);
        assert_eq!(first.topic(), &topic("ops"));
        assert_eq!(first.priority(), Priority::Immediate);
        assert_eq!(first.publisher(), publisher.identity());
        assert_eq!(
            first.authorization_envelope_ids(),
            &[first_authorization.envelope_id()]
        );
        assert!(SelectedEventBridgeAdapter::open_event_payload(&first_bridge, &first).is_err());

        let second = SelectedEventBridgeAdapter::create_nested_hop(
            &mut second_bridge,
            &first,
            second_authorization.envelope_id(),
            &chain,
            &narrowing,
            9,
            false,
        )
        .unwrap_or_else(|error| panic!("nested hop failed: {error}"));
        assert_eq!(second.origin_scope(), &scope("demo/alpha"));
        assert_eq!(second.current_scope(), &scope("demo/bravo"));
        assert_eq!(second.hop_count(), 2);
        assert_eq!(
            second.authorization_envelope_ids(),
            &[
                first_authorization.envelope_id(),
                second_authorization.envelope_id(),
            ]
        );
        assert!(!format!("{second:?}").contains("payload visible"));
        assert!(SelectedEventBridgeAdapter::open_event_payload(&second_bridge, &second).is_err());
        assert!(SelectedEventBridgeAdapter::open_event_payload(&target, &second).is_err());

        let target_route = SelectedEventBridgeAdapter::verify_event_route(
            &target,
            second.exact_wrapper_bytes(),
            second.exact_source_bytes(),
            &chain,
        )
        .unwrap_or_else(|error| panic!("target route verification failed: {error}"));
        assert_eq!(
            SelectedEventBridgeAdapter::open_event_payload(&target, &target_route)
                .unwrap_or_else(|error| panic!("target payload open failed: {error}")),
            payload
        );

        let wrong_topic =
            SelectedBridgeNarrowingPolicy::new(vec![topic("other")], vec![Priority::Immediate])
                .expect("wrong-topic narrowing is structurally valid");
        assert!(
            SelectedEventBridgeAdapter::create_first_hop(
                &mut first_bridge,
                &source.bytes,
                first_authorization.envelope_id(),
                &chain,
                &wrong_topic,
                5,
                false,
            )
            .is_err()
        );
        let wrong_priority =
            SelectedBridgeNarrowingPolicy::new(vec![topic("ops")], vec![Priority::Flash])
                .expect("wrong-priority narrowing is structurally valid");
        assert!(
            SelectedEventBridgeAdapter::create_first_hop(
                &mut first_bridge,
                &source.bytes,
                first_authorization.envelope_id(),
                &chain,
                &wrong_priority,
                5,
                false,
            )
            .is_err()
        );
        let widening = SelectedBridgeNarrowingPolicy::new(Vec::new(), vec![Priority::Routine])
            .expect("widening attempt is structurally valid");
        assert!(
            SelectedEventBridgeAdapter::create_first_hop(
                &mut first_bridge,
                &source.bytes,
                first_authorization.envelope_id(),
                &chain,
                &widening,
                5,
                false,
            )
            .is_err()
        );
    }

    #[test]
    fn selected_event_bridge_rejects_tamper_wrong_edge_loop_stale_and_disabled_authority() {
        let Services {
            mut authority,
            mut publisher,
            mut first_bridge,
            mut second_bridge,
            target,
        } = services(0xc2);
        let (first_enrollment, first_authorization) = authorize_edge(
            &mut authority,
            &first_bridge,
            ("demo/alpha", 1),
            ("demo/parent", 2),
            BridgeAuthorizationLink::new(1, None, 1).expect("first link"),
        );
        let (_second_enrollment, second_authorization) = authorize_edge(
            &mut authority,
            &second_bridge,
            ("demo/parent", 2),
            ("demo/bravo", 3),
            BridgeAuthorizationLink::new(2, Some(first_authorization.envelope_id()), 1)
                .expect("second link"),
        );
        let payload = b"negative-case payload";
        let source = publisher
            .seal_event(&event_header(publisher.identity(), payload), payload)
            .expect("source seal");
        let narrowing =
            SelectedBridgeNarrowingPolicy::new(vec![topic("ops")], vec![Priority::Immediate])
                .expect("narrowing");
        let initial_chain = [&first_authorization, &second_authorization];

        assert!(
            SelectedEventBridgeAdapter::create_first_hop(
                &mut first_bridge,
                &source.bytes,
                second_authorization.envelope_id(),
                &initial_chain,
                &narrowing,
                0,
                false,
            )
            .is_err()
        );
        let first = SelectedEventBridgeAdapter::create_first_hop(
            &mut first_bridge,
            &source.bytes,
            first_authorization.envelope_id(),
            &initial_chain,
            &narrowing,
            0,
            false,
        )
        .expect("first hop");
        let second = SelectedEventBridgeAdapter::create_nested_hop(
            &mut second_bridge,
            &first,
            second_authorization.envelope_id(),
            &initial_chain,
            &narrowing,
            1,
            false,
        )
        .expect("second hop");
        let mut damaged_wrapper = second.exact_wrapper_bytes().to_vec();
        let last = damaged_wrapper.len() - 1;
        damaged_wrapper[last] ^= 1;
        assert!(
            SelectedEventBridgeAdapter::verify_event_route(
                &target,
                &damaged_wrapper,
                second.exact_source_bytes(),
                &initial_chain,
            )
            .is_err()
        );
        let mut damaged_authorization = first_authorization.exact_bytes().to_vec();
        let last = damaged_authorization.len() - 1;
        damaged_authorization[last] ^= 1;
        assert!(
            SelectedEventBridgeAdapter::verify_authorization(&target, &damaged_authorization)
                .is_err()
        );

        let loop_enrollment = SelectedEventBridgeAdapter::create_enrollment(
            &second_bridge,
            &scope("demo/parent"),
            2,
            &scope("demo/alpha"),
            1,
        )
        .expect("loop enrollment");
        let loop_enrollment =
            SelectedEventBridgeAdapter::verify_enrollment(&authority, &loop_enrollment)
                .expect("loop enrollment verification");
        let policy = SelectedBridgeAuthorizationPolicy::new(
            vec![topic("ops")],
            vec![Priority::Immediate],
            2,
        )
        .expect("loop policy");
        let loop_authorization = SelectedEventBridgeAdapter::issue_authorization(
            &mut authority,
            &loop_enrollment,
            BridgeAuthorizationLink::new(3, Some(second_authorization.envelope_id()), 1)
                .expect("loop link"),
            &policy,
        )
        .expect("loop authorization");
        let loop_chain = [
            &first_authorization,
            &second_authorization,
            &loop_authorization,
        ];
        assert!(
            SelectedEventBridgeAdapter::create_nested_hop(
                &mut second_bridge,
                &first,
                loop_authorization.envelope_id(),
                &loop_chain,
                &narrowing,
                1,
                false,
            )
            .is_err()
        );

        let replacement = SelectedEventBridgeAdapter::issue_authorization(
            &mut authority,
            &first_enrollment,
            BridgeAuthorizationLink::new(4, Some(loop_authorization.envelope_id()), 2)
                .expect("replacement link"),
            &policy,
        )
        .expect("replacement authorization");
        let stale_chain = [
            &first_authorization,
            &second_authorization,
            &loop_authorization,
            &replacement,
        ];
        assert!(
            SelectedEventBridgeAdapter::verify_event_route(
                &second_bridge,
                first.exact_wrapper_bytes(),
                first.exact_source_bytes(),
                &stale_chain,
            )
            .is_err()
        );

        let disabled = SelectedEventBridgeAdapter::issue_disabled_authorization(
            &mut authority,
            &replacement,
            BridgeAuthorizationLink::new(5, Some(replacement.envelope_id()), 3)
                .expect("disable link"),
        )
        .expect("disabled authorization");
        assert!(!disabled.is_enabled());
        let disabled_chain = [
            &first_authorization,
            &second_authorization,
            &loop_authorization,
            &replacement,
            &disabled,
        ];
        assert!(
            SelectedEventBridgeAdapter::create_first_hop(
                &mut first_bridge,
                &source.bytes,
                disabled.envelope_id(),
                &disabled_chain,
                &narrowing,
                0,
                false,
            )
            .is_err()
        );

        let outsider = services(0xc3).target;
        assert!(
            SelectedEventBridgeAdapter::verify_authorization(
                &outsider,
                first_authorization.exact_bytes(),
            )
            .is_err()
        );
    }
}
