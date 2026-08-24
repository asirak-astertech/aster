//! Source-authenticated Event envelope seam for store/runtime compositions.
//!
//! This module does not define another Event format. It constrains the existing
//! [`EnvelopeSealer`] surface to [`DataClass::Event`] and carries the exact
//! provider-authenticated [`EnvelopeHeader`] across a persistence boundary.

use crate::{
    crypto::ReferenceEnvelopeSealer,
    envelope::{EnvelopeError, EnvelopeHeader, EnvelopeSealer, SealRequest, SealedEnvelope},
    model::{DataClass, Dot, ItemId, NodeId, Priority, Scope, Topic, VersionVector},
};
use sha2::{Digest, Sha256};

/// Route- and source-authenticated metadata for one exact source-sealed Event.
///
/// Fields are deliberately private. A caller can obtain this capability only
/// by asking [`ReferenceEnvelopeSealer`] to authenticate an envelope. It is
/// sufficient for bounded opaque relay storage, but not for semantic acceptance
/// or application reaction because a route-only node cannot authenticate the
/// protected content. Use [`ReferenceEnvelopeSealer::verify_event_content`] to
/// obtain a [`ContentVerifiedEventEnvelope`] when content access is authorized.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RouteVerifiedEventEnvelope {
    envelope: crate::envelope::VerifiedEnvelope,
    envelope_id: [u8; 32],
    mission_authority_id: NodeId,
}

impl RouteVerifiedEventEnvelope {
    fn from_verified(
        envelope: crate::envelope::VerifiedEnvelope,
        sealed: &[u8],
        mission_authority_id: NodeId,
    ) -> Result<Self, EnvelopeError> {
        if envelope.header.class != DataClass::Event || envelope.header.event_sequence.is_none() {
            return Err(EnvelopeError(
                "authenticated envelope is not an Event".into(),
            ));
        }
        Ok(Self {
            envelope,
            envelope_id: Sha256::digest(sealed).into(),
            mission_authority_id,
        })
    }

    /// Semantic identifier derived by the existing source-envelope profile.
    ///
    /// This does not identify one randomized sealed representation. Sealing the
    /// same authenticated core again preserves this ID but produces different
    /// exact bytes and therefore a different [`Self::envelope_id`].
    pub const fn item_id(&self) -> ItemId {
        self.envelope.id
    }

    /// SHA-256 transfer identity of the exact stable source-sealed bytes.
    pub const fn envelope_id(&self) -> [u8; 32] {
        self.envelope_id
    }

    /// Stable mission authority that authenticated the source credential.
    pub const fn mission_authority_id(&self) -> NodeId {
        self.mission_authority_id
    }

    /// Alias for [`Self::mission_authority_id`].
    pub const fn authority_id(&self) -> NodeId {
        self.mission_authority_id()
    }

    /// Complete provider-authenticated Event metadata.
    pub const fn header(&self) -> &EnvelopeHeader {
        &self.envelope.header
    }

    /// Authority-provisioned source identity authenticated by the envelope.
    pub const fn publisher(&self) -> NodeId {
        self.envelope.header.stamp.dot.publisher
    }

    /// Exact source-authenticated causal dot.
    pub const fn dot(&self) -> Dot {
        self.envelope.header.stamp.dot
    }

    /// Source-authenticated causal context preceding this Event.
    pub const fn causal_context(&self) -> &VersionVector {
        &self.envelope.header.stamp.context
    }

    /// Nonzero sequence in this publisher/topic/scope Event stream.
    pub fn event_sequence(&self) -> u64 {
        self.envelope
            .header
            .event_sequence
            .expect("RouteVerifiedEventEnvelope constructor requires an Event sequence")
    }

    /// Source-authenticated content channel.
    pub const fn topic(&self) -> &Topic {
        &self.envelope.header.topic
    }

    /// Source-authenticated administrative propagation scope.
    pub const fn scope(&self) -> &Scope {
        &self.envelope.header.scope
    }

    /// Source-authenticated scheduling priority.
    pub const fn priority(&self) -> Priority {
        self.envelope.header.priority
    }

    /// Source-authenticated finite custody lifetime, when present.
    pub const fn ttl_ms(&self) -> Option<u64> {
        self.envelope.header.ttl_ms
    }

    /// Source-authenticated application correlation/key bytes.
    pub fn logical_key(&self) -> &[u8] {
        &self.envelope.header.logical_key
    }

    /// Exact authenticated plaintext content length.
    pub const fn content_len(&self) -> u64 {
        self.envelope.header.content_len
    }

    /// Whether this Event is an authenticated deletion marker.
    pub const fn tombstone(&self) -> bool {
        self.envelope.header.tombstone
    }

    /// Source-authenticated route/content key epoch.
    pub const fn key_epoch(&self) -> u64 {
        self.envelope.header.key_epoch
    }

    /// Checks that bytes accompanying this capability are the exact bytes that
    /// were authenticated when it was created.
    pub fn verify_exact_sealed(&self, sealed: &[u8]) -> Result<(), EnvelopeError> {
        if <[u8; 32]>::from(Sha256::digest(sealed)) != self.envelope_id {
            return Err(EnvelopeError(
                "source Event capability does not match sealed bytes".into(),
            ));
        }
        Ok(())
    }
}

/// Source metadata and protected content verified by an authorized provider.
///
/// This is the capability required for durable semantic acceptance and
/// application reaction. Its private constructor can be reached only after
/// [`EnvelopeSealer::open_payload_if_authorized`] returns authenticated
/// plaintext for the exact bytes bound by the route capability.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ContentVerifiedEventEnvelope {
    route: RouteVerifiedEventEnvelope,
}

impl ContentVerifiedEventEnvelope {
    fn from_opened(route: RouteVerifiedEventEnvelope) -> Self {
        Self { route }
    }

    /// Semantic identifier derived by the existing source-envelope profile.
    pub const fn item_id(&self) -> ItemId {
        self.route.item_id()
    }

    /// SHA-256 transfer identity of the exact source-sealed bytes that opened.
    pub const fn envelope_id(&self) -> [u8; 32] {
        self.route.envelope_id()
    }

    /// Stable mission authority that authenticated source and content access.
    pub const fn mission_authority_id(&self) -> NodeId {
        self.route.mission_authority_id()
    }

    /// Alias for [`Self::mission_authority_id`].
    pub const fn authority_id(&self) -> NodeId {
        self.mission_authority_id()
    }

    /// Complete source- and content-authenticated Event metadata.
    pub const fn header(&self) -> &EnvelopeHeader {
        self.route.header()
    }

    /// Authority-provisioned source identity authenticated by the envelope.
    pub const fn publisher(&self) -> NodeId {
        self.route.publisher()
    }

    /// Exact source-authenticated causal dot.
    pub const fn dot(&self) -> Dot {
        self.route.dot()
    }

    /// Source-authenticated causal context preceding this Event.
    pub const fn causal_context(&self) -> &VersionVector {
        self.route.causal_context()
    }

    /// Nonzero sequence in this publisher/topic/scope Event stream.
    pub fn event_sequence(&self) -> u64 {
        self.route.event_sequence()
    }

    /// Source-authenticated content channel.
    pub const fn topic(&self) -> &Topic {
        self.route.topic()
    }

    /// Source-authenticated administrative propagation scope.
    pub const fn scope(&self) -> &Scope {
        self.route.scope()
    }

    /// Source-authenticated scheduling priority.
    pub const fn priority(&self) -> Priority {
        self.route.priority()
    }

    /// Source-authenticated finite custody lifetime, when present.
    pub const fn ttl_ms(&self) -> Option<u64> {
        self.route.ttl_ms()
    }

    /// Source-authenticated application correlation/key bytes.
    pub fn logical_key(&self) -> &[u8] {
        self.route.logical_key()
    }

    /// Exact authenticated plaintext content length.
    pub const fn content_len(&self) -> u64 {
        self.route.content_len()
    }

    /// Whether this Event is an authenticated deletion marker.
    pub const fn tombstone(&self) -> bool {
        self.route.tombstone()
    }

    /// Source-authenticated route/content key epoch.
    pub const fn key_epoch(&self) -> u64 {
        self.route.key_epoch()
    }

    /// Checks that later bytes are the exact content-verified representation.
    pub fn verify_exact_sealed(&self, sealed: &[u8]) -> Result<(), EnvelopeError> {
        self.route.verify_exact_sealed(sealed)
    }

    /// Applies the existing age-zero TTL rule to a locally created Event.
    ///
    /// This method is only for atomic local publication, where custody begins
    /// at zero. It must not be used for a remotely received Event.
    pub fn ensure_live_for_local_publication(&self) -> Result<(), EnvelopeError> {
        if !self.tombstone() && self.ttl_ms() == Some(0) {
            return Err(EnvelopeError(
                "source Event is expired at local publication".into(),
            ));
        }
        Ok(())
    }

    /// Fails closed for a remote finite-TTL Event when authenticated forwarding
    /// age has not yet been ported into the selected runtime.
    ///
    /// Durable Events and tombstones do not require an age decision. A future
    /// forwarding capability must carry provider-authenticated cumulative age;
    /// callers must never substitute wall time or assume a remote age of zero.
    pub fn ensure_remote_acceptance_without_forwarding_age(&self) -> Result<(), EnvelopeError> {
        if !self.tombstone() && self.ttl_ms().is_some() {
            return Err(EnvelopeError(
                "remote finite-TTL Event requires authenticated forwarding age".into(),
            ));
        }
        Ok(())
    }
}

/// Result of attempting content verification through the local provider.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum EventContentVerification {
    /// Source/route metadata is valid, but this provider has no content grant.
    RouteOnly(RouteVerifiedEventEnvelope),
    /// Source metadata and content both authenticated for the exact bytes.
    ContentVerified {
        event: ContentVerifiedEventEnvelope,
        payload: Vec<u8>,
    },
}

impl ReferenceEnvelopeSealer {
    /// Seals an Event through the existing hybrid source-envelope provider.
    ///
    /// Counter, causal context, Event sequence, scope, topic, data priority,
    /// TTL, and key epoch must come from the durable semantic authority. The
    /// existing provider validates every field and binds it into the source
    /// signature; this wrapper only prevents another data class from crossing
    /// the Event-specific API by mistake.
    pub fn seal_event(
        &mut self,
        header: &EnvelopeHeader,
        payload: &[u8],
    ) -> Result<SealedEnvelope, EnvelopeError> {
        if header.class != DataClass::Event {
            return Err(EnvelopeError(
                "source Event must use Event data class".into(),
            ));
        }
        <Self as EnvelopeSealer>::seal(self, SealRequest { header, payload })
    }

    /// Authenticates source identity and all protected Event metadata without
    /// requiring local content access.
    ///
    /// A route-only relay may call this method and retain the opaque bytes. This
    /// capability must not cross a semantic acceptance or application boundary.
    pub fn verify_event(
        &mut self,
        sealed: &[u8],
    ) -> Result<RouteVerifiedEventEnvelope, EnvelopeError> {
        let verified = <Self as EnvelopeSealer>::inspect(self, sealed)?;
        RouteVerifiedEventEnvelope::from_verified(verified, sealed, self.mission_authority_id())
    }

    /// Authenticates an Event and requires its source to equal `expected`.
    pub fn verify_event_from(
        &mut self,
        expected: NodeId,
        sealed: &[u8],
    ) -> Result<RouteVerifiedEventEnvelope, EnvelopeError> {
        let event = self.verify_event(sealed)?;
        if event.publisher() != expected {
            return Err(EnvelopeError(
                "source Event publisher differs from expected identity".into(),
            ));
        }
        Ok(event)
    }

    /// Attempts to authenticate protected content for an exact route-verified
    /// Event through this provider's existing authorization boundary.
    ///
    /// A provider without the content grant returns [`EventContentVerification::RouteOnly`].
    /// A provider with the grant must successfully authenticate and open the
    /// content to mint [`ContentVerifiedEventEnvelope`]; ciphertext corruption
    /// is an error and can never be converted into a strong capability.
    pub fn verify_event_content(
        &mut self,
        event: RouteVerifiedEventEnvelope,
        sealed: &[u8],
    ) -> Result<EventContentVerification, EnvelopeError> {
        event.verify_exact_sealed(sealed)?;
        if event.mission_authority_id() != self.mission_authority_id() {
            return Err(EnvelopeError(
                "source Event capability belongs to another mission authority".into(),
            ));
        }
        match <Self as EnvelopeSealer>::open_payload_if_authorized(self, &event.envelope, sealed)? {
            None => Ok(EventContentVerification::RouteOnly(event)),
            Some(payload) => {
                if u64::try_from(payload.len()).ok() != Some(event.content_len()) {
                    return Err(EnvelopeError(
                        "source Event payload length differs from authenticated metadata".into(),
                    ));
                }
                Ok(EventContentVerification::ContentVerified {
                    event: ContentVerifiedEventEnvelope::from_opened(event),
                    payload,
                })
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        crypto::{ProvisioningAccess, ReferenceProvisioner},
        model::{CausalStamp, Dot, Priority, Scope, Topic, VersionVector},
    };

    fn scope() -> Scope {
        Scope::new("test/source-event").expect("scope")
    }

    fn topic() -> Topic {
        Topic::new("mesh-event").expect("topic")
    }

    fn member_access() -> ProvisioningAccess {
        ProvisioningAccess::member(scope(), vec![1], vec![topic()]).expect("member access")
    }

    fn relay_access() -> ProvisioningAccess {
        ProvisioningAccess::relay(scope(), vec![1]).expect("relay access")
    }

    struct Services {
        publisher: ReferenceEnvelopeSealer,
        other: ReferenceEnvelopeSealer,
        reader: ReferenceEnvelopeSealer,
        relay: ReferenceEnvelopeSealer,
    }

    fn services() -> Services {
        let mut provisioner = ReferenceProvisioner::from_seed([0x5a; 32]).expect("provisioner");
        let publisher = provisioner
            .issue_node(1, &[member_access()])
            .and_then(ReferenceEnvelopeSealer::open)
            .expect("publisher");
        let other = provisioner
            .issue_node(2, &[member_access()])
            .and_then(ReferenceEnvelopeSealer::open)
            .expect("other publisher");
        let reader = provisioner
            .issue_node(3, &[member_access()])
            .and_then(ReferenceEnvelopeSealer::open)
            .expect("reader");
        let relay = provisioner
            .issue_node(4, &[relay_access()])
            .and_then(ReferenceEnvelopeSealer::open)
            .expect("relay");
        Services {
            publisher,
            other,
            reader,
            relay,
        }
    }

    fn wrong_mission_reader() -> ReferenceEnvelopeSealer {
        let mut provisioner =
            ReferenceProvisioner::from_seed([0x6b; 32]).expect("wrong mission provisioner");
        provisioner
            .issue_node(1, &[member_access()])
            .and_then(ReferenceEnvelopeSealer::open)
            .expect("wrong mission reader")
    }

    fn header(publisher: NodeId, payload: &[u8], ttl_ms: Option<u64>) -> EnvelopeHeader {
        EnvelopeHeader {
            class: DataClass::Event,
            topic: topic(),
            scope: scope(),
            priority: Priority::Immediate,
            stamp: CausalStamp {
                dot: Dot {
                    publisher,
                    counter: 1,
                },
                context: VersionVector::default(),
            },
            event_sequence: Some(1),
            logical_key: b"ping".to_vec(),
            blob_route: None,
            ttl_ms,
            content_len: payload.len() as u64,
            tombstone: false,
            key_epoch: 1,
        }
    }

    fn content_verified(
        reader: &mut ReferenceEnvelopeSealer,
        sealed: &[u8],
    ) -> (ContentVerifiedEventEnvelope, Vec<u8>) {
        let route = reader.verify_event(sealed).expect("route verification");
        match reader
            .verify_event_content(route, sealed)
            .expect("content verification")
        {
            EventContentVerification::ContentVerified { event, payload } => (event, payload),
            EventContentVerification::RouteOnly(_) => panic!("member unexpectedly route-only"),
        }
    }

    #[test]
    fn route_and_content_capabilities_bind_metadata_authority_and_exact_bytes() {
        let Services {
            mut publisher,
            other: _,
            mut reader,
            relay: _,
        } = services();
        let payload = b"authenticated ping";
        let header = header(publisher.identity(), payload, None);
        let sealed = publisher.seal_event(&header, payload).expect("seal Event");
        let resealed = publisher
            .seal_event(&header, payload)
            .expect("reseal identical Event core");

        let first = reader.verify_event(&sealed.bytes).expect("verify Event");
        let replay = reader
            .verify_event(&sealed.bytes)
            .expect("repeat verification is stable");
        let alternate_representation = reader
            .verify_event(&resealed.bytes)
            .expect("verify alternate sealed representation");
        assert_eq!(first, replay);
        assert_eq!(first.item_id(), sealed.id);
        assert_eq!(
            first.envelope_id(),
            <[u8; 32]>::from(Sha256::digest(&sealed.bytes))
        );
        assert_eq!(alternate_representation.item_id(), first.item_id());
        assert_ne!(resealed.bytes, sealed.bytes);
        assert_ne!(alternate_representation.envelope_id(), first.envelope_id());
        assert!(first.verify_exact_sealed(&resealed.bytes).is_err());
        assert_eq!(
            first.mission_authority_id(),
            publisher.mission_authority_id()
        );
        assert_eq!(publisher.authority_id(), publisher.mission_authority_id());
        assert_eq!(first.mission_authority_id(), reader.mission_authority_id());
        assert_eq!(first.publisher(), publisher.identity());
        assert_eq!(first.dot(), header.stamp.dot);
        assert_eq!(first.causal_context(), &header.stamp.context);
        assert_eq!(first.event_sequence(), 1);
        assert_eq!(first.topic(), &header.topic);
        assert_eq!(first.scope(), &header.scope);
        assert_eq!(first.priority(), header.priority);
        assert_eq!(first.ttl_ms(), header.ttl_ms);
        assert_eq!(first.logical_key(), header.logical_key.as_slice());
        assert_eq!(first.content_len(), header.content_len);
        assert_eq!(first.tombstone(), header.tombstone);
        assert_eq!(first.key_epoch(), header.key_epoch);
        assert_eq!(first.header(), &header);
        first
            .verify_exact_sealed(&sealed.bytes)
            .expect("exact bytes");

        let (content, opened) = content_verified(&mut reader, &sealed.bytes);
        assert_eq!(opened, payload);
        assert_eq!(content.item_id(), first.item_id());
        assert_eq!(content.envelope_id(), first.envelope_id());
        assert_eq!(content.mission_authority_id(), first.mission_authority_id());
        assert_eq!(content.header(), first.header());
        content
            .verify_exact_sealed(&sealed.bytes)
            .expect("content token exact bytes");

        let mut different = sealed.bytes.clone();
        different[0] ^= 1;
        assert!(first.verify_exact_sealed(&different).is_err());
        assert!(content.verify_exact_sealed(&different).is_err());
    }

    #[test]
    fn event_verification_rejects_non_event_zero_sequence_route_tamper_and_wrong_source() {
        let Services {
            mut publisher,
            other,
            mut reader,
            relay: _,
        } = services();
        let payload = b"authenticated ping";
        let header = header(publisher.identity(), payload, None);
        let sealed = publisher.seal_event(&header, payload).expect("seal Event");

        assert!(
            reader
                .verify_event_from(other.identity(), &sealed.bytes)
                .is_err()
        );
        reader
            .verify_event_from(publisher.identity(), &sealed.bytes)
            .expect("expected source");

        let mut tampered = sealed.bytes;
        tampered[0] ^= 1;
        assert!(reader.verify_event(&tampered).is_err());

        let mut state_header = header.clone();
        state_header.class = DataClass::State;
        state_header.event_sequence = None;
        assert!(publisher.seal_event(&state_header, payload).is_err());
        let state = <ReferenceEnvelopeSealer as EnvelopeSealer>::seal(
            &mut publisher,
            SealRequest {
                header: &state_header,
                payload,
            },
        )
        .expect("seal non-Event through generic proven boundary");
        assert!(reader.verify_event(&state.bytes).is_err());

        let mut zero_sequence = header;
        zero_sequence.event_sequence = Some(0);
        assert!(publisher.seal_event(&zero_sequence, payload).is_err());
    }

    #[test]
    fn route_only_is_relayable_but_cannot_mint_a_content_capability() {
        let Services {
            mut publisher,
            other: _,
            reader: _,
            mut relay,
        } = services();
        let payload = b"authenticated ping";
        let header = header(publisher.identity(), payload, None);
        let sealed = publisher.seal_event(&header, payload).expect("seal Event");
        let route = relay
            .verify_event(&sealed.bytes)
            .expect("route-only source verification");
        match relay
            .verify_event_content(route, &sealed.bytes)
            .expect("route-only content decision")
        {
            EventContentVerification::RouteOnly(route) => {
                assert_eq!(route.item_id(), sealed.id);
                route
                    .verify_exact_sealed(&sealed.bytes)
                    .expect("relay exact bytes");
            }
            EventContentVerification::ContentVerified { .. } => {
                panic!("route-only relay minted a content capability")
            }
        }
    }

    #[test]
    fn content_tamper_and_wrong_mission_cannot_mint_a_strong_capability() {
        let Services {
            mut publisher,
            other: _,
            mut reader,
            relay: _,
        } = services();
        let payload = b"authenticated ping";
        let header = header(publisher.identity(), payload, None);
        let sealed = publisher.seal_event(&header, payload).expect("seal Event");
        let mut tampered = sealed.bytes.clone();
        let last = tampered.len().checked_sub(1).expect("sealed bytes");
        tampered[last] ^= 1;

        // Source/route authentication remains sufficient for an opaque relay.
        // A content-authorized provider must fail the AEAD open and therefore
        // cannot mint ContentVerifiedEventEnvelope.
        let route = reader
            .verify_event(&tampered)
            .expect("source metadata remains authenticated");
        assert!(reader.verify_event_content(route, &tampered).is_err());

        let mut outsider = wrong_mission_reader();
        assert!(outsider.verify_event(&sealed.bytes).is_err());
        let route = reader
            .verify_event(&sealed.bytes)
            .expect("right mission route token");
        assert!(outsider.verify_event_content(route, &sealed.bytes).is_err());
    }

    #[test]
    fn ttl_is_explicitly_local_or_remote_fail_closed_and_tombstones_do_not_expire() {
        let Services {
            mut publisher,
            other: _,
            mut reader,
            relay: _,
        } = services();
        let payload = b"perishable ping";
        let header = header(publisher.identity(), payload, Some(25));
        let sealed = publisher.seal_event(&header, payload).expect("seal Event");
        let (event, _) = content_verified(&mut reader, &sealed.bytes);
        event
            .ensure_live_for_local_publication()
            .expect("positive TTL is live at local age zero");
        assert!(
            event
                .ensure_remote_acceptance_without_forwarding_age()
                .is_err()
        );

        let mut immediately_expired = header.clone();
        immediately_expired.ttl_ms = Some(0);
        let sealed = publisher
            .seal_event(&immediately_expired, payload)
            .expect("seal zero-TTL Event");
        let (event, _) = content_verified(&mut reader, &sealed.bytes);
        assert!(event.ensure_live_for_local_publication().is_err());

        let mut tombstone = header;
        tombstone.ttl_ms = Some(0);
        tombstone.tombstone = true;
        tombstone.content_len = 0;
        let sealed = publisher
            .seal_event(&tombstone, b"")
            .expect("seal tombstone Event");
        let (event, payload) = content_verified(&mut reader, &sealed.bytes);
        assert!(payload.is_empty());
        assert!(event.tombstone());
        event
            .ensure_live_for_local_publication()
            .expect("tombstone does not expire locally");
        event
            .ensure_remote_acceptance_without_forwarding_age()
            .expect("tombstone does not require custody age");
    }
}
