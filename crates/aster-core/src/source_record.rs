//! Source-authenticated Record envelope seam for store/runtime compositions.
//!
//! This module does not define another Record format. It constrains the
//! existing [`EnvelopeSealer`] surface to [`DataClass::Record`] and carries the
//! exact provider-authenticated [`EnvelopeHeader`] across a persistence
//! boundary.

use crate::{
    crypto::ReferenceEnvelopeSealer,
    envelope::{EnvelopeError, EnvelopeHeader, EnvelopeSealer, SealRequest, SealedEnvelope},
    model::{DataClass, Dot, ItemId, NodeId, Priority, Scope, Topic, VersionVector},
};
use sha2::{Digest, Sha256};

/// Authentication-profile ceiling inherited from the reference envelope
/// provider. This is not an application admission limit: the selected Record
/// API and durable redb composition apply their narrower 4,096-byte key bound
/// before publication or commit.
const REFERENCE_PROVIDER_MAX_RECORD_LOGICAL_KEY_LEN: usize = 64 * 1024;

/// Route- and source-authenticated metadata for one exact source-sealed Record.
///
/// Fields are deliberately private. A caller can obtain this capability only
/// by asking [`ReferenceEnvelopeSealer`] to authenticate an envelope. It is
/// sufficient for bounded opaque relay storage, but not for semantic acceptance
/// or application reaction because a route-only node cannot authenticate the
/// protected content. Use [`ReferenceEnvelopeSealer::verify_record_content`] to
/// obtain a [`ContentVerifiedRecordEnvelope`] when content access is authorized.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RouteVerifiedRecordEnvelope {
    envelope: crate::envelope::VerifiedEnvelope,
    envelope_id: [u8; 32],
    mission_authority_id: NodeId,
}

impl RouteVerifiedRecordEnvelope {
    fn from_verified(
        envelope: crate::envelope::VerifiedEnvelope,
        sealed: &[u8],
        mission_authority_id: NodeId,
    ) -> Result<Self, EnvelopeError> {
        if envelope.header.class != DataClass::Record
            || envelope.header.event_sequence.is_some()
            || envelope.header.blob_route.is_some()
            || envelope.header.logical_key.is_empty()
            || envelope.header.logical_key.len() > REFERENCE_PROVIDER_MAX_RECORD_LOGICAL_KEY_LEN
            || envelope.header.ttl_ms.is_some()
            || (envelope.header.tombstone && envelope.header.content_len != 0)
        {
            return Err(EnvelopeError(
                "authenticated envelope is not a valid selected Record".into(),
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

    /// Complete provider-authenticated Record metadata.
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

    /// Source-authenticated causal context preceding this Record.
    pub const fn causal_context(&self) -> &VersionVector {
        &self.envelope.header.stamp.context
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

    /// Finite TTL is unsupported by this selected Record slice, so an
    /// authenticated Record capability always reports `None`.
    pub const fn ttl_ms(&self) -> Option<u64> {
        self.envelope.header.ttl_ms
    }

    /// Nonempty source-authenticated Record key bytes.
    pub fn logical_key(&self) -> &[u8] {
        &self.envelope.header.logical_key
    }

    /// Exact authenticated plaintext content length.
    pub const fn content_len(&self) -> u64 {
        self.envelope.header.content_len
    }

    /// Whether this Record is an authenticated deletion marker.
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
                "source Record capability does not match sealed bytes".into(),
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
pub struct ContentVerifiedRecordEnvelope {
    route: RouteVerifiedRecordEnvelope,
    content_sha256: [u8; 32],
}

impl ContentVerifiedRecordEnvelope {
    fn from_opened(route: RouteVerifiedRecordEnvelope, payload: &[u8]) -> Self {
        Self {
            route,
            content_sha256: Sha256::digest(payload).into(),
        }
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

    /// Complete source- and content-authenticated Record metadata.
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

    /// Source-authenticated causal context preceding this Record.
    pub const fn causal_context(&self) -> &VersionVector {
        self.route.causal_context()
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

    /// Finite TTL is unsupported by this selected Record slice.
    pub const fn ttl_ms(&self) -> Option<u64> {
        self.route.ttl_ms()
    }

    /// Nonempty source-authenticated Record key bytes.
    pub fn logical_key(&self) -> &[u8] {
        self.route.logical_key()
    }

    /// Exact authenticated plaintext content length.
    pub const fn content_len(&self) -> u64 {
        self.route.content_len()
    }

    /// Whether this Record is an authenticated deletion marker.
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

    /// Checks that application bytes still equal the exact authenticated
    /// plaintext that minted this capability.
    pub fn verify_exact_payload(&self, payload: &[u8]) -> Result<(), EnvelopeError> {
        if <[u8; 32]>::from(Sha256::digest(payload)) != self.content_sha256 {
            return Err(EnvelopeError(
                "source Record capability does not match plaintext payload".into(),
            ));
        }
        Ok(())
    }
}

/// Result of attempting Record content verification through the local provider.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum RecordContentVerification {
    /// Source/route metadata is valid, but this provider has no content grant.
    RouteOnly(RouteVerifiedRecordEnvelope),
    /// Source metadata and content both authenticated for the exact bytes.
    ContentVerified {
        record: ContentVerifiedRecordEnvelope,
        payload: Vec<u8>,
    },
}

impl ReferenceEnvelopeSealer {
    /// Reports whether this node owns the exact route capability for a Record
    /// scope epoch.
    ///
    /// Record, State, and Event source envelopes intentionally use the same
    /// authority-provisioned scope route grant. This Record-named alias exposes
    /// the existing provider decision without leaking key material.
    pub fn can_route_record(&self, scope: &Scope, epoch: u64) -> bool {
        self.can_route_event(scope, epoch)
    }

    /// Reports whether this node can open Record content for an exact topic and
    /// scope epoch.
    pub fn can_open_record_content(&self, scope: &Scope, topic: &Topic, epoch: u64) -> bool {
        self.can_open_event_content(scope, topic, epoch)
    }

    /// Seals a Record through the existing hybrid source-envelope provider.
    ///
    /// Counter, causal context, scope, topic, priority, and key epoch must come
    /// from the durable semantic authority. The selected Record slice rejects
    /// finite TTL until authenticated forwarding age is integrated.
    pub fn seal_record(
        &mut self,
        header: &EnvelopeHeader,
        payload: &[u8],
    ) -> Result<SealedEnvelope, EnvelopeError> {
        if header.class != DataClass::Record {
            return Err(EnvelopeError(
                "source Record must use Record data class".into(),
            ));
        }
        if header.event_sequence.is_some()
            || header.blob_route.is_some()
            || header.logical_key.is_empty()
            || header.logical_key.len() > REFERENCE_PROVIDER_MAX_RECORD_LOGICAL_KEY_LEN
            || header.ttl_ms.is_some()
            || (header.tombstone && !payload.is_empty())
        {
            return Err(EnvelopeError(
                "invalid selected source Record metadata".into(),
            ));
        }
        <Self as EnvelopeSealer>::seal(self, SealRequest { header, payload })
    }

    /// Authenticates source identity and all protected Record metadata without
    /// requiring local content access.
    pub fn verify_record(
        &mut self,
        sealed: &[u8],
    ) -> Result<RouteVerifiedRecordEnvelope, EnvelopeError> {
        let verified = <Self as EnvelopeSealer>::inspect(self, sealed)?;
        RouteVerifiedRecordEnvelope::from_verified(verified, sealed, self.mission_authority_id())
    }

    /// Authenticates a Record and requires its source to equal `expected`.
    pub fn verify_record_from(
        &mut self,
        expected: NodeId,
        sealed: &[u8],
    ) -> Result<RouteVerifiedRecordEnvelope, EnvelopeError> {
        let record = self.verify_record(sealed)?;
        if record.publisher() != expected {
            return Err(EnvelopeError(
                "source Record publisher differs from expected identity".into(),
            ));
        }
        Ok(record)
    }

    /// Attempts to authenticate protected content for an exact route-verified
    /// Record through this provider's existing authorization boundary.
    pub fn verify_record_content(
        &mut self,
        record: RouteVerifiedRecordEnvelope,
        sealed: &[u8],
    ) -> Result<RecordContentVerification, EnvelopeError> {
        record.verify_exact_sealed(sealed)?;
        if record.mission_authority_id() != self.mission_authority_id() {
            return Err(EnvelopeError(
                "source Record capability belongs to another mission authority".into(),
            ));
        }
        match <Self as EnvelopeSealer>::open_payload_if_authorized(self, &record.envelope, sealed)?
        {
            None => Ok(RecordContentVerification::RouteOnly(record)),
            Some(payload) => {
                if u64::try_from(payload.len()).ok() != Some(record.content_len()) {
                    return Err(EnvelopeError(
                        "source Record payload length differs from authenticated metadata".into(),
                    ));
                }
                Ok(RecordContentVerification::ContentVerified {
                    record: ContentVerifiedRecordEnvelope::from_opened(record, &payload),
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
        blob::{BlobId, BlobRouteCommitment},
        crypto::{ProvisioningAccess, ReferenceProvisioner},
        model::{CausalStamp, Dot, Priority, Scope, Topic, VersionVector},
    };

    fn scope() -> Scope {
        Scope::new("test/source-record").expect("scope")
    }

    fn topic() -> Topic {
        Topic::new("mesh-record").expect("topic")
    }

    fn other_topic() -> Topic {
        Topic::new("other-record").expect("other topic")
    }

    fn member_access() -> ProvisioningAccess {
        ProvisioningAccess::member(scope(), vec![1], vec![topic()]).expect("member access")
    }

    fn relay_access() -> ProvisioningAccess {
        ProvisioningAccess::relay(scope(), vec![1]).expect("relay access")
    }

    fn wrong_topic_access() -> ProvisioningAccess {
        ProvisioningAccess::member(scope(), vec![1], vec![other_topic()])
            .expect("wrong-topic access")
    }

    struct Services {
        publisher: ReferenceEnvelopeSealer,
        other: ReferenceEnvelopeSealer,
        reader: ReferenceEnvelopeSealer,
        relay: ReferenceEnvelopeSealer,
        wrong_topic: ReferenceEnvelopeSealer,
    }

    fn services() -> Services {
        let mut provisioner = ReferenceProvisioner::from_seed([0x3a; 32]).expect("provisioner");
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
        let wrong_topic = provisioner
            .issue_node(5, &[wrong_topic_access()])
            .and_then(ReferenceEnvelopeSealer::open)
            .expect("wrong-topic reader");
        Services {
            publisher,
            other,
            reader,
            relay,
            wrong_topic,
        }
    }

    fn wrong_mission_reader() -> ReferenceEnvelopeSealer {
        let mut provisioner =
            ReferenceProvisioner::from_seed([0x7c; 32]).expect("wrong mission provisioner");
        provisioner
            .issue_node(1, &[member_access()])
            .and_then(ReferenceEnvelopeSealer::open)
            .expect("wrong mission reader")
    }

    fn header(publisher: NodeId, payload: &[u8]) -> EnvelopeHeader {
        EnvelopeHeader {
            class: DataClass::Record,
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
            event_sequence: None,
            logical_key: b"incident/7".to_vec(),
            blob_route: None,
            ttl_ms: None,
            content_len: payload.len() as u64,
            tombstone: false,
            key_epoch: 1,
        }
    }

    fn content_verified(
        reader: &mut ReferenceEnvelopeSealer,
        sealed: &[u8],
    ) -> (ContentVerifiedRecordEnvelope, Vec<u8>) {
        let route = reader.verify_record(sealed).expect("route verification");
        match reader
            .verify_record_content(route, sealed)
            .expect("content verification")
        {
            RecordContentVerification::ContentVerified { record, payload } => (record, payload),
            RecordContentVerification::RouteOnly(_) => panic!("member unexpectedly route-only"),
        }
    }

    #[test]
    fn route_and_content_capabilities_bind_metadata_authority_and_exact_bytes() {
        let Services {
            mut publisher,
            other: _,
            mut reader,
            relay: _,
            wrong_topic: _,
        } = services();
        let payload = b"open";
        let header = header(publisher.identity(), payload);
        let sealed = publisher
            .seal_record(&header, payload)
            .expect("seal Record");
        let resealed = publisher
            .seal_record(&header, payload)
            .expect("reseal identical Record core");

        let first = reader.verify_record(&sealed.bytes).expect("verify Record");
        let replay = reader
            .verify_record(&sealed.bytes)
            .expect("repeat verification is stable");
        let alternate = reader
            .verify_record(&resealed.bytes)
            .expect("verify alternate sealed representation");
        assert_eq!(first, replay);
        assert_eq!(first.item_id(), sealed.id);
        assert_eq!(
            first.envelope_id(),
            <[u8; 32]>::from(Sha256::digest(&sealed.bytes))
        );
        assert_eq!(alternate.item_id(), first.item_id());
        assert_ne!(resealed.bytes, sealed.bytes);
        assert_ne!(alternate.envelope_id(), first.envelope_id());
        assert!(first.verify_exact_sealed(&resealed.bytes).is_err());
        assert_eq!(
            first.mission_authority_id(),
            publisher.mission_authority_id()
        );
        assert_eq!(first.authority_id(), first.mission_authority_id());
        assert_eq!(first.mission_authority_id(), reader.mission_authority_id());
        assert_eq!(first.publisher(), publisher.identity());
        assert_eq!(first.dot(), header.stamp.dot);
        assert_eq!(first.causal_context(), &header.stamp.context);
        assert_eq!(first.topic(), &header.topic);
        assert_eq!(first.scope(), &header.scope);
        assert_eq!(first.priority(), header.priority);
        assert_eq!(first.ttl_ms(), None);
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
        assert_eq!(content.authority_id(), content.mission_authority_id());
        assert_eq!(content.header(), first.header());
        assert_eq!(content.publisher(), first.publisher());
        assert_eq!(content.dot(), first.dot());
        assert_eq!(content.causal_context(), first.causal_context());
        assert_eq!(content.topic(), first.topic());
        assert_eq!(content.scope(), first.scope());
        assert_eq!(content.priority(), first.priority());
        assert_eq!(content.ttl_ms(), first.ttl_ms());
        assert_eq!(content.logical_key(), first.logical_key());
        assert_eq!(content.content_len(), first.content_len());
        assert_eq!(content.tombstone(), first.tombstone());
        assert_eq!(content.key_epoch(), first.key_epoch());
        content
            .verify_exact_sealed(&sealed.bytes)
            .expect("content token exact bytes");
        content
            .verify_exact_payload(payload)
            .expect("content token exact plaintext");
        assert!(content.verify_exact_payload(b"stale").is_err());
    }

    #[test]
    fn record_api_rejects_class_confusion_event_fields_blob_routes_and_bad_keys() {
        let Services {
            mut publisher,
            other: _,
            mut reader,
            relay: _,
            wrong_topic: _,
        } = services();
        let payload = b"open";
        let record_header = header(publisher.identity(), payload);

        let mut state_header = record_header.clone();
        state_header.class = DataClass::State;
        assert!(publisher.seal_record(&state_header, payload).is_err());
        let state = <ReferenceEnvelopeSealer as EnvelopeSealer>::seal(
            &mut publisher,
            SealRequest {
                header: &state_header,
                payload,
            },
        )
        .expect("seal State through generic boundary");
        assert!(reader.verify_record(&state.bytes).is_err());

        let mut event_header = record_header.clone();
        event_header.class = DataClass::Event;
        event_header.event_sequence = Some(1);
        let event = <ReferenceEnvelopeSealer as EnvelopeSealer>::seal(
            &mut publisher,
            SealRequest {
                header: &event_header,
                payload,
            },
        )
        .expect("seal Event through generic boundary");
        assert!(reader.verify_record(&event.bytes).is_err());

        let mut event_field = record_header.clone();
        event_field.event_sequence = Some(1);
        assert!(publisher.seal_record(&event_field, payload).is_err());

        let mut blob_field = record_header.clone();
        blob_field.blob_route = Some(BlobRouteCommitment::from_authenticated_header(
            BlobId::from_bytes([0x61; 32]),
            1,
            [0x62; 32],
        ));
        assert!(publisher.seal_record(&blob_field, payload).is_err());

        let mut empty_key = record_header.clone();
        empty_key.logical_key.clear();
        assert!(publisher.seal_record(&empty_key, payload).is_err());
        let generic_empty_key = <ReferenceEnvelopeSealer as EnvelopeSealer>::seal(
            &mut publisher,
            SealRequest {
                header: &empty_key,
                payload,
            },
        )
        .expect("generic provider permits an authenticated empty-key Record");
        assert!(reader.verify_record(&generic_empty_key.bytes).is_err());

        let mut oversized_key = record_header.clone();
        oversized_key.logical_key = vec![0; REFERENCE_PROVIDER_MAX_RECORD_LOGICAL_KEY_LEN + 1];
        assert!(publisher.seal_record(&oversized_key, payload).is_err());

        let mut wrong_len = record_header;
        wrong_len.content_len += 1;
        assert!(publisher.seal_record(&wrong_len, payload).is_err());
    }

    #[test]
    fn finite_ttl_is_rejected_at_seal_and_typed_verification_boundaries() {
        let Services {
            mut publisher,
            other: _,
            mut reader,
            relay: _,
            wrong_topic: _,
        } = services();
        let payload = b"perishable";
        for ttl_ms in [Some(0), Some(25)] {
            let mut finite = header(publisher.identity(), payload);
            finite.ttl_ms = ttl_ms;
            assert!(publisher.seal_record(&finite, payload).is_err());
            let generic = <ReferenceEnvelopeSealer as EnvelopeSealer>::seal(
                &mut publisher,
                SealRequest {
                    header: &finite,
                    payload,
                },
            )
            .expect("generic provider permits a finite-TTL Record");
            assert!(reader.verify_record(&generic.bytes).is_err());
        }
    }

    #[test]
    fn tamper_wrong_source_and_wrong_mission_fail_closed() {
        let Services {
            mut publisher,
            other,
            mut reader,
            relay: _,
            wrong_topic: _,
        } = services();
        let payload = b"open";
        let header = header(publisher.identity(), payload);
        let sealed = publisher
            .seal_record(&header, payload)
            .expect("seal Record");

        assert!(
            reader
                .verify_record_from(other.identity(), &sealed.bytes)
                .is_err()
        );
        reader
            .verify_record_from(publisher.identity(), &sealed.bytes)
            .expect("expected source");

        let mut route_tamper = sealed.bytes.clone();
        route_tamper[0] ^= 1;
        assert!(reader.verify_record(&route_tamper).is_err());

        let mut content_tamper = sealed.bytes.clone();
        let last = content_tamper.len().checked_sub(1).expect("sealed bytes");
        content_tamper[last] ^= 1;
        let route = reader
            .verify_record(&content_tamper)
            .expect("source metadata remains authenticated");
        assert!(
            reader
                .verify_record_content(route, &content_tamper)
                .is_err()
        );

        let mut outsider = wrong_mission_reader();
        assert!(outsider.verify_record(&sealed.bytes).is_err());
        let route = reader
            .verify_record(&sealed.bytes)
            .expect("right mission route capability");
        assert!(
            outsider
                .verify_record_content(route, &sealed.bytes)
                .is_err()
        );
    }

    #[test]
    fn route_only_and_wrong_topic_grants_cannot_mint_content_capabilities() {
        let Services {
            mut publisher,
            other: _,
            reader: _,
            mut relay,
            mut wrong_topic,
        } = services();
        let payload = b"open";
        let header = header(publisher.identity(), payload);
        let sealed = publisher
            .seal_record(&header, payload)
            .expect("seal Record");

        for provider in [&mut relay, &mut wrong_topic] {
            let route = provider
                .verify_record(&sealed.bytes)
                .expect("route-only source verification");
            match provider
                .verify_record_content(route, &sealed.bytes)
                .expect("route-only content decision")
            {
                RecordContentVerification::RouteOnly(route) => {
                    assert_eq!(route.item_id(), sealed.id);
                    route
                        .verify_exact_sealed(&sealed.bytes)
                        .expect("route exact bytes");
                }
                RecordContentVerification::ContentVerified { .. } => {
                    panic!("provider without the topic content grant minted a strong capability")
                }
            }
        }
    }

    #[test]
    fn record_named_grant_checks_match_provisioned_event_and_state_capabilities() {
        let Services {
            publisher,
            other: _,
            reader: _,
            relay,
            wrong_topic,
        } = services();

        for provider in [&publisher, &relay, &wrong_topic] {
            assert_eq!(
                provider.can_route_record(&scope(), 1),
                provider.can_route_event(&scope(), 1)
            );
            assert_eq!(
                provider.can_route_record(&scope(), 1),
                provider.can_route_state(&scope(), 1)
            );
            assert_eq!(
                provider.can_open_record_content(&scope(), &topic(), 1),
                provider.can_open_event_content(&scope(), &topic(), 1)
            );
            assert_eq!(
                provider.can_open_record_content(&scope(), &topic(), 1),
                provider.can_open_state_content(&scope(), &topic(), 1)
            );
            assert_eq!(
                provider.can_open_record_content(&scope(), &other_topic(), 1),
                provider.can_open_event_content(&scope(), &other_topic(), 1)
            );
        }

        assert!(publisher.can_route_record(&scope(), 1));
        assert!(publisher.can_open_record_content(&scope(), &topic(), 1));
        assert!(relay.can_route_record(&scope(), 1));
        assert!(!relay.can_open_record_content(&scope(), &topic(), 1));
        assert!(wrong_topic.can_route_record(&scope(), 1));
        assert!(!wrong_topic.can_open_record_content(&scope(), &topic(), 1));
        assert!(wrong_topic.can_open_record_content(&scope(), &other_topic(), 1));
        assert!(!publisher.can_route_record(&scope(), 2));
        assert!(!publisher.can_open_record_content(&scope(), &topic(), 2));
    }

    #[test]
    fn tombstones_require_empty_payload_and_retain_durable_record_capabilities() {
        let Services {
            mut publisher,
            other: _,
            mut reader,
            relay: _,
            wrong_topic: _,
        } = services();
        let mut tombstone = header(publisher.identity(), b"");
        tombstone.tombstone = true;
        assert!(publisher.seal_record(&tombstone, b"not empty").is_err());
        let sealed = publisher
            .seal_record(&tombstone, b"")
            .expect("seal Record tombstone");
        let (record, payload) = content_verified(&mut reader, &sealed.bytes);
        assert!(payload.is_empty());
        assert!(record.tombstone());
        assert_eq!(record.content_len(), 0);
        assert_eq!(record.ttl_ms(), None);
        record
            .verify_exact_payload(b"")
            .expect("exact tombstone payload");
    }
}
