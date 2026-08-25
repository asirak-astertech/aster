//! Source-authenticated selected Blob manifest seam for store/runtime compositions.
//!
//! The protected envelope payload is the exact bounded canonical Blob manifest.
//! Route-only nodes can authenticate its `(BlobId, chunk_count, route_root)`
//! commitment, while only a provider with the exact topic content grant can
//! mint a capability that authorizes manifest installation and plaintext reads.

use crate::{
    blob::{
        BlobError, BlobId, BlobManifest, BlobReader, BlobRouteCommitment, BlobStore,
        InspectedBlobManifest, MAX_BLOB_MANIFEST_BYTES, ReferenceBlobService, VerifiedBlobManifest,
        content_group_id, inspect_selected_blob_manifest,
        verify_source_authenticated_store_completion,
    },
    crypto::ReferenceEnvelopeSealer,
    envelope::{EnvelopeError, EnvelopeHeader, EnvelopeSealer, SealRequest, SealedEnvelope},
    model::{DataClass, Dot, ItemId, NodeId, Priority, Scope, Topic, VersionVector},
};
use sha2::{Digest, Sha256};
use std::io;

/// Route- and source-authenticated metadata for one exact selected Blob envelope.
///
/// Fields and construction are deliberately private. This capability permits
/// opaque custody decisions, but it cannot authorize manifest installation or
/// plaintext reads. Use [`ReferenceEnvelopeSealer::verify_blob_content`] to
/// obtain a [`ContentVerifiedBlobEnvelope`] when content access is authorized.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RouteVerifiedBlobEnvelope {
    envelope: crate::envelope::VerifiedEnvelope,
    envelope_id: [u8; 32],
    mission_authority_id: NodeId,
}

impl RouteVerifiedBlobEnvelope {
    fn from_verified(
        envelope: crate::envelope::VerifiedEnvelope,
        sealed: &[u8],
        mission_authority_id: NodeId,
    ) -> Result<Self, EnvelopeError> {
        validate_selected_blob_header(&envelope.header)?;
        Ok(Self {
            envelope,
            envelope_id: Sha256::digest(sealed).into(),
            mission_authority_id,
        })
    }

    /// Semantic identifier derived by the existing source-envelope profile.
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

    /// Complete provider-authenticated selected Blob metadata.
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

    /// Source-authenticated causal context preceding this Blob publication.
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

    /// Finite TTL is unsupported by the selected Blob slice.
    pub const fn ttl_ms(&self) -> Option<u64> {
        self.envelope.header.ttl_ms
    }

    /// Exact 32-byte Blob identifier used as the logical key.
    pub fn logical_key(&self) -> &[u8] {
        &self.envelope.header.logical_key
    }

    /// Exact authenticated canonical manifest byte length.
    pub const fn content_len(&self) -> u64 {
        self.envelope.header.content_len
    }

    /// Selected Blobs can never be tombstones.
    pub const fn tombstone(&self) -> bool {
        self.envelope.header.tombstone
    }

    /// Source-authenticated route/content key epoch.
    pub const fn key_epoch(&self) -> u64 {
        self.envelope.header.key_epoch
    }

    /// Blob identity committed by the protected route descriptor.
    pub fn blob_id(&self) -> BlobId {
        self.route_commitment().blob_id()
    }

    /// Exact `(BlobId, chunk_count, route_root)` route commitment.
    pub fn route_commitment(&self) -> BlobRouteCommitment {
        self.envelope
            .header
            .blob_route
            .expect("RouteVerifiedBlobEnvelope requires a Blob route commitment")
    }

    /// Checks that later bytes equal the exact source-sealed representation.
    pub fn verify_exact_sealed(&self, sealed: &[u8]) -> Result<(), EnvelopeError> {
        if <[u8; 32]>::from(Sha256::digest(sealed)) != self.envelope_id {
            return Err(EnvelopeError(
                "source Blob capability does not match sealed bytes".into(),
            ));
        }
        Ok(())
    }
}

/// Source metadata and exact canonical manifest verified by an authorized provider.
///
/// Its private constructor is reachable only after the provider authenticates
/// and opens the exact envelope bytes held by a route capability.
#[derive(Clone, Eq, PartialEq)]
pub struct ContentVerifiedBlobEnvelope {
    route: RouteVerifiedBlobEnvelope,
    inspected: InspectedBlobManifest,
    manifest_sha256: [u8; 32],
}

impl std::fmt::Debug for ContentVerifiedBlobEnvelope {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("ContentVerifiedBlobEnvelope")
            .field("blob_id", &self.blob_id())
            .field("envelope_id", &self.envelope_id())
            .field("mission_authority_id", &self.mission_authority_id())
            .field("publisher", &self.publisher())
            .field("manifest_len", &self.content_len())
            .field("manifest_digest", &"[REDACTED]")
            .finish()
    }
}

impl ContentVerifiedBlobEnvelope {
    fn from_opened(
        route: RouteVerifiedBlobEnvelope,
        manifest_bytes: &[u8],
    ) -> Result<Self, EnvelopeError> {
        let (inspected, computed_route) = inspect_selected_blob_manifest(manifest_bytes)
            .map_err(|_| invalid_selected_blob_manifest())?;
        if computed_route != route.route_commitment()
            || inspected.manifest().id() != route.blob_id()
            || inspected.manifest().chunk_count() != route.route_commitment().chunk_count()
            || *inspected.manifest().content_group()
                != content_group_id(route.scope(), route.topic())
            || inspected.manifest().content_epoch() != route.key_epoch()
        {
            return Err(EnvelopeError(
                "source Blob manifest differs from authenticated routing metadata".into(),
            ));
        }
        Ok(Self {
            route,
            inspected,
            manifest_sha256: Sha256::digest(manifest_bytes).into(),
        })
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

    /// Complete source- and content-authenticated Blob metadata.
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

    /// Source-authenticated causal context preceding this Blob publication.
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

    /// Finite TTL is unsupported by the selected Blob slice.
    pub const fn ttl_ms(&self) -> Option<u64> {
        self.route.ttl_ms()
    }

    /// Exact 32-byte Blob identifier used as the logical key.
    pub fn logical_key(&self) -> &[u8] {
        self.route.logical_key()
    }

    /// Exact authenticated canonical manifest byte length.
    pub const fn content_len(&self) -> u64 {
        self.route.content_len()
    }

    /// Selected Blobs can never be tombstones.
    pub const fn tombstone(&self) -> bool {
        self.route.tombstone()
    }

    /// Source-authenticated route/content key epoch.
    pub const fn key_epoch(&self) -> u64 {
        self.route.key_epoch()
    }

    /// Blob identity committed by both route descriptor and exact manifest.
    pub fn blob_id(&self) -> BlobId {
        self.route.blob_id()
    }

    /// Exact `(BlobId, chunk_count, route_root)` route commitment.
    pub fn route_commitment(&self) -> BlobRouteCommitment {
        self.route.route_commitment()
    }

    /// Canonically decoded manifest authenticated from the exact payload bytes.
    pub fn manifest(&self) -> &BlobManifest {
        self.inspected.manifest()
    }

    /// Domain-separated digest of the exact canonical manifest encoding.
    pub fn manifest_digest(&self) -> &[u8; 32] {
        self.inspected.manifest_digest()
    }

    /// Checks that later bytes equal the exact content-verified envelope.
    pub fn verify_exact_sealed(&self, sealed: &[u8]) -> Result<(), EnvelopeError> {
        self.route.verify_exact_sealed(sealed)
    }

    /// Checks that later bytes equal the exact authenticated canonical manifest.
    pub fn verify_exact_manifest(&self, manifest_bytes: &[u8]) -> Result<(), EnvelopeError> {
        if <[u8; 32]>::from(Sha256::digest(manifest_bytes)) != self.manifest_sha256 {
            return Err(EnvelopeError(
                "source Blob capability does not match manifest bytes".into(),
            ));
        }
        Ok(())
    }

    /// Alias for [`Self::verify_exact_manifest`] at generic payload boundaries.
    pub fn verify_exact_payload(&self, payload: &[u8]) -> Result<(), EnvelopeError> {
        self.verify_exact_manifest(payload)
    }

    /// Proves that a durable adapter completed the exact authenticated manifest.
    ///
    /// Every expected and committed chunk record, plus the finalization digest,
    /// is compared without exposing content keys or creating source authority.
    /// Raw [`BlobStore::finalize_blob`] calls therefore remain storage mechanics,
    /// not sufficient evidence for publication or delivery.
    pub fn verify_store_completion<S: BlobStore + ?Sized>(
        &self,
        manifest_bytes: &[u8],
        store: &mut S,
    ) -> Result<(), BlobError> {
        self.verify_exact_manifest(manifest_bytes)
            .map_err(|_| BlobError::AuthenticationFailed)?;
        verify_source_authenticated_store_completion(
            manifest_bytes,
            self.inspected_manifest(),
            store,
        )
    }

    pub(crate) const fn inspected_manifest(&self) -> &InspectedBlobManifest {
        &self.inspected
    }
}

/// Result of attempting selected Blob content verification through the provider.
#[derive(Clone, Eq, PartialEq)]
// Keep parity with Event/Record verification by returning the strong capability
// directly. Exact manifest bytes remain out-of-line in `Vec` storage.
#[allow(clippy::large_enum_variant)]
pub enum BlobContentVerification {
    /// Source/route metadata is valid, but this provider has no content grant.
    RouteOnly(RouteVerifiedBlobEnvelope),
    /// Source metadata and the exact canonical manifest both authenticated.
    ContentVerified {
        blob: ContentVerifiedBlobEnvelope,
        manifest_bytes: Vec<u8>,
    },
}

impl std::fmt::Debug for BlobContentVerification {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::RouteOnly(blob) => formatter
                .debug_struct("BlobContentVerification::RouteOnly")
                .field("blob_id", &blob.blob_id())
                .field("envelope_id", &blob.envelope_id())
                .finish(),
            Self::ContentVerified {
                blob,
                manifest_bytes,
            } => formatter
                .debug_struct("BlobContentVerification::ContentVerified")
                .field("blob_id", &blob.blob_id())
                .field("envelope_id", &blob.envelope_id())
                .field("manifest_len", &manifest_bytes.len())
                .field("manifest_bytes", &"[REDACTED]")
                .finish(),
        }
    }
}

impl ReferenceEnvelopeSealer {
    /// Reports whether this node owns the exact route capability for a Blob scope epoch.
    pub fn can_route_blob(&self, scope: &Scope, epoch: u64) -> bool {
        self.can_route_event(scope, epoch)
    }

    /// Reports whether this node can open Blob content for an exact topic and epoch.
    pub fn can_open_blob_content(&self, scope: &Scope, topic: &Topic, epoch: u64) -> bool {
        self.can_open_event_content(scope, topic, epoch)
    }

    /// Seals an exact canonical selected Blob manifest through the source provider.
    pub fn seal_blob_manifest(
        &mut self,
        header: &EnvelopeHeader,
        manifest_bytes: &[u8],
    ) -> Result<SealedEnvelope, EnvelopeError> {
        validate_selected_blob_header(header)?;
        if u64::try_from(manifest_bytes.len()).ok() != Some(header.content_len) {
            return Err(EnvelopeError(
                "source Blob manifest length differs from authenticated metadata".into(),
            ));
        }
        let (inspected, route) = inspect_selected_blob_manifest(manifest_bytes)
            .map_err(|_| invalid_selected_blob_manifest())?;
        validate_manifest_binding(header, &inspected, route)?;
        <Self as EnvelopeSealer>::seal(
            self,
            SealRequest {
                header,
                payload: manifest_bytes,
            },
        )
    }

    /// Authenticates source identity and protected Blob routing metadata.
    pub fn verify_blob(
        &mut self,
        sealed: &[u8],
    ) -> Result<RouteVerifiedBlobEnvelope, EnvelopeError> {
        let verified = <Self as EnvelopeSealer>::inspect(self, sealed)?;
        RouteVerifiedBlobEnvelope::from_verified(verified, sealed, self.mission_authority_id())
    }

    /// Authenticates a Blob and requires its source to equal `expected`.
    pub fn verify_blob_from(
        &mut self,
        expected: NodeId,
        sealed: &[u8],
    ) -> Result<RouteVerifiedBlobEnvelope, EnvelopeError> {
        let blob = self.verify_blob(sealed)?;
        if blob.publisher() != expected {
            return Err(EnvelopeError(
                "source Blob publisher differs from expected identity".into(),
            ));
        }
        Ok(blob)
    }

    /// Attempts to authenticate and open the exact manifest for a route capability.
    pub fn verify_blob_content(
        &mut self,
        blob: RouteVerifiedBlobEnvelope,
        sealed: &[u8],
    ) -> Result<BlobContentVerification, EnvelopeError> {
        blob.verify_exact_sealed(sealed)?;
        if blob.mission_authority_id() != self.mission_authority_id() {
            return Err(EnvelopeError(
                "source Blob capability belongs to another mission authority".into(),
            ));
        }
        match <Self as EnvelopeSealer>::open_payload_if_authorized(self, &blob.envelope, sealed)? {
            None => Ok(BlobContentVerification::RouteOnly(blob)),
            Some(manifest_bytes) => {
                if u64::try_from(manifest_bytes.len()).ok() != Some(blob.content_len()) {
                    return Err(EnvelopeError(
                        "source Blob manifest length differs from authenticated metadata".into(),
                    ));
                }
                let verified = ContentVerifiedBlobEnvelope::from_opened(blob, &manifest_bytes)?;
                Ok(BlobContentVerification::ContentVerified {
                    blob: verified,
                    manifest_bytes,
                })
            }
        }
    }
}

impl<S: BlobStore> ReferenceBlobService<S> {
    /// Installs the exact provider-verified canonical manifest into the durable adapter.
    pub fn install_verified_manifest(
        &mut self,
        blob: &ContentVerifiedBlobEnvelope,
        manifest_bytes: &[u8],
    ) -> Result<(), BlobError> {
        blob.verify_exact_manifest(manifest_bytes)
            .map_err(|_| BlobError::AuthenticationFailed)?;
        self.validate_verified_blob_binding(blob)?;
        let mut input = io::Cursor::new(manifest_bytes);
        self.install_authenticated_manifest(&mut input, blob.inspected_manifest())?;
        Ok(())
    }

    /// Opens a selected reader that remains borrowed from this service/store.
    pub fn reader_for_verified(
        &mut self,
        blob: &ContentVerifiedBlobEnvelope,
    ) -> Result<BlobReader<&'_ mut S>, BlobError> {
        self.validate_verified_blob_binding(blob)?;
        self.reader(VerifiedBlobManifest::new(blob.manifest().clone()))
    }

    fn validate_verified_blob_binding(
        &self,
        blob: &ContentVerifiedBlobEnvelope,
    ) -> Result<(), BlobError> {
        if self
            .bound_mission_authority_id()
            .is_some_and(|authority| authority != blob.mission_authority_id())
            || self.bound_content_group() != blob.manifest().content_group()
            || self.bound_epoch() != blob.manifest().content_epoch()
        {
            return Err(BlobError::AuthenticationFailed);
        }
        Ok(())
    }
}

fn validate_selected_blob_header(header: &EnvelopeHeader) -> Result<(), EnvelopeError> {
    let route = header
        .blob_route
        .ok_or_else(|| EnvelopeError("selected source Blob requires a route commitment".into()))?;
    if header.class != DataClass::Blob
        || header.event_sequence.is_some()
        || header.tombstone
        || header.ttl_ms.is_some()
        || header.content_len == 0
        || header.content_len > MAX_BLOB_MANIFEST_BYTES
        || route.chunk_count() == 0
        || header.logical_key.as_slice() != route.blob_id().as_bytes()
    {
        return Err(EnvelopeError(
            "authenticated envelope is not a valid selected Blob".into(),
        ));
    }
    Ok(())
}

fn validate_manifest_binding(
    header: &EnvelopeHeader,
    inspected: &InspectedBlobManifest,
    route: BlobRouteCommitment,
) -> Result<(), EnvelopeError> {
    if header.blob_route != Some(route)
        || inspected.manifest().id() != route.blob_id()
        || inspected.manifest().chunk_count() != route.chunk_count()
        || *inspected.manifest().content_group() != content_group_id(&header.scope, &header.topic)
        || inspected.manifest().content_epoch() != header.key_epoch
    {
        return Err(EnvelopeError(
            "source Blob manifest differs from authenticated routing metadata".into(),
        ));
    }
    Ok(())
}

fn invalid_selected_blob_manifest() -> EnvelopeError {
    EnvelopeError("invalid selected source Blob manifest".into())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        BlobChunkRecord, BlobMetadata, BlobStore, CausalStamp, SELECTED_BLOB_CHUNK_SIZE,
        crypto::{ProvisioningAccess, ReferenceProvisioner},
        prepare_blob,
    };
    use std::io::{self, Cursor, Read, Seek, SeekFrom};

    #[derive(Default)]
    struct TestBlobStore {
        manifest: Option<BlobManifest>,
        plaintext: Vec<Option<[u8; 32]>>,
        records: Vec<Option<BlobChunkRecord>>,
        expected: Vec<Option<BlobChunkRecord>>,
        chunks: Vec<Option<Vec<u8>>>,
        finalized: Option<[u8; 32]>,
    }

    impl TestBlobStore {
        fn slot(&self, id: BlobId, index: u64) -> io::Result<usize> {
            let manifest = self
                .manifest
                .as_ref()
                .ok_or_else(|| io::Error::other("manifest absent"))?;
            if manifest.id() != id || index >= manifest.chunk_count() {
                return Err(io::Error::other("Blob key outside manifest"));
            }
            usize::try_from(index).map_err(io::Error::other)
        }
    }

    impl BlobStore for TestBlobStore {
        type StoreError = io::Error;

        fn begin_blob(&mut self, manifest: &BlobManifest) -> io::Result<()> {
            if let Some(existing) = &self.manifest {
                if existing != manifest {
                    return Err(io::Error::other("manifest conflict"));
                }
                return Ok(());
            }
            let count = usize::try_from(manifest.chunk_count()).map_err(io::Error::other)?;
            self.plaintext.resize(count, None);
            self.records.resize(count, None);
            self.expected.resize(count, None);
            self.chunks.resize(count, None);
            self.manifest = Some(manifest.clone());
            Ok(())
        }

        fn put_plaintext_digest(
            &mut self,
            id: BlobId,
            index: u64,
            digest: [u8; 32],
        ) -> io::Result<()> {
            let index = self.slot(id, index)?;
            if self.plaintext[index].is_some_and(|existing| existing != digest) {
                return Err(io::Error::other("plaintext digest conflict"));
            }
            self.plaintext[index] = Some(digest);
            Ok(())
        }

        fn plaintext_digest(&mut self, id: BlobId, index: u64) -> io::Result<Option<[u8; 32]>> {
            let index = self.slot(id, index)?;
            Ok(self.plaintext[index])
        }

        fn chunk_record(&mut self, id: BlobId, index: u64) -> io::Result<Option<BlobChunkRecord>> {
            let index = self.slot(id, index)?;
            Ok(self.records[index])
        }

        fn put_expected_chunk_record(
            &mut self,
            id: BlobId,
            index: u64,
            record: BlobChunkRecord,
        ) -> io::Result<()> {
            let index = self.slot(id, index)?;
            if self.expected[index].is_some_and(|existing| existing != record) {
                return Err(io::Error::other("expected record conflict"));
            }
            self.expected[index] = Some(record);
            Ok(())
        }

        fn expected_chunk_record(
            &mut self,
            id: BlobId,
            index: u64,
        ) -> io::Result<Option<BlobChunkRecord>> {
            let index = self.slot(id, index)?;
            Ok(self.expected[index])
        }

        fn commit_verified_chunk(
            &mut self,
            id: BlobId,
            index: u64,
            record: BlobChunkRecord,
            ciphertext: &[u8],
        ) -> io::Result<()> {
            let index = self.slot(id, index)?;
            if self.expected[index].is_some_and(|expected| expected != record)
                || self.records[index].is_some_and(|existing| existing != record)
                || self.chunks[index]
                    .as_ref()
                    .is_some_and(|existing| existing.as_slice() != ciphertext)
            {
                return Err(io::Error::other("chunk conflict"));
            }
            self.records[index] = Some(record);
            self.chunks[index] = Some(ciphertext.to_vec());
            Ok(())
        }

        fn read_verified_chunk(
            &mut self,
            id: BlobId,
            index: u64,
            output: &mut Vec<u8>,
        ) -> io::Result<bool> {
            let index = self.slot(id, index)?;
            output.clear();
            if let Some(chunk) = &self.chunks[index] {
                output.extend_from_slice(chunk);
                Ok(true)
            } else {
                Ok(false)
            }
        }

        fn finalize_blob(&mut self, id: BlobId, manifest_digest: [u8; 32]) -> io::Result<()> {
            let _ = self.slot(id, 0)?;
            if self
                .finalized
                .is_some_and(|existing| existing != manifest_digest)
            {
                return Err(io::Error::other("finalized digest conflict"));
            }
            self.finalized = Some(manifest_digest);
            Ok(())
        }

        fn finalized_manifest_digest(&mut self, id: BlobId) -> io::Result<Option<[u8; 32]>> {
            let _ = self.slot(id, 0)?;
            Ok(self.finalized)
        }
    }

    fn scope() -> Scope {
        Scope::new("test/source-blob").expect("scope")
    }

    fn topic() -> Topic {
        Topic::new("mesh-blob").expect("topic")
    }

    fn other_topic() -> Topic {
        Topic::new("other-blob").expect("other topic")
    }

    fn full_access() -> ProvisioningAccess {
        ProvisioningAccess::member(scope(), vec![1, 2], vec![topic(), other_topic()])
            .expect("member access")
    }

    fn relay_access() -> ProvisioningAccess {
        ProvisioningAccess::relay(scope(), vec![1, 2]).expect("relay access")
    }

    fn wrong_topic_access() -> ProvisioningAccess {
        ProvisioningAccess::member(scope(), vec![1, 2], vec![other_topic()])
            .expect("wrong topic access")
    }

    struct Services {
        publisher: ReferenceEnvelopeSealer,
        other: ReferenceEnvelopeSealer,
        reader: ReferenceEnvelopeSealer,
        relay: ReferenceEnvelopeSealer,
        wrong_topic: ReferenceEnvelopeSealer,
    }

    fn services() -> Services {
        let mut provisioner = ReferenceProvisioner::from_seed([0x41; 32]).expect("provisioner");
        let publisher = provisioner
            .issue_node(1, &[full_access()])
            .and_then(ReferenceEnvelopeSealer::open)
            .expect("publisher");
        let other = provisioner
            .issue_node(2, &[full_access()])
            .and_then(ReferenceEnvelopeSealer::open)
            .expect("other publisher");
        let reader = provisioner
            .issue_node(3, &[full_access()])
            .and_then(ReferenceEnvelopeSealer::open)
            .expect("reader");
        let relay = provisioner
            .issue_node(4, &[relay_access()])
            .and_then(ReferenceEnvelopeSealer::open)
            .expect("relay");
        let wrong_topic = provisioner
            .issue_node(5, &[wrong_topic_access()])
            .and_then(ReferenceEnvelopeSealer::open)
            .expect("wrong topic reader");
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
            ReferenceProvisioner::from_seed([0x92; 32]).expect("wrong mission provisioner");
        provisioner
            .issue_node(1, &[full_access()])
            .and_then(ReferenceEnvelopeSealer::open)
            .expect("wrong mission reader")
    }

    struct Fixture {
        service: ReferenceBlobService<TestBlobStore>,
        manifest: BlobManifest,
        finished: crate::FinishedBlob,
        plaintext: Vec<u8>,
    }

    fn fixture(
        provider: &ReferenceEnvelopeSealer,
        channel: &Topic,
        epoch: u64,
        plaintext: Vec<u8>,
        metadata: BlobMetadata,
    ) -> Fixture {
        let mut source = Cursor::new(plaintext.clone());
        let prepared = prepare_blob(&mut source, SELECTED_BLOB_CHUNK_SIZE, metadata)
            .expect("prepare selected Blob");
        let mut service = provider
            .blob_service_with_store(&scope(), channel, epoch, TestBlobStore::default())
            .expect("provider-owned store service");
        let manifest = service
            .install_prepared(&prepared)
            .expect("install preparation");
        let progress = service
            .encrypt_some(&mut source, &manifest, u64::MAX)
            .expect("encrypt chunks");
        assert!(progress.complete);
        let finished = service.finish_manifest(&manifest).expect("finish manifest");
        Fixture {
            service,
            manifest,
            finished,
            plaintext,
        }
    }

    fn header(
        publisher: NodeId,
        finished: &crate::FinishedBlob,
        channel: Topic,
        epoch: u64,
        counter: u64,
    ) -> EnvelopeHeader {
        EnvelopeHeader {
            class: DataClass::Blob,
            topic: channel,
            scope: scope(),
            priority: Priority::Immediate,
            stamp: CausalStamp {
                dot: Dot { publisher, counter },
                context: VersionVector::default(),
            },
            event_sequence: None,
            logical_key: finished.id().as_bytes().to_vec(),
            blob_route: Some(finished.route_commitment()),
            ttl_ms: None,
            content_len: finished.manifest_bytes().len() as u64,
            tombstone: false,
            key_epoch: epoch,
        }
    }

    fn content_verified(
        reader: &mut ReferenceEnvelopeSealer,
        sealed: &[u8],
    ) -> (ContentVerifiedBlobEnvelope, Vec<u8>) {
        let route = reader.verify_blob(sealed).expect("verify Blob route");
        match reader
            .verify_blob_content(route, sealed)
            .expect("verify Blob content")
        {
            BlobContentVerification::ContentVerified {
                blob,
                manifest_bytes,
            } => (blob, manifest_bytes),
            BlobContentVerification::RouteOnly(_) => panic!("member unexpectedly route-only"),
        }
    }

    #[test]
    fn selected_blob_identity_capabilities_and_borrowed_reader_bind_exact_bytes() {
        let Services {
            mut publisher,
            other: _,
            mut reader,
            relay: _,
            wrong_topic: _,
        } = services();
        let plaintext = (0..SELECTED_BLOB_CHUNK_SIZE as usize + 37)
            .map(|index| (index % 251) as u8)
            .collect::<Vec<_>>();
        let metadata = BlobMetadata::new(Some("application/octet-stream".into()), vec![7, 9])
            .expect("metadata");

        let mut positioned = Cursor::new(plaintext.clone());
        positioned.set_position(17);
        let same_first = prepare_blob(&mut positioned, SELECTED_BLOB_CHUNK_SIZE, metadata.clone())
            .expect("first preparation");
        assert_eq!(positioned.position(), 17);
        let same_second = prepare_blob(
            &mut Cursor::new(plaintext.clone()),
            SELECTED_BLOB_CHUNK_SIZE,
            metadata.clone(),
        )
        .expect("repeat preparation");
        assert_eq!(same_first.id(), same_second.id());
        let changed_metadata = prepare_blob(
            &mut Cursor::new(plaintext.clone()),
            SELECTED_BLOB_CHUNK_SIZE,
            BlobMetadata::new(Some("application/example".into()), vec![7, 9])
                .expect("different metadata"),
        )
        .expect("metadata preparation");
        assert_ne!(same_first.id(), changed_metadata.id());
        let mut changed_plaintext = plaintext.clone();
        changed_plaintext[0] ^= 1;
        let changed_content = prepare_blob(
            &mut Cursor::new(changed_plaintext),
            SELECTED_BLOB_CHUNK_SIZE,
            metadata.clone(),
        )
        .expect("changed content preparation");
        assert_ne!(same_first.id(), changed_content.id());

        let mut fixture = fixture(&publisher, &topic(), 1, plaintext, metadata);
        let finished_debug = format!("{:?}", fixture.finished);
        assert!(finished_debug.contains("manifest_bytes: \"[REDACTED]\""));
        assert!(finished_debug.contains("manifest_digest: \"[REDACTED]\""));
        assert_eq!(fixture.manifest.id(), same_first.id());
        assert_eq!(fixture.manifest.chunk_size(), SELECTED_BLOB_CHUNK_SIZE);
        assert_eq!(fixture.manifest.chunk_count(), 2);
        let source_header = header(publisher.identity(), &fixture.finished, topic(), 1, 1);
        let sealed = publisher
            .seal_blob_manifest(&source_header, fixture.finished.manifest_bytes())
            .expect("seal selected Blob");
        let resealed = publisher
            .seal_blob_manifest(&source_header, fixture.finished.manifest_bytes())
            .expect("reseal selected Blob");
        assert_ne!(sealed.bytes, resealed.bytes);

        let route = reader.verify_blob(&sealed.bytes).expect("route capability");
        assert_eq!(route.item_id(), sealed.id);
        assert_eq!(route.blob_id(), fixture.finished.id());
        assert_eq!(
            route.route_commitment(),
            fixture.finished.route_commitment()
        );
        assert_eq!(route.logical_key(), fixture.finished.id().as_bytes());
        assert_eq!(route.ttl_ms(), None);
        assert!(!route.tombstone());
        assert_eq!(route.key_epoch(), 1);
        assert_eq!(route.header(), &source_header);
        assert!(route.verify_exact_sealed(&resealed.bytes).is_err());

        let verification = reader
            .verify_blob_content(route, &sealed.bytes)
            .expect("content verification");
        let debug = format!("{verification:?}");
        assert!(debug.contains("[REDACTED]"));
        let (blob, manifest_bytes) = match verification {
            BlobContentVerification::ContentVerified {
                blob,
                manifest_bytes,
            } => (blob, manifest_bytes),
            BlobContentVerification::RouteOnly(_) => panic!("member unexpectedly route-only"),
        };
        assert_eq!(blob.blob_id(), fixture.finished.id());
        assert_eq!(blob.route_commitment(), fixture.finished.route_commitment());
        assert_eq!(blob.manifest(), &fixture.manifest);
        assert_eq!(blob.manifest_digest(), fixture.finished.manifest_digest());
        assert!(format!("{blob:?}").contains("manifest_digest: \"[REDACTED]\""));
        blob.verify_exact_sealed(&sealed.bytes)
            .expect("exact sealed bytes");
        blob.verify_exact_manifest(&manifest_bytes)
            .expect("exact manifest bytes");
        blob.verify_exact_payload(&manifest_bytes)
            .expect("exact payload alias");
        let mut stale = manifest_bytes.clone();
        stale[0] ^= 1;
        assert!(blob.verify_exact_manifest(&stale).is_err());

        fixture
            .service
            .install_verified_manifest(&blob, &manifest_bytes)
            .expect("install verified manifest");
        let mut output = Vec::new();
        let stats = fixture
            .service
            .reader_for_verified(&blob)
            .and_then(|mut blob_reader| blob_reader.stream_into(&mut output))
            .expect("borrowed verified reader");
        assert_eq!(output, fixture.plaintext);
        assert_eq!(stats.plaintext_bytes, fixture.plaintext.len() as u64);
        assert_eq!(stats.verified_chunks, fixture.manifest.chunk_count());
    }

    #[test]
    fn store_completion_requires_every_exact_authenticated_record_and_digest() {
        let Services {
            mut publisher,
            other: _,
            mut reader,
            relay: _,
            wrong_topic: _,
        } = services();
        let plaintext = (0..SELECTED_BLOB_CHUNK_SIZE as usize + 19)
            .map(|index| (index % 239) as u8)
            .collect::<Vec<_>>();
        let mut source = Cursor::new(plaintext);
        let prepared = prepare_blob(
            &mut source,
            SELECTED_BLOB_CHUNK_SIZE,
            BlobMetadata::new(Some("application/octet-stream".into()), vec![4, 2])
                .expect("metadata"),
        )
        .expect("prepare selected Blob");
        let mut store = TestBlobStore::default();
        let mut service = publisher
            .blob_service_with_store(&scope(), &topic(), 1, &mut store)
            .expect("borrowed provider-owned store service");
        let manifest = service
            .install_prepared(&prepared)
            .expect("install preparation");
        assert!(
            service
                .encrypt_some(&mut source, &manifest, u64::MAX)
                .expect("encrypt chunks")
                .complete
        );
        let finished = service.finish_manifest(&manifest).expect("finish manifest");
        drop(service);
        // The selected redb adapter binds locally derived records as expected
        // records during commit. Model that stronger completion invariant here.
        store.expected.clone_from(&store.records);

        let selected = header(publisher.identity(), &finished, topic(), 1, 33);
        let sealed = publisher
            .seal_blob_manifest(&selected, finished.manifest_bytes())
            .expect("seal manifest");
        let (blob, manifest_bytes) = content_verified(&mut reader, &sealed.bytes);
        blob.verify_store_completion(&manifest_bytes, &mut store)
            .expect("exact durable completion");

        let authentic = store.records[0].expect("committed record");
        let mut wrong_ciphertext_digest = *authentic.ciphertext_sha256();
        wrong_ciphertext_digest[0] ^= 1;
        let wrong = BlobChunkRecord::from_parts(
            *authentic.plaintext_sha256(),
            wrong_ciphertext_digest,
            authentic.plaintext_len(),
            authentic.ciphertext_len(),
        )
        .expect("structurally valid wrong record");

        // A caller-controlled adapter cannot turn mutually consistent wrong
        // records plus the authentic final digest into completion authority.
        store.expected[0] = Some(wrong);
        store.records[0] = Some(wrong);
        store.finalized = Some(*blob.manifest_digest());
        assert!(
            blob.verify_store_completion(&manifest_bytes, &mut store)
                .is_err()
        );

        store.expected[0] = Some(authentic);
        store.records[0] = Some(authentic);
        store.finalized = Some([0x55; 32]);
        assert!(
            blob.verify_store_completion(&manifest_bytes, &mut store)
                .is_err()
        );

        store.finalized = Some(*blob.manifest_digest());
        store.expected[0] = None;
        assert!(
            blob.verify_store_completion(&manifest_bytes, &mut store)
                .is_err()
        );

        store.expected[0] = Some(authentic);
        let mut tampered_manifest = manifest_bytes;
        tampered_manifest[0] ^= 1;
        assert!(
            blob.verify_store_completion(&tampered_manifest, &mut store)
                .is_err()
        );
    }

    #[test]
    fn class_ttl_empty_noncanonical_chunking_and_tamper_fail_closed() {
        let Services {
            mut publisher,
            other: _,
            mut reader,
            relay: _,
            wrong_topic: _,
        } = services();
        let fixture = fixture(
            &publisher,
            &topic(),
            1,
            b"nonempty selected Blob".to_vec(),
            BlobMetadata::new(None, Vec::new()).expect("metadata"),
        );
        let selected = header(publisher.identity(), &fixture.finished, topic(), 1, 1);

        let mut wrong_class = selected.clone();
        wrong_class.class = DataClass::State;
        wrong_class.blob_route = None;
        assert!(
            publisher
                .seal_blob_manifest(&wrong_class, fixture.finished.manifest_bytes())
                .is_err()
        );
        let generic_state = <ReferenceEnvelopeSealer as EnvelopeSealer>::seal(
            &mut publisher,
            SealRequest {
                header: &wrong_class,
                payload: fixture.finished.manifest_bytes(),
            },
        )
        .expect("seal class-confused payload through generic boundary");
        assert!(reader.verify_blob(&generic_state.bytes).is_err());

        for ttl_ms in [Some(0), Some(50)] {
            let mut finite = selected.clone();
            finite.ttl_ms = ttl_ms;
            assert!(
                publisher
                    .seal_blob_manifest(&finite, fixture.finished.manifest_bytes())
                    .is_err()
            );
            let generic = <ReferenceEnvelopeSealer as EnvelopeSealer>::seal(
                &mut publisher,
                SealRequest {
                    header: &finite,
                    payload: fixture.finished.manifest_bytes(),
                },
            )
            .expect("generic provider permits finite TTL syntax");
            assert!(reader.verify_blob(&generic.bytes).is_err());
        }

        let empty = prepare_blob(
            &mut Cursor::new(Vec::<u8>::new()),
            SELECTED_BLOB_CHUNK_SIZE,
            BlobMetadata::new(None, Vec::new()).expect("empty metadata"),
        )
        .expect("bounded empty preparation");
        let mut selected_service = publisher
            .blob_service_with_store(&scope(), &topic(), 1, TestBlobStore::default())
            .expect("selected service");
        assert!(selected_service.install_prepared(&empty).is_err());

        let noncanonical = prepare_blob(
            &mut Cursor::new(vec![1_u8; 4097]),
            4 * 1024,
            BlobMetadata::new(None, Vec::new()).expect("metadata"),
        )
        .expect("generic preparation");
        assert!(selected_service.install_prepared(&noncanonical).is_err());

        let sealed = publisher
            .seal_blob_manifest(&selected, fixture.finished.manifest_bytes())
            .expect("seal Blob");
        let mut route_tamper = sealed.bytes.clone();
        route_tamper[0] ^= 1;
        assert!(reader.verify_blob(&route_tamper).is_err());

        let mut content_tamper = sealed.bytes.clone();
        let last = content_tamper.len() - 1;
        content_tamper[last] ^= 1;
        let route = reader
            .verify_blob(&content_tamper)
            .expect("route metadata remains authenticated");
        assert!(reader.verify_blob_content(route, &content_tamper).is_err());

        let mut manifest_tamper = fixture.finished.manifest_bytes().to_vec();
        manifest_tamper[0] ^= 1;
        assert!(
            publisher
                .seal_blob_manifest(&selected, &manifest_tamper)
                .is_err()
        );
    }

    #[test]
    fn route_root_group_epoch_source_and_mission_bindings_are_exact() {
        let Services {
            mut publisher,
            other,
            mut reader,
            relay: _,
            wrong_topic: _,
        } = services();
        let base = fixture(
            &publisher,
            &topic(),
            1,
            vec![0x35; SELECTED_BLOB_CHUNK_SIZE as usize + 1],
            BlobMetadata::new(Some("application/base".into()), vec![1]).expect("base metadata"),
        );
        let base_header = header(publisher.identity(), &base.finished, topic(), 1, 1);
        let sealed = publisher
            .seal_blob_manifest(&base_header, base.finished.manifest_bytes())
            .expect("seal base Blob");
        assert!(
            reader
                .verify_blob_from(other.identity(), &sealed.bytes)
                .is_err()
        );
        reader
            .verify_blob_from(publisher.identity(), &sealed.bytes)
            .expect("expected source");

        let mut wrong_root_header = base_header.clone();
        let route = base.finished.route_commitment();
        let mut wrong_root = *route.root();
        wrong_root[0] ^= 1;
        wrong_root_header.blob_route = Some(
            BlobRouteCommitment::from_parts(route.blob_id(), route.chunk_count(), wrong_root)
                .expect("structurally valid wrong root"),
        );
        assert!(
            publisher
                .seal_blob_manifest(&wrong_root_header, base.finished.manifest_bytes())
                .is_err()
        );
        let wrong_root_sealed = <ReferenceEnvelopeSealer as EnvelopeSealer>::seal(
            &mut publisher,
            SealRequest {
                header: &wrong_root_header,
                payload: base.finished.manifest_bytes(),
            },
        )
        .expect("generic provider seals authenticated wrong root");
        let wrong_root_route = reader
            .verify_blob(&wrong_root_sealed.bytes)
            .expect("route-only verification authenticates committed root");
        assert!(
            reader
                .verify_blob_content(wrong_root_route, &wrong_root_sealed.bytes)
                .is_err()
        );

        let wrong_group = fixture(
            &publisher,
            &other_topic(),
            1,
            b"wrong group".to_vec(),
            BlobMetadata::new(None, vec![2]).expect("group metadata"),
        );
        let wrong_group_header = header(publisher.identity(), &wrong_group.finished, topic(), 1, 2);
        assert!(
            publisher
                .seal_blob_manifest(&wrong_group_header, wrong_group.finished.manifest_bytes())
                .is_err()
        );
        let generic_wrong_group = <ReferenceEnvelopeSealer as EnvelopeSealer>::seal(
            &mut publisher,
            SealRequest {
                header: &wrong_group_header,
                payload: wrong_group.finished.manifest_bytes(),
            },
        )
        .expect("generic group mismatch");
        let group_route = reader
            .verify_blob(&generic_wrong_group.bytes)
            .expect("verify group route");
        assert!(
            reader
                .verify_blob_content(group_route, &generic_wrong_group.bytes)
                .is_err()
        );

        let wrong_epoch = fixture(
            &publisher,
            &topic(),
            2,
            b"wrong epoch".to_vec(),
            BlobMetadata::new(None, vec![3]).expect("epoch metadata"),
        );
        let wrong_epoch_header = header(publisher.identity(), &wrong_epoch.finished, topic(), 1, 3);
        assert!(
            publisher
                .seal_blob_manifest(&wrong_epoch_header, wrong_epoch.finished.manifest_bytes())
                .is_err()
        );
        let generic_wrong_epoch = <ReferenceEnvelopeSealer as EnvelopeSealer>::seal(
            &mut publisher,
            SealRequest {
                header: &wrong_epoch_header,
                payload: wrong_epoch.finished.manifest_bytes(),
            },
        )
        .expect("generic epoch mismatch");
        let epoch_route = reader
            .verify_blob(&generic_wrong_epoch.bytes)
            .expect("verify epoch route");
        assert!(
            reader
                .verify_blob_content(epoch_route, &generic_wrong_epoch.bytes)
                .is_err()
        );

        let mut outsider = wrong_mission_reader();
        assert!(outsider.verify_blob(&sealed.bytes).is_err());
        let right_route = reader
            .verify_blob(&sealed.bytes)
            .expect("right mission route");
        assert!(
            outsider
                .verify_blob_content(right_route, &sealed.bytes)
                .is_err()
        );
    }

    #[test]
    fn route_only_and_wrong_topic_grants_cannot_mint_blob_content() {
        let Services {
            mut publisher,
            other: _,
            reader: _,
            mut relay,
            mut wrong_topic,
        } = services();
        let fixture = fixture(
            &publisher,
            &topic(),
            1,
            b"opaque to relays".to_vec(),
            BlobMetadata::new(None, Vec::new()).expect("metadata"),
        );
        let source_header = header(publisher.identity(), &fixture.finished, topic(), 1, 1);
        let sealed = publisher
            .seal_blob_manifest(&source_header, fixture.finished.manifest_bytes())
            .expect("seal Blob");

        assert!(relay.can_route_blob(&scope(), 1));
        assert!(!relay.can_open_blob_content(&scope(), &topic(), 1));
        assert!(
            relay
                .blob_service_with_store(&scope(), &topic(), 1, TestBlobStore::default())
                .is_err()
        );
        for provider in [&mut relay, &mut wrong_topic] {
            let route = provider
                .verify_blob(&sealed.bytes)
                .expect("route-only verification");
            match provider
                .verify_blob_content(route, &sealed.bytes)
                .expect("route-only decision")
            {
                BlobContentVerification::RouteOnly(route) => {
                    assert_eq!(route.blob_id(), fixture.finished.id());
                }
                BlobContentVerification::ContentVerified { .. } => {
                    panic!("route-only provider minted Blob content capability")
                }
            }
        }
    }

    struct FailingSource {
        inner: Cursor<Vec<u8>>,
        yielded_partial_plaintext: bool,
    }

    impl Read for FailingSource {
        fn read(&mut self, output: &mut [u8]) -> io::Result<usize> {
            if self.yielded_partial_plaintext {
                return Err(io::Error::other("injected read failure"));
            }
            self.yielded_partial_plaintext = true;
            let count = output.len().min(5);
            self.inner.read(&mut output[..count])
        }
    }

    impl Seek for FailingSource {
        fn seek(&mut self, position: SeekFrom) -> io::Result<u64> {
            self.inner.seek(position)
        }
    }

    #[test]
    fn preparation_restores_source_position_after_io_error_and_redacts_digests() {
        fn assert_zeroize_on_drop<T: zeroize::ZeroizeOnDrop>() {}
        assert_zeroize_on_drop::<zeroize::Zeroizing<Vec<u8>>>();

        let mut source = FailingSource {
            inner: Cursor::new(vec![0x77; 10]),
            yielded_partial_plaintext: false,
        };
        source.seek(SeekFrom::Start(4)).expect("initial seek");
        let result = prepare_blob(
            &mut source,
            SELECTED_BLOB_CHUNK_SIZE,
            BlobMetadata::new(None, Vec::new()).expect("metadata"),
        );
        assert!(result.is_err());
        assert_eq!(source.stream_position().expect("restored position"), 4);

        let prepared = prepare_blob(
            &mut Cursor::new(b"debug-safe".to_vec()),
            SELECTED_BLOB_CHUNK_SIZE,
            BlobMetadata::new(None, Vec::new()).expect("metadata"),
        )
        .expect("preparation");
        let debug = format!("{prepared:?}");
        assert!(debug.contains("[REDACTED]"));
        assert!(!debug.contains("plaintext_sha256"));
    }
}
