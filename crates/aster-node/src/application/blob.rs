//! High-level stopped-state surface for immutable, source-authenticated Blobs.
//!
//! Blob plaintext crosses this boundary only through caller-owned streaming
//! readers and writers. Encrypted chunks remain in the mission-bound depot;
//! source-envelope bytes, manifest records, keys, nonces, and depot mechanics
//! are never returned to applications.

use std::{
    fmt, fs,
    io::{Read, Seek, Write},
    path::Path,
    sync::Arc,
};

use aster_mesh::{
    BlobContentVerification, BlobError, BlobId as CoreBlobId, BlobMetadata as CoreBlobMetadata,
    ContentVerifiedBlobEnvelope, NodeId, Priority, ReferenceEnvelopeSealer,
    SELECTED_BLOB_CHUNK_SIZE, Scope, Topic, prepare_blob,
};
pub use aster_redb_store::BlobDepotLimits;
use aster_redb_store::{
    BlobOperationKey, BlobOperationRequest, BlobPublicationDisposition, BlobPublicationIntent,
    BlobReadPlan, BlobSemanticId, BlobVariantId, ControlPolicySnapshot, ControlTransferId, Store,
    StoreLimits, StoredBlob,
};

use super::{ApplicationError, ApplicationErrorKind, application_error};
use crate::{
    mission::UnprotectedReferenceMission,
    runtime::{
        STORE_FILE, ensure_principal_active, ensure_state_accepts_normal_operation,
        open_replayed_verifier, refresh_application_policy,
    },
};

/// Stable selected-profile identity of immutable Blob bytes and identity metadata.
///
/// The selected profile fixes chunking at 64 KiB. Media type and schema bytes
/// are committed by this identity, so changing either produces another ID.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct BlobId([u8; 32]);

impl BlobId {
    /// Constructs an identity from its complete collision-resistant bytes.
    pub const fn from_bytes(bytes: [u8; 32]) -> Self {
        Self(bytes)
    }

    /// Returns the complete identity bytes.
    pub const fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }

    fn from_core(id: CoreBlobId) -> Self {
        Self(*id.as_bytes())
    }

    fn into_core(self) -> CoreBlobId {
        CoreBlobId::from_bytes(self.0)
    }
}

impl fmt::Display for BlobId {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        for byte in self.0 {
            write!(formatter, "{byte:02x}")?;
        }
        Ok(())
    }
}

/// One durable, operation-key-idempotent Blob publication request.
///
/// `source` is supplied separately to [`SelectedBlobNode::publish`] and must
/// remain byte-for-byte stable across its bounded hash and encryption passes.
/// Empty content is rejected by the selected Blob profile.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct BlobPublishRequest {
    pub operation_key: Vec<u8>,
    pub topic: Topic,
    pub scope: Scope,
    pub priority: Priority,
    pub media_type: Option<String>,
    pub schema_id: Vec<u8>,
}

/// Successful durable Blob publication without manifest or provider details.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct BlobPublishResult {
    pub id: BlobId,
    pub publisher: NodeId,
    pub publisher_counter: u64,
    pub priority: Priority,
    pub total_len: u64,
    pub media_type: Option<String>,
    pub schema_id: Vec<u8>,
    pub acceptance_marker: u64,
    /// True only when this call inserted a new signed publication.
    ///
    /// A different operation may insert another source publication while
    /// reusing the same immutable encrypted depot variant.
    pub inserted: bool,
}

/// Exact immutable-content lookup in one selected topic and scope.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct BlobReadRequest {
    pub id: BlobId,
    pub topic: Topic,
    pub scope: Scope,
}

/// Statistics and authenticated identity metadata from one complete Blob read.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct BlobReadResult {
    pub id: BlobId,
    pub publisher: NodeId,
    pub publisher_counter: u64,
    pub priority: Priority,
    pub total_len: u64,
    pub media_type: Option<String>,
    pub schema_id: Vec<u8>,
    pub acceptance_marker: u64,
    pub verified_chunks: u64,
    /// Peak buffer capacity reported by the core Blob streaming engine.
    ///
    /// Store adapters may concurrently hold additional independently bounded,
    /// chunk-sized buffers; this is not a whole-operation peak-memory measure.
    pub peak_working_buffer_bytes: usize,
}

/// Explicit admission limits for the selected Blob depot.
///
/// The byte cap covers marked committed chunk files (including their fixed
/// file headers) plus the incoming serialized file before its marker. Chunk
/// and variant caps count all durable chunk-metadata and import rows, including
/// unfinished staging; abandoned durable rows remain charged until a future
/// explicit garbage-collection design removes them. Unmarked temporary or
/// otherwise untracked filesystem allocation is outside these counters.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct SelectedBlobOptions {
    pub depot_limits: BlobDepotLimits,
}

struct VerifiedStoredBlob {
    blob: ContentVerifiedBlobEnvelope,
    manifest_bytes: Vec<u8>,
    semantic_id: BlobSemanticId,
    acceptance_marker: u64,
}

/// Exclusive stopped-state handle over selected immutable Blob content.
///
/// This owns the same process-exclusive mission-bound redb writer as Event,
/// State, Record, and the live runtime. Blob network reconciliation is absent
/// from this stopped local slice.
pub struct SelectedBlobNode {
    mission: UnprotectedReferenceMission,
    store: Arc<Store>,
    verifier: ReferenceEnvelopeSealer,
    verifier_head: Option<(u64, ControlTransferId)>,
}

impl SelectedBlobNode {
    /// Opens the explicitly unprotected reference provisioning path with
    /// conservative default depot limits.
    pub fn open_unprotected_reference(
        state: impl AsRef<Path>,
        mission_bundle: impl AsRef<Path>,
    ) -> Result<Self, ApplicationError> {
        Self::open_unprotected_reference_with_options(
            state,
            mission_bundle,
            SelectedBlobOptions::default(),
        )
    }

    /// Opens the stopped selected Blob surface with explicit physical limits.
    ///
    /// Terminal state is rejected before mission bytes are loaded. The exact
    /// store and depot are then mission-bound and process-locked, and every
    /// committed control is replayed before Blob operations become available.
    pub fn open_unprotected_reference_with_options(
        state: impl AsRef<Path>,
        mission_bundle: impl AsRef<Path>,
        options: SelectedBlobOptions,
    ) -> Result<Self, ApplicationError> {
        let state = state.as_ref();
        ensure_state_accepts_normal_operation(state)
            .map_err(|error| application_error("blob open", error))?;
        let mission = UnprotectedReferenceMission::load(mission_bundle)
            .map_err(|error| application_error("blob open", error.into()))?;
        fs::create_dir_all(state).map_err(|error| application_error("blob open", error.into()))?;
        let store = Store::open_with_limits_and_blob_depot_limits_for_mission(
            state.join(STORE_FILE),
            StoreLimits::default(),
            options.depot_limits,
            mission.mission_authority_id(),
        )
        .map_err(|error| application_error("blob open", error.into()))?;
        store
            .require_process_exclusive_lock()
            .map_err(|error| application_error("blob open", error.into()))?;
        let verifier = open_replayed_verifier(&store, &mission)
            .map_err(|error| application_error("blob open", error))?;
        ensure_principal_active(&store, verifier.identity())
            .map_err(|error| application_error("blob open", error))?;
        let verifier_head = store
            .control_head()
            .map_err(|error| application_error("blob open", error.into()))?;
        let mut selected = Self {
            mission,
            store: Arc::new(store),
            verifier,
            verifier_head,
        };
        selected.current_policy("blob open")?;
        Ok(selected)
    }

    /// Authenticated local Blob publisher identity.
    pub fn identity(&self) -> NodeId {
        self.verifier.identity()
    }

    /// Stable mission authority bound to provisioning, redb, and the depot.
    pub const fn mission_authority(&self) -> NodeId {
        self.mission.mission_authority_id()
    }

    /// Streams, encrypts, and durably publishes one immutable Blob.
    ///
    /// The first pass uses one bounded zeroizing plaintext-chunk buffer and,
    /// after it completes, retains only a manifest-bounded digest vector. The
    /// second pass commits independently authenticated 64 KiB encrypted chunks.
    /// A semantic publication becomes visible only after the complete depot
    /// variant, source envelope, and operation mapping commit atomically.
    pub fn publish<R: Read + Seek>(
        &mut self,
        request: BlobPublishRequest,
        source: &mut R,
    ) -> Result<BlobPublishResult, ApplicationError> {
        let BlobPublishRequest {
            operation_key,
            topic,
            scope,
            priority,
            media_type,
            schema_id,
        } = request;
        let operation = BlobOperationKey::new(operation_key)
            .map_err(|error| application_error("blob publish", error.into()))?;
        let metadata = CoreBlobMetadata::new(media_type, schema_id)
            .map_err(|error| blob_core_error("blob publish", error))?;
        let policy = self.current_policy("blob publish")?;
        let epoch = self.active_epoch(&scope, "blob publish")?;
        self.require_blob_grants(&topic, &scope, epoch, "blob publish")?;
        let prepared =
            prepare_blob(source, SELECTED_BLOB_CHUNK_SIZE, metadata).map_err(blob_prepare_error)?;
        if prepared.total_len() == 0 || prepared.chunk_count() == 0 {
            return Err(ApplicationError::new(
                ApplicationErrorKind::InvalidRequest,
                "blob publish",
            ));
        }
        let intent = BlobPublicationIntent::new(
            self.identity(),
            topic.clone(),
            scope.clone(),
            priority,
            prepared.id(),
        )
        .map_err(|error| application_error("blob publish", error.into()))?;
        let operation_request = BlobOperationRequest::new(&operation, &intent);

        if let Some(existing) = self
            .store
            .blob_for_operation_with_policy(&policy, &operation_request)
            .map_err(|error| application_error("blob publish", error.into()))?
        {
            let verified =
                self.verify_stored_blob(&existing, Some(&intent), epoch, "blob publish", true)?;
            return Ok(blob_publish_result(&verified, false));
        }

        let finished = {
            let depot = self
                .store
                .blob_depot()
                .map_err(|error| application_error("blob publish", error.into()))?;
            let mut service = self
                .verifier
                .blob_service_with_store(&scope, &topic, epoch, depot)
                .map_err(|error| application_error("blob publish", error.into()))?;
            let manifest = service
                .install_prepared(&prepared)
                .map_err(|error| blob_core_error("blob publish", error))?;
            let progress = service
                .encrypt_some(source, &manifest, prepared.chunk_count())
                .map_err(|error| blob_core_error("blob publish", error))?;
            if !progress.complete || progress.verified_chunks != prepared.chunk_count() {
                return Err(ApplicationError::new(
                    ApplicationErrorKind::Integrity,
                    "blob publish",
                ));
            }
            service
                .finish_manifest(&manifest)
                .map_err(|error| blob_core_error("blob publish", error))?
        };

        let reservation = self
            .store
            .reserve_blob_with_policy(&policy, self.identity(), &topic, &scope)
            .map_err(|error| application_error("blob publish", error.into()))?;
        let manifest_len = u64::try_from(finished.manifest_bytes().len()).map_err(|_| {
            ApplicationError::new(ApplicationErrorKind::ResourceLimit, "blob publish")
        })?;
        let header = reservation
            .header(priority, finished.route_commitment(), manifest_len, epoch)
            .map_err(|error| application_error("blob publish", error.into()))?;
        let sealed = self
            .verifier
            .seal_blob_manifest(&header, finished.manifest_bytes())
            .map_err(|error| application_error("blob publish", error.into()))?;
        let verified = self.open_blob(&sealed.bytes, "blob publish")?;
        if verified.blob.blob_id() != prepared.id()
            || verified.manifest_bytes != finished.manifest_bytes()
            || verified.blob.manifest_digest() != finished.manifest_digest()
        {
            return Err(ApplicationError::new(
                ApplicationErrorKind::Integrity,
                "blob publish",
            ));
        }
        let completion = self
            .store
            .blob_depot()
            .and_then(|mut depot| depot.completed_blob(&verified.blob, &verified.manifest_bytes))
            .map_err(|error| application_error("blob publish", error.into()))?;
        let outcome = self
            .store
            .commit_reserved_blob_once_with_policy(
                &policy,
                &operation_request,
                &reservation,
                &verified.blob,
                &sealed.bytes,
                &completion,
            )
            .map_err(|error| application_error("blob publish", error.into()))?;
        let stored =
            self.verify_stored_blob(outcome.blob(), Some(&intent), epoch, "blob publish", true)?;
        Ok(blob_publish_result(&stored, outcome.inserted()))
    }

    /// Streams one freshly source/content/depot-verified Blob into `output`.
    ///
    /// Every retained source publication for the requested content is freshly
    /// verified before a deterministic active publication is selected and the
    /// exact plan is rechecked. If a later chunk or final whole-content digest
    /// fails, `output` may already contain the independently verified prefix.
    pub fn read_into<W: Write>(
        &mut self,
        request: BlobReadRequest,
        output: &mut W,
    ) -> Result<BlobReadResult, ApplicationError> {
        let policy = self.current_policy("blob read")?;
        let epoch = self.active_epoch(&request.scope, "blob read")?;
        self.require_blob_grants(&request.topic, &request.scope, epoch, "blob read")?;
        let plan = self
            .store
            .prepare_blob_read_with_policy(
                &policy,
                &request.topic,
                &request.scope,
                request.id.into_core(),
            )
            .map_err(|error| application_error("blob read", error.into()))?;
        let selected = self.verify_read_plan(&plan, epoch)?;
        self.store
            .require_blob_read_plan_with_policy(&policy, &plan)
            .map_err(|error| application_error("blob read", error.into()))?;
        self.store
            .blob_depot()
            .and_then(|mut depot| depot.completed_blob(&selected.blob, &selected.manifest_bytes))
            .map_err(|error| application_error("blob read", error.into()))?;
        let mut service = self
            .verifier
            .blob_service_with_store(
                selected.blob.scope(),
                selected.blob.topic(),
                selected.blob.key_epoch(),
                self.store
                    .blob_depot()
                    .map_err(|error| application_error("blob read", error.into()))?,
            )
            .map_err(|error| application_error("blob read", error.into()))?;
        service
            .install_verified_manifest(&selected.blob, &selected.manifest_bytes)
            .map_err(|error| blob_core_error("blob read", error))?;
        let mut reader = service
            .reader_for_verified(&selected.blob)
            .map_err(|error| blob_core_error("blob read", error))?;
        let stats = reader
            .stream_into(output)
            .map_err(|error| blob_core_error("blob read", error))?;
        if stats.plaintext_bytes != selected.blob.manifest().total_len()
            || stats.verified_chunks != selected.blob.manifest().chunk_count()
        {
            return Err(ApplicationError::new(
                ApplicationErrorKind::Integrity,
                "blob read",
            ));
        }
        let metadata = selected.blob.manifest().metadata();
        Ok(BlobReadResult {
            id: BlobId::from_core(selected.blob.blob_id()),
            publisher: selected.blob.publisher(),
            publisher_counter: selected.blob.dot().counter,
            priority: selected.blob.priority(),
            total_len: selected.blob.manifest().total_len(),
            media_type: metadata.media_type().map(str::to_owned),
            schema_id: metadata.schema_id().to_vec(),
            acceptance_marker: selected.acceptance_marker,
            verified_chunks: stats.verified_chunks,
            peak_working_buffer_bytes: stats.peak_working_buffer_bytes,
        })
    }

    fn verify_read_plan(
        &mut self,
        plan: &BlobReadPlan,
        current_epoch: u64,
    ) -> Result<VerifiedStoredBlob, ApplicationError> {
        let mut active = Vec::with_capacity(plan.candidates().len());
        let mut selected: Option<VerifiedStoredBlob> = None;
        for candidate in plan.candidates() {
            let verified =
                self.verify_stored_blob(candidate.blob(), None, current_epoch, "blob read", false)?;
            Self::require_blob_plan_claims(plan, &verified)?;
            let revoked = self
                .store
                .is_control_principal_revoked(verified.blob.publisher())
                .map_err(|error| application_error("blob read", error.into()))?;
            let is_active = !revoked && verified.blob.key_epoch() == current_epoch;
            active.push(is_active);
            if is_active
                && selected
                    .as_ref()
                    .is_none_or(|current| verified.semantic_id > current.semantic_id)
            {
                selected = Some(verified);
            }
        }
        let selected_id = selected.as_ref().map(|selected| selected.semantic_id);
        for (candidate, active) in plan.candidates().iter().zip(active) {
            let expected = if !active {
                None
            } else if Some(candidate.blob().semantic_id) == selected_id {
                Some(BlobPublicationDisposition::Current)
            } else {
                Some(BlobPublicationDisposition::Alternate)
            };
            if candidate.disposition() != expected {
                return Err(ApplicationError::new(
                    ApplicationErrorKind::Integrity,
                    "blob read",
                ));
            }
        }
        let selected = selected.ok_or_else(|| {
            ApplicationError::new(ApplicationErrorKind::UnauthorizedOrRevoked, "blob read")
        })?;
        if plan.current().map(|candidate| candidate.blob().semantic_id)
            != Some(selected.semantic_id)
        {
            return Err(ApplicationError::new(
                ApplicationErrorKind::Integrity,
                "blob read",
            ));
        }
        Ok(selected)
    }

    fn require_blob_plan_claims(
        plan: &BlobReadPlan,
        verified: &VerifiedStoredBlob,
    ) -> Result<(), ApplicationError> {
        if verified.blob.topic() != plan.topic()
            || verified.blob.scope() != plan.scope()
            || verified.blob.blob_id() != plan.blob_id()
        {
            return Err(ApplicationError::new(
                ApplicationErrorKind::Integrity,
                "blob read",
            ));
        }
        Ok(())
    }

    fn verify_stored_blob(
        &mut self,
        stored: &StoredBlob,
        expected: Option<&BlobPublicationIntent>,
        current_epoch: u64,
        operation: &'static str,
        verify_completion: bool,
    ) -> Result<VerifiedStoredBlob, ApplicationError> {
        let route = self
            .verifier
            .verify_blob(&stored.sealed)
            .map_err(|error| application_error(operation, error.into()))?;
        if route.envelope_id() != *stored.transfer_id.as_bytes()
            || route.item_id() != *stored.semantic_id.as_bytes()
            || route.header() != &stored.header
            || route.blob_id() != stored.blob_id
            || route.mission_authority_id() != self.mission_authority()
            || route.key_epoch() > current_epoch
        {
            return Err(ApplicationError::new(
                ApplicationErrorKind::Integrity,
                operation,
            ));
        }
        if let Some(expected) = expected
            && (route.publisher() != expected.publisher()
                || route.topic() != expected.topic()
                || route.scope() != expected.scope()
                || route.priority() != expected.priority()
                || route.blob_id() != expected.blob_id())
        {
            return Err(ApplicationError::new(
                ApplicationErrorKind::Integrity,
                operation,
            ));
        }
        if !self
            .verifier
            .can_route_blob(route.scope(), route.key_epoch())
            || !self
                .verifier
                .can_open_blob_content(route.scope(), route.topic(), route.key_epoch())
        {
            return Err(ApplicationError::new(
                ApplicationErrorKind::Integrity,
                operation,
            ));
        }
        let (blob, manifest_bytes) = match self
            .verifier
            .verify_blob_content(route, &stored.sealed)
            .map_err(|error| application_error(operation, error.into()))?
        {
            BlobContentVerification::ContentVerified {
                blob,
                manifest_bytes,
            } => (blob, manifest_bytes),
            BlobContentVerification::RouteOnly(_) => {
                return Err(ApplicationError::new(
                    ApplicationErrorKind::Integrity,
                    operation,
                ));
            }
        };
        if blob.blob_id() != stored.blob_id
            || stored.variant_id
                != BlobVariantId::for_content(
                    blob.blob_id(),
                    blob.manifest().content_group(),
                    blob.manifest().content_epoch(),
                )
            || blob.manifest_digest() != &stored.manifest_digest
            || blob.manifest().total_len() == 0
            || blob.manifest().chunk_size() != SELECTED_BLOB_CHUNK_SIZE
        {
            return Err(ApplicationError::new(
                ApplicationErrorKind::Integrity,
                operation,
            ));
        }
        blob.verify_exact_manifest(&manifest_bytes)
            .map_err(|error| application_error(operation, error.into()))?;
        if verify_completion {
            self.store
                .blob_depot()
                .and_then(|mut depot| depot.completed_blob(&blob, &manifest_bytes))
                .map_err(|error| application_error(operation, error.into()))?;
        }
        Ok(VerifiedStoredBlob {
            blob,
            manifest_bytes,
            semantic_id: stored.semantic_id,
            acceptance_marker: stored.acceptance_marker,
        })
    }

    fn active_epoch(
        &self,
        scope: &Scope,
        operation: &'static str,
    ) -> Result<u64, ApplicationError> {
        self.store
            .active_scope_epoch(scope)
            .map(|epoch| epoch.map_or(1, |(epoch, _)| epoch))
            .map_err(|error| application_error(operation, error.into()))
    }

    fn require_blob_grants(
        &self,
        topic: &Topic,
        scope: &Scope,
        epoch: u64,
        operation: &'static str,
    ) -> Result<(), ApplicationError> {
        if self.verifier.can_route_blob(scope, epoch)
            && self.verifier.can_open_blob_content(scope, topic, epoch)
        {
            Ok(())
        } else {
            Err(ApplicationError::new(
                ApplicationErrorKind::RequestRejected,
                operation,
            ))
        }
    }

    fn current_policy(
        &mut self,
        operation: &'static str,
    ) -> Result<ControlPolicySnapshot, ApplicationError> {
        match refresh_application_policy(
            &self.store,
            &self.mission,
            &mut self.verifier,
            &mut self.verifier_head,
        ) {
            Ok(Some(policy)) => Ok(policy),
            Ok(None) => Err(ApplicationError::new(
                ApplicationErrorKind::PolicyUnsettled,
                operation,
            )),
            Err(error) => Err(application_error(operation, error)),
        }
    }

    fn open_blob(
        &mut self,
        sealed: &[u8],
        operation: &'static str,
    ) -> Result<VerifiedStoredBlob, ApplicationError> {
        let route = self
            .verifier
            .verify_blob(sealed)
            .map_err(|error| application_error(operation, error.into()))?;
        match self
            .verifier
            .verify_blob_content(route, sealed)
            .map_err(|error| application_error(operation, error.into()))?
        {
            BlobContentVerification::ContentVerified {
                blob,
                manifest_bytes,
            } => Ok(VerifiedStoredBlob {
                semantic_id: BlobSemanticId::new(blob.item_id()),
                acceptance_marker: 0,
                blob,
                manifest_bytes,
            }),
            BlobContentVerification::RouteOnly(_) => Err(ApplicationError::new(
                ApplicationErrorKind::RequestRejected,
                operation,
            )),
        }
    }
}

fn blob_publish_result(blob: &VerifiedStoredBlob, inserted: bool) -> BlobPublishResult {
    let metadata = blob.blob.manifest().metadata();
    BlobPublishResult {
        id: BlobId::from_core(blob.blob.blob_id()),
        publisher: blob.blob.publisher(),
        publisher_counter: blob.blob.dot().counter,
        priority: blob.blob.priority(),
        total_len: blob.blob.manifest().total_len(),
        media_type: metadata.media_type().map(str::to_owned),
        schema_id: metadata.schema_id().to_vec(),
        acceptance_marker: blob.acceptance_marker,
        inserted,
    }
}

fn blob_prepare_error(error: BlobError) -> ApplicationError {
    match error {
        BlobError::InvalidManifest => {
            ApplicationError::new(ApplicationErrorKind::ResourceLimit, "blob publish")
        }
        error => blob_core_error("blob publish", error),
    }
}

fn blob_core_error(operation: &'static str, error: BlobError) -> ApplicationError {
    // The generic service deliberately erases its adapter's exact failure kind.
    // Never infer a quota from that opaque category; typed direct store calls
    // retain their precise resource, availability, and policy classifications.
    let kind = match error {
        BlobError::InvalidChunkSize | BlobError::InvalidMetadata | BlobError::WorkLimitZero => {
            ApplicationErrorKind::InvalidRequest
        }
        BlobError::LengthOverflow => ApplicationErrorKind::ResourceLimit,
        BlobError::SourceChanged => ApplicationErrorKind::Conflict,
        BlobError::Io(_) => ApplicationErrorKind::StateUnavailable,
        BlobError::Store(_) => ApplicationErrorKind::Integrity,
        BlobError::InvalidManifest
        | BlobError::InvalidChunkIndex
        | BlobError::MissingChunk
        | BlobError::AuthenticationFailed => ApplicationErrorKind::Integrity,
    };
    ApplicationError::new(kind, operation)
}

#[cfg(test)]
mod tests {
    use std::{
        fs,
        io::Cursor,
        path::{Path, PathBuf},
        sync::atomic::{AtomicU64, Ordering},
    };

    #[cfg(unix)]
    use std::time::Duration;

    use aster_mesh::{
        ProvisioningAccess, ReferenceEnvelopeSealer, ReferenceProvisioner, ScopeRekeyRecipient,
    };

    use super::*;
    use crate::application::SelectedEventNode;

    static NEXT_ROOT: AtomicU64 = AtomicU64::new(0);

    struct TestRoot(PathBuf);

    impl TestRoot {
        fn new(label: &str) -> Self {
            let sequence = NEXT_ROOT.fetch_add(1, Ordering::Relaxed);
            let path = std::env::temp_dir().join(format!(
                "aster-selected-blob-{}-{sequence}-{label}",
                std::process::id()
            ));
            fs::create_dir(&path).expect("create Blob test root");
            Self(path)
        }

        fn path(&self) -> &Path {
            &self.0
        }

        fn mission_path(&self) -> PathBuf {
            self.path().join("mission.unprotected-reference.bundle")
        }

        fn depot_path(&self) -> PathBuf {
            self.path().join("blob-depot-v1")
        }
    }

    impl Drop for TestRoot {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.0);
        }
    }

    fn blob_topic() -> Topic {
        Topic::new("ops.blob").expect("Blob topic")
    }

    fn blob_scope() -> Scope {
        Scope::new("mission/apps").expect("Blob scope")
    }

    fn persist_member_mission(root: &TestRoot) {
        let access = ProvisioningAccess::member(blob_scope(), vec![1], vec![blob_topic()])
            .expect("member access");
        let mut provisioner = ReferenceProvisioner::from_seed([0xb1; 32]).expect("provisioner");
        let bytes = provisioner
            .issue_node(1, &[access])
            .expect("issue node")
            .to_bytes()
            .expect("encode mission");
        drop(
            UnprotectedReferenceMission::persist(root.mission_path(), bytes)
                .expect("persist mission"),
        );
    }

    fn persist_relay_mission(root: &TestRoot) {
        let access = ProvisioningAccess::relay(blob_scope(), vec![1]).expect("relay access");
        let mut provisioner = ReferenceProvisioner::from_seed([0xb2; 32]).expect("provisioner");
        let bytes = provisioner
            .issue_node(1, &[access])
            .expect("issue relay")
            .to_bytes()
            .expect("encode relay mission");
        drop(
            UnprotectedReferenceMission::persist(root.mission_path(), bytes)
                .expect("persist relay mission"),
        );
    }

    fn persist_future_only_mission(root: &TestRoot) {
        let access = ProvisioningAccess::member(blob_scope(), vec![2], vec![blob_topic()])
            .expect("future-only member access");
        let mut provisioner = ReferenceProvisioner::from_seed([0xb4; 32]).expect("provisioner");
        let bytes = provisioner
            .issue_node(1, &[access])
            .expect("issue future-only node")
            .to_bytes()
            .expect("encode future-only mission");
        drop(
            UnprotectedReferenceMission::persist(root.mission_path(), bytes)
                .expect("persist future-only mission"),
        );
    }

    struct RekeyServices {
        control_authority: ReferenceEnvelopeSealer,
        reader: ReferenceEnvelopeSealer,
        registry: Vec<u8>,
        selected_identity: NodeId,
        mission_authority: NodeId,
    }

    fn persist_rekey_mission(root: &TestRoot) -> RekeyServices {
        let access = ProvisioningAccess::member(blob_scope(), vec![1], vec![blob_topic()])
            .expect("member access");
        let mut provisioner = ReferenceProvisioner::from_seed([0xb3; 32]).expect("provisioner");
        let control_authority = provisioner
            .issue_control_authority(60, std::slice::from_ref(&access))
            .and_then(ReferenceEnvelopeSealer::open)
            .expect("control authority");
        let reader = provisioner
            .issue_node(51, std::slice::from_ref(&access))
            .and_then(ReferenceEnvelopeSealer::open)
            .expect("control reader");
        let selected_bundle = provisioner
            .issue_node(52, std::slice::from_ref(&access))
            .expect("selected node bundle");
        let selected_bytes = selected_bundle
            .to_bytes()
            .expect("encode selected node bundle");
        let selected_mission = UnprotectedReferenceMission::from_bytes(selected_bytes.clone())
            .expect("parse selected mission");
        let selected_identity = ReferenceEnvelopeSealer::open(
            selected_mission
                .fresh_bundle()
                .expect("fresh selected bundle"),
        )
        .expect("open selected identity")
        .identity();
        let registry = provisioner.export_rekey_registry().expect("rekey registry");
        drop(
            UnprotectedReferenceMission::persist(root.mission_path(), selected_bytes)
                .expect("persist selected mission"),
        );
        RekeyServices {
            mission_authority: control_authority.mission_authority_id(),
            control_authority,
            reader,
            registry,
            selected_identity,
        }
    }

    fn apply_epoch_two_rekey(root: &TestRoot, services: &mut RekeyServices) {
        let recipients = vec![
            ScopeRekeyRecipient::member(services.control_authority.identity(), vec![blob_topic()])
                .expect("authority recipient"),
            ScopeRekeyRecipient::member(services.reader.identity(), vec![blob_topic()])
                .expect("reader recipient"),
            ScopeRekeyRecipient::member(services.selected_identity, vec![blob_topic()])
                .expect("selected recipient"),
        ];
        let (sealed, _) = services
            .control_authority
            .seal_chained_scope_rekey_control_from_registry(
                &services.registry,
                0,
                blob_scope(),
                2,
                recipients,
                1,
                None,
            )
            .expect("seal epoch-two rekey");
        let verified = services
            .reader
            .verify_control(&sealed)
            .expect("verify epoch-two rekey");
        let store =
            Store::open_for_mission(root.path().join(STORE_FILE), services.mission_authority)
                .expect("open Blob store for rekey");
        let outcome = store
            .ingest_verified_control(&verified, &sealed)
            .expect("commit epoch-two rekey");
        assert_eq!(outcome.activated().len(), 1);
        assert_eq!(
            store
                .active_scope_epoch(&blob_scope())
                .expect("active epoch")
                .map(|(epoch, _)| epoch),
            Some(2)
        );
    }

    fn selected_node(root: &TestRoot) -> SelectedBlobNode {
        if !root.mission_path().exists() {
            persist_member_mission(root);
        }
        SelectedBlobNode::open_unprotected_reference(root.path(), root.mission_path())
            .expect("open selected Blob node")
    }

    fn request(operation: &[u8]) -> BlobPublishRequest {
        BlobPublishRequest {
            operation_key: operation.to_vec(),
            topic: blob_topic(),
            scope: blob_scope(),
            priority: Priority::Priority,
            media_type: Some("application/x-aster-test".into()),
            schema_id: b"schema/blob-v1".to_vec(),
        }
    }

    fn payload(length: usize) -> Vec<u8> {
        (0..length).map(|index| (index % 251) as u8).collect()
    }

    #[test]
    fn blob_publish_retry_change_conflict_dedup_read_and_reopen_are_stable() {
        let root = TestRoot::new("lifecycle");
        let bytes = payload(4 * SELECTED_BLOB_CHUNK_SIZE as usize + 317);
        let first_request = request(b"blob/lifecycle/first");
        let (first, second, first_stats) = {
            let mut node = selected_node(&root);
            let first = node
                .publish(first_request.clone(), &mut Cursor::new(bytes.clone()))
                .expect("publish first Blob");
            assert!(first.inserted);
            assert_eq!(first.total_len, bytes.len() as u64);
            assert_eq!(first.publisher_counter, 1);
            assert_eq!(
                first.media_type.as_deref(),
                Some("application/x-aster-test")
            );
            assert_eq!(first.schema_id, b"schema/blob-v1");
            let first_stats = node.store.blob_stats().expect("first Blob stats");
            assert_eq!(first_stats.publications, 1);
            assert_eq!(first_stats.variants, 1);
            assert_eq!(first_stats.finalized_variants, 1);
            assert_eq!(first_stats.committed_chunks, 5);

            let replay = node
                .publish(first_request.clone(), &mut Cursor::new(bytes.clone()))
                .expect("exact retry");
            assert!(!replay.inserted);
            assert_eq!(
                replay,
                BlobPublishResult {
                    inserted: false,
                    ..first.clone()
                }
            );
            assert_eq!(node.store.blob_stats().expect("retry stats"), first_stats);

            let changed = payload(bytes.len() + 1);
            let conflict = node
                .publish(first_request.clone(), &mut Cursor::new(changed))
                .expect_err("changed source must conflict before depot install");
            assert_eq!(conflict.kind(), ApplicationErrorKind::Conflict);
            assert_eq!(
                node.store.blob_stats().expect("conflict stats"),
                first_stats
            );

            let mut changed_metadata = first_request.clone();
            changed_metadata.media_type = Some("application/x-changed".into());
            let conflict = node
                .publish(changed_metadata, &mut Cursor::new(bytes.clone()))
                .expect_err("changed identity metadata under one operation must conflict");
            assert_eq!(conflict.kind(), ApplicationErrorKind::Conflict);
            assert_eq!(
                node.store.blob_stats().expect("metadata conflict stats"),
                first_stats
            );

            let stale_policy = node.current_policy("blob stale plan").expect("policy");
            let stale_plan = node
                .store
                .prepare_blob_read_with_policy(
                    &stale_policy,
                    &blob_topic(),
                    &blob_scope(),
                    first.id.into_core(),
                )
                .expect("single-publication read plan");
            let mut second_request = request(b"blob/lifecycle/second-publication");
            second_request.priority = Priority::Flash;
            let second = node
                .publish(second_request, &mut Cursor::new(bytes.clone()))
                .expect("publish another source envelope over same content");
            assert!(second.inserted);
            assert_eq!(second.id, first.id);
            assert_eq!(second.publisher_counter, 2);
            assert_eq!(second.priority, Priority::Flash);
            let second_stats = node.store.blob_stats().expect("dedup stats");
            assert_eq!(second_stats.publications, 2);
            assert_eq!(second_stats.variants, first_stats.variants);
            assert_eq!(second_stats.committed_chunks, first_stats.committed_chunks);
            assert_eq!(
                second_stats.committed_file_bytes,
                first_stats.committed_file_bytes
            );
            let drift = node
                .store
                .require_blob_read_plan_with_policy(&stale_policy, &stale_plan)
                .expect_err("new signed publication must invalidate the exact read plan");
            assert_eq!(
                application_error("blob read", drift.into()).kind(),
                ApplicationErrorKind::PolicyUnsettled
            );

            let mut output = Vec::new();
            let read = node
                .read_into(
                    BlobReadRequest {
                        id: first.id,
                        topic: blob_topic(),
                        scope: blob_scope(),
                    },
                    &mut output,
                )
                .expect("stream selected Blob");
            assert_eq!(output, bytes);
            assert_eq!(read.id, first.id);
            assert_eq!(read.total_len, bytes.len() as u64);
            assert_eq!(read.verified_chunks, 5);
            assert!(
                read.peak_working_buffer_bytes <= SELECTED_BLOB_CHUNK_SIZE as usize + 16,
                "core Blob reader exceeded its chunk-sized buffer bound"
            );
            assert_eq!(read.media_type, first.media_type);
            assert_eq!(read.schema_id, first.schema_id);
            let policy = node.current_policy("blob test plan").expect("policy");
            let plan = node
                .store
                .prepare_blob_read_with_policy(
                    &policy,
                    &blob_topic(),
                    &blob_scope(),
                    first.id.into_core(),
                )
                .expect("read plan");
            let current = plan.current().expect("deterministic active publication");
            assert_eq!(
                read.publisher_counter,
                current.blob().header.stamp.dot.counter
            );
            (first, second, first_stats)
        };

        let mut reopened = selected_node(&root);
        let replay = reopened
            .publish(first_request, &mut Cursor::new(bytes.clone()))
            .expect("restart-stable exact retry");
        assert!(!replay.inserted);
        assert_eq!(replay.id, first.id);
        assert_eq!(replay.publisher, first.publisher);
        assert_eq!(replay.publisher_counter, first.publisher_counter);
        assert_eq!(replay.acceptance_marker, first.acceptance_marker);
        let reopened_stats = reopened.store.blob_stats().expect("reopened stats");
        assert_eq!(reopened_stats.publications, 2);
        assert_eq!(reopened_stats.variants, first_stats.variants);
        assert_eq!(
            reopened_stats.committed_chunks,
            first_stats.committed_chunks
        );
        assert_eq!(
            reopened_stats.committed_file_bytes,
            first_stats.committed_file_bytes
        );
        assert_eq!(second.id, replay.id);
    }

    #[test]
    fn blob_invalid_empty_metadata_operation_and_route_only_requests_fail_closed() {
        let root = TestRoot::new("invalid");
        let mut node = selected_node(&root);
        let empty = node
            .publish(request(b"blob/empty"), &mut Cursor::new(Vec::new()))
            .expect_err("empty selected Blob");
        assert_eq!(empty.kind(), ApplicationErrorKind::InvalidRequest);

        let mut invalid_metadata = request(b"blob/metadata");
        invalid_metadata.media_type = Some(String::new());
        let metadata = node
            .publish(invalid_metadata, &mut Cursor::new(vec![1]))
            .expect_err("empty media type");
        assert_eq!(metadata.kind(), ApplicationErrorKind::InvalidRequest);

        let mut invalid_operation = request(&vec![0x41; 257]);
        invalid_operation.operation_key = vec![0x41; 257];
        let operation = node
            .publish(invalid_operation, &mut Cursor::new(vec![1]))
            .expect_err("oversized operation key");
        assert_eq!(operation.kind(), ApplicationErrorKind::InvalidRequest);

        let mut wrong_topic = request(b"blob/wrong-topic");
        wrong_topic.topic = Topic::new("ops.not-granted").expect("wrong topic");
        let denied = node
            .publish(wrong_topic, &mut Cursor::new(vec![1, 2, 3]))
            .expect_err("ungranted topic");
        assert_eq!(denied.kind(), ApplicationErrorKind::RequestRejected);
        assert_eq!(node.store.blob_stats().expect("empty stats").variants, 0);
        drop(node);

        let relay_root = TestRoot::new("route-only");
        persist_relay_mission(&relay_root);
        let mut relay = SelectedBlobNode::open_unprotected_reference(
            relay_root.path(),
            relay_root.mission_path(),
        )
        .expect("open route-only selected node");
        let denied = relay
            .publish(request(b"blob/route-only"), &mut Cursor::new(vec![1, 2, 3]))
            .expect_err("route-only node cannot publish plaintext");
        assert_eq!(denied.kind(), ApplicationErrorKind::RequestRejected);

        let future_root = TestRoot::new("future-only");
        persist_future_only_mission(&future_root);
        let mut future = SelectedBlobNode::open_unprotected_reference(
            future_root.path(),
            future_root.mission_path(),
        )
        .expect("open future-only selected node");
        let denied = future
            .publish(
                request(b"blob/future-only"),
                &mut Cursor::new(vec![1, 2, 3]),
            )
            .expect_err("future epoch key is not current authority");
        assert_eq!(denied.kind(), ApplicationErrorKind::RequestRejected);
        assert_eq!(
            future
                .store
                .blob_stats()
                .expect("future-only stats")
                .variants,
            0
        );

        let erased_adapter = blob_core_error(
            "blob publish",
            BlobError::Store("provider-sanitized adapter failure".into()),
        );
        assert_eq!(erased_adapter.kind(), ApplicationErrorKind::Integrity);
        assert_eq!(
            blob_prepare_error(BlobError::InvalidManifest).kind(),
            ApplicationErrorKind::ResourceLimit
        );
        assert_eq!(
            blob_core_error("blob publish", BlobError::InvalidManifest).kind(),
            ApplicationErrorKind::Integrity
        );
    }

    #[test]
    fn blob_chunk_tamper_fails_stream_and_reopen_and_writer_lock_is_shared() {
        let root = TestRoot::new("tamper");
        let bytes = payload(SELECTED_BLOB_CHUNK_SIZE as usize + 23);
        let mut node = selected_node(&root);
        let published = node
            .publish(request(b"blob/tamper"), &mut Cursor::new(bytes))
            .expect("publish tamper fixture");
        let locked =
            match SelectedEventNode::open_unprotected_reference(root.path(), root.mission_path()) {
                Ok(_) => panic!("Blob handle must own the shared writer lock"),
                Err(error) => error,
            };
        assert_eq!(locked.kind(), ApplicationErrorKind::StateUnavailable);

        let chunk = first_chunk_file(&root.depot_path());
        let mut ciphertext = fs::read(&chunk).expect("read committed chunk file");
        let last = ciphertext.last_mut().expect("nonempty chunk file");
        *last ^= 0x80;
        fs::write(&chunk, ciphertext).expect("tamper committed chunk file");
        let mut output = Vec::new();
        let error = node
            .read_into(
                BlobReadRequest {
                    id: published.id,
                    topic: blob_topic(),
                    scope: blob_scope(),
                },
                &mut output,
            )
            .expect_err("tampered depot must not stream successfully");
        assert_eq!(error.kind(), ApplicationErrorKind::Integrity);
        drop(node);

        let reopen =
            match SelectedBlobNode::open_unprotected_reference(root.path(), root.mission_path()) {
                Ok(_) => panic!("marked corrupt depot must fail closed on reopen"),
                Err(error) => error,
            };
        assert_eq!(reopen.kind(), ApplicationErrorKind::Integrity);
    }

    #[test]
    fn blob_rekey_retries_old_operation_without_install_then_new_operation_gets_new_variant() {
        let root = TestRoot::new("rekey");
        let mut services = persist_rekey_mission(&root);
        let bytes = payload(SELECTED_BLOB_CHUNK_SIZE as usize + 73);
        let old_request = request(b"blob/rekey/old-operation");
        let first = {
            let mut node =
                SelectedBlobNode::open_unprotected_reference(root.path(), root.mission_path())
                    .expect("open epoch-one Blob node");
            node.publish(old_request.clone(), &mut Cursor::new(bytes.clone()))
                .expect("publish epoch-one Blob")
        };
        let before_rekey =
            Store::open_for_mission(root.path().join(STORE_FILE), services.mission_authority)
                .expect("inspect epoch-one store")
                .blob_stats()
                .expect("epoch-one stats");
        assert_eq!(before_rekey.variants, 1);
        assert_eq!(before_rekey.committed_chunks, 2);

        apply_epoch_two_rekey(&root, &mut services);
        let mut node =
            SelectedBlobNode::open_unprotected_reference(root.path(), root.mission_path())
                .expect("open epoch-two Blob node");
        let replay = node
            .publish(old_request, &mut Cursor::new(bytes.clone()))
            .expect("authorized historical operation retry");
        assert!(!replay.inserted);
        assert_eq!(replay.id, first.id);
        assert_eq!(replay.publisher_counter, first.publisher_counter);
        assert_eq!(replay.acceptance_marker, first.acceptance_marker);
        assert_eq!(
            node.store.blob_stats().expect("post-retry stats"),
            before_rekey
        );

        let inactive = node
            .read_into(
                BlobReadRequest {
                    id: first.id,
                    topic: blob_topic(),
                    scope: blob_scope(),
                },
                &mut Vec::new(),
            )
            .expect_err("epoch-one-only publication is inactive after rekey");
        assert_eq!(inactive.kind(), ApplicationErrorKind::UnauthorizedOrRevoked);

        let current = node
            .publish(
                request(b"blob/rekey/current-operation"),
                &mut Cursor::new(bytes.clone()),
            )
            .expect("publish current-epoch source envelope");
        assert!(current.inserted);
        assert_eq!(current.id, first.id);
        let current_stats = node.store.blob_stats().expect("epoch-two stats");
        assert_eq!(current_stats.publications, 2);
        assert_eq!(current_stats.variants, 2);
        assert_eq!(current_stats.committed_chunks, 4);

        let mut output = Vec::new();
        let read = node
            .read_into(
                BlobReadRequest {
                    id: first.id,
                    topic: blob_topic(),
                    scope: blob_scope(),
                },
                &mut output,
            )
            .expect("read current-epoch Blob");
        assert_eq!(output, bytes);
        assert_eq!(read.publisher_counter, current.publisher_counter);

        let policy = node
            .current_policy("blob inactive candidate")
            .expect("policy");
        let plan = node
            .store
            .prepare_blob_read_with_policy(
                &policy,
                &blob_topic(),
                &blob_scope(),
                first.id.into_core(),
            )
            .expect("mixed-epoch read plan");
        let mut tampered = plan
            .candidates()
            .iter()
            .find(|candidate| candidate.disposition().is_none())
            .expect("inactive epoch-one source publication")
            .blob()
            .clone();
        *tampered
            .sealed
            .last_mut()
            .expect("nonempty inactive source envelope") ^= 0x40;
        let error = match node.verify_stored_blob(&tampered, None, 2, "blob read", false) {
            Ok(_) => panic!("tampered inactive candidate passed fresh source verification"),
            Err(error) => error,
        };
        assert_eq!(error.kind(), ApplicationErrorKind::Integrity);
    }

    #[test]
    fn blob_verified_candidate_must_match_every_exact_read_plan_claim() {
        let root = TestRoot::new("plan-claims");
        let mut node = selected_node(&root);
        let first = node
            .publish(
                request(b"blob/plan-claims/first"),
                &mut Cursor::new(vec![1, 2, 3]),
            )
            .expect("publish first plan fixture");
        let second = node
            .publish(
                request(b"blob/plan-claims/second"),
                &mut Cursor::new(vec![4, 5, 6]),
            )
            .expect("publish mismatched plan fixture");
        assert_ne!(first.id, second.id);

        let policy = node.current_policy("blob plan claims").expect("policy");
        let plan = node
            .store
            .prepare_blob_read_with_policy(
                &policy,
                &blob_topic(),
                &blob_scope(),
                first.id.into_core(),
            )
            .expect("first Blob read plan");
        let mismatched = node
            .store
            .blob_inventory()
            .expect("Blob inventory")
            .into_iter()
            .find_map(|transfer| {
                node.store
                    .get_blob(transfer)
                    .expect("load Blob publication")
                    .filter(|stored| stored.blob_id == second.id.into_core())
            })
            .expect("second Blob publication");
        let mut wrong_variant = mismatched.clone();
        let mut variant_bytes = *wrong_variant.variant_id.as_bytes();
        variant_bytes[0] ^= 0x80;
        wrong_variant.variant_id = BlobVariantId::from_bytes(variant_bytes);
        assert_ne!(wrong_variant.variant_id, mismatched.variant_id);
        let error = match node.verify_stored_blob(&wrong_variant, None, 1, "blob read", false) {
            Ok(_) => panic!("persisted variant identity escaped authenticated content binding"),
            Err(error) => error,
        };
        assert_eq!(error.kind(), ApplicationErrorKind::Integrity);
        let verified = node
            .verify_stored_blob(&mismatched, None, 1, "blob read", false)
            .expect("freshly verify source-valid mismatched candidate");
        let error = SelectedBlobNode::require_blob_plan_claims(&plan, &verified)
            .expect_err("source-valid wrong-key candidate must not enter plan authority");
        assert_eq!(error.kind(), ApplicationErrorKind::Integrity);
    }

    #[test]
    fn blob_publisher_revocation_closes_retained_and_reopened_facades() {
        let root = TestRoot::new("revocation");
        let mut services = persist_rekey_mission(&root);
        let mut node =
            SelectedBlobNode::open_unprotected_reference(root.path(), root.mission_path())
                .expect("open pre-revocation Blob node");
        let published = node
            .publish(request(b"blob/revocation"), &mut Cursor::new(vec![1, 2, 3]))
            .expect("publish before revocation");
        let sealed = services
            .control_authority
            .seal_chained_revocation_control(services.selected_identity, 1, 1, None)
            .expect("seal selected publisher revocation");
        let verified = services
            .reader
            .verify_control(&sealed)
            .expect("verify selected publisher revocation");
        let outcome = node
            .store
            .ingest_verified_control(&verified, &sealed)
            .expect("commit selected publisher revocation");
        assert_eq!(outcome.activated().len(), 1);

        let error = node
            .read_into(
                BlobReadRequest {
                    id: published.id,
                    topic: blob_topic(),
                    scope: blob_scope(),
                },
                &mut Vec::new(),
            )
            .expect_err("retained facade must refresh durable revocation");
        assert_eq!(error.kind(), ApplicationErrorKind::UnauthorizedOrRevoked);
        drop(node);

        let error =
            match SelectedBlobNode::open_unprotected_reference(root.path(), root.mission_path()) {
                Ok(_) => panic!("revoked publisher facade reopened"),
                Err(error) => error,
            };
        assert_eq!(error.kind(), ApplicationErrorKind::UnauthorizedOrRevoked);
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn blob_terminal_zeroization_prevents_facade_reopen() {
        let root = TestRoot::new("terminal");
        drop(crate::NodeIdentity::load_or_create(root.path()).expect("create carrier identity"));
        let mut node = selected_node(&root);
        node.publish(request(b"blob/terminal"), &mut Cursor::new(vec![1, 2, 3]))
            .expect("publish before terminal zeroization");
        drop(node);

        let receipt =
            crate::zeroize_node(root.path(), &root.mission_path(), Duration::from_secs(2))
                .await
                .expect("zeroize stopped Blob state");
        assert!(receipt.mission_destroyed && receipt.identity_destroyed);
        let error =
            match SelectedBlobNode::open_unprotected_reference(root.path(), root.mission_path()) {
                Ok(_) => panic!("terminal Blob state reopened"),
                Err(error) => error,
            };
        assert_eq!(error.kind(), ApplicationErrorKind::StateUnavailable);
    }

    fn first_chunk_file(depot: &Path) -> PathBuf {
        let mut chunks = Vec::new();
        for variant in fs::read_dir(depot).expect("read depot") {
            let variant = variant.expect("variant entry").path();
            if !variant.is_dir() {
                continue;
            }
            for entry in fs::read_dir(variant).expect("read variant") {
                let entry = entry.expect("chunk entry").path();
                if entry.extension().and_then(|extension| extension.to_str()) == Some("chunk") {
                    chunks.push(entry);
                }
            }
        }
        chunks.sort();
        chunks.into_iter().next().expect("committed chunk file")
    }
}
