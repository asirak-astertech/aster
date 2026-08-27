//! High-level live and stopped-state surfaces for immutable, source-authenticated Blobs.
//!
//! The stopped facade preserves caller-owned streaming readers and writers.
//! The live facade accepts only an already-open regular [`fs::File`] and
//! returns at most one zeroize-on-drop 64 KiB page. Encrypted chunks remain in
//! the mission-bound depot; source-envelope bytes, manifest records, keys,
//! nonces, and depot mechanics are never returned to applications.

use std::{
    fmt, fs,
    io::{Read, Seek, Write},
    path::Path,
    sync::{
        Arc,
        atomic::{AtomicBool, Ordering},
    },
};

use aster_mesh::{
    BlobContentVerification, BlobError, BlobId as CoreBlobId, BlobMetadata as CoreBlobMetadata,
    ContentVerifiedBlobEnvelope, MAX_BLOB_MEDIA_TYPE_BYTES, MAX_BLOB_SCHEMA_ID_BYTES, NodeId,
    PreparedBlob, Priority, ReferenceEnvelopeSealer, SELECTED_BLOB_CHUNK_SIZE, Scope, Topic,
    prepare_blob,
};
pub use aster_redb_store::BlobDepotLimits;
use aster_redb_store::{
    BlobDepotCompletion, BlobOperationKey, BlobOperationRequest, BlobPublicationDisposition,
    BlobPublicationIntent, BlobReadPlan, BlobSemanticId, BlobSourceProjection, BlobSourceRetention,
    BlobStoreError, BlobVariantId, ControlPolicySnapshot, ControlTransferId,
    MAX_BLOB_OPERATION_KEY_BYTES, MAX_NETWORK_BLOB_BYTES, MAX_NETWORK_BLOB_CHUNKS, Store,
    StoreError, StoreLimits, StoredBlob,
};
use tokio::sync::{mpsc, oneshot};
use zeroize::{Zeroize as _, Zeroizing};

use super::{
    ApplicationError, ApplicationErrorKind, SelectedApplicationCommand, actor_unavailable,
    application_error, store_error_kind,
};
use crate::{
    NodeError,
    mission::UnprotectedReferenceMission,
    runtime::{
        AuthenticatedEventRouteCache, STORE_FILE, StartupEventVerification,
        cache_authenticated_blob_route_claim, ensure_principal_active,
        ensure_state_accepts_normal_operation, open_startup_event_verifier_and_cache,
        refresh_application_policy,
    },
};

struct AdmittedFile<'a> {
    file: &'a mut fs::File,
    admission: &'a AtomicBool,
    max_len: u64,
    #[cfg(test)]
    pass_two_gate: Option<(Arc<std::sync::Barrier>, Arc<std::sync::Barrier>)>,
    #[cfg(test)]
    expected_len: u64,
    #[cfg(test)]
    total_bytes_read: u64,
}

struct LivePublishContext<'a> {
    admission: &'a AtomicBool,
    length_probe: fs::File,
    expected_len: u64,
    fatal: &'a mut Option<NodeError>,
}

impl LivePublishContext<'_> {
    fn require_admission(&self) -> Result<(), ApplicationError> {
        if self.admission.load(Ordering::Acquire) {
            Ok(())
        } else {
            Err(actor_unavailable("blob publish"))
        }
    }

    fn require_exact_len(&self, observed: u64) -> Result<(), ApplicationError> {
        let current = self
            .length_probe
            .metadata()
            .map_err(|error| application_error("blob publish", error.into()))?;
        if !current.is_file() || current.len() != self.expected_len || observed != self.expected_len
        {
            return Err(ApplicationError::new(
                ApplicationErrorKind::Conflict,
                "blob publish",
            ));
        }
        Ok(())
    }
}

impl AdmittedFile<'_> {
    fn require_admission(&self) -> std::io::Result<()> {
        if self.admission.load(Ordering::Acquire) {
            Ok(())
        } else {
            Err(std::io::Error::new(
                std::io::ErrorKind::Interrupted,
                "live Blob worker admission closed",
            ))
        }
    }
}

impl Read for AdmittedFile<'_> {
    fn read(&mut self, output: &mut [u8]) -> std::io::Result<usize> {
        self.require_admission()?;
        #[cfg(test)]
        if self.pass_two_gate.is_some()
            && self.total_bytes_read
                >= self
                    .expected_len
                    .saturating_add(u64::from(SELECTED_BLOB_CHUNK_SIZE))
        {
            let (reached, release) = self
                .pass_two_gate
                .take()
                .expect("present live Blob pass-two gate");
            reached.wait();
            release.wait();
        }
        if output.is_empty() {
            return Ok(0);
        }
        let position = self.file.stream_position()?;
        if position > self.max_len {
            return Err(std::io::Error::new(
                std::io::ErrorKind::FileTooLarge,
                "live Blob source crossed its byte ceiling",
            ));
        }
        let remaining = self.max_len - position;
        if remaining == 0 {
            let mut probe = Zeroizing::new([0u8; 1]);
            return match self.file.read(&mut probe[..])? {
                0 => Ok(0),
                _ => Err(std::io::Error::new(
                    std::io::ErrorKind::FileTooLarge,
                    "live Blob source grew beyond its byte ceiling",
                )),
            };
        }
        let allowed = usize::try_from(remaining)
            .unwrap_or(usize::MAX)
            .min(output.len());
        let read = self.file.read(&mut output[..allowed])?;
        #[cfg(test)]
        {
            self.total_bytes_read = self
                .total_bytes_read
                .checked_add(u64::try_from(read).map_err(std::io::Error::other)?)
                .ok_or_else(|| std::io::Error::other("live Blob test read accounting overflow"))?;
        }
        Ok(read)
    }
}

impl Seek for AdmittedFile<'_> {
    fn seek(&mut self, position: std::io::SeekFrom) -> std::io::Result<u64> {
        self.require_admission()?;
        let offset = self.file.seek(position)?;
        if offset > self.max_len {
            Err(std::io::Error::new(
                std::io::ErrorKind::FileTooLarge,
                "live Blob source crossed its byte ceiling",
            ))
        } else {
            Ok(offset)
        }
    }
}

/// Maximum plaintext accepted by one live Blob publication.
pub const MAX_SELECTED_LIVE_BLOB_BYTES: u64 = MAX_NETWORK_BLOB_BYTES;

/// Maximum canonical 64 KiB chunks accepted by one live Blob publication.
pub const MAX_SELECTED_LIVE_BLOB_CHUNKS: u64 = MAX_NETWORK_BLOB_CHUNKS;

/// Maximum plaintext returned by one live Blob page read.
pub const MAX_SELECTED_BLOB_PAGE_BYTES: usize = SELECTED_BLOB_CHUNK_SIZE as usize;

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
/// Empty content is rejected by the selected Blob profile. `operation_key` is
/// a non-secret, non-path, low-sensitivity idempotency identifier retained with
/// the durable store. `media_type` and arbitrary `schema_id` bytes are likewise
/// non-secret, non-path metadata: they are retained in plaintext by the
/// depot/application projection and may appear in publication results and
/// pages. All three fields may appear in `Debug` output. For
/// [`SelectedBlobHandle::publish`], the owned regular file must have its cursor
/// positioned at exactly zero. Exact-operation retry remains available only
/// while the publisher and Store are authorized and not zeroized. A failed
/// publication may leave bounded, quota-charged unfinished or
/// completed-but-unpublished depot staging with no semantic/operation row;
/// this profile has no staging garbage collection. An authorized publisher can
/// therefore exhaust the default 512-MiB depot with roughly eight maximum-size
/// Blobs, before separately bounded carrier-prefix staging.
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

/// One bounded live Blob plaintext page.
///
/// `offset` is an absolute plaintext byte offset and `max_bytes` must be in
/// `1..=MAX_SELECTED_BLOB_PAGE_BYTES`. The final page may be shorter. An
/// offset at or beyond the authenticated Blob length is rejected rather than
/// manufacturing an empty plaintext result.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct BlobReadPageRequest {
    pub blob: BlobReadRequest,
    pub offset: u64,
    pub max_bytes: usize,
}

/// One freshly authenticated live Blob plaintext page.
///
/// Plaintext is deliberately private and cannot be moved into a raw `Vec`.
/// Borrow it through [`Self::as_bytes`]; the owned allocation is zeroized when
/// this value is dropped. Any bytes the caller copies from that borrow become
/// caller custody and may outlive node shutdown or zeroization. Closing live
/// admission prevents new pages; it cannot erase caller-owned copies.
pub struct BlobReadPage {
    pub id: BlobId,
    pub publisher: NodeId,
    pub publisher_counter: u64,
    pub priority: Priority,
    pub total_len: u64,
    pub media_type: Option<String>,
    pub schema_id: Vec<u8>,
    pub acceptance_marker: u64,
    pub offset: u64,
    pub complete: bool,
    next_offset: u64,
    plaintext: Zeroizing<Vec<u8>>,
}

impl BlobReadPage {
    /// Authenticated plaintext bytes for this page.
    pub fn as_bytes(&self) -> &[u8] {
        &self.plaintext
    }

    /// Number of authenticated plaintext bytes in this page.
    pub fn len(&self) -> usize {
        self.plaintext.len()
    }

    /// This profile never returns an empty live page.
    pub fn is_empty(&self) -> bool {
        self.plaintext.is_empty()
    }

    /// Absolute byte offset for the next page.
    pub const fn next_offset(&self) -> u64 {
        self.next_offset
    }
}

impl fmt::Debug for BlobReadPage {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("BlobReadPage")
            .field("id", &self.id)
            .field("publisher", &self.publisher)
            .field("publisher_counter", &self.publisher_counter)
            .field("priority", &self.priority)
            .field("total_len", &self.total_len)
            .field("media_type", &self.media_type)
            .field("schema_id", &self.schema_id)
            .field("acceptance_marker", &self.acceptance_marker)
            .field("offset", &self.offset)
            .field("complete", &self.complete)
            .field("next_offset", &self.next_offset)
            .field("plaintext_bytes", &self.plaintext.len())
            .finish()
    }
}

impl Drop for BlobReadPage {
    fn drop(&mut self) {
        self.plaintext.zeroize();
    }
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

/// Cloneable live Blob handle backed by the running node's protected worker.
#[derive(Clone)]
pub struct SelectedBlobHandle {
    commands: mpsc::Sender<SelectedApplicationCommand>,
    admission: Arc<AtomicBool>,
    identity: NodeId,
    mission_authority: NodeId,
}

impl SelectedBlobHandle {
    pub(crate) fn new(
        commands: mpsc::Sender<SelectedApplicationCommand>,
        admission: Arc<AtomicBool>,
        identity: NodeId,
        mission_authority: NodeId,
    ) -> Self {
        Self {
            commands,
            admission,
            identity,
            mission_authority,
        }
    }

    /// Authenticated local Blob publisher identity.
    pub const fn identity(&self) -> NodeId {
        self.identity
    }

    /// Stable mission authority bound to the live store and depot.
    pub const fn mission_authority(&self) -> NodeId {
        self.mission_authority
    }

    /// Durably publishes one already-open regular file through the live worker.
    ///
    /// The file must be nonempty, no larger than the live limit, and positioned
    /// at cursor offset exactly zero when this method is called.
    ///
    /// Dropping this future before its command is successfully enqueued in the
    /// shared application lane drops the file and cannot publish. After enqueue,
    /// cancellation leaves the outcome indeterminate and the worker may durably
    /// commit; retry the exact `operation_key` to recover the authoritative
    /// result only while that publisher and Store remain authorized and have
    /// not been zeroized. A failed or concurrently mutated source can leave
    /// bounded, quota-charged unfinished or completed-but-unpublished depot
    /// staging without a semantic or operation row; this profile does not yet
    /// garbage-collect that staging. An authorized publisher can therefore
    /// exhaust the default 512-MiB depot with roughly eight maximum-size Blobs,
    /// before separately bounded carrier-prefix staging.
    /// Admitted file syscalls run on the joined blocking worker, so a hostile or
    /// delayed FUSE/NFS/other filesystem can delay rekey, shutdown, and
    /// zeroization completion. A control change that wins the Store/final policy
    /// check prevents a stale-authority commit or page; an operation which
    /// linearizes first may return afterward. Rekey is logical forward
    /// authorization, not synchronous erasure of prior-epoch keys; facade drop
    /// or terminal zeroization is the node custody-erasure boundary. Node
    /// zeroization cannot erase the caller's backing source file or any
    /// externally cloned file descriptors.
    pub async fn publish(
        &self,
        request: BlobPublishRequest,
        source: fs::File,
    ) -> Result<BlobPublishResult, ApplicationError> {
        validate_live_publish_request(&request)?;
        let (response, received) = oneshot::channel();
        self.send(
            SelectedBlobCommand::Publish {
                request,
                source,
                response,
            },
            received,
            "blob publish",
        )
        .await
    }

    /// Reads one authenticated, zeroize-on-drop plaintext page.
    ///
    /// The unique current source is exact-loaded and content-authenticated.
    /// Inactive alternates are rechecked as projection-only durable rows
    /// against startup-authenticated cache capabilities under the Store's
    /// exclusive-writer boundary; their sealed bytes are not rehashed for
    /// every page and can never supply plaintext.
    ///
    /// Dropping the future cancels this side-effect-free read and prevents any
    /// subsequently produced page from being disclosed.
    pub async fn read_page(
        &self,
        request: BlobReadPageRequest,
    ) -> Result<BlobReadPage, ApplicationError> {
        let (response, received) = oneshot::channel();
        self.send(
            SelectedBlobCommand::ReadPage { request, response },
            received,
            "blob read page",
        )
        .await
    }

    async fn send<T>(
        &self,
        command: SelectedBlobCommand,
        received: oneshot::Receiver<Result<T, ApplicationError>>,
        operation: &'static str,
    ) -> Result<T, ApplicationError> {
        if !self.admission.load(Ordering::Acquire) {
            return Err(actor_unavailable(operation));
        }
        self.commands
            .send(SelectedApplicationCommand::Blob(command))
            .await
            .map_err(|_| actor_unavailable(operation))?;
        received.await.map_err(|_| actor_unavailable(operation))?
    }
}

pub(crate) enum SelectedBlobCommand {
    Publish {
        request: BlobPublishRequest,
        source: fs::File,
        response: oneshot::Sender<Result<BlobPublishResult, ApplicationError>>,
    },
    ReadPage {
        request: BlobReadPageRequest,
        response: oneshot::Sender<Result<BlobReadPage, ApplicationError>>,
    },
}

impl SelectedBlobCommand {
    pub(crate) fn reject(self) {
        match self {
            Self::Publish { response, .. } => {
                _ = response.send(Err(actor_unavailable("blob publish")));
            }
            Self::ReadPage { response, .. } => {
                _ = response.send(Err(actor_unavailable("blob read page")));
            }
        }
    }

    pub(crate) fn reject_resource_limit(self) {
        match self {
            Self::Publish { response, .. } => {
                _ = response.send(Err(ApplicationError::new(
                    ApplicationErrorKind::ResourceLimit,
                    "blob publish",
                )));
            }
            Self::ReadPage { response, .. } => {
                _ = response.send(Err(ApplicationError::new(
                    ApplicationErrorKind::ResourceLimit,
                    "blob read page",
                )));
            }
        }
    }
}

struct VerifiedStoredBlob {
    blob: ContentVerifiedBlobEnvelope,
    manifest_bytes: Vec<u8>,
    semantic_id: BlobSemanticId,
    acceptance_marker: u64,
}

struct VerifiedLiveBlob {
    stored: VerifiedStoredBlob,
    projection: BlobSourceProjection,
    retention: BlobSourceRetention,
    completion: BlobDepotCompletion,
    sealed: Vec<u8>,
    variant_id: aster_redb_store::BlobVariantId,
}

struct VerifiedLiveCandidate {
    semantic_id: BlobSemanticId,
    transfer_id: aster_redb_store::BlobTransferId,
    projection: BlobSourceProjection,
    retention: BlobSourceRetention,
    disposition: Option<BlobPublicationDisposition>,
    policy_active: bool,
    current_lineage: bool,
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
    source_route_cache: Arc<AuthenticatedEventRouteCache>,
    #[cfg(test)]
    final_read_gate: Option<(Arc<std::sync::Barrier>, Arc<std::sync::Barrier>)>,
    #[cfg(test)]
    live_publish_pass_two_gate: Option<(Arc<std::sync::Barrier>, Arc<std::sync::Barrier>)>,
    #[cfg(test)]
    live_operation_preflight_coherence_fault: bool,
    #[cfg(test)]
    live_read_projection_coherence_fault: bool,
    #[cfg(test)]
    live_selected_load_policy_race_fault: bool,
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
        let StartupEventVerification {
            verifier,
            historical_verifier,
            cache: source_route_cache,
            policy: _,
        } = open_startup_event_verifier_and_cache(&store, &mission)
            .map_err(|error| application_error("blob open", error))?;
        drop(historical_verifier);
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
            source_route_cache,
            #[cfg(test)]
            final_read_gate: None,
            #[cfg(test)]
            live_publish_pass_two_gate: None,
            #[cfg(test)]
            live_operation_preflight_coherence_fault: false,
            #[cfg(test)]
            live_read_projection_coherence_fault: false,
            #[cfg(test)]
            live_selected_load_policy_race_fault: false,
        };
        selected.current_policy("blob open")?;
        Ok(selected)
    }

    pub(crate) fn from_runtime(
        mission: UnprotectedReferenceMission,
        store: Arc<Store>,
        verifier: ReferenceEnvelopeSealer,
        verifier_head: Option<(u64, ControlTransferId)>,
        source_route_cache: Arc<AuthenticatedEventRouteCache>,
    ) -> Self {
        Self {
            mission,
            store,
            verifier,
            verifier_head,
            source_route_cache,
            #[cfg(test)]
            final_read_gate: None,
            #[cfg(test)]
            live_publish_pass_two_gate: None,
            #[cfg(test)]
            live_operation_preflight_coherence_fault: false,
            #[cfg(test)]
            live_read_projection_coherence_fault: false,
            #[cfg(test)]
            live_selected_load_policy_race_fault: false,
        }
    }

    #[cfg(test)]
    pub(crate) fn set_final_read_gate(
        &mut self,
        reached: Arc<std::sync::Barrier>,
        release: Arc<std::sync::Barrier>,
    ) {
        self.final_read_gate = Some((reached, release));
    }

    #[cfg(test)]
    fn set_live_publish_pass_two_gate(
        &mut self,
        reached: Arc<std::sync::Barrier>,
        release: Arc<std::sync::Barrier>,
    ) {
        self.live_publish_pass_two_gate = Some((reached, release));
    }

    /// Executes one worker-owned live command.
    ///
    /// Ordinary application failures are sent through the command response.
    /// An authenticated cache/depot invariant failure, including any failure
    /// after a durable Blob commit, drops that response and escapes as a fatal
    /// [`NodeError`] so the runtime can stop.
    pub(crate) fn execute_live(
        &mut self,
        command: SelectedBlobCommand,
        admission: &AtomicBool,
    ) -> Result<(), NodeError> {
        if !admission.load(Ordering::Acquire) {
            command.reject();
            return Ok(());
        }
        match command {
            SelectedBlobCommand::Publish {
                request,
                source,
                response,
            } => {
                let mut fatal = None;
                let result =
                    self.publish_live_with_admission(request, source, admission, &mut fatal);
                if let Some(error) = fatal {
                    drop(response);
                    Err(error)
                } else {
                    if admission.load(Ordering::Acquire) {
                        _ = response.send(result);
                    } else {
                        drop(result);
                        _ = response.send(Err(actor_unavailable("blob publish")));
                    }
                    Ok(())
                }
            }
            SelectedBlobCommand::ReadPage { request, response } => {
                let mut fatal = None;
                let result =
                    self.read_page_with_admission(request, admission, Some(&response), &mut fatal);
                if let Some(error) = fatal {
                    drop(response);
                    Err(error)
                } else {
                    if admission.load(Ordering::Acquire) {
                        _ = response.send(result);
                    } else {
                        drop(result);
                        _ = response.send(Err(actor_unavailable("blob read page")));
                    }
                    Ok(())
                }
            }
        }
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
        self.publish_inner(request, source, None)
    }

    /// Executes one live publication after accepting ownership of its file.
    #[cfg(test)]
    pub(crate) fn publish_live(
        &mut self,
        request: BlobPublishRequest,
        source: fs::File,
    ) -> Result<BlobPublishResult, ApplicationError> {
        let admission = AtomicBool::new(true);
        let mut fatal = None;
        let result = self.publish_live_with_admission(request, source, &admission, &mut fatal);
        if let Some(error) = fatal {
            Err(application_error("blob publish", error))
        } else {
            result
        }
    }

    fn publish_live_with_admission(
        &mut self,
        request: BlobPublishRequest,
        mut source: fs::File,
        admission: &AtomicBool,
        fatal: &mut Option<NodeError>,
    ) -> Result<BlobPublishResult, ApplicationError> {
        if !admission.load(Ordering::Acquire) {
            return Err(actor_unavailable("blob publish"));
        }
        if source
            .stream_position()
            .map_err(|error| application_error("blob publish", error.into()))?
            != 0
        {
            return Err(ApplicationError::new(
                ApplicationErrorKind::InvalidRequest,
                "blob publish",
            ));
        }
        let metadata = source
            .metadata()
            .map_err(|error| application_error("blob publish", error.into()))?;
        if !metadata.is_file() || metadata.len() == 0 {
            return Err(ApplicationError::new(
                ApplicationErrorKind::InvalidRequest,
                "blob publish",
            ));
        }
        if metadata.len() > MAX_SELECTED_LIVE_BLOB_BYTES {
            return Err(ApplicationError::new(
                ApplicationErrorKind::ResourceLimit,
                "blob publish",
            ));
        }
        let expected_len = metadata.len();
        let length_probe = source
            .try_clone()
            .map_err(|error| application_error("blob publish", error.into()))?;
        let mut context = LivePublishContext {
            admission,
            length_probe,
            expected_len,
            fatal,
        };
        let mut source = AdmittedFile {
            file: &mut source,
            admission,
            max_len: MAX_SELECTED_LIVE_BLOB_BYTES,
            #[cfg(test)]
            pass_two_gate: self.live_publish_pass_two_gate.take(),
            #[cfg(test)]
            expected_len,
            #[cfg(test)]
            total_bytes_read: 0,
        };
        self.publish_inner(request, &mut source, Some(&mut context))
    }

    fn publish_inner<R: Read + Seek>(
        &mut self,
        request: BlobPublishRequest,
        source: &mut R,
        mut live: Option<&mut LivePublishContext<'_>>,
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
        if live.is_some()
            && (prepared.total_len() > MAX_SELECTED_LIVE_BLOB_BYTES
                || prepared.chunk_count() > MAX_SELECTED_LIVE_BLOB_CHUNKS)
        {
            return Err(ApplicationError::new(
                ApplicationErrorKind::ResourceLimit,
                "blob publish",
            ));
        }
        if let Some(context) = live.as_deref_mut() {
            context.require_admission()?;
            context.require_exact_len(prepared.total_len())?;
            if source
                .stream_position()
                .map_err(|error| application_error("blob publish", error.into()))?
                != 0
            {
                return Err(ApplicationError::new(
                    ApplicationErrorKind::Conflict,
                    "blob publish",
                ));
            }
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

        let retry_cache = Arc::clone(&self.source_route_cache);
        let retry_lifecycle = match retry_cache.lock_blob_lifecycle() {
            Ok(lifecycle) => lifecycle,
            Err(error) => {
                if let Some(context) = live.as_deref_mut() {
                    *context.fatal = Some(live_blob_coherence_fatal(
                        "pre-retry Blob lifecycle lock",
                        error,
                    ));
                    return Err(ApplicationError::new(
                        ApplicationErrorKind::Integrity,
                        "blob publish",
                    ));
                }
                return Err(application_error("blob publish", error));
            }
        };
        let operation_preflight = {
            #[cfg(test)]
            if std::mem::replace(&mut self.live_operation_preflight_coherence_fault, false) {
                Err(StoreError::Blob(BlobStoreError::SchemaInvariant(
                    "injected orphan live Blob operation",
                )))
            } else {
                self.store
                    .blob_for_operation_with_policy(&policy, &operation_request)
            }
            #[cfg(not(test))]
            self.store
                .blob_for_operation_with_policy(&policy, &operation_request)
        };
        let existing = match operation_preflight {
            Ok(existing) => existing,
            Err(error) => {
                if live.is_some() && live_blob_durable_coherence_error(&error) {
                    if let Some(context) = live.as_deref_mut() {
                        *context.fatal = Some(live_blob_coherence_fatal(
                            "live Blob operation preflight",
                            error.into(),
                        ));
                    }
                    return Err(ApplicationError::new(
                        ApplicationErrorKind::Integrity,
                        "blob publish",
                    ));
                }
                return Err(application_error("blob publish", error.into()));
            }
        };
        if let Some(existing) = existing {
            let result = match self.verify_publication_retry(
                &existing,
                &intent,
                &prepared,
                epoch,
                live.is_some(),
            ) {
                Ok(result) => result,
                Err(error) => {
                    if let Some(context) = live.as_deref_mut() {
                        *context.fatal = Some(NodeError::FatalBlobCoherence(
                            "live Blob operation retry lost its exact authenticated claim".into(),
                        ));
                    }
                    return Err(error);
                }
            };
            return Ok(result);
        }
        drop(retry_lifecycle);

        let finished = {
            let depot = match if live.is_some() {
                self.store.blob_depot_for_local_publish()
            } else {
                self.store.blob_depot()
            } {
                Ok(depot) => depot,
                Err(error) => {
                    if live.is_some() && live_blob_durable_coherence_error(&error) {
                        if let Some(context) = live.as_deref_mut() {
                            *context.fatal = Some(live_blob_coherence_fatal(
                                "live Blob initial depot open",
                                error.into(),
                            ));
                        }
                        return Err(ApplicationError::new(
                            ApplicationErrorKind::Integrity,
                            "blob publish",
                        ));
                    }
                    return Err(application_error("blob publish", error.into()));
                }
            };
            let mut service = self
                .verifier
                .blob_service_with_store(&scope, &topic, epoch, depot)
                .map_err(|error| application_error("blob publish", error.into()))?;
            let (manifest, progress) =
                match service.install_prepared(&prepared).and_then(|manifest| {
                    service
                        .encrypt_some(source, &manifest, prepared.chunk_count())
                        .map(|progress| (manifest, progress))
                }) {
                    Ok(result) => result,
                    Err(error) => {
                        drop(service);
                        return Err(live_blob_core_error(&self.store, error, &mut live));
                    }
                };
            if !progress.complete || progress.verified_chunks != prepared.chunk_count() {
                return Err(ApplicationError::new(
                    ApplicationErrorKind::Integrity,
                    "blob publish",
                ));
            }
            if let Some(context) = live.as_deref_mut() {
                context.require_admission()?;
                let observed = source
                    .seek(std::io::SeekFrom::End(0))
                    .map_err(|error| application_error("blob publish", error.into()))?;
                context.require_exact_len(observed)?;
            }
            let result = service.finish_manifest(&manifest);
            drop(service);
            result.map_err(|error| live_blob_core_error(&self.store, error, &mut live))?
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
        let completion = match if live.is_some() {
            self.store
                .completed_local_blob(&verified.blob, &verified.manifest_bytes)
        } else {
            self.store.blob_depot().and_then(|mut depot| {
                depot.completed_blob(&verified.blob, &verified.manifest_bytes)
            })
        } {
            Ok(completion) => completion,
            Err(error) => {
                if live.is_some() && live_blob_durable_coherence_error(&error) {
                    if let Some(context) = live.as_deref_mut() {
                        *context.fatal = Some(live_blob_coherence_fatal(
                            "live Blob completion proof",
                            error.into(),
                        ));
                    }
                    return Err(ApplicationError::new(
                        ApplicationErrorKind::Integrity,
                        "blob publish",
                    ));
                }
                return Err(application_error("blob publish", error.into()));
            }
        };
        let source_route_cache = Arc::clone(&self.source_route_cache);
        if let Some(context) = live.as_deref_mut() {
            context.require_admission()?;
        }
        let _lifecycle = match source_route_cache.lock_blob_lifecycle() {
            Ok(lifecycle) => lifecycle,
            Err(error) => {
                if let Some(context) = live.as_deref_mut() {
                    *context.fatal = Some(live_blob_coherence_fatal(
                        "pre-commit Blob lifecycle lock",
                        error,
                    ));
                    return Err(ApplicationError::new(
                        ApplicationErrorKind::Integrity,
                        "blob publish",
                    ));
                }
                return Err(application_error("blob publish", error));
            }
        };
        if let Some(context) = live.as_deref_mut() {
            context.require_admission()?;
        }
        let outcome = match self.store.commit_reserved_blob_once_with_policy(
            &policy,
            &operation_request,
            &reservation,
            &verified.blob,
            &sealed.bytes,
            &completion,
        ) {
            Ok(outcome) => outcome,
            Err(error) => {
                if live.is_some() && live_blob_durable_coherence_error(&error) {
                    if let Some(context) = live.as_deref_mut() {
                        *context.fatal = Some(live_blob_coherence_fatal(
                            "live Blob durable commit precondition",
                            error.into(),
                        ));
                    }
                    return Err(ApplicationError::new(
                        ApplicationErrorKind::Integrity,
                        "blob publish",
                    ));
                }
                return Err(application_error("blob publish", error.into()));
            }
        };
        let stored = match self.verify_stored_blob(
            outcome.blob(),
            Some(&intent),
            epoch,
            "blob publish",
            false,
        ) {
            Ok(stored) => stored,
            Err(error) => {
                if let Some(context) = live.as_deref_mut() {
                    *context.fatal = Some(NodeError::FatalBlobCoherence(
                        "durable live Blob commit failed post-commit verification".into(),
                    ));
                }
                return Err(error);
            }
        };
        if let Err(error) = cache_authenticated_blob_route_claim(
            &self.store,
            &source_route_cache,
            &self.verifier,
            &stored.blob,
            &stored.manifest_bytes,
            &outcome.blob().sealed,
            outcome.blob().acceptance_marker,
        ) {
            if let Some(context) = live {
                *context.fatal = Some(live_blob_coherence_fatal(
                    "durable live Blob commit cache transition",
                    error,
                ));
                return Err(ApplicationError::new(
                    ApplicationErrorKind::Integrity,
                    "blob publish",
                ));
            }
            return Err(application_error("blob publish", error));
        }
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

    /// Reads one bounded page for the protected live facade.
    #[cfg(test)]
    pub(crate) fn read_page(
        &mut self,
        request: BlobReadPageRequest,
    ) -> Result<BlobReadPage, ApplicationError> {
        let admission = AtomicBool::new(true);
        let mut fatal = None;
        let result = self.read_page_with_admission(request, &admission, None, &mut fatal);
        if let Some(error) = fatal {
            Err(application_error("blob read page", error))
        } else {
            result
        }
    }

    fn read_page_with_admission(
        &mut self,
        request: BlobReadPageRequest,
        admission: &AtomicBool,
        response: Option<&oneshot::Sender<Result<BlobReadPage, ApplicationError>>>,
        fatal: &mut Option<NodeError>,
    ) -> Result<BlobReadPage, ApplicationError> {
        if live_blob_read_cancelled(admission, response) {
            return Err(actor_unavailable("blob read page"));
        }
        if request.max_bytes == 0 || request.max_bytes > MAX_SELECTED_BLOB_PAGE_BYTES {
            return Err(ApplicationError::new(
                ApplicationErrorKind::InvalidRequest,
                "blob read page",
            ));
        }
        if request
            .offset
            .checked_add(u64::try_from(request.max_bytes).map_err(|_| {
                ApplicationError::new(ApplicationErrorKind::InvalidRequest, "blob read page")
            })?)
            .is_none()
        {
            return Err(ApplicationError::new(
                ApplicationErrorKind::InvalidRequest,
                "blob read page",
            ));
        }
        let policy = self.current_policy("blob read page")?;
        let epoch = self.active_epoch(&request.blob.scope, "blob read page")?;
        self.require_blob_grants(
            &request.blob.topic,
            &request.blob.scope,
            epoch,
            "blob read page",
        )?;
        let source_route_cache = Arc::clone(&self.source_route_cache);
        let initial_lifecycle = match source_route_cache.lock_blob_lifecycle() {
            Ok(lifecycle) => lifecycle,
            Err(error) => {
                *fatal = Some(live_blob_coherence_fatal(
                    "initial live Blob read lifecycle lock",
                    error,
                ));
                return Err(ApplicationError::new(
                    ApplicationErrorKind::Integrity,
                    "blob read page",
                ));
            }
        };
        if live_blob_read_cancelled(admission, response) {
            drop(initial_lifecycle);
            return Err(actor_unavailable("blob read page"));
        }
        let read_projection = {
            #[cfg(test)]
            if std::mem::replace(&mut self.live_read_projection_coherence_fault, false) {
                Err(StoreError::Blob(BlobStoreError::SchemaInvariant(
                    "injected orphan live Blob content index",
                )))
            } else {
                self.store.prepare_blob_read_with_policy(
                    &policy,
                    &request.blob.topic,
                    &request.blob.scope,
                    request.blob.id.into_core(),
                )
            }
            #[cfg(not(test))]
            self.store.prepare_blob_read_with_policy(
                &policy,
                &request.blob.topic,
                &request.blob.scope,
                request.blob.id.into_core(),
            )
        };
        let plan = match read_projection {
            Ok(plan) => plan,
            Err(error) => {
                if live_blob_durable_coherence_error(&error) {
                    *fatal = Some(live_blob_coherence_fatal(
                        "live Blob durable read projection",
                        error.into(),
                    ));
                    return Err(ApplicationError::new(
                        ApplicationErrorKind::Integrity,
                        "blob read page",
                    ));
                }
                return Err(application_error("blob read page", error.into()));
            }
        };
        let selected = self.verify_live_read_plan(&plan, epoch, fatal)?;
        if live_blob_read_cancelled(admission, response) {
            return Err(actor_unavailable("blob read page"));
        }
        let total_len = selected.stored.blob.manifest().total_len();
        if request.offset >= total_len {
            return Err(ApplicationError::new(
                ApplicationErrorKind::InvalidRequest,
                "blob read page",
            ));
        }
        let remaining = total_len - request.offset;
        let page_len = usize::try_from(remaining.min(request.max_bytes as u64)).map_err(|_| {
            ApplicationError::new(ApplicationErrorKind::ResourceLimit, "blob read page")
        })?;
        let next_offset = request
            .offset
            .checked_add(u64::try_from(page_len).map_err(|_| {
                ApplicationError::new(ApplicationErrorKind::ResourceLimit, "blob read page")
            })?)
            .ok_or_else(|| {
                ApplicationError::new(ApplicationErrorKind::InvalidRequest, "blob read page")
            })?;
        let complete = next_offset == total_len;
        let first_chunk = request.offset / u64::from(SELECTED_BLOB_CHUNK_SIZE);
        let last_chunk = next_offset
            .checked_sub(1)
            .map(|last_byte| last_byte / u64::from(SELECTED_BLOB_CHUNK_SIZE))
            .ok_or_else(|| {
                ApplicationError::new(ApplicationErrorKind::Integrity, "blob read page")
            })?;
        let range_chunk_count = last_chunk
            .checked_sub(first_chunk)
            .and_then(|span| span.checked_add(1))
            .filter(|count| (1..=2).contains(count))
            .ok_or_else(|| {
                ApplicationError::new(ApplicationErrorKind::Integrity, "blob read page")
            })?;

        self.require_live_read_authority(
            &policy,
            &plan,
            &selected,
            first_chunk,
            range_chunk_count,
            fatal,
        )?;
        drop(initial_lifecycle);
        let mut plaintext = Zeroizing::new(vec![0u8; page_len]);
        let decrypt_result = (|| -> Result<(), ApplicationError> {
            let mut service = self
                .verifier
                .blob_service_with_store(
                    selected.stored.blob.scope(),
                    selected.stored.blob.topic(),
                    selected.stored.blob.key_epoch(),
                    self.store
                        .blob_depot_for_authenticated_read(&selected.completion)
                        .map_err(|error| application_error("blob read page", error.into()))?,
                )
                .map_err(|error| application_error("blob read page", error.into()))?;
            let stats = service
                .read_range_for_verified(&selected.stored.blob, request.offset, &mut plaintext)
                .map_err(|error| blob_core_error("blob read page", error))?;
            if stats.plaintext_bytes != page_len as u64
                || stats.verified_chunks != range_chunk_count
                || !(1..=2).contains(&stats.verified_chunks)
            {
                return Err(ApplicationError::new(
                    ApplicationErrorKind::Integrity,
                    "blob read page",
                ));
            }
            Ok(())
        })();
        if let Err(error) = decrypt_result {
            if error.kind() == ApplicationErrorKind::Integrity {
                *fatal = Some(NodeError::FatalBlobCoherence(
                    "bounded live Blob page decryption failed integrity verification".into(),
                ));
            }
            return Err(error);
        }
        if live_blob_read_cancelled(admission, response) {
            return Err(actor_unavailable("blob read page"));
        }
        #[cfg(test)]
        if let Some((reached, release)) = self.final_read_gate.take() {
            reached.wait();
            release.wait();
        }
        let final_lifecycle = match source_route_cache.lock_blob_lifecycle() {
            Ok(lifecycle) => lifecycle,
            Err(error) => {
                *fatal = Some(live_blob_coherence_fatal(
                    "final live Blob read lifecycle lock",
                    error,
                ));
                return Err(ApplicationError::new(
                    ApplicationErrorKind::Integrity,
                    "blob read page",
                ));
            }
        };
        if live_blob_read_cancelled(admission, response) {
            drop(final_lifecycle);
            return Err(actor_unavailable("blob read page"));
        }
        self.require_live_read_authority(
            &policy,
            &plan,
            &selected,
            first_chunk,
            range_chunk_count,
            fatal,
        )?;
        let metadata = selected.stored.blob.manifest().metadata();
        let page = BlobReadPage {
            id: BlobId::from_core(selected.stored.blob.blob_id()),
            publisher: selected.stored.blob.publisher(),
            publisher_counter: selected.stored.blob.dot().counter,
            priority: selected.stored.blob.priority(),
            total_len,
            media_type: metadata.media_type().map(str::to_owned),
            schema_id: metadata.schema_id().to_vec(),
            acceptance_marker: selected.stored.acceptance_marker,
            offset: request.offset,
            complete,
            next_offset,
            plaintext,
        };
        drop(final_lifecycle);
        Ok(page)
    }

    fn verify_live_read_plan(
        &mut self,
        plan: &BlobReadPlan,
        current_epoch: u64,
        fatal: &mut Option<NodeError>,
    ) -> Result<VerifiedLiveBlob, ApplicationError> {
        let result = self.verify_live_read_plan_inner(plan, current_epoch, fatal);
        if let Err(error) = &result
            && fatal.is_none()
            && matches!(
                error.kind(),
                ApplicationErrorKind::Integrity | ApplicationErrorKind::StateUnavailable
            )
        {
            *fatal = Some(NodeError::FatalBlobCoherence(
                "live Blob read plan lost an exact authenticated authority claim".into(),
            ));
        }
        result
    }

    fn verify_live_read_plan_inner(
        &mut self,
        plan: &BlobReadPlan,
        current_epoch: u64,
        fatal: &mut Option<NodeError>,
    ) -> Result<VerifiedLiveBlob, ApplicationError> {
        let mut candidates = Vec::with_capacity(plan.candidates().len());
        for candidate in plan.candidates() {
            let projection = candidate.projection().clone();
            if projection.topic != *plan.topic()
                || projection.scope != *plan.scope()
                || projection.blob_id != plan.blob_id()
            {
                return Err(ApplicationError::new(
                    ApplicationErrorKind::Integrity,
                    "blob read page",
                ));
            }
            let retention = BlobSourceRetention::Completed {
                acceptance_marker: candidate.acceptance_marker(),
            };
            let current_lineage = match self.source_route_cache.is_current_blob_source_projection(
                &self.verifier,
                &projection,
                retention,
            ) {
                Ok(current) => current,
                Err(error) => {
                    *fatal = Some(live_blob_coherence_fatal(
                        "live Blob candidate route claim",
                        error,
                    ));
                    return Err(ApplicationError::new(
                        ApplicationErrorKind::Integrity,
                        "blob read page",
                    ));
                }
            };
            let revoked = self
                .store
                .is_control_principal_revoked(projection.publisher)
                .map_err(|error| application_error("blob read page", error.into()))?;
            let policy_active = !revoked && projection.epoch == current_epoch;
            candidates.push(VerifiedLiveCandidate {
                semantic_id: projection.semantic_id,
                transfer_id: projection.transfer_id,
                projection,
                retention,
                disposition: candidate.disposition(),
                policy_active,
                current_lineage,
            });
        }

        let policy_selected = candidates
            .iter()
            .filter(|candidate| candidate.policy_active)
            .max_by_key(|candidate| candidate.semantic_id)
            .map(|candidate| candidate.semantic_id);
        let plan_current = plan.current();
        if plan_current.map(|candidate| candidate.projection().semantic_id) != policy_selected {
            return Err(ApplicationError::new(
                ApplicationErrorKind::Integrity,
                "blob read page",
            ));
        }
        for candidate in &candidates {
            let expected = if !candidate.policy_active {
                None
            } else if Some(candidate.semantic_id) == policy_selected {
                Some(BlobPublicationDisposition::Current)
            } else {
                Some(BlobPublicationDisposition::Alternate)
            };
            if candidate.disposition != expected {
                return Err(ApplicationError::new(
                    ApplicationErrorKind::Integrity,
                    "blob read page",
                ));
            }
        }
        let selected = policy_selected.ok_or_else(|| {
            ApplicationError::new(
                ApplicationErrorKind::UnauthorizedOrRevoked,
                "blob read page",
            )
        })?;
        let plan_current = plan_current.ok_or_else(|| {
            ApplicationError::new(
                ApplicationErrorKind::UnauthorizedOrRevoked,
                "blob read page",
            )
        })?;
        if candidates
            .iter()
            .filter(|candidate| candidate.policy_active && candidate.semantic_id == selected)
            .count()
            != 1
        {
            return Err(ApplicationError::new(
                ApplicationErrorKind::Integrity,
                "blob read page",
            ));
        }
        let selected_claim = candidates
            .into_iter()
            .find(|candidate| {
                candidate.semantic_id == selected
                    && candidate.transfer_id == plan_current.projection().transfer_id
                    && candidate.disposition == Some(BlobPublicationDisposition::Current)
            })
            .ok_or_else(|| {
                ApplicationError::new(ApplicationErrorKind::Integrity, "blob read page")
            })?;
        if !selected_claim.policy_active || !selected_claim.current_lineage {
            return Err(ApplicationError::new(
                ApplicationErrorKind::UnauthorizedOrRevoked,
                "blob read page",
            ));
        }

        // Only the exact, structurally selected current source may incur a
        // content-envelope open or depot scan. Alternates are authenticated by
        // their exact cached source claims above and never supply plaintext.
        let selected_load = {
            #[cfg(test)]
            if std::mem::replace(&mut self.live_selected_load_policy_race_fault, false) {
                Err(StoreError::ControlPolicyChanged)
            } else {
                self.store
                    .load_blob_read_candidate_with_policy(plan.control_policy(), plan_current)
            }
            #[cfg(not(test))]
            self.store
                .load_blob_read_candidate_with_policy(plan.control_policy(), plan_current)
        };
        let exact_stored = match selected_load {
            Ok(stored) => stored,
            Err(error) => {
                if live_blob_durable_coherence_error(&error) {
                    *fatal = Some(live_blob_coherence_fatal(
                        "live Blob selected source exact load",
                        error.into(),
                    ));
                    return Err(ApplicationError::new(
                        ApplicationErrorKind::Integrity,
                        "blob read page",
                    ));
                }
                return Err(application_error("blob read page", error.into()));
            }
        };
        let stored =
            self.verify_stored_blob(&exact_stored, None, current_epoch, "blob read page", false)?;
        let (cache_current, completion) =
            match self.source_route_cache.verify_completed_blob_source_claim(
                &self.verifier,
                &selected_claim.projection,
                selected_claim.retention,
                &exact_stored.sealed,
                stored.blob.blob_id(),
                stored.blob.manifest().total_len(),
                stored.blob.manifest().chunk_size(),
                stored.blob.manifest().chunk_count(),
                exact_stored.variant_id,
            ) {
                Ok(current) => current,
                Err(error) => {
                    *fatal = Some(live_blob_coherence_fatal(
                        "live Blob selected source claim",
                        error,
                    ));
                    return Err(ApplicationError::new(
                        ApplicationErrorKind::Integrity,
                        "blob read page",
                    ));
                }
            };
        if !cache_current {
            return Err(ApplicationError::new(
                ApplicationErrorKind::UnauthorizedOrRevoked,
                "blob read page",
            ));
        }
        Self::require_blob_plan_claims_for(plan, &stored, "blob read page")?;
        if stored.blob.manifest().total_len() > MAX_SELECTED_LIVE_BLOB_BYTES
            || stored.blob.manifest().chunk_count() > MAX_SELECTED_LIVE_BLOB_CHUNKS
        {
            return Err(ApplicationError::new(
                ApplicationErrorKind::ResourceLimit,
                "blob read page",
            ));
        }
        if !self.verifier.is_current_source_route_lineage(
            stored.blob.scope(),
            stored.blob.key_epoch(),
            stored.blob.route_lineage(),
        ) || !self.verifier.is_current_blob_physical_lineage(
            stored.blob.scope(),
            stored.blob.topic(),
            stored.blob.key_epoch(),
            stored.blob.physical_lineage(),
        ) {
            return Err(ApplicationError::new(
                ApplicationErrorKind::Integrity,
                "blob read page",
            ));
        }
        Ok(VerifiedLiveBlob {
            stored,
            projection: selected_claim.projection,
            retention: selected_claim.retention,
            completion,
            sealed: exact_stored.sealed,
            variant_id: exact_stored.variant_id,
        })
    }

    fn require_live_read_authority(
        &self,
        policy: &ControlPolicySnapshot,
        plan: &BlobReadPlan,
        selected: &VerifiedLiveBlob,
        first_chunk: u64,
        range_chunk_count: u64,
        fatal: &mut Option<NodeError>,
    ) -> Result<(), ApplicationError> {
        let result = self.require_live_read_authority_inner(
            policy,
            plan,
            selected,
            first_chunk,
            range_chunk_count,
            fatal,
        );
        if let Err(error) = &result
            && fatal.is_none()
            && matches!(
                error.kind(),
                ApplicationErrorKind::Integrity | ApplicationErrorKind::StateUnavailable
            )
        {
            *fatal = Some(NodeError::FatalBlobCoherence(
                "live Blob page authority changed around bounded decryption".into(),
            ));
        }
        result
    }

    fn require_live_read_authority_inner(
        &self,
        policy: &ControlPolicySnapshot,
        plan: &BlobReadPlan,
        selected: &VerifiedLiveBlob,
        first_chunk: u64,
        range_chunk_count: u64,
        fatal: &mut Option<NodeError>,
    ) -> Result<(), ApplicationError> {
        if plan.current().is_none_or(|candidate| {
            candidate.projection().transfer_id != selected.projection.transfer_id
                || candidate.projection().semantic_id != selected.stored.semantic_id
                || candidate.disposition() != Some(BlobPublicationDisposition::Current)
        }) {
            return Err(ApplicationError::new(
                ApplicationErrorKind::Integrity,
                "blob read page",
            ));
        }
        self.store
            .require_blob_read_plan_with_policy(policy, plan)
            .map_err(|error| application_error("blob read page", error.into()))?;
        let retained = self
            .store
            .blob_source_projection(selected.projection.transfer_id)
            .map_err(|error| application_error("blob read page", error.into()))?
            .ok_or_else(|| {
                ApplicationError::new(ApplicationErrorKind::Integrity, "blob read page")
            })?;
        if retained.source != selected.projection || retained.retention != selected.retention {
            return Err(ApplicationError::new(
                ApplicationErrorKind::Integrity,
                "blob read page",
            ));
        }
        let (current, completion) =
            match self.source_route_cache.verify_completed_blob_source_claim(
                &self.verifier,
                &retained.source,
                retained.retention,
                &selected.sealed,
                selected.stored.blob.blob_id(),
                selected.stored.blob.manifest().total_len(),
                selected.stored.blob.manifest().chunk_size(),
                selected.stored.blob.manifest().chunk_count(),
                selected.variant_id,
            ) {
                Ok(current) => current,
                Err(error) => {
                    *fatal = Some(live_blob_coherence_fatal(
                        "live Blob final source claim",
                        error,
                    ));
                    return Err(ApplicationError::new(
                        ApplicationErrorKind::Integrity,
                        "blob read page",
                    ));
                }
            };
        if completion != selected.completion {
            *fatal = Some(NodeError::FatalBlobCoherence(
                "live Blob range completion capability changed".into(),
            ));
            return Err(ApplicationError::new(
                ApplicationErrorKind::Integrity,
                "blob read page",
            ));
        }
        if let Err(error) = self
            .store
            .blob_depot_for_authenticated_read(&completion)
            .and_then(|mut depot| {
                depot.recheck_completion_range(&completion, first_chunk, range_chunk_count)
            })
        {
            *fatal = Some(live_blob_coherence_fatal(
                "live Blob range completion recheck",
                error.into(),
            ));
            return Err(ApplicationError::new(
                ApplicationErrorKind::Integrity,
                "blob read page",
            ));
        }
        if !current
            || !self.verifier.is_current_source_route_lineage(
                selected.stored.blob.scope(),
                selected.stored.blob.key_epoch(),
                selected.stored.blob.route_lineage(),
            )
            || !self.verifier.is_current_blob_physical_lineage(
                selected.stored.blob.scope(),
                selected.stored.blob.topic(),
                selected.stored.blob.key_epoch(),
                selected.stored.blob.physical_lineage(),
            )
        {
            return Err(ApplicationError::new(
                ApplicationErrorKind::UnauthorizedOrRevoked,
                "blob read page",
            ));
        }
        Ok(())
    }

    fn verify_read_plan(
        &mut self,
        plan: &BlobReadPlan,
        current_epoch: u64,
    ) -> Result<VerifiedStoredBlob, ApplicationError> {
        let mut active = Vec::with_capacity(plan.candidates().len());
        let mut selected: Option<VerifiedStoredBlob> = None;
        for candidate in plan.candidates() {
            let stored = self
                .store
                .load_blob_read_candidate_with_policy(plan.control_policy(), candidate)
                .map_err(|error| application_error("blob read", error.into()))?;
            let verified =
                self.verify_stored_blob(&stored, None, current_epoch, "blob read", false)?;
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
            } else if Some(candidate.projection().semantic_id) == selected_id {
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
        if plan
            .current()
            .map(|candidate| candidate.projection().semantic_id)
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
        Self::require_blob_plan_claims_for(plan, verified, "blob read")
    }

    fn require_blob_plan_claims_for(
        plan: &BlobReadPlan,
        verified: &VerifiedStoredBlob,
        operation: &'static str,
    ) -> Result<(), ApplicationError> {
        if verified.blob.topic() != plan.topic()
            || verified.blob.scope() != plan.scope()
            || verified.blob.blob_id() != plan.blob_id()
        {
            return Err(ApplicationError::new(
                ApplicationErrorKind::Integrity,
                operation,
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
        Self::verify_stored_blob_with(
            &self.store,
            self.mission_authority(),
            &mut self.verifier,
            stored,
            expected,
            current_epoch,
            operation,
            verify_completion,
        )
    }

    #[allow(clippy::too_many_arguments)]
    fn verify_stored_blob_with(
        store: &Store,
        mission_authority: NodeId,
        verifier: &mut ReferenceEnvelopeSealer,
        stored: &StoredBlob,
        expected: Option<&BlobPublicationIntent>,
        current_epoch: u64,
        operation: &'static str,
        verify_completion: bool,
    ) -> Result<VerifiedStoredBlob, ApplicationError> {
        let route = verifier
            .verify_blob(&stored.sealed)
            .map_err(|error| application_error(operation, error.into()))?;
        if route.envelope_id() != *stored.transfer_id.as_bytes()
            || route.item_id() != *stored.semantic_id.as_bytes()
            || route.header() != &stored.header
            || route.blob_id() != stored.blob_id
            || route.mission_authority_id() != mission_authority
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
        if !verifier.can_route_blob(route.scope(), route.key_epoch())
            || !verifier.can_open_blob_content(route.scope(), route.topic(), route.key_epoch())
        {
            return Err(ApplicationError::new(
                ApplicationErrorKind::Integrity,
                operation,
            ));
        }
        let (blob, manifest_bytes) = match verifier
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
            || stored.route_lineage != Some(*blob.route_lineage().binding())
            || stored.physical_lineage != Some(*blob.physical_lineage().binding())
            || blob.manifest().total_len() == 0
            || blob.manifest().chunk_size() != SELECTED_BLOB_CHUNK_SIZE
        {
            return Err(ApplicationError::new(
                ApplicationErrorKind::Integrity,
                operation,
            ));
        }
        blob.verify_exact_sealed(&stored.sealed)
            .map_err(|error| application_error(operation, error.into()))?;
        blob.verify_exact_manifest(&manifest_bytes)
            .map_err(|error| application_error(operation, error.into()))?;
        if verify_completion {
            store
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

    fn completed_projection(
        &self,
        stored: &StoredBlob,
        operation: &'static str,
    ) -> Result<(BlobSourceProjection, BlobSourceRetention), ApplicationError> {
        let retained = self
            .store
            .blob_source_projection(stored.transfer_id)
            .map_err(|error| application_error(operation, error.into()))?
            .ok_or_else(|| ApplicationError::new(ApplicationErrorKind::Integrity, operation))?;
        let expected = BlobSourceRetention::Completed {
            acceptance_marker: stored.acceptance_marker,
        };
        if retained.retention != expected
            || retained.source.transfer_id != stored.transfer_id
            || retained.source.semantic_id != stored.semantic_id
            || retained.source.publisher != stored.header.stamp.dot.publisher
            || retained.source.topic != stored.header.topic
            || retained.source.scope != stored.header.scope
            || retained.source.epoch != stored.header.key_epoch
            || retained.source.blob_id != stored.blob_id
            || retained.source.manifest_digest != stored.manifest_digest
            || stored.route_lineage != Some(retained.source.route_lineage)
            || stored.physical_lineage != Some(retained.source.physical_lineage)
            || retained.source.sealed_len
                != u64::try_from(stored.sealed.len()).map_err(|_| {
                    ApplicationError::new(ApplicationErrorKind::Integrity, operation)
                })?
        {
            return Err(ApplicationError::new(
                ApplicationErrorKind::Integrity,
                operation,
            ));
        }
        Ok((retained.source, retained.retention))
    }

    fn verify_publication_retry(
        &mut self,
        stored: &StoredBlob,
        expected: &BlobPublicationIntent,
        prepared: &PreparedBlob,
        current_epoch: u64,
        live_bounded: bool,
    ) -> Result<BlobPublishResult, ApplicationError> {
        let (projection, retention) = self.completed_projection(stored, "blob publish")?;
        let (current, completion) = self
            .source_route_cache
            .verify_completed_blob_source_claim(
                &self.verifier,
                &projection,
                retention,
                &stored.sealed,
                prepared.id(),
                prepared.total_len(),
                SELECTED_BLOB_CHUNK_SIZE,
                prepared.chunk_count(),
                stored.variant_id,
            )
            .map_err(|error| application_error("blob publish", error))?;
        self.store
            .blob_depot_for_authenticated_read(&completion)
            .and_then(|mut depot| depot.recheck_completion(&completion))
            .map_err(|error| application_error("blob publish", error.into()))?;
        if current && stored.header.key_epoch == current_epoch {
            let verified = self.verify_stored_blob(
                stored,
                Some(expected),
                current_epoch,
                "blob publish",
                false,
            )?;
            return Ok(blob_publish_result(&verified, false));
        }
        if stored.header.key_epoch > current_epoch
            || stored.header.stamp.dot.publisher != expected.publisher()
            || stored.header.topic != *expected.topic()
            || stored.header.scope != *expected.scope()
            || stored.header.priority != expected.priority()
            || stored.blob_id != expected.blob_id()
            || stored.blob_id != prepared.id()
            || prepared.total_len() == 0
            || prepared.chunk_count() == 0
            || (live_bounded
                && (prepared.chunk_count() > MAX_SELECTED_LIVE_BLOB_CHUNKS
                    || prepared.total_len() > MAX_SELECTED_LIVE_BLOB_BYTES))
        {
            return Err(ApplicationError::new(
                ApplicationErrorKind::Integrity,
                "blob publish",
            ));
        }
        let metadata = prepared.metadata();
        Ok(BlobPublishResult {
            id: BlobId::from_core(prepared.id()),
            publisher: stored.header.stamp.dot.publisher,
            publisher_counter: stored.header.stamp.dot.counter,
            priority: stored.header.priority,
            total_len: prepared.total_len(),
            media_type: metadata.media_type().map(str::to_owned),
            schema_id: metadata.schema_id().to_vec(),
            acceptance_marker: stored.acceptance_marker,
            inserted: false,
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

fn live_blob_durable_coherence_error(error: &StoreError) -> bool {
    matches!(
        error,
        StoreError::Blob(
            BlobStoreError::SchemaInvariant(_)
                | BlobStoreError::DepotIntegrity(_)
                | BlobStoreError::CompletionMismatch
        )
    )
}

fn live_blob_coherence_fatal(context: &'static str, error: NodeError) -> NodeError {
    match error {
        NodeError::FatalBlobCoherence(_) => error,
        error => NodeError::FatalBlobCoherence(format!("{context}: {error}")),
    }
}

fn validate_live_publish_request(request: &BlobPublishRequest) -> Result<(), ApplicationError> {
    if request.operation_key.is_empty()
        || request.operation_key.len() > MAX_BLOB_OPERATION_KEY_BYTES
        || request
            .media_type
            .as_ref()
            .is_some_and(|value| value.is_empty() || value.len() > MAX_BLOB_MEDIA_TYPE_BYTES)
        || request.schema_id.len() > MAX_BLOB_SCHEMA_ID_BYTES
    {
        return Err(ApplicationError::new(
            ApplicationErrorKind::InvalidRequest,
            "blob publish",
        ));
    }
    Ok(())
}

fn live_blob_read_cancelled(
    admission: &AtomicBool,
    response: Option<&oneshot::Sender<Result<BlobReadPage, ApplicationError>>>,
) -> bool {
    !admission.load(Ordering::Acquire) || response.is_some_and(oneshot::Sender::is_closed)
}

fn blob_prepare_error(error: BlobError) -> ApplicationError {
    match error {
        BlobError::InvalidManifest => {
            ApplicationError::new(ApplicationErrorKind::ResourceLimit, "blob publish")
        }
        error => blob_core_error("blob publish", error),
    }
}

fn live_blob_core_error(
    _store: &Store,
    error: BlobError,
    live: &mut Option<&mut LivePublishContext<'_>>,
) -> ApplicationError {
    if let Some(context) = live.as_deref_mut()
        && let BlobError::Store(adapter) = &error
    {
        // The core keeps the concrete adapter error as a typed source while
        // its public display remains sanitized. This preserves the exact
        // quota/conflict versus durable-coherence boundary even when a marked
        // target chunk fails during an otherwise opaque core operation.
        if let Some(store_error) = adapter.downcast_ref::<StoreError>() {
            if live_blob_durable_coherence_error(store_error) {
                *context.fatal = Some(NodeError::FatalBlobCoherence(
                    "live Blob core adapter reported durable coherence loss".into(),
                ));
                return ApplicationError::new(ApplicationErrorKind::Integrity, "blob publish");
            }
            return ApplicationError::new(store_error_kind(store_error), "blob publish");
        }
        *context.fatal = Some(NodeError::FatalBlobCoherence(
            "live Blob core adapter returned an unexpected error type".into(),
        ));
        return ApplicationError::new(ApplicationErrorKind::Integrity, "blob publish");
    }
    blob_core_error("blob publish", error)
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
        BlobError::Io(error) if error.kind() == std::io::ErrorKind::FileTooLarge => {
            ApplicationErrorKind::ResourceLimit
        }
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

    fn apply_scope_rekey(
        root: &TestRoot,
        services: &mut RekeyServices,
        epoch: u64,
        sequence: u64,
        previous: Option<[u8; 32]>,
    ) -> [u8; 32] {
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
                epoch,
                recipients,
                sequence,
                previous,
            )
            .expect("seal scope rekey");
        let verified = services
            .reader
            .verify_control(&sealed)
            .expect("verify scope rekey");
        let transfer_id = verified.envelope_id();
        let store =
            Store::open_for_mission(root.path().join(STORE_FILE), services.mission_authority)
                .expect("open Blob store for rekey");
        let outcome = store
            .ingest_verified_control(&verified, &sealed)
            .expect("commit scope rekey");
        assert_eq!(outcome.activated().len(), 1);
        assert_eq!(
            store
                .active_scope_epoch(&blob_scope())
                .expect("active epoch")
                .map(|(epoch, _)| epoch),
            Some(epoch)
        );
        transfer_id
    }

    fn apply_epoch_two_rekey(root: &TestRoot, services: &mut RekeyServices) {
        let _ = apply_scope_rekey(root, services, 2, 1, None);
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
    fn live_blob_page_is_bounded_exact_and_rejects_invalid_ranges() {
        let root = TestRoot::new("live-page");
        let bytes = payload(2 * SELECTED_BLOB_CHUNK_SIZE as usize + 73);
        let mut node = selected_node(&root);
        let published = node
            .publish(request(b"blob/live-page"), &mut Cursor::new(bytes.clone()))
            .expect("publish live page fixture");
        let blob = BlobReadRequest {
            id: published.id,
            topic: blob_topic(),
            scope: blob_scope(),
        };

        let offset = 31u64;
        let page = node
            .read_page(BlobReadPageRequest {
                blob: blob.clone(),
                offset,
                max_bytes: MAX_SELECTED_BLOB_PAGE_BYTES,
            })
            .expect("read cross-chunk live page");
        assert_eq!(page.len(), MAX_SELECTED_BLOB_PAGE_BYTES);
        assert_eq!(
            page.as_bytes(),
            &bytes[offset as usize..page.next_offset() as usize]
        );
        assert_eq!(
            page.next_offset(),
            offset + MAX_SELECTED_BLOB_PAGE_BYTES as u64
        );
        assert!(!page.complete);

        let final_offset = bytes.len() as u64 - 17;
        let final_page = node
            .read_page(BlobReadPageRequest {
                blob: blob.clone(),
                offset: final_offset,
                max_bytes: MAX_SELECTED_BLOB_PAGE_BYTES,
            })
            .expect("read final live page");
        assert_eq!(final_page.as_bytes(), &bytes[bytes.len() - 17..]);
        assert_eq!(final_page.next_offset(), bytes.len() as u64);
        assert!(final_page.complete);

        for (request, label) in [
            (
                BlobReadPageRequest {
                    blob: blob.clone(),
                    offset: 0,
                    max_bytes: 0,
                },
                "empty page",
            ),
            (
                BlobReadPageRequest {
                    blob: blob.clone(),
                    offset: 0,
                    max_bytes: MAX_SELECTED_BLOB_PAGE_BYTES + 1,
                },
                "oversized page",
            ),
            (
                BlobReadPageRequest {
                    blob: blob.clone(),
                    offset: u64::MAX,
                    max_bytes: 1,
                },
                "overflowing page",
            ),
            (
                BlobReadPageRequest {
                    blob: blob.clone(),
                    offset: bytes.len() as u64,
                    max_bytes: 1,
                },
                "past-end page",
            ),
        ] {
            let error = node.read_page(request).expect_err(label);
            assert_eq!(
                error.kind(),
                ApplicationErrorKind::InvalidRequest,
                "{label}"
            );
            assert_eq!(error.operation(), "blob read page", "{label}");
        }
    }

    #[test]
    fn live_blob_commands_reject_exactly_when_closed_or_saturated() {
        let request = BlobReadPageRequest {
            blob: BlobReadRequest {
                id: BlobId::from_bytes([7; 32]),
                topic: blob_topic(),
                scope: blob_scope(),
            },
            offset: 0,
            max_bytes: 1,
        };
        let (response, received) = oneshot::channel();
        SelectedBlobCommand::ReadPage {
            request: request.clone(),
            response,
        }
        .reject();
        let error = received
            .blocking_recv()
            .expect("closed command response")
            .expect_err("closed worker rejects");
        assert_eq!(error.kind(), ApplicationErrorKind::StateUnavailable);
        assert_eq!(error.operation(), "blob read page");

        let (response, received) = oneshot::channel();
        SelectedBlobCommand::ReadPage { request, response }.reject_resource_limit();
        let error = received
            .blocking_recv()
            .expect("saturated command response")
            .expect_err("saturated worker rejects");
        assert_eq!(error.kind(), ApplicationErrorKind::ResourceLimit);
        assert_eq!(error.operation(), "blob read page");
    }

    #[tokio::test]
    async fn live_blob_handle_rejects_oversized_request_before_enqueuing_file() {
        let root = TestRoot::new("live-handle-preflight");
        let source_path = root.path().join("source.bin");
        fs::write(&source_path, [1u8]).expect("write live handle source");
        let node = selected_node(&root);
        let identity = node.identity();
        let mission_authority = node.mission_authority();
        drop(node);
        let (commands, mut received) = mpsc::channel(1);
        let handle = SelectedBlobHandle::new(
            commands,
            Arc::new(AtomicBool::new(true)),
            identity,
            mission_authority,
        );

        let mut oversized_operation = request(b"blob/handle-operation");
        oversized_operation.operation_key = vec![1; MAX_BLOB_OPERATION_KEY_BYTES + 1];
        let mut oversized_media_type = request(b"blob/handle-media");
        oversized_media_type.media_type = Some("a".repeat(MAX_BLOB_MEDIA_TYPE_BYTES + 1));
        let mut oversized_schema = request(b"blob/handle-schema");
        oversized_schema.schema_id = vec![2; MAX_BLOB_SCHEMA_ID_BYTES + 1];

        for invalid in [oversized_operation, oversized_media_type, oversized_schema] {
            let source = fs::File::open(&source_path).expect("open live handle source");
            let error = handle
                .publish(invalid, source)
                .await
                .expect_err("oversized request must fail in handle preflight");
            assert_eq!(error.kind(), ApplicationErrorKind::InvalidRequest);
            assert_eq!(error.operation(), "blob publish");
            assert!(matches!(
                received.try_recv(),
                Err(mpsc::error::TryRecvError::Empty)
            ));
        }
    }

    #[test]
    fn live_blob_precommit_cache_poison_is_actor_fatal_and_drops_response() {
        let root = TestRoot::new("live-precommit-cache-poison");
        let source_path = root.path().join("source.bin");
        fs::write(&source_path, [1u8, 2, 3]).expect("write live poison source");
        let mut node = selected_node(&root);
        let cache = Arc::clone(&node.source_route_cache);
        let poison = std::thread::spawn(move || {
            let _lifecycle = cache
                .lock_blob_lifecycle()
                .expect("lock lifecycle before poisoning");
            panic!("deliberately poison live Blob lifecycle lock");
        });
        assert!(poison.join().is_err());

        let (response, received) = oneshot::channel();
        let command = SelectedBlobCommand::Publish {
            request: request(b"blob/live-precommit-cache-poison"),
            source: fs::File::open(&source_path).expect("open live poison source"),
            response,
        };
        let admission = AtomicBool::new(true);
        let error = node
            .execute_live(command, &admission)
            .expect_err("cache poison must escape the worker as actor-fatal");
        assert!(matches!(&error, NodeError::FatalBlobCoherence(_)));
        assert!(error.to_string().contains("lifecycle lock is poisoned"));
        assert!(received.blocking_recv().is_err());
        assert_eq!(
            node.store
                .blob_stats()
                .expect("post-poison Blob stats")
                .publications,
            0
        );
    }

    #[test]
    fn live_blob_corrupt_exact_retry_is_actor_fatal_and_drops_response() {
        let root = TestRoot::new("live-corrupt-retry-fatal");
        let source_path = root.path().join("live-corrupt-retry.bin");
        let bytes = payload(SELECTED_BLOB_CHUNK_SIZE as usize + 19);
        fs::write(&source_path, &bytes).expect("write corrupt-retry source");
        let request = request(b"blob/live-corrupt-retry");
        let mut node = selected_node(&root);
        node.publish_live(
            request.clone(),
            fs::File::open(&source_path).expect("open initial live source"),
        )
        .expect("publish corrupt-retry fixture");

        let chunk = first_chunk_file(&root.depot_path());
        let mut encoded = fs::read(&chunk).expect("read corrupt-retry chunk");
        *encoded.last_mut().expect("nonempty corrupt-retry chunk") ^= 0x80;
        fs::write(&chunk, encoded).expect("corrupt exact committed chunk");

        let admission = AtomicBool::new(true);
        let (response, received) = oneshot::channel();
        let command = SelectedBlobCommand::Publish {
            request,
            source: fs::File::open(&source_path).expect("open retry live source"),
            response,
        };
        let error = node
            .execute_live(command, &admission)
            .expect_err("corrupt exact retry must stop its Blob worker");
        assert!(matches!(error, NodeError::FatalBlobCoherence(_)));
        assert!(
            received.blocking_recv().is_err(),
            "fatal exact retry must drop its application response"
        );
    }

    #[test]
    fn live_blob_depot_quota_is_ordinary_resource_limit() {
        let root = TestRoot::new("live-depot-quota-ordinary");
        persist_member_mission(&root);
        let source_path = root.path().join("live-depot-quota.bin");
        fs::write(&source_path, [0x51; 128]).expect("write quota source");
        let mut node = SelectedBlobNode::open_unprotected_reference_with_options(
            root.path(),
            root.mission_path(),
            SelectedBlobOptions {
                depot_limits: BlobDepotLimits::new(1, 4, 1).expect("tiny depot limits"),
            },
        )
        .expect("open tiny-depot Blob node");
        let admission = AtomicBool::new(true);
        let (response, received) = oneshot::channel();
        node.execute_live(
            SelectedBlobCommand::Publish {
                request: request(b"blob/live-depot-quota"),
                source: fs::File::open(source_path).expect("open quota source"),
                response,
            },
            &admission,
        )
        .expect("depot quota must not stop the Blob worker");
        let error = received
            .blocking_recv()
            .expect("quota response")
            .expect_err("tiny depot must reject publication");
        assert_eq!(error.kind(), ApplicationErrorKind::ResourceLimit);
    }

    #[test]
    fn live_blob_orphan_preflights_are_actor_fatal_but_absence_is_ordinary() {
        let publish_root = TestRoot::new("live-orphan-operation");
        let source_path = publish_root.path().join("source.bin");
        fs::write(&source_path, [1u8, 2, 3]).expect("write orphan-operation source");
        let mut publish_node = selected_node(&publish_root);
        publish_node.live_operation_preflight_coherence_fault = true;
        let (response, received) = oneshot::channel();
        let publish_command = SelectedBlobCommand::Publish {
            request: request(b"blob/live-orphan-operation"),
            source: fs::File::open(&source_path).expect("open orphan-operation source"),
            response,
        };
        let admission = AtomicBool::new(true);
        let error = publish_node
            .execute_live(publish_command, &admission)
            .expect_err("orphan operation must escape actor-fatal");
        assert!(matches!(error, NodeError::FatalBlobCoherence(_)));
        assert!(received.blocking_recv().is_err());
        assert_eq!(
            publish_node
                .store
                .blob_stats()
                .expect("orphan-operation stats")
                .publications,
            0
        );

        let read_root = TestRoot::new("live-orphan-content");
        let mut read_node = selected_node(&read_root);
        read_node.live_read_projection_coherence_fault = true;
        let missing = BlobReadPageRequest {
            blob: BlobReadRequest {
                id: BlobId::from_bytes([0x91; 32]),
                topic: blob_topic(),
                scope: blob_scope(),
            },
            offset: 0,
            max_bytes: 1,
        };
        let (response, received) = oneshot::channel();
        let error = read_node
            .execute_live(
                SelectedBlobCommand::ReadPage {
                    request: missing.clone(),
                    response,
                },
                &admission,
            )
            .expect_err("orphan content index must escape actor-fatal");
        assert!(matches!(error, NodeError::FatalBlobCoherence(_)));
        assert!(received.blocking_recv().is_err());

        let absent_root = TestRoot::new("live-absent-content");
        let mut absent_node = selected_node(&absent_root);
        let (response, received) = oneshot::channel();
        absent_node
            .execute_live(
                SelectedBlobCommand::ReadPage {
                    request: missing,
                    response,
                },
                &admission,
            )
            .expect("absent Blob is an ordinary application result");
        let absent = received
            .blocking_recv()
            .expect("absent Blob response")
            .expect_err("absent Blob cannot return plaintext");
        assert_eq!(absent.kind(), ApplicationErrorKind::UnauthorizedOrRevoked);
    }

    #[test]
    fn live_blob_selected_load_policy_race_is_ordinary_and_discloses_no_page() {
        let root = TestRoot::new("live-selected-load-policy-race");
        let bytes = payload(SELECTED_BLOB_CHUNK_SIZE as usize + 9);
        let mut node = selected_node(&root);
        let published = node
            .publish(
                request(b"blob/live-selected-load-policy-race"),
                &mut Cursor::new(bytes),
            )
            .expect("publish selected-load race fixture");
        node.live_selected_load_policy_race_fault = true;
        let admission = AtomicBool::new(true);
        let (response, received) = oneshot::channel();
        node.execute_live(
            SelectedBlobCommand::ReadPage {
                request: BlobReadPageRequest {
                    blob: BlobReadRequest {
                        id: published.id,
                        topic: blob_topic(),
                        scope: blob_scope(),
                    },
                    offset: 0,
                    max_bytes: 1,
                },
                response,
            },
            &admission,
        )
        .expect("selected-load control race must not stop the Blob worker");
        let error = received
            .blocking_recv()
            .expect("selected-load race response")
            .expect_err("selected-load race cannot disclose a page");
        assert_eq!(error.kind(), ApplicationErrorKind::PolicyUnsettled);
    }

    #[test]
    fn live_blob_durable_coherence_classifier_is_narrow() {
        for fatal in [
            BlobStoreError::SchemaInvariant("test invariant"),
            BlobStoreError::DepotIntegrity("test depot invariant"),
            BlobStoreError::CompletionMismatch,
        ] {
            assert!(live_blob_durable_coherence_error(&StoreError::Blob(fatal)));
        }
        for ordinary in [
            BlobStoreError::OperationConflict,
            BlobStoreError::PublisherRevoked([0x44; 32]),
            BlobStoreError::KeyEpochStale {
                current: 2,
                received: 1,
            },
            BlobStoreError::KeyEpochNotActive {
                current: 1,
                received: 2,
            },
            BlobStoreError::ReadPlanChanged,
            BlobStoreError::PublicationLimitExceeded {
                current: 1,
                limit: 1,
            },
            BlobStoreError::PhysicalLineageConflict,
            BlobStoreError::PhysicalLineageMigrationRequired,
        ] {
            assert!(!live_blob_durable_coherence_error(&StoreError::Blob(
                ordinary
            )));
        }
    }

    #[test]
    fn live_blob_page_closes_after_waiting_for_final_lifecycle_check() {
        let root = TestRoot::new("page-final-close");
        let bytes = payload(SELECTED_BLOB_CHUNK_SIZE as usize + 19);
        let mut node = selected_node(&root);
        let published = node
            .publish(request(b"blob/page-final-close"), &mut Cursor::new(bytes))
            .expect("publish final-close fixture");
        let reached = Arc::new(std::sync::Barrier::new(2));
        let release = Arc::new(std::sync::Barrier::new(2));
        node.set_final_read_gate(Arc::clone(&reached), Arc::clone(&release));
        let cache = Arc::clone(&node.source_route_cache);
        let admission = Arc::new(AtomicBool::new(true));
        let worker_admission = Arc::clone(&admission);
        let (response, received) = oneshot::channel();
        let command = SelectedBlobCommand::ReadPage {
            request: BlobReadPageRequest {
                blob: BlobReadRequest {
                    id: published.id,
                    topic: blob_topic(),
                    scope: blob_scope(),
                },
                offset: 7,
                max_bytes: 31,
            },
            response,
        };
        let worker = std::thread::spawn(move || {
            node.execute_live(command, &worker_admission)
                .expect("closed page is an ordinary rejection")
        });

        reached.wait();
        let lifecycle = cache
            .lock_blob_lifecycle()
            .expect("hold final Blob lifecycle");
        admission.store(false, Ordering::Release);
        release.wait();
        drop(lifecycle);
        worker.join().expect("join live Blob page worker");
        let error = received
            .blocking_recv()
            .expect("closed final page response")
            .expect_err("closed final page cannot disclose plaintext");
        assert_eq!(error.kind(), ApplicationErrorKind::StateUnavailable);
        assert_eq!(error.operation(), "blob read page");
    }

    #[test]
    fn live_blob_file_requires_zero_cursor_and_growth_cannot_cross_ceiling() {
        let root = TestRoot::new("live-file-boundary");
        let source_path = root.path().join("source.bin");
        fs::write(&source_path, [1u8, 2, 3]).expect("write live source");
        let mut source = fs::File::open(&source_path).expect("open live source");
        source
            .seek(std::io::SeekFrom::Start(1))
            .expect("pre-seek live source");
        let mut node = selected_node(&root);
        let error = node
            .publish_live(request(b"blob/live-preseek"), source)
            .expect_err("pre-seeked live file must fail");
        assert_eq!(error.kind(), ApplicationErrorKind::InvalidRequest);

        let mut source = fs::OpenOptions::new()
            .read(true)
            .write(true)
            .open(&source_path)
            .expect("open growing source");
        source
            .set_len(MAX_SELECTED_LIVE_BLOB_BYTES)
            .expect("set bounded sparse length");
        let grower = source.try_clone().expect("clone growing source");
        grower
            .set_len(MAX_SELECTED_LIVE_BLOB_BYTES + 1)
            .expect("grow sparse source past live ceiling");
        let admission = AtomicBool::new(true);
        let mut admitted = AdmittedFile {
            file: &mut source,
            admission: &admission,
            max_len: MAX_SELECTED_LIVE_BLOB_BYTES,
            pass_two_gate: None,
            expected_len: MAX_SELECTED_LIVE_BLOB_BYTES,
            total_bytes_read: 0,
        };
        let error = admitted
            .seek(std::io::SeekFrom::End(0))
            .expect_err("growth past live ceiling must fail before hashing");
        assert_eq!(error.kind(), std::io::ErrorKind::FileTooLarge);
        drop(admitted);
        let oversized = fs::File::open(&source_path).expect("reopen oversized live source");
        let error = node
            .publish_live(request(b"blob/live-oversized"), oversized)
            .expect_err("oversized live file must fail with its public category");
        assert_eq!(error.kind(), ApplicationErrorKind::ResourceLimit);
        assert_eq!(error.operation(), "blob publish");
        let streamed_growth = blob_core_error(
            "blob publish",
            BlobError::Io(std::io::Error::new(
                std::io::ErrorKind::FileTooLarge,
                "simulated concurrent live source growth",
            )),
        );
        assert_eq!(streamed_growth.kind(), ApplicationErrorKind::ResourceLimit);
    }

    #[test]
    fn live_blob_second_pass_change_leaves_only_bounded_unfinalized_staging() {
        let root = TestRoot::new("live-second-pass-change");
        persist_member_mission(&root);
        let limits = BlobDepotLimits::new(1_000_000, 4, 1).expect("bounded test depot limits");
        let options = SelectedBlobOptions {
            depot_limits: limits,
        };
        let source_path = root.path().join("source.bin");
        let bytes = payload(2 * SELECTED_BLOB_CHUNK_SIZE as usize + 31);
        fs::write(&source_path, &bytes).expect("write mutable live source");
        let source = fs::File::open(&source_path).expect("open mutable live source");
        let reached = Arc::new(std::sync::Barrier::new(2));
        let release = Arc::new(std::sync::Barrier::new(2));
        let mut node = SelectedBlobNode::open_unprotected_reference_with_options(
            root.path(),
            root.mission_path(),
            options,
        )
        .expect("open bounded live Blob node");
        node.set_live_publish_pass_two_gate(Arc::clone(&reached), Arc::clone(&release));

        let mutate_path = source_path.clone();
        let changed_offset = u64::from(SELECTED_BLOB_CHUNK_SIZE) + 17;
        let changed_byte = bytes[usize::try_from(changed_offset).expect("mutation offset")] ^ 0x80;
        let mutator = std::thread::spawn(move || {
            reached.wait();
            let mut file = fs::OpenOptions::new()
                .read(true)
                .write(true)
                .open(mutate_path)
                .expect("open second-pass mutation handle");
            file.seek(std::io::SeekFrom::Start(changed_offset))
                .expect("seek second-pass mutation");
            file.write_all(&[changed_byte])
                .expect("mutate later plaintext chunk");
            file.sync_data().expect("sync later plaintext mutation");
            release.wait();
        });

        let error = node
            .publish_live(request(b"blob/live-second-pass-change"), source)
            .expect_err("second-pass source mutation must fail closed");
        mutator.join().expect("join second-pass mutator");
        assert_eq!(error.kind(), ApplicationErrorKind::Conflict);
        assert_eq!(error.operation(), "blob publish");

        let staged = node.store.blob_stats().expect("abandoned staging stats");
        assert_eq!(staged.publications, 0);
        assert_eq!(staged.acceptance_markers, 0);
        assert_eq!(staged.operations, 0);
        assert_eq!(staged.variants, 1);
        assert_eq!(staged.finalized_variants, 0);
        assert_eq!(staged.committed_chunks, 1);
        assert!(staged.committed_file_bytes <= limits.max_bytes());
        assert!(staged.reserved_file_bytes <= limits.max_bytes());
        assert!(staged.committed_chunks <= limits.max_chunks());
        assert!(staged.variants <= limits.max_variants());
        assert!(
            node.store
                .blob_inventory()
                .expect("empty inventory")
                .is_empty()
        );
        drop(node);

        let reopened = SelectedBlobNode::open_unprotected_reference_with_options(
            root.path(),
            root.mission_path(),
            options,
        )
        .expect("reopen bounded staging");
        assert_eq!(
            reopened.store.blob_stats().expect("reopened staging stats"),
            staged,
            "restart preserves charged, unfinalized staging without making it visible"
        );
        assert!(
            reopened
                .store
                .blob_inventory()
                .expect("reopened empty inventory")
                .is_empty()
        );
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
            let current = node
                .store
                .load_blob_read_candidate_with_policy(&policy, current)
                .expect("exact-load selected publication");
            assert_eq!(read.publisher_counter, current.header.stamp.dot.counter);
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
            BlobError::Store(Box::new(std::io::Error::other(
                "provider-sanitized adapter failure",
            ))),
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
        let candidate = plan
            .candidates()
            .iter()
            .find(|candidate| candidate.disposition().is_none())
            .expect("inactive epoch-one source publication");
        let mut tampered = node
            .store
            .load_blob_read_candidate_with_policy(&policy, candidate)
            .expect("exact-load inactive source publication");
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
    fn live_blob_claims_survive_intermediate_same_epoch_lineage_and_reopen() {
        let root = TestRoot::new("three-lineage-reopen");
        let mut services = persist_rekey_mission(&root);
        let bytes = payload(SELECTED_BLOB_CHUNK_SIZE as usize + 211);
        let first_request = request(b"blob/three-epoch/one");
        let mut middle_request = request(b"blob/three-epoch/two");
        // A same-epoch replacement needs a distinct immutable variant; priority
        // changes only envelope semantics and does not affect Blob identity, so
        // vary authenticated schema metadata as well as the semantic priority.
        middle_request.priority = Priority::Flash;
        middle_request.schema_id = b"schema/blob-v2".to_vec();
        let current_request = request(b"blob/three-epoch/three");

        let first = {
            let mut node =
                SelectedBlobNode::open_unprotected_reference(root.path(), root.mission_path())
                    .expect("open epoch-one Blob node");
            node.publish(first_request.clone(), &mut Cursor::new(bytes.clone()))
                .expect("publish epoch-one Blob")
        };
        let second_lineage = apply_scope_rekey(&root, &mut services, 1, 1, None);
        let middle = {
            let mut node =
                SelectedBlobNode::open_unprotected_reference(root.path(), root.mission_path())
                    .expect("open second-lineage Blob node");
            let retry = node
                .publish(first_request.clone(), &mut Cursor::new(bytes.clone()))
                .expect("claim-only first-lineage retry after replacement");
            assert!(!retry.inserted);
            node.publish(middle_request.clone(), &mut Cursor::new(bytes.clone()))
                .expect("publish second-lineage Blob")
        };
        let _third_lineage = apply_scope_rekey(&root, &mut services, 2, 2, Some(second_lineage));

        let current = {
            let mut node =
                SelectedBlobNode::open_unprotected_reference(root.path(), root.mission_path())
                    .expect("open third-lineage Blob node");
            let inventory = node
                .store
                .blob_inventory()
                .expect("third-lineage inventory");
            let middle_stored = inventory
                .into_iter()
                .find_map(|transfer_id| {
                    let stored = node
                        .store
                        .get_blob(transfer_id)
                        .expect("load third-lineage stored Blob")
                        .expect("inventory Blob must exist");
                    (stored.header.stamp.dot.counter == middle.publisher_counter).then_some(stored)
                })
                .expect("middle lineage stored Blob");
            let (middle_projection, middle_retention) = node
                .completed_projection(&middle_stored, "blob retry lineage test")
                .expect("middle lineage projection");
            assert_eq!(middle_stored.header.key_epoch, 1);
            assert_eq!(
                node.active_epoch(&blob_scope(), "blob retry lineage test")
                    .expect("third-lineage active epoch"),
                2
            );
            assert!(
                node.source_route_cache
                    .is_current_blob_source_projection(
                        &node.verifier,
                        &middle_projection,
                        middle_retention,
                    )
                    .expect("middle lineage exact cached claim"),
                "middle epoch-one lineage remains provider-current inside its old epoch"
            );
            for (request, expected) in [
                (first_request.clone(), &first),
                (middle_request.clone(), &middle),
            ] {
                let retry = node
                    .publish(request, &mut Cursor::new(bytes.clone()))
                    .expect("claim-only historical retry at third lineage");
                assert!(!retry.inserted);
                assert_eq!(retry.publisher_counter, expected.publisher_counter);
                assert_eq!(retry.acceptance_marker, expected.acceptance_marker);
            }
            let inactive = node
                .read_page(BlobReadPageRequest {
                    blob: BlobReadRequest {
                        id: first.id,
                        topic: blob_topic(),
                        scope: blob_scope(),
                    },
                    offset: 0,
                    max_bytes: 32,
                })
                .expect_err("noncurrent plan-selected source cannot disclose plaintext");
            assert_eq!(inactive.kind(), ApplicationErrorKind::UnauthorizedOrRevoked);
            let current = node
                .publish(current_request, &mut Cursor::new(bytes.clone()))
                .expect("publish third-lineage Blob");
            let page = node
                .read_page(BlobReadPageRequest {
                    blob: BlobReadRequest {
                        id: first.id,
                        topic: blob_topic(),
                        scope: blob_scope(),
                    },
                    offset: 29,
                    max_bytes: 97,
                })
                .expect("read current third-lineage page");
            assert_eq!(page.as_bytes(), &bytes[29..126]);
            current
        };

        let mut reopened =
            SelectedBlobNode::open_unprotected_reference(root.path(), root.mission_path())
                .expect("reopen third-lineage Blob node");
        for (request, expected) in [(first_request, first), (middle_request, middle)] {
            let retry = reopened
                .publish(request, &mut Cursor::new(bytes.clone()))
                .expect("reopened claim-only historical retry");
            assert!(!retry.inserted);
            assert_eq!(retry.publisher_counter, expected.publisher_counter);
            assert_eq!(retry.acceptance_marker, expected.acceptance_marker);
        }
        let page = reopened
            .read_page(BlobReadPageRequest {
                blob: BlobReadRequest {
                    id: current.id,
                    topic: blob_topic(),
                    scope: blob_scope(),
                },
                offset: SELECTED_BLOB_CHUNK_SIZE as u64 - 11,
                max_bytes: 64,
            })
            .expect("reopened third-lineage live page");
        let offset = SELECTED_BLOB_CHUNK_SIZE as usize - 11;
        assert_eq!(page.as_bytes(), &bytes[offset..offset + 64]);
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
