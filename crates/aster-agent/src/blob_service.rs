use std::{path::Path, sync::Arc};

use aster_mesh::{MAX_BLOB_MEDIA_TYPE_BYTES, MAX_BLOB_SCHEMA_ID_BYTES};
use aster_node::application::{
    ApplicationErrorKind, BlobId, BlobPublishOptions, BlobPublishRequest as NodeBlobPublishRequest,
    BlobPublishResult, BlobPublishStreamRequest, BlobReadPage, BlobReadPageRequest,
    BlobReadRequest as NodeBlobReadRequest, BlobReadStreamMetadata, Priority, Scope,
    SelectedBlobHandle, SelectedBlobReadStream, Topic,
};
use aster_redb_store::MAX_BLOB_OPERATION_KEY_BYTES;
use connectrpc::{ConnectError, ErrorCode, RequestContext, Response, ServiceResult, ServiceStream};
use futures::StreamExt as _;
use zeroize::Zeroizing;

use crate::{
    BLOB_RPC_FRAME_BYTES, BLOB_RPC_READ_FRAME_BYTES, api,
    error::{PublicOperation, connect_blob_application_error, public_error},
};

const UPLOAD_PERMITS: usize = 1;

#[derive(Clone)]
pub(crate) struct BlobConnectService {
    blobs: SelectedBlobHandle,
    max_publish_bytes: u64,
    uploads: Arc<tokio::sync::Semaphore>,
}

impl BlobConnectService {
    pub(crate) fn new(blobs: SelectedBlobHandle, state_root: &Path) -> std::io::Result<Self> {
        let _ = state_root;
        let max_publish_bytes = blobs.max_publish_bytes();
        Ok(Self {
            blobs,
            max_publish_bytes,
            uploads: Arc::new(tokio::sync::Semaphore::new(UPLOAD_PERMITS)),
        })
    }

    pub(crate) async fn publish(
        &self,
        ctx: RequestContext,
        mut requests: connectrpc::InboundStream<api::PublishBlobRequest>,
    ) -> ServiceResult<api::PublishBlobResponse> {
        let operation = PublicOperation::PublishBlob;
        if ctx.protocol() == Some(connectrpc::Protocol::GrpcWeb) {
            return Err(unsupported_transport(operation));
        }
        let first = requests
            .next()
            .await
            .ok_or_else(|| malformed(operation))?
            .map_err(|_| malformed(operation))?
            .to_owned_message();
        let (parsed, mut grammar) = UploadGrammar::start(first, self.max_publish_bytes)?;
        let _permit = Arc::clone(&self.uploads)
            .try_acquire_owned()
            .map_err(|_| resource_exhausted(operation))?;
        let mut stream = self
            .blobs
            .open_publish_stream(BlobPublishStreamRequest {
                publication: parsed.request,
                options: parsed.options,
                total_len: grammar.total_len,
            })
            .await
            .map_err(|error| connect_blob_application_error(error, operation))?;
        let mut offset = stream.durable_offset();

        while let Some(frame) = requests.next().await {
            let frame = frame.map_err(|_| malformed(operation))?.to_owned_message();
            let chunk = Zeroizing::new(grammar.accept(frame)?);
            let progress = stream
                .write(offset, chunk)
                .await
                .map_err(|error| connect_blob_application_error(error, operation))?;
            offset = progress.accepted_offset;
        }
        grammar.finish()?;
        let result = stream
            .finish()
            .await
            .map_err(|error| connect_blob_application_error(error, operation))?;
        Ok(publish_response(result).into())
    }

    pub(crate) async fn read(
        &self,
        request: api::ReadBlobRequest,
    ) -> ServiceResult<ServiceStream<api::ReadBlobResponse>> {
        let operation = PublicOperation::ReadBlob;
        let (request, topic, scope) = parse_read_request(request)?;
        let mut stream = match self.blobs.open_read_stream(request.clone()).await {
            Ok(stream) => stream,
            Err(error) if error.kind() == ApplicationErrorKind::NotFound => {
                return legacy_read_stream(self.blobs.clone(), request, topic, scope);
            }
            Err(error) => return Err(connect_blob_application_error(error, operation)),
        };
        let metadata = ReadMetadata::from_stream(stream.metadata());
        let pending = stream
            .next(BLOB_RPC_READ_FRAME_BYTES)
            .await
            .map_err(|error| connect_blob_application_error(error, operation))?
            .ok_or_else(|| internal(operation))?;
        if pending.offset != 0 || pending.bytes.is_empty() {
            return Err(internal(operation));
        }
        let state = ReadStreamState {
            stream,
            pending,
            metadata,
            complete: false,
        };
        let responses = futures::stream::try_unfold(state, move |mut state| async move {
            if state.complete {
                return Ok(None);
            }
            let next = state
                .stream
                .next(BLOB_RPC_READ_FRAME_BYTES)
                .await
                .map_err(|error| connect_blob_application_error(error, operation))?;
            let complete = next.is_none();
            let following_offset = next.as_ref().map(|frame| frame.offset);
            let frame = std::mem::replace(
                &mut state.pending,
                next.unwrap_or_else(|| aster_node::application::BlobReadFrame {
                    offset: state.metadata.total_len,
                    bytes: Zeroizing::new(Vec::new()),
                }),
            );
            let end = frame
                .offset
                .checked_add(frame.bytes.len() as u64)
                .ok_or_else(|| internal(operation))?;
            if frame.bytes.is_empty()
                || end > state.metadata.total_len
                || complete != (end == state.metadata.total_len)
                || following_offset.is_some_and(|offset| offset != end)
            {
                return Err(internal(operation));
            }
            state.complete = complete;
            let response = read_response(
                &state.metadata,
                frame.offset,
                frame.bytes.to_vec(),
                complete,
            );
            Ok(Some((response, state)))
        });
        Response::stream_ok(responses)
    }
}

#[derive(Debug)]
struct ParsedPublish {
    request: NodeBlobPublishRequest,
    options: BlobPublishOptions,
}

#[derive(Debug)]
struct UploadGrammar {
    total_len: u64,
    received: u64,
    frames: u64,
    maximum_frames: u64,
}

impl UploadGrammar {
    fn start(
        first: api::PublishBlobRequest,
        max_publish_bytes: u64,
    ) -> Result<(ParsedPublish, Self), ConnectError> {
        let operation = PublicOperation::PublishBlob;
        let api::publish_blob_request::Frame::Metadata(metadata) =
            first.frame.ok_or_else(|| malformed(operation))?
        else {
            return Err(malformed(operation));
        };
        if metadata.total_len == 0 {
            return Err(malformed(operation));
        }
        if metadata.total_len > max_publish_bytes {
            return Err(resource_exhausted(operation));
        }
        if metadata.operation_key.is_empty()
            || metadata.operation_key.len() > MAX_BLOB_OPERATION_KEY_BYTES
            || metadata
                .media_type
                .as_ref()
                .is_some_and(|value| value.is_empty() || value.len() > MAX_BLOB_MEDIA_TYPE_BYTES)
            || metadata.schema_id.len() > MAX_BLOB_SCHEMA_ID_BYTES
        {
            return Err(malformed(operation));
        }
        let priority = parse_priority(metadata.priority, operation)?;
        let topic = Topic::new(metadata.topic).map_err(|_| malformed(operation))?;
        let scope = Scope::new(metadata.scope).map_err(|_| malformed(operation))?;
        let options = match metadata.ttl_ms {
            None => BlobPublishOptions::durable(),
            Some(0) => return Err(malformed(operation)),
            Some(ttl_ms) => {
                BlobPublishOptions::finite_ttl_ms(ttl_ms).map_err(|_| malformed(operation))?
            }
        };
        let maximum_frames = maximum_chunk_frames_for_len(metadata.total_len)?;
        Ok((
            ParsedPublish {
                request: NodeBlobPublishRequest {
                    operation_key: metadata.operation_key,
                    topic,
                    scope,
                    priority,
                    media_type: metadata.media_type,
                    schema_id: metadata.schema_id,
                },
                options,
            },
            Self {
                total_len: metadata.total_len,
                received: 0,
                frames: 0,
                maximum_frames,
            },
        ))
    }

    fn accept(&mut self, frame: api::PublishBlobRequest) -> Result<Vec<u8>, ConnectError> {
        let operation = PublicOperation::PublishBlob;
        let api::publish_blob_request::Frame::Chunk(chunk) =
            frame.frame.ok_or_else(|| malformed(operation))?
        else {
            return Err(malformed(operation));
        };
        if chunk.is_empty() || chunk.len() > BLOB_RPC_FRAME_BYTES {
            return Err(malformed(operation));
        }
        let chunk_len = u64::try_from(chunk.len()).map_err(|_| malformed(operation))?;
        let remaining = self
            .total_len
            .checked_sub(self.received)
            .ok_or_else(|| malformed(operation))?;
        let canonical_len = remaining.min(BLOB_RPC_FRAME_BYTES as u64);
        if chunk_len != canonical_len {
            return Err(malformed(operation));
        }
        self.received = self
            .received
            .checked_add(chunk_len)
            .ok_or_else(|| malformed(operation))?;
        self.frames = self
            .frames
            .checked_add(1)
            .ok_or_else(|| malformed(operation))?;
        if self.frames > self.maximum_frames {
            return Err(malformed(operation));
        }
        Ok(chunk)
    }

    fn finish(self) -> Result<(), ConnectError> {
        if self.received == self.total_len && self.frames == self.maximum_frames {
            Ok(())
        } else {
            Err(malformed(PublicOperation::PublishBlob))
        }
    }
}

fn maximum_chunk_frames_for_len(total_len: u64) -> Result<u64, ConnectError> {
    let operation = PublicOperation::PublishBlob;
    let chunk_bytes = u64::try_from(BLOB_RPC_FRAME_BYTES).map_err(|_| internal(operation))?;
    total_len
        .checked_sub(1)
        .and_then(|value| value.checked_div(chunk_bytes))
        .and_then(|value| value.checked_add(1))
        .ok_or_else(|| malformed(operation))
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct ReadMetadata {
    id: [u8; 32],
    publisher: [u8; 32],
    publisher_counter: u64,
    topic: String,
    scope: String,
    priority: Priority,
    ttl_ms: Option<u64>,
    total_len: u64,
    media_type: Option<String>,
    schema_id: Vec<u8>,
    acceptance_marker: u64,
}

impl ReadMetadata {
    fn from_page(page: &BlobReadPage, topic: &str, scope: &str) -> Self {
        Self {
            id: *page.id.as_bytes(),
            publisher: page.publisher,
            publisher_counter: page.publisher_counter,
            topic: topic.to_owned(),
            scope: scope.to_owned(),
            priority: page.priority,
            ttl_ms: page.ttl_ms,
            total_len: page.total_len,
            media_type: page.media_type.clone(),
            schema_id: page.schema_id.clone(),
            acceptance_marker: page.acceptance_marker,
        }
    }

    fn from_stream(metadata: &BlobReadStreamMetadata) -> Self {
        Self {
            id: *metadata.id.as_bytes(),
            publisher: metadata.publisher,
            publisher_counter: metadata.publisher_counter,
            topic: metadata.topic.as_str().to_owned(),
            scope: metadata.scope.as_str().to_owned(),
            priority: metadata.priority,
            ttl_ms: metadata.ttl_ms,
            total_len: metadata.total_len,
            media_type: metadata.media_type.clone(),
            schema_id: metadata.schema_id.clone(),
            acceptance_marker: metadata.acceptance_marker,
        }
    }
}

struct ReadStreamState {
    stream: SelectedBlobReadStream,
    pending: aster_node::application::BlobReadFrame,
    metadata: ReadMetadata,
    complete: bool,
}

struct LegacyReadStreamState {
    blobs: SelectedBlobHandle,
    request: NodeBlobReadRequest,
    topic: String,
    scope: String,
    offset: u64,
    metadata: Option<ReadMetadata>,
    complete: bool,
}

fn legacy_read_stream(
    blobs: SelectedBlobHandle,
    request: NodeBlobReadRequest,
    topic: String,
    scope: String,
) -> ServiceResult<ServiceStream<api::ReadBlobResponse>> {
    let operation = PublicOperation::ReadBlob;
    let state = LegacyReadStreamState {
        blobs,
        request,
        topic,
        scope,
        offset: 0,
        metadata: None,
        complete: false,
    };
    let responses = futures::stream::try_unfold(state, move |mut state| async move {
        if state.complete {
            return Ok(None);
        }
        let page = state
            .blobs
            .read_page(BlobReadPageRequest {
                blob: state.request.clone(),
                offset: state.offset,
                max_bytes: BLOB_RPC_READ_FRAME_BYTES,
            })
            .await
            .map_err(|error| connect_blob_application_error(error, operation))?;
        if page.offset != state.offset || page.is_empty() {
            return Err(internal(operation));
        }
        let observed = ReadMetadata::from_page(&page, &state.topic, &state.scope);
        if let Some(expected) = &state.metadata {
            ensure_stable_read_metadata(expected, &observed)?;
        } else {
            state.metadata = Some(observed.clone());
        }
        let next_offset = page.next_offset();
        let complete = page.complete;
        let page_len = u64::try_from(page.len()).map_err(|_| internal(operation))?;
        if page.offset.checked_add(page_len) != Some(next_offset)
            || page.len() > BLOB_RPC_READ_FRAME_BYTES
            || complete != (next_offset == observed.total_len)
        {
            return Err(internal(operation));
        }
        let metadata = state.metadata.as_ref().ok_or_else(|| internal(operation))?;
        let response = read_response(metadata, page.offset, page.as_bytes().to_vec(), complete);
        if next_offset <= state.offset || next_offset > observed.total_len {
            return Err(internal(operation));
        }
        state.offset = next_offset;
        state.complete = complete;
        Ok(Some((response, state)))
    });
    Response::stream_ok(responses)
}

fn ensure_stable_read_metadata(
    expected: &ReadMetadata,
    observed: &ReadMetadata,
) -> Result<(), ConnectError> {
    if expected == observed {
        Ok(())
    } else {
        Err(internal(PublicOperation::ReadBlob))
    }
}

fn parse_read_request(
    request: api::ReadBlobRequest,
) -> Result<(NodeBlobReadRequest, String, String), ConnectError> {
    let operation = PublicOperation::ReadBlob;
    let id: [u8; 32] = request
        .id
        .as_slice()
        .try_into()
        .map_err(|_| malformed(operation))?;
    let topic = Topic::new(request.topic).map_err(|_| malformed(operation))?;
    let scope = Scope::new(request.scope).map_err(|_| malformed(operation))?;
    let topic_name = topic.as_str().to_owned();
    let scope_name = scope.as_str().to_owned();
    Ok((
        NodeBlobReadRequest {
            id: BlobId::from_bytes(id),
            topic,
            scope,
        },
        topic_name,
        scope_name,
    ))
}

fn publish_response(result: BlobPublishResult) -> api::PublishBlobResponse {
    api::PublishBlobResponse {
        id: result.id.as_bytes().to_vec(),
        publisher: result.publisher.to_vec(),
        publisher_counter: result.publisher_counter,
        priority: priority_message(result.priority).into(),
        ttl_ms: result.ttl_ms,
        total_len: result.total_len,
        media_type: result.media_type,
        schema_id: result.schema_id,
        acceptance_marker: result.acceptance_marker,
        inserted: result.inserted,
        ..Default::default()
    }
}

fn read_response(
    metadata: &ReadMetadata,
    offset: u64,
    chunk: Vec<u8>,
    complete: bool,
) -> api::ReadBlobResponse {
    api::ReadBlobResponse {
        id: metadata.id.to_vec(),
        publisher: metadata.publisher.to_vec(),
        publisher_counter: metadata.publisher_counter,
        topic: metadata.topic.clone(),
        scope: metadata.scope.clone(),
        priority: priority_message(metadata.priority).into(),
        ttl_ms: metadata.ttl_ms,
        total_len: metadata.total_len,
        media_type: metadata.media_type.clone(),
        schema_id: metadata.schema_id.clone(),
        acceptance_marker: metadata.acceptance_marker,
        offset,
        chunk,
        complete,
        ..Default::default()
    }
}

fn parse_priority(
    value: buffa::EnumValue<api::Priority>,
    operation: PublicOperation,
) -> Result<Priority, ConnectError> {
    match value.as_known() {
        Some(api::Priority::Routine) => Ok(Priority::Routine),
        Some(api::Priority::Priority) => Ok(Priority::Priority),
        Some(api::Priority::Immediate) => Ok(Priority::Immediate),
        Some(api::Priority::Flash) => Ok(Priority::Flash),
        Some(api::Priority::Unspecified) | None => Err(unsupported_value(operation)),
    }
}

const fn priority_message(priority: Priority) -> api::Priority {
    match priority {
        Priority::Routine => api::Priority::Routine,
        Priority::Priority => api::Priority::Priority,
        Priority::Immediate => api::Priority::Immediate,
        Priority::Flash => api::Priority::Flash,
    }
}

fn malformed(operation: PublicOperation) -> ConnectError {
    public_error(
        ErrorCode::InvalidArgument,
        api::PublicErrorReason::MalformedInput,
        operation,
        false,
        None,
    )
}

fn unsupported_value(operation: PublicOperation) -> ConnectError {
    public_error(
        ErrorCode::InvalidArgument,
        api::PublicErrorReason::UnsupportedValue,
        operation,
        false,
        None,
    )
}

fn unsupported_transport(operation: PublicOperation) -> ConnectError {
    public_error(
        ErrorCode::Unimplemented,
        api::PublicErrorReason::UnsupportedValue,
        operation,
        false,
        None,
    )
}

fn resource_exhausted(operation: PublicOperation) -> ConnectError {
    public_error(
        ErrorCode::ResourceExhausted,
        api::PublicErrorReason::ResourceExhaustion,
        operation,
        true,
        None,
    )
}

fn internal(operation: PublicOperation) -> ConnectError {
    public_error(
        ErrorCode::DataLoss,
        api::PublicErrorReason::Internal,
        operation,
        false,
        None,
    )
}

#[cfg(test)]
mod tests {
    #[cfg(target_os = "linux")]
    use std::{
        fs,
        path::PathBuf,
        sync::atomic::{AtomicU64, Ordering},
    };

    #[cfg(target_os = "linux")]
    use std::os::unix::fs::PermissionsExt as _;

    #[cfg(target_os = "linux")]
    use aster_mesh::{ProvisioningAccess, ReferenceProvisioner};
    use aster_node::application::{MAX_SELECTED_BLOB_PAGE_BYTES, MAX_SELECTED_LIVE_BLOB_BYTES};
    #[cfg(target_os = "linux")]
    use aster_node::mission::UnprotectedReferenceMission;
    #[cfg(target_os = "linux")]
    use aster_node::{MutableSourceInterests, NodeApplication, NodeConfig, start_node};
    use buffa::Message as _;
    use connectrpc::ErrorCode;

    use super::*;
    use crate::api;

    #[cfg(target_os = "linux")]
    static NEXT_STAGING_TEST: AtomicU64 = AtomicU64::new(0);

    #[cfg(target_os = "linux")]
    struct StagingTestRoot(PathBuf);

    #[cfg(target_os = "linux")]
    impl StagingTestRoot {
        fn new() -> Self {
            let sequence = NEXT_STAGING_TEST.fetch_add(1, Ordering::Relaxed);
            let path = std::env::temp_dir().join(format!(
                "aster-agent-staging-test-{}-{sequence}",
                std::process::id()
            ));
            fs::create_dir(&path).unwrap();
            fs::set_permissions(&path, fs::Permissions::from_mode(0o700)).unwrap();
            Self(path)
        }
    }

    #[cfg(target_os = "linux")]
    impl Drop for StagingTestRoot {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.0);
        }
    }

    fn metadata(total_len: u64, ttl_ms: Option<u64>) -> api::PublishBlobMetadata {
        api::PublishBlobMetadata {
            operation_key: b"blob-operation".to_vec(),
            topic: "imagery.maps".to_owned(),
            scope: "mission/team/alpha".to_owned(),
            priority: api::Priority::Immediate.into(),
            media_type: Some("image/octet-stream".to_owned()),
            schema_id: b"schema-v1".to_vec(),
            total_len,
            ttl_ms,
            ..Default::default()
        }
    }

    fn metadata_frame(total_len: u64, ttl_ms: Option<u64>) -> api::PublishBlobRequest {
        api::PublishBlobRequest {
            frame: Some(api::publish_blob_request::Frame::Metadata(Box::new(
                metadata(total_len, ttl_ms),
            ))),
            ..Default::default()
        }
    }

    fn start_upload(
        first: api::PublishBlobRequest,
    ) -> Result<(ParsedPublish, UploadGrammar), ConnectError> {
        UploadGrammar::start(first, MAX_SELECTED_LIVE_BLOB_BYTES)
    }

    fn chunk(bytes: Vec<u8>) -> api::PublishBlobRequest {
        api::PublishBlobRequest {
            frame: Some(api::publish_blob_request::Frame::Chunk(bytes)),
            ..Default::default()
        }
    }

    #[test]
    fn blob_ttl_wire_presence_round_trips_and_zero_is_rejected() {
        let durable = metadata_frame(1, None);
        let durable = api::PublishBlobRequest::decode_from_slice(&durable.encode_to_vec()).unwrap();
        let (durable, _) = start_upload(durable).unwrap();
        assert_eq!(durable.options.ttl_ms(), None);

        let finite = metadata_frame(1, Some(u64::MAX));
        let finite = api::PublishBlobRequest::decode_from_slice(&finite.encode_to_vec()).unwrap();
        let (finite, _) = start_upload(finite).unwrap();
        assert_eq!(finite.options.ttl_ms(), Some(u64::MAX));

        let error = start_upload(metadata_frame(1, Some(0))).unwrap_err();
        assert_eq!(error.code, ErrorCode::InvalidArgument);
    }

    #[test]
    fn blob_upload_requires_one_metadata_frame_before_chunks() {
        assert_eq!(
            start_upload(api::PublishBlobRequest::default())
                .unwrap_err()
                .code,
            ErrorCode::InvalidArgument
        );
        assert_eq!(
            start_upload(chunk(vec![1])).unwrap_err().code,
            ErrorCode::InvalidArgument
        );

        let (_, mut grammar) = start_upload(metadata_frame(1, None)).unwrap();
        assert_eq!(
            grammar.accept(metadata_frame(1, None)).unwrap_err().code,
            ErrorCode::InvalidArgument
        );
    }

    #[test]
    fn blob_upload_rejects_empty_oversized_and_length_mismatched_streams() {
        assert_eq!(
            start_upload(metadata_frame(0, None)).unwrap_err().code,
            ErrorCode::InvalidArgument
        );
        assert_eq!(
            start_upload(metadata_frame(MAX_SELECTED_LIVE_BLOB_BYTES + 1, None))
                .unwrap_err()
                .code,
            ErrorCode::ResourceExhausted
        );

        let (_, mut empty_chunk) = start_upload(metadata_frame(1, None)).unwrap();
        assert_eq!(
            empty_chunk.accept(chunk(Vec::new())).unwrap_err().code,
            ErrorCode::InvalidArgument
        );

        let (_, mut oversized_chunk) = start_upload(metadata_frame(
            (MAX_SELECTED_BLOB_PAGE_BYTES + 1) as u64,
            None,
        ))
        .unwrap();
        assert_eq!(
            oversized_chunk
                .accept(chunk(vec![0; MAX_SELECTED_BLOB_PAGE_BYTES + 1]))
                .unwrap_err()
                .code,
            ErrorCode::InvalidArgument
        );

        let (_, short) = start_upload(metadata_frame(2, None)).unwrap();
        assert_eq!(short.finish().unwrap_err().code, ErrorCode::InvalidArgument);

        let (_, mut long) = start_upload(metadata_frame(1, None)).unwrap();
        assert_eq!(
            long.accept(chunk(vec![1, 2])).unwrap_err().code,
            ErrorCode::InvalidArgument
        );
    }

    #[test]
    fn blob_upload_admission_uses_the_live_profile_capacity() {
        let configured_max = 2 * 1024 * 1024 * 1024;
        let declared = 800 * 1024 * 1024;

        UploadGrammar::start(metadata_frame(declared, None), configured_max)
            .expect("profile-5 upload below the configured live capacity");
        assert_eq!(
            UploadGrammar::start(metadata_frame(configured_max + 1, None), configured_max)
                .unwrap_err()
                .code,
            ErrorCode::ResourceExhausted
        );
    }

    #[test]
    fn blob_upload_derives_frame_bound_from_declared_u64_length() {
        let declared = BLOB_RPC_FRAME_BYTES as u64 * 1_025;
        assert_eq!(maximum_chunk_frames_for_len(declared).unwrap(), 1_025);
    }

    #[test]
    fn read_page_response_carries_complete_stable_publication_metadata() {
        let metadata = ReadMetadata {
            id: [0x11; 32],
            publisher: [0x22; 32],
            publisher_counter: 7,
            topic: "imagery.maps".to_owned(),
            scope: "mission/team/alpha".to_owned(),
            priority: aster_node::application::Priority::Immediate,
            ttl_ms: Some(u64::MAX),
            total_len: 3,
            media_type: Some("image/octet-stream".to_owned()),
            schema_id: b"schema-v1".to_vec(),
            acceptance_marker: 9,
        };
        let response = read_response(&metadata, 1, vec![0xbb, 0xcc], true);
        assert_eq!(response.id, vec![0x11; 32]);
        assert_eq!(response.publisher, vec![0x22; 32]);
        assert_eq!(response.publisher_counter, 7);
        assert_eq!(response.topic, "imagery.maps");
        assert_eq!(response.scope, "mission/team/alpha");
        assert_eq!(response.priority, api::Priority::Immediate);
        assert_eq!(response.ttl_ms, Some(u64::MAX));
        assert_eq!(response.total_len, 3);
        assert_eq!(response.media_type.as_deref(), Some("image/octet-stream"));
        assert_eq!(response.schema_id, b"schema-v1");
        assert_eq!(response.acceptance_marker, 9);
        assert_eq!(response.offset, 1);
        assert_eq!(response.chunk, [0xbb, 0xcc]);
        assert!(response.complete);

        let mut changed = metadata.clone();
        changed.acceptance_marker = 10;
        assert_eq!(
            ensure_stable_read_metadata(&metadata, &changed)
                .unwrap_err()
                .code,
            ErrorCode::DataLoss
        );
    }

    #[cfg(any())]
    #[tokio::test]
    async fn cancelled_handler_keeps_upload_permit_until_node_operation_finishes() {
        let uploads = Arc::new(Semaphore::new(1));
        let permit = Arc::clone(&uploads).try_acquire_owned().unwrap();
        let entered = Arc::new(Notify::new());
        let release = Arc::new(Notify::new());
        let operation_entered = Arc::clone(&entered);
        let operation_release = Arc::clone(&release);
        let handler = tokio::spawn(await_upload_with_permit(permit, async move {
            operation_entered.notify_one();
            operation_release.notified().await;
        }));

        entered.notified().await;
        handler.abort();
        assert!(handler.await.unwrap_err().is_cancelled());
        assert!(
            Arc::clone(&uploads).try_acquire_owned().is_err(),
            "a cancelled handler must not release capacity while the node operation is live"
        );

        release.notify_one();
        tokio::time::timeout(std::time::Duration::from_secs(1), async {
            loop {
                if Arc::clone(&uploads).try_acquire_owned().is_ok() {
                    break;
                }
                tokio::task::yield_now().await;
            }
        })
        .await
        .expect("node completion releases upload capacity");
    }

    #[cfg(all(any(), target_os = "linux"))]
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn blocking_writer_reports_the_final_write_failure_before_releasing_capacity() {
        let uploads = Arc::new(Semaphore::new(1));
        let permit = Arc::clone(&uploads).try_acquire_owned().unwrap();
        let file = fs::OpenOptions::new()
            .write(true)
            .open("/dev/full")
            .unwrap();
        let (commands, receiver) = tokio::sync::mpsc::channel(1);
        let task = tokio::task::spawn_blocking(move || run_blocking_writer(file, permit, receiver));
        let (completed, result) = tokio::sync::oneshot::channel();
        commands
            .send(WriterCommand::Write(Zeroizing::new(vec![0x5a]), completed))
            .await
            .unwrap();

        assert!(result.await.unwrap().is_err());
        assert!(Arc::clone(&uploads).try_acquire_owned().is_err());
        drop(commands);
        task.await.unwrap();
        assert!(Arc::clone(&uploads).try_acquire_owned().is_ok());
    }

    #[cfg(all(any(), target_os = "linux"))]
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn cancelled_blocking_write_keeps_capacity_until_current_io_and_cleanup_finish() {
        use std::os::fd::AsRawFd as _;

        let uploads = Arc::new(Semaphore::new(1));
        let permit = Arc::clone(&uploads).try_acquire_owned().unwrap();
        let fixture = StagingTestRoot::new();
        let file_path = fixture.0.join("writer-cleanup");
        let file = fs::File::create(&file_path).unwrap();
        let descriptor_path = PathBuf::from(format!("/proc/self/fd/{}", file.as_raw_fd()));
        let (commands, receiver) = tokio::sync::mpsc::channel(1);
        let task = tokio::task::spawn_blocking(move || run_blocking_writer(file, permit, receiver));
        let (completed, _result) = tokio::sync::oneshot::channel();
        commands
            .send(WriterCommand::Write(Zeroizing::new(vec![0x7b]), completed))
            .await
            .unwrap();

        assert!(Arc::clone(&uploads).try_acquire_owned().is_err());
        assert!(descriptor_path.exists());
        drop(commands);
        let reacquired = tokio::time::timeout(std::time::Duration::from_secs(1), async {
            loop {
                if descriptor_path.exists() {
                    assert!(Arc::clone(&uploads).try_acquire_owned().is_err());
                    tokio::task::yield_now().await;
                    continue;
                }
                if let Ok(permit) = Arc::clone(&uploads).try_acquire_owned() {
                    break permit;
                }
                tokio::task::yield_now().await;
            }
        })
        .await
        .expect("writer cleanup deadline");
        task.await.unwrap();
        drop(reacquired);
    }

    #[cfg(all(any(), target_os = "linux"))]
    #[test]
    fn fallocate_failures_distinguish_capacity_from_unsupported_filesystems() {
        assert_eq!(
            classify_fallocate_error(rustix::io::Errno::NOSPC).code,
            ErrorCode::ResourceExhausted
        );
        assert_eq!(
            classify_fallocate_error(rustix::io::Errno::DQUOT).code,
            ErrorCode::ResourceExhausted
        );
        assert_eq!(
            classify_fallocate_error(rustix::io::Errno::OPNOTSUPP).code,
            ErrorCode::FailedPrecondition
        );
    }

    #[cfg(all(any(), target_os = "linux"))]
    #[test]
    fn staging_uses_pinned_directory_after_configured_path_is_replaced() {
        use std::os::fd::AsRawFd as _;

        let fixture = StagingTestRoot::new();
        let configured = fixture.0.join("configured");
        let pinned_location = fixture.0.join("pinned");
        let redirect = fixture.0.join("redirect");
        fs::create_dir(&configured).unwrap();
        fs::create_dir(&redirect).unwrap();
        let staging = PinnedStagingDirectory::open(&configured).unwrap();

        fs::rename(&configured, &pinned_location).unwrap();
        symlink(&redirect, &configured).unwrap();

        let file = open_private_staging(&staging, 4096).unwrap();
        let metadata = file.metadata().unwrap();
        let descriptor_target =
            fs::read_link(format!("/proc/self/fd/{}", file.as_raw_fd())).unwrap();
        assert_eq!(metadata.len(), 4096);
        assert_eq!(metadata.mode() & 0o777, 0o600);
        assert!(
            descriptor_target.starts_with(&pinned_location),
            "the anonymous staging inode must belong to the pinned directory"
        );
        assert!(
            fs::read_dir(&pinned_location).unwrap().next().is_none(),
            "the pinned directory must not retain a linked staging name"
        );
        assert!(
            fs::read_dir(&redirect).unwrap().next().is_none(),
            "path replacement must not redirect staging"
        );
    }

    #[cfg(all(any(), target_os = "linux"))]
    #[test]
    fn staging_accepts_a_configured_symlink_but_pins_its_exact_target() {
        let fixture = StagingTestRoot::new();
        let target = fixture.0.join("target");
        let configured = fixture.0.join("configured");
        let replacement = fixture.0.join("replacement");
        fs::create_dir(&target).unwrap();
        fs::create_dir(&replacement).unwrap();
        symlink(&target, &configured).unwrap();

        let staging = PinnedStagingDirectory::open(&configured).unwrap();
        fs::remove_file(&configured).unwrap();
        symlink(&replacement, &configured).unwrap();

        let file = open_private_staging(&staging, 4096).unwrap();
        assert_eq!(
            file.metadata().unwrap().dev(),
            fs::metadata(&target).unwrap().dev()
        );
        assert!(fs::read_dir(&replacement).unwrap().next().is_none());
    }

    #[test]
    fn rpc_blob_frame_size_is_a_stable_agent_contract() {
        assert_eq!(crate::BLOB_RPC_FRAME_BYTES, 64 * 1024);
        assert_eq!(crate::BLOB_RPC_READ_FRAME_BYTES, 1024 * 1024);
    }

    #[cfg(all(any(), target_os = "linux"))]
    #[test]
    fn staging_reserves_real_blocks_before_upload_bytes_are_accepted() {
        let fixture = StagingTestRoot::new();
        let staging = PinnedStagingDirectory::open(&fixture.0).unwrap();
        let total_len = 1024 * 1024;
        let file = open_private_staging(&staging, total_len).unwrap();
        let metadata = file.metadata().unwrap();
        assert_eq!(metadata.len(), total_len);
        assert!(
            metadata.blocks() * 512 >= total_len,
            "staging reservation must allocate blocks rather than create a sparse extent"
        );
    }

    #[cfg(target_os = "linux")]
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn lazy_read_reauthenticates_expiry_between_pages() {
        let fixture = StagingTestRoot::new();
        let state_root = fixture.0.join("state");
        fs::create_dir(&state_root).unwrap();
        fs::set_permissions(&state_root, fs::Permissions::from_mode(0o700)).unwrap();
        let access = ProvisioningAccess::member(
            Scope::new("mission/team/alpha").unwrap(),
            vec![1],
            vec![Topic::new("imagery.maps").unwrap()],
        )
        .unwrap();
        let mut provisioner = ReferenceProvisioner::from_seed([0xb8; 32]).unwrap();
        let mission = UnprotectedReferenceMission::from_bytes(
            provisioner
                .issue_node(1, &[access])
                .unwrap()
                .to_bytes()
                .unwrap(),
        )
        .unwrap();
        let node = start_node(NodeConfig {
            state: state_root.clone(),
            bind: "127.0.0.1:0".parse().unwrap(),
            mission,
            peers: Vec::new(),
            mutable_interests: MutableSourceInterests::default(),
            sync_interval: std::time::Duration::from_millis(50),
            run_for: None,
            application: NodeApplication::Relay,
        })
        .await
        .unwrap();
        let blobs = node.selected_blobs();
        let source_path = fixture.0.join("source.bin");
        fs::write(&source_path, vec![0x5c; MAX_SELECTED_BLOB_PAGE_BYTES + 1]).unwrap();
        let publication = blobs
            .publish_with_options(
                NodeBlobPublishRequest {
                    operation_key: b"lazy-expiry".to_vec(),
                    topic: Topic::new("imagery.maps").unwrap(),
                    scope: Scope::new("mission/team/alpha").unwrap(),
                    priority: Priority::Routine,
                    media_type: None,
                    schema_id: Vec::new(),
                },
                BlobPublishOptions::finite_ttl_ms(1_000).unwrap(),
                fs::File::open(source_path).unwrap(),
            )
            .await
            .unwrap();
        let service = BlobConnectService::new(blobs, &state_root).unwrap();
        let mut stream = service
            .read(api::ReadBlobRequest {
                id: publication.id.as_bytes().to_vec(),
                topic: "imagery.maps".to_owned(),
                scope: "mission/team/alpha".to_owned(),
                ..Default::default()
            })
            .await
            .unwrap()
            .body;
        let first = stream.next().await.unwrap().unwrap();
        assert_eq!(first.offset, 0);
        assert_eq!(first.chunk.len(), MAX_SELECTED_BLOB_PAGE_BYTES);
        assert!(!first.complete);

        tokio::time::sleep(std::time::Duration::from_millis(1_100)).await;
        let expired = stream.next().await.unwrap().unwrap_err();
        assert_eq!(expired.code, ErrorCode::NotFound);
        assert_eq!(
            expired.message.as_deref(),
            Some("durable object expired or was retired")
        );

        node.shutdown().await.unwrap();
    }
}
