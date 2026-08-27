//! Retained one-host acceptance producer for the live selected Blob API.
//!
//! Application plaintext, operation keys, provisioning bytes, filesystem paths,
//! socket addresses, process identifiers, and secrets are deliberately absent
//! from the `LIVE_BLOB` transcript. Runtime `READY`/`CONTACT`/`STOP` records stay
//! in stdout so an independent verifier can bind the sanitized observations to
//! all four actor lifetimes.

use std::{
    collections::BTreeSet,
    env,
    error::Error,
    fmt,
    fs::{self, File, OpenOptions},
    io::Write as _,
    net::{SocketAddr, UdpSocket},
    path::{Path, PathBuf},
    time::Duration,
};

use aster_iroh::{EndpointId, ExpectedPeer};
use aster_mesh::{ProvisioningAccess, ReferenceProvisioner};
use aster_node::{
    MissionExpectedPeer, MutableSourceInterests, NodeApplication, NodeConfig, NodeIdentity,
    NodeReceipt, SourceInterestSelector,
    application::{
        ApplicationError, ApplicationErrorKind, BlobPublishRequest, BlobPublishResult,
        BlobReadPageRequest, BlobReadRequest, MAX_SELECTED_BLOB_PAGE_BYTES, Priority, Scope,
        SelectedBlobHandle, Topic,
    },
    format_node_id,
    mission::UnprotectedReferenceMission,
    start_node,
};
use sha2::{Digest as _, Sha256};
use tokio::time::{sleep, timeout};
use zeroize::{Zeroize as _, Zeroizing};

const TRANSCRIPT_SCHEMA: &str = "aster-selected-live-blob-transcript/v1";
const CLAIM: &str =
    "selected-live-blob-one-host-direct-iroh-peerless-publish-transfer-read-restart-acceptance";
const TOPIC: &str = "opaque";
const SCOPE: &str = "test/runtime-contact";
const MEDIA_TYPE: &str = "application/x-aster-live-blob-acceptance";
const SCHEMA_ID: &[u8] = b"acceptance/live-blob-v1";
const SCHEMA_ID_SHA256: &str = "2a538df7b419268fda25ef2f0e358db63a764ee3b55db19e0a4ef00c8a942be2";
const OPERATION_KEY: &[u8] = b"acceptance/live-blob-operation-v1";
const PAYLOAD_LEN: usize = 65_747;
const PAYLOAD_SHA256: &str = "52d2759ceaccc2ac63ab528f40edbe80ddd3abda8f4b5d894fb034881fcda9cf";
const CHANGED_PAYLOAD_SHA256: &str =
    "b3da9883cd3819a8e6fe834e65e0f65bcfc3903f2da14bd28eb2a42c2680619c";
const FIRST_PAGE_SHA256: &str = "1047ab624c89856e2a3c2dea5cea7a299c2d0ba0a9bcbf1cb951a6d54927239a";
const LAST_PAGE_SHA256: &str = "2740c403e3254a595863ffffbb94bfb26d5cedaa94566c57c6683ba61bf672a7";
const EXPECTED_PAGES: usize = 2;
const POLL_DEADLINE: Duration = Duration::from_secs(30);

type DynError = Box<dyn Error + Send + Sync>;

#[derive(Debug)]
struct AcceptanceFailure(&'static str);

impl fmt::Display for AcceptanceFailure {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.0)
    }
}

impl Error for AcceptanceFailure {}

fn require(condition: bool, label: &'static str) -> Result<(), DynError> {
    if condition {
        Ok(())
    } else {
        Err(Box::new(AcceptanceFailure(label)))
    }
}

#[derive(Clone)]
struct Participant {
    name: &'static str,
    state: PathBuf,
    mission: UnprotectedReferenceMission,
    mission_id: [u8; 32],
    mission_authority: [u8; 32],
    carrier_id: EndpointId,
}

struct ParticipantTranscript {
    name: &'static str,
    carrier_id: String,
    mission_id: String,
    mission_authority: String,
    expected_carrier_peer: String,
    expected_mission_peer: String,
}

struct HandleEvidence {
    phase: &'static str,
    participant: &'static str,
    blob_identity: String,
    blob_authority: String,
}

struct PageEvidence {
    page_index: usize,
    offset: u64,
    max_bytes: usize,
    page_len: usize,
    next_offset: u64,
    complete: bool,
    page_sha256: String,
}

struct ReadEvidence {
    pages: Vec<PageEvidence>,
    payload_sha256: String,
}

struct AcceptanceTranscript {
    participants: [ParticipantTranscript; 2],
    peerless_handle: HandleEvidence,
    publication: BlobPublishResult,
    retry: BlobPublishResult,
    peerless_read: ReadEvidence,
    peerless_shutdown: NodeReceipt,
    connected_handles: [HandleEvidence; 2],
    connected_read: ReadEvidence,
    connected_shutdowns: [NodeReceipt; 2],
    restart_handle: HandleEvidence,
    restart_read: ReadEvidence,
    restart_shutdown: NodeReceipt,
}

#[tokio::main]
async fn main() {
    if let Err(error) = run().await {
        let stage = if let Some(failure) = error.downcast_ref::<AcceptanceFailure>() {
            failure.0.to_owned()
        } else if let Some(failure) = error.downcast_ref::<ApplicationError>() {
            format!("application_{:?}_{}", failure.kind(), failure.operation())
        } else {
            "runtime".to_owned()
        };
        let stage = stage.replace(' ', "_").to_ascii_lowercase();
        eprintln!("LIVE_BLOB_FAILURE status=error stage={stage}");
        std::process::exit(1);
    }
}

async fn run() -> Result<(), DynError> {
    require(
        MAX_SELECTED_BLOB_PAGE_BYTES == 65_536,
        "selected Blob page limit",
    )?;
    require(
        sha256_hex(SCHEMA_ID) == SCHEMA_ID_SHA256,
        "schema identifier digest",
    )?;

    let raw_root = parse_raw_root()?;
    let topic = Topic::new(TOPIC)?;
    let scope = Scope::new(SCOPE)?;
    let participants_root = raw_root.join("participants");
    create_owner_directory(&participants_root)?;
    let [publisher, receiver] = provision_participants(&participants_root, &topic, &scope)?;
    validate_participant_domains(&publisher, &receiver)?;

    let source_path = raw_root.join("live-blob-source.bin");
    let changed_source_path = raw_root.join("live-blob-conflict-source.bin");
    let payload = original_payload();
    require(
        payload.len() == PAYLOAD_LEN && sha256_hex(&payload) == PAYLOAD_SHA256,
        "fixed Blob payload",
    )?;
    write_source(&source_path, &payload)?;
    drop(payload);
    let changed_payload = changed_payload();
    require(
        changed_payload.len() == PAYLOAD_LEN
            && sha256_hex(&changed_payload) == CHANGED_PAYLOAD_SHA256,
        "fixed changed Blob payload",
    )?;
    write_source(&changed_source_path, &changed_payload)?;
    drop(changed_payload);

    let publish_request = BlobPublishRequest {
        operation_key: OPERATION_KEY.to_vec(),
        topic: topic.clone(),
        scope: scope.clone(),
        priority: Priority::Priority,
        media_type: Some(MEDIA_TYPE.to_owned()),
        schema_id: SCHEMA_ID.to_vec(),
    };

    let peerless = start_peerless(&publisher).await?;
    let peerless_blobs = peerless.selected_blobs();
    let peerless_handle = handle_evidence("peerless_source", &publisher, &peerless_blobs)?;
    let publication = peerless_blobs
        .publish(publish_request.clone(), File::open(&source_path)?)
        .await?;
    validate_publication(&publication, &publisher)?;
    let retry = peerless_blobs
        .publish(publish_request.clone(), File::open(&source_path)?)
        .await?;
    validate_exact_retry(&publication, &retry)?;
    let conflict = match peerless_blobs
        .publish(publish_request.clone(), File::open(&changed_source_path)?)
        .await
    {
        Err(error) => error,
        Ok(_) => {
            return Err(Box::new(AcceptanceFailure(
                "changed Blob operation key accepted",
            )));
        }
    };
    require(
        conflict.kind() == ApplicationErrorKind::Conflict && conflict.operation() == "blob publish",
        "changed Blob operation key conflict",
    )?;
    let read_request = BlobReadRequest {
        id: publication.id,
        topic: topic.clone(),
        scope: scope.clone(),
    };
    let peerless_read = read_blob_pages(&peerless_blobs, &read_request, &publication).await?;
    let peerless_retained = peerless_blobs.clone();
    let peerless_shutdown = peerless.shutdown().await?;
    validate_peerless_publisher_receipt(&peerless_shutdown)?;
    validate_closed_blob_handle(&peerless_retained, &read_request).await?;

    fs::remove_file(&source_path)?;
    fs::remove_file(&changed_source_path)?;
    sync_directory(&raw_root)?;
    require(
        !source_path.exists() && !changed_source_path.exists(),
        "Blob plaintext sources removed",
    )?;

    let publisher_socket = UdpSocket::bind(("127.0.0.1", 0))?;
    let receiver_socket = UdpSocket::bind(("127.0.0.1", 0))?;
    let publisher_address = publisher_socket.local_addr()?;
    let receiver_address = receiver_socket.local_addr()?;
    require(
        publisher_address != receiver_address,
        "distinct connected binds",
    )?;
    drop((publisher_socket, receiver_socket));

    let interests = MutableSourceInterests::default().with_blob(vec![SourceInterestSelector::new(
        topic.clone(),
        scope.clone(),
        false,
    )]);
    let publisher_config = connected_config(
        &publisher,
        publisher_address,
        &receiver,
        receiver_address,
        interests.clone(),
    );
    let receiver_config = connected_config(
        &receiver,
        receiver_address,
        &publisher,
        publisher_address,
        interests,
    );
    let (publisher_running, receiver_running) = if publisher.carrier_id > receiver.carrier_id {
        let publisher_running = start_node(publisher_config).await?;
        let receiver_running = start_node(receiver_config).await?;
        (publisher_running, receiver_running)
    } else {
        let receiver_running = start_node(receiver_config).await?;
        let publisher_running = start_node(publisher_config).await?;
        (publisher_running, receiver_running)
    };
    let publisher_blobs = publisher_running.selected_blobs();
    let receiver_blobs = receiver_running.selected_blobs();
    let connected_handles = [
        handle_evidence("connected_transfer", &publisher, &publisher_blobs)?,
        handle_evidence("connected_transfer", &receiver, &receiver_blobs)?,
    ];
    wait_for_blob_transfer(&receiver_blobs, &read_request, &publication).await?;
    let connected_read = read_blob_pages(&receiver_blobs, &read_request, &publication).await?;
    wait_for_contact_accounting(&publisher_running, &receiver_running).await?;
    let publisher_retained = publisher_blobs.clone();
    let receiver_retained = receiver_blobs.clone();
    let (publisher_shutdown, receiver_shutdown) =
        tokio::join!(publisher_running.shutdown(), receiver_running.shutdown());
    let publisher_shutdown = publisher_shutdown?;
    let receiver_shutdown = receiver_shutdown?;
    validate_connected_receipts(&peerless_shutdown, &publisher_shutdown, &receiver_shutdown)?;
    validate_closed_blob_handle(&publisher_retained, &read_request).await?;
    validate_closed_blob_handle(&receiver_retained, &read_request).await?;

    let restarted = start_peerless(&receiver).await?;
    let restart_blobs = restarted.selected_blobs();
    let restart_handle = handle_evidence("restart_receiver", &receiver, &restart_blobs)?;
    let restart_read = read_blob_pages(&restart_blobs, &read_request, &publication).await?;
    let restart_retained = restart_blobs.clone();
    let restart_shutdown = restarted.shutdown().await?;
    validate_restart_receiver_receipt(&receiver_shutdown, &restart_shutdown)?;
    validate_closed_blob_handle(&restart_retained, &read_request).await?;

    let rebound_publisher = UdpSocket::bind(publisher_address)?;
    let rebound_receiver = UdpSocket::bind(receiver_address)?;
    require(
        rebound_publisher.local_addr()? == publisher_address
            && rebound_receiver.local_addr()? == receiver_address,
        "connected binds reacquired",
    )?;
    drop((rebound_publisher, rebound_receiver));

    let transcript = AcceptanceTranscript {
        participants: [
            participant_transcript(&publisher, &receiver),
            participant_transcript(&receiver, &publisher),
        ],
        peerless_handle,
        publication,
        retry,
        peerless_read,
        peerless_shutdown,
        connected_handles,
        connected_read,
        connected_shutdowns: [publisher_shutdown, receiver_shutdown],
        restart_handle,
        restart_read,
        restart_shutdown,
    };
    emit_transcript(&transcript);
    Ok(())
}

fn parse_raw_root() -> Result<PathBuf, DynError> {
    let mut arguments = env::args_os();
    let _program = arguments.next();
    let root = arguments
        .next()
        .map(PathBuf::from)
        .ok_or(AcceptanceFailure("missing raw root"))?;
    require(arguments.next().is_none(), "unexpected arguments")?;
    require(root.is_absolute(), "raw root must be absolute")?;
    let root = fs::canonicalize(root)?;
    require(root.is_dir(), "raw root must be a directory")?;
    Ok(root)
}

#[cfg(unix)]
fn create_owner_directory(path: &Path) -> Result<(), DynError> {
    use std::os::unix::fs::DirBuilderExt as _;

    fs::DirBuilder::new().mode(0o700).create(path)?;
    Ok(())
}

#[cfg(not(unix))]
fn create_owner_directory(path: &Path) -> Result<(), DynError> {
    fs::create_dir(path)?;
    Ok(())
}

#[cfg(unix)]
fn write_source(path: &Path, bytes: &[u8]) -> Result<(), DynError> {
    use std::os::unix::fs::OpenOptionsExt as _;

    let mut options = OpenOptions::new();
    options.write(true).create_new(true).mode(0o600);
    let mut output = options.open(path)?;
    output.write_all(bytes)?;
    output.sync_all()?;
    Ok(())
}

#[cfg(not(unix))]
fn write_source(path: &Path, bytes: &[u8]) -> Result<(), DynError> {
    let mut output = OpenOptions::new().write(true).create_new(true).open(path)?;
    output.write_all(bytes)?;
    output.sync_all()?;
    Ok(())
}

#[cfg(unix)]
fn sync_directory(path: &Path) -> Result<(), DynError> {
    File::open(path)?.sync_all()?;
    Ok(())
}

#[cfg(not(unix))]
fn sync_directory(_path: &Path) -> Result<(), DynError> {
    Ok(())
}

fn original_payload() -> Zeroizing<Vec<u8>> {
    Zeroizing::new(
        (0..PAYLOAD_LEN)
            .map(|index| (index.wrapping_mul(13) % 251) as u8)
            .collect(),
    )
}

fn changed_payload() -> Zeroizing<Vec<u8>> {
    Zeroizing::new(
        (0..PAYLOAD_LEN)
            .map(|index| (index.wrapping_mul(17).wrapping_add(1) % 251) as u8)
            .collect(),
    )
}

fn provision_participants(
    participants_root: &Path,
    topic: &Topic,
    scope: &Scope,
) -> Result<[Participant; 2], DynError> {
    let access = ProvisioningAccess::member(scope.clone(), vec![1], vec![topic.clone()])?;
    let mut seed = [0u8; 32];
    if let Err(error) = getrandom::fill(&mut seed) {
        seed.zeroize();
        return Err(Box::new(error));
    }
    let provisioner_result = ReferenceProvisioner::from_seed(seed);
    seed.zeroize();
    let mut provisioner = provisioner_result?;
    let publisher_bundle = provisioner.issue_node(1, std::slice::from_ref(&access))?;
    let receiver_bundle = provisioner.issue_node(2, std::slice::from_ref(&access))?;
    let publisher =
        persist_participant(participants_root, "publisher", publisher_bundle.to_bytes()?)?;
    let receiver = persist_participant(participants_root, "receiver", receiver_bundle.to_bytes()?)?;
    Ok([publisher, receiver])
}

fn persist_participant(
    participants_root: &Path,
    name: &'static str,
    mission_bytes: Vec<u8>,
) -> Result<Participant, DynError> {
    let root = participants_root.join(name);
    let state = root.join("state");
    create_owner_directory(&root)?;
    create_owner_directory(&state)?;
    let mission = UnprotectedReferenceMission::persist(root.join("mission.bundle"), mission_bytes)?;
    let mission_id = mission.identity();
    let mission_authority = mission.mission_authority_id();
    let identity = NodeIdentity::load_or_create(&state)?;
    let carrier_id = identity.id();
    drop(identity);
    Ok(Participant {
        name,
        state,
        mission,
        mission_id,
        mission_authority,
        carrier_id,
    })
}

fn validate_participant_domains(
    publisher: &Participant,
    receiver: &Participant,
) -> Result<(), DynError> {
    require(
        publisher.mission_id != receiver.mission_id,
        "distinct mission identities",
    )?;
    require(
        publisher.carrier_id != receiver.carrier_id,
        "distinct carrier identities",
    )?;
    require(
        publisher.mission_authority == receiver.mission_authority,
        "common mission authority",
    )?;
    let domains = [
        publisher.carrier_id.to_string(),
        receiver.carrier_id.to_string(),
        format_node_id(publisher.mission_id),
        format_node_id(receiver.mission_id),
        format_node_id(publisher.mission_authority),
    ];
    require(
        domains.iter().collect::<BTreeSet<_>>().len() == domains.len(),
        "identity domains",
    )
}

async fn start_peerless(participant: &Participant) -> Result<aster_node::RunningNode, DynError> {
    Ok(start_node(NodeConfig {
        state: participant.state.clone(),
        bind: SocketAddr::from(([127, 0, 0, 1], 0)),
        mission: participant.mission.clone(),
        peers: Vec::new(),
        mutable_interests: MutableSourceInterests::default(),
        sync_interval: Duration::from_millis(10),
        run_for: None,
        application: NodeApplication::Relay,
    })
    .await?)
}

fn connected_config(
    local: &Participant,
    bind: SocketAddr,
    remote: &Participant,
    remote_address: SocketAddr,
    mutable_interests: MutableSourceInterests,
) -> NodeConfig {
    NodeConfig {
        state: local.state.clone(),
        bind,
        mission: local.mission.clone(),
        peers: vec![MissionExpectedPeer {
            carrier: ExpectedPeer {
                id: remote.carrier_id,
                address: remote_address,
            },
            mission: remote.mission_id,
        }],
        mutable_interests,
        sync_interval: Duration::from_millis(20),
        run_for: None,
        application: NodeApplication::Relay,
    }
}

fn handle_evidence(
    phase: &'static str,
    participant: &Participant,
    handle: &SelectedBlobHandle,
) -> Result<HandleEvidence, DynError> {
    require(
        handle.identity() == participant.mission_id
            && handle.mission_authority() == participant.mission_authority,
        "live Blob handle mission binding",
    )?;
    Ok(HandleEvidence {
        phase,
        participant: participant.name,
        blob_identity: format_node_id(handle.identity()),
        blob_authority: format_node_id(handle.mission_authority()),
    })
}

fn validate_publication(
    publication: &BlobPublishResult,
    publisher: &Participant,
) -> Result<(), DynError> {
    require(
        publication.inserted
            && publication.publisher == publisher.mission_id
            && publication.publisher_counter == 1
            && publication.priority == Priority::Priority
            && publication.total_len == PAYLOAD_LEN as u64
            && publication.media_type.as_deref() == Some(MEDIA_TYPE)
            && publication.schema_id == SCHEMA_ID
            && publication.acceptance_marker == 1,
        "live Blob publication metadata",
    )
}

fn validate_exact_retry(
    publication: &BlobPublishResult,
    retry: &BlobPublishResult,
) -> Result<(), DynError> {
    require(
        !retry.inserted
            && retry.id == publication.id
            && retry.publisher == publication.publisher
            && retry.publisher_counter == publication.publisher_counter
            && retry.priority == publication.priority
            && retry.total_len == publication.total_len
            && retry.media_type == publication.media_type
            && retry.schema_id == publication.schema_id
            && retry.acceptance_marker == publication.acceptance_marker,
        "live Blob exact retry",
    )
}

fn validate_page_metadata(
    page: &aster_node::application::BlobReadPage,
    request: &BlobReadRequest,
    publication: &BlobPublishResult,
) -> Result<(), DynError> {
    require(
        page.id == request.id
            && page.id == publication.id
            && page.publisher == publication.publisher
            && page.publisher_counter == publication.publisher_counter
            && page.priority == publication.priority
            && page.total_len == publication.total_len
            && page.media_type == publication.media_type
            && page.schema_id == publication.schema_id
            && page.acceptance_marker == publication.acceptance_marker,
        "live Blob page metadata",
    )
}

async fn read_blob_pages(
    handle: &SelectedBlobHandle,
    request: &BlobReadRequest,
    publication: &BlobPublishResult,
) -> Result<ReadEvidence, DynError> {
    let mut offset = 0u64;
    let mut whole = Sha256::new();
    let mut pages = Vec::with_capacity(EXPECTED_PAGES);
    loop {
        require(pages.len() < EXPECTED_PAGES, "live Blob page count")?;
        let page = handle
            .read_page(BlobReadPageRequest {
                blob: request.clone(),
                offset,
                max_bytes: MAX_SELECTED_BLOB_PAGE_BYTES,
            })
            .await?;
        validate_page_metadata(&page, request, publication)?;
        require(
            page.offset == offset && !page.is_empty() && page.len() <= MAX_SELECTED_BLOB_PAGE_BYTES,
            "bounded live Blob page",
        )?;
        let page_index = pages.len();
        let page_sha256 = sha256_hex(page.as_bytes());
        let (expected_offset, expected_len, expected_next, expected_complete, expected_sha256) =
            match page_index {
                0 => (
                    0,
                    MAX_SELECTED_BLOB_PAGE_BYTES,
                    MAX_SELECTED_BLOB_PAGE_BYTES as u64,
                    false,
                    FIRST_PAGE_SHA256,
                ),
                1 => (
                    MAX_SELECTED_BLOB_PAGE_BYTES as u64,
                    PAYLOAD_LEN - MAX_SELECTED_BLOB_PAGE_BYTES,
                    PAYLOAD_LEN as u64,
                    true,
                    LAST_PAGE_SHA256,
                ),
                _ => return Err(Box::new(AcceptanceFailure("unexpected live Blob page"))),
            };
        require(
            page.offset == expected_offset
                && page.len() == expected_len
                && page.next_offset() == expected_next
                && page.complete == expected_complete
                && page_sha256 == expected_sha256,
            "exact live Blob page",
        )?;
        whole.update(page.as_bytes());
        let next_offset = page.next_offset();
        let complete = page.complete;
        pages.push(PageEvidence {
            page_index,
            offset: page.offset,
            max_bytes: MAX_SELECTED_BLOB_PAGE_BYTES,
            page_len: page.len(),
            next_offset,
            complete,
            page_sha256,
        });
        drop(page);
        if complete {
            break;
        }
        offset = next_offset;
    }
    let payload_sha256 = hex_bytes(&whole.finalize());
    require(
        pages.len() == EXPECTED_PAGES && payload_sha256 == PAYLOAD_SHA256,
        "complete live Blob digest",
    )?;
    Ok(ReadEvidence {
        pages,
        payload_sha256,
    })
}

async fn wait_for_blob_transfer(
    handle: &SelectedBlobHandle,
    request: &BlobReadRequest,
    publication: &BlobPublishResult,
) -> Result<(), DynError> {
    timeout(POLL_DEADLINE, async {
        loop {
            match handle
                .read_page(BlobReadPageRequest {
                    blob: request.clone(),
                    offset: 0,
                    max_bytes: 1,
                })
                .await
            {
                Ok(page) => {
                    validate_page_metadata(&page, request, publication)?;
                    require(
                        page.offset == 0
                            && page.len() == 1
                            && page.next_offset() == 1
                            && !page.complete,
                        "direct Blob readiness page",
                    )?;
                    return Ok::<(), DynError>(());
                }
                Err(error)
                    if matches!(
                        error.kind(),
                        ApplicationErrorKind::RequestRejected
                            | ApplicationErrorKind::UnauthorizedOrRevoked
                            | ApplicationErrorKind::PolicyUnsettled
                    ) =>
                {
                    sleep(Duration::from_millis(20)).await;
                }
                Err(error) => return Err(Box::new(error) as DynError),
            }
        }
    })
    .await
    .map_err(|_| AcceptanceFailure("direct Blob convergence deadline"))??;
    Ok(())
}

async fn wait_for_contact_accounting(
    publisher: &aster_node::RunningNode,
    receiver: &aster_node::RunningNode,
) -> Result<(), DynError> {
    let publisher_status = publisher.selected_events();
    let receiver_status = receiver.selected_events();
    timeout(POLL_DEADLINE, async {
        loop {
            let publisher = publisher_status.status().await?;
            let receiver = receiver_status.status().await?;
            require(
                publisher.failed_contact_attempts == 0 && receiver.failed_contact_attempts == 0,
                "direct Blob contact errors",
            )?;
            if publisher.authenticated_contacts > 0 && receiver.authenticated_contacts > 0 {
                return Ok::<(), DynError>(());
            }
            sleep(Duration::from_millis(20)).await;
        }
    })
    .await
    .map_err(|_| AcceptanceFailure("direct Blob contact accounting deadline"))??;
    Ok(())
}

async fn validate_closed_blob_handle(
    handle: &SelectedBlobHandle,
    request: &BlobReadRequest,
) -> Result<(), DynError> {
    let error = match handle
        .read_page(BlobReadPageRequest {
            blob: request.clone(),
            offset: 0,
            max_bytes: 1,
        })
        .await
    {
        Err(error) => error,
        Ok(_) => {
            return Err(Box::new(AcceptanceFailure(
                "closed Blob handle accepted read",
            )));
        }
    };
    require(
        error.kind() == ApplicationErrorKind::StateUnavailable
            && error.operation() == "blob read page",
        "closed live Blob handle",
    )
}

fn validate_non_blob_receipt(receipt: &NodeReceipt) -> Result<(), DynError> {
    require(
        receipt.items == 0
            && receipt.acceptance_markers == 0
            && receipt.events == 0
            && receipt.event_acceptance_markers == 0
            && receipt.route_cached_events == 0
            && receipt.controls == 0
            && receipt.applied_controls == 0
            && receipt.pending_controls == 0
            && receipt.control_highwater == 0,
        "excluded durable classes remain empty",
    )
}

fn validate_blob_shape(receipt: &NodeReceipt, operation_count: u64) -> Result<(), DynError> {
    require(
        receipt.blobs == 1
            && receipt.blob_acceptance_markers == 1
            && receipt.blob_last_acceptance_marker == 1
            && receipt.blob_sealed_bytes > 0
            && receipt.blob_operations == operation_count
            && ((operation_count == 0 && receipt.blob_operation_bytes == 0)
                || (operation_count == 1 && receipt.blob_operation_bytes > 0))
            && receipt.blob_variants == 1
            && receipt.blob_finalized_variants == 1
            && receipt.blob_committed_chunks == EXPECTED_PAGES as u64
            && receipt.blob_committed_file_bytes >= PAYLOAD_LEN as u64
            && receipt.blob_reserved_file_bytes == receipt.blob_committed_file_bytes
            && receipt.pending_blobs == 0
            && receipt.blob_carrier_prefixes == 0
            && receipt.blob_network_staging_bytes == 0
            && receipt.blob_deferred == 0,
        "durable live Blob shape",
    )
}

fn validate_peerless_publisher_receipt(receipt: &NodeReceipt) -> Result<(), DynError> {
    validate_non_blob_receipt(receipt)?;
    validate_blob_shape(receipt, 1)?;
    require(
        receipt.contacts == 0
            && receipt.contact_errors == 0
            && receipt.direct_contacts == 0
            && receipt.relay_contacts == 0
            && receipt.unknown_path_contacts == 0
            && receipt.carrier_path_transitions == 0
            && receipt.carrier_path_transition_saturations == 0
            && receipt.blob_ranges_fetched == 0
            && receipt.blob_bytes_fetched == 0
            && receipt.blob_remaining == 0
            && receipt.blob_carrier_fetch_cursors == 0,
        "peerless Blob publisher receipt",
    )
}

fn validate_connected_receipts(
    peerless: &NodeReceipt,
    publisher: &NodeReceipt,
    receiver: &NodeReceipt,
) -> Result<(), DynError> {
    validate_non_blob_receipt(publisher)?;
    validate_non_blob_receipt(receiver)?;
    validate_blob_shape(publisher, 1)?;
    validate_blob_shape(receiver, 0)?;
    for receipt in [publisher, receiver] {
        require(
            receipt.contacts > 0
                && receipt.direct_contacts == receipt.contacts
                && receipt.relay_contacts == 0
                && receipt.unknown_path_contacts == 0
                && receipt.contact_errors == 0
                && receipt.carrier_path_transitions == 0
                && receipt.carrier_path_transition_saturations == 0
                && receipt.blob_carrier_fetch_cursors <= 1,
            "direct-only Blob connected receipt",
        )?;
    }
    require(
        publisher.contacts == receiver.contacts
            && publisher.blob_ranges_fetched == 0
            && publisher.blob_bytes_fetched == 0
            && receiver.blob_ranges_fetched > 0
            && receiver.blob_bytes_fetched > 0,
        "direct Blob transfer accounting",
    )?;
    require_same_durable_blob(peerless, publisher, true)?;
    require_same_physical_blob(publisher, receiver)
}

fn validate_restart_receiver_receipt(
    connected: &NodeReceipt,
    restarted: &NodeReceipt,
) -> Result<(), DynError> {
    validate_non_blob_receipt(restarted)?;
    validate_blob_shape(restarted, 0)?;
    require(
        restarted.contacts == 0
            && restarted.contact_errors == 0
            && restarted.direct_contacts == 0
            && restarted.relay_contacts == 0
            && restarted.unknown_path_contacts == 0
            && restarted.carrier_path_transitions == 0
            && restarted.carrier_path_transition_saturations == 0
            && restarted.blob_ranges_fetched == 0
            && restarted.blob_bytes_fetched == 0
            && restarted.blob_remaining == 0
            && restarted.blob_carrier_fetch_cursors == 0,
        "peerless Blob receiver restart receipt",
    )?;
    require_same_durable_blob(connected, restarted, true)
}

fn require_same_durable_blob(
    before: &NodeReceipt,
    after: &NodeReceipt,
    include_operation: bool,
) -> Result<(), DynError> {
    require(
        before.blobs == after.blobs
            && before.blob_acceptance_markers == after.blob_acceptance_markers
            && before.blob_last_acceptance_marker == after.blob_last_acceptance_marker
            && before.blob_sealed_bytes == after.blob_sealed_bytes
            && (!include_operation
                || (before.blob_operations == after.blob_operations
                    && before.blob_operation_bytes == after.blob_operation_bytes))
            && before.blob_variants == after.blob_variants
            && before.blob_finalized_variants == after.blob_finalized_variants
            && before.blob_committed_chunks == after.blob_committed_chunks
            && before.blob_committed_file_bytes == after.blob_committed_file_bytes
            && before.blob_reserved_file_bytes == after.blob_reserved_file_bytes
            && before.pending_blobs == after.pending_blobs
            && before.blob_carrier_prefixes == after.blob_carrier_prefixes
            && before.blob_network_staging_bytes == after.blob_network_staging_bytes,
        "durable Blob unchanged across actor lifetime",
    )
}

fn require_same_physical_blob(
    publisher: &NodeReceipt,
    receiver: &NodeReceipt,
) -> Result<(), DynError> {
    require(
        publisher.blobs == receiver.blobs
            && publisher.blob_acceptance_markers == receiver.blob_acceptance_markers
            && publisher.blob_last_acceptance_marker == receiver.blob_last_acceptance_marker
            && publisher.blob_sealed_bytes == receiver.blob_sealed_bytes
            && publisher.blob_variants == receiver.blob_variants
            && publisher.blob_finalized_variants == receiver.blob_finalized_variants
            && publisher.blob_committed_chunks == receiver.blob_committed_chunks
            && publisher.blob_committed_file_bytes == receiver.blob_committed_file_bytes
            && publisher.blob_reserved_file_bytes == receiver.blob_reserved_file_bytes,
        "direct receiver retained exact physical Blob",
    )
}

fn participant_transcript(local: &Participant, remote: &Participant) -> ParticipantTranscript {
    ParticipantTranscript {
        name: local.name,
        carrier_id: local.carrier_id.to_string(),
        mission_id: format_node_id(local.mission_id),
        mission_authority: format_node_id(local.mission_authority),
        expected_carrier_peer: remote.carrier_id.to_string(),
        expected_mission_peer: format_node_id(remote.mission_id),
    }
}

fn priority_label(priority: Priority) -> &'static str {
    match priority {
        Priority::Routine => "routine",
        Priority::Priority => "priority",
        Priority::Immediate => "immediate",
        Priority::Flash => "flash",
    }
}

fn sha256_hex(bytes: &[u8]) -> String {
    hex_bytes(&Sha256::digest(bytes))
}

fn hex_bytes(bytes: &[u8]) -> String {
    let mut output = String::with_capacity(bytes.len().saturating_mul(2));
    for byte in bytes {
        use fmt::Write as _;
        let _ = write!(output, "{byte:02x}");
    }
    output
}

fn emit_transcript(transcript: &AcceptanceTranscript) {
    emit(
        "RUN",
        &[
            ("schema", TRANSCRIPT_SCHEMA.to_owned()),
            ("claim", CLAIM.to_owned()),
            ("participants", "2".to_owned()),
            ("actor_lifetimes", "4".to_owned()),
            ("maximum_concurrent_actors", "2".to_owned()),
            ("topic", TOPIC.to_owned()),
            ("scope", SCOPE.to_owned()),
            ("payload_len", PAYLOAD_LEN.to_string()),
            ("payload_sha256", PAYLOAD_SHA256.to_owned()),
            ("page_limit", MAX_SELECTED_BLOB_PAGE_BYTES.to_string()),
            ("expected_pages", EXPECTED_PAGES.to_string()),
        ],
    );
    for participant in &transcript.participants {
        emit_participant(participant);
    }
    emit_handle(&transcript.peerless_handle);
    emit_publication(&transcript.publication);
    emit_retry(&transcript.publication, &transcript.retry);
    emit(
        "BLOB_CONFLICT",
        &[
            ("phase", "peerless_source".to_owned()),
            ("participant", "publisher".to_owned()),
            ("original_id", transcript.publication.id.to_string()),
            ("original_payload_sha256", PAYLOAD_SHA256.to_owned()),
            ("changed_payload_sha256", CHANGED_PAYLOAD_SHA256.to_owned()),
            ("error_kind", "conflict".to_owned()),
            ("operation", "blob_publish".to_owned()),
            ("publication_preserved", "true".to_owned()),
        ],
    );
    emit_read(
        "peerless_source",
        "publisher",
        &transcript.publication,
        &transcript.peerless_read,
    );
    emit_shutdown(
        "peerless_source",
        "publisher",
        &transcript.peerless_shutdown,
    );
    emit_closed_handle("peerless_source", "publisher");
    emit(
        "SOURCE_REMOVED",
        &[
            ("participant", "publisher".to_owned()),
            ("status", "removed-and-parent-synced".to_owned()),
            ("bytes", PAYLOAD_LEN.to_string()),
            ("sha256", PAYLOAD_SHA256.to_owned()),
        ],
    );
    for handle in &transcript.connected_handles {
        emit_handle(handle);
    }
    emit_read(
        "connected_receiver",
        "receiver",
        &transcript.publication,
        &transcript.connected_read,
    );
    emit_shutdown(
        "connected_transfer",
        "publisher",
        &transcript.connected_shutdowns[0],
    );
    emit_shutdown(
        "connected_transfer",
        "receiver",
        &transcript.connected_shutdowns[1],
    );
    emit_closed_handle("connected_transfer", "publisher");
    emit_closed_handle("connected_transfer", "receiver");
    emit_handle(&transcript.restart_handle);
    emit_read(
        "restart_receiver",
        "receiver",
        &transcript.publication,
        &transcript.restart_read,
    );
    emit_shutdown("restart_receiver", "receiver", &transcript.restart_shutdown);
    emit_closed_handle("restart_receiver", "receiver");
    for participant in ["publisher", "receiver"] {
        emit(
            "BIND_REACQUIRED",
            &[
                ("participant", participant.to_owned()),
                ("status", "reacquired".to_owned()),
            ],
        );
    }
    emit(
        "RESULT",
        &[
            ("status", "pass".to_owned()),
            ("secret_values_emitted", "false".to_owned()),
            ("payload_representation", "sha256_only".to_owned()),
            ("records", "31".to_owned()),
            ("actor_lifetimes", "4".to_owned()),
            ("maximum_concurrent_actors", "2".to_owned()),
            ("graceful_shutdowns", "4".to_owned()),
            ("retained_handles", "4".to_owned()),
            ("closed_handles", "4".to_owned()),
            ("bind_reacquisitions", "2".to_owned()),
            ("source_removed", "true".to_owned()),
        ],
    );
}

fn emit_participant(participant: &ParticipantTranscript) {
    emit(
        "PARTICIPANT",
        &[
            ("participant", participant.name.to_owned()),
            ("carrier_id", participant.carrier_id.clone()),
            ("mission_id", participant.mission_id.clone()),
            ("mission_authority", participant.mission_authority.clone()),
            (
                "expected_carrier_peer",
                participant.expected_carrier_peer.clone(),
            ),
            (
                "expected_mission_peer",
                participant.expected_mission_peer.clone(),
            ),
        ],
    );
}

fn emit_handle(handle: &HandleEvidence) {
    emit(
        "HANDLE",
        &[
            ("phase", handle.phase.to_owned()),
            ("participant", handle.participant.to_owned()),
            ("blob_identity", handle.blob_identity.clone()),
            ("blob_authority", handle.blob_authority.clone()),
        ],
    );
}

fn publication_fields(publication: &BlobPublishResult) -> [(&'static str, String); 10] {
    [
        ("id", publication.id.to_string()),
        ("publisher", format_node_id(publication.publisher)),
        ("counter", publication.publisher_counter.to_string()),
        ("priority", priority_label(publication.priority).to_owned()),
        ("total_len", publication.total_len.to_string()),
        (
            "media_type",
            publication
                .media_type
                .as_deref()
                .unwrap_or("none")
                .to_owned(),
        ),
        ("schema_id_sha256", sha256_hex(&publication.schema_id)),
        (
            "acceptance_marker",
            publication.acceptance_marker.to_string(),
        ),
        ("inserted", publication.inserted.to_string()),
        ("payload_sha256", PAYLOAD_SHA256.to_owned()),
    ]
}

fn emit_publication(publication: &BlobPublishResult) {
    let common = publication_fields(publication);
    let mut fields = vec![
        ("phase", "peerless_source".to_owned()),
        ("participant", "publisher".to_owned()),
    ];
    fields.extend(common);
    emit("BLOB_PUBLICATION", &fields);
}

fn emit_retry(publication: &BlobPublishResult, retry: &BlobPublishResult) {
    emit(
        "BLOB_RETRY",
        &[
            ("phase", "peerless_source".to_owned()),
            ("participant", "publisher".to_owned()),
            ("original_id", publication.id.to_string()),
            ("retry_id", retry.id.to_string()),
            ("publisher", format_node_id(retry.publisher)),
            ("counter", retry.publisher_counter.to_string()),
            ("priority", priority_label(retry.priority).to_owned()),
            ("total_len", retry.total_len.to_string()),
            (
                "media_type",
                retry.media_type.as_deref().unwrap_or("none").to_owned(),
            ),
            ("schema_id_sha256", sha256_hex(&retry.schema_id)),
            ("acceptance_marker", retry.acceptance_marker.to_string()),
            ("inserted", retry.inserted.to_string()),
            ("exact_match", "true".to_owned()),
        ],
    );
}

fn emit_read(phase: &str, participant: &str, publication: &BlobPublishResult, read: &ReadEvidence) {
    for page in &read.pages {
        emit(
            "PAGE",
            &[
                ("phase", phase.to_owned()),
                ("participant", participant.to_owned()),
                ("page_index", page.page_index.to_string()),
                ("id", publication.id.to_string()),
                ("publisher", format_node_id(publication.publisher)),
                ("counter", publication.publisher_counter.to_string()),
                ("priority", priority_label(publication.priority).to_owned()),
                ("total_len", publication.total_len.to_string()),
                (
                    "media_type",
                    publication
                        .media_type
                        .as_deref()
                        .unwrap_or("none")
                        .to_owned(),
                ),
                ("schema_id_sha256", sha256_hex(&publication.schema_id)),
                (
                    "acceptance_marker",
                    publication.acceptance_marker.to_string(),
                ),
                ("offset", page.offset.to_string()),
                ("max_bytes", page.max_bytes.to_string()),
                ("page_len", page.page_len.to_string()),
                ("next_offset", page.next_offset.to_string()),
                ("complete", page.complete.to_string()),
                ("page_sha256", page.page_sha256.clone()),
            ],
        );
    }
    emit(
        "READ",
        &[
            ("phase", phase.to_owned()),
            ("participant", participant.to_owned()),
            ("id", publication.id.to_string()),
            ("publisher", format_node_id(publication.publisher)),
            ("counter", publication.publisher_counter.to_string()),
            ("priority", priority_label(publication.priority).to_owned()),
            ("total_len", publication.total_len.to_string()),
            (
                "media_type",
                publication
                    .media_type
                    .as_deref()
                    .unwrap_or("none")
                    .to_owned(),
            ),
            ("schema_id_sha256", sha256_hex(&publication.schema_id)),
            (
                "acceptance_marker",
                publication.acceptance_marker.to_string(),
            ),
            ("pages", read.pages.len().to_string()),
            ("max_page_bytes", MAX_SELECTED_BLOB_PAGE_BYTES.to_string()),
            ("payload_sha256", read.payload_sha256.clone()),
        ],
    );
}

fn emit_shutdown(phase: &str, participant: &str, receipt: &NodeReceipt) {
    emit(
        "SHUTDOWN",
        &[
            ("phase", phase.to_owned()),
            ("participant", participant.to_owned()),
            ("contacts", receipt.contacts.to_string()),
            ("contact_errors", receipt.contact_errors.to_string()),
            ("direct_contacts", receipt.direct_contacts.to_string()),
            ("relay_contacts", receipt.relay_contacts.to_string()),
            (
                "unknown_path_contacts",
                receipt.unknown_path_contacts.to_string(),
            ),
            (
                "carrier_path_transitions",
                receipt.carrier_path_transitions.to_string(),
            ),
            (
                "carrier_path_transition_saturations",
                receipt.carrier_path_transition_saturations.to_string(),
            ),
            ("items", receipt.items.to_string()),
            ("acceptance_markers", receipt.acceptance_markers.to_string()),
            ("events", receipt.events.to_string()),
            (
                "event_acceptance_markers",
                receipt.event_acceptance_markers.to_string(),
            ),
            (
                "route_cached_events",
                receipt.route_cached_events.to_string(),
            ),
            ("controls", receipt.controls.to_string()),
            ("applied_controls", receipt.applied_controls.to_string()),
            ("pending_controls", receipt.pending_controls.to_string()),
            ("control_highwater", receipt.control_highwater.to_string()),
            (
                "blob_ranges_fetched",
                receipt.blob_ranges_fetched.to_string(),
            ),
            ("blob_bytes_fetched", receipt.blob_bytes_fetched.to_string()),
            ("blob_remaining", receipt.blob_remaining.to_string()),
            ("blob_deferred", receipt.blob_deferred.to_string()),
            ("blobs", receipt.blobs.to_string()),
            (
                "blob_acceptance_markers",
                receipt.blob_acceptance_markers.to_string(),
            ),
            (
                "blob_last_acceptance_marker",
                receipt.blob_last_acceptance_marker.to_string(),
            ),
            ("blob_sealed_bytes", receipt.blob_sealed_bytes.to_string()),
            ("blob_operations", receipt.blob_operations.to_string()),
            (
                "blob_operation_bytes",
                receipt.blob_operation_bytes.to_string(),
            ),
            ("blob_variants", receipt.blob_variants.to_string()),
            (
                "blob_finalized_variants",
                receipt.blob_finalized_variants.to_string(),
            ),
            (
                "blob_committed_chunks",
                receipt.blob_committed_chunks.to_string(),
            ),
            (
                "blob_committed_file_bytes",
                receipt.blob_committed_file_bytes.to_string(),
            ),
            (
                "blob_reserved_file_bytes",
                receipt.blob_reserved_file_bytes.to_string(),
            ),
            ("pending_blobs", receipt.pending_blobs.to_string()),
            (
                "blob_carrier_prefixes",
                receipt.blob_carrier_prefixes.to_string(),
            ),
            (
                "blob_carrier_fetch_cursors",
                receipt.blob_carrier_fetch_cursors.to_string(),
            ),
            (
                "blob_network_staging_bytes",
                receipt.blob_network_staging_bytes.to_string(),
            ),
        ],
    );
}

fn emit_closed_handle(phase: &str, participant: &str) {
    emit(
        "CLOSED_HANDLE",
        &[
            ("phase", phase.to_owned()),
            ("participant", participant.to_owned()),
            ("error_kind", "state_unavailable".to_owned()),
            ("operation", "blob_read_page".to_owned()),
        ],
    );
}

fn emit(record: &str, fields: &[(&str, String)]) {
    print!("LIVE_BLOB\t{record}");
    for (key, value) in fields {
        print!("\t{key}={value}");
    }
    println!();
}
