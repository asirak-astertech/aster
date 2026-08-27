//! Retained one-host acceptance producer for the live selected State/Record API.
//!
//! The executable deliberately writes no application payload, operation key,
//! provisioning byte, path, socket, or process identifier into its terminal
//! `LIVE_MUTABLE` transcript. Runtime `READY`/`CONTACT`/`STOP` records remain in
//! stdout so an independent projector can cross-check the actor observations.

use std::{
    collections::BTreeSet,
    env,
    error::Error,
    fmt, fs,
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
        ApplicationError, ApplicationErrorKind, Priority, RecordId, RecordItem, RecordProjection,
        RecordPublishRequest, RecordPublishResult, RecordQuery, RecordResolveRequest,
        RecordVersionDisposition, Scope, StateId, StateItem, StateProjection, StatePublishRequest,
        StatePublishResult, StateQuery, StateVersionDisposition, Topic,
    },
    format_node_id,
    mission::UnprotectedReferenceMission,
    start_node,
};
use sha2::{Digest as _, Sha256};
use tokio::time::{sleep, timeout};
use zeroize::Zeroize as _;

const TRANSCRIPT_SCHEMA: &str = "aster-selected-live-mutable-transcript/v1";
const CLAIM: &str = "selected-live-state-record-one-host-direct-iroh-two-actor-acceptance";
const TOPIC: &str = "opaque";
const SCOPE: &str = "test/runtime-contact";
const STATE_KEY: &[u8] = b"disconnected-state";
const RECORD_KEY: &[u8] = b"disconnected-record";
const LEFT_STATE_PAYLOAD: &[u8] = b"left State";
const RIGHT_STATE_PAYLOAD: &[u8] = b"right State";
const LEFT_RECORD_PAYLOAD: &[u8] = b"left Record";
const RIGHT_RECORD_PAYLOAD: &[u8] = b"right Record";
const RESOLVED_RECORD_PAYLOAD: &[u8] = b"resolved Record";
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

#[derive(Clone)]
struct PublicationEvidence {
    id: String,
    publisher: String,
    counter: u64,
    payload_sha256: String,
    inserted: bool,
}

#[derive(Clone)]
struct ItemEvidence {
    id: String,
    publisher: String,
    counter: u64,
    payload_sha256: String,
    disposition: &'static str,
}

#[derive(Clone)]
struct StateViewEvidence {
    current: ItemEvidence,
    concurrent: ItemEvidence,
}

#[derive(Clone)]
struct RecordConflictEvidence {
    current: ItemEvidence,
    concurrent: ItemEvidence,
    siblings: Vec<String>,
    guard_siblings: Vec<String>,
}

#[derive(Clone)]
struct RecordResolvedEvidence {
    current: ItemEvidence,
    superseded: Vec<String>,
}

#[derive(Clone, Copy)]
struct ShutdownEvidence {
    contacts: usize,
    direct_contacts: usize,
    relay_contacts: usize,
    unknown_path_contacts: usize,
    contact_errors: usize,
}

impl From<&NodeReceipt> for ShutdownEvidence {
    fn from(receipt: &NodeReceipt) -> Self {
        Self {
            contacts: receipt.contacts,
            direct_contacts: receipt.direct_contacts,
            relay_contacts: receipt.relay_contacts,
            unknown_path_contacts: receipt.unknown_path_contacts,
            contact_errors: receipt.contact_errors,
        }
    }
}

struct ParticipantTranscript {
    name: &'static str,
    carrier_id: String,
    mission_id: String,
    mission_authority: String,
    expected_carrier_peer: String,
    expected_mission_peer: String,
    state_identity: String,
    state_authority: String,
    record_identity: String,
    record_authority: String,
}

struct AcceptanceTranscript {
    participants: [ParticipantTranscript; 2],
    state_publications: [PublicationEvidence; 2],
    state_retry_ids: [String; 2],
    record_publications: [PublicationEvidence; 2],
    record_retry_ids: [String; 2],
    peerless_shutdowns: [ShutdownEvidence; 2],
    connected_state: [StateViewEvidence; 2],
    connected_conflicts: [RecordConflictEvidence; 2],
    rejection_siblings: Vec<String>,
    resolution: PublicationEvidence,
    resolution_observed: Vec<String>,
    immediate_retry_id: String,
    connected_resolved: [RecordResolvedEvidence; 2],
    connected_shutdowns: [ShutdownEvidence; 2],
    restarted_state: [StateViewEvidence; 2],
    restarted_resolved: [RecordResolvedEvidence; 2],
    post_restart_retry_id: String,
    restart_shutdowns: [ShutdownEvidence; 2],
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
        eprintln!("LIVE_MUTABLE_FAILURE status=error stage={stage}");
        std::process::exit(1);
    }
}

async fn run() -> Result<(), DynError> {
    let raw_root = parse_raw_root()?;
    let topic = Topic::new(TOPIC)?;
    let scope = Scope::new(SCOPE)?;
    let participants_root = raw_root.join("participants");
    create_owner_directory(&participants_root)?;
    let [node_a, node_b] = provision_participants(&participants_root, &topic, &scope)?;

    require(node_a.mission_id != node_b.mission_id, "mission identities")?;
    require(node_a.carrier_id != node_b.carrier_id, "carrier identities")?;
    require(
        node_a.mission_authority == node_b.mission_authority,
        "common mission authority",
    )?;
    let identity_domains = [
        node_a.carrier_id.to_string(),
        node_b.carrier_id.to_string(),
        format_node_id(node_a.mission_id),
        format_node_id(node_b.mission_id),
        format_node_id(node_a.mission_authority),
    ];
    require(
        identity_domains.iter().collect::<BTreeSet<_>>().len() == identity_domains.len(),
        "identity domains",
    )?;

    let state_query = StateQuery {
        topic: topic.clone(),
        scope: scope.clone(),
        logical_key: STATE_KEY.to_vec(),
        include_recoverable_versions: true,
    };
    let record_query = RecordQuery {
        topic: topic.clone(),
        scope: scope.clone(),
        logical_key: RECORD_KEY.to_vec(),
        include_superseded_versions: true,
    };

    let left_offline = start_peerless(&node_a).await?;
    let right_offline = start_peerless(&node_b).await?;
    let left_state_handle = left_offline.selected_state();
    let right_state_handle = right_offline.selected_state();
    let left_record_handle = left_offline.selected_records();
    let right_record_handle = right_offline.selected_records();
    validate_handle_binding(
        &node_a,
        left_state_handle.identity(),
        left_state_handle.mission_authority(),
        left_record_handle.identity(),
        left_record_handle.mission_authority(),
    )?;
    validate_handle_binding(
        &node_b,
        right_state_handle.identity(),
        right_state_handle.mission_authority(),
        right_record_handle.identity(),
        right_record_handle.mission_authority(),
    )?;

    let left_state_request = StatePublishRequest {
        operation_key: b"left-disconnected-state".to_vec(),
        topic: topic.clone(),
        scope: scope.clone(),
        priority: Priority::Priority,
        logical_key: STATE_KEY.to_vec(),
        payload: LEFT_STATE_PAYLOAD.to_vec(),
        tombstone: false,
    };
    let right_state_request = StatePublishRequest {
        operation_key: b"right-disconnected-state".to_vec(),
        payload: RIGHT_STATE_PAYLOAD.to_vec(),
        ..left_state_request.clone()
    };
    let left_state_publication = left_state_handle
        .publish(left_state_request.clone())
        .await?;
    let left_state_retry = left_state_handle.publish(left_state_request).await?;
    let right_state_publication = right_state_handle
        .publish(right_state_request.clone())
        .await?;
    let right_state_retry = right_state_handle.publish(right_state_request).await?;
    validate_publication_retry(
        &left_state_publication,
        &left_state_retry,
        node_a.mission_id,
    )?;
    validate_publication_retry(
        &right_state_publication,
        &right_state_retry,
        node_b.mission_id,
    )?;
    require(
        left_state_publication.id != right_state_publication.id,
        "distinct State identities",
    )?;

    let left_record_request = RecordPublishRequest {
        operation_key: b"left-disconnected-record".to_vec(),
        topic: topic.clone(),
        scope: scope.clone(),
        priority: Priority::Priority,
        logical_key: RECORD_KEY.to_vec(),
        payload: LEFT_RECORD_PAYLOAD.to_vec(),
        tombstone: false,
    };
    let right_record_request = RecordPublishRequest {
        operation_key: b"right-disconnected-record".to_vec(),
        payload: RIGHT_RECORD_PAYLOAD.to_vec(),
        ..left_record_request.clone()
    };
    let left_record_publication = left_record_handle
        .publish(left_record_request.clone())
        .await?;
    let left_record_retry = left_record_handle.publish(left_record_request).await?;
    let right_record_publication = right_record_handle
        .publish(right_record_request.clone())
        .await?;
    let right_record_retry = right_record_handle.publish(right_record_request).await?;
    validate_record_publication_retry(
        &left_record_publication,
        &left_record_retry,
        node_a.mission_id,
    )?;
    validate_record_publication_retry(
        &right_record_publication,
        &right_record_retry,
        node_b.mission_id,
    )?;
    require(
        left_record_publication.id != right_record_publication.id,
        "distinct Record identities",
    )?;
    require(
        left_record_publication.publisher_counter > left_state_publication.publisher_counter
            && right_record_publication.publisher_counter
                > right_state_publication.publisher_counter,
        "shared publisher frontier",
    )?;

    let (left_peerless_receipt, right_peerless_receipt) =
        tokio::join!(left_offline.shutdown(), right_offline.shutdown());
    let left_peerless_receipt = left_peerless_receipt?;
    let right_peerless_receipt = right_peerless_receipt?;
    validate_peerless_receipt(&left_peerless_receipt)?;
    validate_peerless_receipt(&right_peerless_receipt)?;

    validate_closed_state(&left_state_handle, state_query.clone()).await?;
    validate_closed_record(&left_record_handle, record_query.clone()).await?;
    validate_closed_state(&right_state_handle, state_query.clone()).await?;
    validate_closed_record(&right_record_handle, record_query.clone()).await?;

    let left_reservation = UdpSocket::bind(("127.0.0.1", 0))?;
    let right_reservation = UdpSocket::bind(("127.0.0.1", 0))?;
    let left_address = left_reservation.local_addr()?;
    let right_address = right_reservation.local_addr()?;
    require(left_address != right_address, "distinct connected binds")?;
    drop((left_reservation, right_reservation));

    let interests = MutableSourceInterests::new(
        vec![SourceInterestSelector::new(
            topic.clone(),
            scope.clone(),
            false,
        )],
        vec![SourceInterestSelector::new(
            topic.clone(),
            scope.clone(),
            false,
        )],
    );
    let left_config = connected_config(
        &node_a,
        left_address,
        &node_b,
        right_address,
        interests.clone(),
    );
    let right_config = connected_config(&node_b, right_address, &node_a, left_address, interests);
    let (left_running, right_running) = if node_a.carrier_id > node_b.carrier_id {
        let left = start_node(left_config).await?;
        let right = start_node(right_config).await?;
        (left, right)
    } else {
        let right = start_node(right_config).await?;
        let left = start_node(left_config).await?;
        (left, right)
    };
    let left_live_state = left_running.selected_state();
    let right_live_state = right_running.selected_state();
    let left_live_records = left_running.selected_records();
    let right_live_records = right_running.selected_records();
    let left_live_status = left_running.selected_events();
    let right_live_status = right_running.selected_events();

    let expected_state_ids =
        sorted_state_ids(left_state_publication.id, right_state_publication.id);
    let expected_record_ids =
        sorted_record_ids(left_record_publication.id, right_record_publication.id);
    let (connected_state, connected_conflicts, left_conflict_projection) =
        timeout(POLL_DEADLINE, async {
            loop {
                let left_state = match left_live_state.query(state_query.clone()).await {
                    Ok(projection) => projection,
                    Err(error) if error.kind() == ApplicationErrorKind::PolicyUnsettled => {
                        sleep(Duration::from_millis(20)).await;
                        continue;
                    }
                    Err(error) => return Err(error.into()),
                };
                let right_state = match right_live_state.query(state_query.clone()).await {
                    Ok(projection) => projection,
                    Err(error) if error.kind() == ApplicationErrorKind::PolicyUnsettled => {
                        sleep(Duration::from_millis(20)).await;
                        continue;
                    }
                    Err(error) => return Err(error.into()),
                };
                let left_record = match left_live_records.query(record_query.clone()).await {
                    Ok(projection) => projection,
                    Err(error) if is_transient_record_query(&error) => {
                        sleep(Duration::from_millis(20)).await;
                        continue;
                    }
                    Err(error) => return Err(error.into()),
                };
                let right_record = match right_live_records.query(record_query.clone()).await {
                    Ok(projection) => projection,
                    Err(error) if is_transient_record_query(&error) => {
                        sleep(Duration::from_millis(20)).await;
                        continue;
                    }
                    Err(error) => return Err(error.into()),
                };
                if projections_converged(
                    &left_state,
                    &right_state,
                    &left_record,
                    &right_record,
                    expected_state_ids,
                    &expected_record_ids,
                ) {
                    break Ok::<_, DynError>((
                        [left_state, right_state],
                        [left_record.clone(), right_record],
                        left_record,
                    ));
                }
                sleep(Duration::from_millis(20)).await;
            }
        })
        .await
        .map_err(|_| AcceptanceFailure("connected convergence deadline"))??;

    let connected_state_evidence = [
        validate_state_view(
            &connected_state[0],
            &topic,
            &scope,
            &left_state_publication,
            &right_state_publication,
        )?,
        validate_state_view(
            &connected_state[1],
            &topic,
            &scope,
            &left_state_publication,
            &right_state_publication,
        )?,
    ];
    require(
        connected_state_evidence[0].current.id == connected_state_evidence[1].current.id
            && connected_state_evidence[0].concurrent.id
                == connected_state_evidence[1].concurrent.id,
        "identical connected State projections",
    )?;
    let connected_conflict_evidence = [
        validate_record_conflict(
            &connected_conflicts[0],
            &topic,
            &scope,
            &left_record_publication,
            &right_record_publication,
            &expected_record_ids,
        )?,
        validate_record_conflict(
            &connected_conflicts[1],
            &topic,
            &scope,
            &left_record_publication,
            &right_record_publication,
            &expected_record_ids,
        )?,
    ];
    require(
        connected_conflict_evidence[0].siblings == connected_conflict_evidence[1].siblings
            && connected_conflict_evidence[0].guard_siblings
                == connected_conflict_evidence[1].guard_siblings,
        "identical connected Record conflicts",
    )?;
    let _initial_connected_contact = wait_for_contact_advance(
        &left_live_status,
        &right_live_status,
        [0, 0],
        "initial connected contact accounting deadline",
    )
    .await?;

    let before_siblings = connected_conflict_evidence[0].siblings.clone();
    let ordinary_request = RecordPublishRequest {
        operation_key: b"ordinary-publish-cannot-hide-conflict".to_vec(),
        topic: topic.clone(),
        scope: scope.clone(),
        priority: Priority::Priority,
        logical_key: RECORD_KEY.to_vec(),
        payload: b"must not replace disconnected siblings".to_vec(),
        tombstone: false,
    };
    let ordinary_error = timeout(POLL_DEADLINE, async {
        loop {
            match left_live_records.publish(ordinary_request.clone()).await {
                Err(error) if error.kind() == ApplicationErrorKind::PolicyUnsettled => {
                    sleep(Duration::from_millis(20)).await;
                }
                Err(error) => break Ok::<_, DynError>(error),
                Ok(_) => {
                    break Err(
                        Box::new(AcceptanceFailure("ordinary Record publication")) as DynError
                    );
                }
            }
        }
    })
    .await
    .map_err(|_| AcceptanceFailure("ordinary rejection deadline"))??;
    require(
        ordinary_error.kind() == ApplicationErrorKind::Conflict
            && ordinary_error.operation() == "record publish",
        "ordinary Record conflict",
    )?;
    let after_rejection = query_record_eventually(
        &left_live_records,
        record_query.clone(),
        "post-rejection Record query deadline",
    )
    .await?;
    let after_conflict = validate_record_conflict(
        &after_rejection,
        &topic,
        &scope,
        &left_record_publication,
        &right_record_publication,
        &expected_record_ids,
    )?;
    require(
        after_conflict.siblings == before_siblings,
        "Record conflict preserved",
    )?;

    let resolution_guard = left_conflict_projection
        .conflict
        .ok_or(AcceptanceFailure("missing resolution guard"))?
        .resolution_guard;
    require(
        record_ids_as_strings(resolution_guard.siblings()) == before_siblings,
        "resolution guard siblings",
    )?;
    let resolution_request = RecordResolveRequest {
        operation_key: b"resolve-disconnected-record".to_vec(),
        resolution_guard,
        priority: Priority::Immediate,
        payload: RESOLVED_RECORD_PAYLOAD.to_vec(),
        tombstone: false,
    };
    let restart_resolution_request = resolution_request.clone();
    let resolved = resolve_eventually(&left_live_records, resolution_request.clone()).await?;
    let immediate_retry = resolve_eventually(&left_live_records, resolution_request).await?;
    require(resolved.inserted, "Record resolution insertion")?;
    require(
        !immediate_retry.inserted && immediate_retry.id == resolved.id,
        "immediate Record resolution retry",
    )?;
    let resolution_contact_baseline =
        snapshot_contact_counters(&left_live_status, &right_live_status).await?;

    let connected_resolved = timeout(POLL_DEADLINE, async {
        loop {
            let left = match left_live_records.query(record_query.clone()).await {
                Ok(projection) => projection,
                Err(error) if is_transient_record_query(&error) => {
                    sleep(Duration::from_millis(20)).await;
                    continue;
                }
                Err(error) => return Err(error.into()),
            };
            let right = match right_live_records.query(record_query.clone()).await {
                Ok(projection) => projection,
                Err(error) if is_transient_record_query(&error) => {
                    sleep(Duration::from_millis(20)).await;
                    continue;
                }
                Err(error) => return Err(error.into()),
            };
            if resolved_projection_ready(&left, resolved.id, &expected_record_ids)
                && resolved_projection_ready(&right, resolved.id, &expected_record_ids)
            {
                break Ok::<_, DynError>([left, right]);
            }
            sleep(Duration::from_millis(20)).await;
        }
    })
    .await
    .map_err(|_| AcceptanceFailure("resolution convergence deadline"))??;
    let connected_resolved_evidence = [
        validate_record_resolved(
            &connected_resolved[0],
            &topic,
            &scope,
            &resolved,
            &expected_record_ids,
        )?,
        validate_record_resolved(
            &connected_resolved[1],
            &topic,
            &scope,
            &resolved,
            &expected_record_ids,
        )?,
    ];

    let _resolution_contact = wait_for_contact_advance(
        &left_live_status,
        &right_live_status,
        resolution_contact_baseline,
        "resolution contact accounting deadline",
    )
    .await?;

    let (left_connected_receipt, right_connected_receipt) =
        tokio::join!(left_running.shutdown(), right_running.shutdown());
    let left_connected_receipt = left_connected_receipt?;
    let right_connected_receipt = right_connected_receipt?;
    validate_connected_receipt(&left_connected_receipt)?;
    validate_connected_receipt(&right_connected_receipt)?;
    require(
        left_connected_receipt.contacts == right_connected_receipt.contacts,
        "paired connected contact accounting",
    )?;

    let left_restarted = start_peerless(&node_a).await?;
    let right_restarted = start_peerless(&node_b).await?;
    let left_restarted_state = left_restarted.selected_state();
    let right_restarted_state = right_restarted.selected_state();
    let left_restarted_records = left_restarted.selected_records();
    let right_restarted_records = right_restarted.selected_records();
    let restarted_state_projections = [
        left_restarted_state.query(state_query.clone()).await?,
        right_restarted_state.query(state_query).await?,
    ];
    let restarted_record_projections = [
        left_restarted_records.query(record_query.clone()).await?,
        right_restarted_records.query(record_query).await?,
    ];
    let restarted_state_evidence = [
        validate_state_view(
            &restarted_state_projections[0],
            &topic,
            &scope,
            &left_state_publication,
            &right_state_publication,
        )?,
        validate_state_view(
            &restarted_state_projections[1],
            &topic,
            &scope,
            &left_state_publication,
            &right_state_publication,
        )?,
    ];
    let restarted_resolved_evidence = [
        validate_record_resolved(
            &restarted_record_projections[0],
            &topic,
            &scope,
            &resolved,
            &expected_record_ids,
        )?,
        validate_record_resolved(
            &restarted_record_projections[1],
            &topic,
            &scope,
            &resolved,
            &expected_record_ids,
        )?,
    ];
    let post_restart_retry = left_restarted_records
        .resolve(restart_resolution_request)
        .await?;
    require(
        !post_restart_retry.inserted && post_restart_retry.id == resolved.id,
        "post-restart Record resolution retry",
    )?;

    let (left_restart_receipt, right_restart_receipt) =
        tokio::join!(left_restarted.shutdown(), right_restarted.shutdown());
    let left_restart_receipt = left_restart_receipt?;
    let right_restart_receipt = right_restart_receipt?;
    validate_peerless_receipt(&left_restart_receipt)?;
    validate_peerless_receipt(&right_restart_receipt)?;

    let left_reacquired = UdpSocket::bind(left_address)?;
    let right_reacquired = UdpSocket::bind(right_address)?;
    require(
        left_reacquired.local_addr()? == left_address
            && right_reacquired.local_addr()? == right_address,
        "configured bind reacquisition",
    )?;

    let transcript = AcceptanceTranscript {
        participants: [
            participant_transcript(
                &node_a,
                &node_b,
                left_state_handle.identity(),
                left_state_handle.mission_authority(),
                left_record_handle.identity(),
                left_record_handle.mission_authority(),
            ),
            participant_transcript(
                &node_b,
                &node_a,
                right_state_handle.identity(),
                right_state_handle.mission_authority(),
                right_record_handle.identity(),
                right_record_handle.mission_authority(),
            ),
        ],
        state_publications: [
            state_publication_evidence(&left_state_publication, LEFT_STATE_PAYLOAD),
            state_publication_evidence(&right_state_publication, RIGHT_STATE_PAYLOAD),
        ],
        state_retry_ids: [
            left_state_retry.id.to_string(),
            right_state_retry.id.to_string(),
        ],
        record_publications: [
            record_publication_evidence(&left_record_publication, LEFT_RECORD_PAYLOAD),
            record_publication_evidence(&right_record_publication, RIGHT_RECORD_PAYLOAD),
        ],
        record_retry_ids: [
            left_record_retry.id.to_string(),
            right_record_retry.id.to_string(),
        ],
        peerless_shutdowns: [
            ShutdownEvidence::from(&left_peerless_receipt),
            ShutdownEvidence::from(&right_peerless_receipt),
        ],
        connected_state: connected_state_evidence,
        connected_conflicts: connected_conflict_evidence,
        rejection_siblings: before_siblings.clone(),
        resolution: record_publication_evidence(&resolved, RESOLVED_RECORD_PAYLOAD),
        resolution_observed: before_siblings,
        immediate_retry_id: immediate_retry.id.to_string(),
        connected_resolved: connected_resolved_evidence,
        connected_shutdowns: [
            ShutdownEvidence::from(&left_connected_receipt),
            ShutdownEvidence::from(&right_connected_receipt),
        ],
        restarted_state: restarted_state_evidence,
        restarted_resolved: restarted_resolved_evidence,
        post_restart_retry_id: post_restart_retry.id.to_string(),
        restart_shutdowns: [
            ShutdownEvidence::from(&left_restart_receipt),
            ShutdownEvidence::from(&right_restart_receipt),
        ],
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
    let node_a_bundle = provisioner.issue_node(1, std::slice::from_ref(&access))?;
    let node_b_bundle = provisioner.issue_node(2, std::slice::from_ref(&access))?;
    let node_a = persist_participant(participants_root, "node-a", node_a_bundle.to_bytes()?)?;
    let node_b = persist_participant(participants_root, "node-b", node_b_bundle.to_bytes()?)?;
    Ok([node_a, node_b])
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
        sync_interval: Duration::from_secs(5),
        run_for: None,
        application: NodeApplication::Relay,
    }
}

fn validate_handle_binding(
    participant: &Participant,
    state_identity: [u8; 32],
    state_authority: [u8; 32],
    record_identity: [u8; 32],
    record_authority: [u8; 32],
) -> Result<(), DynError> {
    require(
        state_identity == participant.mission_id
            && record_identity == participant.mission_id
            && state_authority == participant.mission_authority
            && record_authority == participant.mission_authority,
        "live handle mission binding",
    )
}

fn validate_publication_retry(
    publication: &StatePublishResult,
    retry: &StatePublishResult,
    publisher: [u8; 32],
) -> Result<(), DynError> {
    require(
        publication.inserted
            && !retry.inserted
            && publication.id == retry.id
            && publication.publisher == publisher
            && retry.publisher == publisher
            && publication.publisher_counter == retry.publisher_counter
            && publication.priority == Priority::Priority
            && publication.acceptance_marker == retry.acceptance_marker,
        "State exact retry",
    )
}

fn validate_record_publication_retry(
    publication: &RecordPublishResult,
    retry: &RecordPublishResult,
    publisher: [u8; 32],
) -> Result<(), DynError> {
    require(
        publication.inserted
            && !retry.inserted
            && publication.id == retry.id
            && publication.publisher == publisher
            && retry.publisher == publisher
            && publication.publisher_counter == retry.publisher_counter
            && publication.priority == Priority::Priority
            && publication.acceptance_marker == retry.acceptance_marker,
        "Record exact retry",
    )
}

fn validate_peerless_receipt(receipt: &NodeReceipt) -> Result<(), DynError> {
    require(
        receipt.contacts == 0
            && receipt.direct_contacts == 0
            && receipt.relay_contacts == 0
            && receipt.unknown_path_contacts == 0
            && receipt.contact_errors == 0,
        "peerless shutdown receipt",
    )
}

fn validate_connected_receipt(receipt: &NodeReceipt) -> Result<(), DynError> {
    require(
        receipt.contacts > 0
            && receipt.direct_contacts == receipt.contacts
            && receipt.relay_contacts == 0
            && receipt.unknown_path_contacts == 0
            && receipt.contact_errors == 0,
        "direct-only connected shutdown receipt",
    )
}

async fn validate_closed_state(
    handle: &aster_node::application::SelectedStateHandle,
    query: StateQuery,
) -> Result<(), DynError> {
    let error = match handle.query(query).await {
        Err(error) => error,
        Ok(_) => return Err(Box::new(AcceptanceFailure("closed State handle accepted"))),
    };
    require(
        error.kind() == ApplicationErrorKind::StateUnavailable
            && error.operation() == "state query",
        "closed State handle",
    )
}

async fn validate_closed_record(
    handle: &aster_node::application::SelectedRecordHandle,
    query: RecordQuery,
) -> Result<(), DynError> {
    let error = match handle.query(query).await {
        Err(error) => error,
        Ok(_) => return Err(Box::new(AcceptanceFailure("closed Record handle accepted"))),
    };
    require(
        error.kind() == ApplicationErrorKind::StateUnavailable
            && error.operation() == "record query",
        "closed Record handle",
    )
}

fn is_transient_record_query(error: &ApplicationError) -> bool {
    matches!(
        error.kind(),
        ApplicationErrorKind::PolicyUnsettled | ApplicationErrorKind::Conflict
    ) && error.operation() == "record query"
}

async fn query_record_eventually(
    handle: &aster_node::application::SelectedRecordHandle,
    query: RecordQuery,
    deadline_label: &'static str,
) -> Result<RecordProjection, DynError> {
    timeout(POLL_DEADLINE, async {
        loop {
            match handle.query(query.clone()).await {
                Ok(projection) => break Ok::<_, DynError>(projection),
                Err(error) if is_transient_record_query(&error) => {
                    sleep(Duration::from_millis(20)).await;
                }
                Err(error) => break Err(error.into()),
            }
        }
    })
    .await
    .map_err(|_| AcceptanceFailure(deadline_label))?
}

async fn resolve_eventually(
    handle: &aster_node::application::SelectedRecordHandle,
    request: RecordResolveRequest,
) -> Result<RecordPublishResult, DynError> {
    timeout(POLL_DEADLINE, async {
        loop {
            match handle.resolve(request.clone()).await {
                Ok(result) => break Ok::<_, DynError>(result),
                Err(error) if error.kind() == ApplicationErrorKind::PolicyUnsettled => {
                    sleep(Duration::from_millis(20)).await;
                }
                Err(error) => break Err(error.into()),
            }
        }
    })
    .await
    .map_err(|_| AcceptanceFailure("Record resolution deadline"))?
}

async fn wait_for_contact_advance(
    left: &aster_node::application::SelectedEventHandle,
    right: &aster_node::application::SelectedEventHandle,
    baseline: [u64; 2],
    deadline_label: &'static str,
) -> Result<[u64; 2], DynError> {
    timeout(POLL_DEADLINE, async {
        loop {
            let left_status = left.status().await?;
            let right_status = right.status().await?;
            require(
                left_status.failed_contact_attempts == 0
                    && right_status.failed_contact_attempts == 0,
                "connected status contact errors",
            )?;
            if left_status.authenticated_contacts > baseline[0]
                && right_status.authenticated_contacts > baseline[1]
            {
                break Ok::<_, DynError>([
                    left_status.authenticated_contacts,
                    right_status.authenticated_contacts,
                ]);
            }
            sleep(Duration::from_millis(20)).await;
        }
    })
    .await
    .map_err(|_| AcceptanceFailure(deadline_label))?
}

async fn snapshot_contact_counters(
    left: &aster_node::application::SelectedEventHandle,
    right: &aster_node::application::SelectedEventHandle,
) -> Result<[u64; 2], DynError> {
    let left_status = left.status().await?;
    let right_status = right.status().await?;
    require(
        left_status.authenticated_contacts > 0
            && right_status.authenticated_contacts > 0
            && left_status.failed_contact_attempts == 0
            && right_status.failed_contact_attempts == 0,
        "resolution baseline contact status",
    )?;
    Ok([
        left_status.authenticated_contacts,
        right_status.authenticated_contacts,
    ])
}

fn sorted_state_ids(left: StateId, right: StateId) -> [StateId; 2] {
    if left < right {
        [left, right]
    } else {
        [right, left]
    }
}

fn sorted_record_ids(left: RecordId, right: RecordId) -> Vec<RecordId> {
    [left, right]
        .into_iter()
        .collect::<BTreeSet<_>>()
        .into_iter()
        .collect()
}

fn projections_converged(
    left_state: &StateProjection,
    right_state: &StateProjection,
    left_record: &RecordProjection,
    right_record: &RecordProjection,
    state_ids: [StateId; 2],
    record_ids: &[RecordId],
) -> bool {
    let state_ready = |projection: &StateProjection| {
        projection
            .current
            .as_ref()
            .is_some_and(|item| item.id == state_ids[1])
            && projection.recoverable.len() == 1
            && projection.recoverable[0].id == state_ids[0]
    };
    let record_ready = |projection: &RecordProjection| {
        projection
            .conflict
            .as_ref()
            .is_some_and(|conflict| conflict.siblings == record_ids)
    };
    state_ready(left_state)
        && state_ready(right_state)
        && record_ready(left_record)
        && record_ready(right_record)
}

fn validate_state_view(
    projection: &StateProjection,
    topic: &Topic,
    scope: &Scope,
    left: &StatePublishResult,
    right: &StatePublishResult,
) -> Result<StateViewEvidence, DynError> {
    require(
        projection.recoverable.len() == 1,
        "State recovery cardinality",
    )?;
    let current = projection
        .current
        .as_ref()
        .ok_or(AcceptanceFailure("State current missing"))?;
    let concurrent = &projection.recoverable[0];
    require(
        current.id == left.id.max(right.id),
        "deterministic State current",
    )?;
    require(
        concurrent.id == left.id.min(right.id),
        "deterministic State concurrent",
    )?;
    Ok(StateViewEvidence {
        current: validate_state_item(
            current,
            topic,
            scope,
            left,
            right,
            StateVersionDisposition::Current,
        )?,
        concurrent: validate_state_item(
            concurrent,
            topic,
            scope,
            left,
            right,
            StateVersionDisposition::Concurrent,
        )?,
    })
}

fn validate_state_item(
    item: &StateItem,
    topic: &Topic,
    scope: &Scope,
    left: &StatePublishResult,
    right: &StatePublishResult,
    disposition: StateVersionDisposition,
) -> Result<ItemEvidence, DynError> {
    let (expected, payload) = if item.id == left.id {
        (left, LEFT_STATE_PAYLOAD)
    } else if item.id == right.id {
        (right, RIGHT_STATE_PAYLOAD)
    } else {
        return Err(Box::new(AcceptanceFailure("unknown State item")));
    };
    require(
        item.publisher == expected.publisher
            && item.publisher_counter == expected.publisher_counter
            && item.topic == *topic
            && item.scope == *scope
            && item.priority == Priority::Priority
            && item.logical_key == STATE_KEY
            && item.payload == payload
            && !item.tombstone
            && item.disposition == disposition,
        "verified State item",
    )?;
    Ok(ItemEvidence {
        id: item.id.to_string(),
        publisher: format_node_id(item.publisher),
        counter: item.publisher_counter,
        payload_sha256: sha256_hex(&item.payload),
        disposition: state_disposition(item.disposition),
    })
}

fn validate_record_conflict(
    projection: &RecordProjection,
    topic: &Topic,
    scope: &Scope,
    left: &RecordPublishResult,
    right: &RecordPublishResult,
    expected_ids: &[RecordId],
) -> Result<RecordConflictEvidence, DynError> {
    require(
        projection.concurrent.len() == 1 && projection.superseded.is_empty(),
        "Record conflict lanes",
    )?;
    let current = projection
        .current
        .as_ref()
        .ok_or(AcceptanceFailure("Record conflict current missing"))?;
    let concurrent = &projection.concurrent[0];
    let conflict = projection
        .conflict
        .as_ref()
        .ok_or(AcceptanceFailure("Record conflict annotation missing"))?;
    require(
        conflict.siblings == expected_ids,
        "Record conflict siblings",
    )?;
    require(
        conflict.resolution_guard.siblings() == expected_ids,
        "Record guard siblings",
    )?;
    require(
        current.id == left.id.max(right.id) && concurrent.id == left.id.min(right.id),
        "deterministic Record lanes",
    )?;
    Ok(RecordConflictEvidence {
        current: validate_record_item(
            current,
            topic,
            scope,
            left,
            right,
            RecordVersionDisposition::Current,
        )?,
        concurrent: validate_record_item(
            concurrent,
            topic,
            scope,
            left,
            right,
            RecordVersionDisposition::Concurrent,
        )?,
        siblings: record_ids_as_strings(&conflict.siblings),
        guard_siblings: record_ids_as_strings(conflict.resolution_guard.siblings()),
    })
}

fn validate_record_item(
    item: &RecordItem,
    topic: &Topic,
    scope: &Scope,
    left: &RecordPublishResult,
    right: &RecordPublishResult,
    disposition: RecordVersionDisposition,
) -> Result<ItemEvidence, DynError> {
    let (expected, payload) = if item.id == left.id {
        (left, LEFT_RECORD_PAYLOAD)
    } else if item.id == right.id {
        (right, RIGHT_RECORD_PAYLOAD)
    } else {
        return Err(Box::new(AcceptanceFailure("unknown Record item")));
    };
    require(
        item.publisher == expected.publisher
            && item.publisher_counter == expected.publisher_counter
            && item.topic == *topic
            && item.scope == *scope
            && item.priority == Priority::Priority
            && item.logical_key == RECORD_KEY
            && item.payload == payload
            && !item.tombstone
            && item.disposition == disposition,
        "verified Record conflict item",
    )?;
    Ok(ItemEvidence {
        id: item.id.to_string(),
        publisher: format_node_id(item.publisher),
        counter: item.publisher_counter,
        payload_sha256: sha256_hex(&item.payload),
        disposition: record_disposition(item.disposition),
    })
}

fn resolved_projection_ready(
    projection: &RecordProjection,
    resolved: RecordId,
    expected_superseded: &[RecordId],
) -> bool {
    projection
        .current
        .as_ref()
        .is_some_and(|item| item.id == resolved)
        && projection.concurrent.is_empty()
        && projection.conflict.is_none()
        && projection.superseded.len() == 2
        && projection
            .superseded
            .iter()
            .map(|item| item.id)
            .collect::<BTreeSet<_>>()
            == expected_superseded.iter().copied().collect::<BTreeSet<_>>()
}

fn validate_record_resolved(
    projection: &RecordProjection,
    topic: &Topic,
    scope: &Scope,
    resolved: &RecordPublishResult,
    expected_superseded: &[RecordId],
) -> Result<RecordResolvedEvidence, DynError> {
    require(
        projection.concurrent.is_empty()
            && projection.conflict.is_none()
            && projection.superseded.len() == 2,
        "resolved Record lanes",
    )?;
    let current = projection
        .current
        .as_ref()
        .ok_or(AcceptanceFailure("resolved Record current missing"))?;
    require(
        current.id == resolved.id
            && current.publisher == resolved.publisher
            && current.publisher_counter == resolved.publisher_counter
            && current.topic == *topic
            && current.scope == *scope
            && current.priority == Priority::Immediate
            && current.logical_key == RECORD_KEY
            && current.payload == RESOLVED_RECORD_PAYLOAD
            && !current.tombstone
            && current.disposition == RecordVersionDisposition::Current,
        "verified resolved Record current",
    )?;
    let superseded = projection
        .superseded
        .iter()
        .map(|item| {
            require(
                item.disposition == RecordVersionDisposition::Superseded,
                "Record superseded disposition",
            )?;
            Ok::<_, DynError>(item.id)
        })
        .collect::<Result<BTreeSet<_>, _>>()?;
    require(
        superseded == expected_superseded.iter().copied().collect(),
        "Record superseded identities",
    )?;
    Ok(RecordResolvedEvidence {
        current: ItemEvidence {
            id: current.id.to_string(),
            publisher: format_node_id(current.publisher),
            counter: current.publisher_counter,
            payload_sha256: sha256_hex(&current.payload),
            disposition: record_disposition(current.disposition),
        },
        superseded: superseded.into_iter().map(|id| id.to_string()).collect(),
    })
}

fn state_publication_evidence(result: &StatePublishResult, payload: &[u8]) -> PublicationEvidence {
    PublicationEvidence {
        id: result.id.to_string(),
        publisher: format_node_id(result.publisher),
        counter: result.publisher_counter,
        payload_sha256: sha256_hex(payload),
        inserted: result.inserted,
    }
}

fn record_publication_evidence(
    result: &RecordPublishResult,
    payload: &[u8],
) -> PublicationEvidence {
    PublicationEvidence {
        id: result.id.to_string(),
        publisher: format_node_id(result.publisher),
        counter: result.publisher_counter,
        payload_sha256: sha256_hex(payload),
        inserted: result.inserted,
    }
}

fn participant_transcript(
    local: &Participant,
    remote: &Participant,
    state_identity: [u8; 32],
    state_authority: [u8; 32],
    record_identity: [u8; 32],
    record_authority: [u8; 32],
) -> ParticipantTranscript {
    ParticipantTranscript {
        name: local.name,
        carrier_id: local.carrier_id.to_string(),
        mission_id: format_node_id(local.mission_id),
        mission_authority: format_node_id(local.mission_authority),
        expected_carrier_peer: remote.carrier_id.to_string(),
        expected_mission_peer: format_node_id(remote.mission_id),
        state_identity: format_node_id(state_identity),
        state_authority: format_node_id(state_authority),
        record_identity: format_node_id(record_identity),
        record_authority: format_node_id(record_authority),
    }
}

fn record_ids_as_strings(ids: &[RecordId]) -> Vec<String> {
    ids.iter().map(ToString::to_string).collect()
}

fn state_disposition(disposition: StateVersionDisposition) -> &'static str {
    match disposition {
        StateVersionDisposition::Current => "current",
        StateVersionDisposition::Concurrent => "concurrent",
        StateVersionDisposition::Superseded => "superseded",
    }
}

fn record_disposition(disposition: RecordVersionDisposition) -> &'static str {
    match disposition {
        RecordVersionDisposition::Current => "current",
        RecordVersionDisposition::Concurrent => "concurrent",
        RecordVersionDisposition::Superseded => "superseded",
    }
}

fn sha256_hex(bytes: &[u8]) -> String {
    let digest = Sha256::digest(bytes);
    let mut output = String::with_capacity(64);
    for byte in digest {
        use fmt::Write as _;
        let _ = write!(output, "{byte:02x}");
    }
    output
}

fn join_ids(ids: &[String]) -> String {
    ids.join(",")
}

fn emit_transcript(transcript: &AcceptanceTranscript) {
    emit(
        "RUN",
        &[
            ("schema", TRANSCRIPT_SCHEMA.to_owned()),
            ("claim", CLAIM.to_owned()),
            ("participants", "2".to_owned()),
            ("actor_lifetimes", "6".to_owned()),
            ("maximum_concurrent_actors", "2".to_owned()),
            ("topic", TOPIC.to_owned()),
            ("scope", SCOPE.to_owned()),
        ],
    );
    for participant in &transcript.participants {
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
    for participant in &transcript.participants {
        emit(
            "HANDLE",
            &[
                ("participant", participant.name.to_owned()),
                ("state_identity", participant.state_identity.clone()),
                ("state_authority", participant.state_authority.clone()),
                ("record_identity", participant.record_identity.clone()),
                ("record_authority", participant.record_authority.clone()),
            ],
        );
    }
    emit_publications(
        "STATE_PUBLICATION",
        &transcript.participants,
        &transcript.state_publications,
    );
    emit_retries(
        "STATE_RETRY",
        &transcript.participants,
        &transcript.state_publications,
        &transcript.state_retry_ids,
    );
    emit_publications(
        "RECORD_PUBLICATION",
        &transcript.participants,
        &transcript.record_publications,
    );
    emit_retries(
        "RECORD_RETRY",
        &transcript.participants,
        &transcript.record_publications,
        &transcript.record_retry_ids,
    );
    emit_shutdowns(
        "peerless",
        &transcript.participants,
        &transcript.peerless_shutdowns,
    );
    for participant in &transcript.participants {
        for (kind, operation) in [("state", "state_query"), ("record", "record_query")] {
            emit(
                "CLOSED_HANDLE",
                &[
                    ("participant", participant.name.to_owned()),
                    ("kind", kind.to_owned()),
                    ("error_kind", "state_unavailable".to_owned()),
                    ("operation", operation.to_owned()),
                ],
            );
        }
    }
    emit_state_views(
        "connected",
        &transcript.participants,
        &transcript.connected_state,
    );
    for (participant, conflict) in transcript
        .participants
        .iter()
        .zip(&transcript.connected_conflicts)
    {
        emit(
            "RECORD_CONFLICT",
            &[
                ("phase", "connected".to_owned()),
                ("participant", participant.name.to_owned()),
                ("current_id", conflict.current.id.clone()),
                ("current_publisher", conflict.current.publisher.clone()),
                ("current_counter", conflict.current.counter.to_string()),
                (
                    "current_payload_sha256",
                    conflict.current.payload_sha256.clone(),
                ),
                (
                    "current_disposition",
                    conflict.current.disposition.to_owned(),
                ),
                ("concurrent_id", conflict.concurrent.id.clone()),
                (
                    "concurrent_publisher",
                    conflict.concurrent.publisher.clone(),
                ),
                (
                    "concurrent_counter",
                    conflict.concurrent.counter.to_string(),
                ),
                (
                    "concurrent_payload_sha256",
                    conflict.concurrent.payload_sha256.clone(),
                ),
                (
                    "concurrent_disposition",
                    conflict.concurrent.disposition.to_owned(),
                ),
                ("conflict", "true".to_owned()),
                ("siblings", join_ids(&conflict.siblings)),
                ("guard_siblings", join_ids(&conflict.guard_siblings)),
            ],
        );
    }
    emit(
        "RECORD_REJECTION",
        &[
            ("participant", "node-a".to_owned()),
            ("error_kind", "conflict".to_owned()),
            ("operation", "record_publish".to_owned()),
            ("before_siblings", join_ids(&transcript.rejection_siblings)),
            ("after_siblings", join_ids(&transcript.rejection_siblings)),
            ("after_conflict", "true".to_owned()),
        ],
    );
    emit(
        "RECORD_RESOLUTION",
        &[
            ("participant", "node-a".to_owned()),
            (
                "observed_siblings",
                join_ids(&transcript.resolution_observed),
            ),
            ("id", transcript.resolution.id.clone()),
            ("publisher", transcript.resolution.publisher.clone()),
            ("counter", transcript.resolution.counter.to_string()),
            (
                "payload_sha256",
                transcript.resolution.payload_sha256.clone(),
            ),
            ("inserted", transcript.resolution.inserted.to_string()),
        ],
    );
    emit(
        "RECORD_RESOLUTION_RETRY",
        &[
            ("phase", "immediate".to_owned()),
            ("participant", "node-a".to_owned()),
            ("original_id", transcript.resolution.id.clone()),
            ("retry_id", transcript.immediate_retry_id.clone()),
            ("inserted", "false".to_owned()),
        ],
    );
    emit_resolved_views(
        "connected",
        &transcript.participants,
        &transcript.connected_resolved,
    );
    emit_shutdowns(
        "connected",
        &transcript.participants,
        &transcript.connected_shutdowns,
    );
    emit_state_views(
        "restart",
        &transcript.participants,
        &transcript.restarted_state,
    );
    emit_resolved_views(
        "restart",
        &transcript.participants,
        &transcript.restarted_resolved,
    );
    emit(
        "RECORD_RESOLUTION_RETRY",
        &[
            ("phase", "post_restart".to_owned()),
            ("participant", "node-a".to_owned()),
            ("original_id", transcript.resolution.id.clone()),
            ("retry_id", transcript.post_restart_retry_id.clone()),
            ("inserted", "false".to_owned()),
        ],
    );
    emit_shutdowns(
        "restart",
        &transcript.participants,
        &transcript.restart_shutdowns,
    );
    for participant in &transcript.participants {
        emit(
            "BIND_REACQUIRED",
            &[
                ("participant", participant.name.to_owned()),
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
            ("records", "40".to_owned()),
            ("actor_lifetimes", "6".to_owned()),
            ("maximum_concurrent_actors", "2".to_owned()),
            ("graceful_shutdowns", "6".to_owned()),
            ("retained_handles", "4".to_owned()),
            ("closed_handles", "4".to_owned()),
            ("bind_reacquisitions", "2".to_owned()),
        ],
    );
}

fn emit_publications(
    record: &str,
    participants: &[ParticipantTranscript; 2],
    publications: &[PublicationEvidence; 2],
) {
    for (participant, publication) in participants.iter().zip(publications) {
        emit(
            record,
            &[
                ("participant", participant.name.to_owned()),
                ("id", publication.id.clone()),
                ("publisher", publication.publisher.clone()),
                ("counter", publication.counter.to_string()),
                ("payload_sha256", publication.payload_sha256.clone()),
                ("inserted", publication.inserted.to_string()),
            ],
        );
    }
}

fn emit_retries(
    record: &str,
    participants: &[ParticipantTranscript; 2],
    publications: &[PublicationEvidence; 2],
    retry_ids: &[String; 2],
) {
    for ((participant, publication), retry_id) in
        participants.iter().zip(publications).zip(retry_ids)
    {
        emit(
            record,
            &[
                ("participant", participant.name.to_owned()),
                ("original_id", publication.id.clone()),
                ("retry_id", retry_id.clone()),
                ("inserted", "false".to_owned()),
            ],
        );
    }
}

fn emit_shutdowns(
    phase: &str,
    participants: &[ParticipantTranscript; 2],
    shutdowns: &[ShutdownEvidence; 2],
) {
    for (participant, shutdown) in participants.iter().zip(shutdowns) {
        emit(
            "SHUTDOWN",
            &[
                ("phase", phase.to_owned()),
                ("participant", participant.name.to_owned()),
                ("contacts", shutdown.contacts.to_string()),
                ("direct_contacts", shutdown.direct_contacts.to_string()),
                ("relay_contacts", shutdown.relay_contacts.to_string()),
                (
                    "unknown_path_contacts",
                    shutdown.unknown_path_contacts.to_string(),
                ),
                ("contact_errors", shutdown.contact_errors.to_string()),
            ],
        );
    }
}

fn emit_state_views(
    phase: &str,
    participants: &[ParticipantTranscript; 2],
    views: &[StateViewEvidence; 2],
) {
    for (participant, view) in participants.iter().zip(views) {
        emit(
            "STATE_VIEW",
            &[
                ("phase", phase.to_owned()),
                ("participant", participant.name.to_owned()),
                ("current_id", view.current.id.clone()),
                ("current_publisher", view.current.publisher.clone()),
                ("current_counter", view.current.counter.to_string()),
                (
                    "current_payload_sha256",
                    view.current.payload_sha256.clone(),
                ),
                ("current_disposition", view.current.disposition.to_owned()),
                ("recoverable_count", "1".to_owned()),
                ("concurrent_id", view.concurrent.id.clone()),
                ("concurrent_publisher", view.concurrent.publisher.clone()),
                ("concurrent_counter", view.concurrent.counter.to_string()),
                (
                    "concurrent_payload_sha256",
                    view.concurrent.payload_sha256.clone(),
                ),
                (
                    "concurrent_disposition",
                    view.concurrent.disposition.to_owned(),
                ),
            ],
        );
    }
}

fn emit_resolved_views(
    phase: &str,
    participants: &[ParticipantTranscript; 2],
    views: &[RecordResolvedEvidence; 2],
) {
    for (participant, view) in participants.iter().zip(views) {
        emit(
            "RECORD_RESOLVED",
            &[
                ("phase", phase.to_owned()),
                ("participant", participant.name.to_owned()),
                ("current_id", view.current.id.clone()),
                ("current_publisher", view.current.publisher.clone()),
                ("current_counter", view.current.counter.to_string()),
                (
                    "current_payload_sha256",
                    view.current.payload_sha256.clone(),
                ),
                ("current_disposition", view.current.disposition.to_owned()),
                ("conflict", "false".to_owned()),
                ("superseded_count", "2".to_owned()),
                ("superseded", join_ids(&view.superseded)),
                (
                    "superseded_dispositions",
                    "superseded,superseded".to_owned(),
                ),
            ],
        );
    }
}

fn emit(record: &str, fields: &[(&str, String)]) {
    print!("LIVE_MUTABLE\t{record}");
    for (key, value) in fields {
        print!("\t{key}={value}");
    }
    println!();
}
