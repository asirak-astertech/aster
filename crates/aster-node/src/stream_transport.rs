//! Internal selection and recovery for one active streaming transport.

use aster_iroh::{BoundedReceiveStream, BoundedSendStream, Connection, SelectedPath};
use std::{future::Future, pin::Pin, sync::Arc, time::Duration};
use tokio::{sync::Mutex, time::Instant};

#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
#[repr(u16)]
pub(crate) enum StreamTransportId {
    IrohQuicV1 = 1,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum CandidateHealth {
    Unavailable,
    Unknown,
    Degraded,
    Healthy,
}
impl CandidateHealth {
    const fn rank(self) -> u8 {
        match self {
            Self::Unavailable => 0,
            Self::Unknown => 1,
            Self::Degraded => 2,
            Self::Healthy => 3,
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum AuthenticatedSupportSource {
    ProvisionedPeer,
    AuthenticatedConfiguration,
    AuthenticatedDiscovery,
    MissionSessionNegotiation,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct AuthenticatedPeerSupport {
    source: AuthenticatedSupportSource,
    stream_v1: bool,
}
impl AuthenticatedPeerSupport {
    pub(crate) const fn new(source: AuthenticatedSupportSource, stream_v1: bool) -> Self {
        Self { source, stream_v1 }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct TransportCandidate {
    pub id: StreamTransportId,
    pub locally_enabled: bool,
    pub policy_allowed: bool,
    pub peer_support: Option<AuthenticatedPeerSupport>,
    pub reliable_ordered: bool,
    pub full_duplex: bool,
    pub health: CandidateHealth,
    pub configured_priority: i16,
}

pub(crate) struct TransportAdapterCandidate {
    pub candidate: TransportCandidate,
    pub adapter: Arc<dyn StreamTransportAdapter>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct TransferRequirements {
    pub reliable_ordered: bool,
    pub full_duplex: bool,
}
impl Default for TransferRequirements {
    fn default() -> Self {
        Self {
            reliable_ordered: true,
            full_duplex: true,
        }
    }
}

pub(crate) struct TransportSelector;
impl TransportSelector {
    pub(crate) fn rank(
        requirements: TransferRequirements,
        candidates: &[TransportCandidate],
    ) -> Vec<TransportCandidate> {
        let mut ranked: Vec<_> = candidates
            .iter()
            .copied()
            .filter(|candidate| {
                candidate.locally_enabled
                    && candidate.policy_allowed
                    && candidate
                        .peer_support
                        .is_some_and(|support| support.stream_v1)
                    && (!requirements.reliable_ordered || candidate.reliable_ordered)
                    && (!requirements.full_duplex || candidate.full_duplex)
                    && candidate.health != CandidateHealth::Unavailable
            })
            .collect();
        ranked.sort_by(|left, right| {
            right
                .health
                .rank()
                .cmp(&left.health.rank())
                .then_with(|| right.configured_priority.cmp(&left.configured_priority))
                .then_with(|| left.id.cmp(&right.id))
        });
        ranked
    }

    pub(crate) fn select_adapter(
        requirements: TransferRequirements,
        candidates: &[TransportAdapterCandidate],
    ) -> Option<Arc<dyn StreamTransportAdapter>> {
        let descriptors = candidates
            .iter()
            .map(|candidate| candidate.candidate)
            .collect::<Vec<_>>();
        Self::rank(requirements, &descriptors)
            .into_iter()
            .find_map(|selected| {
                candidates
                    .iter()
                    .find(|candidate| {
                        candidate.candidate == selected
                            && candidate.adapter.id() == selected.id
                            && candidate.adapter.health() == selected.health
                            && candidate.adapter.eligibility(requirements)
                    })
                    .map(|candidate| Arc::clone(&candidate.adapter))
            })
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum TransportFailure {
    Closed,
    PositiveCreditStall,
    ControlLivenessExpired,
    Cancelled,
    Exhausted,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum TerminalOutcome {
    Protocol,
    Integrity,
    Lifecycle,
    Policy,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum AttemptSignal {
    Transport(TransportFailure),
    ZeroCreditDataDeadline,
    Terminal(TerminalOutcome),
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum CoordinatorAction {
    ContinueBackpressure,
    Retry {
        durable_offset: u64,
        checkpoint_generation: u64,
    },
    Terminal(TerminalOutcome),
    Exhausted,
    Cancelled,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct AttemptAuthority {
    pub peer_authenticated: bool,
    pub mission_authenticated: bool,
    pub semantic_version: u16,
    pub profile_id: u16,
    pub transcript: [u8; 32],
    pub attempt_nonce: [u8; 32],
    pub custody_age_ms: Option<u64>,
    pub durable_offset: u64,
    pub checkpoint_generation: u64,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct CoordinatorConfig {
    pub retry_budget: u8,
    pub positive_credit_stall: Duration,
    pub control_liveness: Duration,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum CoordinatorError {
    ActiveAttempt,
    Authentication,
    Replay,
    YoungerCustody,
    CheckpointRegression,
}

pub(crate) struct AttemptCoordinator {
    config: CoordinatorConfig,
    attempts: u8,
    active: bool,
    last_transcript: Option<[u8; 32]>,
    last_nonce: Option<[u8; 32]>,
    custody_age_ms: Option<u64>,
    durable_offset: u64,
    checkpoint_generation: u64,
}

impl AttemptCoordinator {
    pub(crate) const fn new(config: CoordinatorConfig) -> Self {
        Self {
            config,
            attempts: 0,
            active: false,
            last_transcript: None,
            last_nonce: None,
            custody_age_ms: None,
            durable_offset: 0,
            checkpoint_generation: 0,
        }
    }

    pub(crate) fn begin(&mut self, authority: AttemptAuthority) -> Result<(), CoordinatorError> {
        if self.active {
            return Err(CoordinatorError::ActiveAttempt);
        }
        if !authority.peer_authenticated
            || !authority.mission_authenticated
            || authority.semantic_version != 9
            || authority.profile_id != 5
            || authority.transcript.iter().all(|byte| *byte == 0)
            || authority.attempt_nonce.iter().all(|byte| *byte == 0)
        {
            return Err(CoordinatorError::Authentication);
        }
        if self.last_transcript == Some(authority.transcript)
            || self.last_nonce == Some(authority.attempt_nonce)
        {
            return Err(CoordinatorError::Replay);
        }
        if self
            .custody_age_ms
            .zip(authority.custody_age_ms)
            .is_some_and(|(previous, next)| next < previous)
        {
            return Err(CoordinatorError::YoungerCustody);
        }
        if authority.durable_offset < self.durable_offset
            || authority.checkpoint_generation < self.checkpoint_generation
        {
            return Err(CoordinatorError::CheckpointRegression);
        }
        self.attempts = self.attempts.saturating_add(1);
        self.active = true;
        self.last_transcript = Some(authority.transcript);
        self.last_nonce = Some(authority.attempt_nonce);
        self.custody_age_ms = match (self.custody_age_ms, authority.custody_age_ms) {
            (Some(left), Some(right)) => Some(left.max(right)),
            (None, value) | (value, None) => value,
        };
        self.durable_offset = authority.durable_offset;
        self.checkpoint_generation = authority.checkpoint_generation;
        Ok(())
    }

    pub(crate) fn checkpoint(
        &mut self,
        offset: u64,
        generation: u64,
    ) -> Result<(), CoordinatorError> {
        if offset < self.durable_offset
            || generation < self.checkpoint_generation
            || (offset > self.durable_offset) != (generation > self.checkpoint_generation)
        {
            return Err(CoordinatorError::CheckpointRegression);
        }
        self.durable_offset = offset;
        self.checkpoint_generation = generation;
        Ok(())
    }

    pub(crate) fn signal(&mut self, signal: AttemptSignal) -> CoordinatorAction {
        match signal {
            AttemptSignal::ZeroCreditDataDeadline => CoordinatorAction::ContinueBackpressure,
            AttemptSignal::Terminal(outcome) => {
                self.active = false;
                CoordinatorAction::Terminal(outcome)
            }
            AttemptSignal::Transport(TransportFailure::Cancelled) => {
                self.active = false;
                CoordinatorAction::Cancelled
            }
            AttemptSignal::Transport(TransportFailure::Exhausted) => {
                self.active = false;
                CoordinatorAction::Exhausted
            }
            AttemptSignal::Transport(_) => {
                self.active = false;
                if self.attempts > self.config.retry_budget {
                    CoordinatorAction::Exhausted
                } else {
                    CoordinatorAction::Retry {
                        durable_offset: self.durable_offset,
                        checkpoint_generation: self.checkpoint_generation,
                    }
                }
            }
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct AttemptOpenRequest {
    pub deadline: Instant,
    pub max_data_bytes: usize,
    pub max_control_bytes: usize,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum StreamTransportError {
    Ineligible,
    Timeout,
    Closed,
    Bounds,
}

pub(crate) type AdapterFuture<'a, T> =
    Pin<Box<dyn Future<Output = Result<T, StreamTransportError>> + Send + 'a>>;

pub(crate) trait StreamAttempt: Send + Sync {
    fn send_data<'a>(&'a self, frame: &'a [u8]) -> AdapterFuture<'a, ()>;
    fn send_data_parts<'a>(&'a self, prefix: &'a [u8], body: &'a [u8]) -> AdapterFuture<'a, ()>;
    fn receive_control(&self) -> AdapterFuture<'_, Option<Vec<u8>>>;
    fn finish_data(&self) -> AdapterFuture<'_, ()>;
}

pub(crate) trait StreamReceiveAttempt: Send + Sync {
    fn receive_data(&self) -> AdapterFuture<'_, Option<Vec<u8>>>;
    fn send_control<'a>(&'a self, frame: &'a [u8]) -> AdapterFuture<'a, ()>;
    fn finish_control(&self) -> AdapterFuture<'_, ()>;
}

pub(crate) trait StreamTransportAdapter: Send + Sync {
    fn id(&self) -> StreamTransportId;
    fn eligibility(&self, requirements: TransferRequirements) -> bool;
    fn health(&self) -> CandidateHealth;
    fn open_attempt<'a>(
        &'a self,
        request: AttemptOpenRequest,
    ) -> AdapterFuture<'a, Arc<dyn StreamAttempt>>;
    fn accept_attempt<'a>(
        &'a self,
        request: AttemptOpenRequest,
    ) -> AdapterFuture<'a, Arc<dyn StreamReceiveAttempt>>;
}

pub(crate) struct IrohQuicV1Adapter {
    connection: Connection,
}
impl IrohQuicV1Adapter {
    pub(crate) const fn new(connection: Connection) -> Self {
        Self { connection }
    }
}

struct IrohSenderAttempt {
    data: Mutex<BoundedSendStream>,
    control: Mutex<BoundedReceiveStream>,
}

struct IrohReceiverAttempt {
    data: Mutex<BoundedReceiveStream>,
    control: Mutex<BoundedSendStream>,
}

impl StreamReceiveAttempt for IrohReceiverAttempt {
    fn receive_data(&self) -> AdapterFuture<'_, Option<Vec<u8>>> {
        Box::pin(async move {
            self.data
                .lock()
                .await
                .read_frame()
                .await
                .map_err(map_iroh_error)
        })
    }
    fn send_control<'a>(&'a self, frame: &'a [u8]) -> AdapterFuture<'a, ()> {
        Box::pin(async move {
            self.control
                .lock()
                .await
                .write_frame(frame)
                .await
                .map_err(map_iroh_error)
        })
    }
    fn finish_control(&self) -> AdapterFuture<'_, ()> {
        Box::pin(async move {
            self.control
                .lock()
                .await
                .finish()
                .await
                .map_err(map_iroh_error)
        })
    }
}
impl StreamAttempt for IrohSenderAttempt {
    fn send_data<'a>(&'a self, frame: &'a [u8]) -> AdapterFuture<'a, ()> {
        Box::pin(async move {
            self.data
                .lock()
                .await
                .write_frame(frame)
                .await
                .map_err(map_iroh_error)
        })
    }
    fn send_data_parts<'a>(&'a self, prefix: &'a [u8], body: &'a [u8]) -> AdapterFuture<'a, ()> {
        Box::pin(async move {
            self.data
                .lock()
                .await
                .write_frame_parts(prefix, body)
                .await
                .map_err(map_iroh_error)
        })
    }
    fn receive_control(&self) -> AdapterFuture<'_, Option<Vec<u8>>> {
        Box::pin(async move {
            self.control
                .lock()
                .await
                .read_frame()
                .await
                .map_err(map_iroh_error)
        })
    }
    fn finish_data(&self) -> AdapterFuture<'_, ()> {
        Box::pin(async move {
            self.data
                .lock()
                .await
                .finish()
                .await
                .map_err(map_iroh_error)
        })
    }
}

impl StreamTransportAdapter for IrohQuicV1Adapter {
    fn id(&self) -> StreamTransportId {
        StreamTransportId::IrohQuicV1
    }
    fn eligibility(&self, requirements: TransferRequirements) -> bool {
        requirements.reliable_ordered && requirements.full_duplex
    }
    fn health(&self) -> CandidateHealth {
        match self.connection.path_witness().selected {
            SelectedPath::Unknown => CandidateHealth::Unknown,
            SelectedPath::Direct | SelectedPath::Relay => CandidateHealth::Healthy,
        }
    }
    fn open_attempt<'a>(
        &'a self,
        request: AttemptOpenRequest,
    ) -> AdapterFuture<'a, Arc<dyn StreamAttempt>> {
        Box::pin(async move {
            let pair = self
                .connection
                .open_stream_pair(
                    request.deadline,
                    request.max_data_bytes,
                    request.max_control_bytes,
                )
                .await
                .map_err(map_iroh_error)?;
            Ok(Arc::new(IrohSenderAttempt {
                data: Mutex::new(pair.data),
                control: Mutex::new(pair.control),
            }) as Arc<dyn StreamAttempt>)
        })
    }

    fn accept_attempt<'a>(
        &'a self,
        request: AttemptOpenRequest,
    ) -> AdapterFuture<'a, Arc<dyn StreamReceiveAttempt>> {
        Box::pin(async move {
            let pair = self
                .connection
                .accept_stream_pair(
                    request.deadline,
                    request.max_data_bytes,
                    request.max_control_bytes,
                )
                .await
                .map_err(map_iroh_error)?;
            Ok(Arc::new(IrohReceiverAttempt {
                data: Mutex::new(pair.data),
                control: Mutex::new(pair.control),
            }) as Arc<dyn StreamReceiveAttempt>)
        })
    }
}

fn map_iroh_error(error: aster_iroh::CarrierError) -> StreamTransportError {
    match error {
        aster_iroh::CarrierError::Timeout(_) => StreamTransportError::Timeout,
        aster_iroh::CarrierError::FrameTooLarge { .. }
        | aster_iroh::CarrierError::TurnTooLarge { .. } => StreamTransportError::Bounds,
        _ => StreamTransportError::Closed,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::application::{
        BlobId, BlobPublicationInspection, BlobPublicationPhase, BlobStreamPublicationId,
    };
    use crate::stream_transfer::{
        StreamAction, StreamDataV1, StreamExtentAction, StreamFrame, StreamOpenV1,
        StreamReceiverState, StreamResultCode, StreamSenderState,
    };
    use aster_iroh::{CarrierSecurityProfile, Endpoint, EndpointConfig, ExpectedPeer, SecretKey};
    use sha2::{Digest as _, Sha256};
    use std::collections::BTreeSet;

    fn candidate(priority: i16, health: CandidateHealth) -> TransportCandidate {
        TransportCandidate {
            id: StreamTransportId::IrohQuicV1,
            locally_enabled: true,
            policy_allowed: true,
            peer_support: Some(AuthenticatedPeerSupport::new(
                AuthenticatedSupportSource::ProvisionedPeer,
                true,
            )),
            reliable_ordered: true,
            full_duplex: true,
            health,
            configured_priority: priority,
        }
    }

    #[test]
    fn stream_transport_ranking_is_deterministic_and_authenticated() {
        assert!(TransportSelector::rank(TransferRequirements::default(), &[]).is_empty());
        let mut disabled = candidate(9, CandidateHealth::Healthy);
        disabled.locally_enabled = false;
        let mut unauthenticated = candidate(8, CandidateHealth::Healthy);
        unauthenticated.peer_support = None;
        let degraded = candidate(100, CandidateHealth::Degraded);
        let healthy = candidate(1, CandidateHealth::Healthy);
        assert_eq!(
            TransportSelector::rank(
                TransferRequirements::default(),
                &[disabled, degraded, unauthenticated, healthy]
            ),
            vec![healthy, degraded]
        );
    }

    struct SelectionAdapter {
        health: CandidateHealth,
    }

    impl StreamTransportAdapter for SelectionAdapter {
        fn id(&self) -> StreamTransportId {
            StreamTransportId::IrohQuicV1
        }

        fn eligibility(&self, requirements: TransferRequirements) -> bool {
            requirements.reliable_ordered && requirements.full_duplex
        }

        fn health(&self) -> CandidateHealth {
            self.health
        }

        fn open_attempt<'a>(
            &'a self,
            _request: AttemptOpenRequest,
        ) -> AdapterFuture<'a, Arc<dyn StreamAttempt>> {
            Box::pin(async { Err(StreamTransportError::Closed) })
        }

        fn accept_attempt<'a>(
            &'a self,
            _request: AttemptOpenRequest,
        ) -> AdapterFuture<'a, Arc<dyn StreamReceiveAttempt>> {
            Box::pin(async { Err(StreamTransportError::Closed) })
        }
    }

    #[test]
    fn stream_transport_selector_returns_best_eligible_adapter() {
        let unavailable = Arc::new(SelectionAdapter {
            health: CandidateHealth::Healthy,
        });
        let degraded: Arc<dyn StreamTransportAdapter> = Arc::new(SelectionAdapter {
            health: CandidateHealth::Degraded,
        });
        let healthy: Arc<dyn StreamTransportAdapter> = Arc::new(SelectionAdapter {
            health: CandidateHealth::Healthy,
        });

        let selected = TransportSelector::select_adapter(
            TransferRequirements::default(),
            &[
                TransportAdapterCandidate {
                    candidate: TransportCandidate {
                        policy_allowed: false,
                        ..candidate(100, CandidateHealth::Healthy)
                    },
                    adapter: unavailable,
                },
                TransportAdapterCandidate {
                    candidate: candidate(10, CandidateHealth::Degraded),
                    adapter: Arc::clone(&degraded),
                },
                TransportAdapterCandidate {
                    candidate: candidate(1, CandidateHealth::Healthy),
                    adapter: Arc::clone(&healthy),
                },
            ],
        )
        .expect("one adapter is eligible");

        assert!(Arc::ptr_eq(&selected, &healthy));
        assert!(!Arc::ptr_eq(&selected, &degraded));
    }

    fn authority(seed: u8, age: u64, offset: u64, generation: u64) -> AttemptAuthority {
        AttemptAuthority {
            peer_authenticated: true,
            mission_authenticated: true,
            semantic_version: 9,
            profile_id: 5,
            transcript: [seed; 32],
            attempt_nonce: [seed.wrapping_add(1); 32],
            custody_age_ms: Some(age),
            durable_offset: offset,
            checkpoint_generation: generation,
        }
    }

    #[test]
    fn stream_transport_coordinator_retries_only_from_authenticated_durable_progress() {
        let mut coordinator = AttemptCoordinator::new(CoordinatorConfig {
            retry_budget: 2,
            positive_credit_stall: Duration::from_secs(3),
            control_liveness: Duration::from_secs(1),
        });
        coordinator.begin(authority(1, 50, 0, 0)).unwrap();
        coordinator.checkpoint(8, 1).unwrap();
        assert_eq!(
            coordinator.signal(AttemptSignal::Transport(TransportFailure::Closed)),
            CoordinatorAction::Retry {
                durable_offset: 8,
                checkpoint_generation: 1
            }
        );
        assert!(matches!(
            coordinator.begin(authority(1, 50, 8, 1)),
            Err(CoordinatorError::Replay)
        ));
        assert!(matches!(
            coordinator.begin(authority(2, 49, 8, 1)),
            Err(CoordinatorError::YoungerCustody)
        ));
        coordinator.begin(authority(3, 50, 8, 1)).unwrap();
        assert_eq!(
            coordinator.signal(AttemptSignal::ZeroCreditDataDeadline),
            CoordinatorAction::ContinueBackpressure
        );
        assert_eq!(
            coordinator.signal(AttemptSignal::Transport(
                TransportFailure::ControlLivenessExpired
            )),
            CoordinatorAction::Retry {
                durable_offset: 8,
                checkpoint_generation: 1
            }
        );
        coordinator.begin(authority(5, 51, 8, 1)).unwrap();
        assert_eq!(
            coordinator.signal(AttemptSignal::Transport(
                TransportFailure::PositiveCreditStall
            )),
            CoordinatorAction::Exhausted
        );
    }

    #[test]
    fn stream_transport_terminal_cancel_and_checkpoint_rules_are_typed() {
        let mut coordinator = AttemptCoordinator::new(CoordinatorConfig {
            retry_budget: 3,
            positive_credit_stall: Duration::from_secs(3),
            control_liveness: Duration::from_secs(1),
        });
        coordinator.begin(authority(7, 10, 0, 0)).unwrap();
        assert!(coordinator.checkpoint(4, 0).is_err());
        assert_eq!(
            coordinator.signal(AttemptSignal::Terminal(TerminalOutcome::Integrity)),
            CoordinatorAction::Terminal(TerminalOutcome::Integrity)
        );
        coordinator.begin(authority(9, 10, 0, 0)).unwrap();
        assert_eq!(
            coordinator.signal(AttemptSignal::Transport(TransportFailure::Cancelled)),
            CoordinatorAction::Cancelled
        );
    }

    #[test]
    fn publication_status_survives_small_mtu_interrupt_and_different_adapter_resume() {
        struct FragmentingAdapter {
            mtu: usize,
        }
        impl FragmentingAdapter {
            fn carry(&self, frame: StreamFrame) -> StreamFrame {
                let encoded = frame.encode_for_context(9, 5).unwrap();
                let mut received = Vec::with_capacity(encoded.len());
                for fragment in encoded.chunks(self.mtu) {
                    received.extend_from_slice(fragment);
                }
                StreamFrame::decode_for_context(9, 5, &received).unwrap()
            }
        }

        fn open(nonce: [u8; 32]) -> StreamOpenV1 {
            StreamOpenV1 {
                class: crate::stream_transfer::StreamClass::Blob,
                direction: crate::stream_transfer::StreamDirection::ToSessionResponder,
                session_transcript: [3; 32],
                exchange_id: 4,
                transfer_id: [1; 32],
                source_transfer_id: [5; 32],
                publication_id: [6; 32],
                variant_id: [7; 32],
                total_len: 32,
                attempt_nonce: nonce,
                checkpoint_generation: 1,
                custody_digest: None,
                authenticated_open: vec![8],
            }
        }

        fn accepted(action: StreamAction) -> crate::stream_transfer::StreamAcceptV1 {
            let StreamAction::Send(StreamFrame::Accept(frame)) = action else {
                panic!("receiver acceptance")
            };
            frame
        }

        fn sent_data(action: StreamExtentAction) -> StreamDataV1 {
            let StreamExtentAction::Send(frame) = action else {
                panic!("sender data")
            };
            frame
        }

        fn checkpoint_frame(action: StreamAction) -> crate::stream_transfer::StreamCheckpointV1 {
            let StreamAction::Send(StreamFrame::Checkpoint(frame)) = action else {
                panic!("receiver checkpoint")
            };
            frame
        }

        let payload: Vec<u8> = (0_u8..32).collect();
        let expected_blob_id: [u8; 32] = Sha256::digest(&payload).into();
        let first_adapter = FragmentingAdapter { mtu: 3 };
        let second_adapter = FragmentingAdapter { mtu: 5 };

        let first_open = open([2; 32]);
        let mut first_receiver = StreamReceiverState::new(&first_open, 0, 1, 32, 16).unwrap();
        let mut first_sender = StreamSenderState::new([1; 32], [2; 32], 32);
        let accept = accepted(first_receiver.accept(16).unwrap());
        let StreamFrame::Accept(accept) = first_adapter.carry(StreamFrame::Accept(accept)) else {
            unreachable!()
        };
        first_sender.accept(accept).unwrap();
        let data = sent_data(first_sender.send_extent(payload[..16].to_vec()).unwrap());
        let StreamFrame::Data(data) = first_adapter.carry(StreamFrame::Data(data)) else {
            unreachable!()
        };
        assert_eq!(
            first_receiver.data(&data).unwrap(),
            StreamAction::Persist { through: 16 }
        );
        let checkpoint = checkpoint_frame(first_receiver.persisted(16, 2, 32).unwrap());
        let interrupted_generation = checkpoint.checkpoint_generation;
        let interrupted_status = BlobPublicationInspection {
            publication_id: BlobStreamPublicationId::from_bytes(first_open.publication_id).unwrap(),
            phase: BlobPublicationPhase::Receiving,
            plaintext_total_bytes: first_open.total_len,
            durable_plaintext_bytes: checkpoint.durable_offset,
            transfer_total_bytes: first_open.total_len,
            durable_transfer_bytes: checkpoint.durable_offset,
            total_units: 2,
            durable_units: 1,
            blob_id: None,
        };
        let StreamFrame::Checkpoint(checkpoint) =
            first_adapter.carry(StreamFrame::Checkpoint(checkpoint))
        else {
            unreachable!()
        };
        first_sender.checkpoint(checkpoint).unwrap();

        let resumed_open = open([9; 32]);
        let mut resumed_receiver = StreamReceiverState::reopen(
            &first_open.attempt_nonce,
            &resumed_open,
            interrupted_status.durable_transfer_bytes,
            interrupted_generation,
            32,
            16,
        )
        .unwrap();
        let mut resumed_sender = StreamSenderState::new([1; 32], [9; 32], 32);
        let accept = accepted(resumed_receiver.accept(16).unwrap());
        let StreamFrame::Accept(accept) = second_adapter.carry(StreamFrame::Accept(accept)) else {
            unreachable!()
        };
        resumed_sender.accept(accept).unwrap();
        let data = sent_data(resumed_sender.send_extent(payload[16..].to_vec()).unwrap());
        let StreamFrame::Data(data) = second_adapter.carry(StreamFrame::Data(data)) else {
            unreachable!()
        };
        assert_eq!(
            resumed_receiver.data(&data).unwrap(),
            StreamAction::Persist { through: 32 }
        );
        let checkpoint = checkpoint_frame(resumed_receiver.persisted(32, 3, 32).unwrap());
        let StreamFrame::Checkpoint(checkpoint) =
            second_adapter.carry(StreamFrame::Checkpoint(checkpoint))
        else {
            unreachable!()
        };
        resumed_sender.checkpoint(checkpoint).unwrap();
        let StreamAction::Send(StreamFrame::Finish(finish)) =
            resumed_sender.finish(expected_blob_id.to_vec()).unwrap()
        else {
            panic!("sender finish")
        };
        let StreamFrame::Finish(finish) = second_adapter.carry(StreamFrame::Finish(finish)) else {
            unreachable!()
        };
        assert_eq!(resumed_receiver.finish(finish), Ok(StreamAction::Promote));
        assert!(matches!(
            resumed_receiver.promoted(StreamResultCode::Promoted, expected_blob_id),
            Ok(StreamAction::Send(StreamFrame::Result(_)))
        ));
        let available_status = BlobPublicationInspection {
            publication_id: BlobStreamPublicationId::from_bytes(resumed_open.publication_id)
                .unwrap(),
            phase: BlobPublicationPhase::Available,
            plaintext_total_bytes: resumed_open.total_len,
            durable_plaintext_bytes: 32,
            transfer_total_bytes: resumed_open.total_len,
            durable_transfer_bytes: 32,
            total_units: 2,
            durable_units: 2,
            blob_id: Some(BlobId::from_bytes(expected_blob_id)),
        };

        assert_eq!(
            available_status.publication_id,
            interrupted_status.publication_id
        );
        assert!(
            available_status.durable_transfer_bytes >= interrupted_status.durable_transfer_bytes
        );
        assert_eq!(
            available_status.blob_id,
            Some(BlobId::from_bytes(Sha256::digest(&payload).into()))
        );
        let BlobPublicationInspection {
            publication_id: _,
            phase: _,
            plaintext_total_bytes: _,
            durable_plaintext_bytes: _,
            transfer_total_bytes: _,
            durable_transfer_bytes: _,
            total_units: _,
            durable_units: _,
            blob_id: _,
        } = available_status;
    }

    #[test]
    fn stream_iroh_adapter_reports_one_production_transport() {
        assert_eq!(StreamTransportId::IrohQuicV1 as u16, 1);
    }

    #[tokio::test]
    async fn stream_iroh_adapter_reopens_a_fresh_concurrent_pair() {
        let config = EndpointConfig::direct("127.0.0.1:0".parse().unwrap());
        let server = Endpoint::bind_with_security_profile(
            SecretKey::generate(),
            config,
            CarrierSecurityProfile::IrohQuicV1,
        )
        .await
        .unwrap();
        let client = Endpoint::bind_with_security_profile(
            SecretKey::generate(),
            config,
            CarrierSecurityProfile::IrohQuicV1,
        )
        .await
        .unwrap();
        let allowed = BTreeSet::from([client.id()]);
        let server_task = tokio::spawn({
            let server = server.clone();
            async move {
                let connection = server.accept(&allowed).await.unwrap();
                for expected in [
                    b"first".as_slice(),
                    b"headerbody".as_slice(),
                    b"resume".as_slice(),
                ] {
                    let mut pair = connection
                        .accept_stream_pair(Instant::now() + Duration::from_secs(2), 64, 64)
                        .await
                        .unwrap();
                    assert_eq!(
                        pair.data.read_frame().await.unwrap().as_deref(),
                        Some(expected)
                    );
                    pair.control.write_frame(b"checkpoint").await.unwrap();
                    pair.control.finish().await.unwrap();
                    assert_eq!(pair.data.read_frame().await.unwrap(), None);
                }
            }
        });
        let address = server
            .bound_sockets()
            .into_iter()
            .find(|address| address.is_ipv4())
            .unwrap();
        let connection = client
            .connect(ExpectedPeer {
                id: server.id(),
                address,
            })
            .await
            .unwrap();
        let adapter = IrohQuicV1Adapter::new(connection.clone());
        assert_eq!(adapter.id(), StreamTransportId::IrohQuicV1);
        for (prefix, body) in [
            (b"first".as_slice(), b"".as_slice()),
            (b"header".as_slice(), b"body".as_slice()),
            (b"resume".as_slice(), b"".as_slice()),
        ] {
            let attempt = adapter
                .open_attempt(AttemptOpenRequest {
                    deadline: Instant::now() + Duration::from_secs(2),
                    max_data_bytes: 64,
                    max_control_bytes: 64,
                })
                .await
                .unwrap();
            attempt.send_data_parts(prefix, body).await.unwrap();
            assert_eq!(
                attempt.receive_control().await.unwrap().as_deref(),
                Some(b"checkpoint".as_slice())
            );
            assert_eq!(attempt.receive_control().await.unwrap(), None);
            attempt.finish_data().await.unwrap();
        }
        server_task.await.unwrap();
        connection.close();
        client.close().await;
        server.close().await;
    }
}
