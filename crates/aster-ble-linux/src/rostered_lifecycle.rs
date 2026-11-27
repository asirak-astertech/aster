use crate::{
    AsterRosterBeaconV1, AttemptKind, DiscoveryAdmission, DiscoveryCandidate, DiscoveryRecordError,
    DriverError, DriverErrorKind, FixedRole, ObservationOutcome, SupervisorError,
    ValidatedAutomaticRosteredSupervisorConfig, ValidatedRosteredSupervisorConfig,
    automatic_carrier::{
        AutomaticBtleCarrierBackend, AutomaticBtleCarrierReadinessPublisher,
        AutomaticBtleCarrierRelease, OutboundCarrierRequest, ReadinessPublishError,
        automatic_btle_carrier_channel,
    },
    controller_resolver::{
        ControllerEpochActivator, ControllerEpochView, OperationalControllerEpoch,
        OperationalEpochFuture, OperationalEpochOutcome, OperationalEpochState,
        spawn_linux_controller_resolver,
    },
    discovery::{SCAN_ACTIVE_INTERVAL, SCAN_IDLE_INTERVAL},
    lifecycle::{ContactAdmission, ContactScheduleEffect, contact_schedule_effect},
    platform::{
        discovery::{
            BluezDiscoveryPlatform, BluezOwnerLoss, DiscoveryObservation, DiscoveryPlatform,
            PlatformFuture, RosterAdvertisement, ScanTermination, TerminationFuture,
        },
        socket::{
            AcceptedSocket, BluezRosteredSocketFactory, OpenedContact, RosteredSocketFactory,
            opened_rostered_contact,
        },
    },
    policy::{CappedBackoff, LifecycleCancellation, LifecycleCancellationObserver},
};
use aster_contact::OrderedContact;
use aster_mesh::NodeId;
use aster_node::{
    ContactDisposition, ContactOutcome, ContactReason, MissionPeerExpectation,
    OrderedEventContactHandle, OrderedEventContactRole, PeerReceipt,
};
use std::{
    future::{Future, poll_fn},
    pin::Pin,
    sync::{
        Arc, Mutex,
        atomic::{AtomicBool, Ordering as AtomicOrdering},
    },
    time::Instant,
};
use tokio::{
    sync::{Mutex as AsyncMutex, mpsc, oneshot, watch},
    task::JoinHandle,
    time::{Duration, timeout},
};

const ADVERTISEMENT_ROTATION_INTERVAL: Duration = Duration::from_secs(25);
const OWNED_STOP_DEADLINE: Duration = Duration::from_secs(5);
const CONTACT_DRAIN_DEADLINE: Duration = Duration::from_secs(5);
const INITIAL_EPOCH_RETRY: Duration = Duration::from_millis(250);
const MAXIMUM_EPOCH_RETRY: Duration = Duration::from_secs(30);
const STABLE_EPOCH_DURATION: Duration = Duration::from_secs(30);
const OWNER_LOSS_AFTER: Duration = Duration::from_secs(35);
const OWNER_LOSS_JOIN_DEADLINE: Duration = Duration::from_secs(5);

struct ActiveScan {
    owner: Box<dyn crate::platform::discovery::OwnedScan>,
    observations: tokio::sync::mpsc::Receiver<DiscoveryObservation>,
}

enum ScanPhase {
    Active {
        scan: ActiveScan,
        deadline: tokio::time::Instant,
    },
    Idle {
        deadline: tokio::time::Instant,
    },
}

enum EpochEvent {
    Cancelled,
    AdvertisementTerminated,
    AdvertisementRotation,
    ScanTerminated(ScanTermination),
    Observation(Option<DiscoveryObservation>),
    ScanDeadline,
    ScanIdleDeadline,
    InboundAccepted(Result<(AcceptedSocket, crate::CanonicalLocator), DriverError>),
    InboundReady(Result<(crate::SocketOpen, crate::CanonicalLocator), DriverError>),
    InboundAcceptReady,
    OutboundRetry,
    AutomaticCarrierRequest(AutomaticCarrierRequestEvent),
    ContactFinished(ContactAttemptOutcome),
    CredentialExpired,
}

type ContactWorkFuture = Pin<Box<dyn Future<Output = ContactAttemptOutcome> + Send>>;
type SharedContactAdmission = Arc<dyn ContactAdmission>;
type InboundAcceptFuture = Pin<
    Box<dyn Future<Output = Result<(AcceptedSocket, crate::CanonicalLocator), DriverError>> + Send>,
>;
type InboundReadinessFuture = Pin<
    Box<
        dyn Future<Output = Result<(crate::SocketOpen, crate::CanonicalLocator), DriverError>>
            + Send,
    >,
>;
enum AutomaticCarrierRequestEvent {
    Received(Option<OutboundCarrierRequest>),
    Cancelled,
}

enum EpochContactMode {
    FixedEvaluation {
        contacts: SharedContactAdmission,
        peer_mission_id: NodeId,
    },
    Automatic {
        backend: AutomaticBtleCarrierBackend,
        pending: Option<OutboundCarrierRequest>,
    },
}

impl EpochContactMode {
    fn fixed(contacts: SharedContactAdmission, peer_mission_id: NodeId) -> Self {
        Self::FixedEvaluation {
            contacts,
            peer_mission_id,
        }
    }

    fn automatic(backend: AutomaticBtleCarrierBackend) -> Self {
        Self::Automatic {
            backend,
            pending: None,
        }
    }

    const fn is_automatic(&self) -> bool {
        matches!(self, Self::Automatic { .. })
    }

    fn accepts_inbound(&self, config: &ValidatedRosteredSupervisorConfig) -> bool {
        self.is_automatic() || config.role() == FixedRole::Listener
    }

    fn can_open_outbound(&self, config: &ValidatedRosteredSupervisorConfig) -> bool {
        match self {
            Self::FixedEvaluation { .. } => config.role() == FixedRole::Initiator,
            Self::Automatic { pending, .. } => {
                config.role() == FixedRole::Initiator && pending.is_some()
            }
        }
    }

    fn fixed_contacts(&self) -> &SharedContactAdmission {
        match self {
            Self::FixedEvaluation { contacts, .. } => contacts,
            Self::Automatic { .. } => {
                unreachable!("automatic mode never creates fixed contact work")
            }
        }
    }

    fn fixed_peer_mission_id(&self) -> NodeId {
        match self {
            Self::FixedEvaluation {
                peer_mission_id, ..
            } => *peer_mission_id,
            Self::Automatic { .. } => {
                unreachable!("automatic mode never runs fixed contact work")
            }
        }
    }

    async fn next_automatic_carrier_event(&mut self) -> AutomaticCarrierRequestEvent {
        match self {
            Self::FixedEvaluation { .. } => std::future::pending().await,
            Self::Automatic {
                pending: Some(request),
                ..
            } => {
                request.cancellation().cancelled().await;
                AutomaticCarrierRequestEvent::Cancelled
            }
            Self::Automatic {
                backend,
                pending: None,
            } => AutomaticCarrierRequestEvent::Received(backend.recv_outbound().await),
        }
    }

    fn accept_carrier_request(
        &mut self,
        config: &ValidatedRosteredSupervisorConfig,
        request: OutboundCarrierRequest,
    ) -> bool {
        let Self::Automatic { pending, .. } = self else {
            request.complete_error(DriverError::new(
                DriverErrorKind::Configuration,
                "automatic carrier request reached a fixed evaluation owner",
            ));
            return false;
        };
        if pending.is_some() {
            request.complete_error(DriverError::new(
                DriverErrorKind::Configuration,
                "automatic carrier owner already has a pending request",
            ));
            false
        } else if config.role() != FixedRole::Initiator {
            request.complete_error(DriverError::new(
                DriverErrorKind::Unavailable,
                "automatic carrier owner is not configured to originate",
            ));
            false
        } else {
            *pending = Some(request);
            true
        }
    }

    fn take_outbound(&mut self) -> OutboundAttemptOwner {
        match self {
            Self::FixedEvaluation { .. } => OutboundAttemptOwner::FixedEvaluation,
            Self::Automatic { pending, .. } => OutboundAttemptOwner::Automatic(
                pending
                    .take()
                    .expect("automatic outbound requires a carrier request"),
            ),
        }
    }

    fn restore_outbound(&mut self, owner: OutboundAttemptOwner) {
        if let (Self::Automatic { pending, .. }, OutboundAttemptOwner::Automatic(request)) =
            (self, owner)
        {
            debug_assert!(pending.is_none());
            *pending = Some(request);
        }
    }

    fn fail_pending_carrier_open(&mut self) {
        if let Self::Automatic { pending, .. } = self
            && let Some(request) = pending.take()
        {
            request.complete_error(DriverError::new(
                DriverErrorKind::Unavailable,
                "automatic carrier epoch ended before opening",
            ));
        }
    }

    fn fail_pending_no_candidate(&mut self) {
        if let Self::Automatic { pending, .. } = self
            && let Some(request) = pending.take()
        {
            request.complete_error(DriverError::new(
                DriverErrorKind::Unavailable,
                "automatic carrier has no selectable peer candidate",
            ));
        }
    }

    fn finish_pending_cancelled(&mut self) {
        if let Self::Automatic { pending, .. } = self
            && let Some(request) = pending.take()
        {
            request.complete_error(DriverError::new(
                DriverErrorKind::Cancelled,
                "automatic carrier request was cancelled",
            ));
        }
    }

    fn cancel_pending_carrier_open(&mut self) {
        if let Self::Automatic { pending, .. } = self
            && let Some(request) = pending.take()
        {
            request.complete_error(DriverError::new(
                DriverErrorKind::Cancelled,
                "automatic carrier owner stopped",
            ));
        }
    }

    fn deliver_inbound(&self, contact: OpenedContact) -> Option<AutomaticBtleCarrierRelease> {
        let Self::Automatic { backend, .. } = self else {
            return None;
        };
        backend.deliver_inbound(contact)
    }
}

enum OutboundAttemptOwner {
    FixedEvaluation,
    Automatic(OutboundCarrierRequest),
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum AvailabilityPublishError {
    PortClosed,
    GenerationExhausted,
}

struct AdapterAvailabilityPublisher {
    publication: Arc<AvailabilityPublication>,
    selector_can_originate: bool,
}

struct AvailabilityPublication {
    readiness: Option<AutomaticBtleCarrierReadinessPublisher>,
    updates: watch::Sender<crate::BtleAvailability>,
    output: crate::BtleOperatorOutput,
}

#[derive(Clone)]
struct UnavailableAvailabilityPublisher {
    publication: Arc<AvailabilityPublication>,
}

impl AdapterAvailabilityPublisher {
    fn fixed(
        updates: watch::Sender<crate::BtleAvailability>,
        output: crate::BtleOperatorOutput,
    ) -> Self {
        Self {
            publication: Arc::new(AvailabilityPublication {
                readiness: None,
                updates,
                output,
            }),
            selector_can_originate: false,
        }
    }

    fn automatic(
        readiness: AutomaticBtleCarrierReadinessPublisher,
        updates: watch::Sender<crate::BtleAvailability>,
        output: crate::BtleOperatorOutput,
        role: FixedRole,
    ) -> Self {
        Self {
            publication: Arc::new(AvailabilityPublication {
                readiness: Some(readiness),
                updates,
                output,
            }),
            selector_can_originate: role == FixedRole::Initiator,
        }
    }

    fn unavailable_only(&self) -> UnavailableAvailabilityPublisher {
        UnavailableAvailabilityPublisher {
            publication: self.publication.clone(),
        }
    }

    fn publish(
        &self,
        availability: crate::BtleAvailability,
    ) -> Result<(), AvailabilityPublishError> {
        self.publication.publish(availability)
    }

    fn publish_selector_available(&self) -> Result<(), AvailabilityPublishError> {
        if self.selector_can_originate {
            self.publication.publish_selector_available()
        } else {
            Ok(())
        }
    }

    fn publish_selector_unavailable(&self) -> Result<(), AvailabilityPublishError> {
        if self.selector_can_originate {
            self.publication.publish_selector_unavailable()
        } else {
            Ok(())
        }
    }
}

impl UnavailableAvailabilityPublisher {
    fn publish(&self) -> Result<(), AvailabilityPublishError> {
        self.publication
            .publish(crate::BtleAvailability::Unavailable(
                crate::AvailabilityReason::BluezUnavailable,
            ))
    }

    fn publish_terminal(&self, terminal: crate::controller::TerminalAvailability) {
        self.publication.output.publish_terminal(terminal);
    }
}

impl AvailabilityPublication {
    fn publish(
        &self,
        availability: crate::BtleAvailability,
    ) -> Result<(), AvailabilityPublishError> {
        if *self.updates.borrow() == availability {
            return Ok(());
        }
        if matches!(availability, crate::BtleAvailability::Unavailable(_))
            && let Some(readiness) = &self.readiness
        {
            publish_carrier_readiness(readiness, availability)?;
        }
        self.updates.send_replace(availability);
        self.output
            .emit(crate::controller::availability_event(availability));
        Ok(())
    }

    fn publish_selector_available(&self) -> Result<(), AvailabilityPublishError> {
        if *self.updates.borrow() != crate::BtleAvailability::Available {
            return Err(AvailabilityPublishError::PortClosed);
        }
        let Some(readiness) = &self.readiness else {
            return Ok(());
        };
        publish_carrier_readiness(readiness, crate::BtleAvailability::Available)
    }

    fn publish_selector_unavailable(&self) -> Result<(), AvailabilityPublishError> {
        let Some(readiness) = &self.readiness else {
            return Ok(());
        };
        publish_carrier_readiness(
            readiness,
            crate::BtleAvailability::Unavailable(crate::AvailabilityReason::BluezUnavailable),
        )
    }
}

fn publish_carrier_readiness(
    readiness: &AutomaticBtleCarrierReadinessPublisher,
    availability: crate::BtleAvailability,
) -> Result<(), AvailabilityPublishError> {
    readiness
        .publish(availability)
        .map(|_| ())
        .map_err(|error| match error {
            ReadinessPublishError::PortClosed => AvailabilityPublishError::PortClosed,
            ReadinessPublishError::GenerationExhausted => {
                AvailabilityPublishError::GenerationExhausted
            }
        })
}

#[derive(Default)]
struct EpochSignals {
    availability: Option<watch::Sender<crate::BtleAvailability>>,
    publisher: Option<Arc<AdapterAvailabilityPublisher>>,
    available_started: Option<oneshot::Sender<Instant>>,
    operational: Option<watch::Sender<OperationalEpochState>>,
    availability_fence: Option<Arc<AvailabilityFence>>,
    supervisor_availability_fence: Option<Arc<AvailabilityFence>>,
}

#[derive(Default)]
struct AvailabilityFence(Mutex<bool>);

struct AvailabilityGuards<'a> {
    _supervisor: Option<std::sync::MutexGuard<'a, bool>>,
    _epoch: Option<std::sync::MutexGuard<'a, bool>>,
}

impl AvailabilityFence {
    fn quiesce(&self) {
        *self
            .0
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner) = true;
    }
}

impl EpochSignals {
    fn with_publisher(
        publisher: Arc<AdapterAvailabilityPublisher>,
        available_started: oneshot::Sender<Instant>,
    ) -> Self {
        Self {
            availability: None,
            publisher: Some(publisher),
            available_started: Some(available_started),
            operational: None,
            availability_fence: None,
            supervisor_availability_fence: None,
        }
    }

    fn operational(
        publisher: Arc<AdapterAvailabilityPublisher>,
        operational: watch::Sender<OperationalEpochState>,
        availability_fence: Arc<AvailabilityFence>,
        supervisor_availability_fence: Arc<AvailabilityFence>,
    ) -> Self {
        Self {
            availability: None,
            publisher: Some(publisher),
            available_started: None,
            operational: Some(operational),
            availability_fence: Some(availability_fence),
            supervisor_availability_fence: Some(supervisor_availability_fence),
        }
    }

    fn publish(&self, availability: crate::BtleAvailability) -> Result<(), SupervisorError> {
        let _guards = (availability == crate::BtleAvailability::Available)
            .then(|| self.acquire_available_guards())
            .transpose()?;
        let result = if let Some(publisher) = &self.publisher {
            publisher
                .publish(availability)
                .map_err(|_| SupervisorError::TaskStopped)
        } else if let Some(updates) = &self.availability {
            publish_availability(updates, availability);
            Ok(())
        } else {
            Ok(())
        };
        if result.is_ok()
            && let Some(operational) = &self.operational
        {
            let state = if availability == crate::BtleAvailability::Available {
                OperationalEpochState::Available
            } else {
                OperationalEpochState::Unavailable
            };
            operational.send_replace(state);
        }
        result
    }

    fn publish_selector_available(&self) -> Result<(), SupervisorError> {
        let _guards = self.acquire_available_guards()?;
        self.publisher.as_ref().map_or(Ok(()), |publisher| {
            publisher
                .publish_selector_available()
                .map_err(|_| SupervisorError::TaskStopped)
        })
    }

    fn publish_selector_unavailable(&self) -> Result<(), SupervisorError> {
        self.publisher.as_ref().map_or(Ok(()), |publisher| {
            publisher
                .publish_selector_unavailable()
                .map_err(|_| SupervisorError::TaskStopped)
        })
    }

    fn acquire_available_guards(&self) -> Result<AvailabilityGuards<'_>, SupervisorError> {
        let supervisor = self.supervisor_availability_fence.as_ref().map(|fence| {
            fence
                .0
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner)
        });
        if supervisor.as_deref().is_some_and(|quiesced| *quiesced) {
            return Err(SupervisorError::TaskStopped);
        }
        let epoch = self.availability_fence.as_ref().map(|fence| {
            fence
                .0
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner)
        });
        if epoch.as_deref().is_some_and(|quiesced| *quiesced) {
            return Err(SupervisorError::TaskStopped);
        }
        Ok(AvailabilityGuards {
            _supervisor: supervisor,
            _epoch: epoch,
        })
    }
}

enum ContactAttemptOutcome {
    Opened {
        opened: Box<OpenedContact>,
        owner: OutboundAttemptOwner,
    },
    Completed(Box<Result<PeerReceipt, ContactOutcome>>),
    AutomaticCarrierReleased,
    OpenFailed(Box<ContactOpenFailure>),
    Cancelled,
}

struct ContactOpenFailure {
    candidate: DiscoveryCandidate,
    error: DriverError,
    owner: OutboundAttemptOwner,
}

enum ContactPhase {
    Accepting(InboundAcceptFuture),
    AdmittingInbound(InboundReadinessFuture),
    Paused(tokio::time::Instant),
    Active {
        cancellation: LifecycleCancellation,
        work: ContactWorkFuture,
    },
    Leased(AutomaticBtleCarrierRelease),
}

#[derive(Clone, Copy)]
enum OutboundDelay {
    Ready,
    PeerRetryUntil(Instant),
    TokenRefillUntil(Instant),
    CadenceUntil(Instant),
}

impl OutboundDelay {
    fn deadline(self, now: Instant) -> Instant {
        match self {
            Self::Ready => now,
            Self::PeerRetryUntil(deadline)
            | Self::TokenRefillUntil(deadline)
            | Self::CadenceUntil(deadline) => deadline,
        }
    }

    fn wake_for_new_candidate(&mut self) {
        if matches!(self, Self::PeerRetryUntil(_)) {
            *self = Self::Ready;
        }
    }
}

impl ContactPhase {
    fn accepting<S>(sockets: Arc<S>, listener: Arc<S::Listener>) -> Self
    where
        S: RosteredSocketFactory + 'static,
    {
        Self::Accepting(Box::pin(
            async move { sockets.accept(listener.as_ref()).await },
        ))
    }

    fn opening<S>(
        config: Arc<ValidatedRosteredSupervisorConfig>,
        sockets: Arc<S>,
        candidate: DiscoveryCandidate,
        mut owner: OutboundAttemptOwner,
    ) -> Self
    where
        S: RosteredSocketFactory + 'static,
    {
        let cancellation = LifecycleCancellation::new();
        let work_cancellation = cancellation.clone();
        Self::Active {
            cancellation,
            work: Box::pin(async move {
                let open = open_candidate(
                    config.as_ref(),
                    sockets.as_ref(),
                    candidate,
                    &work_cancellation,
                );
                tokio::pin!(open);
                let opened = match &mut owner {
                    OutboundAttemptOwner::FixedEvaluation => Ok(open.as_mut().await),
                    OutboundAttemptOwner::Automatic(request) => {
                        let request_cancellation = request.cancellation();
                        tokio::select! {
                            biased;
                            () = request_cancellation.cancelled() => Err(()),
                            result = open.as_mut() => Ok(result),
                        }
                    }
                };
                let opened = match opened {
                    Ok(opened) => opened,
                    Err(()) => {
                        work_cancellation.cancel();
                        let _ = timeout(CONTACT_DRAIN_DEADLINE, open.as_mut()).await;
                        if let OutboundAttemptOwner::Automatic(request) = owner {
                            request.complete_error(DriverError::new(
                                DriverErrorKind::Cancelled,
                                "automatic carrier request was cancelled during open",
                            ));
                        }
                        return ContactAttemptOutcome::Cancelled;
                    }
                };
                match opened {
                    Ok(opened) => ContactAttemptOutcome::Opened {
                        opened: Box::new(opened),
                        owner,
                    },
                    Err(error) => ContactAttemptOutcome::OpenFailed(Box::new(ContactOpenFailure {
                        candidate,
                        error,
                        owner,
                    })),
                }
            }),
        }
    }

    fn admitting_inbound(
        accepted: AcceptedSocket,
        locator: crate::CanonicalLocator,
        readiness_timeout: Duration,
    ) -> Self {
        Self::AdmittingInbound(Box::pin(async move {
            accepted
                .finish(readiness_timeout)
                .await
                .map(|socket| (socket, locator))
        }))
    }

    fn paused_until(deadline: Instant) -> Self {
        Self::Paused(tokio::time::Instant::from_std(deadline))
    }

    fn admitted(
        contacts: SharedContactAdmission,
        peer_mission_id: NodeId,
        role: OrderedEventContactRole,
        opened: OpenedContact,
    ) -> Self {
        let cancellation = LifecycleCancellation::new();
        let work_cancellation = cancellation.clone();
        Self::Active {
            cancellation,
            work: Box::pin(async move {
                run_opened_contact(
                    contacts.as_ref(),
                    peer_mission_id,
                    role,
                    opened,
                    &work_cancellation,
                )
                .await
            }),
        }
    }

    fn leased(release: AutomaticBtleCarrierRelease) -> Self {
        Self::Leased(release)
    }

    async fn next(&mut self) -> EpochEvent {
        match self {
            Self::Accepting(accept) => EpochEvent::InboundAccepted(accept.await),
            Self::AdmittingInbound(readiness) => EpochEvent::InboundReady(readiness.await),
            Self::Paused(deadline) => {
                tokio::time::sleep_until(*deadline).await;
                EpochEvent::InboundAcceptReady
            }
            Self::Active { work, .. } => EpochEvent::ContactFinished(work.await),
            Self::Leased(release) => {
                release.wait().await;
                EpochEvent::ContactFinished(ContactAttemptOutcome::AutomaticCarrierReleased)
            }
        }
    }

    const fn is_free(&self) -> bool {
        matches!(self, Self::Accepting(_) | Self::Paused(_))
    }

    fn cancel(&self) {
        if let Self::Active { cancellation, .. } = self {
            cancellation.cancel();
        } else if let Self::Leased(release) = self {
            release.close();
        }
    }

    async fn join(self) -> Option<ContactAttemptOutcome> {
        match self {
            Self::Active { mut work, .. } => Some((&mut work).await),
            Self::Leased(mut release) => {
                release.wait().await;
                Some(ContactAttemptOutcome::AutomaticCarrierReleased)
            }
            Self::Accepting(_) | Self::AdmittingInbound(_) | Self::Paused(_) => None,
        }
    }
}

#[derive(Clone, Copy)]
enum EpochContactTermination {
    Cancelled,
    LocalEpochLoss,
}

fn complete_interrupted_contact(
    outcome: Option<ContactAttemptOutcome>,
    termination: EpochContactTermination,
) {
    let owner = match outcome {
        Some(ContactAttemptOutcome::Opened { opened, owner }) => {
            drop(opened);
            Some(owner)
        }
        Some(ContactAttemptOutcome::OpenFailed(failure)) => Some(failure.owner),
        Some(
            ContactAttemptOutcome::Completed(_)
            | ContactAttemptOutcome::AutomaticCarrierReleased
            | ContactAttemptOutcome::Cancelled,
        )
        | None => None,
    };
    let Some(OutboundAttemptOwner::Automatic(request)) = owner else {
        return;
    };
    let (kind, detail) = match termination {
        EpochContactTermination::Cancelled => (
            DriverErrorKind::Cancelled,
            "automatic carrier owner stopped during open",
        ),
        EpochContactTermination::LocalEpochLoss => (
            DriverErrorKind::Unavailable,
            "automatic carrier epoch ended during open",
        ),
    };
    request.complete_error(DriverError::new(kind, detail));
}

trait DiscoveryNonceSource: Send + Sync {
    fn next_nonce(&self) -> Result<[u8; 16], DriverError>;
}

trait NonceRandom: Send + Sync {
    fn generate(&self) -> Result<[u8; 16], ()>;
}

#[derive(Clone, Copy, Debug, Default)]
struct OsNonceRandom;

impl NonceRandom for OsNonceRandom {
    fn generate(&self) -> Result<[u8; 16], ()> {
        let mut nonce = [0; 16];
        getrandom::fill(&mut nonce).map_err(|_| ())?;
        Ok(nonce)
    }
}

struct UniqueNonceSource<R> {
    random: R,
    previous: Mutex<Option<[u8; 16]>>,
}

impl<R> UniqueNonceSource<R> {
    const fn new(random: R) -> Self {
        Self {
            random,
            previous: Mutex::new(None),
        }
    }
}

fn production_nonce_source() -> UniqueNonceSource<OsNonceRandom> {
    UniqueNonceSource::new(OsNonceRandom)
}

impl<R> DiscoveryNonceSource for UniqueNonceSource<R>
where
    R: NonceRandom,
{
    fn next_nonce(&self) -> Result<[u8; 16], DriverError> {
        let mut previous = self.previous.lock().map_err(|_| nonce_unavailable())?;
        for _ in 0..=3 {
            let nonce = self.random.generate().map_err(|_| nonce_unavailable())?;
            if previous.as_ref() != Some(&nonce) {
                *previous = Some(nonce);
                return Ok(nonce);
            }
        }
        Err(nonce_unavailable())
    }
}

fn nonce_unavailable() -> DriverError {
    DriverError::new(
        DriverErrorKind::Unavailable,
        "rostered discovery nonce generation is unavailable",
    )
}

/// Owned unattended Linux rostered-BTLE lifecycle.
pub struct LinuxRosteredBtleSupervisor {
    availability: watch::Receiver<crate::BtleAvailability>,
    completion: watch::Receiver<bool>,
    cancellation: LifecycleCancellation,
    platform_owner: Arc<PlatformOwner>,
    output: crate::BtleOperatorOutput,
    failure_park: Option<(Arc<AvailabilityFence>, UnavailableAvailabilityPublisher)>,
    task: Option<JoinHandle<Result<(), SupervisorError>>>,
    abort_on_unconfirmed_cleanup: bool,
}

trait PlatformOwnerLoss: Send + Sync {
    fn force(&self);
}

impl PlatformOwnerLoss for BluezOwnerLoss {
    fn force(&self) {
        BluezOwnerLoss::force(self);
    }
}

#[derive(Default)]
struct PlatformOwner(Mutex<Option<Arc<dyn PlatformOwnerLoss>>>);

impl PlatformOwner {
    fn replace(&self, owner: impl PlatformOwnerLoss + 'static) {
        *self
            .0
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner) = Some(Arc::new(owner));
    }

    fn clear(&self) {
        self.0
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .take();
    }

    fn force_loss(&self) -> bool {
        let owner = self
            .0
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .clone();
        if let Some(owner) = owner {
            owner.force();
            true
        } else {
            false
        }
    }
}

impl LinuxRosteredBtleSupervisor {
    fn report_cleanup_unconfirmed(&self) {
        self.output
            .emit(crate::BtleOperatorEvent::CleanupUnconfirmed);
        self.output
            .publish_terminal(crate::controller::TerminalAvailability::CleanupUnconfirmed);
    }

    /// Returns coarse adapter availability without exposing discovery material.
    pub fn availability(&self) -> watch::Receiver<crate::BtleAvailability> {
        self.availability.clone()
    }

    /// Returns the coarse terminal supervisor signal.
    pub fn completion(&self) -> watch::Receiver<bool> {
        self.completion.clone()
    }

    /// Requests idempotent cancellation of all owned rostered lifecycle work.
    pub fn cancel(&self) {
        self.cancellation.cancel();
    }

    /// Fences late availability and publishes the adapter unavailable before
    /// an authority failure begins cleanup.
    pub fn park_unavailable(&self) -> Result<(), SupervisorError> {
        let Some((fence, publisher)) = &self.failure_park else {
            return Ok(());
        };
        fence.quiesce();
        publisher
            .publish()
            .map_err(|_| SupervisorError::TaskStopped)
    }

    /// Fences late status and availability after discovery authority is lost.
    pub fn park_authority_unavailable(&self) -> Result<(), SupervisorError> {
        self.output
            .publish_terminal(crate::controller::TerminalAvailability::CredentialUnavailable);
        self.park_unavailable()
    }

    /// Waits until the owned rostered lifecycle reaches a terminal result.
    pub async fn wait_for_completion(&self) {
        let mut completion = self.completion.clone();
        while !*completion.borrow_and_update() {
            if completion.changed().await.is_err() {
                return;
            }
        }
    }

    /// Consumes the supervisor and joins its owned lifecycle work.
    pub async fn shutdown(mut self) -> Result<(), SupervisorError> {
        self.cancel();
        let mut task = self.task.take().expect("supervisor task retained");
        match timeout(OWNER_LOSS_AFTER, &mut task).await {
            Ok(result) => {
                let result = result.map_err(|_| SupervisorError::TaskStopped)?;
                self.output.emit(crate::BtleOperatorEvent::Stopped);
                result
            }
            Err(_) => {
                self.platform_owner.force_loss();
                self.output.emit(crate::BtleOperatorEvent::CleanupForced);
                match timeout(OWNER_LOSS_JOIN_DEADLINE, &mut task).await {
                    Ok(result) => {
                        let result = result.map_err(|_| SupervisorError::TaskStopped)?;
                        self.output.emit(crate::BtleOperatorEvent::Stopped);
                        result
                    }
                    Err(_) if self.abort_on_unconfirmed_cleanup => {
                        task.abort();
                        let _ = task.await;
                        self.report_cleanup_unconfirmed();
                        Err(SupervisorError::PlatformCleanupUnconfirmed)
                    }
                    Err(_) => {
                        self.report_cleanup_unconfirmed();
                        retain_task_custody(task);
                        Err(SupervisorError::PlatformCleanupUnconfirmed)
                    }
                }
            }
        }
    }
}

impl Drop for LinuxRosteredBtleSupervisor {
    fn drop(&mut self) {
        let Some(task) = self.task.take() else {
            return;
        };
        let _ = self.park_unavailable();
        self.cancellation.cancel();
        let platform_owner = self.platform_owner.clone();
        let output = self.output.clone();
        if let Ok(runtime) = tokio::runtime::Handle::try_current() {
            runtime.spawn(async move {
                contain_supervisor_task(task, platform_owner, output).await;
            });
        }
    }
}

fn retain_task_custody(task: JoinHandle<Result<(), SupervisorError>>) {
    tokio::spawn(async move {
        let _ = task.await;
    });
}

async fn contain_supervisor_task(
    mut task: JoinHandle<Result<(), SupervisorError>>,
    platform_owner: Arc<PlatformOwner>,
    output: crate::BtleOperatorOutput,
) {
    if timeout(OWNER_LOSS_AFTER, &mut task).await.is_ok() {
        return;
    }
    platform_owner.force_loss();
    output.emit(crate::BtleOperatorEvent::CleanupForced);
    if timeout(OWNER_LOSS_JOIN_DEADLINE, &mut task).await.is_err() {
        output.emit(crate::BtleOperatorEvent::CleanupUnconfirmed);
        let _ = task.await;
    }
}

struct CompletionOnDrop(watch::Sender<bool>);

impl Drop for CompletionOnDrop {
    fn drop(&mut self) {
        self.0.send_if_modified(|completed| {
            if *completed {
                false
            } else {
                *completed = true;
                true
            }
        });
    }
}

/// Starts one unattended rostered Linux BTLE Event supervisor.
pub fn spawn_linux_rostered_btle_event_supervisor(
    config: ValidatedRosteredSupervisorConfig,
    contacts: OrderedEventContactHandle,
) -> LinuxRosteredBtleSupervisor {
    spawn_rostered_btle_event_supervisor(config, contacts, crate::BtleOperatorOutput::discard())
}

struct RosteredEpochActivator {
    config: Arc<ValidatedAutomaticRosteredSupervisorConfig>,
    mode: Arc<AsyncMutex<EpochContactMode>>,
    publisher: Arc<AdapterAvailabilityPublisher>,
    platform_owner: Arc<PlatformOwner>,
    supervisor_availability_fence: Arc<AvailabilityFence>,
}

impl ControllerEpochActivator for RosteredEpochActivator {
    fn activate(
        &self,
        epoch: ControllerEpochView<'_>,
    ) -> Result<Box<dyn OperationalControllerEpoch>, DriverError> {
        let config = Arc::new(self.config.for_controller(
            epoch.adapter_name().to_owned(),
            epoch.address(),
            epoch.address_type(),
            epoch.inventory_generation(),
            epoch.cancellation(),
        )?);
        let (updates, status) = watch::channel(OperationalEpochState::Starting);
        let cancellation = LifecycleCancellation::new();
        let observer = cancellation.observer();
        let task_cancellation = cancellation.clone();
        let availability_fence = Arc::new(AvailabilityFence::default());
        let task_availability_fence = availability_fence.clone();
        let (quiesce, mut quiesce_requests) = mpsc::channel(1);
        let mode = self.mode.clone();
        let publisher = self.publisher.clone();
        let platform_owner = self.platform_owner.clone();
        let supervisor_availability_fence = self.supervisor_availability_fence.clone();
        let task_updates = updates.clone();
        let task = tokio::spawn(async move {
            let epoch = async {
                let discovery = match await_startup_platform(
                    config.epoch_discovery_credentials().expires_at(),
                    config.open_timeout(),
                    &observer,
                    BluezDiscoveryPlatform::open(),
                )
                .await
                {
                    Ok(discovery) => discovery,
                    Err(error) => {
                        return finish_operational_epoch_result(
                            Err(error),
                            platform_owner.as_ref(),
                        );
                    }
                };
                platform_owner.replace(discovery.owner_loss());
                let sockets = Arc::new(BluezRosteredSocketFactory);
                let nonces = Arc::new(production_nonce_source());
                let mut mode = mode.lock().await;
                let result = run_available_epoch_with_mode(
                    config,
                    sockets,
                    Arc::new(discovery),
                    nonces,
                    &mut mode,
                    EpochSignals::operational(
                        publisher.clone(),
                        task_updates.clone(),
                        task_availability_fence,
                        supervisor_availability_fence,
                    ),
                    observer.clone(),
                )
                .await;
                complete_pending_after_epoch(&mut mode, &observer, &result);
                finish_operational_epoch_result(result, platform_owner.as_ref())
            };
            tokio::pin!(epoch);
            let (result, quiesced) = tokio::select! {
                biased;
                request = quiesce_requests.recv() => {
                    if let Some(acknowledged) = request {
                        acknowledge_operational_quiesce(
                            &publisher,
                            &task_updates,
                            acknowledged,
                        );
                    }
                    task_cancellation.cancel();
                    (epoch.await, true)
                }
                result = &mut epoch => (result, false),
            };
            let _ = publisher.publish(crate::BtleAvailability::Unavailable(
                crate::AvailabilityReason::BluezUnavailable,
            ));
            task_updates.send_replace(OperationalEpochState::Unavailable);
            if !quiesced && let Some(acknowledged) = quiesce_requests.recv().await {
                acknowledge_operational_quiesce(&publisher, &task_updates, acknowledged);
                task_cancellation.cancel();
            }
            result
        });
        Ok(Box::new(RosteredOperationalEpoch {
            status,
            quiesce,
            availability_fence,
            cancellation,
            task: Some(task),
            platform_owner: self.platform_owner.clone(),
            unavailable: self.publisher.unavailable_only(),
        }))
    }
}

fn finish_operational_epoch_result(
    result: Result<(), SupervisorError>,
    platform_owner: &PlatformOwner,
) -> OperationalEpochOutcome {
    let terminal = match result {
        Ok(()) | Err(SupervisorError::Controller(_)) => None,
        Err(SupervisorError::ContactSuppressed(_)) => {
            platform_owner.clear();
            return OperationalEpochOutcome::Suppressed;
        }
        Err(SupervisorError::PlatformCleanupUnconfirmed) => Some(DriverError::new(
            DriverErrorKind::Transport,
            "automatic rostered carrier cleanup was not confirmed",
        )),
        Err(
            SupervisorError::Configuration
            | SupervisorError::AdmissionClosed
            | SupervisorError::ActorUnavailable
            | SupervisorError::ActorStopped
            | SupervisorError::ContactTerminal(_)
            | SupervisorError::CredentialExpired
            | SupervisorError::TaskStopped,
        ) => Some(DriverError::new(
            DriverErrorKind::Transport,
            "automatic rostered carrier operation terminated",
        )),
    };
    if let Some(error) = terminal {
        OperationalEpochOutcome::Terminal(error)
    } else {
        platform_owner.clear();
        OperationalEpochOutcome::Retryable
    }
}

fn acknowledge_operational_quiesce(
    publisher: &AdapterAvailabilityPublisher,
    updates: &watch::Sender<OperationalEpochState>,
    acknowledged: oneshot::Sender<Result<(), DriverError>>,
) {
    let unavailable = publisher
        .publish(crate::BtleAvailability::Unavailable(
            crate::AvailabilityReason::BluezUnavailable,
        ))
        .map_err(|_| {
            DriverError::new(
                DriverErrorKind::Transport,
                "automatic carrier readiness publication failed",
            )
        });
    updates.send_replace(OperationalEpochState::Unavailable);
    let _ = acknowledged.send(unavailable);
}

struct RosteredOperationalEpoch {
    status: watch::Receiver<OperationalEpochState>,
    quiesce: mpsc::Sender<oneshot::Sender<Result<(), DriverError>>>,
    availability_fence: Arc<AvailabilityFence>,
    cancellation: LifecycleCancellation,
    task: Option<JoinHandle<OperationalEpochOutcome>>,
    platform_owner: Arc<PlatformOwner>,
    unavailable: UnavailableAvailabilityPublisher,
}

impl OperationalControllerEpoch for RosteredOperationalEpoch {
    fn status(&self) -> watch::Receiver<OperationalEpochState> {
        self.status.clone()
    }

    fn quiesce(&mut self) -> OperationalEpochFuture<'_, Result<(), DriverError>> {
        self.availability_fence.quiesce();
        Box::pin(async move {
            timeout(OWNER_LOSS_AFTER, async {
                let (acknowledged, acknowledgement) = oneshot::channel();
                self.quiesce.send(acknowledged).await.map_err(|_| {
                    self.publish_unavailable_after_failure(
                        "automatic rostered carrier epoch quiesce channel closed",
                    )
                })?;
                acknowledgement.await.map_err(|_| {
                    self.publish_unavailable_after_failure(
                        "automatic rostered carrier epoch quiesce was not acknowledged",
                    )
                })?
            })
            .await
            .unwrap_or_else(|_| {
                Err(self.publish_unavailable_after_failure(
                    "automatic rostered carrier epoch quiesce exceeded its deadline",
                ))
            })
        })
    }

    fn cancel(&self) {
        self.cancellation.cancel();
    }

    fn join(mut self: Box<Self>) -> OperationalEpochFuture<'static, OperationalEpochOutcome> {
        Box::pin(async move {
            self.availability_fence.quiesce();
            self.cancellation.cancel();
            finish_operational_epoch_task(
                self.task.take().expect("operational epoch task retained"),
                self.platform_owner.clone(),
                self.unavailable.clone(),
            )
            .await
        })
    }
}

impl RosteredOperationalEpoch {
    fn publish_unavailable_after_failure(&self, message: &'static str) -> DriverError {
        let _ = self.unavailable.publish();
        DriverError::new(DriverErrorKind::Transport, message)
    }
}

impl Drop for RosteredOperationalEpoch {
    fn drop(&mut self) {
        let Some(task) = self.task.take() else {
            return;
        };
        self.availability_fence.quiesce();
        let _ = self.unavailable.publish();
        self.cancellation.cancel();
        let platform_owner = self.platform_owner.clone();
        let unavailable = self.unavailable.clone();
        if let Ok(runtime) = tokio::runtime::Handle::try_current() {
            runtime.spawn(async move {
                let _ = finish_operational_epoch_task(task, platform_owner, unavailable).await;
            });
        } else {
            platform_owner.force_loss();
            task.abort();
        }
    }
}

async fn finish_operational_epoch_task(
    mut task: JoinHandle<OperationalEpochOutcome>,
    platform_owner: Arc<PlatformOwner>,
    unavailable: UnavailableAvailabilityPublisher,
) -> OperationalEpochOutcome {
    let task_result = match timeout(OWNER_LOSS_AFTER, &mut task).await {
        Ok(result) => result,
        Err(_) => {
            let _ = unavailable.publish();
            platform_owner.force_loss();
            if timeout(OWNER_LOSS_JOIN_DEADLINE, &mut task).await.is_err() {
                task.abort();
                let _ = task.await;
            }
            return OperationalEpochOutcome::Terminal(DriverError::new(
                DriverErrorKind::Transport,
                "automatic rostered carrier epoch cleanup exceeded its deadline",
            ));
        }
    };
    match task_result {
        Ok(OperationalEpochOutcome::Retryable) => OperationalEpochOutcome::Retryable,
        Ok(OperationalEpochOutcome::Suppressed) => {
            platform_owner.clear();
            OperationalEpochOutcome::Suppressed
        }
        Ok(OperationalEpochOutcome::Terminal(error)) => {
            let _ = unavailable.publish();
            platform_owner.force_loss();
            OperationalEpochOutcome::Terminal(error)
        }
        Err(_) => {
            let _ = unavailable.publish();
            platform_owner.force_loss();
            OperationalEpochOutcome::Terminal(DriverError::new(
                DriverErrorKind::Transport,
                "automatic rostered carrier epoch cleanup was not confirmed",
            ))
        }
    }
}

/// Starts one automatic rostered Linux BTLE carrier owner.
///
/// The caller owns host policy. Linux returns a non-authoritative carrier port
/// and retains only discovery, radio, socket, and carrier-lifecycle ownership.
pub fn spawn_resolving_linux_rostered_btle_carrier_supervisor(
    config: ValidatedAutomaticRosteredSupervisorConfig,
) -> (
    LinuxRosteredBtleSupervisor,
    watch::Receiver<crate::BtleCurrentStatus>,
    crate::AutomaticBtleCarrierPort,
) {
    let initial_status = crate::BtleCurrentStatus::Unavailable {
        reason: crate::AvailabilityReason::BluezUnavailable,
        support: crate::BtleSupport::NotEvaluated,
    };
    let (output, status) = crate::BtleOperatorOutput::current_status(initial_status);
    let config = Arc::new(config);
    let expires_at = config.discovery_credentials_expires_at();
    let cancellation = LifecycleCancellation::new();
    let initial = crate::BtleAvailability::Unavailable(crate::AvailabilityReason::BluezUnavailable);
    let (backend, port) = automatic_btle_carrier_channel(initial);
    let readiness = backend.readiness_publisher();
    let (availability_updates, availability) = watch::channel(initial);
    let publisher = Arc::new(AdapterAvailabilityPublisher::automatic(
        readiness,
        availability_updates,
        output.clone(),
        config.role(),
    ));
    let platform_owner = Arc::new(PlatformOwner::default());
    let supervisor_availability_fence = Arc::new(AvailabilityFence::default());
    let activator = Arc::new(RosteredEpochActivator {
        config: config.clone(),
        mode: Arc::new(AsyncMutex::new(EpochContactMode::automatic(backend))),
        publisher: publisher.clone(),
        platform_owner: platform_owner.clone(),
        supervisor_availability_fence: supervisor_availability_fence.clone(),
    });
    let resolver = spawn_linux_controller_resolver(
        config.controller_policy().clone(),
        config.controller_probe_limits(),
        output.clone(),
        activator,
    );
    let (completion_updates, completion) = watch::channel(false);
    let task_cancellation = cancellation.clone();
    let failure_park = (
        supervisor_availability_fence.clone(),
        publisher.unavailable_only(),
    );
    let task = tokio::spawn(async move {
        let _completion = CompletionOnDrop(completion_updates);
        let status = resolver.status();
        run_automatic_resolver_owner(
            status,
            task_cancellation,
            expires_at,
            supervisor_availability_fence,
            publisher.unavailable_only(),
            async move { resolver.shutdown_for_supervisor().await },
        )
        .await
    });
    (
        LinuxRosteredBtleSupervisor {
            availability,
            completion,
            cancellation,
            platform_owner,
            output,
            failure_park: Some(failure_park),
            task: Some(task),
            abort_on_unconfirmed_cleanup: false,
        },
        status,
        port,
    )
}

async fn run_automatic_resolver_owner<T, F>(
    mut status: watch::Receiver<T>,
    cancellation: LifecycleCancellation,
    expires_at: Instant,
    supervisor_availability_fence: Arc<AvailabilityFence>,
    unavailable: UnavailableAvailabilityPublisher,
    shutdown: F,
) -> Result<(), SupervisorError>
where
    T: Send + Sync + 'static,
    F: Future<Output = Result<(), DriverError>>,
{
    enum Wake {
        Cancelled,
        ResolverStopped,
        Expired,
    }

    let resolver_stopped = async { while status.changed().await.is_ok() {} };
    let wake = tokio::select! {
        biased;
        () = cancellation.cancelled() => Wake::Cancelled,
        () = resolver_stopped => Wake::ResolverStopped,
        () = tokio::time::sleep_until(tokio::time::Instant::from_std(expires_at)) => Wake::Expired,
    };
    let publication_error = if matches!(wake, Wake::Expired | Wake::ResolverStopped) {
        if matches!(wake, Wake::Expired) {
            supervisor_availability_fence.quiesce();
            unavailable
                .publish_terminal(crate::controller::TerminalAvailability::CredentialExpired);
        } else {
            unavailable.publish_terminal(crate::controller::TerminalAvailability::PlatformFailure);
        }
        unavailable
            .publish()
            .err()
            .map(|_| SupervisorError::TaskStopped)
    } else {
        None
    };
    let shutdown_result = shutdown
        .await
        .map_err(|_| SupervisorError::PlatformCleanupUnconfirmed);
    if let Err(error) = shutdown_result {
        unavailable.publish_terminal(crate::controller::TerminalAvailability::CleanupUnconfirmed);
        return Err(error);
    }
    if let Some(error) = publication_error {
        return Err(error);
    }
    if matches!(wake, Wake::Expired) {
        // Terminate only after fencing and cleanup so the process owner can
        // rebuild this immutable credential epoch through controlled restart.
        Err(SupervisorError::CredentialExpired)
    } else {
        Ok(())
    }
}

fn spawn_rostered_btle_event_supervisor(
    config: ValidatedRosteredSupervisorConfig,
    contacts: OrderedEventContactHandle,
    output: crate::BtleOperatorOutput,
) -> LinuxRosteredBtleSupervisor {
    let cancellation = LifecycleCancellation::new();
    let initial = crate::BtleAvailability::Unavailable(crate::AvailabilityReason::BluezUnavailable);
    let (availability_updates, availability) = watch::channel(initial);
    output.emit(crate::BtleOperatorEvent::AdapterUnavailable(
        crate::AvailabilityReason::BluezUnavailable,
    ));
    let publisher = Arc::new(AdapterAvailabilityPublisher::fixed(
        availability_updates,
        output.clone(),
    ));
    let (completion_updates, completion) = watch::channel(false);
    let platform_owner = Arc::new(PlatformOwner::default());
    let task_cancellation = cancellation.clone();
    let task_platform_owner = platform_owner.clone();
    let peer_mission_id = config.fixed_peer_mission_id();
    let task = tokio::spawn(async move {
        let _completion = CompletionOnDrop(completion_updates);
        run_rostered_supervisor(
            Arc::new(config),
            publisher,
            task_cancellation,
            task_platform_owner,
            EpochContactMode::fixed(Arc::new(contacts), peer_mission_id),
        )
        .await
    });
    LinuxRosteredBtleSupervisor {
        availability,
        completion,
        cancellation,
        platform_owner,
        output,
        failure_park: None,
        task: Some(task),
        abort_on_unconfirmed_cleanup: true,
    }
}

async fn run_rostered_supervisor(
    config: Arc<ValidatedRosteredSupervisorConfig>,
    publisher: Arc<AdapterAvailabilityPublisher>,
    cancellation: LifecycleCancellation,
    platform_owner: Arc<PlatformOwner>,
    mut mode: EpochContactMode,
) -> Result<(), SupervisorError> {
    let sockets = Arc::new(BluezRosteredSocketFactory);
    let nonces = Arc::new(production_nonce_source());
    let mut backoff = CappedBackoff::new(INITIAL_EPOCH_RETRY, MAXIMUM_EPOCH_RETRY);
    loop {
        if cancellation.is_cancelled() {
            return Ok(());
        }
        if lifecycle_now() >= config.epoch_discovery_credentials().expires_at() {
            return park_expired_adapter(config, &publisher, &cancellation).await;
        }
        let discovery = match await_startup_platform(
            config.epoch_discovery_credentials().expires_at(),
            config.open_timeout(),
            &cancellation.observer(),
            BluezDiscoveryPlatform::open(),
        )
        .await
        {
            Ok(discovery) => discovery,
            Err(SupervisorError::Configuration) => return Err(SupervisorError::Configuration),
            Err(SupervisorError::Controller(DriverErrorKind::Cancelled)) => return Ok(()),
            Err(_) if lifecycle_now() >= config.epoch_discovery_credentials().expires_at() => {
                return park_expired_adapter(config, &publisher, &cancellation).await;
            }
            Err(_) => {
                publisher
                    .publish(crate::BtleAvailability::Unavailable(
                        crate::AvailabilityReason::BluezUnavailable,
                    ))
                    .map_err(|_| SupervisorError::TaskStopped)?;
                if wait_epoch_retry(backoff.next_delay(), &cancellation).await {
                    return Ok(());
                }
                continue;
            }
        };
        platform_owner.replace(discovery.owner_loss());
        let (available_started, available_started_at) = oneshot::channel();
        let result = run_available_epoch_with_mode(
            config.clone(),
            sockets.clone(),
            Arc::new(discovery),
            nonces.clone(),
            &mut mode,
            EpochSignals::with_publisher(publisher.clone(), available_started),
            cancellation.observer(),
        )
        .await;
        complete_pending_after_epoch(&mut mode, &cancellation.observer(), &result);
        platform_owner.clear();
        if available_started_at
            .await
            .is_ok_and(|started| stable_epoch_elapsed(started, lifecycle_now()))
        {
            backoff.reset();
        }
        match result {
            Ok(()) => return Ok(()),
            Err(SupervisorError::Configuration) => return Err(SupervisorError::Configuration),
            Err(
                error @ (SupervisorError::AdmissionClosed
                | SupervisorError::ActorUnavailable
                | SupervisorError::ActorStopped
                | SupervisorError::ContactSuppressed(_)
                | SupervisorError::ContactTerminal(_)
                | SupervisorError::CredentialExpired
                | SupervisorError::TaskStopped
                | SupervisorError::PlatformCleanupUnconfirmed),
            ) => return Err(error),
            Err(SupervisorError::Controller(_)) => {
                publisher
                    .publish(crate::BtleAvailability::Unavailable(
                        crate::AvailabilityReason::BluezUnavailable,
                    ))
                    .map_err(|_| SupervisorError::TaskStopped)?;
                if lifecycle_now() >= config.epoch_discovery_credentials().expires_at() {
                    return park_expired_adapter(config, &publisher, &cancellation).await;
                }
                if wait_epoch_retry(backoff.next_delay(), &cancellation).await {
                    return Ok(());
                }
            }
        }
    }
}

fn complete_pending_after_epoch(
    mode: &mut EpochContactMode,
    cancellation: &LifecycleCancellationObserver,
    result: &Result<(), SupervisorError>,
) {
    if matches!(result, Err(SupervisorError::Controller(_))) && !cancellation.is_cancelled() {
        mode.fail_pending_carrier_open();
    } else {
        mode.cancel_pending_carrier_open();
    }
}

async fn park_expired_adapter(
    config: Arc<ValidatedRosteredSupervisorConfig>,
    publisher: &AdapterAvailabilityPublisher,
    cancellation: &LifecycleCancellation,
) -> Result<(), SupervisorError> {
    drop(config);
    publisher
        .publish(crate::BtleAvailability::Unavailable(
            crate::AvailabilityReason::BluezUnavailable,
        ))
        .map_err(|_| SupervisorError::TaskStopped)?;
    cancellation.cancelled().await;
    Ok(())
}

fn stable_epoch_elapsed(started: Instant, ended: Instant) -> bool {
    ended.saturating_duration_since(started) >= STABLE_EPOCH_DURATION
}

fn supervisor_error(error: DriverError) -> SupervisorError {
    if error.kind() == DriverErrorKind::Configuration {
        SupervisorError::Configuration
    } else {
        SupervisorError::Controller(error.kind())
    }
}

fn operation_interrupted(error: SupervisorError) -> bool {
    matches!(
        error,
        SupervisorError::Controller(DriverErrorKind::Cancelled | DriverErrorKind::Unavailable)
    )
}

async fn wait_epoch_retry(delay: Duration, cancellation: &LifecycleCancellation) -> bool {
    tokio::select! {
        biased;
        () = cancellation.cancelled() => true,
        () = tokio::time::sleep(delay) => false,
    }
}

async fn await_startup_platform<T, F>(
    expires_at: Instant,
    open_timeout: Duration,
    cancellation: &LifecycleCancellationObserver,
    operation: F,
) -> Result<T, SupervisorError>
where
    F: Future<Output = Result<T, DriverError>>,
{
    let local_deadline = tokio::time::Instant::now() + open_timeout;
    let credential_deadline = tokio::time::Instant::from_std(expires_at);
    let deadline = local_deadline.min(credential_deadline);
    tokio::pin!(operation);
    tokio::select! {
        biased;
        () = cancellation.cancelled() => {
            Err(SupervisorError::Controller(DriverErrorKind::Cancelled))
        }
        () = tokio::time::sleep_until(deadline) => {
            Err(SupervisorError::Controller(DriverErrorKind::Unavailable))
        }
        result = &mut operation => result.map_err(supervisor_error),
    }
}

async fn await_owned_discovery_start<D, T, F, Cleanup, CleanupFuture>(
    discovery: &D,
    expires_at: Instant,
    open_timeout: Duration,
    cancellation: &LifecycleCancellationObserver,
    operation: F,
    cleanup: Cleanup,
) -> Result<T, SupervisorError>
where
    D: DiscoveryPlatform + ?Sized,
    F: Future<Output = Result<T, DriverError>>,
    Cleanup: FnOnce(T) -> CleanupFuture,
    CleanupFuture: Future<Output = Result<(), DriverError>>,
{
    let local_deadline = tokio::time::Instant::now() + open_timeout;
    let credential_deadline = tokio::time::Instant::from_std(expires_at);
    let deadline = local_deadline.min(credential_deadline);
    tokio::pin!(operation);
    let operation_polled = AtomicBool::new(false);
    let interrupted = {
        let tracked_operation = poll_fn(|context| {
            operation_polled.store(true, AtomicOrdering::Relaxed);
            operation.as_mut().poll(context)
        });
        tokio::pin!(tracked_operation);
        tokio::select! {
            biased;
            () = cancellation.cancelled() => {
                SupervisorError::Controller(DriverErrorKind::Cancelled)
            }
            () = tokio::time::sleep_until(deadline) => {
                SupervisorError::Controller(DriverErrorKind::Unavailable)
            }
            result = &mut tracked_operation => return result.map_err(supervisor_error),
        }
    };
    if !operation_polled.load(AtomicOrdering::Relaxed) {
        return Err(interrupted);
    }
    discovery.force_owner_loss();
    match timeout(OWNED_STOP_DEADLINE, &mut operation).await {
        Ok(Ok(owner)) => cleanup(owner).await.map_err(owned_cleanup_unconfirmed)?,
        Ok(Err(_)) => {}
        Err(_) => return Err(SupervisorError::PlatformCleanupUnconfirmed),
    }
    Err(interrupted)
}

fn publish_availability(
    updates: &watch::Sender<crate::BtleAvailability>,
    availability: crate::BtleAvailability,
) {
    let _ = updates.send_if_modified(|current| {
        if *current == availability {
            false
        } else {
            *current = availability;
            true
        }
    });
}

#[cfg(test)]
async fn run_available_epoch<S, D, N>(
    config: Arc<ValidatedRosteredSupervisorConfig>,
    sockets: Arc<S>,
    discovery: Arc<D>,
    nonces: Arc<N>,
    contacts: SharedContactAdmission,
    signals: EpochSignals,
    cancellation: LifecycleCancellation,
) -> Result<(), SupervisorError>
where
    S: RosteredSocketFactory + 'static,
    D: DiscoveryPlatform,
    N: DiscoveryNonceSource,
{
    let mut mode = EpochContactMode::fixed(contacts, config.fixed_peer_mission_id());
    run_available_epoch_with_mode(
        config,
        sockets,
        discovery,
        nonces,
        &mut mode,
        signals,
        cancellation.observer(),
    )
    .await
}

#[cfg(test)]
#[allow(clippy::too_many_arguments)]
async fn run_automatic_available_epoch<S, D, N>(
    config: Arc<ValidatedRosteredSupervisorConfig>,
    sockets: Arc<S>,
    discovery: Arc<D>,
    nonces: Arc<N>,
    backend: AutomaticBtleCarrierBackend,
    signals: EpochSignals,
    cancellation: LifecycleCancellation,
) -> Result<(), SupervisorError>
where
    S: RosteredSocketFactory + 'static,
    D: DiscoveryPlatform,
    N: DiscoveryNonceSource,
{
    let mut mode = EpochContactMode::automatic(backend);
    run_available_epoch_with_mode(
        config,
        sockets,
        discovery,
        nonces,
        &mut mode,
        signals,
        cancellation.observer(),
    )
    .await
}

#[allow(clippy::too_many_arguments)]
async fn run_available_epoch_with_mode<S, D, N>(
    config: Arc<ValidatedRosteredSupervisorConfig>,
    sockets: Arc<S>,
    discovery: Arc<D>,
    nonces: Arc<N>,
    mode: &mut EpochContactMode,
    mut signals: EpochSignals,
    cancellation: LifecycleCancellationObserver,
) -> Result<(), SupervisorError>
where
    S: RosteredSocketFactory + 'static,
    D: DiscoveryPlatform,
    N: DiscoveryNonceSource,
{
    let expires_at = config.epoch_discovery_credentials().expires_at();
    let bound_listener = await_startup_platform(
        expires_at,
        config.open_timeout(),
        &cancellation,
        sockets.bind_dynamic_listener(config.controller()),
    )
    .await?;
    let listener_psm = bound_listener.allocated_psm();
    let listener = Arc::new(bound_listener.into_listener());
    let record =
        encode_advertisement(&config, listener_psm, nonces.as_ref()).map_err(supervisor_error)?;
    let mut advertisement = Some(
        match await_owned_discovery_start(
            discovery.as_ref(),
            expires_at,
            config.open_timeout(),
            &cancellation,
            discovery.start_advertisement(config.controller(), record),
            |mut owner| async move { release_advertisement(owner.as_mut()).await },
        )
        .await
        {
            Ok(owner) => owner,
            Err(error) => {
                if operation_interrupted(error) {
                    discovery.force_owner_loss();
                }
                return Err(error);
            }
        },
    );
    if lifecycle_now() >= expires_at {
        discovery.force_owner_loss();
        let cleanup = release_advertisement(
            advertisement
                .as_mut()
                .expect("advertisement was just registered")
                .as_mut(),
        )
        .await;
        drop(listener);
        cleanup.map_err(owned_cleanup_unconfirmed)?;
        return Err(SupervisorError::Controller(DriverErrorKind::Unavailable));
    }
    let started_scan = match await_owned_discovery_start(
        discovery.as_ref(),
        expires_at,
        config.open_timeout(),
        &cancellation,
        discovery.start_scan(config.controller()),
        |started| async move {
            let (mut owner, _) = started.into_parts();
            stop_scan(owner.as_mut()).await
        },
    )
    .await
    {
        Ok(started) => started,
        Err(error) => {
            discovery.force_owner_loss();
            let cleanup = release_advertisement(
                advertisement
                    .as_mut()
                    .expect("advertisement was just registered")
                    .as_mut(),
            )
            .await;
            drop(listener);
            cleanup.map_err(owned_cleanup_unconfirmed)?;
            return Err(error);
        }
    };
    if lifecycle_now() >= expires_at {
        discovery.force_owner_loss();
        let (mut scan, _) = started_scan.into_parts();
        let scan_cleanup = stop_scan(scan.as_mut());
        let advertisement_cleanup = release_advertisement(
            advertisement
                .as_mut()
                .expect("advertisement was just registered")
                .as_mut(),
        );
        let (scan_result, advertisement_result) = tokio::join!(scan_cleanup, advertisement_cleanup);
        drop(listener);
        scan_result.map_err(owned_cleanup_unconfirmed)?;
        advertisement_result.map_err(owned_cleanup_unconfirmed)?;
        return Err(SupervisorError::Controller(DriverErrorKind::Unavailable));
    }
    let (scan, observations) = started_scan.into_parts();
    let mut admission = DiscoveryAdmission::new();
    let started_at = lifecycle_now();
    let scan_start = admission.start_scan(started_at);
    debug_assert_eq!(scan_start, crate::ScanStartOutcome::Started);
    let mut scan_phase = ScanPhase::Active {
        scan: ActiveScan {
            owner: scan,
            observations,
        },
        deadline: tokio::time::Instant::now() + SCAN_ACTIVE_INTERVAL,
    };
    let advertisement_deadline = tokio::time::Instant::now() + ADVERTISEMENT_ROTATION_INTERVAL;
    let credential_deadline = tokio::time::Instant::from_std(expires_at);
    let mut contact_phase = ContactPhase::accepting(sockets.clone(), listener.clone());
    let mut outbound_delay = OutboundDelay::Ready;
    let mut outbound_candidate_pending = false;
    let mut contact_backoff = CappedBackoff::new(INITIAL_EPOCH_RETRY, MAXIMUM_EPOCH_RETRY);
    let mut owner_loss_required = true;
    let mut selector_ready = !mode.is_automatic();
    let mut result = if cancellation.is_cancelled() {
        Err(SupervisorError::Controller(DriverErrorKind::Cancelled))
    } else {
        config
            .controller()
            .ensure_current()
            .map_err(supervisor_error)
            .and_then(|()| signals.publish(crate::BtleAvailability::Available))
    };
    if result.is_ok()
        && let Some(available_started) = signals.available_started.take()
    {
        let _ = available_started.send(lifecycle_now());
    }

    if result.is_ok() {
        result = loop {
            let contact_is_free = contact_phase.is_free();
            let outbound_retry_enabled =
                contact_is_free && outbound_candidate_pending && mode.can_open_outbound(&config);
            let automatic_request_enabled = mode.is_automatic();
            let outbound_retry_deadline =
                tokio::time::Instant::from_std(outbound_delay.deadline(lifecycle_now()));
            let event = match &mut scan_phase {
                ScanPhase::Active { scan, deadline } => {
                    let advertisement_terminated = advertisement
                        .as_ref()
                        .expect("advertisement is live")
                        .terminated();
                    let scan_terminated = scan.owner.termination();
                    tokio::select! {
                        biased;
                        () = cancellation.cancelled() => EpochEvent::Cancelled,
                        () = tokio::time::sleep_until(credential_deadline) => EpochEvent::CredentialExpired,
                        () = tokio::time::sleep_until(*deadline) => EpochEvent::ScanDeadline,
                        () = tokio::time::sleep_until(advertisement_deadline) => {
                            EpochEvent::AdvertisementRotation
                        },
                        () = advertisement_terminated => EpochEvent::AdvertisementTerminated,
                        reason = scan_terminated => EpochEvent::ScanTerminated(reason),
                        event = mode.next_automatic_carrier_event(), if automatic_request_enabled => {
                            EpochEvent::AutomaticCarrierRequest(event)
                        },
                        () = tokio::time::sleep_until(outbound_retry_deadline), if outbound_retry_enabled => {
                            EpochEvent::OutboundRetry
                        },
                        observation = scan.observations.recv() => EpochEvent::Observation(observation),
                        event = contact_phase.next() => event,
                    }
                }
                ScanPhase::Idle { deadline } => {
                    let advertisement_terminated = advertisement
                        .as_ref()
                        .expect("advertisement is live")
                        .terminated();
                    tokio::select! {
                        biased;
                        () = cancellation.cancelled() => EpochEvent::Cancelled,
                        () = tokio::time::sleep_until(credential_deadline) => EpochEvent::CredentialExpired,
                        () = tokio::time::sleep_until(*deadline), if contact_is_free => {
                            EpochEvent::ScanIdleDeadline
                        },
                        () = tokio::time::sleep_until(advertisement_deadline) => {
                            EpochEvent::AdvertisementRotation
                        },
                        () = advertisement_terminated => EpochEvent::AdvertisementTerminated,
                        event = mode.next_automatic_carrier_event(), if automatic_request_enabled => {
                            EpochEvent::AutomaticCarrierRequest(event)
                        },
                        () = tokio::time::sleep_until(outbound_retry_deadline), if outbound_retry_enabled => {
                            EpochEvent::OutboundRetry
                        },
                        event = contact_phase.next() => event,
                    }
                }
            };
            match event {
                EpochEvent::Cancelled => break Ok(()),
                EpochEvent::AdvertisementTerminated => {
                    break Err(SupervisorError::Controller(DriverErrorKind::Transport));
                }
                EpochEvent::CredentialExpired => {
                    break Err(SupervisorError::Controller(DriverErrorKind::Unavailable));
                }
                EpochEvent::ScanTerminated(ScanTermination::CapacityExceeded) => {
                    finish_ended_scan(&mut scan_phase, &mut admission);
                }
                EpochEvent::ScanTerminated(
                    ScanTermination::Requested | ScanTermination::Unexpected,
                )
                | EpochEvent::Observation(None) => {
                    break Err(SupervisorError::Controller(DriverErrorKind::Transport));
                }
                EpochEvent::AdvertisementRotation => {
                    let mut previous = advertisement.take().expect("advertisement is live");
                    if let Err(error) = release_advertisement(previous.as_mut()).await {
                        break Err(owned_cleanup_unconfirmed(error));
                    }
                    owner_loss_required = false;
                    break Err(SupervisorError::Controller(DriverErrorKind::Transport));
                }
                EpochEvent::Observation(Some(observation)) => {
                    let now = lifecycle_now();
                    let outcome =
                        admit_platform_observation(&mut admission, &config, observation, now);
                    let candidate_selectable = outcome == ObservationOutcome::Accepted
                        && admission.selected_candidate(now).is_some();
                    if candidate_selectable && !selector_ready {
                        if let Err(error) = config
                            .controller()
                            .ensure_current()
                            .map_err(supervisor_error)
                            .and_then(|()| signals.publish_selector_available())
                        {
                            break Err(error);
                        }
                        selector_ready = true;
                    }
                    if matches!(outcome, ObservationOutcome::StopWindow(_)) {
                        if let Err(error) = stop_active_scan(&mut scan_phase, &mut admission).await
                        {
                            break Err(error);
                        }
                    } else if candidate_selectable
                        && (mode.is_automatic() || config.role() == FixedRole::Initiator)
                    {
                        outbound_candidate_pending = true;
                        outbound_delay.wake_for_new_candidate();
                        match begin_outbound_contact(
                            &config,
                            &sockets,
                            &mut admission,
                            &mut scan_phase,
                            &mut outbound_candidate_pending,
                            &mut outbound_delay,
                            mode,
                        )
                        .await
                        {
                            Ok(Some(phase)) => contact_phase = phase,
                            Ok(None) => {}
                            Err(error) => break Err(error),
                        }
                    }
                }
                EpochEvent::InboundAccepted(accepted) => {
                    let (accepted_socket, locator) = match accepted {
                        Ok(accepted) => accepted,
                        Err(error) if error.kind() == DriverErrorKind::PeerRejected => {
                            contact_phase =
                                ContactPhase::accepting(sockets.clone(), listener.clone());
                            continue;
                        }
                        Err(error) => break Err(supervisor_error(error)),
                    };
                    let now = lifecycle_now();
                    match admit_inbound_contact(&config, &mut admission, locator, now, mode) {
                        InboundContactAdmission::Admitted => {}
                        InboundContactAdmission::Rejected => {
                            drop(accepted_socket);
                            contact_phase =
                                ContactPhase::accepting(sockets.clone(), listener.clone());
                            continue;
                        }
                        InboundContactAdmission::BackoffUntil(deadline) => {
                            drop(accepted_socket);
                            contact_phase = ContactPhase::paused_until(deadline);
                            continue;
                        }
                    }
                    contact_phase = ContactPhase::admitting_inbound(
                        accepted_socket,
                        locator,
                        config.open_timeout(),
                    );
                }
                EpochEvent::InboundReady(ready) => {
                    let (opened_socket, locator) = match ready {
                        Ok(ready) => ready,
                        Err(error) if error.kind() == DriverErrorKind::PeerRejected => {
                            contact_phase =
                                ContactPhase::accepting(sockets.clone(), listener.clone());
                            continue;
                        }
                        Err(error) => break Err(supervisor_error(error)),
                    };
                    let opened = match opened_rostered_contact(&config, locator, opened_socket) {
                        Ok(opened) => opened,
                        Err(error) if error.kind() == DriverErrorKind::PeerRejected => {
                            contact_phase =
                                ContactPhase::accepting(sockets.clone(), listener.clone());
                            continue;
                        }
                        Err(error) => break Err(supervisor_error(error)),
                    };
                    let now = lifecycle_now();
                    if let Err(error) = stop_active_scan(&mut scan_phase, &mut admission).await {
                        break Err(error);
                    }
                    admission.enter_authenticated_contact(now);
                    contact_phase = if mode.is_automatic() {
                        match mode.deliver_inbound(opened) {
                            Some(release) => ContactPhase::leased(release),
                            None => {
                                admission.contact_closed(now);
                                scan_phase = idle_scan_phase();
                                ContactPhase::accepting(sockets.clone(), listener.clone())
                            }
                        }
                    } else {
                        ContactPhase::admitted(
                            mode.fixed_contacts().clone(),
                            mode.fixed_peer_mission_id(),
                            OrderedEventContactRole::Responder,
                            opened,
                        )
                    };
                }
                EpochEvent::InboundAcceptReady => {
                    contact_phase = ContactPhase::accepting(sockets.clone(), listener.clone());
                }
                EpochEvent::OutboundRetry => {
                    match begin_outbound_contact(
                        &config,
                        &sockets,
                        &mut admission,
                        &mut scan_phase,
                        &mut outbound_candidate_pending,
                        &mut outbound_delay,
                        mode,
                    )
                    .await
                    {
                        Ok(Some(phase)) => contact_phase = phase,
                        Ok(None) => {}
                        Err(error) => break Err(error),
                    }
                }
                EpochEvent::AutomaticCarrierRequest(AutomaticCarrierRequestEvent::Received(
                    Some(request),
                )) => {
                    if mode.accept_carrier_request(&config, request) {
                        outbound_candidate_pending =
                            admission.selected_candidate(lifecycle_now()).is_some();
                        if outbound_candidate_pending && contact_phase.is_free() {
                            match begin_outbound_contact(
                                &config,
                                &sockets,
                                &mut admission,
                                &mut scan_phase,
                                &mut outbound_candidate_pending,
                                &mut outbound_delay,
                                mode,
                            )
                            .await
                            {
                                Ok(Some(phase)) => contact_phase = phase,
                                Ok(None) => {}
                                Err(error) => break Err(error),
                            }
                        } else if !outbound_candidate_pending {
                            mode.fail_pending_no_candidate();
                            if selector_ready {
                                signals.publish_selector_unavailable()?;
                                selector_ready = false;
                            }
                        }
                    }
                }
                EpochEvent::AutomaticCarrierRequest(AutomaticCarrierRequestEvent::Received(
                    None,
                )) => {
                    break Ok(());
                }
                EpochEvent::AutomaticCarrierRequest(AutomaticCarrierRequestEvent::Cancelled) => {
                    mode.finish_pending_cancelled();
                    outbound_candidate_pending = false;
                }
                EpochEvent::ContactFinished(outcome) => {
                    let now = lifecycle_now();
                    let outcome = match outcome {
                        ContactAttemptOutcome::Opened { opened, owner } => {
                            if now >= config.epoch_discovery_credentials().expires_at() {
                                drop(opened);
                                if let OutboundAttemptOwner::Automatic(request) = owner {
                                    request.complete_error(DriverError::new(
                                        DriverErrorKind::Unavailable,
                                        "automatic carrier credential expired after open",
                                    ));
                                }
                                break Err(SupervisorError::Controller(
                                    DriverErrorKind::Unavailable,
                                ));
                            }
                            if matches!(&owner, OutboundAttemptOwner::FixedEvaluation)
                                && !admission
                                    .try_consume_attempt(AttemptKind::MissionHandshake, now)
                            {
                                drop(opened);
                                admission.contact_closed(now);
                                scan_phase = idle_scan_phase();
                                outbound_candidate_pending = true;
                                mode.restore_outbound(owner);
                                outbound_delay = OutboundDelay::TokenRefillUntil(
                                    admission.attempt_retry_at(AttemptKind::MissionHandshake, now),
                                );
                                contact_phase =
                                    ContactPhase::accepting(sockets.clone(), listener.clone());
                                continue;
                            }
                            contact_phase = match owner {
                                OutboundAttemptOwner::FixedEvaluation => ContactPhase::admitted(
                                    mode.fixed_contacts().clone(),
                                    mode.fixed_peer_mission_id(),
                                    OrderedEventContactRole::Initiator,
                                    *opened,
                                ),
                                OutboundAttemptOwner::Automatic(request) => {
                                    match request.complete_contact(*opened) {
                                        Some(release) => ContactPhase::leased(release),
                                        None => {
                                            admission.contact_closed(now);
                                            scan_phase = idle_scan_phase();
                                            ContactPhase::accepting(
                                                sockets.clone(),
                                                listener.clone(),
                                            )
                                        }
                                    }
                                }
                            };
                            continue;
                        }
                        outcome => outcome,
                    };
                    admission.contact_closed(now);
                    scan_phase = idle_scan_phase();
                    let mut schedule = OutboundSchedule {
                        delay: &mut outbound_delay,
                        candidate_pending: &mut outbound_candidate_pending,
                        backoff: &mut contact_backoff,
                        self_schedule: !mode.is_automatic(),
                    };
                    if let Err(error) =
                        finish_contact_attempt(&config, &mut admission, outcome, now, &mut schedule)
                    {
                        break Err(error);
                    }
                    if mode.is_automatic()
                        && selector_ready
                        && admission.selected_candidate(now).is_none()
                    {
                        signals.publish_selector_unavailable()?;
                        selector_ready = false;
                        outbound_candidate_pending = false;
                    }
                    contact_phase = ContactPhase::accepting(sockets.clone(), listener.clone());
                }
                EpochEvent::ScanDeadline => {
                    if let Err(error) = stop_active_scan(&mut scan_phase, &mut admission).await {
                        break Err(error);
                    }
                }
                EpochEvent::ScanIdleDeadline => {
                    let started_scan = match await_owned_discovery_start(
                        discovery.as_ref(),
                        expires_at,
                        config.open_timeout(),
                        &cancellation,
                        discovery.start_scan(config.controller()),
                        |started| async move {
                            let (mut owner, _) = started.into_parts();
                            stop_scan(owner.as_mut()).await
                        },
                    )
                    .await
                    {
                        Ok(started) => started,
                        Err(error) => break Err(error),
                    };
                    if lifecycle_now() >= expires_at {
                        let (mut owner, _) = started_scan.into_parts();
                        if let Err(error) = stop_scan(owner.as_mut()).await {
                            break Err(owned_cleanup_unconfirmed(error));
                        }
                        break Err(SupervisorError::Controller(DriverErrorKind::Unavailable));
                    }
                    let (owner, observations) = started_scan.into_parts();
                    let now = lifecycle_now();
                    let scan_start = admission.start_scan(now);
                    debug_assert_eq!(scan_start, crate::ScanStartOutcome::Started);
                    scan_phase = ScanPhase::Active {
                        scan: ActiveScan {
                            owner,
                            observations,
                        },
                        deadline: tokio::time::Instant::now() + SCAN_ACTIVE_INTERVAL,
                    };
                }
            }
        };
    }

    let contact_termination = if matches!(result, Err(SupervisorError::Controller(_))) {
        EpochContactTermination::LocalEpochLoss
    } else {
        EpochContactTermination::Cancelled
    };
    if result.is_err()
        && let Err(error) = signals.publish(crate::BtleAvailability::Unavailable(
            crate::AvailabilityReason::BluezUnavailable,
        ))
    {
        result = Err(error);
    }
    if result.is_err() && owner_loss_required {
        discovery.force_owner_loss();
    }
    contact_phase.cancel();
    let contact_join = contact_phase.join();
    let scan_cleanup = async move {
        match scan_phase {
            ScanPhase::Active { mut scan, .. } => stop_scan(scan.owner.as_mut()).await,
            ScanPhase::Idle { .. } => Ok(()),
        }
    };
    let advertisement_cleanup = async move {
        match advertisement {
            Some(mut advertisement) => release_advertisement(advertisement.as_mut()).await,
            None => Ok(()),
        }
    };
    let (contact_outcome, scan_stop, advertisement_release) =
        tokio::join!(contact_join, scan_cleanup, advertisement_cleanup);
    complete_interrupted_contact(contact_outcome, contact_termination);
    drop(listener);
    if scan_stop.is_err() || advertisement_release.is_err() {
        discovery.force_owner_loss();
        return Err(SupervisorError::PlatformCleanupUnconfirmed);
    }
    result?;
    Ok(())
}

struct OutboundSchedule<'a> {
    delay: &'a mut OutboundDelay,
    candidate_pending: &'a mut bool,
    backoff: &'a mut CappedBackoff,
    self_schedule: bool,
}

fn finish_contact_attempt(
    config: &ValidatedRosteredSupervisorConfig,
    admission: &mut DiscoveryAdmission,
    outcome: ContactAttemptOutcome,
    now: Instant,
    schedule: &mut OutboundSchedule<'_>,
) -> Result<(), SupervisorError> {
    match outcome {
        ContactAttemptOutcome::Opened { .. } => {
            unreachable!("opened contact is handled in the epoch")
        }
        ContactAttemptOutcome::AutomaticCarrierReleased => {}
        ContactAttemptOutcome::OpenFailed(failure) => {
            let ContactOpenFailure {
                candidate,
                error,
                owner,
            } = *failure;
            if error.kind() == DriverErrorKind::Configuration {
                if let OutboundAttemptOwner::Automatic(request) = owner {
                    request.complete_error(error);
                }
                return Err(SupervisorError::Configuration);
            }
            if error.kind() == DriverErrorKind::Cancelled {
                if let OutboundAttemptOwner::Automatic(request) = owner {
                    request.complete_error(error);
                }
                return Ok(());
            }
            admission.invalidate_after_open_failure(candidate, now);
            match owner {
                OutboundAttemptOwner::FixedEvaluation => {
                    if schedule.self_schedule && config.role() == FixedRole::Initiator {
                        *schedule.candidate_pending = admission.selected_candidate(now).is_some();
                        if *schedule.candidate_pending {
                            *schedule.delay =
                                OutboundDelay::PeerRetryUntil(now + schedule.backoff.next_delay());
                        }
                    }
                }
                OutboundAttemptOwner::Automatic(request) => {
                    *schedule.candidate_pending = false;
                    request.complete_error(error);
                }
            }
        }
        ContactAttemptOutcome::Cancelled => {}
        ContactAttemptOutcome::Completed(result) => match *result {
            Ok(_receipt) => {
                if schedule.self_schedule && config.role() == FixedRole::Initiator {
                    schedule.backoff.reset();
                    *schedule.candidate_pending = admission.selected_candidate(now).is_some();
                    *schedule.delay = OutboundDelay::CadenceUntil(now + config.contact_cadence());
                }
            }
            Err(outcome) if outcome.reason() == ContactReason::AdmissionClosed => {
                return Err(SupervisorError::AdmissionClosed);
            }
            Err(outcome) if outcome.reason() == ContactReason::ActorUnavailable => {
                return Err(SupervisorError::ActorUnavailable);
            }
            Err(outcome) if outcome.reason() == ContactReason::ActorStopped => {
                return Err(SupervisorError::ActorStopped);
            }
            Err(outcome) => finish_contact_disposition(
                config,
                admission,
                outcome.disposition(),
                outcome.reason(),
                now,
                schedule,
            )?,
        },
    }
    Ok(())
}

fn finish_contact_disposition(
    config: &ValidatedRosteredSupervisorConfig,
    admission: &mut DiscoveryAdmission,
    disposition: ContactDisposition,
    reason: ContactReason,
    now: Instant,
    schedule: &mut OutboundSchedule<'_>,
) -> Result<(), SupervisorError> {
    match contact_schedule_effect(disposition) {
        ContactScheduleEffect::RetryLater => {
            if schedule.self_schedule && config.role() == FixedRole::Initiator {
                *schedule.candidate_pending = admission.selected_candidate(now).is_some();
                if *schedule.candidate_pending {
                    *schedule.delay =
                        OutboundDelay::PeerRetryUntil(now + schedule.backoff.next_delay());
                }
            }
            Ok(())
        }
        ContactScheduleEffect::Reselect => {
            if schedule.self_schedule && config.role() == FixedRole::Initiator {
                *schedule.candidate_pending = admission.selected_candidate(now).is_some();
                *schedule.delay = OutboundDelay::Ready;
            }
            Ok(())
        }
        ContactScheduleEffect::Suppress => Err(SupervisorError::ContactSuppressed(reason)),
        ContactScheduleEffect::Cancelled => Ok(()),
        ContactScheduleEffect::Terminal => Err(SupervisorError::ContactTerminal(reason)),
    }
}

async fn begin_outbound_contact<S>(
    config: &Arc<ValidatedRosteredSupervisorConfig>,
    sockets: &Arc<S>,
    admission: &mut DiscoveryAdmission,
    scan_phase: &mut ScanPhase,
    candidate_pending: &mut bool,
    outbound_delay: &mut OutboundDelay,
    mode: &mut EpochContactMode,
) -> Result<Option<ContactPhase>, SupervisorError>
where
    S: RosteredSocketFactory + 'static,
{
    let now = lifecycle_now();
    if !mode.can_open_outbound(config)
        || now >= config.epoch_discovery_credentials().expires_at()
        || now < outbound_delay.deadline(now)
    {
        return Ok(None);
    }
    let Some(candidate) = admission.selected_candidate(now) else {
        *candidate_pending = false;
        return Ok(None);
    };
    if !admission.try_consume_attempt(AttemptKind::OutboundOpen, now) {
        *outbound_delay = OutboundDelay::TokenRefillUntil(
            admission.attempt_retry_at(AttemptKind::OutboundOpen, now),
        );
        return Ok(None);
    }
    stop_active_scan(scan_phase, admission).await?;
    admission.enter_authenticated_contact(now);
    *candidate_pending = false;
    *outbound_delay = OutboundDelay::Ready;
    let owner = mode.take_outbound();
    Ok(Some(ContactPhase::opening(
        config.clone(),
        sockets.clone(),
        candidate,
        owner,
    )))
}

fn idle_scan_phase() -> ScanPhase {
    ScanPhase::Idle {
        deadline: tokio::time::Instant::now() + SCAN_IDLE_INTERVAL,
    }
}

async fn stop_active_scan(
    phase: &mut ScanPhase,
    admission: &mut DiscoveryAdmission,
) -> Result<(), SupervisorError> {
    let now = lifecycle_now();
    let idle = ScanPhase::Idle {
        deadline: tokio::time::Instant::now() + SCAN_IDLE_INTERVAL,
    };
    let ScanPhase::Active { mut scan, .. } = std::mem::replace(phase, idle) else {
        return Ok(());
    };
    let result = stop_scan(scan.owner.as_mut()).await;
    admission.stop_scan(now);
    result.map_err(owned_cleanup_unconfirmed)
}

fn owned_cleanup_unconfirmed(_: DriverError) -> SupervisorError {
    SupervisorError::PlatformCleanupUnconfirmed
}

fn finish_ended_scan(phase: &mut ScanPhase, admission: &mut DiscoveryAdmission) {
    let idle = ScanPhase::Idle {
        deadline: tokio::time::Instant::now() + SCAN_IDLE_INTERVAL,
    };
    let previous = std::mem::replace(phase, idle);
    debug_assert!(matches!(previous, ScanPhase::Active { .. }));
    admission.callback_queue_overflow(lifecycle_now());
}

fn lifecycle_now() -> Instant {
    tokio::time::Instant::now().into_std()
}

enum InboundContactAdmission {
    Admitted,
    Rejected,
    BackoffUntil(Instant),
}

fn admit_inbound_contact(
    config: &ValidatedRosteredSupervisorConfig,
    admission: &mut DiscoveryAdmission,
    locator: crate::CanonicalLocator,
    now: Instant,
    mode: &EpochContactMode,
) -> InboundContactAdmission {
    if admission.candidate(locator, now).is_none()
        || !mode.accepts_inbound(config)
        || now >= config.epoch_discovery_credentials().expires_at()
    {
        return InboundContactAdmission::Rejected;
    }
    if !admission.try_consume_attempt(AttemptKind::InboundAccept, now) {
        return InboundContactAdmission::BackoffUntil(
            admission.attempt_retry_at(AttemptKind::InboundAccept, now),
        );
    }
    if !mode.is_automatic() && !admission.try_consume_attempt(AttemptKind::MissionHandshake, now) {
        return InboundContactAdmission::BackoffUntil(
            admission.attempt_retry_at(AttemptKind::MissionHandshake, now),
        );
    }
    InboundContactAdmission::Admitted
}

async fn open_candidate<S>(
    config: &ValidatedRosteredSupervisorConfig,
    sockets: &S,
    candidate: DiscoveryCandidate,
    cancellation: &LifecycleCancellation,
) -> Result<OpenedContact, DriverError>
where
    S: RosteredSocketFactory,
{
    let connect = sockets.connect(
        config.controller(),
        candidate.locator(),
        candidate.listener_psm(),
    );
    let opened = tokio::select! {
        biased;
        () = cancellation.cancelled() => Err(DriverError::new(
            DriverErrorKind::Cancelled,
            "rostered contact open was cancelled",
        )),
        result = timeout(config.open_timeout(), connect) => match result {
            Ok(result) => result,
            Err(_) => Err(DriverError::new(
                DriverErrorKind::Timeout,
                "rostered contact open exceeded its deadline",
            )),
        }
    }?;
    opened_rostered_contact(config, candidate.locator(), opened)
}

async fn run_opened_contact(
    contacts: &dyn ContactAdmission,
    peer_mission_id: NodeId,
    role: OrderedEventContactRole,
    opened: OpenedContact,
    cancellation: &LifecycleCancellation,
) -> ContactAttemptOutcome {
    let contact: Arc<dyn OrderedContact> = opened.into_contact();
    let peer = MissionPeerExpectation::new(contact.peer_evidence(), peer_mission_id);
    let mut admission = contacts.run(role, contact.clone(), peer);
    let completion = tokio::select! {
        biased;
        () = cancellation.cancelled() => {
            contact.close();
            let _ = timeout(CONTACT_DRAIN_DEADLINE, &mut admission).await;
            ContactAttemptOutcome::Cancelled
        }
        result = &mut admission => {
            contact.close();
            ContactAttemptOutcome::Completed(Box::new(result))
        }
    };
    drop(admission);
    drop(contact);
    completion
}

async fn release_advertisement(
    owner: &mut dyn crate::platform::discovery::OwnedAdvertisement,
) -> Result<(), DriverError> {
    let terminated = owner.terminated();
    let release = owner.release();
    stop_with_barrier(
        release,
        terminated,
        "owned roster advertisement release timed out",
    )
    .await
}

async fn stop_scan(
    owner: &mut dyn crate::platform::discovery::OwnedScan,
) -> Result<(), DriverError> {
    let termination = owner.termination();
    let terminated: TerminationFuture<'static> = Box::pin(async move {
        let _ = termination.await;
    });
    let stop = owner.stop();
    stop_with_barrier(stop, terminated, "owned roster scan stop timed out").await
}

async fn stop_with_barrier(
    mut stop: PlatformFuture<'_, ()>,
    mut terminated: TerminationFuture<'static>,
    timeout_message: &'static str,
) -> Result<(), DriverError> {
    let stopped = async {
        tokio::select! {
            result = stop.as_mut() => result,
            () = terminated.as_mut() => Ok(()),
        }
    };
    match timeout(OWNED_STOP_DEADLINE, stopped).await {
        Ok(result) => result,
        Err(_) => Err(DriverError::new(
            DriverErrorKind::Transport,
            timeout_message,
        )),
    }
}

fn encode_advertisement(
    config: &ValidatedRosteredSupervisorConfig,
    listener_psm: u16,
    nonces: &dyn DiscoveryNonceSource,
) -> Result<RosterAdvertisement, DriverError> {
    AsterRosterBeaconV1::encode(
        listener_psm,
        nonces.next_nonce()?,
        config.epoch_discovery_credentials(),
        lifecycle_now(),
    )
    .map(RosterAdvertisement::new)
    .map_err(|error| {
        if error == DiscoveryRecordError::CredentialExpired {
            DriverError::new(
                DriverErrorKind::Unavailable,
                "rostered discovery credential lease expired",
            )
        } else {
            DriverError::new(
                DriverErrorKind::Configuration,
                "roster advertisement could not be encoded",
            )
        }
    })
}

fn admit_platform_observation(
    admission: &mut DiscoveryAdmission,
    config: &ValidatedRosteredSupervisorConfig,
    observation: DiscoveryObservation,
    now: Instant,
) -> ObservationOutcome {
    admission.observe(
        observation.locator(),
        observation.record(),
        config.epoch_discovery_credentials(),
        now,
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        AutomaticRosteredSupervisorConfig, ContactLimits, ControllerAdmissionPolicy,
        ControllerConfig, ControllerProbeLimits, DiscoveryCredential, DiscoveryGeneration,
        DiscoverySecret, LeasedDiscoveryCredentialSet, RING1_MAXIMUM_EXCHANGE_BYTES,
        RING1_MAXIMUM_FRAME_BYTES, RosteredAdapterConfig, RosteredDiscoveryConfig,
        RosteredSupervisorConfig, ValidatedControllerConfig, ValidatedRosteredSupervisorConfig,
        platform::{
            discovery::{
                DiscoveryPlatform, OwnedAdvertisement, OwnedScan, PlatformFuture,
                RosterAdvertisement, ScanTerminationFuture, StartedScan, TerminationFuture,
            },
            socket::{BoundRosteredListener, RosteredBindFuture, RosteredSocketFactory},
        },
        policy::LifecycleCancellation,
        stream::SocketOpen,
    };
    use aster_contact::OrderedContact;
    use aster_node::{
        ContactOutcome, MissionPeerExpectation, OrderedEventContactRole, PeerReceipt,
    };
    use bluer::{Address, AddressType};
    use std::{
        collections::VecDeque,
        future::pending,
        sync::{
            Arc, Mutex,
            atomic::{AtomicU8, Ordering},
        },
        time::{Duration, Instant},
    };
    use tokio::sync::{Notify, mpsc, oneshot};

    fn config() -> ValidatedRosteredSupervisorConfig {
        config_with_ids([0x11; 32], [0x22; 32])
    }

    fn config_with_ids(
        local_mission_id: [u8; 32],
        peer_mission_id: [u8; 32],
    ) -> ValidatedRosteredSupervisorConfig {
        config_with_ids_and_lease(local_mission_id, peer_mission_id, Duration::from_secs(60))
    }

    fn config_with_ids_and_lease(
        local_mission_id: [u8; 32],
        peer_mission_id: [u8; 32],
        lease: Duration,
    ) -> ValidatedRosteredSupervisorConfig {
        let credentials = LeasedDiscoveryCredentialSet::new(
            DiscoveryCredential::new(
                DiscoveryGeneration::new(7).unwrap(),
                DiscoverySecret::new([0x42; 32]).unwrap(),
            ),
            None,
            Instant::now() + lease,
        )
        .unwrap();
        RosteredAdapterConfig::Enabled(Box::new(RosteredSupervisorConfig {
            controller: ControllerConfig {
                adapter_name: "hci7".to_owned(),
                local_address: Address::new([2, 0, 0, 0, 0, 1]),
                local_address_type: AddressType::LeRandom,
            },
            discovery: RosteredDiscoveryConfig { credentials },
            local_mission_id,
            peer_mission_id,
            contact_cadence: Duration::from_secs(60),
            contact_limits: ContactLimits {
                maximum_frame_bytes: RING1_MAXIMUM_FRAME_BYTES,
                maximum_exchange_bytes: RING1_MAXIMUM_EXCHANGE_BYTES,
                open_timeout: Duration::from_secs(5),
                operation_timeout: Duration::from_secs(30),
            },
        }))
        .validate()
        .unwrap()
        .unwrap()
    }

    fn automatic_config() -> ValidatedAutomaticRosteredSupervisorConfig {
        let credentials = LeasedDiscoveryCredentialSet::new(
            DiscoveryCredential::new(
                DiscoveryGeneration::new(7).unwrap(),
                DiscoverySecret::new([0x42; 32]).unwrap(),
            ),
            None,
            Instant::now() + Duration::from_secs(60),
        )
        .unwrap();
        AutomaticRosteredSupervisorConfig {
            controller_policy: ControllerAdmissionPolicy::default(),
            controller_probe_limits: ControllerProbeLimits::new(
                Duration::from_secs(1),
                Duration::from_secs(2),
                Duration::from_secs(3),
            ),
            discovery: RosteredDiscoveryConfig { credentials },
            role: FixedRole::Initiator,
            contact_limits: ContactLimits {
                maximum_frame_bytes: RING1_MAXIMUM_FRAME_BYTES,
                maximum_exchange_bytes: RING1_MAXIMUM_EXCHANGE_BYTES,
                open_timeout: Duration::from_secs(5),
                operation_timeout: Duration::from_secs(30),
            },
        }
        .validate()
        .unwrap()
    }

    #[tokio::test]
    async fn automatic_listener_rejects_outbound_request_without_opening() {
        let (backend, port) = crate::automatic_carrier::automatic_btle_carrier_channel(
            crate::BtleAvailability::Unavailable(crate::AvailabilityReason::Activating),
        );
        let (_, outbound, _) = port.into_parts();
        let opened =
            tokio::spawn(async move { outbound.open(crate::OpenCancellation::new()).await });
        let mut mode = EpochContactMode::automatic(backend);

        let AutomaticCarrierRequestEvent::Received(Some(request)) =
            mode.next_automatic_carrier_event().await
        else {
            panic!("automatic carrier request must reach the Linux owner");
        };
        let listener = config_with_ids([0x22; 32], [0x11; 32]);
        assert_eq!(listener.role(), FixedRole::Listener);
        assert!(!mode.accept_carrier_request(&listener, request));

        let Err(error) = opened.await.unwrap() else {
            panic!("listener must reject an outbound carrier request");
        };
        assert_eq!(error.kind(), DriverErrorKind::Unavailable);
    }

    #[test]
    fn automatic_inbound_does_not_consume_mission_handshake_budget() {
        let config = config();
        let now = Instant::now();
        let locator = crate::CanonicalLocator::new(
            Address::new([2, 0, 0, 0, 0, 0x75]),
            AddressType::LeRandom,
        )
        .unwrap();
        let record =
            AsterRosterBeaconV1::encode(0x0083, [0x35; 16], config.discovery_credentials(), now)
                .unwrap();
        let mut admission = DiscoveryAdmission::new();
        assert_eq!(admission.start_scan(now), crate::ScanStartOutcome::Started);
        assert_eq!(
            admission.observe(locator, &record, config.discovery_credentials(), now,),
            ObservationOutcome::Accepted
        );
        for _ in 0..4 {
            assert!(admission.try_consume_attempt(AttemptKind::MissionHandshake, now));
        }
        assert!(!admission.try_consume_attempt(AttemptKind::MissionHandshake, now));
        let (backend, _port) = crate::automatic_carrier::automatic_btle_carrier_channel(
            crate::BtleAvailability::Unavailable(crate::AvailabilityReason::Activating),
        );
        let mode = EpochContactMode::automatic(backend);

        assert!(matches!(
            admit_inbound_contact(&config, &mut admission, locator, now, &mode),
            InboundContactAdmission::Admitted
        ));
    }

    struct FakeOwner {
        stop_event: &'static str,
        events: Arc<Mutex<Vec<&'static str>>>,
    }

    impl FakeOwner {
        fn stop(&mut self) -> PlatformFuture<'_, ()> {
            Box::pin(async {
                self.events.lock().unwrap().push(self.stop_event);
                Ok(())
            })
        }

        fn terminated(&self) -> TerminationFuture<'static> {
            Box::pin(pending())
        }
    }

    impl OwnedAdvertisement for FakeOwner {
        fn release(&mut self) -> PlatformFuture<'_, ()> {
            FakeOwner::stop(self)
        }

        fn terminated(&self) -> TerminationFuture<'static> {
            FakeOwner::terminated(self)
        }
    }

    impl OwnedScan for FakeOwner {
        fn stop(&mut self) -> PlatformFuture<'_, ()> {
            FakeOwner::stop(self)
        }

        fn termination(&self) -> ScanTerminationFuture<'static> {
            Box::pin(pending())
        }
    }

    struct FakeDiscovery {
        events: Arc<Mutex<Vec<&'static str>>>,
        advertisements: Arc<Mutex<Vec<RosterAdvertisement>>>,
        scan_started: Arc<Notify>,
        observation_sender:
            Mutex<Option<mpsc::Sender<crate::platform::discovery::DiscoveryObservation>>>,
    }

    impl DiscoveryPlatform for FakeDiscovery {
        fn start_advertisement<'a>(
            &'a self,
            _controller: &'a ValidatedControllerConfig,
            _advertisement: RosterAdvertisement,
        ) -> PlatformFuture<'a, Box<dyn OwnedAdvertisement>> {
            self.events.lock().unwrap().push("advertise");
            self.advertisements.lock().unwrap().push(_advertisement);
            let owner = FakeOwner {
                stop_event: "advertisement-release",
                events: self.events.clone(),
            };
            Box::pin(async move { Ok(Box::new(owner) as Box<dyn OwnedAdvertisement>) })
        }

        fn start_scan<'a>(
            &'a self,
            _controller: &'a ValidatedControllerConfig,
        ) -> PlatformFuture<'a, StartedScan> {
            self.events.lock().unwrap().push("scan");
            let (sender, observations) = mpsc::channel(1);
            *self.observation_sender.lock().unwrap() = Some(sender);
            self.scan_started.notify_one();
            let owner = FakeOwner {
                stop_event: "scan-stop",
                events: self.events.clone(),
            };
            Box::pin(async move {
                Ok(StartedScan::new(
                    Box::new(owner) as Box<dyn OwnedScan>,
                    observations,
                ))
            })
        }
    }

    struct FakeSockets {
        events: Arc<Mutex<Vec<&'static str>>>,
    }

    struct PendingBindSockets {
        started: Arc<Notify>,
    }

    struct ConnectingSockets {
        connected: Mutex<Vec<(crate::CanonicalLocator, u16)>>,
    }

    struct FailingConnectSockets {
        connected: AtomicU8,
        kind: DriverErrorKind,
    }

    struct RecordingAdmission {
        roles: Mutex<Vec<OrderedEventContactRole>>,
        peers: Mutex<Vec<[u8; 32]>>,
    }

    fn recording_admission() -> Arc<RecordingAdmission> {
        Arc::new(RecordingAdmission {
            roles: Mutex::new(Vec::new()),
            peers: Mutex::new(Vec::new()),
        })
    }

    struct DrainingAdmission {
        started: Arc<Notify>,
        drained: Arc<AtomicU8>,
    }

    struct PendingAdmission {
        started: Arc<Notify>,
    }

    struct NotifyingAdmission {
        roles: Mutex<Vec<OrderedEventContactRole>>,
        peers: Mutex<Vec<[u8; 32]>>,
        admitted: Notify,
    }

    type AcceptedContact = Result<(AcceptedSocket, crate::CanonicalLocator), DriverError>;

    struct InboundSockets {
        accepted: tokio::sync::Mutex<mpsc::Receiver<AcceptedContact>>,
        connected: AtomicU8,
    }

    impl crate::lifecycle::ContactAdmission for RecordingAdmission {
        fn run(
            &self,
            role: OrderedEventContactRole,
            _contact: Arc<dyn OrderedContact>,
            peer: MissionPeerExpectation,
        ) -> crate::lifecycle::ContactAdmissionFuture {
            self.roles.lock().unwrap().push(role);
            self.peers.lock().unwrap().push(peer.mission_id());
            Box::pin(async { Ok(PeerReceipt::default()) })
        }
    }

    impl crate::lifecycle::ContactAdmission for DrainingAdmission {
        fn run(
            &self,
            _role: OrderedEventContactRole,
            contact: Arc<dyn OrderedContact>,
            _peer: MissionPeerExpectation,
        ) -> crate::lifecycle::ContactAdmissionFuture {
            let started = self.started.clone();
            let drained = self.drained.clone();
            Box::pin(async move {
                started.notify_one();
                let result = contact.finish_as_initiator().await;
                drained.store(1, Ordering::SeqCst);
                result
                    .map(|()| PeerReceipt::default())
                    .map_err(|_| ContactOutcome::admission_busy())
            })
        }
    }

    impl crate::lifecycle::ContactAdmission for PendingAdmission {
        fn run(
            &self,
            _role: OrderedEventContactRole,
            _contact: Arc<dyn OrderedContact>,
            _peer: MissionPeerExpectation,
        ) -> crate::lifecycle::ContactAdmissionFuture {
            let started = self.started.clone();
            Box::pin(async move {
                started.notify_one();
                pending().await
            })
        }
    }

    impl crate::lifecycle::ContactAdmission for NotifyingAdmission {
        fn run(
            &self,
            role: OrderedEventContactRole,
            _contact: Arc<dyn OrderedContact>,
            peer: MissionPeerExpectation,
        ) -> crate::lifecycle::ContactAdmissionFuture {
            self.roles.lock().unwrap().push(role);
            self.peers.lock().unwrap().push(peer.mission_id());
            self.admitted.notify_one();
            Box::pin(async { Ok(PeerReceipt::default()) })
        }
    }

    impl RosteredSocketFactory for InboundSockets {
        type Listener = ();

        fn bind_dynamic_listener<'a>(
            &'a self,
            _controller: &'a ValidatedControllerConfig,
        ) -> RosteredBindFuture<'a, Self::Listener> {
            Box::pin(async { BoundRosteredListener::new((), 0x0081) })
        }

        fn connect<'a>(
            &'a self,
            _controller: &'a ValidatedControllerConfig,
            _locator: crate::CanonicalLocator,
            _advertised_psm: u16,
        ) -> crate::OpenFuture<'a> {
            self.connected.fetch_add(1, Ordering::AcqRel);
            Box::pin(pending())
        }

        fn accept<'a>(
            &'a self,
            _listener: &'a Self::Listener,
        ) -> crate::platform::socket::RosteredAcceptFuture<'a> {
            Box::pin(async move {
                match self.accepted.lock().await.recv().await {
                    Some(accepted) => accepted,
                    None => pending().await,
                }
            })
        }
    }

    impl RosteredSocketFactory for PendingBindSockets {
        type Listener = ();

        fn bind_dynamic_listener<'a>(
            &'a self,
            _controller: &'a ValidatedControllerConfig,
        ) -> RosteredBindFuture<'a, Self::Listener> {
            self.started.notify_one();
            Box::pin(pending())
        }

        fn connect<'a>(
            &'a self,
            _controller: &'a ValidatedControllerConfig,
            _locator: crate::CanonicalLocator,
            _advertised_psm: u16,
        ) -> crate::OpenFuture<'a> {
            unreachable!("listener bind never completes")
        }

        fn accept<'a>(
            &'a self,
            _listener: &'a Self::Listener,
        ) -> crate::platform::socket::RosteredAcceptFuture<'a> {
            unreachable!("listener bind never completes")
        }
    }

    impl RosteredSocketFactory for ConnectingSockets {
        type Listener = ();

        fn bind_dynamic_listener<'a>(
            &'a self,
            _controller: &'a ValidatedControllerConfig,
        ) -> RosteredBindFuture<'a, Self::Listener> {
            Box::pin(async { BoundRosteredListener::new((), 0x0081) })
        }

        fn connect<'a>(
            &'a self,
            _controller: &'a ValidatedControllerConfig,
            locator: crate::CanonicalLocator,
            advertised_psm: u16,
        ) -> crate::OpenFuture<'a> {
            self.connected
                .lock()
                .unwrap()
                .push((locator, advertised_psm));
            Box::pin(async {
                let (stream, _peer) = tokio::io::duplex(4096);
                SocketOpen::with_observed_mtu(Box::new(stream), 128, 96)
            })
        }

        fn accept<'a>(
            &'a self,
            _listener: &'a Self::Listener,
        ) -> crate::platform::socket::RosteredAcceptFuture<'a> {
            Box::pin(pending())
        }
    }

    impl RosteredSocketFactory for FailingConnectSockets {
        type Listener = ();

        fn bind_dynamic_listener<'a>(
            &'a self,
            _controller: &'a ValidatedControllerConfig,
        ) -> RosteredBindFuture<'a, Self::Listener> {
            Box::pin(async { BoundRosteredListener::new((), 0x0081) })
        }

        fn connect<'a>(
            &'a self,
            _controller: &'a ValidatedControllerConfig,
            _locator: crate::CanonicalLocator,
            _advertised_psm: u16,
        ) -> crate::OpenFuture<'a> {
            self.connected.fetch_add(1, Ordering::AcqRel);
            let kind = self.kind;
            Box::pin(async move { Err(DriverError::new(kind, "test connect failure")) })
        }

        fn accept<'a>(
            &'a self,
            _listener: &'a Self::Listener,
        ) -> crate::platform::socket::RosteredAcceptFuture<'a> {
            Box::pin(pending())
        }
    }

    struct FailingScanDiscovery {
        events: Arc<Mutex<Vec<&'static str>>>,
    }

    struct GatedScanDiscovery {
        events: Arc<Mutex<Vec<&'static str>>>,
        scan_entered: Arc<Notify>,
        allow_scan: Arc<Notify>,
        observation_sender: Mutex<Option<mpsc::Sender<DiscoveryObservation>>>,
    }

    struct PendingAdvertisementDiscovery {
        started: Arc<Notify>,
        owner_loss_forced: Arc<AtomicU8>,
    }

    struct PendingScanDiscovery {
        scan_started: Arc<Notify>,
        owner_loss_forced: Arc<AtomicU8>,
        events: Arc<Mutex<Vec<&'static str>>>,
    }

    struct OneScanThenPendingDiscovery {
        starts: AtomicU8,
        restart_started: Arc<Notify>,
        owner_loss_forced: Arc<AtomicU8>,
        events: Arc<Mutex<Vec<&'static str>>>,
        observation_sender: Mutex<Option<mpsc::Sender<DiscoveryObservation>>>,
    }

    impl DiscoveryPlatform for PendingAdvertisementDiscovery {
        fn start_advertisement<'a>(
            &'a self,
            _controller: &'a ValidatedControllerConfig,
            _advertisement: RosterAdvertisement,
        ) -> PlatformFuture<'a, Box<dyn OwnedAdvertisement>> {
            self.started.notify_one();
            Box::pin(pending())
        }

        fn start_scan<'a>(
            &'a self,
            _controller: &'a ValidatedControllerConfig,
        ) -> PlatformFuture<'a, StartedScan> {
            unreachable!("expired advertisement registration never starts scanning")
        }

        fn force_owner_loss(&self) {
            self.owner_loss_forced.store(1, Ordering::Release);
        }
    }

    impl DiscoveryPlatform for PendingScanDiscovery {
        fn start_advertisement<'a>(
            &'a self,
            _controller: &'a ValidatedControllerConfig,
            _advertisement: RosterAdvertisement,
        ) -> PlatformFuture<'a, Box<dyn OwnedAdvertisement>> {
            let owner = FakeOwner {
                stop_event: "advertisement-release",
                events: self.events.clone(),
            };
            Box::pin(async move { Ok(Box::new(owner) as Box<dyn OwnedAdvertisement>) })
        }

        fn start_scan<'a>(
            &'a self,
            _controller: &'a ValidatedControllerConfig,
        ) -> PlatformFuture<'a, StartedScan> {
            self.scan_started.notify_one();
            Box::pin(pending())
        }

        fn force_owner_loss(&self) {
            self.owner_loss_forced.store(1, Ordering::Release);
        }
    }

    impl DiscoveryPlatform for OneScanThenPendingDiscovery {
        fn start_advertisement<'a>(
            &'a self,
            _controller: &'a ValidatedControllerConfig,
            _advertisement: RosterAdvertisement,
        ) -> PlatformFuture<'a, Box<dyn OwnedAdvertisement>> {
            let owner = FakeOwner {
                stop_event: "advertisement-release",
                events: self.events.clone(),
            };
            Box::pin(async move { Ok(Box::new(owner) as Box<dyn OwnedAdvertisement>) })
        }

        fn start_scan<'a>(
            &'a self,
            _controller: &'a ValidatedControllerConfig,
        ) -> PlatformFuture<'a, StartedScan> {
            if self.starts.fetch_add(1, Ordering::AcqRel) > 0 {
                self.restart_started.notify_one();
                return Box::pin(pending());
            }
            let (sender, observations) = mpsc::channel(1);
            *self.observation_sender.lock().unwrap() = Some(sender);
            let owner = FakeOwner {
                stop_event: "scan-stop",
                events: self.events.clone(),
            };
            Box::pin(async move { Ok(StartedScan::new(Box::new(owner), observations)) })
        }

        fn force_owner_loss(&self) {
            self.owner_loss_forced.store(1, Ordering::Release);
        }
    }

    impl DiscoveryPlatform for FailingScanDiscovery {
        fn start_advertisement<'a>(
            &'a self,
            _controller: &'a ValidatedControllerConfig,
            _advertisement: RosterAdvertisement,
        ) -> PlatformFuture<'a, Box<dyn OwnedAdvertisement>> {
            self.events.lock().unwrap().push("advertise");
            let owner = FakeOwner {
                stop_event: "advertisement-release",
                events: self.events.clone(),
            };
            Box::pin(async move { Ok(Box::new(owner) as Box<dyn OwnedAdvertisement>) })
        }

        fn start_scan<'a>(
            &'a self,
            _controller: &'a ValidatedControllerConfig,
        ) -> PlatformFuture<'a, StartedScan> {
            self.events.lock().unwrap().push("scan-failed");
            Box::pin(async {
                Err(DriverError::new(
                    DriverErrorKind::Unavailable,
                    "test scan unavailable",
                ))
            })
        }
    }

    impl DiscoveryPlatform for GatedScanDiscovery {
        fn start_advertisement<'a>(
            &'a self,
            _controller: &'a ValidatedControllerConfig,
            _advertisement: RosterAdvertisement,
        ) -> PlatformFuture<'a, Box<dyn OwnedAdvertisement>> {
            let owner = FakeOwner {
                stop_event: "advertisement-release",
                events: self.events.clone(),
            };
            self.events.lock().unwrap().push("advertise");
            Box::pin(async move { Ok(Box::new(owner) as Box<dyn OwnedAdvertisement>) })
        }

        fn start_scan<'a>(
            &'a self,
            _controller: &'a ValidatedControllerConfig,
        ) -> PlatformFuture<'a, StartedScan> {
            self.events.lock().unwrap().push("scan-starting");
            self.scan_entered.notify_one();
            let allow_scan = self.allow_scan.clone();
            let events = self.events.clone();
            Box::pin(async move {
                allow_scan.notified().await;
                let (sender, observations) = mpsc::channel(1);
                *self.observation_sender.lock().unwrap() = Some(sender);
                Ok(StartedScan::new(
                    Box::new(FakeOwner {
                        stop_event: "scan-stop",
                        events,
                    }),
                    observations,
                ))
            })
        }
    }

    struct BlockingAdvertisementOwner {
        events: Arc<Mutex<Vec<&'static str>>>,
        release_completed: Option<Arc<Notify>>,
        terminated: Arc<Notify>,
    }

    impl OwnedAdvertisement for BlockingAdvertisementOwner {
        fn release(&mut self) -> PlatformFuture<'_, ()> {
            Box::pin(async {
                self.events
                    .lock()
                    .unwrap()
                    .push("advertisement-release-started");
                match &self.release_completed {
                    Some(released) => {
                        released.notified().await;
                        Ok(())
                    }
                    None => pending().await,
                }
            })
        }

        fn terminated(&self) -> TerminationFuture<'static> {
            let terminated = self.terminated.clone();
            Box::pin(async move { terminated.notified().await })
        }
    }

    struct BarrierDiscovery {
        events: Arc<Mutex<Vec<&'static str>>>,
        advertisement_release_completed: Option<Arc<Notify>>,
        advertisement_terminated: Arc<Notify>,
        scan_started: Arc<Notify>,
        owner_loss_forced: Arc<AtomicU8>,
        observation_sender: Mutex<Option<mpsc::Sender<DiscoveryObservation>>>,
    }

    impl DiscoveryPlatform for BarrierDiscovery {
        fn start_advertisement<'a>(
            &'a self,
            _controller: &'a ValidatedControllerConfig,
            _advertisement: RosterAdvertisement,
        ) -> PlatformFuture<'a, Box<dyn OwnedAdvertisement>> {
            self.events.lock().unwrap().push("advertise");
            let owner = BlockingAdvertisementOwner {
                events: self.events.clone(),
                release_completed: self.advertisement_release_completed.clone(),
                terminated: self.advertisement_terminated.clone(),
            };
            Box::pin(async move { Ok(Box::new(owner) as Box<dyn OwnedAdvertisement>) })
        }

        fn start_scan<'a>(
            &'a self,
            _controller: &'a ValidatedControllerConfig,
        ) -> PlatformFuture<'a, StartedScan> {
            self.events.lock().unwrap().push("scan");
            self.scan_started.notify_one();
            let (sender, observations) = mpsc::channel(1);
            *self.observation_sender.lock().unwrap() = Some(sender);
            let owner = FakeOwner {
                stop_event: "scan-stop",
                events: self.events.clone(),
            };
            Box::pin(async move {
                Ok(StartedScan::new(
                    Box::new(owner) as Box<dyn OwnedScan>,
                    observations,
                ))
            })
        }

        fn force_owner_loss(&self) {
            self.owner_loss_forced.fetch_add(1, Ordering::AcqRel);
            self.advertisement_terminated.notify_waiters();
            self.advertisement_terminated.notify_one();
        }
    }

    struct FixedNonce([u8; 16]);

    impl DiscoveryNonceSource for FixedNonce {
        fn next_nonce(&self) -> Result<[u8; 16], DriverError> {
            Ok(self.0)
        }
    }

    struct SequenceNonce(AtomicU8);

    impl DiscoveryNonceSource for SequenceNonce {
        fn next_nonce(&self) -> Result<[u8; 16], DriverError> {
            Ok([self.0.fetch_add(1, Ordering::AcqRel); 16])
        }
    }

    struct FakeRandom(Mutex<VecDeque<Result<[u8; 16], ()>>>);

    impl NonceRandom for FakeRandom {
        fn generate(&self) -> Result<[u8; 16], ()> {
            self.0.lock().unwrap().pop_front().unwrap()
        }
    }

    struct RecordingOwnerLoss {
        force_count: Arc<AtomicU8>,
        release: Option<Arc<Notify>>,
    }

    struct RecordDrop(Arc<AtomicU8>);

    impl Drop for RecordDrop {
        fn drop(&mut self) {
            self.0.fetch_add(1, Ordering::AcqRel);
        }
    }

    impl PlatformOwnerLoss for RecordingOwnerLoss {
        fn force(&self) {
            self.force_count.fetch_add(1, Ordering::AcqRel);
            if let Some(release) = &self.release {
                release.notify_one();
            }
        }
    }

    fn test_supervisor(
        task: JoinHandle<Result<(), SupervisorError>>,
        platform_owner: Arc<PlatformOwner>,
    ) -> LinuxRosteredBtleSupervisor {
        let (_availability_updates, availability) = watch::channel(
            crate::BtleAvailability::Unavailable(crate::AvailabilityReason::BluezUnavailable),
        );
        let (_completion_updates, completion) = watch::channel(false);
        LinuxRosteredBtleSupervisor {
            availability,
            completion,
            cancellation: LifecycleCancellation::new(),
            platform_owner,
            output: crate::BtleOperatorOutput::discard(),
            failure_park: None,
            task: Some(task),
            abort_on_unconfirmed_cleanup: true,
        }
    }

    fn test_unavailable_publisher() -> UnavailableAvailabilityPublisher {
        let (updates, _availability) = watch::channel(crate::BtleAvailability::Unavailable(
            crate::AvailabilityReason::BluezUnavailable,
        ));
        AdapterAvailabilityPublisher::fixed(updates, crate::BtleOperatorOutput::discard())
            .unavailable_only()
    }

    #[test]
    fn nonce_source_rejects_reuse_and_exhausts_three_redraws() {
        let source = UniqueNonceSource::new(FakeRandom(Mutex::new(
            [
                [1; 16], [1; 16], [2; 16], [2; 16], [2; 16], [2; 16], [2; 16],
            ]
            .into_iter()
            .map(Ok)
            .collect(),
        )));

        assert_eq!(source.next_nonce().unwrap(), [1; 16]);
        assert_eq!(source.next_nonce().unwrap(), [2; 16]);
        assert_eq!(
            source.next_nonce().unwrap_err().kind(),
            DriverErrorKind::Unavailable
        );
    }

    #[tokio::test(start_paused = true)]
    async fn supervisor_shutdown_does_not_force_owner_loss_after_normal_cleanup() {
        let force_count = Arc::new(AtomicU8::new(0));
        let platform_owner = Arc::new(PlatformOwner::default());
        platform_owner.replace(RecordingOwnerLoss {
            force_count: force_count.clone(),
            release: None,
        });
        let supervisor = test_supervisor(tokio::spawn(async { Ok(()) }), platform_owner);

        assert_eq!(supervisor.shutdown().await, Ok(()));
        assert_eq!(force_count.load(Ordering::Acquire), 0);
    }

    #[tokio::test(start_paused = true)]
    async fn supervisor_shutdown_forces_owner_loss_after_graceful_deadline() {
        let force_count = Arc::new(AtomicU8::new(0));
        let release = Arc::new(Notify::new());
        let task_release = release.clone();
        let platform_owner = Arc::new(PlatformOwner::default());
        platform_owner.replace(RecordingOwnerLoss {
            force_count: force_count.clone(),
            release: Some(release),
        });
        let supervisor = test_supervisor(
            tokio::spawn(async move {
                task_release.notified().await;
                Ok(())
            }),
            platform_owner,
        );
        let shutdown = tokio::spawn(supervisor.shutdown());
        tokio::task::yield_now().await;

        tokio::time::advance(OWNER_LOSS_AFTER - Duration::from_millis(1)).await;
        tokio::task::yield_now().await;
        assert_eq!(force_count.load(Ordering::Acquire), 0);
        assert!(!shutdown.is_finished());

        tokio::time::advance(Duration::from_millis(1)).await;
        assert_eq!(shutdown.await.unwrap(), Ok(()));
        assert_eq!(force_count.load(Ordering::Acquire), 1);
    }

    #[tokio::test(start_paused = true)]
    async fn supervisor_shutdown_reports_unconfirmed_cleanup_after_forced_join_deadline() {
        let force_count = Arc::new(AtomicU8::new(0));
        let platform_owner = Arc::new(PlatformOwner::default());
        platform_owner.replace(RecordingOwnerLoss {
            force_count: force_count.clone(),
            release: None,
        });
        let mut supervisor = test_supervisor(
            tokio::spawn(async { pending::<Result<(), SupervisorError>>().await }),
            platform_owner,
        );
        let (output, mut operator_status) =
            crate::BtleOperatorOutput::current_status(crate::BtleCurrentStatus::Available {
                support: crate::BtleSupport::Qualified,
            });
        supervisor.output = output;
        let shutdown = tokio::spawn(supervisor.shutdown());
        tokio::task::yield_now().await;

        tokio::time::advance(OWNER_LOSS_AFTER).await;
        tokio::task::yield_now().await;
        assert_eq!(force_count.load(Ordering::Acquire), 1);
        assert!(!shutdown.is_finished());

        tokio::time::advance(OWNER_LOSS_JOIN_DEADLINE).await;
        assert_eq!(
            shutdown.await.unwrap(),
            Err(SupervisorError::PlatformCleanupUnconfirmed)
        );
        assert_eq!(force_count.load(Ordering::Acquire), 1);
        assert_eq!(
            *operator_status.borrow_and_update(),
            crate::BtleCurrentStatus::Unavailable {
                reason: crate::AvailabilityReason::CleanupUnconfirmed,
                support: crate::BtleSupport::Qualified,
            }
        );
    }

    #[tokio::test]
    async fn authority_failure_fences_status_before_cleanup() {
        let platform_owner = Arc::new(PlatformOwner::default());
        let mut supervisor = test_supervisor(tokio::spawn(async { Ok(()) }), platform_owner);
        let (output, status) =
            crate::BtleOperatorOutput::current_status(crate::BtleCurrentStatus::Available {
                support: crate::BtleSupport::Qualified,
            });
        supervisor.output = output.clone();

        supervisor.park_authority_unavailable().unwrap();
        output.publish_status(crate::BtleCurrentStatus::Available {
            support: crate::BtleSupport::Unqualified,
        });

        assert_eq!(
            *status.borrow(),
            crate::BtleCurrentStatus::Unavailable {
                reason: crate::AvailabilityReason::CredentialUnavailable,
                support: crate::BtleSupport::Qualified,
            }
        );
    }

    #[tokio::test(start_paused = true)]
    async fn automatic_shutdown_is_bounded_without_claiming_or_aborting_cleanup() {
        let force_count = Arc::new(AtomicU8::new(0));
        let drop_count = Arc::new(AtomicU8::new(0));
        let platform_owner = Arc::new(PlatformOwner::default());
        platform_owner.replace(RecordingOwnerLoss {
            force_count: force_count.clone(),
            release: None,
        });
        let guard = RecordDrop(drop_count.clone());
        let mut supervisor = test_supervisor(
            tokio::spawn(async move {
                let _guard = guard;
                pending::<Result<(), SupervisorError>>().await
            }),
            platform_owner,
        );
        supervisor.abort_on_unconfirmed_cleanup = false;
        let shutdown = tokio::spawn(supervisor.shutdown());
        tokio::task::yield_now().await;

        tokio::time::advance(OWNER_LOSS_AFTER + OWNER_LOSS_JOIN_DEADLINE).await;
        assert_eq!(
            shutdown.await.unwrap(),
            Err(SupervisorError::PlatformCleanupUnconfirmed)
        );
        assert_eq!(force_count.load(Ordering::Acquire), 1);
        assert_eq!(drop_count.load(Ordering::Acquire), 0);
    }

    #[tokio::test]
    async fn dropping_supervisor_cancels_and_retains_task_until_cleanup_finishes() {
        let cancellation = LifecycleCancellation::new();
        let task_cancellation = cancellation.clone();
        let cancellation_seen = Arc::new(AtomicU8::new(0));
        let task_cancellation_seen = cancellation_seen.clone();
        let release = Arc::new(Notify::new());
        let task_release = release.clone();
        let secret_drops = Arc::new(AtomicU8::new(0));
        let secret_owner = RecordDrop(secret_drops.clone());
        let (_availability_updates, availability) = watch::channel(
            crate::BtleAvailability::Unavailable(crate::AvailabilityReason::BluezUnavailable),
        );
        let (_completion_updates, completion) = watch::channel(false);
        let supervisor = LinuxRosteredBtleSupervisor {
            availability,
            completion,
            cancellation,
            platform_owner: Arc::new(PlatformOwner::default()),
            output: crate::BtleOperatorOutput::discard(),
            failure_park: None,
            task: Some(tokio::spawn(async move {
                let _secret_owner = secret_owner;
                task_cancellation.cancelled().await;
                task_cancellation_seen.store(1, Ordering::Release);
                task_release.notified().await;
                Ok(())
            })),
            abort_on_unconfirmed_cleanup: true,
        };
        tokio::task::yield_now().await;

        drop(supervisor);
        tokio::time::timeout(Duration::from_secs(1), async {
            while cancellation_seen.load(Ordering::Acquire) == 0 {
                tokio::task::yield_now().await;
            }
        })
        .await
        .expect("drop must synchronously signal supervisor cancellation");
        assert_eq!(secret_drops.load(Ordering::Acquire), 0);

        release.notify_one();
        tokio::time::timeout(Duration::from_secs(1), async {
            while secret_drops.load(Ordering::Acquire) == 0 {
                tokio::task::yield_now().await;
            }
        })
        .await
        .expect("cleanup custody releases secrets only after task completion");
    }

    #[tokio::test]
    async fn operational_cleanup_error_forces_retained_owner_and_propagates() {
        let force_count = Arc::new(AtomicU8::new(0));
        let platform_owner = Arc::new(PlatformOwner::default());
        platform_owner.replace(RecordingOwnerLoss {
            force_count: force_count.clone(),
            release: None,
        });
        let (_updates, status) = watch::channel(OperationalEpochState::Unavailable);
        let (quiesce, _requests) = mpsc::channel(1);
        let epoch = RosteredOperationalEpoch {
            status,
            quiesce,
            availability_fence: Arc::new(AvailabilityFence::default()),
            cancellation: LifecycleCancellation::new(),
            task: Some(tokio::spawn(async {
                OperationalEpochOutcome::Terminal(DriverError::new(
                    DriverErrorKind::Transport,
                    "test platform cleanup unconfirmed",
                ))
            })),
            platform_owner,
            unavailable: test_unavailable_publisher(),
        };

        assert!(matches!(
            Box::new(epoch).join().await,
            OperationalEpochOutcome::Terminal(_)
        ));
        assert_eq!(force_count.load(Ordering::Acquire), 1);
    }

    #[tokio::test]
    async fn operational_suppression_releases_retained_owner_without_forcing() {
        let force_count = Arc::new(AtomicU8::new(0));
        let platform_owner = Arc::new(PlatformOwner::default());
        platform_owner.replace(RecordingOwnerLoss {
            force_count: force_count.clone(),
            release: None,
        });
        let (_updates, status) = watch::channel(OperationalEpochState::Unavailable);
        let (quiesce, _requests) = mpsc::channel(1);
        let epoch = RosteredOperationalEpoch {
            status,
            quiesce,
            availability_fence: Arc::new(AvailabilityFence::default()),
            cancellation: LifecycleCancellation::new(),
            task: Some(tokio::spawn(async { OperationalEpochOutcome::Suppressed })),
            platform_owner: platform_owner.clone(),
            unavailable: test_unavailable_publisher(),
        };

        assert!(matches!(
            Box::new(epoch).join().await,
            OperationalEpochOutcome::Suppressed
        ));
        assert_eq!(force_count.load(Ordering::Acquire), 0);
        assert!(!platform_owner.force_loss());
    }

    #[tokio::test]
    async fn operational_epoch_containment_forces_owner_on_prompt_terminal_outcome() {
        let force_count = Arc::new(AtomicU8::new(0));
        let platform_owner = Arc::new(PlatformOwner::default());
        platform_owner.replace(RecordingOwnerLoss {
            force_count: force_count.clone(),
            release: None,
        });
        let task = tokio::spawn(async {
            OperationalEpochOutcome::Terminal(DriverError::new(
                DriverErrorKind::Transport,
                "test terminal operational outcome",
            ))
        });

        let _ =
            finish_operational_epoch_task(task, platform_owner, test_unavailable_publisher()).await;

        assert_eq!(force_count.load(Ordering::Acquire), 1);
    }

    #[tokio::test]
    async fn operational_epoch_containment_forces_owner_on_prompt_join_error() {
        let force_count = Arc::new(AtomicU8::new(0));
        let platform_owner = Arc::new(PlatformOwner::default());
        platform_owner.replace(RecordingOwnerLoss {
            force_count: force_count.clone(),
            release: None,
        });
        let task: JoinHandle<OperationalEpochOutcome> = tokio::spawn(async {
            panic!("test operational epoch panic");
        });

        let _ =
            finish_operational_epoch_task(task, platform_owner, test_unavailable_publisher()).await;

        assert_eq!(force_count.load(Ordering::Acquire), 1);
    }

    #[tokio::test(start_paused = true)]
    async fn dropping_operational_epoch_bounds_credential_config_custody() {
        let force_count = Arc::new(AtomicU8::new(0));
        let platform_owner = Arc::new(PlatformOwner::default());
        platform_owner.replace(RecordingOwnerLoss {
            force_count: force_count.clone(),
            release: None,
        });
        let epoch_cancellation = LifecycleCancellation::new();
        let cancellation = epoch_cancellation.observer();
        let config = Arc::new(
            automatic_config()
                .for_controller(
                    "hci0".to_owned(),
                    Address::new([2, 0, 0, 0, 0, 1]),
                    AddressType::LeRandom,
                    1,
                    LifecycleCancellation::new().observer(),
                )
                .unwrap(),
        );
        let config_weak = Arc::downgrade(&config);
        let (availability_updates, availability) =
            watch::channel(crate::BtleAvailability::Available);
        let publisher = AdapterAvailabilityPublisher::fixed(
            availability_updates,
            crate::BtleOperatorOutput::discard(),
        );
        let (_updates, status) = watch::channel(OperationalEpochState::Available);
        let (quiesce, _requests) = mpsc::channel(1);
        let epoch = RosteredOperationalEpoch {
            status,
            quiesce,
            availability_fence: Arc::new(AvailabilityFence::default()),
            cancellation: epoch_cancellation,
            task: Some(tokio::spawn(async move {
                let _config = config;
                pending::<OperationalEpochOutcome>().await
            })),
            platform_owner,
            unavailable: publisher.unavailable_only(),
        };
        tokio::task::yield_now().await;

        drop(epoch);
        tokio::task::yield_now().await;
        assert!(cancellation.is_cancelled());
        assert_eq!(
            *availability.borrow(),
            crate::BtleAvailability::Unavailable(crate::AvailabilityReason::BluezUnavailable)
        );
        assert_eq!(force_count.load(Ordering::Acquire), 0);
        assert!(config_weak.upgrade().is_some());

        tokio::time::advance(OWNER_LOSS_AFTER - Duration::from_millis(1)).await;
        tokio::task::yield_now().await;
        assert_eq!(force_count.load(Ordering::Acquire), 0);
        assert!(config_weak.upgrade().is_some());

        tokio::time::advance(Duration::from_millis(1)).await;
        tokio::task::yield_now().await;
        assert_eq!(force_count.load(Ordering::Acquire), 1);
        assert!(config_weak.upgrade().is_some());

        tokio::time::advance(OWNER_LOSS_JOIN_DEADLINE).await;
        tokio::time::timeout(Duration::from_secs(1), async {
            while config_weak.upgrade().is_some() {
                tokio::task::yield_now().await;
            }
        })
        .await
        .expect("abortable operational cleanup must release credential custody after the bound");
    }

    #[test]
    fn dropping_operational_epoch_without_an_entered_runtime_fails_closed() {
        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap();
        let force_count = Arc::new(AtomicU8::new(0));
        let platform_owner = Arc::new(PlatformOwner::default());
        platform_owner.replace(RecordingOwnerLoss {
            force_count: force_count.clone(),
            release: None,
        });
        let cancellation = LifecycleCancellation::new();
        let cancellation_observer = cancellation.observer();
        let (availability_updates, availability) =
            watch::channel(crate::BtleAvailability::Available);
        let publisher = AdapterAvailabilityPublisher::fixed(
            availability_updates,
            crate::BtleOperatorOutput::discard(),
        );
        let (_updates, status) = watch::channel(OperationalEpochState::Available);
        let (quiesce, _requests) = mpsc::channel(1);
        let epoch = RosteredOperationalEpoch {
            status,
            quiesce,
            availability_fence: Arc::new(AvailabilityFence::default()),
            cancellation,
            task: Some(runtime.spawn(pending::<OperationalEpochOutcome>())),
            platform_owner,
            unavailable: publisher.unavailable_only(),
        };

        drop(epoch);

        assert!(cancellation_observer.is_cancelled());
        assert_eq!(
            *availability.borrow(),
            crate::BtleAvailability::Unavailable(crate::AvailabilityReason::BluezUnavailable)
        );
        assert_eq!(force_count.load(Ordering::Acquire), 1);
        runtime.block_on(tokio::task::yield_now());
    }

    #[tokio::test]
    async fn spontaneous_resolver_failure_wakes_automatic_completion_without_shutdown() {
        let cancellation = LifecycleCancellation::new();
        let (status_updates, status) = watch::channel(OperationalEpochState::Starting);
        let (completion_updates, mut completion) = watch::channel(false);
        let task = tokio::spawn(async move {
            let _completion = CompletionOnDrop(completion_updates);
            run_automatic_resolver_owner(
                status,
                cancellation,
                Instant::now() + Duration::from_secs(60),
                Arc::new(AvailabilityFence::default()),
                test_unavailable_publisher(),
                async {
                    Err(DriverError::new(
                        DriverErrorKind::Transport,
                        "test spontaneous resolver failure",
                    ))
                },
            )
            .await
        });

        drop(status_updates);
        completion.changed().await.unwrap();
        assert!(*completion.borrow_and_update());
        assert_eq!(
            task.await.unwrap(),
            Err(SupervisorError::PlatformCleanupUnconfirmed)
        );
    }

    #[tokio::test(start_paused = true)]
    async fn automatic_expiry_publishes_unavailable_releases_config_and_terminates() {
        let cancellation = LifecycleCancellation::new();
        let task_cancellation = cancellation.clone();
        let (_status_updates, status) = watch::channel(OperationalEpochState::Starting);
        let (availability_updates, mut availability) =
            watch::channel(crate::BtleAvailability::Available);
        let (operator_output, mut operator_status) =
            crate::BtleOperatorOutput::current_status(crate::BtleCurrentStatus::Available {
                support: crate::BtleSupport::Qualified,
            });
        let shutdown_output = operator_output.clone();
        let unavailable =
            AdapterAvailabilityPublisher::fixed(availability_updates, operator_output)
                .unavailable_only();
        let config = Arc::new(automatic_config());
        let config_weak = Arc::downgrade(&config);
        let task = tokio::spawn(async move {
            run_automatic_resolver_owner(
                status,
                task_cancellation,
                Instant::now() + Duration::from_secs(5),
                Arc::new(AvailabilityFence::default()),
                unavailable,
                async move {
                    shutdown_output.publish_status(crate::BtleCurrentStatus::Unavailable {
                        reason: crate::AvailabilityReason::Cancelled,
                        support: crate::BtleSupport::Qualified,
                    });
                    drop(config);
                    Ok(())
                },
            )
            .await
        });
        tokio::task::yield_now().await;

        tokio::time::advance(Duration::from_secs(5)).await;
        availability.changed().await.unwrap();

        assert_eq!(
            *availability.borrow_and_update(),
            crate::BtleAvailability::Unavailable(crate::AvailabilityReason::BluezUnavailable)
        );
        assert_eq!(
            *operator_status.borrow_and_update(),
            crate::BtleCurrentStatus::Unavailable {
                reason: crate::AvailabilityReason::CredentialExpired,
                support: crate::BtleSupport::Qualified,
            }
        );
        assert!(
            config_weak.upgrade().is_none(),
            "expired automatic configuration must release credential custody"
        );
        let result = tokio::time::timeout(Duration::from_secs(1), task)
            .await
            .expect("credential expiry must terminate the owner for controlled restart")
            .expect("credential expiry owner task");
        assert_eq!(result, Err(SupervisorError::CredentialExpired));
    }

    #[tokio::test(start_paused = true)]
    async fn expiry_readiness_port_loss_still_completes_resolver_shutdown() {
        let cancellation = LifecycleCancellation::new();
        let (_status_updates, status) = watch::channel(OperationalEpochState::Starting);
        let (backend, port) = automatic_btle_carrier_channel(crate::BtleAvailability::Unavailable(
            crate::AvailabilityReason::Activating,
        ));
        let readiness = backend.readiness_publisher();
        drop(port);
        let (availability_updates, _availability) =
            watch::channel(crate::BtleAvailability::Available);
        let unavailable = AdapterAvailabilityPublisher::automatic(
            readiness,
            availability_updates,
            crate::BtleOperatorOutput::discard(),
            FixedRole::Initiator,
        )
        .unavailable_only();
        let shutdown_completed = Arc::new(AtomicU8::new(0));
        let task_shutdown_completed = shutdown_completed.clone();
        let secret_drops = Arc::new(AtomicU8::new(0));
        let secret_owner = RecordDrop(secret_drops.clone());
        let task = tokio::spawn(run_automatic_resolver_owner(
            status,
            cancellation,
            Instant::now() + Duration::from_secs(5),
            Arc::new(AvailabilityFence::default()),
            unavailable,
            async move {
                let _secret_owner = secret_owner;
                task_shutdown_completed.store(1, Ordering::Release);
                Ok(())
            },
        ));
        tokio::task::yield_now().await;

        tokio::time::advance(Duration::from_secs(5)).await;

        assert_eq!(task.await.unwrap(), Err(SupervisorError::TaskStopped));
        assert_eq!(shutdown_completed.load(Ordering::Acquire), 1);
        assert_eq!(secret_drops.load(Ordering::Acquire), 1);
    }

    #[tokio::test(start_paused = true)]
    async fn operational_join_bounds_hung_task_and_releases_credential_custody() {
        let force_count = Arc::new(AtomicU8::new(0));
        let platform_owner = Arc::new(PlatformOwner::default());
        platform_owner.replace(RecordingOwnerLoss {
            force_count: force_count.clone(),
            release: None,
        });
        let cancellation = LifecycleCancellation::new();
        let cancellation_observer = cancellation.observer();
        let (_status_updates, status) = watch::channel(OperationalEpochState::Starting);
        let (quiesce, _requests) = mpsc::channel(1);
        let secret_drops = Arc::new(AtomicU8::new(0));
        let secret_owner = RecordDrop(secret_drops.clone());
        let epoch = RosteredOperationalEpoch {
            status,
            cancellation,
            quiesce,
            availability_fence: Arc::new(AvailabilityFence::default()),
            task: Some(tokio::spawn(async move {
                let _secret_owner = secret_owner;
                pending::<OperationalEpochOutcome>().await
            })),
            platform_owner,
            unavailable: test_unavailable_publisher(),
        };
        tokio::task::yield_now().await;
        let join = tokio::spawn(Box::new(epoch).join());
        tokio::task::yield_now().await;

        tokio::time::advance(OWNER_LOSS_AFTER + Duration::from_millis(1)).await;
        tokio::task::yield_now().await;
        assert!(cancellation_observer.is_cancelled());
        assert_eq!(force_count.load(Ordering::Acquire), 1);
        assert_eq!(secret_drops.load(Ordering::Acquire), 0);

        tokio::time::advance(OWNER_LOSS_JOIN_DEADLINE + Duration::from_millis(1)).await;
        tokio::task::yield_now().await;

        assert!(matches!(
            join.await.unwrap(),
            OperationalEpochOutcome::Terminal(_)
        ));
        assert_eq!(secret_drops.load(Ordering::Acquire), 1);
    }

    #[tokio::test(start_paused = true)]
    async fn expiry_fences_a_concurrent_late_available_publication() {
        let cancellation = LifecycleCancellation::new();
        let task_cancellation = cancellation.clone();
        let (_status_updates, status) = watch::channel(OperationalEpochState::Starting);
        let (availability_updates, mut availability) =
            watch::channel(crate::BtleAvailability::Available);
        let publisher = Arc::new(AdapterAvailabilityPublisher::fixed(
            availability_updates,
            crate::BtleOperatorOutput::discard(),
        ));
        let expiry_fence = Arc::new(AvailabilityFence::default());
        let (operational, _operational_updates) = watch::channel(OperationalEpochState::Starting);
        let signals = EpochSignals::operational(
            publisher.clone(),
            operational,
            Arc::new(AvailabilityFence::default()),
            expiry_fence.clone(),
        );
        let (late_result_updates, late_result) = oneshot::channel();
        let task = tokio::spawn(run_automatic_resolver_owner(
            status,
            task_cancellation,
            Instant::now() + Duration::from_secs(5),
            expiry_fence,
            publisher.unavailable_only(),
            async move {
                let _ =
                    late_result_updates.send(signals.publish(crate::BtleAvailability::Available));
                Ok(())
            },
        ));
        tokio::task::yield_now().await;

        tokio::time::advance(Duration::from_secs(5)).await;

        assert_eq!(
            late_result.await.unwrap(),
            Err(SupervisorError::TaskStopped)
        );
        assert_eq!(
            *availability.borrow_and_update(),
            crate::BtleAvailability::Unavailable(crate::AvailabilityReason::BluezUnavailable)
        );
        assert_eq!(task.await.unwrap(), Err(SupervisorError::CredentialExpired));
    }

    #[test]
    fn only_a_stable_epoch_resets_outer_retry_backoff() {
        let started = Instant::now();

        assert!(!stable_epoch_elapsed(
            started,
            started + STABLE_EPOCH_DURATION - Duration::from_millis(1),
        ));
        assert!(stable_epoch_elapsed(
            started,
            started + STABLE_EPOCH_DURATION,
        ));
    }

    #[test]
    fn new_candidates_wake_retry_backoff_but_never_success_cadence() {
        let now = Instant::now();
        let cadence_deadline = now + Duration::from_secs(60);
        let mut cadence = OutboundDelay::CadenceUntil(cadence_deadline);
        cadence.wake_for_new_candidate();
        assert_eq!(cadence.deadline(now), cadence_deadline);

        let mut retry = OutboundDelay::PeerRetryUntil(now + Duration::from_secs(30));
        retry.wake_for_new_candidate();
        assert_eq!(retry.deadline(now), now);

        let refill_deadline = now + Duration::from_secs(10);
        let mut refill = OutboundDelay::TokenRefillUntil(refill_deadline);
        refill.wake_for_new_candidate();
        assert_eq!(refill.deadline(now), refill_deadline);
    }

    #[tokio::test]
    async fn expired_adapter_parks_until_cancelled_without_terminal_failure() {
        let cancellation = LifecycleCancellation::new();
        let task_cancellation = cancellation.clone();
        let config = Arc::new(config());
        let config_weak = Arc::downgrade(&config);
        let (updates, availability) = watch::channel(crate::BtleAvailability::Available);
        let publisher =
            AdapterAvailabilityPublisher::fixed(updates, crate::BtleOperatorOutput::discard());
        let task = tokio::spawn(async move {
            park_expired_adapter(config, &publisher, &task_cancellation).await
        });

        tokio::task::yield_now().await;
        assert_eq!(
            *availability.borrow(),
            crate::BtleAvailability::Unavailable(crate::AvailabilityReason::BluezUnavailable)
        );
        assert!(!task.is_finished());
        assert!(
            config_weak.upgrade().is_none(),
            "parking must release expired discovery credentials"
        );

        cancellation.cancel();
        assert_eq!(task.await.unwrap(), Ok(()));
    }

    #[test]
    fn terminal_contact_admission_errors_remain_terminal_supervisor_errors() {
        let cases = [
            (
                ContactOutcome::admission_closed(),
                SupervisorError::AdmissionClosed,
            ),
            (
                ContactOutcome::actor_unavailable(),
                SupervisorError::ActorUnavailable,
            ),
            (
                ContactOutcome::actor_stopped(),
                SupervisorError::ActorStopped,
            ),
        ];

        for (contact_error, expected) in cases {
            let now = Instant::now();
            let mut admission = DiscoveryAdmission::new();
            let mut outbound_delay = OutboundDelay::Ready;
            let mut outbound_candidate_pending = false;
            let mut backoff = CappedBackoff::new(INITIAL_EPOCH_RETRY, MAXIMUM_EPOCH_RETRY);
            let mut schedule = OutboundSchedule {
                delay: &mut outbound_delay,
                candidate_pending: &mut outbound_candidate_pending,
                backoff: &mut backoff,
                self_schedule: true,
            };
            let error = finish_contact_attempt(
                &config(),
                &mut admission,
                ContactAttemptOutcome::Completed(Box::new(Err(contact_error))),
                now,
                &mut schedule,
            )
            .unwrap_err();

            assert_eq!(error, expected);
        }
    }

    #[test]
    fn rostered_contact_dispositions_drive_distinct_scheduler_effects() {
        let config = Arc::new(config());
        let now = Instant::now();
        let admission_with_candidate = || {
            let record = AsterRosterBeaconV1::encode(
                0x0081,
                [0x6d; 16],
                config.discovery_credentials(),
                now,
            )
            .unwrap();
            let locator = crate::CanonicalLocator::new(
                Address::new([2, 0, 0, 0, 0, 0x6d]),
                AddressType::LeRandom,
            )
            .unwrap();
            let observation =
                DiscoveryObservation::new(locator.address(), locator.address_type(), &record)
                    .unwrap();
            let mut admission = DiscoveryAdmission::new();
            assert_eq!(admission.start_scan(now), crate::ScanStartOutcome::Started);
            assert_eq!(
                admit_platform_observation(&mut admission, &config, observation, now),
                ObservationOutcome::Accepted
            );
            admission
        };

        let run = |disposition| {
            let mut admission = admission_with_candidate();
            let mut delay = OutboundDelay::Ready;
            let mut pending = false;
            let mut backoff = CappedBackoff::new(INITIAL_EPOCH_RETRY, MAXIMUM_EPOCH_RETRY);
            let mut schedule = OutboundSchedule {
                delay: &mut delay,
                candidate_pending: &mut pending,
                backoff: &mut backoff,
                self_schedule: true,
            };
            let result = finish_contact_disposition(
                &config,
                &mut admission,
                disposition,
                ContactReason::ProtocolViolation,
                now,
                &mut schedule,
            );
            (result, pending, delay.deadline(now))
        };

        let (retry, retry_pending, retry_deadline) = run(ContactDisposition::RetryLater);
        assert_eq!(retry, Ok(()));
        assert!(retry_pending);
        assert!(retry_deadline > now);

        let (reselect, reselect_pending, reselect_deadline) = run(ContactDisposition::Reselect);
        assert_eq!(reselect, Ok(()));
        assert!(reselect_pending);
        assert_eq!(reselect_deadline, now);

        let (cancelled, cancelled_pending, cancelled_deadline) = run(ContactDisposition::Cancelled);
        assert_eq!(cancelled, Ok(()));
        assert!(!cancelled_pending);
        assert_eq!(cancelled_deadline, now);

        assert!(matches!(
            run(ContactDisposition::Suppress).0,
            Err(SupervisorError::ContactSuppressed(
                ContactReason::ProtocolViolation
            ))
        ));
        assert!(matches!(
            run(ContactDisposition::Terminal).0,
            Err(SupervisorError::ContactTerminal(
                ContactReason::ProtocolViolation
            ))
        ));
    }

    #[test]
    fn platform_observation_enters_authenticated_candidate_admission() {
        let config = config();
        let now = Instant::now();
        let record =
            AsterRosterBeaconV1::encode(0x0081, [0x5a; 16], config.discovery_credentials(), now)
                .unwrap();
        let locator =
            crate::CanonicalLocator::new(Address::new([2, 0, 0, 0, 0, 9]), AddressType::LeRandom)
                .unwrap();
        let observation =
            DiscoveryObservation::new(locator.address(), locator.address_type(), &record).unwrap();
        let mut admission = DiscoveryAdmission::new();
        assert_eq!(admission.start_scan(now), crate::ScanStartOutcome::Started);

        assert_eq!(
            admit_platform_observation(&mut admission, &config, observation, now),
            ObservationOutcome::Accepted
        );
        assert_eq!(
            admission.selected_candidate(now).unwrap().locator(),
            locator
        );
    }

    impl RosteredSocketFactory for FakeSockets {
        type Listener = ();

        fn bind_dynamic_listener<'a>(
            &'a self,
            _controller: &'a ValidatedControllerConfig,
        ) -> RosteredBindFuture<'a, Self::Listener> {
            self.events.lock().unwrap().push("bind");
            Box::pin(async { BoundRosteredListener::new((), 0x0081) })
        }

        fn connect<'a>(
            &'a self,
            _controller: &'a ValidatedControllerConfig,
            _locator: crate::CanonicalLocator,
            _advertised_psm: u16,
        ) -> crate::OpenFuture<'a> {
            unreachable!("startup-order test does not connect")
        }

        fn accept<'a>(
            &'a self,
            _listener: &'a Self::Listener,
        ) -> crate::platform::socket::RosteredAcceptFuture<'a> {
            Box::pin(pending())
        }
    }

    #[tokio::test]
    async fn epoch_marks_available_only_after_listener_advertisement_and_scan_start() {
        let events = Arc::new(Mutex::new(Vec::new()));
        let scan_started = Arc::new(Notify::new());
        let discovery = Arc::new(FakeDiscovery {
            events: events.clone(),
            advertisements: Arc::new(Mutex::new(Vec::new())),
            scan_started: scan_started.clone(),
            observation_sender: Mutex::new(None),
        });
        let sockets = Arc::new(FakeSockets {
            events: events.clone(),
        });
        let cancellation = LifecycleCancellation::new();
        let task_cancellation = cancellation.clone();
        let (available_started, mut available_started_at) = oneshot::channel();
        let task = tokio::spawn(async move {
            run_available_epoch(
                Arc::new(config()),
                sockets,
                discovery,
                Arc::new(FixedNonce([0x33; 16])),
                recording_admission(),
                EpochSignals {
                    available_started: Some(available_started),
                    ..EpochSignals::default()
                },
                task_cancellation,
            )
            .await
        });

        scan_started.notified().await;
        tokio::task::yield_now().await;
        assert!(
            available_started_at.try_recv().is_ok(),
            "a fully started epoch must expose its Available start time"
        );
        cancellation.cancel();
        task.await.unwrap().unwrap();

        assert_eq!(
            *events.lock().unwrap(),
            [
                "bind",
                "advertise",
                "scan",
                "scan-stop",
                "advertisement-release"
            ]
        );
    }

    #[tokio::test]
    async fn scan_start_failure_releases_the_local_advertisement_owner() {
        let events = Arc::new(Mutex::new(Vec::new()));
        let result = run_available_epoch(
            Arc::new(config()),
            Arc::new(FakeSockets {
                events: events.clone(),
            }),
            Arc::new(FailingScanDiscovery {
                events: events.clone(),
            }),
            Arc::new(FixedNonce([0x33; 16])),
            recording_admission(),
            EpochSignals::default(),
            LifecycleCancellation::new(),
        )
        .await;

        assert_eq!(
            result.unwrap_err(),
            SupervisorError::Controller(DriverErrorKind::Unavailable)
        );
        assert_eq!(
            *events.lock().unwrap(),
            ["bind", "advertise", "scan-failed", "advertisement-release"]
        );
    }

    #[tokio::test(start_paused = true)]
    async fn local_open_timeout_bounds_hung_platform_open() {
        let cancellation = LifecycleCancellation::new();
        let observer = cancellation.observer();
        let task = tokio::spawn(async move {
            await_startup_platform(
                Instant::now() + Duration::from_secs(60),
                Duration::from_secs(5),
                &observer,
                pending::<Result<(), DriverError>>(),
            )
            .await
        });
        tokio::task::yield_now().await;

        tokio::time::advance(Duration::from_secs(5)).await;

        assert_eq!(
            task.await.unwrap().unwrap_err(),
            SupervisorError::Controller(DriverErrorKind::Unavailable)
        );
    }

    #[tokio::test(start_paused = true)]
    async fn local_open_timeout_bounds_hung_listener_bind() {
        let bind_started = Arc::new(Notify::new());
        let task = tokio::spawn(run_available_epoch(
            Arc::new(config()),
            Arc::new(PendingBindSockets {
                started: bind_started.clone(),
            }),
            Arc::new(FakeDiscovery {
                events: Arc::new(Mutex::new(Vec::new())),
                advertisements: Arc::new(Mutex::new(Vec::new())),
                scan_started: Arc::new(Notify::new()),
                observation_sender: Mutex::new(None),
            }),
            Arc::new(FixedNonce([0x33; 16])),
            recording_admission(),
            EpochSignals::default(),
            LifecycleCancellation::new(),
        ));
        bind_started.notified().await;

        tokio::time::advance(Duration::from_secs(5)).await;

        assert_eq!(
            tokio::time::timeout(Duration::from_secs(1), task)
                .await
                .expect("local deadline ends a hung listener bind")
                .unwrap()
                .unwrap_err(),
            SupervisorError::Controller(DriverErrorKind::Unavailable)
        );
    }

    #[tokio::test(start_paused = true)]
    async fn hung_advertisement_start_fences_retry_as_unconfirmed_cleanup() {
        let started = Arc::new(Notify::new());
        let owner_loss_forced = Arc::new(AtomicU8::new(0));
        let task = tokio::spawn(run_available_epoch(
            Arc::new(config()),
            Arc::new(FakeSockets {
                events: Arc::new(Mutex::new(Vec::new())),
            }),
            Arc::new(PendingAdvertisementDiscovery {
                started: started.clone(),
                owner_loss_forced: owner_loss_forced.clone(),
            }),
            Arc::new(FixedNonce([0x33; 16])),
            recording_admission(),
            EpochSignals::default(),
            LifecycleCancellation::new(),
        ));
        started.notified().await;

        tokio::time::advance(Duration::from_secs(5)).await;
        tokio::task::yield_now().await;
        assert!(!task.is_finished());
        assert_eq!(owner_loss_forced.load(Ordering::Acquire), 1);
        tokio::time::advance(OWNED_STOP_DEADLINE).await;

        assert_eq!(
            tokio::time::timeout(Duration::from_secs(1), task)
                .await
                .expect("cleanup deadline ends hung advertisement startup")
                .unwrap()
                .unwrap_err(),
            SupervisorError::PlatformCleanupUnconfirmed
        );
    }

    #[tokio::test(start_paused = true)]
    async fn pre_cancelled_owned_start_is_never_polled() {
        let polls = AtomicU8::new(0);
        let cancellation = LifecycleCancellation::new();
        cancellation.cancel();
        let observer = cancellation.observer();
        let owner_loss_forced = Arc::new(AtomicU8::new(0));
        let discovery = PendingAdvertisementDiscovery {
            started: Arc::new(Notify::new()),
            owner_loss_forced: owner_loss_forced.clone(),
        };

        let result = await_owned_discovery_start(
            &discovery,
            Instant::now() + Duration::from_secs(60),
            Duration::from_secs(5),
            &observer,
            async {
                polls.fetch_add(1, Ordering::AcqRel);
                pending::<Result<(), DriverError>>().await
            },
            |()| async { Ok(()) },
        )
        .await;

        assert_eq!(
            result,
            Err(SupervisorError::Controller(DriverErrorKind::Cancelled))
        );
        assert_eq!(polls.load(Ordering::Acquire), 0);
        assert_eq!(owner_loss_forced.load(Ordering::Acquire), 0);
    }

    #[tokio::test(start_paused = true)]
    async fn expired_owned_start_is_never_polled() {
        let polls = AtomicU8::new(0);
        let cancellation = LifecycleCancellation::new();
        let observer = cancellation.observer();
        let owner_loss_forced = Arc::new(AtomicU8::new(0));
        let discovery = PendingAdvertisementDiscovery {
            started: Arc::new(Notify::new()),
            owner_loss_forced: owner_loss_forced.clone(),
        };

        let result = await_owned_discovery_start(
            &discovery,
            Instant::now() - Duration::from_secs(1),
            Duration::from_secs(5),
            &observer,
            async {
                polls.fetch_add(1, Ordering::AcqRel);
                pending::<Result<(), DriverError>>().await
            },
            |()| async { Ok(()) },
        )
        .await;

        assert_eq!(
            result,
            Err(SupervisorError::Controller(DriverErrorKind::Unavailable))
        );
        assert_eq!(polls.load(Ordering::Acquire), 0);
        assert_eq!(owner_loss_forced.load(Ordering::Acquire), 0);
    }

    #[tokio::test(start_paused = true)]
    async fn hung_initial_scan_start_fences_retry_as_unconfirmed_cleanup() {
        let scan_started = Arc::new(Notify::new());
        let owner_loss_forced = Arc::new(AtomicU8::new(0));
        let task = tokio::spawn(run_available_epoch(
            Arc::new(config()),
            Arc::new(FakeSockets {
                events: Arc::new(Mutex::new(Vec::new())),
            }),
            Arc::new(PendingScanDiscovery {
                scan_started: scan_started.clone(),
                owner_loss_forced: owner_loss_forced.clone(),
                events: Arc::new(Mutex::new(Vec::new())),
            }),
            Arc::new(FixedNonce([0x33; 16])),
            recording_admission(),
            EpochSignals::default(),
            LifecycleCancellation::new(),
        ));
        scan_started.notified().await;

        tokio::time::advance(Duration::from_secs(5)).await;
        tokio::task::yield_now().await;
        assert!(!task.is_finished());
        assert_eq!(owner_loss_forced.load(Ordering::Acquire), 1);
        tokio::time::advance(OWNED_STOP_DEADLINE).await;

        assert_eq!(
            tokio::time::timeout(Duration::from_secs(1), task)
                .await
                .expect("cleanup deadline ends hung initial scan")
                .unwrap()
                .unwrap_err(),
            SupervisorError::PlatformCleanupUnconfirmed
        );
    }

    #[tokio::test(start_paused = true)]
    async fn hung_scan_restart_fences_retry_as_unconfirmed_cleanup() {
        let restart_started = Arc::new(Notify::new());
        let owner_loss_forced = Arc::new(AtomicU8::new(0));
        let discovery = Arc::new(OneScanThenPendingDiscovery {
            starts: AtomicU8::new(0),
            restart_started: restart_started.clone(),
            owner_loss_forced: owner_loss_forced.clone(),
            events: Arc::new(Mutex::new(Vec::new())),
            observation_sender: Mutex::new(None),
        });
        let task = tokio::spawn(run_available_epoch(
            Arc::new(config()),
            Arc::new(FakeSockets {
                events: Arc::new(Mutex::new(Vec::new())),
            }),
            discovery.clone(),
            Arc::new(FixedNonce([0x33; 16])),
            recording_admission(),
            EpochSignals::default(),
            LifecycleCancellation::new(),
        ));
        tokio::task::yield_now().await;
        tokio::time::advance(SCAN_ACTIVE_INTERVAL).await;
        tokio::task::yield_now().await;
        tokio::time::advance(SCAN_IDLE_INTERVAL).await;
        assert!(
            tokio::time::timeout(Duration::from_secs(1), restart_started.notified())
                .await
                .is_ok(),
            "scan restart begins after active and idle windows: {:?}",
            discovery.events.lock().unwrap()
        );

        tokio::time::advance(Duration::from_secs(5)).await;
        tokio::task::yield_now().await;
        assert!(!task.is_finished());
        assert_eq!(owner_loss_forced.load(Ordering::Acquire), 1);
        tokio::time::advance(OWNED_STOP_DEADLINE).await;

        assert_eq!(
            tokio::time::timeout(Duration::from_secs(1), task)
                .await
                .expect("cleanup deadline ends a hung scan restart")
                .unwrap()
                .unwrap_err(),
            SupervisorError::PlatformCleanupUnconfirmed
        );
    }

    #[tokio::test(start_paused = true)]
    async fn credential_expiry_fences_hung_registration_as_unconfirmed_cleanup() {
        let owner_loss_forced = Arc::new(AtomicU8::new(0));
        let registration_started = Arc::new(Notify::new());
        let (available_started, available_started_at) = oneshot::channel();
        let task = tokio::spawn(run_available_epoch(
            Arc::new(config_with_ids_and_lease(
                [0x11; 32],
                [0x22; 32],
                Duration::from_secs(1),
            )),
            Arc::new(FakeSockets {
                events: Arc::new(Mutex::new(Vec::new())),
            }),
            Arc::new(PendingAdvertisementDiscovery {
                started: registration_started.clone(),
                owner_loss_forced: owner_loss_forced.clone(),
            }),
            Arc::new(FixedNonce([0x33; 16])),
            recording_admission(),
            EpochSignals {
                available_started: Some(available_started),
                ..EpochSignals::default()
            },
            LifecycleCancellation::new(),
        ));
        registration_started.notified().await;

        tokio::time::advance(Duration::from_secs(2)).await;
        tokio::task::yield_now().await;
        assert!(!task.is_finished());
        assert_eq!(owner_loss_forced.load(Ordering::Acquire), 1);
        tokio::time::advance(OWNED_STOP_DEADLINE).await;

        assert_eq!(
            task.await.unwrap().unwrap_err(),
            SupervisorError::PlatformCleanupUnconfirmed
        );
        assert!(
            available_started_at.await.is_err(),
            "failed startup must not count toward stable Available time"
        );
    }

    #[tokio::test]
    async fn cancellation_waits_for_late_scan_owner_cleanup() {
        let events = Arc::new(Mutex::new(Vec::new()));
        let scan_entered = Arc::new(Notify::new());
        let allow_scan = Arc::new(Notify::new());
        let cancellation = LifecycleCancellation::new();
        let task = tokio::spawn(run_available_epoch(
            Arc::new(config()),
            Arc::new(FakeSockets {
                events: events.clone(),
            }),
            Arc::new(GatedScanDiscovery {
                events: events.clone(),
                scan_entered: scan_entered.clone(),
                allow_scan: allow_scan.clone(),
                observation_sender: Mutex::new(None),
            }),
            Arc::new(FixedNonce([0x33; 16])),
            recording_admission(),
            EpochSignals::default(),
            cancellation.clone(),
        ));
        scan_entered.notified().await;

        cancellation.cancel();
        tokio::task::yield_now().await;
        assert!(!task.is_finished());
        allow_scan.notify_one();

        assert_eq!(
            tokio::time::timeout(Duration::from_secs(1), task)
                .await
                .expect("late scan owner is stopped before cancellation completes")
                .unwrap()
                .unwrap_err(),
            SupervisorError::Controller(DriverErrorKind::Cancelled)
        );
        assert_eq!(
            *events.lock().unwrap(),
            [
                "bind",
                "advertise",
                "scan-starting",
                "scan-stop",
                "advertisement-release"
            ]
        );
    }

    #[tokio::test]
    async fn outbound_open_uses_the_newest_authenticated_candidate_and_dynamic_psm() {
        let config = config();
        let now = Instant::now();
        let newer = now + Duration::from_millis(1);
        let older_locator =
            crate::CanonicalLocator::new(Address::new([2, 0, 0, 0, 0, 8]), AddressType::LeRandom)
                .unwrap();
        let newer_locator =
            crate::CanonicalLocator::new(Address::new([2, 0, 0, 0, 0, 9]), AddressType::LeRandom)
                .unwrap();
        let older_record =
            AsterRosterBeaconV1::encode(0x0081, [0x41; 16], config.discovery_credentials(), now)
                .unwrap();
        let newer_record =
            AsterRosterBeaconV1::encode(0x0083, [0x42; 16], config.discovery_credentials(), newer)
                .unwrap();
        let mut candidates = DiscoveryAdmission::new();
        assert_eq!(candidates.start_scan(now), crate::ScanStartOutcome::Started);
        assert_eq!(
            candidates.observe(
                older_locator,
                &older_record,
                config.discovery_credentials(),
                now,
            ),
            ObservationOutcome::Accepted
        );
        assert_eq!(
            candidates.observe(
                newer_locator,
                &newer_record,
                config.discovery_credentials(),
                newer,
            ),
            ObservationOutcome::Accepted
        );
        let sockets = ConnectingSockets {
            connected: Mutex::new(Vec::new()),
        };

        let candidate = candidates.selected_candidate(newer).unwrap();
        assert!(candidates.try_consume_attempt(AttemptKind::OutboundOpen, newer));
        let opened = open_candidate(&config, &sockets, candidate, &LifecycleCancellation::new())
            .await
            .unwrap();

        assert_eq!(
            *sockets.connected.lock().unwrap(),
            [(newer_locator, 0x0083)]
        );
        assert_eq!(
            opened.maximum_exchange_bytes(),
            RING1_MAXIMUM_EXCHANGE_BYTES
        );
    }

    #[tokio::test]
    async fn opened_outbound_contact_runs_initiator_with_the_exact_rostered_mission_peer() {
        let config = config();
        let locator =
            crate::CanonicalLocator::new(Address::new([2, 0, 0, 0, 0, 9]), AddressType::LeRandom)
                .unwrap();
        let (stream, _peer) = tokio::io::duplex(4096);
        let opened = crate::platform::socket::opened_rostered_contact(
            &config,
            locator,
            SocketOpen::with_observed_mtu(Box::new(stream), 128, 96).unwrap(),
        )
        .unwrap();
        let contacts = RecordingAdmission {
            roles: Mutex::new(Vec::new()),
            peers: Mutex::new(Vec::new()),
        };

        let outcome = run_opened_contact(
            &contacts,
            config.fixed_peer_mission_id(),
            OrderedEventContactRole::Initiator,
            opened,
            &LifecycleCancellation::new(),
        )
        .await;

        assert!(matches!(
            outcome,
            ContactAttemptOutcome::Completed(result) if result.is_ok()
        ));
        assert_eq!(
            *contacts.roles.lock().unwrap(),
            [OrderedEventContactRole::Initiator]
        );
        assert_eq!(
            *contacts.peers.lock().unwrap(),
            [config.fixed_peer_mission_id()]
        );
    }

    #[tokio::test]
    async fn cancelling_an_opened_contact_closes_and_drains_admission() {
        let config = config();
        let locator =
            crate::CanonicalLocator::new(Address::new([2, 0, 0, 0, 0, 9]), AddressType::LeRandom)
                .unwrap();
        let (stream, _peer) = tokio::io::duplex(4096);
        let opened = crate::platform::socket::opened_rostered_contact(
            &config,
            locator,
            SocketOpen::with_observed_mtu(Box::new(stream), 128, 96).unwrap(),
        )
        .unwrap();
        let started = Arc::new(Notify::new());
        let drained = Arc::new(AtomicU8::new(0));
        let contacts = Arc::new(DrainingAdmission {
            started: started.clone(),
            drained: drained.clone(),
        });
        let cancellation = LifecycleCancellation::new();
        let task_cancellation = cancellation.clone();
        let task_contacts = contacts.clone();
        let peer_mission_id = config.fixed_peer_mission_id();
        let task = tokio::spawn(async move {
            run_opened_contact(
                task_contacts.as_ref(),
                peer_mission_id,
                OrderedEventContactRole::Initiator,
                opened,
                &task_cancellation,
            )
            .await
        });

        started.notified().await;
        cancellation.cancel();

        assert!(matches!(
            task.await.unwrap(),
            ContactAttemptOutcome::Cancelled
        ));
        assert_eq!(drained.load(Ordering::SeqCst), 1);
    }

    #[tokio::test(start_paused = true)]
    async fn cancelling_a_stuck_admission_is_bounded() {
        let config = config();
        let locator =
            crate::CanonicalLocator::new(Address::new([2, 0, 0, 0, 0, 9]), AddressType::LeRandom)
                .unwrap();
        let (stream, _peer) = tokio::io::duplex(4096);
        let opened = crate::platform::socket::opened_rostered_contact(
            &config,
            locator,
            SocketOpen::with_observed_mtu(Box::new(stream), 128, 96).unwrap(),
        )
        .unwrap();
        let started = Arc::new(Notify::new());
        let contacts = Arc::new(PendingAdmission {
            started: started.clone(),
        });
        let cancellation = LifecycleCancellation::new();
        let task_cancellation = cancellation.clone();
        let peer_mission_id = config.fixed_peer_mission_id();
        let task = tokio::spawn(async move {
            run_opened_contact(
                contacts.as_ref(),
                peer_mission_id,
                OrderedEventContactRole::Initiator,
                opened,
                &task_cancellation,
            )
            .await
        });

        started.notified().await;
        cancellation.cancel();
        let outcome = timeout(Duration::from_secs(6), task)
            .await
            .expect("contact cancellation must bound admission drain")
            .unwrap();

        assert!(matches!(outcome, ContactAttemptOutcome::Cancelled));
    }

    #[tokio::test]
    async fn newest_authenticated_candidate_is_opened_and_admitted_as_initiator() {
        let config = config();
        let locator =
            crate::CanonicalLocator::new(Address::new([2, 0, 0, 0, 0, 9]), AddressType::LeRandom)
                .unwrap();
        let record = AsterRosterBeaconV1::encode(
            0x0083,
            [0x55; 16],
            config.discovery_credentials(),
            Instant::now(),
        )
        .unwrap();
        let sockets = Arc::new(ConnectingSockets {
            connected: Mutex::new(Vec::new()),
        });
        let scan_started = Arc::new(Notify::new());
        let discovery = Arc::new(FakeDiscovery {
            events: Arc::new(Mutex::new(Vec::new())),
            advertisements: Arc::new(Mutex::new(Vec::new())),
            scan_started: scan_started.clone(),
            observation_sender: Mutex::new(None),
        });
        let contacts = Arc::new(NotifyingAdmission {
            roles: Mutex::new(Vec::new()),
            peers: Mutex::new(Vec::new()),
            admitted: Notify::new(),
        });
        let cancellation = LifecycleCancellation::new();
        let task_cancellation = cancellation.clone();
        let task_sockets = sockets.clone();
        let task_discovery = discovery.clone();
        let task_contacts = contacts.clone();
        let task = tokio::spawn(async move {
            run_available_epoch(
                Arc::new(config),
                task_sockets,
                task_discovery,
                Arc::new(FixedNonce([0x33; 16])),
                task_contacts,
                EpochSignals::default(),
                task_cancellation,
            )
            .await
        });

        scan_started.notified().await;
        let sender = discovery
            .observation_sender
            .lock()
            .unwrap()
            .as_ref()
            .unwrap()
            .clone();
        sender
            .send(
                DiscoveryObservation::new(locator.address(), locator.address_type(), &record)
                    .unwrap(),
            )
            .await
            .unwrap();

        timeout(Duration::from_secs(2), contacts.admitted.notified())
            .await
            .expect("authenticated discovery candidate must reach contact admission");
        cancellation.cancel();
        task.await.unwrap().unwrap();

        assert_eq!(*sockets.connected.lock().unwrap(), [(locator, 0x0083)]);
        assert_eq!(
            *contacts.roles.lock().unwrap(),
            [OrderedEventContactRole::Initiator]
        );
        assert_eq!(*contacts.peers.lock().unwrap(), [[0x22; 32]]);
    }

    #[tokio::test]
    async fn below_floor_inbound_is_rejected_then_exact_mission_peer_is_admitted() {
        let config = config_with_ids([0x22; 32], [0x11; 32]);
        let locator =
            crate::CanonicalLocator::new(Address::new([2, 0, 0, 0, 0, 9]), AddressType::LeRandom)
                .unwrap();
        let record = AsterRosterBeaconV1::encode(
            0x0083,
            [0x55; 16],
            config.discovery_credentials(),
            Instant::now(),
        )
        .unwrap();
        let (accept_sender, accept_receiver) = mpsc::channel(2);
        let sockets = Arc::new(InboundSockets {
            accepted: tokio::sync::Mutex::new(accept_receiver),
            connected: AtomicU8::new(0),
        });
        let scan_started = Arc::new(Notify::new());
        let discovery = Arc::new(FakeDiscovery {
            events: Arc::new(Mutex::new(Vec::new())),
            advertisements: Arc::new(Mutex::new(Vec::new())),
            scan_started: scan_started.clone(),
            observation_sender: Mutex::new(None),
        });
        let contacts = Arc::new(NotifyingAdmission {
            roles: Mutex::new(Vec::new()),
            peers: Mutex::new(Vec::new()),
            admitted: Notify::new(),
        });
        let cancellation = LifecycleCancellation::new();
        let task_cancellation = cancellation.clone();
        let task_discovery = discovery.clone();
        let task_contacts = contacts.clone();
        let task = tokio::spawn(async move {
            run_available_epoch(
                Arc::new(config),
                sockets,
                task_discovery,
                Arc::new(FixedNonce([0x33; 16])),
                task_contacts,
                EpochSignals::default(),
                task_cancellation,
            )
            .await
        });

        scan_started.notified().await;
        let observation_sender = discovery
            .observation_sender
            .lock()
            .unwrap()
            .as_ref()
            .unwrap()
            .clone();
        observation_sender
            .send(
                DiscoveryObservation::new(locator.address(), locator.address_type(), &record)
                    .unwrap(),
            )
            .await
            .unwrap();
        let (below_floor, _peer) = tokio::io::duplex(4096);
        accept_sender
            .send(
                SocketOpen::with_observed_mtu(Box::new(below_floor), 22, 23)
                    .map(|opened| (AcceptedSocket::ready(opened), locator)),
            )
            .await
            .unwrap();
        let (stream, _peer) = tokio::io::duplex(4096);
        accept_sender
            .send(
                SocketOpen::with_observed_mtu(Box::new(stream), 128, 96)
                    .map(|opened| (AcceptedSocket::ready(opened), locator)),
            )
            .await
            .unwrap();

        contacts.admitted.notified().await;
        cancellation.cancel();
        task.await.unwrap().unwrap();

        assert_eq!(
            *contacts.roles.lock().unwrap(),
            [OrderedEventContactRole::Responder]
        );
        assert_eq!(*contacts.peers.lock().unwrap(), [[0x11; 32]]);
    }

    #[tokio::test(start_paused = true)]
    async fn scan_owner_runs_ten_seconds_then_remains_idle_until_epoch_rotation() {
        let events = Arc::new(Mutex::new(Vec::new()));
        let scan_started = Arc::new(Notify::new());
        let discovery = Arc::new(FakeDiscovery {
            events: events.clone(),
            advertisements: Arc::new(Mutex::new(Vec::new())),
            scan_started: scan_started.clone(),
            observation_sender: Mutex::new(None),
        });
        let socket_events = events.clone();
        let task = tokio::spawn(async move {
            run_available_epoch(
                Arc::new(config()),
                Arc::new(FakeSockets {
                    events: socket_events,
                }),
                discovery,
                Arc::new(SequenceNonce(AtomicU8::new(0x33))),
                recording_admission(),
                EpochSignals::default(),
                LifecycleCancellation::new(),
            )
            .await
        });

        scan_started.notified().await;
        tokio::time::advance(Duration::from_secs(10)).await;
        tokio::task::yield_now().await;
        assert_eq!(
            events
                .lock()
                .unwrap()
                .iter()
                .filter(|event| **event == "scan-stop")
                .count(),
            1
        );

        tokio::time::advance(Duration::from_secs(14)).await;
        tokio::task::yield_now().await;
        assert_eq!(
            events
                .lock()
                .unwrap()
                .iter()
                .filter(|event| **event == "scan")
                .count(),
            1
        );
        assert!(!task.is_finished());

        tokio::time::advance(Duration::from_secs(1)).await;
        tokio::task::yield_now().await;
        assert_eq!(
            events
                .lock()
                .unwrap()
                .iter()
                .filter(|event| **event == "scan")
                .count(),
            1
        );
        assert!(task.is_finished(), "rotation must end the current epoch");

        assert_eq!(
            task.await.unwrap().unwrap_err(),
            SupervisorError::Controller(DriverErrorKind::Transport)
        );
    }

    #[tokio::test(start_paused = true)]
    async fn credential_lease_expiry_ends_the_epoch_and_drains_owned_platform_work() {
        let events = Arc::new(Mutex::new(Vec::new()));
        let scan_started = Arc::new(Notify::new());
        let discovery = Arc::new(FakeDiscovery {
            events: events.clone(),
            advertisements: Arc::new(Mutex::new(Vec::new())),
            scan_started: scan_started.clone(),
            observation_sender: Mutex::new(None),
        });
        let sockets = Arc::new(FakeSockets {
            events: events.clone(),
        });
        let task = tokio::spawn(async move {
            run_available_epoch(
                Arc::new(config_with_ids_and_lease(
                    [0x11; 32],
                    [0x22; 32],
                    Duration::from_secs(1),
                )),
                sockets,
                discovery,
                Arc::new(FixedNonce([0x33; 16])),
                recording_admission(),
                EpochSignals::default(),
                LifecycleCancellation::new(),
            )
            .await
        });

        scan_started.notified().await;
        tokio::task::yield_now().await;
        tokio::time::advance(Duration::from_secs(1)).await;
        let error = task.await.unwrap().unwrap_err();

        assert_eq!(
            error,
            SupervisorError::Controller(DriverErrorKind::Unavailable)
        );
        assert_eq!(
            *events.lock().unwrap(),
            [
                "bind",
                "advertise",
                "scan",
                "scan-stop",
                "advertisement-release"
            ]
        );
    }

    #[tokio::test(start_paused = true)]
    async fn credential_expiry_forces_owner_loss_when_platform_stop_is_stalled() {
        let events = Arc::new(Mutex::new(Vec::new()));
        let owner_loss_forced = Arc::new(AtomicU8::new(0));
        let scan_started = Arc::new(Notify::new());
        let discovery = Arc::new(BarrierDiscovery {
            events: events.clone(),
            advertisement_release_completed: None,
            advertisement_terminated: Arc::new(Notify::new()),
            scan_started: scan_started.clone(),
            owner_loss_forced: owner_loss_forced.clone(),
            observation_sender: Mutex::new(None),
        });
        let task = tokio::spawn(run_available_epoch(
            Arc::new(config_with_ids_and_lease(
                [0x11; 32],
                [0x22; 32],
                Duration::from_secs(1),
            )),
            Arc::new(FakeSockets {
                events: events.clone(),
            }),
            discovery,
            Arc::new(FixedNonce([0x33; 16])),
            recording_admission(),
            EpochSignals::default(),
            LifecycleCancellation::new(),
        ));

        scan_started.notified().await;
        tokio::task::yield_now().await;
        tokio::time::advance(Duration::from_secs(1)).await;
        tokio::task::yield_now().await;

        let outcome = timeout(Duration::from_secs(6), task)
            .await
            .expect("credential expiry must bound cleanup")
            .unwrap()
            .unwrap_err();
        assert_eq!(owner_loss_forced.load(Ordering::Acquire), 1);
        assert_eq!(
            outcome,
            SupervisorError::Controller(DriverErrorKind::Unavailable),
            "events: {:?}",
            *events.lock().unwrap()
        );
    }

    #[tokio::test(start_paused = true)]
    async fn cancellation_forces_owner_loss_when_platform_stop_is_stalled() {
        let events = Arc::new(Mutex::new(Vec::new()));
        let owner_loss_forced = Arc::new(AtomicU8::new(0));
        let scan_started = Arc::new(Notify::new());
        let discovery = Arc::new(BarrierDiscovery {
            events: events.clone(),
            advertisement_release_completed: None,
            advertisement_terminated: Arc::new(Notify::new()),
            scan_started: scan_started.clone(),
            owner_loss_forced: owner_loss_forced.clone(),
            observation_sender: Mutex::new(None),
        });
        let cancellation = LifecycleCancellation::new();
        let task_cancellation = cancellation.clone();
        let task = tokio::spawn(run_available_epoch(
            Arc::new(config()),
            Arc::new(FakeSockets {
                events: events.clone(),
            }),
            discovery,
            Arc::new(FixedNonce([0x33; 16])),
            recording_admission(),
            EpochSignals::default(),
            task_cancellation,
        ));

        scan_started.notified().await;
        tokio::task::yield_now().await;
        cancellation.cancel();
        let outcome = timeout(OWNED_STOP_DEADLINE + Duration::from_secs(1), task)
            .await
            .expect("cancelled epoch cleanup must remain bounded")
            .unwrap()
            .unwrap_err();

        assert_eq!(outcome, SupervisorError::PlatformCleanupUnconfirmed);
        assert_eq!(owner_loss_forced.load(Ordering::Acquire), 1);
    }

    #[tokio::test(start_paused = true)]
    async fn rotation_releases_the_local_advertisement_and_ends_the_epoch() {
        let events = Arc::new(Mutex::new(Vec::new()));
        let advertisements = Arc::new(Mutex::new(Vec::new()));
        let scan_started = Arc::new(Notify::new());
        let discovery = Arc::new(FakeDiscovery {
            events: events.clone(),
            advertisements: advertisements.clone(),
            scan_started: scan_started.clone(),
            observation_sender: Mutex::new(None),
        });
        let sockets = Arc::new(FakeSockets {
            events: events.clone(),
        });
        let cancellation = LifecycleCancellation::new();
        let task_cancellation = cancellation.clone();
        let task = tokio::spawn(async move {
            run_available_epoch(
                Arc::new(config()),
                sockets,
                discovery,
                Arc::new(SequenceNonce(AtomicU8::new(0x33))),
                recording_admission(),
                EpochSignals::default(),
                task_cancellation,
            )
            .await
        });

        scan_started.notified().await;
        tokio::time::advance(Duration::from_secs(25)).await;
        tokio::task::yield_now().await;

        assert!(
            task.is_finished(),
            "rotation must leave replacement registration to a fresh epoch"
        );
        assert_eq!(
            *events.lock().unwrap(),
            [
                "bind",
                "advertise",
                "scan",
                "scan-stop",
                "advertisement-release"
            ]
        );
        {
            let records = advertisements.lock().unwrap();
            assert_eq!(records.len(), 1);
        }

        assert_eq!(
            task.await.unwrap().unwrap_err(),
            SupervisorError::Controller(DriverErrorKind::Transport)
        );
        cancellation.cancel();
    }

    #[tokio::test(start_paused = true)]
    async fn timed_out_rotation_release_forces_owner_loss_without_replacement() {
        let events = Arc::new(Mutex::new(Vec::new()));
        let owner_loss_forced = Arc::new(AtomicU8::new(0));
        let scan_started = Arc::new(Notify::new());
        let discovery = Arc::new(BarrierDiscovery {
            events: events.clone(),
            advertisement_release_completed: None,
            advertisement_terminated: Arc::new(Notify::new()),
            scan_started: scan_started.clone(),
            owner_loss_forced: owner_loss_forced.clone(),
            observation_sender: Mutex::new(None),
        });
        let sockets = Arc::new(FakeSockets {
            events: events.clone(),
        });
        let task = tokio::spawn(async move {
            run_available_epoch(
                Arc::new(config()),
                sockets,
                discovery,
                Arc::new(SequenceNonce(AtomicU8::new(0x33))),
                recording_admission(),
                EpochSignals::default(),
                LifecycleCancellation::new(),
            )
            .await
        });

        scan_started.notified().await;
        tokio::time::advance(Duration::from_secs(25)).await;
        tokio::task::yield_now().await;
        tokio::time::advance(Duration::from_secs(5)).await;
        tokio::task::yield_now().await;

        assert_eq!(
            *events.lock().unwrap(),
            [
                "bind",
                "advertise",
                "scan",
                "scan-stop",
                "advertisement-release-started"
            ]
        );

        assert_eq!(owner_loss_forced.load(Ordering::Acquire), 1);
        assert!(task.is_finished(), "owner loss must release the epoch");
        assert_eq!(
            task.await.unwrap(),
            Err(SupervisorError::PlatformCleanupUnconfirmed)
        );
        assert_eq!(
            events
                .lock()
                .unwrap()
                .iter()
                .filter(|event| **event == "advertise")
                .count(),
            1
        );
    }

    #[tokio::test(start_paused = true)]
    async fn local_release_before_deadline_ends_epoch_without_forced_owner_loss() {
        let events = Arc::new(Mutex::new(Vec::new()));
        let release_completed = Arc::new(Notify::new());
        let owner_loss_forced = Arc::new(AtomicU8::new(0));
        let scan_started = Arc::new(Notify::new());
        let discovery = Arc::new(BarrierDiscovery {
            events: events.clone(),
            advertisement_release_completed: Some(release_completed.clone()),
            advertisement_terminated: Arc::new(Notify::new()),
            scan_started: scan_started.clone(),
            owner_loss_forced: owner_loss_forced.clone(),
            observation_sender: Mutex::new(None),
        });
        let sockets = Arc::new(FakeSockets {
            events: events.clone(),
        });
        let task = tokio::spawn(async move {
            run_available_epoch(
                Arc::new(config()),
                sockets,
                discovery,
                Arc::new(SequenceNonce(AtomicU8::new(0x33))),
                recording_admission(),
                EpochSignals::default(),
                LifecycleCancellation::new(),
            )
            .await
        });

        scan_started.notified().await;
        tokio::time::advance(Duration::from_secs(25)).await;
        tokio::task::yield_now().await;
        tokio::time::advance(Duration::from_secs(4)).await;
        release_completed.notify_one();
        tokio::task::yield_now().await;
        tokio::task::yield_now().await;

        assert_eq!(
            events
                .lock()
                .unwrap()
                .iter()
                .filter(|event| **event == "advertise")
                .count(),
            1
        );
        assert_eq!(owner_loss_forced.load(Ordering::Acquire), 0);
        assert!(task.is_finished(), "local release must end the epoch");

        assert_eq!(
            task.await.unwrap().unwrap_err(),
            SupervisorError::Controller(DriverErrorKind::Transport)
        );
    }

    async fn send_automatic_observation(
        discovery: &FakeDiscovery,
        config: &ValidatedRosteredSupervisorConfig,
        locator: crate::CanonicalLocator,
    ) {
        send_automatic_observation_with_nonce(discovery, config, locator, [0x73; 16]).await;
    }

    async fn send_automatic_observation_with_nonce(
        discovery: &FakeDiscovery,
        config: &ValidatedRosteredSupervisorConfig,
        locator: crate::CanonicalLocator,
        nonce: [u8; 16],
    ) {
        let record = AsterRosterBeaconV1::encode(
            0x0083,
            nonce,
            config.discovery_credentials(),
            Instant::now(),
        )
        .unwrap();
        let sender = discovery
            .observation_sender
            .lock()
            .unwrap()
            .as_ref()
            .unwrap()
            .clone();
        sender
            .send(
                DiscoveryObservation::new(locator.address(), locator.address_type(), &record)
                    .unwrap(),
            )
            .await
            .unwrap();
    }

    #[tokio::test]
    async fn automatic_outbound_waits_for_the_leased_contact_to_close() {
        let config = Arc::new(config());
        let locator = crate::CanonicalLocator::new(
            Address::new([2, 0, 0, 0, 0, 0x72]),
            AddressType::LeRandom,
        )
        .unwrap();
        let sockets = Arc::new(ConnectingSockets {
            connected: Mutex::new(Vec::new()),
        });
        let discovery = Arc::new(FakeDiscovery {
            events: Arc::new(Mutex::new(Vec::new())),
            advertisements: Arc::new(Mutex::new(Vec::new())),
            scan_started: Arc::new(Notify::new()),
            observation_sender: Mutex::new(None),
        });
        let (backend, port) = automatic_btle_carrier_channel(crate::BtleAvailability::Unavailable(
            crate::AvailabilityReason::Activating,
        ));
        let readiness_publisher = backend.readiness_publisher();
        let (availability_updates, _availability) = watch::channel(
            crate::BtleAvailability::Unavailable(crate::AvailabilityReason::Activating),
        );
        let publisher = Arc::new(AdapterAvailabilityPublisher::automatic(
            readiness_publisher,
            availability_updates,
            crate::BtleOperatorOutput::discard(),
            FixedRole::Initiator,
        ));
        let (available_started, _available_observed) = oneshot::channel();
        let (mut readiness, outbound, _inbound) = port.into_parts();
        let outbound = Arc::new(outbound);
        let cancellation = LifecycleCancellation::new();
        let task = tokio::spawn(run_automatic_available_epoch(
            config.clone(),
            sockets.clone(),
            discovery.clone(),
            Arc::new(FixedNonce([0x32; 16])),
            backend,
            EpochSignals::with_publisher(publisher, available_started),
            cancellation.clone(),
        ));

        discovery.scan_started.notified().await;
        send_automatic_observation(&discovery, config.as_ref(), locator).await;
        assert_eq!(
            readiness.changed().await.unwrap().availability(),
            crate::BtleAvailability::Available
        );
        let first = outbound
            .open(crate::OpenCancellation::new())
            .await
            .unwrap()
            .into_contact();
        assert_eq!(sockets.connected.lock().unwrap().len(), 1);

        let second = outbound.open(crate::OpenCancellation::new());
        tokio::pin!(second);
        assert!(futures::poll!(&mut second).is_pending());
        assert_eq!(sockets.connected.lock().unwrap().len(), 1);

        first.close();
        let second = second.await.unwrap().into_contact();
        assert_eq!(sockets.connected.lock().unwrap().len(), 2);
        second.close();

        cancellation.cancel();
        task.await.unwrap().unwrap();
    }

    #[tokio::test]
    async fn automatic_open_failure_revokes_readiness_when_no_candidate_remains() {
        let config = Arc::new(config());
        let locator = crate::CanonicalLocator::new(
            Address::new([2, 0, 0, 0, 0, 0x74]),
            AddressType::LeRandom,
        )
        .unwrap();
        let sockets = Arc::new(FailingConnectSockets {
            connected: AtomicU8::new(0),
            kind: DriverErrorKind::Transport,
        });
        let discovery = Arc::new(FakeDiscovery {
            events: Arc::new(Mutex::new(Vec::new())),
            advertisements: Arc::new(Mutex::new(Vec::new())),
            scan_started: Arc::new(Notify::new()),
            observation_sender: Mutex::new(None),
        });
        let (backend, port) = automatic_btle_carrier_channel(crate::BtleAvailability::Unavailable(
            crate::AvailabilityReason::Activating,
        ));
        let readiness_publisher = backend.readiness_publisher();
        let (availability_updates, _availability) = watch::channel(
            crate::BtleAvailability::Unavailable(crate::AvailabilityReason::Activating),
        );
        let publisher = Arc::new(AdapterAvailabilityPublisher::automatic(
            readiness_publisher,
            availability_updates,
            crate::BtleOperatorOutput::discard(),
            FixedRole::Initiator,
        ));
        let (available_started, _available_observed) = oneshot::channel();
        let (mut readiness, outbound, _inbound) = port.into_parts();
        let cancellation = LifecycleCancellation::new();
        let task = tokio::spawn(run_automatic_available_epoch(
            config.clone(),
            sockets.clone(),
            discovery.clone(),
            Arc::new(FixedNonce([0x34; 16])),
            backend,
            EpochSignals::with_publisher(publisher, available_started),
            cancellation.clone(),
        ));

        discovery.scan_started.notified().await;
        send_automatic_observation(&discovery, config.as_ref(), locator).await;
        let available = readiness.changed().await.unwrap();
        assert_eq!(available.availability(), crate::BtleAvailability::Available);

        let Err(error) = outbound.open(crate::OpenCancellation::new()).await else {
            panic!("failed candidate must not produce a carrier");
        };
        assert_eq!(error.kind(), DriverErrorKind::Transport);
        let unavailable = tokio::time::timeout(Duration::from_secs(1), readiness.changed()).await;

        cancellation.cancel();
        task.await.unwrap().unwrap();
        assert_eq!(sockets.connected.load(Ordering::Acquire), 1);
        assert_eq!(
            unavailable
                .expect("last candidate failure must revoke readiness")
                .expect("readiness owner remains active")
                .availability(),
            crate::BtleAvailability::Unavailable(crate::AvailabilityReason::BluezUnavailable)
        );
    }

    #[tokio::test(start_paused = true)]
    async fn automatic_retry_suppression_does_not_republish_readiness_or_park_open() {
        let config = Arc::new(config());
        let locator = crate::CanonicalLocator::new(
            Address::new([2, 0, 0, 0, 0, 0x75]),
            AddressType::LeRandom,
        )
        .unwrap();
        let sockets = Arc::new(FailingConnectSockets {
            connected: AtomicU8::new(0),
            kind: DriverErrorKind::Transport,
        });
        let discovery = Arc::new(FakeDiscovery {
            events: Arc::new(Mutex::new(Vec::new())),
            advertisements: Arc::new(Mutex::new(Vec::new())),
            scan_started: Arc::new(Notify::new()),
            observation_sender: Mutex::new(None),
        });
        let (backend, port) = automatic_btle_carrier_channel(crate::BtleAvailability::Unavailable(
            crate::AvailabilityReason::Activating,
        ));
        let readiness_publisher = backend.readiness_publisher();
        let (availability_updates, _availability) = watch::channel(
            crate::BtleAvailability::Unavailable(crate::AvailabilityReason::Activating),
        );
        let publisher = Arc::new(AdapterAvailabilityPublisher::automatic(
            readiness_publisher,
            availability_updates,
            crate::BtleOperatorOutput::discard(),
            FixedRole::Initiator,
        ));
        let (available_started, _available_observed) = oneshot::channel();
        let (mut readiness, outbound, _inbound) = port.into_parts();
        let cancellation = LifecycleCancellation::new();
        let task = tokio::spawn(run_automatic_available_epoch(
            config.clone(),
            sockets.clone(),
            discovery.clone(),
            Arc::new(FixedNonce([0x35; 16])),
            backend,
            EpochSignals::with_publisher(publisher, available_started),
            cancellation.clone(),
        ));

        discovery.scan_started.notified().await;
        send_automatic_observation_with_nonce(&discovery, config.as_ref(), locator, [0x74; 16])
            .await;
        assert_eq!(
            readiness.changed().await.unwrap().availability(),
            crate::BtleAvailability::Available
        );
        let Err(first_open) = outbound.open(crate::OpenCancellation::new()).await else {
            panic!("the failing carrier must not open");
        };
        assert_eq!(first_open.kind(), DriverErrorKind::Transport);
        assert!(matches!(
            readiness.changed().await.unwrap().availability(),
            crate::BtleAvailability::Unavailable(_)
        ));

        tokio::time::advance(SCAN_IDLE_INTERVAL).await;
        discovery.scan_started.notified().await;
        send_automatic_observation_with_nonce(&discovery, config.as_ref(), locator, [0x75; 16])
            .await;
        tokio::task::yield_now().await;
        assert!(
            tokio::time::timeout(Duration::from_millis(20), readiness.changed())
                .await
                .is_err(),
            "a retry-suppressed candidate must not restore readiness"
        );
        let open = tokio::time::timeout(
            Duration::from_millis(100),
            outbound.open(crate::OpenCancellation::new()),
        )
        .await
        .expect("an open with no selectable candidate must fail promptly");
        let Err(open) = open else {
            panic!("a retry-suppressed candidate must not open");
        };
        assert_eq!(open.kind(), DriverErrorKind::Unavailable);

        cancellation.cancel();
        task.await.unwrap().unwrap();
    }

    #[tokio::test]
    async fn automatic_inbound_delivers_a_carrier_without_linux_mission_admission() {
        let config = Arc::new(config());
        let locator = crate::CanonicalLocator::new(
            Address::new([2, 0, 0, 0, 0, 0x71]),
            AddressType::LeRandom,
        )
        .unwrap();
        let (accepted, accepted_contacts) = mpsc::channel(1);
        let sockets = Arc::new(InboundSockets {
            accepted: tokio::sync::Mutex::new(accepted_contacts),
            connected: AtomicU8::new(0),
        });
        let discovery = Arc::new(FakeDiscovery {
            events: Arc::new(Mutex::new(Vec::new())),
            advertisements: Arc::new(Mutex::new(Vec::new())),
            scan_started: Arc::new(Notify::new()),
            observation_sender: Mutex::new(None),
        });
        let (backend, port) = automatic_btle_carrier_channel(crate::BtleAvailability::Unavailable(
            crate::AvailabilityReason::Activating,
        ));
        let (_readiness, _outbound, mut inbound) = port.into_parts();
        let cancellation = LifecycleCancellation::new();
        let task = tokio::spawn(run_automatic_available_epoch(
            config.clone(),
            sockets,
            discovery.clone(),
            Arc::new(FixedNonce([0x31; 16])),
            backend,
            EpochSignals::default(),
            cancellation.clone(),
        ));

        discovery.scan_started.notified().await;
        send_automatic_observation(&discovery, config.as_ref(), locator).await;
        let (stream, _peer) = tokio::io::duplex(4096);
        accepted
            .send(
                SocketOpen::with_observed_mtu(Box::new(stream), 128, 96)
                    .map(|opened| (AcceptedSocket::ready(opened), locator)),
            )
            .await
            .unwrap();

        let contact = inbound.recv().await.unwrap().into_contact();
        assert_eq!(contact.peer_evidence().stable_carrier_id(), None);
        contact.close();
        cancellation.cancel();
        task.await.unwrap().unwrap();
    }
}
