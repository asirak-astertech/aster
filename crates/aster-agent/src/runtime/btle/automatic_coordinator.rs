use super::{BtleRuntimeOwnerError, RuntimeCompletionOnDrop};
use aster_ble_linux::{
    AutomaticBtleCarrierInbound, AutomaticBtleCarrierOutbound, AutomaticBtleCarrierPort,
    AutomaticBtleCarrierReadiness, AutomaticBtleCarrierReadinessMonitor, BtleAvailability,
    DriverErrorKind, OpenCancellation,
};
use aster_contact::OrderedContact;
use aster_mesh::NodeId;
use aster_node::{
    EventAdapterControl, EventAdapterRegistration, EventAdapterSnapshot, EventAdapterState,
    EventAttemptReceiver, EventOutboundAttempt, EventTransportKind, MissionPeerExpectation,
    OrderedEventContactHandle, OrderedEventContactRole, UnauthenticatedCarrierOpenFailure,
};
use std::time::Duration;
use std::{
    future::Future,
    pin::Pin,
    sync::{Arc, Mutex},
};
use tokio::{sync::watch, task::JoinHandle};

pub(super) const INITIAL_EVENT_AVAILABILITY_EPOCH: u64 = 0;
const CONTACT_DRAIN_DEADLINE: Duration = Duration::from_secs(5);
const COORDINATOR_DRAIN_DEADLINE: Duration = Duration::from_secs(6);

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct ReadinessMappingError;

struct ReadinessEpochMapping {
    linux_generation: u64,
    linux_availability: BtleAvailability,
    event_epoch: u64,
    event_available: bool,
    parked: bool,
}

impl ReadinessEpochMapping {
    const fn new() -> Self {
        Self {
            linux_generation: 0,
            linux_availability: BtleAvailability::Unavailable(
                aster_ble_linux::AvailabilityReason::BluezUnavailable,
            ),
            event_epoch: INITIAL_EVENT_AVAILABILITY_EPOCH,
            event_available: false,
            parked: false,
        }
    }

    fn observe(
        &mut self,
        generation: u64,
        availability: BtleAvailability,
        can_originate: bool,
    ) -> Result<Option<(u64, bool)>, ReadinessMappingError> {
        if generation == self.linux_generation {
            return if self.linux_availability == availability {
                Ok(None)
            } else {
                Err(ReadinessMappingError)
            };
        }
        if self.linux_generation.checked_add(1) != Some(generation) {
            return Err(ReadinessMappingError);
        }
        self.linux_generation = generation;
        self.linux_availability = availability;
        let available =
            !self.parked && can_originate && availability == BtleAvailability::Available;
        self.transition_event(available)
    }

    fn park_unavailable(&mut self) -> Result<Option<(u64, bool)>, ReadinessMappingError> {
        self.parked = true;
        self.transition_event(false)
    }

    fn transition_event(
        &mut self,
        available: bool,
    ) -> Result<Option<(u64, bool)>, ReadinessMappingError> {
        if available == self.event_available {
            return Ok(None);
        }
        let epoch = self
            .event_epoch
            .checked_add(1)
            .ok_or(ReadinessMappingError)?;
        self.event_epoch = epoch;
        self.event_available = available;
        Ok(Some((epoch, available)))
    }
}

struct AvailabilityPublication {
    control: EventAdapterControl,
    configured_priority: u16,
    can_originate: bool,
    mapping: Mutex<ReadinessEpochMapping>,
}

impl AvailabilityPublication {
    fn observe(
        &self,
        readiness: AutomaticBtleCarrierReadiness,
    ) -> Result<(), BtleRuntimeOwnerError> {
        let mut mapping = self
            .mapping
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let transition = mapping
            .observe(
                readiness.generation(),
                readiness.availability(),
                self.can_originate,
            )
            .map_err(|_| BtleRuntimeOwnerError::Cleanup)?;
        self.publish_transition(transition)
    }

    fn park_unavailable(&self) -> Result<(), BtleRuntimeOwnerError> {
        let mut mapping = self
            .mapping
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let transition = mapping
            .park_unavailable()
            .map_err(|_| BtleRuntimeOwnerError::Cleanup)?;
        self.publish_transition(transition)
    }

    fn publish_transition(
        &self,
        transition: Option<(u64, bool)>,
    ) -> Result<(), BtleRuntimeOwnerError> {
        let Some((epoch, available)) = transition else {
            return Ok(());
        };
        let state = if available {
            EventAdapterState::Available
        } else {
            EventAdapterState::Unavailable
        };
        self.control
            .publish_availability(EventAdapterSnapshot::new(
                EventTransportKind::BLE_L2CAP_V1,
                epoch,
                state,
                true,
                self.configured_priority,
            ))
            .then_some(())
            .ok_or(BtleRuntimeOwnerError::Cleanup)
    }
}

pub(super) struct AutomaticEventCoordinator {
    cancellation: watch::Sender<bool>,
    completion: watch::Receiver<bool>,
    availability: Arc<AvailabilityPublication>,
    task: JoinHandle<Result<(), BtleRuntimeOwnerError>>,
}

impl AutomaticEventCoordinator {
    pub(super) fn start(
        port: AutomaticBtleCarrierPort,
        contacts: OrderedEventContactHandle,
        registration: EventAdapterRegistration,
        mission: NodeId,
        peer: NodeId,
        can_originate: bool,
    ) -> Result<Self, BtleRuntimeOwnerError> {
        let (snapshot, control, attempts) = validate_registration(registration)?;
        let availability = Arc::new(AvailabilityPublication {
            control,
            configured_priority: snapshot.configured_priority(),
            can_originate,
            mapping: Mutex::new(ReadinessEpochMapping::new()),
        });
        let (readiness, outbound, inbound) = port.into_parts();
        let (cancellation, cancellation_requested) = watch::channel(false);
        let (completion_updates, completion) = watch::channel(false);
        let task_availability = Arc::clone(&availability);
        let task = tokio::spawn(async move {
            let _completion = RuntimeCompletionOnDrop(completion_updates);
            let result = run(
                readiness,
                outbound,
                inbound,
                attempts,
                contacts,
                mission,
                peer,
                Arc::clone(&task_availability),
                cancellation_requested,
            )
            .await;
            task_availability.park_unavailable().and(result)
        });
        Ok(Self {
            cancellation,
            completion,
            availability,
            task,
        })
    }

    pub(super) fn completion(&self) -> watch::Receiver<bool> {
        self.completion.clone()
    }

    pub(super) fn cancel(&self) {
        self.cancellation.send_replace(true);
    }

    pub(super) fn park_unavailable(&self) -> Result<(), BtleRuntimeOwnerError> {
        self.availability.park_unavailable()
    }

    pub(super) async fn shutdown(self) -> Result<(), BtleRuntimeOwnerError> {
        self.cancel();
        self.task
            .await
            .map_err(|_| BtleRuntimeOwnerError::Cleanup)?
    }
}

fn validate_registration(
    registration: EventAdapterRegistration,
) -> Result<
    (
        EventAdapterSnapshot,
        EventAdapterControl,
        EventAttemptReceiver,
    ),
    BtleRuntimeOwnerError,
> {
    let snapshot = registration.initial_snapshot();
    if snapshot.kind() != EventTransportKind::BLE_L2CAP_V1
        || snapshot.availability_epoch() != INITIAL_EVENT_AVAILABILITY_EPOCH
        || snapshot.state() != EventAdapterState::Unavailable
        || !snapshot.event_capable()
    {
        return Err(BtleRuntimeOwnerError::Startup);
    }
    Ok(registration.into_parts())
}

#[allow(clippy::too_many_arguments)]
async fn run(
    readiness: AutomaticBtleCarrierReadinessMonitor,
    outbound: AutomaticBtleCarrierOutbound,
    inbound: AutomaticBtleCarrierInbound,
    attempts: EventAttemptReceiver,
    contacts: OrderedEventContactHandle,
    mission: NodeId,
    peer: NodeId,
    availability: Arc<AvailabilityPublication>,
    cancellation: watch::Receiver<bool>,
) -> Result<(), BtleRuntimeOwnerError> {
    let (stop, stop_requested) = watch::channel(false);
    let mut tasks = tokio::task::JoinSet::new();
    tasks.spawn(run_readiness(
        readiness,
        availability,
        stop_requested.clone(),
    ));
    tasks.spawn(run_outbound(
        outbound,
        attempts,
        mission,
        peer,
        stop_requested.clone(),
    ));
    tasks.spawn(run_inbound(inbound, contacts, peer, stop_requested));

    let first = tokio::select! {
        result = tasks.join_next() => joined_loop_result(result),
        () = wait_for_cancellation(cancellation) => Ok(()),
    };
    stop.send_replace(true);
    let remaining = tokio::time::timeout(COORDINATOR_DRAIN_DEADLINE, drain_remaining_tasks(tasks))
        .await
        .map_err(|_| BtleRuntimeOwnerError::Cleanup)?;
    first.and(remaining)
}

async fn drain_remaining_tasks(
    mut tasks: tokio::task::JoinSet<Result<(), BtleRuntimeOwnerError>>,
) -> Result<(), BtleRuntimeOwnerError> {
    let mut first_error = None;
    while let Some(result) = tasks.join_next().await {
        if let Err(error) = joined_loop_result(Some(result)) {
            first_error.get_or_insert(error);
        }
    }
    first_error.map_or(Ok(()), Err)
}

fn joined_loop_result(
    result: Option<Result<Result<(), BtleRuntimeOwnerError>, tokio::task::JoinError>>,
) -> Result<(), BtleRuntimeOwnerError> {
    result
        .ok_or(BtleRuntimeOwnerError::Cleanup)?
        .map_err(|_| BtleRuntimeOwnerError::Cleanup)?
}

async fn run_readiness(
    mut readiness: AutomaticBtleCarrierReadinessMonitor,
    availability: Arc<AvailabilityPublication>,
    cancellation: watch::Receiver<bool>,
) -> Result<(), BtleRuntimeOwnerError> {
    availability.observe(readiness.current())?;
    loop {
        tokio::select! {
            biased;
            () = wait_for_cancellation(cancellation.clone()) => return Ok(()),
            observation = readiness.changed() => {
                let Some(observation) = observation else {
                    return Ok(());
                };
                availability.observe(observation)?;
            }
        }
    }
}

async fn run_outbound(
    outbound: AutomaticBtleCarrierOutbound,
    mut attempts: EventAttemptReceiver,
    mission: NodeId,
    peer: NodeId,
    cancellation: watch::Receiver<bool>,
) -> Result<(), BtleRuntimeOwnerError> {
    loop {
        let attempt = tokio::select! {
            biased;
            () = wait_for_cancellation(cancellation.clone()) => return Ok(()),
            attempt = attempts.recv() => attempt.ok_or(BtleRuntimeOwnerError::Cleanup)?,
        };
        run_outbound_attempt(&outbound, attempt, mission, peer, cancellation.clone()).await?;
    }
}

async fn run_outbound_attempt(
    outbound: &AutomaticBtleCarrierOutbound,
    mut attempt: EventOutboundAttempt,
    mission: NodeId,
    peer: NodeId,
    cancellation: watch::Receiver<bool>,
) -> Result<(), BtleRuntimeOwnerError> {
    if !attempt_matches_authority(
        attempt.transport_kind(),
        attempt.mission(),
        attempt.peer(),
        mission,
        peer,
    ) {
        let _ = attempt.cancel_carrier_open();
        return Err(BtleRuntimeOwnerError::Cleanup);
    }

    let open_cancellation = OpenCancellation::new();
    let open = outbound.open(open_cancellation.clone());
    tokio::pin!(open);
    let result = {
        let revocation = attempt.revocation_outcome();
        tokio::pin!(revocation);
        race_carrier_open(open.as_mut(), revocation.as_mut(), cancellation.clone()).await
    };
    match result {
        CarrierOpenRace::Revoked => {
            let drain = cancel_and_drain_carrier_open(&open_cancellation, open.as_mut()).await;
            attempt.finish_revoked();
            drain?;
        }
        CarrierOpenRace::Cancelled => {
            let drain = cancel_and_drain_carrier_open(&open_cancellation, open.as_mut()).await;
            let _ = attempt.cancel_carrier_open();
            drain?;
        }
        CarrierOpenRace::Opened(Ok(carrier)) => {
            let contact = carrier.into_contact();
            run_contact_to_completion(contact.clone(), attempt.run(contact), cancellation).await?;
        }
        CarrierOpenRace::Opened(Err(error)) => match classify_open_failure(error.kind()) {
            OpenFailureDisposition::Fatal => {
                let _ = attempt.cancel_carrier_open();
                return Err(BtleRuntimeOwnerError::Cleanup);
            }
            OpenFailureDisposition::Unavailable => {
                let _ = attempt.fail_carrier_open();
            }
            OpenFailureDisposition::TimedOut => {
                let _ = attempt
                    .fail_unauthenticated_carrier_open(UnauthenticatedCarrierOpenFailure::TimedOut);
            }
            OpenFailureDisposition::Cancelled => {
                let _ = attempt.cancel_carrier_open();
            }
            OpenFailureDisposition::Interrupted => {
                let _ = attempt.fail_unauthenticated_carrier_open(
                    UnauthenticatedCarrierOpenFailure::Interrupted,
                );
            }
        },
    }
    Ok(())
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum CarrierOpenRace<T> {
    Opened(T),
    Revoked,
    Cancelled,
}

async fn race_carrier_open<T, R>(
    mut open: Pin<&mut (impl Future<Output = T> + ?Sized)>,
    mut revocation: Pin<&mut (impl Future<Output = R> + ?Sized)>,
    cancellation: watch::Receiver<bool>,
) -> CarrierOpenRace<T> {
    tokio::select! {
        biased;
        _ = &mut revocation => CarrierOpenRace::Revoked,
        () = wait_for_cancellation(cancellation) => CarrierOpenRace::Cancelled,
        result = &mut open => CarrierOpenRace::Opened(result),
    }
}

async fn cancel_and_drain_carrier_open<T>(
    cancellation: &OpenCancellation,
    open: Pin<&mut (impl Future<Output = T> + ?Sized)>,
) -> Result<(), BtleRuntimeOwnerError> {
    cancellation.cancel();
    tokio::time::timeout(CONTACT_DRAIN_DEADLINE, open)
        .await
        .map(|_| ())
        .map_err(|_| BtleRuntimeOwnerError::Cleanup)
}

fn attempt_matches_authority(
    kind: EventTransportKind,
    mission: NodeId,
    peer: NodeId,
    expected_mission: NodeId,
    expected_peer: NodeId,
) -> bool {
    kind == EventTransportKind::BLE_L2CAP_V1 && mission == expected_mission && peer == expected_peer
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum OpenFailureDisposition {
    Fatal,
    Unavailable,
    TimedOut,
    Cancelled,
    Interrupted,
}

const fn classify_open_failure(kind: DriverErrorKind) -> OpenFailureDisposition {
    match kind {
        DriverErrorKind::Configuration => OpenFailureDisposition::Fatal,
        DriverErrorKind::Unavailable => OpenFailureDisposition::Unavailable,
        DriverErrorKind::Timeout => OpenFailureDisposition::TimedOut,
        DriverErrorKind::Cancelled => OpenFailureDisposition::Cancelled,
        DriverErrorKind::Transport | DriverErrorKind::PeerRejected => {
            OpenFailureDisposition::Interrupted
        }
    }
}

async fn run_inbound(
    mut inbound: AutomaticBtleCarrierInbound,
    contacts: OrderedEventContactHandle,
    peer: NodeId,
    cancellation: watch::Receiver<bool>,
) -> Result<(), BtleRuntimeOwnerError> {
    loop {
        let carrier = tokio::select! {
            biased;
            () = wait_for_cancellation(cancellation.clone()) => return Ok(()),
            carrier = inbound.recv() => {
                let Some(carrier) = carrier else {
                    return Ok(());
                };
                carrier
            },
        };
        let contact = carrier.into_contact();
        let expectation = inbound_peer_expectation(contact.as_ref(), peer);
        let admission = contacts.run(
            OrderedEventContactRole::Responder,
            contact.clone(),
            expectation,
        );
        run_contact_to_completion(contact, admission, cancellation.clone()).await?;
    }
}

fn inbound_peer_expectation(contact: &dyn OrderedContact, peer: NodeId) -> MissionPeerExpectation {
    MissionPeerExpectation::new(contact.peer_evidence(), peer)
}

async fn run_contact_to_completion<T>(
    contact: Arc<dyn OrderedContact>,
    work: impl Future<Output = T>,
    cancellation: watch::Receiver<bool>,
) -> Result<(), BtleRuntimeOwnerError> {
    tokio::pin!(work);
    tokio::select! {
        biased;
        () = wait_for_cancellation(cancellation) => {
            contact.close();
            tokio::time::timeout(CONTACT_DRAIN_DEADLINE, &mut work)
                .await
                .map(|_| ())
                .map_err(|_| BtleRuntimeOwnerError::Cleanup)
        }
        _ = &mut work => {
            contact.close();
            Ok(())
        }
    }
}

async fn wait_for_cancellation(mut cancellation: watch::Receiver<bool>) {
    while !*cancellation.borrow_and_update() && cancellation.changed().await.is_ok() {}
}

#[cfg(test)]
mod tests {
    use super::*;
    use aster_ble_linux::AvailabilityReason;
    use aster_contact::{
        CarrierPeerEvidence, ContactFuture, ContactPreflight, ContactRequestHandler,
        TransientLocator,
    };
    use std::sync::atomic::{AtomicUsize, Ordering};
    use tokio::sync::Notify;

    struct ClosingContact {
        closes: AtomicUsize,
        closed: Notify,
    }

    impl ClosingContact {
        fn new() -> Arc<Self> {
            Arc::new(Self {
                closes: AtomicUsize::new(0),
                closed: Notify::new(),
            })
        }
    }

    impl OrderedContact for ClosingContact {
        fn peer_evidence(&self) -> CarrierPeerEvidence {
            CarrierPeerEvidence::UnauthenticatedLocator {
                transient_locator: TransientLocator::new(vec![1]).unwrap(),
            }
        }

        fn max_frame_bytes(&self) -> usize {
            1
        }

        fn request_with_total_limit<'a>(
            &'a self,
            _request: &'a [u8],
            _total_limit: usize,
        ) -> ContactFuture<'a, Vec<u8>> {
            Box::pin(std::future::pending())
        }

        fn request_with_total_limit_checked<'a>(
            &'a self,
            _request: &'a [u8],
            _total_limit: usize,
            _before_write: ContactPreflight<'a>,
        ) -> ContactFuture<'a, Vec<u8>> {
            Box::pin(std::future::pending())
        }

        fn respond_once_with_total_limit<'a>(
            &'a self,
            _total_limit: usize,
            _handler: ContactRequestHandler<'a>,
        ) -> ContactFuture<'a, bool> {
            Box::pin(std::future::pending())
        }

        fn finish_as_initiator(&self) -> ContactFuture<'_, ()> {
            Box::pin(std::future::pending())
        }

        fn finish_as_responder(&self) -> ContactFuture<'_, ()> {
            Box::pin(std::future::pending())
        }

        fn close(&self) {
            self.closes.fetch_add(1, Ordering::Relaxed);
            self.closed.notify_one();
        }
    }

    #[tokio::test]
    async fn cancellation_closes_and_drains_active_contact_work() {
        let contact = ClosingContact::new();
        let work_contact = Arc::clone(&contact);
        let (cancel, cancellation) = watch::channel(false);
        cancel.send_replace(true);
        let erased: Arc<dyn OrderedContact> = contact.clone();

        run_contact_to_completion(
            erased,
            async move { work_contact.closed.notified().await },
            cancellation,
        )
        .await
        .unwrap();

        assert_eq!(contact.closes.load(Ordering::Relaxed), 1);
    }

    #[tokio::test]
    async fn revocation_wins_a_simultaneously_ready_carrier_open() {
        let (_cancel, cancellation) = watch::channel(false);
        let open = std::future::ready(7_u8);
        let revocation = std::future::ready(());
        tokio::pin!(open, revocation);
        let result = race_carrier_open(open.as_mut(), revocation.as_mut(), cancellation).await;

        assert_eq!(result, CarrierOpenRace::Revoked);
    }

    #[tokio::test]
    async fn coordinator_cancellation_stops_a_pending_carrier_open() {
        let (cancel, cancellation) = watch::channel(false);
        cancel.send_replace(true);
        let open = std::future::pending::<u8>();
        let revocation = std::future::pending::<()>();
        tokio::pin!(open, revocation);
        let result = race_carrier_open(open.as_mut(), revocation.as_mut(), cancellation).await;

        assert_eq!(result, CarrierOpenRace::Cancelled);
    }

    #[tokio::test]
    async fn coordinator_drain_joins_every_loop_after_an_error() {
        let drained = Arc::new(std::sync::atomic::AtomicBool::new(false));
        let drained_task = Arc::clone(&drained);
        let (release, released) = tokio::sync::oneshot::channel();
        let mut tasks = tokio::task::JoinSet::new();
        tasks.spawn(async { Err(BtleRuntimeOwnerError::Cleanup) });
        tasks.spawn(async move {
            let _ = released.await;
            drained_task.store(true, Ordering::Release);
            Ok(())
        });

        let drain = tokio::spawn(drain_remaining_tasks(tasks));
        tokio::task::yield_now().await;
        release.send(()).unwrap();

        assert_eq!(drain.await.unwrap(), Err(BtleRuntimeOwnerError::Cleanup));
        assert!(drained.load(Ordering::Acquire));
    }

    #[tokio::test]
    async fn cancelled_carrier_open_is_drained_before_completion() {
        let (release, released) = tokio::sync::oneshot::channel();
        let drained = Arc::new(std::sync::atomic::AtomicBool::new(false));
        let drained_open = Arc::clone(&drained);
        let open = async move {
            let _ = released.await;
            drained_open.store(true, Ordering::Release);
        };
        tokio::pin!(open);
        let cancellation = OpenCancellation::new();

        let drain = cancel_and_drain_carrier_open(&cancellation, open.as_mut());
        tokio::pin!(drain);
        assert!(futures::poll!(&mut drain).is_pending());
        release.send(()).unwrap();

        drain.await.unwrap();
        assert!(drained.load(Ordering::Acquire));
    }

    #[test]
    fn outbound_authority_requires_exact_transport_mission_and_peer() {
        let mission = [0x11; 32];
        let peer = [0x22; 32];
        assert!(attempt_matches_authority(
            EventTransportKind::BLE_L2CAP_V1,
            mission,
            peer,
            mission,
            peer,
        ));
        assert!(!attempt_matches_authority(
            EventTransportKind::IROH_QUIC_V1,
            mission,
            peer,
            mission,
            peer,
        ));
        assert!(!attempt_matches_authority(
            EventTransportKind::BLE_L2CAP_V1,
            [0x33; 32],
            peer,
            mission,
            peer,
        ));
        assert!(!attempt_matches_authority(
            EventTransportKind::BLE_L2CAP_V1,
            mission,
            [0x44; 32],
            mission,
            peer,
        ));
    }

    #[test]
    fn driver_open_failures_map_to_closed_event_outcomes() {
        assert_eq!(
            classify_open_failure(DriverErrorKind::Configuration),
            OpenFailureDisposition::Fatal
        );
        assert_eq!(
            classify_open_failure(DriverErrorKind::Unavailable),
            OpenFailureDisposition::Unavailable
        );
        assert_eq!(
            classify_open_failure(DriverErrorKind::Timeout),
            OpenFailureDisposition::TimedOut
        );
        assert_eq!(
            classify_open_failure(DriverErrorKind::Cancelled),
            OpenFailureDisposition::Cancelled
        );
        for kind in [DriverErrorKind::Transport, DriverErrorKind::PeerRejected] {
            assert_eq!(
                classify_open_failure(kind),
                OpenFailureDisposition::Interrupted
            );
        }
    }

    #[test]
    fn inbound_expectation_keeps_carrier_evidence_separate_from_mission_peer() {
        let contact = ClosingContact::new();
        let peer = [0x5a; 32];
        let expectation = inbound_peer_expectation(contact.as_ref(), peer);

        assert_eq!(expectation.mission_id(), peer);
        assert_eq!(expectation.carrier_evidence(), &contact.peer_evidence());
        assert!(expectation.carrier_evidence().stable_carrier_id().is_none());
    }

    #[test]
    fn readiness_generations_map_to_distinct_event_epochs() {
        let mut mapping = ReadinessEpochMapping::new();

        assert_eq!(
            mapping.observe(
                0,
                BtleAvailability::Unavailable(AvailabilityReason::BluezUnavailable),
                true,
            ),
            Ok(None)
        );
        assert_eq!(
            mapping.observe(1, BtleAvailability::Available, true),
            Ok(Some((1, true)))
        );
        assert_eq!(
            mapping.observe(1, BtleAvailability::Available, true),
            Ok(None)
        );
        assert_eq!(
            mapping.observe(
                2,
                BtleAvailability::Unavailable(AvailabilityReason::BluezUnavailable),
                true,
            ),
            Ok(Some((2, false)))
        );
    }

    #[test]
    fn readiness_generation_gap_fails_closed() {
        let mut mapping = ReadinessEpochMapping::new();
        assert_eq!(
            mapping.observe(3, BtleAvailability::Available, true),
            Err(ReadinessMappingError)
        );
        assert_eq!(
            mapping.observe(1, BtleAvailability::Available, true),
            Ok(Some((1, true)))
        );

        assert_eq!(
            mapping.observe(3, BtleAvailability::Available, true),
            Err(ReadinessMappingError)
        );
        assert_eq!(mapping.park_unavailable(), Ok(Some((2, false))));
        assert_eq!(mapping.park_unavailable(), Ok(None));
    }

    #[test]
    fn listener_stays_unavailable_without_hiding_generation_reuse() {
        let mut mapping = ReadinessEpochMapping::new();
        assert_eq!(
            mapping.observe(
                0,
                BtleAvailability::Unavailable(AvailabilityReason::BluezUnavailable),
                false,
            ),
            Ok(None)
        );
        assert_eq!(
            mapping.observe(1, BtleAvailability::Available, false),
            Ok(None)
        );
        assert_eq!(
            mapping.observe(
                1,
                BtleAvailability::Unavailable(AvailabilityReason::BluezUnavailable),
                false,
            ),
            Err(ReadinessMappingError)
        );
    }

    #[test]
    fn parked_readiness_never_returns_event_to_available() {
        let mut mapping = ReadinessEpochMapping::new();
        assert_eq!(
            mapping.observe(1, BtleAvailability::Available, true),
            Ok(Some((1, true)))
        );
        assert_eq!(mapping.park_unavailable(), Ok(Some((2, false))));
        assert_eq!(
            mapping.observe(
                2,
                BtleAvailability::Unavailable(AvailabilityReason::BluezUnavailable),
                true,
            ),
            Ok(None)
        );
        assert_eq!(
            mapping.observe(3, BtleAvailability::Available, true),
            Ok(None)
        );
    }

    #[test]
    fn registration_requires_exact_initial_event_state() {
        let invalid = [
            EventAdapterSnapshot::new(
                EventTransportKind::IROH_QUIC_V1,
                0,
                EventAdapterState::Unavailable,
                true,
                7,
            ),
            EventAdapterSnapshot::new(
                EventTransportKind::BLE_L2CAP_V1,
                1,
                EventAdapterState::Unavailable,
                true,
                7,
            ),
            EventAdapterSnapshot::new(
                EventTransportKind::BLE_L2CAP_V1,
                0,
                EventAdapterState::Available,
                true,
                7,
            ),
            EventAdapterSnapshot::new(
                EventTransportKind::BLE_L2CAP_V1,
                0,
                EventAdapterState::Unavailable,
                false,
                7,
            ),
        ];

        for snapshot in invalid {
            let handle = aster_node::AutomaticEventTransportHandle::new();
            let registration = handle.register_paired(snapshot).unwrap();
            assert_eq!(
                validate_registration(registration).err(),
                Some(BtleRuntimeOwnerError::Startup)
            );
            assert!(handle.register_paired(snapshot).is_some());
        }

        let snapshot = EventAdapterSnapshot::new(
            EventTransportKind::BLE_L2CAP_V1,
            0,
            EventAdapterState::Unavailable,
            true,
            7,
        );
        let handle = aster_node::AutomaticEventTransportHandle::new();
        let registration = handle.register_paired(snapshot).unwrap();
        let (_, control, attempts) = validate_registration(registration).unwrap();
        assert!(handle.register_paired(snapshot).is_none());
        drop((control, attempts));
        assert!(handle.register_paired(snapshot).is_some());
    }
}
