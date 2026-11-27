use crate::{BtleAvailability, DriverError, DriverErrorKind, OpenCancellation, OpenedContact};
use aster_contact::{
    CarrierPeerEvidence, ContactFuture, ContactPreflight, ContactRequestHandler, OrderedContact,
};
use std::sync::{Arc, Mutex};
use tokio::sync::{OwnedSemaphorePermit, Semaphore, mpsc, oneshot, watch};

const CARRIER_CHANNEL_CAPACITY: usize = 1;

/// Move-only agent access to automatic Linux BTLE carrier operations.
///
/// The port carries no Event registration, attempt, admission, or outcome
/// authority. Its three handles can be awaited concurrently by the agent.
pub struct AutomaticBtleCarrierPort {
    readiness: AutomaticBtleCarrierReadinessMonitor,
    outbound: AutomaticBtleCarrierOutbound,
    inbound: AutomaticBtleCarrierInbound,
}

/// One opened Linux BTLE carrier leased to the agent.
///
/// Consuming the lease yields only the adapter-neutral ordered contact. Linux
/// retains the ability to close the carrier and observes when the contact is
/// closed or dropped so it can preserve its one-contact bound.
pub struct AutomaticBtleCarrier {
    contact: Option<Arc<dyn OrderedContact>>,
    lease: Option<CarrierLease>,
}

impl AutomaticBtleCarrier {
    /// Consumes this lease and transfers its ordered contact to the agent.
    pub fn into_contact(mut self) -> Arc<dyn OrderedContact> {
        let contact = self.contact.take().expect("leased carrier retained");
        let lease = self.lease.take().expect("carrier lease retained");
        Arc::new(LeasedOrderedContact { contact, lease })
    }

    fn close(&self) {
        if let (Some(contact), Some(lease)) = (&self.contact, &self.lease) {
            lease.close(contact);
        }
    }
}

impl Drop for AutomaticBtleCarrier {
    fn drop(&mut self) {
        self.close();
    }
}

struct LeasedOrderedContact {
    contact: Arc<dyn OrderedContact>,
    lease: CarrierLease,
}

impl OrderedContact for LeasedOrderedContact {
    fn peer_evidence(&self) -> CarrierPeerEvidence {
        self.contact.peer_evidence()
    }

    fn max_frame_bytes(&self) -> usize {
        self.contact.max_frame_bytes()
    }

    fn request_with_total_limit<'a>(
        &'a self,
        request: &'a [u8],
        total_limit: usize,
    ) -> ContactFuture<'a, Vec<u8>> {
        self.contact.request_with_total_limit(request, total_limit)
    }

    fn request_with_total_limit_checked<'a>(
        &'a self,
        request: &'a [u8],
        total_limit: usize,
        before_write: ContactPreflight<'a>,
    ) -> ContactFuture<'a, Vec<u8>> {
        self.contact
            .request_with_total_limit_checked(request, total_limit, before_write)
    }

    fn respond_once_with_total_limit<'a>(
        &'a self,
        total_limit: usize,
        handler: ContactRequestHandler<'a>,
    ) -> ContactFuture<'a, bool> {
        self.contact
            .respond_once_with_total_limit(total_limit, handler)
    }

    fn finish_as_initiator(&self) -> ContactFuture<'_, ()> {
        self.contact.finish_as_initiator()
    }

    fn finish_as_responder(&self) -> ContactFuture<'_, ()> {
        self.contact.finish_as_responder()
    }

    fn close(&self) {
        self.lease.close(&self.contact);
    }
}

impl Drop for LeasedOrderedContact {
    fn drop(&mut self) {
        self.lease.close(&self.contact);
    }
}

struct CarrierLeaseState {
    close: Mutex<CarrierLeaseCloseState>,
}

struct CarrierLeaseCloseState {
    closed: bool,
    released: Option<oneshot::Sender<()>>,
}

#[derive(Clone)]
struct CarrierLease(Arc<CarrierLeaseState>);

impl CarrierLease {
    fn close(&self, contact: &Arc<dyn OrderedContact>) {
        let mut close = self
            .0
            .close
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        if close.closed {
            return;
        }
        contact.close();
        close.closed = true;
        if let Some(released) = close.released.take() {
            let _ = released.send(());
        }
    }
}

pub(crate) struct AutomaticBtleCarrierRelease {
    contact: Arc<dyn OrderedContact>,
    lease: CarrierLease,
    released: oneshot::Receiver<()>,
}

impl AutomaticBtleCarrierRelease {
    pub(crate) fn close(&self) {
        self.lease.close(&self.contact);
    }

    pub(crate) async fn wait(&mut self) {
        let _ = (&mut self.released).await;
    }
}

fn lease_ordered_contact(
    contact: Arc<dyn OrderedContact>,
) -> (AutomaticBtleCarrier, AutomaticBtleCarrierRelease) {
    let (released, release_observation) = oneshot::channel();
    let lease = CarrierLease(Arc::new(CarrierLeaseState {
        close: Mutex::new(CarrierLeaseCloseState {
            closed: false,
            released: Some(released),
        }),
    }));
    (
        AutomaticBtleCarrier {
            contact: Some(contact.clone()),
            lease: Some(lease.clone()),
        },
        AutomaticBtleCarrierRelease {
            contact,
            lease,
            released: release_observation,
        },
    )
}

fn lease_opened_contact(
    contact: OpenedContact,
) -> (AutomaticBtleCarrier, AutomaticBtleCarrierRelease) {
    let contact: Arc<dyn OrderedContact> = contact.into_contact();
    lease_ordered_contact(contact)
}

impl AutomaticBtleCarrierPort {
    /// Separates the single-owner readiness, outbound, and inbound handles.
    pub fn into_parts(
        self,
    ) -> (
        AutomaticBtleCarrierReadinessMonitor,
        AutomaticBtleCarrierOutbound,
        AutomaticBtleCarrierInbound,
    ) {
        (self.readiness, self.outbound, self.inbound)
    }
}

/// One generation-stamped Linux carrier readiness observation.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct AutomaticBtleCarrierReadiness {
    availability: BtleAvailability,
    generation: u64,
}

impl AutomaticBtleCarrierReadiness {
    /// Current coarse Linux carrier readiness.
    pub const fn availability(self) -> BtleAvailability {
        self.availability
    }

    /// Monotonic generation advanced for every distinct readiness transition.
    pub const fn generation(self) -> u64 {
        self.generation
    }
}

/// Single-owner readiness monitor for the automatic Linux carrier.
pub struct AutomaticBtleCarrierReadinessMonitor {
    readiness: watch::Receiver<AutomaticBtleCarrierReadiness>,
}

impl AutomaticBtleCarrierReadinessMonitor {
    /// Returns and acknowledges the current readiness observation.
    pub fn current(&mut self) -> AutomaticBtleCarrierReadiness {
        *self.readiness.borrow_and_update()
    }

    /// Waits for a newer readiness generation.
    pub async fn changed(&mut self) -> Option<AutomaticBtleCarrierReadiness> {
        self.readiness.changed().await.ok()?;
        Some(*self.readiness.borrow_and_update())
    }
}

/// Outbound-open handle for the automatic Linux carrier.
pub struct AutomaticBtleCarrierOutbound {
    requests: mpsc::Sender<OutboundCarrierRequest>,
    permit: Arc<Semaphore>,
}

impl AutomaticBtleCarrierOutbound {
    /// Requests one outbound carrier from this peer-scoped Linux owner.
    pub async fn open(
        &self,
        cancellation: OpenCancellation,
    ) -> Result<AutomaticBtleCarrier, DriverError> {
        let permit = self.permit.clone().try_acquire_owned().map_err(|_| {
            DriverError::new(
                DriverErrorKind::Unavailable,
                "an automatic carrier open is already pending",
            )
        })?;
        let mut cancel_on_drop = CancelOnDrop::new(cancellation.clone());
        let (result, completion) = oneshot::channel();
        let send = self.requests.send(OutboundCarrierRequest {
            cancellation: cancellation.clone(),
            result,
            _permit: permit,
        });
        tokio::pin!(send);
        let sent = tokio::select! {
            biased;
            () = cancellation.cancelled() => false,
            result = &mut send => {
                if result.is_err() {
                    cancel_on_drop.disarm();
                    return Err(DriverError::new(
                        DriverErrorKind::Unavailable,
                        "automatic carrier owner is unavailable",
                    ));
                }
                true
            }
        };
        if !sent {
            return Err(DriverError::new(
                DriverErrorKind::Cancelled,
                "automatic carrier open was cancelled",
            ));
        }
        tokio::pin!(completion);
        tokio::select! {
            biased;
            () = cancellation.cancelled() => {
                let _ = completion.await;
                cancel_on_drop.disarm();
                Err(DriverError::new(
                    DriverErrorKind::Cancelled,
                    "automatic carrier open was cancelled",
                ))
            },
            result = &mut completion => {
                cancel_on_drop.disarm();
                match result {
                    Ok(Ok(contact)) => Ok(contact),
                    Ok(Err(error)) => Err(error),
                    Err(_) => Err(DriverError::new(
                        DriverErrorKind::Unavailable,
                        "automatic carrier owner stopped before completing the open",
                    )),
                }
            }
        }
    }
}

/// Single-owner inbound carrier stream from Linux.
pub struct AutomaticBtleCarrierInbound {
    contacts: mpsc::Receiver<AutomaticBtleCarrier>,
}

impl AutomaticBtleCarrierInbound {
    /// Receives the next bounded inbound carrier opened by Linux.
    pub async fn recv(&mut self) -> Option<AutomaticBtleCarrier> {
        self.contacts.recv().await
    }
}

struct CancelOnDrop(Option<OpenCancellation>);

impl CancelOnDrop {
    fn new(cancellation: OpenCancellation) -> Self {
        Self(Some(cancellation))
    }

    fn disarm(&mut self) {
        self.0 = None;
    }
}

impl Drop for CancelOnDrop {
    fn drop(&mut self) {
        if let Some(cancellation) = self.0.take() {
            cancellation.cancel();
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum ReadinessPublishError {
    GenerationExhausted,
    PortClosed,
}

#[derive(Clone)]
pub(crate) struct AutomaticBtleCarrierReadinessPublisher {
    readiness: watch::Sender<AutomaticBtleCarrierReadiness>,
}

impl AutomaticBtleCarrierReadinessPublisher {
    pub(crate) fn publish(
        &self,
        availability: BtleAvailability,
    ) -> Result<bool, ReadinessPublishError> {
        if self.readiness.receiver_count() == 0 {
            return Err(ReadinessPublishError::PortClosed);
        }
        let mut exhausted = false;
        let changed = self.readiness.send_if_modified(|current| {
            if current.availability == availability {
                return false;
            }
            let Some(generation) = current.generation.checked_add(1) else {
                exhausted = true;
                return false;
            };
            *current = AutomaticBtleCarrierReadiness {
                availability,
                generation,
            };
            true
        });
        if exhausted {
            Err(ReadinessPublishError::GenerationExhausted)
        } else {
            Ok(changed)
        }
    }
}

pub(crate) struct AutomaticBtleCarrierBackend {
    readiness: AutomaticBtleCarrierReadinessPublisher,
    outbound: mpsc::Receiver<OutboundCarrierRequest>,
    inbound: mpsc::Sender<AutomaticBtleCarrier>,
}

impl AutomaticBtleCarrierBackend {
    pub(crate) fn readiness_publisher(&self) -> AutomaticBtleCarrierReadinessPublisher {
        self.readiness.clone()
    }

    pub(crate) async fn recv_outbound(&mut self) -> Option<OutboundCarrierRequest> {
        self.outbound.recv().await
    }

    pub(crate) fn deliver_inbound(
        &self,
        contact: OpenedContact,
    ) -> Option<AutomaticBtleCarrierRelease> {
        let (carrier, release) = lease_opened_contact(contact);
        deliver_carrier(&self.inbound, carrier).then_some(release)
    }
}

pub(crate) struct OutboundCarrierRequest {
    cancellation: OpenCancellation,
    result: oneshot::Sender<Result<AutomaticBtleCarrier, DriverError>>,
    _permit: OwnedSemaphorePermit,
}

impl OutboundCarrierRequest {
    pub(crate) fn cancellation(&self) -> OpenCancellation {
        self.cancellation.clone()
    }

    pub(crate) fn complete_error(self, error: DriverError) -> bool {
        self.result.send(Err(error)).is_ok()
    }

    pub(crate) fn complete_contact(
        self,
        contact: OpenedContact,
    ) -> Option<AutomaticBtleCarrierRelease> {
        let (carrier, release) = lease_opened_contact(contact);
        complete_carrier(self.result, Ok(carrier)).then_some(release)
    }
}

fn complete_carrier(
    completion: oneshot::Sender<Result<AutomaticBtleCarrier, DriverError>>,
    result: Result<AutomaticBtleCarrier, DriverError>,
) -> bool {
    completion.send(result).is_ok()
}

fn deliver_carrier(
    delivery: &mpsc::Sender<AutomaticBtleCarrier>,
    carrier: AutomaticBtleCarrier,
) -> bool {
    delivery.try_send(carrier).is_ok()
}

pub(crate) fn automatic_btle_carrier_channel(
    initial: BtleAvailability,
) -> (AutomaticBtleCarrierBackend, AutomaticBtleCarrierPort) {
    let initial = AutomaticBtleCarrierReadiness {
        availability: initial,
        generation: 0,
    };
    let (readiness, readiness_updates) = watch::channel(initial);
    let (outbound_requests, outbound) = mpsc::channel(CARRIER_CHANNEL_CAPACITY);
    let (inbound, inbound_contacts) = mpsc::channel(CARRIER_CHANNEL_CAPACITY);
    (
        AutomaticBtleCarrierBackend {
            readiness: AutomaticBtleCarrierReadinessPublisher { readiness },
            outbound,
            inbound,
        },
        AutomaticBtleCarrierPort {
            readiness: AutomaticBtleCarrierReadinessMonitor {
                readiness: readiness_updates,
            },
            outbound: AutomaticBtleCarrierOutbound {
                requests: outbound_requests,
                permit: Arc::new(Semaphore::new(CARRIER_CHANNEL_CAPACITY)),
            },
            inbound: AutomaticBtleCarrierInbound {
                contacts: inbound_contacts,
            },
        },
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::AvailabilityReason;
    use aster_contact::{
        CarrierPeerEvidence, ContactError, ContactErrorKind, ContactFuture, ContactPreflight,
        ContactRequestHandler, OrderedContact, TransientLocator,
    };
    use std::sync::atomic::{AtomicUsize, Ordering};

    struct TestOrderedContact {
        closes: Arc<AtomicUsize>,
    }

    impl TestOrderedContact {
        fn tracked() -> (Arc<dyn OrderedContact>, Arc<AtomicUsize>) {
            let closes = Arc::new(AtomicUsize::new(0));
            (
                Arc::new(Self {
                    closes: closes.clone(),
                }),
                closes,
            )
        }

        fn unsupported<T>() -> ContactFuture<'static, T> {
            Box::pin(async {
                Err(ContactError::new(
                    ContactErrorKind::Unsupported,
                    "unused test operation",
                ))
            })
        }
    }

    impl OrderedContact for TestOrderedContact {
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
            Self::unsupported()
        }

        fn request_with_total_limit_checked<'a>(
            &'a self,
            _request: &'a [u8],
            _total_limit: usize,
            _before_write: ContactPreflight<'a>,
        ) -> ContactFuture<'a, Vec<u8>> {
            Self::unsupported()
        }

        fn respond_once_with_total_limit<'a>(
            &'a self,
            _total_limit: usize,
            _handler: ContactRequestHandler<'a>,
        ) -> ContactFuture<'a, bool> {
            Self::unsupported()
        }

        fn finish_as_initiator(&self) -> ContactFuture<'_, ()> {
            Self::unsupported()
        }

        fn finish_as_responder(&self) -> ContactFuture<'_, ()> {
            Self::unsupported()
        }

        fn close(&self) {
            self.closes.fetch_add(1, Ordering::SeqCst);
        }
    }

    fn activating_channel() -> (AutomaticBtleCarrierBackend, AutomaticBtleCarrierPort) {
        automatic_btle_carrier_channel(BtleAvailability::Unavailable(
            AvailabilityReason::Activating,
        ))
    }

    #[tokio::test]
    async fn one_outbound_request_owns_the_port_until_backend_completion() {
        let (mut backend, port) = activating_channel();
        let (_, outbound, _) = port.into_parts();
        let outbound = Arc::new(outbound);
        let first = tokio::spawn({
            let outbound = outbound.clone();
            async move { outbound.open(OpenCancellation::new()).await }
        });
        let request = backend.recv_outbound().await.unwrap();

        let Err(second) = outbound.open(OpenCancellation::new()).await else {
            panic!("a second outbound request must be rejected");
        };
        assert_eq!(second.kind(), DriverErrorKind::Unavailable);

        assert!(request.complete_error(DriverError::new(
            DriverErrorKind::Transport,
            "test carrier failure",
        )));
        let Err(first) = first.await.unwrap() else {
            panic!("the backend failure must finish the first request");
        };
        assert_eq!(first.kind(), DriverErrorKind::Transport);

        let next = tokio::spawn({
            let outbound = outbound.clone();
            async move { outbound.open(OpenCancellation::new()).await }
        });
        let request = backend.recv_outbound().await.unwrap();
        assert!(request.complete_error(DriverError::new(
            DriverErrorKind::Transport,
            "next carrier failure",
        )));
        let Err(next) = next.await.unwrap() else {
            panic!("backend retirement must release the outbound permit");
        };
        assert_eq!(next.kind(), DriverErrorKind::Transport);
    }

    #[tokio::test]
    async fn cancelled_outbound_keeps_ownership_until_backend_retires_it() {
        let (mut backend, port) = activating_channel();
        let (_, outbound, _) = port.into_parts();
        let cancellation = OpenCancellation::new();
        let opened = outbound.open(cancellation.clone());
        tokio::pin!(opened);
        assert!(futures::poll!(&mut opened).is_pending());
        let request = backend.recv_outbound().await.unwrap();
        let backend_cancellation = request.cancellation();

        cancellation.cancel();
        backend_cancellation.cancelled().await;
        assert!(futures::poll!(&mut opened).is_pending());
        let Err(second) = outbound.open(OpenCancellation::new()).await else {
            panic!("backend retirement must retain single-request ownership");
        };
        assert_eq!(second.kind(), DriverErrorKind::Unavailable);
        assert!(request.complete_error(DriverError::new(
            DriverErrorKind::Transport,
            "late carrier result",
        )));
        let Err(error) = opened.await else {
            panic!("a cancelled outbound request must fail");
        };
        assert_eq!(error.kind(), DriverErrorKind::Cancelled);
    }

    #[tokio::test]
    async fn aborting_outbound_cancels_backend_work() {
        let (mut backend, port) = activating_channel();
        let (_, outbound, _) = port.into_parts();
        let opened = tokio::spawn(async move { outbound.open(OpenCancellation::new()).await });
        let request = backend.recv_outbound().await.unwrap();
        let cancellation = request.cancellation();

        opened.abort();
        let _ = opened.await;
        cancellation.cancelled().await;
    }

    #[tokio::test]
    async fn closed_backend_fails_outbound_without_waiting() {
        let (backend, port) = activating_channel();
        let (_, outbound, _) = port.into_parts();
        drop(backend);

        let Err(error) = outbound.open(OpenCancellation::new()).await else {
            panic!("a closed backend must fail the outbound request");
        };
        assert_eq!(error.kind(), DriverErrorKind::Unavailable);
    }

    #[tokio::test]
    async fn readiness_generation_exposes_coalesced_loss() {
        let (backend, port) = activating_channel();
        let publisher = backend.readiness_publisher();
        let (mut readiness, _, _) = port.into_parts();
        assert_eq!(readiness.current().generation(), 0);
        assert_eq!(publisher.publish(BtleAvailability::Available), Ok(true));
        assert_eq!(
            publisher.publish(BtleAvailability::Unavailable(
                AvailabilityReason::BluezUnavailable,
            )),
            Ok(true)
        );
        assert_eq!(publisher.publish(BtleAvailability::Available), Ok(true));

        let observed = readiness.changed().await.unwrap();
        assert_eq!(observed.availability(), BtleAvailability::Available);
        assert_eq!(observed.generation(), 3);
    }

    #[test]
    fn duplicate_readiness_does_not_advance_generation() {
        let (backend, port) = activating_channel();
        let publisher = backend.readiness_publisher();
        let (mut readiness, _, _) = port.into_parts();
        assert_eq!(
            publisher.publish(BtleAvailability::Unavailable(
                AvailabilityReason::Activating,
            )),
            Ok(false)
        );
        assert_eq!(readiness.current().generation(), 0);
    }

    #[test]
    fn readiness_publication_fails_closed_on_exhaustion_or_port_loss() {
        let (backend, port) = activating_channel();
        let publisher = backend.readiness_publisher();
        backend
            .readiness
            .readiness
            .send_replace(AutomaticBtleCarrierReadiness {
                availability: BtleAvailability::Unavailable(AvailabilityReason::Activating),
                generation: u64::MAX,
            });
        assert_eq!(
            publisher.publish(BtleAvailability::Available),
            Err(ReadinessPublishError::GenerationExhausted)
        );

        drop(port);
        assert_eq!(
            publisher.publish(BtleAvailability::Available),
            Err(ReadinessPublishError::PortClosed)
        );
    }

    #[test]
    fn queued_inbound_carrier_closes_when_receiver_drops() {
        let (delivery, receiver) = mpsc::channel(1);
        let (contact, closes) = TestOrderedContact::tracked();
        let (carrier, mut release) = lease_ordered_contact(contact);
        assert!(deliver_carrier(&delivery, carrier));

        drop(receiver);
        assert_eq!(release.released.try_recv(), Ok(()));
        assert_eq!(closes.load(Ordering::SeqCst), 1);
    }

    #[test]
    fn full_inbound_queue_closes_rejected_carrier() {
        let (delivery, _receiver) = mpsc::channel(1);
        let (first_contact, first_closes) = TestOrderedContact::tracked();
        let (first, mut first_release) = lease_ordered_contact(first_contact);
        let (second_contact, second_closes) = TestOrderedContact::tracked();
        let (second, mut second_release) = lease_ordered_contact(second_contact);
        assert!(deliver_carrier(&delivery, first));
        assert!(!deliver_carrier(&delivery, second));

        assert!(matches!(
            first_release.released.try_recv(),
            Err(oneshot::error::TryRecvError::Empty)
        ));
        assert_eq!(second_release.released.try_recv(), Ok(()));
        assert_eq!(first_closes.load(Ordering::SeqCst), 0);
        assert_eq!(second_closes.load(Ordering::SeqCst), 1);
    }

    #[test]
    fn completed_outbound_carrier_closes_if_waiter_disappears() {
        let (completion, receiver) = oneshot::channel();
        let (contact, closes) = TestOrderedContact::tracked();
        let (carrier, mut release) = lease_ordered_contact(contact);
        assert!(complete_carrier(completion, Ok(carrier)));

        drop(receiver);
        assert_eq!(release.released.try_recv(), Ok(()));
        assert_eq!(closes.load(Ordering::SeqCst), 1);
    }

    #[test]
    fn leased_contact_releases_when_agent_closes_or_drops_it() {
        for close_explicitly in [true, false] {
            let (contact, closes) = TestOrderedContact::tracked();
            let (carrier, mut release) = lease_ordered_contact(contact);
            let contact = carrier.into_contact();
            assert!(matches!(
                release.released.try_recv(),
                Err(oneshot::error::TryRecvError::Empty)
            ));

            if close_explicitly {
                contact.close();
            } else {
                drop(contact);
            }

            assert_eq!(release.released.try_recv(), Ok(()));
            assert_eq!(closes.load(Ordering::SeqCst), 1);
        }
    }

    #[test]
    fn linux_and_agent_close_one_leased_contact_only_once() {
        let (contact, closes) = TestOrderedContact::tracked();
        let (carrier, mut release) = lease_ordered_contact(contact);
        let contact = carrier.into_contact();

        release.close();
        contact.close();
        drop(contact);

        assert_eq!(release.released.try_recv(), Ok(()));
        assert_eq!(closes.load(Ordering::SeqCst), 1);
    }
}
