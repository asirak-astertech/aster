use crate::{
    framing::{EnqueueError, FrameLimits, FrameReader, FrameWriter, ReadFrameError},
    types::{StreamDirection, expected_stream_direction},
};
use libp2p::{
    PeerId,
    core::upgrade::ReadyUpgrade,
    swarm::{
        ConnectionHandler, ConnectionHandlerEvent, Stream, StreamProtocol, SubstreamProtocol,
        handler::{
            ConnectionEvent, DialUpgradeError, FullyNegotiatedInbound, FullyNegotiatedOutbound,
            ListenUpgradeError,
        },
    },
};
use std::{
    collections::VecDeque,
    task::{Context, Poll},
    time::Duration,
};

pub const ASTER_PROTOCOL: &str = "/aster/sync/2";

#[derive(Debug)]
pub(crate) enum HandlerCommand {
    Activate,
    Deactivate,
    SendFrame(Vec<u8>),
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum SendRejectReason {
    StreamUnavailable,
    InvalidLength,
    FrameCapacity,
    ByteCapacity,
}

impl From<EnqueueError> for SendRejectReason {
    fn from(value: EnqueueError) -> Self {
        match value {
            EnqueueError::InvalidLength => Self::InvalidLength,
            EnqueueError::FrameCapacity => Self::FrameCapacity,
            EnqueueError::ByteCapacity => Self::ByteCapacity,
        }
    }
}

#[derive(Debug)]
pub(crate) enum HandlerEvent {
    StreamOpened(StreamDirection),
    FrameReceived(Vec<u8>),
    FrameSent(usize),
    FrameRejected {
        bytes: usize,
        reason: SendRejectReason,
    },
    StreamFailed(String),
}

pub(crate) struct AsterHandler {
    expected_direction: StreamDirection,
    limits: FrameLimits,
    negotiation_timeout: Duration,
    outbound_requested: bool,
    stream: Option<Stream>,
    pending_inbound: Option<Stream>,
    reader: FrameReader,
    writer: FrameWriter,
    events: VecDeque<HandlerEvent>,
    terminal: bool,
    active: bool,
}

impl AsterHandler {
    pub(crate) fn new(
        local: &PeerId,
        remote: &PeerId,
        limits: FrameLimits,
        negotiation_timeout: Duration,
    ) -> Self {
        Self {
            expected_direction: expected_stream_direction(*local, *remote)
                .expect("libp2p does not establish self-connections"),
            limits,
            negotiation_timeout,
            outbound_requested: false,
            stream: None,
            pending_inbound: None,
            reader: FrameReader::default(),
            writer: FrameWriter::default(),
            events: VecDeque::new(),
            terminal: false,
            active: false,
        }
    }

    fn install_stream(&mut self, stream: Stream, direction: StreamDirection) {
        if self.terminal {
            return;
        }
        if direction != self.expected_direction {
            self.fail(format!(
                "unexpected {direction:?} Aster substream; expected {:?}",
                self.expected_direction
            ));
            return;
        }
        if self.stream.is_some() || self.pending_inbound.is_some() {
            self.fail("duplicate Aster substream on one connection".to_owned());
            return;
        }
        if !self.active {
            // ConnectionEstablished is observable before the host can issue
            // Activate. The remote-selected side may therefore finish the
            // single expected inbound negotiation first. Retain exactly one
            // stream, but do not read or allocate a frame until activation.
            if direction == StreamDirection::Inbound {
                self.pending_inbound = Some(stream);
                return;
            }
            self.fail("outbound Aster substream negotiated before activation".to_owned());
            return;
        }
        self.stream = Some(stream);
        self.events.push_back(HandlerEvent::StreamOpened(direction));
    }

    fn fail(&mut self, reason: String) {
        if self.terminal {
            return;
        }
        self.terminal = true;
        self.stream.take();
        self.pending_inbound.take();
        self.reader.clear();
        self.writer.clear();
        self.events.push_back(HandlerEvent::StreamFailed(reason));
    }

    fn handle_read_error(&mut self, error: ReadFrameError) {
        let reason = match error {
            ReadFrameError::CleanEof => "Aster substream closed by remote".to_owned(),
            ReadFrameError::Truncated => "truncated Aster carrier frame".to_owned(),
            ReadFrameError::InvalidLength(length) => {
                format!("Aster carrier frame length {length} is outside the bound")
            }
            ReadFrameError::Io(error) => format!("Aster substream read failed: {error}"),
        };
        self.fail(reason);
    }
}

impl ConnectionHandler for AsterHandler {
    type FromBehaviour = HandlerCommand;
    type ToBehaviour = HandlerEvent;
    type InboundProtocol = ReadyUpgrade<StreamProtocol>;
    type OutboundProtocol = ReadyUpgrade<StreamProtocol>;
    type InboundOpenInfo = ();
    type OutboundOpenInfo = ();

    fn listen_protocol(&self) -> SubstreamProtocol<Self::InboundProtocol, Self::InboundOpenInfo> {
        SubstreamProtocol::new(ReadyUpgrade::new(StreamProtocol::new(ASTER_PROTOCOL)), ())
            .with_timeout(self.negotiation_timeout)
    }

    fn connection_keep_alive(&self) -> bool {
        self.active && !self.terminal
    }

    fn poll(
        &mut self,
        cx: &mut Context<'_>,
    ) -> Poll<
        ConnectionHandlerEvent<Self::OutboundProtocol, Self::OutboundOpenInfo, Self::ToBehaviour>,
    > {
        if let Some(event) = self.events.pop_front() {
            return Poll::Ready(ConnectionHandlerEvent::NotifyBehaviour(event));
        }
        if self.terminal {
            return Poll::Pending;
        }
        if self.expected_direction == StreamDirection::Outbound
            && self.active
            && !self.outbound_requested
            && self.stream.is_none()
        {
            self.outbound_requested = true;
            return Poll::Ready(ConnectionHandlerEvent::OutboundSubstreamRequest {
                protocol: SubstreamProtocol::new(
                    ReadyUpgrade::new(StreamProtocol::new(ASTER_PROTOCOL)),
                    (),
                )
                .with_timeout(self.negotiation_timeout),
            });
        }

        let Some(stream) = self.stream.as_mut() else {
            return Poll::Pending;
        };
        match self.writer.poll_write(stream, cx) {
            Poll::Ready(Ok(bytes)) => {
                return Poll::Ready(ConnectionHandlerEvent::NotifyBehaviour(
                    HandlerEvent::FrameSent(bytes),
                ));
            }
            Poll::Ready(Err(error)) => {
                self.fail(format!("Aster substream write failed: {error}"));
                return Poll::Ready(ConnectionHandlerEvent::NotifyBehaviour(
                    self.events.pop_front().expect("failure queues one event"),
                ));
            }
            Poll::Pending => {}
        }

        let Some(stream) = self.stream.as_mut() else {
            return Poll::Pending;
        };
        match self
            .reader
            .poll_frame(stream, cx, self.limits.max_frame_bytes)
        {
            Poll::Ready(Ok(frame)) => Poll::Ready(ConnectionHandlerEvent::NotifyBehaviour(
                HandlerEvent::FrameReceived(frame),
            )),
            Poll::Ready(Err(error)) => {
                self.handle_read_error(error);
                Poll::Ready(ConnectionHandlerEvent::NotifyBehaviour(
                    self.events.pop_front().expect("failure queues one event"),
                ))
            }
            Poll::Pending => Poll::Pending,
        }
    }

    fn on_behaviour_event(&mut self, event: Self::FromBehaviour) {
        match event {
            HandlerCommand::Activate => {
                if self.terminal {
                    self.events.push_back(HandlerEvent::StreamFailed(
                        "cannot reactivate a retired Aster connection".to_owned(),
                    ));
                } else {
                    self.active = true;
                    if let Some(stream) = self.pending_inbound.take() {
                        self.stream = Some(stream);
                        self.events
                            .push_back(HandlerEvent::StreamOpened(StreamDirection::Inbound));
                    }
                }
            }
            HandlerCommand::Deactivate => {
                self.active = false;
                self.terminal = true;
                self.stream.take();
                self.pending_inbound.take();
                self.reader.clear();
                self.writer.clear();
                self.events.clear();
            }
            HandlerCommand::SendFrame(frame) => {
                let bytes = frame.len();
                if self.terminal || self.stream.is_none() {
                    self.events.push_back(HandlerEvent::FrameRejected {
                        bytes,
                        reason: SendRejectReason::StreamUnavailable,
                    });
                    return;
                }
                if let Err(error) = self.writer.enqueue(frame, self.limits) {
                    self.events.push_back(HandlerEvent::FrameRejected {
                        bytes,
                        reason: error.into(),
                    });
                }
            }
        }
    }

    fn on_connection_event(
        &mut self,
        event: ConnectionEvent<
            Self::InboundProtocol,
            Self::OutboundProtocol,
            Self::InboundOpenInfo,
            Self::OutboundOpenInfo,
        >,
    ) {
        match event {
            ConnectionEvent::FullyNegotiatedInbound(FullyNegotiatedInbound {
                protocol,
                info: (),
            }) => self.install_stream(protocol, StreamDirection::Inbound),
            ConnectionEvent::FullyNegotiatedOutbound(FullyNegotiatedOutbound {
                protocol,
                info: (),
            }) => self.install_stream(protocol, StreamDirection::Outbound),
            ConnectionEvent::DialUpgradeError(DialUpgradeError { error, info: () }) => {
                self.fail(format!("Aster outbound negotiation failed: {error}"));
            }
            ConnectionEvent::ListenUpgradeError(ListenUpgradeError { error, info: () }) => {
                self.fail(format!("Aster inbound negotiation failed: {error:?}"));
            }
            _ => {}
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use futures::{io::AsyncRead, task::noop_waker_ref};
    use libp2p::identity::Keypair;
    use std::{io, pin::Pin};

    const LIMITS: FrameLimits = FrameLimits {
        max_frame_bytes: 1024,
        max_queued_frames: 4,
        max_queued_bytes: 4096,
    };

    fn handler(local: &PeerId, remote: &PeerId) -> AsterHandler {
        AsterHandler::new(local, remote, LIMITS, Duration::from_secs(1))
    }

    #[derive(Debug, Default)]
    struct PartialFrame {
        reads: usize,
    }

    impl AsyncRead for PartialFrame {
        fn poll_read(
            self: Pin<&mut Self>,
            _cx: &mut Context<'_>,
            buffer: &mut [u8],
        ) -> Poll<Result<usize, io::Error>> {
            let this = self.get_mut();
            let bytes: &[u8] = match this.reads {
                0 => &5_u32.to_be_bytes(),
                1 => &[9, 8],
                _ => return Poll::Pending,
            };
            buffer[..bytes.len()].copy_from_slice(bytes);
            this.reads += 1;
            Poll::Ready(Ok(bytes.len()))
        }
    }

    #[test]
    fn exactly_one_peer_initiates_for_every_peer_pair() {
        let first = Keypair::generate_ed25519().public().to_peer_id();
        let second = Keypair::generate_ed25519().public().to_peer_id();
        assert_ne!(first, second);
        assert_ne!(
            expected_stream_direction(first, second).unwrap(),
            expected_stream_direction(second, first).unwrap()
        );
    }

    #[test]
    fn only_the_deterministic_initiator_requests_a_stream() {
        let first = Keypair::generate_ed25519().public().to_peer_id();
        let second = Keypair::generate_ed25519().public().to_peer_id();
        let (local, remote) = if first.to_bytes() < second.to_bytes() {
            (first, second)
        } else {
            (second, first)
        };
        let mut initiator = handler(&local, &remote);
        let mut responder = handler(&remote, &local);
        let mut cx = Context::from_waker(noop_waker_ref());

        assert!(matches!(initiator.poll(&mut cx), Poll::Pending));
        initiator.on_behaviour_event(HandlerCommand::Activate);
        assert!(matches!(
            initiator.poll(&mut cx),
            Poll::Ready(ConnectionHandlerEvent::OutboundSubstreamRequest { .. })
        ));
        assert!(matches!(responder.poll(&mut cx), Poll::Pending));
        assert!(matches!(initiator.poll(&mut cx), Poll::Pending));
    }

    #[test]
    fn deactivate_discards_partial_io_and_predecessor_events_before_replacement() {
        let first = Keypair::generate_ed25519().public().to_peer_id();
        let second = Keypair::generate_ed25519().public().to_peer_id();
        let mut retired = handler(&first, &second);
        retired.writer.enqueue(vec![7; 32], LIMITS).unwrap();
        let mut partial = PartialFrame::default();
        let mut cx = Context::from_waker(noop_waker_ref());
        assert!(matches!(
            retired
                .reader
                .poll_frame(&mut partial, &mut cx, LIMITS.max_frame_bytes),
            Poll::Pending
        ));
        assert!(!retired.reader.is_clear());
        assert_eq!(retired.writer.queued_frames(), 1);
        assert_eq!(retired.writer.queued_bytes(), 32);
        retired
            .events
            .push_back(HandlerEvent::FrameReceived(vec![6; 4]));
        retired.active = true;

        retired.on_behaviour_event(HandlerCommand::Deactivate);
        assert!(retired.terminal);
        assert!(!retired.active);
        assert!(retired.reader.is_clear());
        assert_eq!(retired.writer.queued_frames(), 0);
        assert_eq!(retired.writer.queued_bytes(), 0);
        assert!(retired.events.is_empty());

        retired.on_behaviour_event(HandlerCommand::Activate);
        assert!(matches!(
            retired.poll(&mut cx),
            Poll::Ready(ConnectionHandlerEvent::NotifyBehaviour(
                HandlerEvent::StreamFailed(reason)
            )) if reason == "cannot reactivate a retired Aster connection"
        ));
        assert!(matches!(retired.poll(&mut cx), Poll::Pending));

        let replacement = handler(&first, &second);
        assert!(replacement.reader.is_clear());
        assert_eq!(replacement.writer.queued_frames(), 0);
        assert_eq!(replacement.writer.queued_bytes(), 0);
        assert!(replacement.events.is_empty());
    }
}
