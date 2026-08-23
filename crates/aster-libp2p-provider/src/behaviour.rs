use crate::{
    framing::FrameLimits,
    protocol::{AsterHandler, HandlerCommand, HandlerEvent, SendRejectReason},
    types::{SessionId, StreamDirection},
};
use libp2p::{
    Multiaddr, PeerId,
    core::{Endpoint, transport::PortUse},
    swarm::{
        CloseConnection, ConnectionDenied, ConnectionId, FromSwarm, NetworkBehaviour,
        NotifyHandler, THandler, THandlerInEvent, THandlerOutEvent, ToSwarm,
    },
};
use std::{
    collections::{HashMap, HashSet, VecDeque},
    fmt,
    task::{Context, Poll},
    time::Duration,
};

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
struct QueueUsage {
    frames: usize,
    bytes: usize,
}

/// Immediate refusal to enqueue a carrier frame.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum SendFrameError {
    UnknownSession,
    StreamNotOpen,
    InvalidLength,
    FrameCapacity,
    ByteCapacity,
}

impl fmt::Display for SendFrameError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        let message = match self {
            Self::UnknownSession => "unknown physical libp2p session",
            Self::StreamNotOpen => "Aster substream is not open",
            Self::InvalidLength => "Aster frame length is outside the bound",
            Self::FrameCapacity => "Aster outbound frame queue is full",
            Self::ByteCapacity => "Aster outbound byte queue is full",
        };
        formatter.write_str(message)
    }
}

impl std::error::Error for SendFrameError {}

/// Refusal to activate or replace the connection carrying an Aster session.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum ActivationError {
    UnknownSession,
    PeerAlreadyHasSelectedSession,
    SessionNotSelected,
    PeerMismatch,
    SameSession,
    ReplacementNotReady,
}

impl fmt::Display for ActivationError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        let message = match self {
            Self::UnknownSession => "unknown physical libp2p session",
            Self::PeerAlreadyHasSelectedSession => {
                "peer already has a selected Aster carrier; replace it explicitly"
            }
            Self::SessionNotSelected => "old Aster session is not selected",
            Self::PeerMismatch => "replacement connections belong to different peers",
            Self::SameSession => "old and replacement Aster sessions are identical",
            Self::ReplacementNotReady => "replacement is not ready; wait for old carrier closure",
        };
        formatter.write_str(message)
    }
}

impl std::error::Error for ActivationError {}

#[derive(Debug)]
pub(crate) enum AsterEvent {
    StreamOpened {
        session: SessionId,
        direction: StreamDirection,
    },
    FrameReceived {
        session: SessionId,
        frame: Vec<u8>,
    },
    FrameSent {
        session: SessionId,
        bytes: usize,
    },
    SendRejected {
        session: SessionId,
        bytes: usize,
        reason: SendRejectReason,
    },
    StreamFailed {
        session: SessionId,
        reason: String,
    },
    ReplacementReady {
        retired: SessionId,
        replacement: SessionId,
    },
}

pub(crate) struct AsterBehaviour {
    local_peer_id: PeerId,
    frame_limits: FrameLimits,
    negotiation_timeout: Duration,
    connections: HashSet<SessionId>,
    selected_by_peer: HashMap<PeerId, ConnectionId>,
    pending_replacements: HashMap<SessionId, SessionId>,
    ready_replacements: HashMap<SessionId, SessionId>,
    open_streams: HashSet<SessionId>,
    outbound_usage: HashMap<SessionId, QueueUsage>,
    pending: VecDeque<ToSwarm<AsterEvent, HandlerCommand>>,
}

impl AsterBehaviour {
    pub(crate) fn new(
        local_peer_id: PeerId,
        frame_limits: FrameLimits,
        negotiation_timeout: Duration,
    ) -> Self {
        Self {
            local_peer_id,
            frame_limits,
            negotiation_timeout,
            connections: HashSet::new(),
            selected_by_peer: HashMap::new(),
            pending_replacements: HashMap::new(),
            ready_replacements: HashMap::new(),
            open_streams: HashSet::new(),
            outbound_usage: HashMap::new(),
            pending: VecDeque::new(),
        }
    }

    pub(crate) fn activate(&mut self, session: SessionId) -> Result<(), ActivationError> {
        if !self.connections.contains(&session) {
            return Err(ActivationError::UnknownSession);
        }
        if let Some(selected) = self.selected_by_peer.get(&session.peer_id) {
            if *selected == session.connection_id {
                return Ok(());
            }
            return Err(ActivationError::PeerAlreadyHasSelectedSession);
        }
        self.selected_by_peer
            .insert(session.peer_id, session.connection_id);
        self.pending.push_back(ToSwarm::NotifyHandler {
            peer_id: session.peer_id,
            handler: NotifyHandler::One(session.connection_id),
            event: HandlerCommand::Activate,
        });
        Ok(())
    }

    pub(crate) fn deactivate(&mut self, session: SessionId) -> Result<(), ActivationError> {
        if self.selected_by_peer.get(&session.peer_id) != Some(&session.connection_id) {
            return Err(ActivationError::SessionNotSelected);
        }
        self.retire_selected(session);
        Ok(())
    }

    /// Orders retirement of the old physical carrier before activation of the
    /// replacement. The new connection can never inherit open-stream or queue
    /// state from the old `ConnectionId`.
    pub(crate) fn begin_replacement(
        &mut self,
        old: SessionId,
        new: SessionId,
    ) -> Result<(), ActivationError> {
        if old == new {
            return Err(ActivationError::SameSession);
        }
        if old.peer_id != new.peer_id {
            return Err(ActivationError::PeerMismatch);
        }
        if self.selected_by_peer.get(&old.peer_id) != Some(&old.connection_id) {
            return Err(ActivationError::SessionNotSelected);
        }
        if !self.connections.contains(&new) {
            return Err(ActivationError::UnknownSession);
        }
        self.retire_selected(old);
        self.pending_replacements.insert(old, new);
        Ok(())
    }

    pub(crate) fn complete_replacement(
        &mut self,
        old: SessionId,
        new: SessionId,
    ) -> Result<(), ActivationError> {
        if self.ready_replacements.get(&old) != Some(&new) {
            return Err(ActivationError::ReplacementNotReady);
        }
        if !self.connections.contains(&new) {
            self.ready_replacements.remove(&old);
            return Err(ActivationError::UnknownSession);
        }
        if self.selected_by_peer.contains_key(&new.peer_id) {
            return Err(ActivationError::PeerAlreadyHasSelectedSession);
        }
        self.activate(new)?;
        self.ready_replacements.remove(&old);
        Ok(())
    }

    fn retire_selected(&mut self, session: SessionId) {
        self.selected_by_peer.remove(&session.peer_id);
        self.open_streams.remove(&session);
        self.outbound_usage.remove(&session);
        self.pending.push_back(ToSwarm::NotifyHandler {
            peer_id: session.peer_id,
            handler: NotifyHandler::One(session.connection_id),
            event: HandlerCommand::Deactivate,
        });
        self.pending.push_back(ToSwarm::CloseConnection {
            peer_id: session.peer_id,
            connection: CloseConnection::One(session.connection_id),
        });
    }

    pub(crate) fn send_frame(
        &mut self,
        session: SessionId,
        frame: Vec<u8>,
    ) -> Result<(), SendFrameError> {
        if !self.connections.contains(&session) {
            return Err(SendFrameError::UnknownSession);
        }
        if !self.open_streams.contains(&session) {
            return Err(SendFrameError::StreamNotOpen);
        }
        if frame.is_empty() || frame.len() > self.frame_limits.max_frame_bytes {
            return Err(SendFrameError::InvalidLength);
        }
        let usage = self.outbound_usage.entry(session).or_default();
        if usage.frames >= self.frame_limits.max_queued_frames {
            return Err(SendFrameError::FrameCapacity);
        }
        if usage.bytes.saturating_add(frame.len()) > self.frame_limits.max_queued_bytes {
            return Err(SendFrameError::ByteCapacity);
        }
        let bytes = frame.len();
        usage.frames += 1;
        usage.bytes += bytes;
        self.pending.push_back(ToSwarm::NotifyHandler {
            peer_id: session.peer_id,
            handler: NotifyHandler::One(session.connection_id),
            event: HandlerCommand::SendFrame(frame),
        });
        Ok(())
    }

    #[cfg(test)]
    pub(crate) fn open_stream_count(&self) -> usize {
        self.open_streams.len()
    }

    fn release_outbound(&mut self, session: SessionId, bytes: usize) {
        let Some(usage) = self.outbound_usage.get_mut(&session) else {
            return;
        };
        usage.frames = usage.frames.saturating_sub(1);
        usage.bytes = usage.bytes.saturating_sub(bytes);
        if usage.frames == 0 {
            self.outbound_usage.remove(&session);
        }
    }

    fn fail_connection(&mut self, session: SessionId, reason: String) {
        self.open_streams.remove(&session);
        self.outbound_usage.remove(&session);
        if self.selected_by_peer.get(&session.peer_id) == Some(&session.connection_id) {
            self.selected_by_peer.remove(&session.peer_id);
        }
        self.pending
            .push_back(ToSwarm::GenerateEvent(AsterEvent::StreamFailed {
                session,
                reason,
            }));
        self.pending.push_back(ToSwarm::CloseConnection {
            peer_id: session.peer_id,
            connection: CloseConnection::One(session.connection_id),
        });
    }

    fn record_connection_closed(&mut self, session: SessionId) {
        self.connections.remove(&session);
        self.open_streams.remove(&session);
        self.outbound_usage.remove(&session);
        if self.selected_by_peer.get(&session.peer_id) == Some(&session.connection_id) {
            self.selected_by_peer.remove(&session.peer_id);
        }
        if let Some(replacement) = self.pending_replacements.remove(&session)
            && self.connections.contains(&replacement)
        {
            self.ready_replacements.insert(session, replacement);
            self.pending
                .push_back(ToSwarm::GenerateEvent(AsterEvent::ReplacementReady {
                    retired: session,
                    replacement,
                }));
        }
        self.pending_replacements
            .retain(|_, replacement| *replacement != session);
        self.ready_replacements
            .retain(|_, replacement| *replacement != session);
    }
}

impl NetworkBehaviour for AsterBehaviour {
    type ConnectionHandler = AsterHandler;
    type ToSwarm = AsterEvent;

    fn handle_pending_inbound_connection(
        &mut self,
        _connection_id: ConnectionId,
        _local_addr: &Multiaddr,
        _remote_addr: &Multiaddr,
    ) -> Result<(), ConnectionDenied> {
        Ok(())
    }

    fn handle_established_inbound_connection(
        &mut self,
        _connection_id: ConnectionId,
        peer: PeerId,
        _local_addr: &Multiaddr,
        _remote_addr: &Multiaddr,
    ) -> Result<THandler<Self>, ConnectionDenied> {
        Ok(AsterHandler::new(
            &self.local_peer_id,
            &peer,
            self.frame_limits,
            self.negotiation_timeout,
        ))
    }

    fn handle_pending_outbound_connection(
        &mut self,
        _connection_id: ConnectionId,
        _maybe_peer: Option<PeerId>,
        _addresses: &[Multiaddr],
        _effective_role: Endpoint,
    ) -> Result<Vec<Multiaddr>, ConnectionDenied> {
        Ok(Vec::new())
    }

    fn handle_established_outbound_connection(
        &mut self,
        _connection_id: ConnectionId,
        peer: PeerId,
        _addr: &Multiaddr,
        _role_override: Endpoint,
        _port_use: PortUse,
    ) -> Result<THandler<Self>, ConnectionDenied> {
        Ok(AsterHandler::new(
            &self.local_peer_id,
            &peer,
            self.frame_limits,
            self.negotiation_timeout,
        ))
    }

    fn on_swarm_event(&mut self, event: FromSwarm<'_>) {
        match event {
            FromSwarm::ConnectionEstablished(event) => {
                self.connections.insert(SessionId {
                    peer_id: event.peer_id,
                    connection_id: event.connection_id,
                });
            }
            FromSwarm::ConnectionClosed(event) => {
                self.record_connection_closed(SessionId {
                    peer_id: event.peer_id,
                    connection_id: event.connection_id,
                });
            }
            _ => {}
        }
    }

    fn on_connection_handler_event(
        &mut self,
        peer_id: PeerId,
        connection_id: ConnectionId,
        event: THandlerOutEvent<Self>,
    ) {
        let session = SessionId {
            peer_id,
            connection_id,
        };
        match event {
            HandlerEvent::StreamOpened(direction) => {
                if self.selected_by_peer.get(&peer_id) != Some(&connection_id) {
                    self.fail_connection(
                        session,
                        "Aster stream opened on a non-selected connection".to_owned(),
                    );
                    return;
                }
                if !self.open_streams.insert(session) {
                    self.fail_connection(
                        session,
                        "duplicate open notification for Aster substream".to_owned(),
                    );
                    return;
                }
                self.pending
                    .push_back(ToSwarm::GenerateEvent(AsterEvent::StreamOpened {
                        session,
                        direction,
                    }));
            }
            HandlerEvent::FrameReceived(frame) => {
                self.pending
                    .push_back(ToSwarm::GenerateEvent(AsterEvent::FrameReceived {
                        session,
                        frame,
                    }));
            }
            HandlerEvent::FrameSent(bytes) => {
                self.release_outbound(session, bytes);
                self.pending
                    .push_back(ToSwarm::GenerateEvent(AsterEvent::FrameSent {
                        session,
                        bytes,
                    }));
            }
            HandlerEvent::FrameRejected { bytes, reason } => {
                self.release_outbound(session, bytes);
                self.pending
                    .push_back(ToSwarm::GenerateEvent(AsterEvent::SendRejected {
                        session,
                        bytes,
                        reason,
                    }));
            }
            HandlerEvent::StreamFailed(reason) => self.fail_connection(session, reason),
        }
    }

    fn poll(
        &mut self,
        _cx: &mut Context<'_>,
    ) -> Poll<ToSwarm<Self::ToSwarm, THandlerInEvent<Self>>> {
        self.pending.pop_front().map_or(Poll::Pending, Poll::Ready)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use futures::task::noop_waker_ref;
    use libp2p::identity::Keypair;

    fn behaviour() -> AsterBehaviour {
        AsterBehaviour::new(
            Keypair::generate_ed25519().public().to_peer_id(),
            FrameLimits {
                max_frame_bytes: 1024,
                max_queued_frames: 2,
                max_queued_bytes: 2048,
            },
            Duration::from_secs(1),
        )
    }

    fn install_established(behaviour: &mut AsterBehaviour, session: SessionId) {
        behaviour.connections.insert(session);
    }

    #[test]
    fn handler_event_is_attributed_to_exact_connection_id() {
        let mut behaviour = behaviour();
        let peer_id = Keypair::generate_ed25519().public().to_peer_id();
        let connection_id = ConnectionId::new_unchecked(41);
        let session = SessionId {
            peer_id,
            connection_id,
        };
        install_established(&mut behaviour, session);
        behaviour.selected_by_peer.insert(peer_id, connection_id);
        behaviour.on_connection_handler_event(
            peer_id,
            connection_id,
            HandlerEvent::StreamOpened(StreamDirection::Inbound),
        );

        let mut cx = Context::from_waker(noop_waker_ref());
        match behaviour.poll(&mut cx) {
            Poll::Ready(ToSwarm::GenerateEvent(AsterEvent::StreamOpened {
                session,
                direction,
            })) => {
                assert_eq!(session.peer_id, peer_id);
                assert_eq!(session.connection_id, connection_id);
                assert_eq!(direction, StreamDirection::Inbound);
            }
            other => panic!("unexpected behaviour output: {other:?}"),
        }
    }

    #[test]
    fn replacement_activation_waits_for_close_and_explicit_completion() {
        let mut behaviour = behaviour();
        let peer_id = Keypair::generate_ed25519().public().to_peer_id();
        let old = SessionId {
            peer_id,
            connection_id: ConnectionId::new_unchecked(51),
        };
        let new = SessionId {
            peer_id,
            connection_id: ConnectionId::new_unchecked(52),
        };
        install_established(&mut behaviour, old);
        install_established(&mut behaviour, new);
        behaviour.activate(old).unwrap();
        let mut cx = Context::from_waker(noop_waker_ref());
        assert!(matches!(
            behaviour.poll(&mut cx),
            Poll::Ready(ToSwarm::NotifyHandler {
                handler: NotifyHandler::One(id),
                event: HandlerCommand::Activate,
                ..
            }) if id == old.connection_id
        ));

        behaviour.begin_replacement(old, new).unwrap();
        assert!(matches!(
            behaviour.poll(&mut cx),
            Poll::Ready(ToSwarm::NotifyHandler {
                handler: NotifyHandler::One(id),
                event: HandlerCommand::Deactivate,
                ..
            }) if id == old.connection_id
        ));
        assert!(matches!(
            behaviour.poll(&mut cx),
            Poll::Ready(ToSwarm::CloseConnection {
                connection: CloseConnection::One(id),
                ..
            }) if id == old.connection_id
        ));
        assert!(matches!(behaviour.poll(&mut cx), Poll::Pending));
        assert_eq!(
            behaviour.complete_replacement(old, new),
            Err(ActivationError::ReplacementNotReady)
        );

        behaviour.record_connection_closed(old);
        assert!(matches!(
            behaviour.poll(&mut cx),
            Poll::Ready(ToSwarm::GenerateEvent(AsterEvent::ReplacementReady {
                retired,
                replacement,
            })) if retired == old && replacement == new
        ));
        assert!(matches!(behaviour.poll(&mut cx), Poll::Pending));

        behaviour.complete_replacement(old, new).unwrap();
        assert!(matches!(
            behaviour.poll(&mut cx),
            Poll::Ready(ToSwarm::NotifyHandler {
                handler: NotifyHandler::One(id),
                event: HandlerCommand::Activate,
                ..
            }) if id == new.connection_id
        ));
    }

    #[test]
    fn send_frame_enforces_local_queue_bounds_before_notifying_handler() {
        let mut behaviour = behaviour();
        let session = SessionId {
            peer_id: Keypair::generate_ed25519().public().to_peer_id(),
            connection_id: ConnectionId::new_unchecked(61),
        };
        install_established(&mut behaviour, session);
        behaviour
            .selected_by_peer
            .insert(session.peer_id, session.connection_id);
        behaviour.open_streams.insert(session);

        assert_eq!(
            behaviour.send_frame(session, Vec::new()),
            Err(SendFrameError::InvalidLength)
        );
        behaviour.send_frame(session, vec![1; 1024]).unwrap();
        behaviour.send_frame(session, vec![2; 1024]).unwrap();
        assert_eq!(
            behaviour.send_frame(session, vec![3]),
            Err(SendFrameError::FrameCapacity)
        );

        let mut cx = Context::from_waker(noop_waker_ref());
        for expected in [vec![1; 1024], vec![2; 1024]] {
            assert!(matches!(
                behaviour.poll(&mut cx),
                Poll::Ready(ToSwarm::NotifyHandler {
                    event: HandlerCommand::SendFrame(frame),
                    ..
                }) if frame == expected
            ));
        }
    }
}
