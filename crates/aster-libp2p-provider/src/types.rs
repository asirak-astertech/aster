use libp2p::{Multiaddr, PeerId, swarm::ConnectionId};

/// Exact identity of one physical libp2p connection.
///
/// Aster authentication is scoped to this value. A replacement connection,
/// including a direct connection produced by DCUtR, has a new `ConnectionId`
/// and therefore requires a fresh Aster authentication exchange.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct SessionId {
    pub peer_id: PeerId,
    pub connection_id: ConnectionId,
}

/// Direction of the single negotiated Aster substream.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum StreamDirection {
    Inbound,
    Outbound,
}

/// A bounded, already-discovered address that the supervisor asks libp2p to dial.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct DialCandidate {
    /// Optional expected Noise identity. Address-only discovery leaves this
    /// unset and authenticates the actual remote `PeerId` after the handshake.
    pub expected_peer_id: Option<PeerId>,
    pub address: Multiaddr,
}

/// Whether a physical carrier is direct or traverses a circuit relay.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum CarrierPath {
    Direct,
    Relayed,
}

/// Provider metadata needed for symmetric physical-carrier selection.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct CarrierDescriptor {
    pub session: SessionId,
    pub path: CarrierPath,
    pub outbound: bool,
}

/// Failure to select one physical carrier identically at both endpoints.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum CarrierSelectionError {
    SelfConnection,
    PeerMismatch,
    Ambiguous,
}

impl std::fmt::Display for CarrierSelectionError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let message = match self {
            Self::SelfConnection => "cannot select a carrier to the local PeerId",
            Self::PeerMismatch => "carrier set contains a different remote PeerId",
            Self::Ambiguous => "carrier set has no unique symmetric tie-break winner",
        };
        formatter.write_str(message)
    }
}

impl std::error::Error for CarrierSelectionError {}

/// Returns the only permitted Aster stream direction for a peer pair.
///
/// The endpoint with the lexicographically lower libp2p `PeerId` opens the
/// stream. Both endpoints therefore derive complementary directions without
/// exchanging local-only connection identifiers.
pub fn expected_stream_direction(
    local_peer_id: PeerId,
    remote_peer_id: PeerId,
) -> Result<StreamDirection, CarrierSelectionError> {
    if local_peer_id == remote_peer_id {
        return Err(CarrierSelectionError::SelfConnection);
    }
    if local_peer_id.to_bytes() < remote_peer_id.to_bytes() {
        Ok(StreamDirection::Outbound)
    } else {
        Ok(StreamDirection::Inbound)
    }
}

/// Selects the same physical connection at both endpoints without comparing
/// local-only `ConnectionId` values.
///
/// Direct paths outrank relayed paths. If more than one carrier exists in the
/// best path class (the simultaneous-dial case), the lower `PeerId` selects
/// its outbound carrier and the higher `PeerId` selects the matching inbound
/// carrier. Multiple winners fail closed instead of guessing.
pub fn select_preferred_carrier(
    local_peer_id: PeerId,
    remote_peer_id: PeerId,
    carriers: &[CarrierDescriptor],
) -> Result<Option<SessionId>, CarrierSelectionError> {
    if local_peer_id == remote_peer_id {
        return Err(CarrierSelectionError::SelfConnection);
    }
    if carriers
        .iter()
        .any(|carrier| carrier.session.peer_id != remote_peer_id)
    {
        return Err(CarrierSelectionError::PeerMismatch);
    }
    let best_path = if carriers
        .iter()
        .any(|carrier| carrier.path == CarrierPath::Direct)
    {
        CarrierPath::Direct
    } else if carriers
        .iter()
        .any(|carrier| carrier.path == CarrierPath::Relayed)
    {
        CarrierPath::Relayed
    } else {
        return Ok(None);
    };
    let best = carriers
        .iter()
        .filter(|carrier| carrier.path == best_path)
        .collect::<Vec<_>>();
    if best.len() == 1 {
        return Ok(Some(best[0].session));
    }
    let choose_outbound = local_peer_id.to_bytes() < remote_peer_id.to_bytes();
    let mut winners = best
        .into_iter()
        .filter(|carrier| carrier.outbound == choose_outbound);
    let Some(winner) = winners.next() else {
        return Err(CarrierSelectionError::Ambiguous);
    };
    if winners.next().is_some() {
        return Err(CarrierSelectionError::Ambiguous);
    }
    Ok(Some(winner.session))
}

/// Reachability conclusion emitted by AutoNAT v1.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum NatReachability {
    Unknown,
    Private,
    Public(Multiaddr),
}

/// Provider events consumed by the future shared host supervisor.
#[derive(Debug)]
pub enum ProviderEvent {
    Listening {
        address: Multiaddr,
    },
    IncomingCarrier {
        connection_id: ConnectionId,
        local_address: Multiaddr,
        remote_address: Multiaddr,
    },
    CarrierEstablished {
        session: SessionId,
        path: CarrierPath,
        outbound: bool,
        remote_address: Multiaddr,
    },
    CarrierClosed {
        session: SessionId,
        cause: Option<String>,
    },
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
        reason: String,
    },
    StreamFailed {
        session: SessionId,
        reason: String,
    },
    ReplacementReady {
        retired: SessionId,
        replacement: SessionId,
    },
    IdentifyObserved {
        session: SessionId,
        observed_address: Multiaddr,
        supports_aster: bool,
    },
    NatStatusChanged {
        old: NatReachability,
        new: NatReachability,
    },
    RelayReservationAccepted {
        relay_peer_id: PeerId,
        renewal: bool,
    },
    RelayCircuitEstablished {
        peer_id: PeerId,
        inbound: bool,
    },
    HolePunchFinished {
        peer_id: PeerId,
        direct_connection: Option<ConnectionId>,
        error: Option<String>,
    },
    ExternalAddressCandidate {
        address: Multiaddr,
    },
    ExternalAddressConfirmed {
        address: Multiaddr,
    },
    TransportFailure {
        connection_id: Option<ConnectionId>,
        peer_id: Option<PeerId>,
        error: String,
    },
}

#[cfg(test)]
mod tests {
    use super::*;
    use libp2p::identity::Keypair;

    #[test]
    fn simultaneous_dial_tie_break_is_symmetric_without_connection_id_comparison() {
        let first = Keypair::generate_ed25519().public().to_peer_id();
        let second = Keypair::generate_ed25519().public().to_peer_id();
        let (low, high) = if first.to_bytes() < second.to_bytes() {
            (first, second)
        } else {
            (second, first)
        };
        let low_outbound = SessionId {
            peer_id: high,
            connection_id: ConnectionId::new_unchecked(5),
        };
        let low_inbound = SessionId {
            peer_id: high,
            connection_id: ConnectionId::new_unchecked(90),
        };
        let high_inbound = SessionId {
            peer_id: low,
            connection_id: ConnectionId::new_unchecked(700),
        };
        let high_outbound = SessionId {
            peer_id: low,
            connection_id: ConnectionId::new_unchecked(2),
        };
        let low_carriers = [
            CarrierDescriptor {
                session: low_outbound,
                path: CarrierPath::Direct,
                outbound: true,
            },
            CarrierDescriptor {
                session: low_inbound,
                path: CarrierPath::Direct,
                outbound: false,
            },
        ];
        let high_carriers = [
            CarrierDescriptor {
                session: high_inbound,
                path: CarrierPath::Direct,
                outbound: false,
            },
            CarrierDescriptor {
                session: high_outbound,
                path: CarrierPath::Direct,
                outbound: true,
            },
        ];
        assert_eq!(
            select_preferred_carrier(low, high, &low_carriers),
            Ok(Some(low_outbound))
        );
        assert_eq!(
            select_preferred_carrier(high, low, &high_carriers),
            Ok(Some(high_inbound))
        );
    }

    #[test]
    fn one_direct_carrier_outranks_relay_regardless_of_direction() {
        let local = Keypair::generate_ed25519().public().to_peer_id();
        let remote = Keypair::generate_ed25519().public().to_peer_id();
        let direct = SessionId {
            peer_id: remote,
            connection_id: ConnectionId::new_unchecked(1),
        };
        let carriers = [
            CarrierDescriptor {
                session: SessionId {
                    peer_id: remote,
                    connection_id: ConnectionId::new_unchecked(2),
                },
                path: CarrierPath::Relayed,
                outbound: true,
            },
            CarrierDescriptor {
                session: direct,
                path: CarrierPath::Direct,
                outbound: false,
            },
        ];
        assert_eq!(
            select_preferred_carrier(local, remote, &carriers),
            Ok(Some(direct))
        );
    }

    #[test]
    fn expected_stream_direction_is_complementary_and_rejects_self() {
        let first = Keypair::generate_ed25519().public().to_peer_id();
        let second = Keypair::generate_ed25519().public().to_peer_id();
        let first_direction = expected_stream_direction(first, second).unwrap();
        let second_direction = expected_stream_direction(second, first).unwrap();
        assert_ne!(first_direction, second_direction);
        assert_eq!(
            expected_stream_direction(first, first),
            Err(CarrierSelectionError::SelfConnection)
        );
    }
}
