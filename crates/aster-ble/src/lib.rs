//! BTLE transport adapter for already-fragmented frames and one-to-many
//! advertisement support.
//!
//! Operating-system Bluetooth APIs remain behind [`BleRadio`]. The adapter is a
//! complete link implementation; adding a platform radio changes no protocol or
//! synchronization code.

#![forbid(unsafe_code)]

use aster_mesh::link::{Link, LinkCharacteristics, ReceivedFrame};
use aster_mesh::model::NodeId;
use std::collections::BTreeMap;
use std::io;
use std::sync::RwLock;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::{Duration, Instant};

const MAX_NEGOTIATED_PEERS: usize = 256;

/// One opaque radio fragment received from a BTLE controller integration.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct BlePacket {
    /// Authenticated or connection-bound peer hint.
    pub peer: NodeId,
    /// Opaque application fragment bytes.
    pub bytes: Vec<u8>,
}

/// Narrow platform radio contract used by [`BleLink`].
///
/// Implementations map unicast to an L2CAP credit-based channel when available,
/// with GATT write-without-response/notification as a fallback. Broadcast maps to
/// encrypted service/manufacturer data and may be more size constrained.
pub trait BleRadio: Send + Sync {
    /// Stable diagnostics name.
    fn name(&self) -> &str;

    /// Maximum application bytes accepted by one unicast operation.
    fn unicast_mtu(&self) -> usize;

    /// Maximum application bytes accepted by one advertisement operation.
    fn broadcast_mtu(&self) -> Option<usize>;

    /// Sends one opaque radio packet.
    ///
    /// # Errors
    ///
    /// Returns a platform I/O error or `InvalidInput` when bytes exceed the
    /// driver's current MTU.
    fn send(&self, peer: NodeId, bytes: &[u8]) -> io::Result<()>;

    /// Emits one opaque advertisement received by every eligible listener.
    ///
    /// # Errors
    ///
    /// Returns `Unsupported` when broadcast data is unavailable or a platform
    /// I/O error.
    fn broadcast(&self, bytes: &[u8]) -> io::Result<()>;

    /// Receives without blocking.
    ///
    /// # Errors
    ///
    /// Returns a platform I/O error. `Ok(None)` means no packet is ready.
    fn try_receive(&self) -> io::Result<Option<BlePacket>>;

    /// Enables or disables advertising/scanning according to emission policy.
    ///
    /// # Errors
    ///
    /// Returns a platform configuration error.
    fn set_discovery(&self, enabled: bool) -> io::Result<()>;

    /// Current useful bit-rate estimate, if known.
    fn bits_per_second(&self) -> Option<u64> {
        None
    }
}

/// MTU-aware BTLE link adapter.
#[derive(Debug)]
pub struct BleLink<R: BleRadio> {
    radio: R,
    discovery_enabled: AtomicBool,
    peer_mtu: RwLock<BTreeMap<NodeId, usize>>,
}

impl<R: BleRadio> BleLink<R> {
    /// Creates an adapter. Fragment identity and bounded reassembly are owned by
    /// the transport-neutral runtime; this layer carries each encoded fragment
    /// exactly once.
    pub fn new(radio: R, _local_node: NodeId) -> Self {
        Self {
            radio,
            discovery_enabled: AtomicBool::new(true),
            peer_mtu: RwLock::new(BTreeMap::new()),
        }
    }

    /// Records a connection-specific negotiated ATT/L2CAP MTU.
    pub fn set_peer_mtu(&self, peer: NodeId, mtu: usize) -> io::Result<()> {
        if mtu <= aster_mesh::fragment::HEADER_LEN {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "negotiated BTLE MTU cannot carry an Aster fragment",
            ));
        }
        let mut peers = self.peer_mtu.write().map_err(lock_error)?;
        if !peers.contains_key(&peer) && peers.len() >= MAX_NEGOTIATED_PEERS {
            return Err(io::Error::other("BTLE negotiated-peer capacity reached"));
        }
        peers.insert(peer, mtu.min(self.radio.unicast_mtu()));
        Ok(())
    }

    /// Drops only link-local partial fragments for a disconnected peer. Verified
    /// object and blob-block progress lives in the core store and is unaffected.
    pub fn disconnected(&self, peer: &NodeId) -> io::Result<()> {
        self.peer_mtu.write().map_err(lock_error)?.remove(peer);
        Ok(())
    }

    fn send_unicast(&self, peer: NodeId, frame: &[u8]) -> io::Result<()> {
        let mtu = self
            .peer_mtu
            .read()
            .map_err(lock_error)?
            .get(&peer)
            .copied()
            .unwrap_or_else(|| self.radio.unicast_mtu());
        if frame.len() > mtu {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "encoded frame exceeds negotiated BTLE MTU",
            ));
        }
        self.radio.send(peer, frame)
    }

    fn send_broadcast(&self, frame: &[u8]) -> io::Result<()> {
        let mtu = self.radio.broadcast_mtu().ok_or_else(|| {
            io::Error::new(io::ErrorKind::Unsupported, "BTLE broadcast unavailable")
        })?;
        if frame.len() > mtu {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "encoded frame exceeds BTLE advertisement MTU",
            ));
        }
        self.radio.broadcast(frame)
    }
}

impl<R: BleRadio> Link for BleLink<R> {
    fn name(&self) -> &str {
        self.radio.name()
    }

    fn characteristics(&self) -> LinkCharacteristics {
        let unicast_mtu = self.radio.unicast_mtu();
        let safe_mtu = self
            .radio
            .broadcast_mtu()
            .map_or(unicast_mtu, |broadcast| broadcast.min(unicast_mtu));
        LinkCharacteristics {
            mtu: u16::try_from(safe_mtu).unwrap_or(u16::MAX),
            bits_per_second: self.radio.bits_per_second(),
            cost: 64,
            emission: 96,
            broadcast: self.radio.broadcast_mtu().is_some(),
        }
    }

    fn send(&self, peer: Option<NodeId>, frame: &[u8]) -> io::Result<()> {
        match peer {
            Some(peer) => self.send_unicast(peer, frame),
            None => self.send_broadcast(frame),
        }
    }

    fn try_receive(&self) -> io::Result<Option<ReceivedFrame>> {
        while let Some(packet) = self.radio.try_receive()? {
            let mtu = self
                .peer_mtu
                .read()
                .map_err(lock_error)?
                .get(&packet.peer)
                .copied()
                .unwrap_or_else(|| self.radio.unicast_mtu());
            if packet.bytes.len() <= mtu {
                return Ok(Some(ReceivedFrame {
                    peer: Some(packet.peer),
                    bytes: packet.bytes,
                }));
            }
        }
        Ok(None)
    }

    fn set_discovery(&self, enabled: bool) -> io::Result<()> {
        self.radio.set_discovery(enabled)?;
        self.discovery_enabled.store(enabled, Ordering::Release);
        Ok(())
    }

    fn next_wakeup(&self) -> Option<Instant> {
        None
    }

    fn retry_floor(&self) -> Duration {
        Duration::from_millis(400)
    }
}

fn lock_error<T>(_: std::sync::PoisonError<T>) -> io::Error {
    io::Error::other("BTLE adapter state lock poisoned")
}

#[cfg(test)]
mod tests {
    use super::{BleLink, BlePacket, BleRadio};
    use aster_mesh::fragment::{Fragment, Reassembler, fragment};
    use aster_mesh::link::Link;
    use std::collections::VecDeque;
    use std::io;
    use std::sync::{Arc, Mutex};

    type BusPacket = ([u8; 32], Option<[u8; 32]>, Vec<u8>);
    type TestBus = Arc<Mutex<VecDeque<BusPacket>>>;

    #[derive(Clone, Debug)]
    struct TestRadio {
        name: &'static str,
        node: [u8; 32],
        members: [[u8; 32]; 3],
        mtu: usize,
        bus: TestBus,
        discovery: Arc<Mutex<bool>>,
        sends: Arc<Mutex<usize>>,
    }

    impl BleRadio for TestRadio {
        fn name(&self) -> &str {
            self.name
        }

        fn unicast_mtu(&self) -> usize {
            self.mtu
        }

        fn broadcast_mtu(&self) -> Option<usize> {
            Some(self.mtu)
        }

        fn send(&self, peer: [u8; 32], bytes: &[u8]) -> io::Result<()> {
            *self.sends.lock().unwrap() += 1;
            self.bus
                .lock()
                .unwrap()
                .push_back((self.node, Some(peer), bytes.to_vec()));
            Ok(())
        }

        fn broadcast(&self, bytes: &[u8]) -> io::Result<()> {
            *self.sends.lock().unwrap() += 1;
            let mut bus = self.bus.lock().unwrap();
            for member in self.members {
                if member != self.node {
                    bus.push_back((self.node, Some(member), bytes.to_vec()));
                }
            }
            Ok(())
        }

        fn try_receive(&self) -> io::Result<Option<BlePacket>> {
            let mut bus = self.bus.lock().unwrap();
            let index = bus.iter().position(|(sender, destination, _)| {
                sender != &self.node && destination.is_none_or(|peer| peer == self.node)
            });
            Ok(index
                .and_then(|index| bus.remove(index))
                .map(|(peer, _, bytes)| BlePacket { peer, bytes }))
        }

        fn set_discovery(&self, enabled: bool) -> io::Result<()> {
            *self.discovery.lock().unwrap() = enabled;
            Ok(())
        }

        fn bits_per_second(&self) -> Option<u64> {
            Some(8_000)
        }
    }

    fn radios(mtu: usize) -> (TestRadio, TestRadio, TestRadio) {
        let bus = Arc::new(Mutex::new(VecDeque::new()));
        let members = [[1; 32], [2; 32], [3; 32]];
        let make = |name, node| TestRadio {
            name,
            node,
            members,
            mtu,
            bus: Arc::clone(&bus),
            discovery: Arc::new(Mutex::new(true)),
            sends: Arc::new(Mutex::new(0)),
        };
        (make("a", [1; 32]), make("b", [2; 32]), make("c", [3; 32]))
    }

    #[test]
    fn carries_transport_neutral_fragments_once_at_small_mtu() {
        let (a, b, _) = radios(24);
        let a = BleLink::new(a, [1; 32]);
        let b = BleLink::new(b, [2; 32]);
        let message = b"sealed payload considerably larger than one BLE operation";
        let mut reassembler = Reassembler::new(2);
        let mut received = None;
        for part in fragment(message, 24, 7).unwrap() {
            let encoded = part.encode().unwrap();
            a.send(Some([2; 32]), &encoded).unwrap();
            let frame = b.try_receive().unwrap().unwrap();
            received = reassembler
                .push(Fragment::decode(&frame.bytes).unwrap())
                .unwrap()
                .or(received);
        }
        assert_eq!(received.as_deref(), Some(message.as_slice()));
        assert!(a.send(Some([2; 32]), message).is_err());
    }

    #[test]
    fn one_broadcast_is_visible_to_multiple_receivers() {
        let (a, b, c) = radios(64);
        let send_count = Arc::clone(&a.sends);
        let a = BleLink::new(a, [1; 32]);
        let b = BleLink::new(b, [2; 32]);
        let c = BleLink::new(c, [3; 32]);
        a.send(None, b"one-to-many sealed hint").unwrap();
        assert_eq!(
            b.try_receive().unwrap().unwrap().bytes,
            b"one-to-many sealed hint"
        );
        assert_eq!(
            c.try_receive().unwrap().unwrap().bytes,
            b"one-to-many sealed hint"
        );
        assert_eq!(*send_count.lock().unwrap(), 1);
    }

    #[test]
    fn constrained_policy_disables_discovery() {
        let (radio, _, _) = radios(64);
        let discovery = Arc::clone(&radio.discovery);
        let link = BleLink::new(radio, [1; 32]);
        link.set_discovery(false).unwrap();
        assert!(!*discovery.lock().unwrap());
    }
}
