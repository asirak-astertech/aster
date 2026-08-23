//! Bounded rust-libp2p 0.56 carrier provider for Aster.
//!
//! This crate deliberately contains no Aster database, blob store,
//! credentials, semantic runtime, or host state. It owns one libp2p `Swarm`,
//! physical connections, exactly selected `/aster/sync/2` substreams, and
//! bounded framing. The host supervisor supplies discovery, admission,
//! authorization, and node-global resource accounting.

mod adapter;
mod behaviour;
mod framing;
mod protocol;
mod types;

pub use adapter::{AdapterConfig, AdapterError, Libp2pAdapter};
pub use behaviour::{ActivationError, SendFrameError};
pub use libp2p::{
    Multiaddr, PeerId, core::transport::ListenerId, identity::Keypair, swarm::ConnectionId,
};
pub use protocol::ASTER_PROTOCOL;
pub use types::{
    CarrierDescriptor, CarrierPath, CarrierSelectionError, DialCandidate, NatReachability,
    ProviderEvent, SessionId, StreamDirection, expected_stream_direction, select_preferred_carrier,
};
