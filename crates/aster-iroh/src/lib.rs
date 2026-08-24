//! Profile-independent authenticated Iroh carrier for Aster.
//!
//! This crate owns endpoint lifecycle and bounded opaque byte exchanges only.
//! It deliberately knows nothing about Aster items, reconciliation, mission
//! membership, or application policy.

#![forbid(unsafe_code)]

use std::{
    collections::BTreeSet, error::Error, fmt, net::SocketAddr, str::FromStr, time::Duration,
};

use iroh::{
    Endpoint as IrohEndpoint, EndpointAddr, RelayMode,
    endpoint::{
        NetReportConfig, PortmapperConfig, QuicTransportConfig, ReadToEndError, VarInt, presets,
    },
};
use tokio::time::timeout;

pub use iroh::{EndpointId, SecretKey};

/// ALPN used by the bounded opaque carrier protocol.
///
/// This version identifies carrier framing only; it does not define an Aster
/// item encoding or reconciliation profile.
pub const ALPN: &[u8] = b"aster-carrier/1";

/// Default upper bound for one opaque request or response.
pub const DEFAULT_MAX_EXCHANGE_BYTES: usize = 2 * 1024 * 1024;

/// Direct peer identity and address supplied by an operator or coordinator.
#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub struct ExpectedPeer {
    /// Iroh endpoint identity expected during the TLS handshake.
    pub id: EndpointId,
    /// Explicit direct socket address; the carrier performs no hosted lookup.
    pub address: SocketAddr,
}

impl fmt::Display for ExpectedPeer {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "{}@{}", self.id, self.address)
    }
}

impl FromStr for ExpectedPeer {
    type Err = CarrierError;

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        let (id, address) = value.split_once('@').ok_or_else(|| {
            CarrierError::Configuration("peer must be ENDPOINT_ID@IP:PORT".into())
        })?;
        Ok(Self {
            id: id.parse().map_err(|error| {
                CarrierError::Configuration(format!("invalid peer id: {error}"))
            })?,
            address: address.parse().map_err(|error| {
                CarrierError::Configuration(format!("invalid peer address: {error}"))
            })?,
        })
    }
}

/// Bounded endpoint configuration.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct EndpointConfig {
    /// Socket on which the endpoint listens.
    pub bind: SocketAddr,
    /// Bound for establishing or accepting an authenticated connection.
    pub connect_timeout: Duration,
    /// Bound for one opaque request/response exchange.
    pub exchange_timeout: Duration,
    /// Maximum request or response bytes.
    pub max_exchange_bytes: usize,
}

impl EndpointConfig {
    /// Creates a loopback-friendly direct configuration with conservative bounds.
    pub fn direct(bind: SocketAddr) -> Self {
        Self {
            bind,
            connect_timeout: Duration::from_secs(10),
            exchange_timeout: Duration::from_secs(10),
            max_exchange_bytes: DEFAULT_MAX_EXCHANGE_BYTES,
        }
    }
}

/// Carrier failure at a bounded, operator-visible stage.
#[derive(Debug)]
pub enum CarrierError {
    /// Invalid local or peer configuration.
    Configuration(String),
    /// An Iroh or QUIC operation failed.
    Transport(String),
    /// A bounded operation made no progress before its deadline.
    Timeout(&'static str),
    /// An authenticated endpoint was not in the configured peer set.
    UnauthorizedPeer(EndpointId),
    /// An opaque frame exceeded its configured bound. `actual` is the exact
    /// local size or the smallest size proven by a bounded remote read.
    FrameTooLarge { actual: usize, maximum: usize },
}

impl fmt::Display for CarrierError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Configuration(message) => write!(formatter, "carrier configuration: {message}"),
            Self::Transport(message) => write!(formatter, "carrier transport: {message}"),
            Self::Timeout(stage) => write!(formatter, "carrier timed out during {stage}"),
            Self::UnauthorizedPeer(peer) => write!(formatter, "unauthorized carrier peer {peer}"),
            Self::FrameTooLarge { actual, maximum } => {
                write!(
                    formatter,
                    "carrier frame is at least {actual} bytes; maximum is {maximum}"
                )
            }
        }
    }
}

impl Error for CarrierError {}

/// A bound Iroh endpoint with hosted discovery, relays, and port mapping disabled.
#[derive(Clone)]
pub struct Endpoint {
    inner: IrohEndpoint,
    config: EndpointConfig,
}

impl Endpoint {
    /// Binds a direct endpoint using a caller-supplied secret.
    pub async fn bind(secret: SecretKey, config: EndpointConfig) -> Result<Self, CarrierError> {
        if config.connect_timeout.is_zero() {
            return Err(CarrierError::Configuration(
                "connect timeout must be nonzero".into(),
            ));
        }
        if config.exchange_timeout.is_zero() {
            return Err(CarrierError::Configuration(
                "exchange timeout must be nonzero".into(),
            ));
        }
        if config.max_exchange_bytes == 0 || config.max_exchange_bytes > u32::MAX as usize {
            return Err(CarrierError::Configuration(
                "max exchange bytes must be within 1..=u32::MAX".into(),
            ));
        }
        let window = config.max_exchange_bytes as u32;
        let transport = QuicTransportConfig::builder()
            .max_concurrent_bidi_streams(VarInt::from_u32(16))
            .max_concurrent_uni_streams(VarInt::from_u32(0))
            .stream_receive_window(VarInt::from_u32(window))
            .receive_window(VarInt::from_u32(window.saturating_mul(2)))
            .send_window(u64::from(window.saturating_mul(2)))
            .build();
        let inner = IrohEndpoint::builder(presets::Minimal)
            .secret_key(secret)
            .clear_address_lookup()
            .clear_relay_transports()
            .relay_mode(RelayMode::Disabled)
            .portmapper_config(PortmapperConfig::Disabled)
            .net_report_config(NetReportConfig::minimal())
            .transport_config(transport)
            .clear_ip_transports()
            .bind_addr(config.bind)
            .map_err(|error| CarrierError::Configuration(error.to_string()))?
            .alpns(vec![ALPN.to_vec()])
            .bind()
            .await
            .map_err(|error| CarrierError::Transport(error.to_string()))?;
        Ok(Self { inner, config })
    }

    /// Returns the authenticated endpoint identity.
    pub fn id(&self) -> EndpointId {
        self.inner.id()
    }

    /// Returns the actual local sockets after binding.
    pub fn bound_sockets(&self) -> Vec<SocketAddr> {
        self.inner.bound_sockets()
    }

    /// Connects to the exact expected identity at its explicit direct address.
    pub async fn connect(&self, peer: ExpectedPeer) -> Result<Connection, CarrierError> {
        let address = EndpointAddr::new(peer.id).with_ip_addr(peer.address);
        let inner = timeout(
            self.config.connect_timeout,
            self.inner.connect(address, ALPN),
        )
        .await
        .map_err(|_| CarrierError::Timeout("connect"))?
        .map_err(|error| CarrierError::Transport(error.to_string()))?;
        if inner.remote_id() != peer.id {
            return Err(CarrierError::UnauthorizedPeer(inner.remote_id()));
        }
        Ok(Connection {
            inner,
            exchange_timeout: self.config.exchange_timeout,
            max_exchange_bytes: self.config.max_exchange_bytes,
        })
    }

    /// Accepts one connection and rejects identities outside `allowed` before
    /// any application frame is read.
    pub async fn accept(&self, allowed: &BTreeSet<EndpointId>) -> Result<Connection, CarrierError> {
        let incoming = timeout(self.config.connect_timeout, self.inner.accept())
            .await
            .map_err(|_| CarrierError::Timeout("accept"))?
            .ok_or_else(|| CarrierError::Transport("endpoint stopped accepting".into()))?;
        let inner = timeout(self.config.connect_timeout, incoming)
            .await
            .map_err(|_| CarrierError::Timeout("handshake"))?
            .map_err(|error| CarrierError::Transport(error.to_string()))?;
        let remote = inner.remote_id();
        if !allowed.contains(&remote) {
            inner.close(1u8.into(), b"unauthorized peer");
            return Err(CarrierError::UnauthorizedPeer(remote));
        }
        Ok(Connection {
            inner,
            exchange_timeout: self.config.exchange_timeout,
            max_exchange_bytes: self.config.max_exchange_bytes,
        })
    }

    /// Closes the endpoint and waits for its background tasks.
    pub async fn close(&self) {
        self.inner.close().await;
    }
}

/// Authenticated, bounded opaque exchange channel.
#[derive(Clone)]
pub struct Connection {
    inner: iroh::endpoint::Connection,
    exchange_timeout: Duration,
    max_exchange_bytes: usize,
}

impl Connection {
    /// Returns the authenticated remote endpoint identity.
    pub fn remote_id(&self) -> EndpointId {
        self.inner.remote_id()
    }

    /// Sends one opaque request and reads one opaque response.
    pub async fn request(&self, request: &[u8]) -> Result<Vec<u8>, CarrierError> {
        self.request_with_total_limit(request, usize::MAX).await
    }

    /// Sends one exchange whose combined request/response bytes cannot exceed
    /// `total_limit`, in addition to the carrier's per-frame bound.
    pub async fn request_with_total_limit(
        &self,
        request: &[u8],
        total_limit: usize,
    ) -> Result<Vec<u8>, CarrierError> {
        let request_maximum = self.max_exchange_bytes.min(total_limit);
        ensure_frame_bound(request.len(), request_maximum)?;
        let response_maximum = self
            .max_exchange_bytes
            .min(total_limit.saturating_sub(request.len()));
        let result = timeout(self.exchange_timeout, async {
            let (mut send, mut receive) = self
                .inner
                .open_bi()
                .await
                .map_err(|error| CarrierError::Transport(error.to_string()))?;
            send.write_all(request)
                .await
                .map_err(|error| CarrierError::Transport(error.to_string()))?;
            send.finish()
                .map_err(|error| CarrierError::Transport(error.to_string()))?;
            receive
                .read_to_end(response_maximum)
                .await
                .map_err(|error| map_read_error(error, response_maximum))
        })
        .await;
        match result {
            Ok(result) => result,
            Err(_) => {
                self.inner.close(2u8.into(), b"exchange timeout");
                Err(CarrierError::Timeout("request/response"))
            }
        }
    }

    /// Accepts one opaque request, computes a synchronous response, and sends it.
    /// The returned boolean is the handler's explicit session-complete signal.
    pub async fn respond_once<F>(&self, handler: F) -> Result<bool, CarrierError>
    where
        F: FnOnce(&[u8]) -> Result<(Vec<u8>, bool), CarrierError>,
    {
        self.respond_once_with_total_limit(usize::MAX, handler)
            .await
    }

    /// Responds once while enforcing a combined request/response byte limit.
    pub async fn respond_once_with_total_limit<F>(
        &self,
        total_limit: usize,
        handler: F,
    ) -> Result<bool, CarrierError>
    where
        F: FnOnce(&[u8]) -> Result<(Vec<u8>, bool), CarrierError>,
    {
        let request_maximum = self.max_exchange_bytes.min(total_limit);
        let result = timeout(self.exchange_timeout, async {
            let (mut send, mut receive) = self
                .inner
                .accept_bi()
                .await
                .map_err(|error| CarrierError::Transport(error.to_string()))?;
            let request = receive
                .read_to_end(request_maximum)
                .await
                .map_err(|error| map_read_error(error, request_maximum))?;
            let (response, complete) = handler(&request)?;
            let response_maximum = self
                .max_exchange_bytes
                .min(total_limit.saturating_sub(request.len()));
            ensure_frame_bound(response.len(), response_maximum)?;
            send.write_all(&response)
                .await
                .map_err(|error| CarrierError::Transport(error.to_string()))?;
            send.finish()
                .map_err(|error| CarrierError::Transport(error.to_string()))?;
            match send
                .stopped()
                .await
                .map_err(|error| CarrierError::Transport(error.to_string()))?
            {
                None => {}
                Some(code) => {
                    return Err(CarrierError::Transport(format!(
                        "peer stopped response stream with code {code}"
                    )));
                }
            }
            Ok(complete)
        })
        .await;
        match result {
            Ok(result) => result,
            Err(_) => {
                self.inner.close(2u8.into(), b"exchange timeout");
                Err(CarrierError::Timeout("receive/respond"))
            }
        }
    }

    /// Closes this connection.
    pub fn close(&self) {
        self.inner.close(0u8.into(), b"complete");
    }
}

fn ensure_frame_bound(actual: usize, maximum: usize) -> Result<(), CarrierError> {
    if actual <= maximum {
        Ok(())
    } else {
        Err(CarrierError::FrameTooLarge { actual, maximum })
    }
}

fn map_read_error(error: ReadToEndError, maximum: usize) -> CarrierError {
    match error {
        ReadToEndError::TooLong => CarrierError::FrameTooLarge {
            actual: maximum.saturating_add(1),
            maximum,
        },
        error => CarrierError::Transport(error.to_string()),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn loopback(endpoint: &Endpoint) -> SocketAddr {
        endpoint
            .bound_sockets()
            .into_iter()
            .find(SocketAddr::is_ipv4)
            .expect("IPv4 loopback binding")
    }

    #[tokio::test]
    async fn exact_peer_identity_exchanges_opaque_bytes() {
        let server = Endpoint::bind(
            SecretKey::generate(),
            EndpointConfig::direct("127.0.0.1:0".parse().expect("address")),
        )
        .await
        .expect("server");
        let client = Endpoint::bind(
            SecretKey::generate(),
            EndpointConfig::direct("127.0.0.1:0".parse().expect("address")),
        )
        .await
        .expect("client");
        let allowed = BTreeSet::from([client.id()]);
        let server_task = tokio::spawn({
            let server = server.clone();
            async move {
                let connection = server.accept(&allowed).await.expect("accept");
                assert!(
                    connection
                        .respond_once(|request| Ok((request.to_vec(), true)))
                        .await
                        .expect("respond")
                );
            }
        });
        let connection = client
            .connect(ExpectedPeer {
                id: server.id(),
                address: loopback(&server),
            })
            .await
            .expect("connect");
        assert_eq!(connection.request(b"ping").await.expect("request"), b"ping");
        server_task.await.expect("server task");
        client.close().await;
        server.close().await;
    }

    #[tokio::test]
    async fn combined_exchange_limit_is_exact_and_enforced_by_the_responder() {
        let server = Endpoint::bind(
            SecretKey::generate(),
            EndpointConfig::direct("127.0.0.1:0".parse().expect("address")),
        )
        .await
        .expect("server");
        let client = Endpoint::bind(
            SecretKey::generate(),
            EndpointConfig::direct("127.0.0.1:0".parse().expect("address")),
        )
        .await
        .expect("client");
        let allowed = BTreeSet::from([client.id()]);
        let server_task = tokio::spawn({
            let server = server.clone();
            async move {
                let connection = server.accept(&allowed).await.expect("accept");
                assert!(
                    connection
                        .respond_once_with_total_limit(8, |request| {
                            assert_eq!(request, b"ping");
                            Ok((b"pong".to_vec(), true))
                        })
                        .await
                        .expect("exact combined limit")
                );
                match connection
                    .respond_once_with_total_limit(7, |request| {
                        assert_eq!(request, b"ping");
                        Ok((b"pong".to_vec(), true))
                    })
                    .await
                {
                    Err(CarrierError::FrameTooLarge {
                        actual: 4,
                        maximum: 3,
                    }) => {}
                    Err(error) => panic!("combined limit failed at the wrong stage: {error}"),
                    Ok(_) => panic!("response exceeded the combined exchange limit"),
                }
            }
        });
        let connection = client
            .connect(ExpectedPeer {
                id: server.id(),
                address: loopback(&server),
            })
            .await
            .expect("connect");
        assert_eq!(
            connection
                .request_with_total_limit(b"ping", 8)
                .await
                .expect("exact combined limit"),
            b"pong"
        );
        assert!(
            connection
                .request_with_total_limit(b"ping", 8)
                .await
                .is_err()
        );
        server_task.await.expect("server task");
        client.close().await;
        server.close().await;
    }

    #[tokio::test]
    async fn wrong_expected_identity_fails_before_an_application_exchange() {
        let mut config = EndpointConfig::direct("127.0.0.1:0".parse().expect("address"));
        config.connect_timeout = Duration::from_secs(2);
        let server = Endpoint::bind(SecretKey::generate(), config)
            .await
            .expect("server");
        let client = Endpoint::bind(SecretKey::generate(), config)
            .await
            .expect("client");

        // Drive the actual server-side handshake and record that the client's
        // datagram reached the intended socket. Without this task, a timeout or
        // an idle server could make a weak `is_err()` assertion false-pass.
        let (observed_tx, observed_rx) = tokio::sync::oneshot::channel();
        let server_task = tokio::spawn({
            let server = server.clone();
            async move {
                let incoming = timeout(config.connect_timeout, server.inner.accept())
                    .await
                    .expect("server observed incoming before deadline")
                    .expect("server remained open");
                observed_tx.send(()).expect("observation receiver open");
                timeout(config.connect_timeout, incoming).await
            }
        });

        let result = client
            .connect(ExpectedPeer {
                id: SecretKey::generate().public(),
                address: loopback(&server),
            })
            .await;
        match result {
            Err(CarrierError::Transport(_)) => {}
            Err(error) => panic!("wrong identity failed at the wrong stage: {error}"),
            Ok(_) => panic!("wrong identity authenticated"),
        }
        timeout(config.connect_timeout, observed_rx)
            .await
            .expect("server observation deadline")
            .expect("server observation sender");
        let handshake = server_task.await.expect("server task");
        assert!(
            matches!(handshake, Ok(Err(_))),
            "server handshake should reject the client's wrong expected identity"
        );

        client.close().await;
        server.close().await;
    }

    #[tokio::test]
    async fn inbound_identity_is_rejected_before_a_connection_is_returned() {
        let server = Endpoint::bind(
            SecretKey::generate(),
            EndpointConfig::direct("127.0.0.1:0".parse().expect("address")),
        )
        .await
        .expect("server");
        let client = Endpoint::bind(
            SecretKey::generate(),
            EndpointConfig::direct("127.0.0.1:0".parse().expect("address")),
        )
        .await
        .expect("client");
        let client_id = client.id();
        let server_task = tokio::spawn({
            let server = server.clone();
            async move { server.accept(&BTreeSet::new()).await }
        });

        let _client_result = client
            .connect(ExpectedPeer {
                id: server.id(),
                address: loopback(&server),
            })
            .await;
        match server_task.await.expect("server task") {
            Err(CarrierError::UnauthorizedPeer(peer)) => assert_eq!(peer, client_id),
            Err(error) => panic!("unexpected rejection stage: {error}"),
            Ok(_) => panic!("unlisted peer was accepted"),
        }

        client.close().await;
        server.close().await;
    }

    #[test]
    fn frame_bound_errors_preserve_the_enforced_limit() {
        assert!(ensure_frame_bound(8, 8).is_ok());
        assert!(matches!(
            ensure_frame_bound(9, 8),
            Err(CarrierError::FrameTooLarge {
                actual: 9,
                maximum: 8
            })
        ));
        assert!(matches!(
            map_read_error(ReadToEndError::TooLong, 8),
            CarrierError::FrameTooLarge {
                actual: 9,
                maximum: 8
            }
        ));
    }
}
