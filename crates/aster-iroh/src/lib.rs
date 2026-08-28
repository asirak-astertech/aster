//! Profile-independent authenticated Iroh carrier for Aster.
//!
//! This crate owns endpoint lifecycle and bounded opaque byte exchanges only.
//! It deliberately knows nothing about Aster items, reconciliation, mission
//! membership, or application policy.

#![forbid(unsafe_code)]

use std::{
    collections::BTreeSet,
    error::Error,
    fmt,
    net::SocketAddr,
    str::FromStr,
    sync::{Arc, Mutex},
    time::Duration,
};

use futures::StreamExt;
use iroh::{
    Endpoint as IrohEndpoint, EndpointAddr, RelayConfig as IrohRelayConfig, RelayMode,
    TransportAddr,
    endpoint::{
        ConnectionError, NetReportConfig, PathEvent, PortmapperConfig, QuicTransportConfig,
        ReadToEndError, VarInt, presets,
    },
    tls::CaTlsConfig,
};
use tokio::time::timeout;

pub use iroh::{EndpointId, RelayUrl, SecretKey};

/// ALPN used by the bounded opaque carrier protocol.
///
/// This version identifies carrier framing only; it does not define an Aster
/// item encoding or reconciliation profile.
pub const ALPN: &[u8] = b"aster-carrier/1";

/// ALPN for the Iroh-QUIC-protected carrier profile.
///
/// This is deliberately distinct from [`ALPN`]. An endpoint advertises and
/// dials exactly one carrier security profile, so a profile mismatch fails the
/// QUIC handshake instead of retrying a different profile.
pub const IROH_QUIC_ALPN: &[u8] = b"aster-carrier-iroh-quic/1";

const CHANNEL_BINDING_EXPORTER_LABEL: &[u8] = b"EXPORTER-Aster-Iroh-Channel-Binding-v1";
const CHANNEL_BINDING_CONTEXT_DOMAIN: &[u8] = b"aster-iroh/channel-binding/context/v1";

/// Length of the channel-binding value derived from one QUIC TLS session.
pub const CHANNEL_BINDING_BYTES: usize = 32;

/// Keepalive interval for an open `IrohQuicV1` connection and its default path.
///
/// An idle connection is therefore not traffic-free. Bounded contacts should
/// close their owned connection when work completes instead of retaining it
/// indefinitely. The default legacy carrier profile intentionally leaves QUIC
/// keepalives unset to preserve its existing idle-transport behavior.
pub const CONNECTION_KEEPALIVE_INTERVAL: Duration = Duration::from_secs(5);

/// Maximum caller-owned context accepted for one channel-binding derivation.
pub const MAX_CHANNEL_BINDING_CONTEXT_BYTES: usize = 4 * 1024;

/// Exact carrier protection selected before an Iroh handshake begins.
///
/// This selection is carrier-only. Higher layers remain responsible for
/// authenticating the Aster mission profile and enforcing its policy minimum.
/// The default preserves the original `aster-carrier/1` wire behavior.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub enum CarrierSecurityProfile {
    /// Existing carrier framing used with the Aster hybrid mission record layer.
    #[default]
    HybridAsterRecordV1,
    /// Iroh QUIC protects ephemeral carrier frames for a channel-bound mission exchange.
    IrohQuicV1,
}

impl CarrierSecurityProfile {
    /// Returns the exact ALPN advertised and dialed for this carrier profile.
    pub const fn alpn(self) -> &'static [u8] {
        match self {
            Self::HybridAsterRecordV1 => ALPN,
            Self::IrohQuicV1 => IROH_QUIC_ALPN,
        }
    }
}

const fn connection_keepalive_interval(
    security_profile: CarrierSecurityProfile,
) -> Option<Duration> {
    match security_profile {
        CarrierSecurityProfile::HybridAsterRecordV1 => None,
        CarrierSecurityProfile::IrohQuicV1 => Some(CONNECTION_KEEPALIVE_INTERVAL),
    }
}

/// Caller-owned, bounded context for deriving an exact QUIC channel binding.
///
/// The Aster mission layer should supply one canonical encoding that includes
/// its complete security-profile identifier, authenticated policy generation,
/// both carrier endpoint identities, and both mission identities. The carrier
/// treats those bytes as opaque and additionally binds its selected ALPN.
#[derive(Clone, Copy, Eq, PartialEq)]
pub struct ChannelBindingContext<'a>(&'a [u8]);

impl<'a> ChannelBindingContext<'a> {
    /// Validates a nonempty canonical application context.
    pub fn new(bytes: &'a [u8]) -> Result<Self, CarrierError> {
        if bytes.is_empty() || bytes.len() > MAX_CHANNEL_BINDING_CONTEXT_BYTES {
            return Err(CarrierError::Configuration(format!(
                "channel-binding context must be within 1..={MAX_CHANNEL_BINDING_CONTEXT_BYTES} bytes"
            )));
        }
        Ok(Self(bytes))
    }

    fn as_bytes(self) -> &'a [u8] {
        self.0
    }
}

impl fmt::Debug for ChannelBindingContext<'_> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ChannelBindingContext")
            .field("bytes", &self.0.len())
            .finish()
    }
}

/// Opaque binding to one exact Iroh QUIC TLS session and application context.
#[derive(Clone, Eq, PartialEq)]
pub struct ChannelBinding([u8; CHANNEL_BINDING_BYTES]);

impl ChannelBinding {
    /// Borrows the fixed-length binding for a higher-layer authenticated transcript.
    pub fn as_bytes(&self) -> &[u8; CHANNEL_BINDING_BYTES] {
        &self.0
    }
}

impl fmt::Debug for ChannelBinding {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("ChannelBinding([REDACTED])")
    }
}

const RESPONSE_CONSUMED_MARKER: &[u8] = b"\0";

/// Default upper bound for one opaque request or response.
pub const DEFAULT_MAX_EXCHANGE_BYTES: usize = 2 * 1024 * 1024;

/// Maximum number of direct socket addresses in one controlled peer route.
pub const MAX_DIRECT_ADDRESSES: usize = 8;

/// Maximum serialized length of one pinned relay URL.
pub const MAX_RELAY_URL_BYTES: usize = 2 * 1024;

/// Maximum serialized length of one controlled peer route.
///
/// The allowance above [`MAX_RELAY_URL_BYTES`] covers one endpoint ID,
/// separators, and [`MAX_DIRECT_ADDRESSES`] maximally formatted socket
/// addresses with conservative headroom.
pub const MAX_PEER_ROUTE_TEXT_BYTES: usize = MAX_RELAY_URL_BYTES + 1_024;

/// Maximum number of explicit CA roots accepted for one pinned relay.
pub const MAX_RELAY_CA_ROOTS: usize = 8;

/// Maximum DER length of one explicit relay CA root.
pub const MAX_RELAY_CA_ROOT_BYTES: usize = 64 * 1024;

/// Maximum combined DER length of all explicit relay CA roots.
pub const MAX_RELAY_CA_ROOT_TOTAL_BYTES: usize = 256 * 1024;

/// Maximum selected-path transition count retained by an observation witness.
pub const MAX_PATH_TRANSITIONS: u16 = 1_024;

/// A controlled peer locator with bounded initial direct candidates and one pinned relay.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PeerRoute {
    id: EndpointId,
    direct_addresses: Vec<SocketAddr>,
    relay_url: RelayUrl,
}

impl PeerRoute {
    /// Constructs an authenticated route with an exact identity and relay.
    ///
    /// The direct list bounds operator-supplied initial locators. After peer
    /// authentication, Iroh NAT negotiation may derive additional direct paths.
    /// Use [`Endpoint::bind_relay_only`] to preclude all IP paths.
    pub fn new(
        id: EndpointId,
        direct_addresses: impl IntoIterator<Item = SocketAddr>,
        relay_url: RelayUrl,
    ) -> Result<Self, CarrierError> {
        validate_relay_url(&relay_url)?;
        let mut unique = BTreeSet::new();
        for address in direct_addresses {
            if unique.len() == MAX_DIRECT_ADDRESSES {
                return Err(CarrierError::Configuration(format!(
                    "peer route has more than {MAX_DIRECT_ADDRESSES} direct addresses"
                )));
            }
            if !unique.insert(address) {
                return Err(CarrierError::Configuration(format!(
                    "peer route contains duplicate direct address {address}"
                )));
            }
        }
        Ok(Self {
            id,
            direct_addresses: unique.into_iter().collect(),
            relay_url,
        })
    }

    /// Returns the exact authenticated endpoint identity.
    pub fn id(&self) -> EndpointId {
        self.id
    }

    /// Returns the sorted operator-supplied initial direct candidates.
    pub fn direct_addresses(&self) -> &[SocketAddr] {
        &self.direct_addresses
    }

    /// Returns the single pinned relay URL.
    pub fn relay_url(&self) -> &RelayUrl {
        &self.relay_url
    }
}

impl fmt::Display for PeerRoute {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "{}@", self.id)?;
        for (index, address) in self.direct_addresses.iter().enumerate() {
            if index != 0 {
                formatter.write_str(",")?;
            }
            write!(formatter, "{address}")?;
        }
        write!(formatter, "#{}", self.relay_url)
    }
}

impl FromStr for PeerRoute {
    type Err = CarrierError;

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        if value.len() > MAX_PEER_ROUTE_TEXT_BYTES {
            return Err(CarrierError::Configuration(format!(
                "peer route exceeds {MAX_PEER_ROUTE_TEXT_BYTES} bytes"
            )));
        }
        let (peer, relay_url) = value.split_once('#').ok_or_else(|| {
            CarrierError::Configuration(
                "route must be ENDPOINT_ID@IP:PORT[,IP:PORT]#HTTPS_RELAY_URL".into(),
            )
        })?;
        if relay_url.contains('#') {
            return Err(CarrierError::Configuration(
                "route must contain exactly one relay separator".into(),
            ));
        }
        if relay_url.len() > MAX_RELAY_URL_BYTES {
            return Err(CarrierError::Configuration(format!(
                "relay URL exceeds {MAX_RELAY_URL_BYTES} bytes"
            )));
        }
        let (id, direct_addresses) = peer.split_once('@').ok_or_else(|| {
            CarrierError::Configuration(
                "route must be ENDPOINT_ID@IP:PORT[,IP:PORT]#HTTPS_RELAY_URL".into(),
            )
        })?;
        let id = id
            .parse()
            .map_err(|error| CarrierError::Configuration(format!("invalid peer id: {error}")))?;
        let relay_url = relay_url
            .parse()
            .map_err(|error| CarrierError::Configuration(format!("invalid relay URL: {error}")))?;
        let mut addresses = Vec::new();
        if !direct_addresses.is_empty() {
            for address in direct_addresses.split(',') {
                if addresses.len() == MAX_DIRECT_ADDRESSES {
                    return Err(CarrierError::Configuration(format!(
                        "peer route has more than {MAX_DIRECT_ADDRESSES} direct addresses"
                    )));
                }
                addresses.push(address.parse().map_err(|error| {
                    CarrierError::Configuration(format!("invalid peer address: {error}"))
                })?);
            }
        }
        Self::new(id, addresses, relay_url)
    }
}

/// TLS trust and URL pin for the one operator-selected relay.
///
/// An empty explicit-root list means the embedded WebPKI roots are used.
/// Nonempty roots replace that set, making a private relay trust boundary exact.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PinnedRelay {
    url: RelayUrl,
    ca_roots_der: Arc<[Vec<u8>]>,
}

impl PinnedRelay {
    /// Pins an HTTPS relay using the embedded WebPKI trust roots.
    pub fn new(url: RelayUrl) -> Result<Self, CarrierError> {
        validate_relay_url(&url)?;
        Ok(Self {
            url,
            ca_roots_der: Arc::from([]),
        })
    }

    /// Pins an HTTPS relay using only the supplied DER-encoded CA roots.
    pub fn with_ca_roots(
        url: RelayUrl,
        roots: impl IntoIterator<Item = Vec<u8>>,
    ) -> Result<Self, CarrierError> {
        validate_relay_url(&url)?;
        let mut ca_roots_der = Vec::new();
        let mut validated_roots = rustls::RootCertStore::empty();
        let mut total = 0usize;
        for root in roots {
            if ca_roots_der.len() == MAX_RELAY_CA_ROOTS {
                return Err(CarrierError::Configuration(format!(
                    "relay trust has more than {MAX_RELAY_CA_ROOTS} CA roots"
                )));
            }
            if root.is_empty() || root.len() > MAX_RELAY_CA_ROOT_BYTES {
                return Err(CarrierError::Configuration(format!(
                    "relay CA root must be within 1..={MAX_RELAY_CA_ROOT_BYTES} DER bytes"
                )));
            }
            total = total.checked_add(root.len()).ok_or_else(|| {
                CarrierError::Configuration("relay CA root byte total overflowed".into())
            })?;
            if total > MAX_RELAY_CA_ROOT_TOTAL_BYTES {
                return Err(CarrierError::Configuration(format!(
                    "relay CA roots exceed {MAX_RELAY_CA_ROOT_TOTAL_BYTES} total DER bytes"
                )));
            }
            validated_roots
                .add(rustls::pki_types::CertificateDer::from(root.clone()))
                .map_err(|error| {
                    CarrierError::Configuration(format!(
                        "invalid relay CA root DER certificate: {error}"
                    ))
                })?;
            ca_roots_der.push(root);
        }
        if ca_roots_der.is_empty() {
            return Err(CarrierError::Configuration(
                "explicit relay CA trust requires at least one root".into(),
            ));
        }
        Ok(Self {
            url,
            ca_roots_der: ca_roots_der.into(),
        })
    }

    /// Returns the pinned relay URL.
    pub fn url(&self) -> &RelayUrl {
        &self.url
    }

    /// Returns explicit DER CA roots, or an empty slice for embedded WebPKI trust.
    pub fn ca_roots_der(&self) -> &[Vec<u8>] {
        &self.ca_roots_der
    }
}

fn validate_relay_url(url: &RelayUrl) -> Result<(), CarrierError> {
    if url.as_str().len() > MAX_RELAY_URL_BYTES {
        return Err(CarrierError::Configuration(format!(
            "relay URL exceeds {MAX_RELAY_URL_BYTES} bytes"
        )));
    }
    if url.scheme() != "https" {
        return Err(CarrierError::Configuration(
            "relay URL must use HTTPS".into(),
        ));
    }
    if url.host().is_none() || !url.username().is_empty() || url.password().is_some() {
        return Err(CarrierError::Configuration(
            "relay URL must have a host and no user information".into(),
        ));
    }
    if url.path() != "/" {
        return Err(CarrierError::Configuration(
            "relay URL must identify the root origin".into(),
        ));
    }
    if url.query().is_some() || url.fragment().is_some() {
        return Err(CarrierError::Configuration(
            "relay URL queries and fragments are not allowed".into(),
        ));
    }
    Ok(())
}

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

/// A bound Iroh endpoint with hosted discovery and public relays disabled.
#[derive(Clone)]
pub struct Endpoint {
    inner: IrohEndpoint,
    config: EndpointConfig,
    relay_url: Option<RelayUrl>,
    security_profile: CarrierSecurityProfile,
}

impl Endpoint {
    /// Binds a direct endpoint using a caller-supplied secret.
    pub async fn bind(secret: SecretKey, config: EndpointConfig) -> Result<Self, CarrierError> {
        Self::bind_with_security_profile(secret, config, CarrierSecurityProfile::default()).await
    }

    /// Binds a direct endpoint to exactly one carrier security profile.
    pub async fn bind_with_security_profile(
        secret: SecretKey,
        config: EndpointConfig,
        security_profile: CarrierSecurityProfile,
    ) -> Result<Self, CarrierError> {
        Self::bind_inner(secret, config, None, false, security_profile).await
    }

    /// Binds an endpoint to exactly one operator-pinned custom relay.
    pub async fn bind_with_relay(
        secret: SecretKey,
        config: EndpointConfig,
        relay: PinnedRelay,
    ) -> Result<Self, CarrierError> {
        Self::bind_with_relay_and_security_profile(
            secret,
            config,
            relay,
            CarrierSecurityProfile::default(),
        )
        .await
    }

    /// Binds an endpoint to one pinned relay and one carrier security profile.
    pub async fn bind_with_relay_and_security_profile(
        secret: SecretKey,
        config: EndpointConfig,
        relay: PinnedRelay,
        security_profile: CarrierSecurityProfile,
    ) -> Result<Self, CarrierError> {
        Self::bind_inner(secret, config, Some(relay), false, security_profile).await
    }

    /// Binds a relay-only endpoint with no direct IP transport.
    ///
    /// This is intended for an explicit operator-selected forced-relay mode.
    /// The endpoint cannot dial, listen, or hole-punch over a direct UDP path.
    pub async fn bind_relay_only(
        secret: SecretKey,
        config: EndpointConfig,
        relay: PinnedRelay,
    ) -> Result<Self, CarrierError> {
        Self::bind_relay_only_with_security_profile(
            secret,
            config,
            relay,
            CarrierSecurityProfile::default(),
        )
        .await
    }

    /// Binds a relay-only endpoint to exactly one carrier security profile.
    pub async fn bind_relay_only_with_security_profile(
        secret: SecretKey,
        config: EndpointConfig,
        relay: PinnedRelay,
        security_profile: CarrierSecurityProfile,
    ) -> Result<Self, CarrierError> {
        Self::bind_inner(secret, config, Some(relay), true, security_profile).await
    }

    async fn bind_inner(
        secret: SecretKey,
        config: EndpointConfig,
        relay: Option<PinnedRelay>,
        relay_only: bool,
        security_profile: CarrierSecurityProfile,
    ) -> Result<Self, CarrierError> {
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
        let mut transport = QuicTransportConfig::builder();
        if let Some(keepalive_interval) = connection_keepalive_interval(security_profile) {
            transport = transport
                .keep_alive_interval(keepalive_interval)
                .default_path_keep_alive_interval(keepalive_interval);
        }
        let transport = transport
            .max_concurrent_bidi_streams(VarInt::from_u32(16))
            .max_concurrent_uni_streams(VarInt::from_u32(0))
            .stream_receive_window(VarInt::from_u32(window))
            .receive_window(VarInt::from_u32(window.saturating_mul(2)))
            .send_window(u64::from(window.saturating_mul(2)))
            .build();
        let relay_mode = relay.as_ref().map_or(RelayMode::Disabled, |relay| {
            RelayMode::Custom(IrohRelayConfig::new(relay.url.clone(), None).into())
        });
        let mut net_report_config = NetReportConfig::minimal();
        // With QUIC address discovery disabled on the exact relay config,
        // this bounded HTTPS probe is what lets Iroh select that relay.
        net_report_config.https_probes = relay.is_some();
        let mut builder = IrohEndpoint::builder(presets::Minimal)
            .secret_key(secret)
            .clear_address_lookup()
            .clear_relay_transports()
            .relay_mode(relay_mode)
            .portmapper_config(PortmapperConfig::Disabled)
            .net_report_config(net_report_config)
            .transport_config(transport)
            .clear_ip_transports()
            .alpns(vec![security_profile.alpn().to_vec()]);
        if !relay_only {
            builder = builder
                .bind_addr(config.bind)
                .map_err(|error| CarrierError::Configuration(error.to_string()))?;
        }
        if let Some(relay) = relay.as_ref()
            && !relay.ca_roots_der.is_empty()
        {
            builder = builder.ca_tls_config(CaTlsConfig::custom_roots(
                relay.ca_roots_der.iter().cloned().map(Into::into),
            ));
        }
        let inner = builder
            .bind()
            .await
            .map_err(|error| CarrierError::Transport(error.to_string()))?;
        Ok(Self {
            inner,
            config,
            relay_url: relay.map(|relay| relay.url),
            security_profile,
        })
    }

    /// Returns the authenticated endpoint identity.
    pub fn id(&self) -> EndpointId {
        self.inner.id()
    }

    /// Returns the exact carrier profile this endpoint advertises and dials.
    pub fn security_profile(&self) -> CarrierSecurityProfile {
        self.security_profile
    }

    /// Returns the actual local sockets after binding.
    pub fn bound_sockets(&self) -> Vec<SocketAddr> {
        self.inner.bound_sockets()
    }

    /// Waits, within the configured connection deadline, for the pinned relay
    /// registration to become usable.
    pub async fn wait_relay_ready(&self) -> Result<(), CarrierError> {
        if self.relay_url.is_none() {
            return Err(CarrierError::Configuration(
                "relay readiness requires a relay-enabled endpoint".into(),
            ));
        }
        timeout(self.config.connect_timeout, self.inner.online())
            .await
            .map_err(|_| CarrierError::Timeout("relay readiness"))
    }

    /// Connects to the exact expected identity at its explicit direct address.
    pub async fn connect(&self, peer: ExpectedPeer) -> Result<Connection, CarrierError> {
        let address = EndpointAddr::new(peer.id).with_ip_addr(peer.address);
        self.connect_address(address, peer.id).await
    }

    /// Connects using the route's initial direct candidates and exact pinned relay.
    ///
    /// Iroh may probe initial paths in parallel and, after authenticating the
    /// exact endpoint ID, NAT negotiation may derive additional direct paths.
    /// The endpoint identity and sole configured relay remain exact; this API
    /// makes no temporal direct-first ordering promise.
    pub async fn connect_route(&self, route: &PeerRoute) -> Result<Connection, CarrierError> {
        match self.relay_url.as_ref() {
            Some(configured) if configured == route.relay_url() => {}
            Some(_) => {
                return Err(CarrierError::Configuration(
                    "peer route relay does not match the endpoint's pinned relay".into(),
                ));
            }
            None => {
                return Err(CarrierError::Configuration(
                    "controlled peer route requires a relay-enabled endpoint".into(),
                ));
            }
        }
        let address = EndpointAddr::new(route.id())
            .with_addrs(
                route
                    .direct_addresses()
                    .iter()
                    .copied()
                    .map(TransportAddr::Ip),
            )
            .with_relay_url(route.relay_url().clone());
        self.connect_address(address, route.id()).await
    }

    async fn connect_address(
        &self,
        address: EndpointAddr,
        expected_id: EndpointId,
    ) -> Result<Connection, CarrierError> {
        let inner = timeout(
            self.config.connect_timeout,
            self.inner.connect(address, self.security_profile.alpn()),
        )
        .await
        .map_err(|_| CarrierError::Timeout("connect"))?
        .map_err(|error| CarrierError::Transport(error.to_string()))?;
        if inner.remote_id() != expected_id {
            return Err(CarrierError::UnauthorizedPeer(inner.remote_id()));
        }
        self.ensure_negotiated_profile(&inner)?;
        Ok(Connection::new(
            inner,
            self.id(),
            self.config.exchange_timeout,
            self.config.max_exchange_bytes,
            self.security_profile,
        ))
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
        self.ensure_negotiated_profile(&inner)?;
        Ok(Connection::new(
            inner,
            self.id(),
            self.config.exchange_timeout,
            self.config.max_exchange_bytes,
            self.security_profile,
        ))
    }

    fn ensure_negotiated_profile(
        &self,
        connection: &iroh::endpoint::Connection,
    ) -> Result<(), CarrierError> {
        if connection.alpn() == self.security_profile.alpn() {
            return Ok(());
        }
        connection.close(1u8.into(), b"carrier profile mismatch");
        Err(CarrierError::Transport(
            "negotiated carrier security profile mismatch".into(),
        ))
    }

    /// Closes the endpoint and waits for its background tasks.
    pub async fn close(&self) {
        self.inner.close().await;
    }
}

/// Selected network path kind observed for an authenticated connection.
///
/// This is diagnostic state only. It never establishes peer identity,
/// membership, authorization, receipt validity, or replication success.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum SelectedPath {
    /// The most recently observed selected path used a direct IP transport.
    Direct,
    /// The most recently observed selected path used the pinned relay transport.
    Relay,
    /// No selected path has yet been observed, or observation lost continuity.
    Unknown,
}

/// Bounded observation of selected-path changes for one connection.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct PathWitness {
    /// Most recently observed selected network path, retained across ordinary
    /// path closure after the connection completes.
    pub selected: SelectedPath,
    /// Number of observed path-kind transitions, capped at
    /// [`MAX_PATH_TRANSITIONS`].
    pub transition_count: u16,
    /// Whether events were lost or the transition count reached its cap.
    pub transitions_saturated: bool,
}

impl PathWitness {
    fn new(selected: SelectedPath) -> Self {
        Self {
            selected,
            transition_count: 0,
            transitions_saturated: false,
        }
    }

    fn observe(&mut self, selected: SelectedPath) {
        if self.selected == selected {
            return;
        }
        self.selected = selected;
        if self.transition_count < MAX_PATH_TRANSITIONS {
            self.transition_count += 1;
            if self.transition_count == MAX_PATH_TRANSITIONS {
                self.transitions_saturated = true;
            }
        } else {
            self.transitions_saturated = true;
        }
    }

    fn lose_continuity(&mut self) {
        self.selected = SelectedPath::Unknown;
        self.transitions_saturated = true;
    }
}

/// Authenticated, bounded opaque exchange channel.
#[derive(Clone)]
pub struct Connection {
    inner: iroh::endpoint::Connection,
    local_id: EndpointId,
    exchange_timeout: Duration,
    max_exchange_bytes: usize,
    path_witness: Arc<Mutex<PathWitness>>,
    security_profile: CarrierSecurityProfile,
}

impl Connection {
    fn new(
        inner: iroh::endpoint::Connection,
        local_id: EndpointId,
        exchange_timeout: Duration,
        max_exchange_bytes: usize,
        security_profile: CarrierSecurityProfile,
    ) -> Self {
        // Subscribe before the snapshot. Path events are not replayed, so the
        // opposite order has a window in which a selection change can vanish.
        let mut events = inner.path_events();
        let weak = inner.weak_handle();
        let selected = selected_path_snapshot(&inner);
        let path_witness = Arc::new(Mutex::new(PathWitness::new(selected)));
        let observed = Arc::clone(&path_witness);
        tokio::spawn(async move {
            while let Some(event) = events.next().await {
                if matches!(event, PathEvent::Lagged { .. }) {
                    if let Ok(mut witness) = observed.lock() {
                        witness.lose_continuity();
                    }
                    return;
                }
                let Some(connection) = weak.upgrade() else {
                    break;
                };
                // Re-snapshot rather than replaying the event's address. An
                // event queued before the initial snapshot may already be
                // stale by the time this task runs.
                let selected = selected_path_snapshot(&connection);
                drop(connection);
                let mut witness = match observed.lock() {
                    Ok(witness) => witness,
                    Err(poisoned) => {
                        let mut witness = poisoned.into_inner();
                        witness.lose_continuity();
                        break;
                    }
                };
                // A transient lack of a selected path during ordinary path
                // closure does not erase the last successfully observed
                // transport. Only a lag or poisoned state loses continuity.
                if selected != SelectedPath::Unknown {
                    witness.observe(selected);
                }
            }
        });
        Self {
            inner,
            local_id,
            exchange_timeout,
            max_exchange_bytes,
            path_witness,
            security_profile,
        }
    }

    /// Returns this connection's local carrier endpoint identity.
    pub fn local_id(&self) -> EndpointId {
        self.local_id
    }

    /// Returns the authenticated remote endpoint identity.
    pub fn remote_id(&self) -> EndpointId {
        self.inner.remote_id()
    }

    /// Returns the exact carrier security profile negotiated for this connection.
    pub fn security_profile(&self) -> CarrierSecurityProfile {
        self.security_profile
    }

    /// Derives a domain-separated binding to this exact QUIC TLS session.
    ///
    /// The exporter label and output size are fixed by this crate. Callers can
    /// vary only a validated application context; the selected carrier ALPN is
    /// incorporated automatically. The returned bytes should be authenticated
    /// by the higher-layer mission transcript before application inventory is
    /// exchanged.
    pub fn channel_binding(
        &self,
        context: ChannelBindingContext<'_>,
    ) -> Result<ChannelBinding, CarrierError> {
        let application_context = context.as_bytes();
        let alpn = self.security_profile.alpn();
        let mut exporter_context = Vec::with_capacity(
            CHANNEL_BINDING_CONTEXT_DOMAIN.len()
                + 1
                + std::mem::size_of::<u16>()
                + alpn.len()
                + std::mem::size_of::<u32>()
                + application_context.len(),
        );
        exporter_context.extend_from_slice(CHANNEL_BINDING_CONTEXT_DOMAIN);
        exporter_context.push(0);
        exporter_context.extend_from_slice(
            &u16::try_from(alpn.len())
                .expect("carrier ALPN length is statically bounded")
                .to_be_bytes(),
        );
        exporter_context.extend_from_slice(alpn);
        exporter_context.extend_from_slice(
            &u32::try_from(application_context.len())
                .expect("validated channel-binding context fits u32")
                .to_be_bytes(),
        );
        exporter_context.extend_from_slice(application_context);

        let mut binding = [0u8; CHANNEL_BINDING_BYTES];
        self.inner
            .export_keying_material(
                &mut binding,
                CHANNEL_BINDING_EXPORTER_LABEL,
                &exporter_context,
            )
            .map_err(|_| {
                CarrierError::Transport("QUIC TLS channel-binding derivation failed".into())
            })?;
        Ok(ChannelBinding(binding))
    }

    /// Returns a bounded observation of the selected network path.
    ///
    /// The witness is never an authorization or delivery-success signal.
    pub fn path_witness(&self) -> PathWitness {
        match self.path_witness.lock() {
            Ok(witness) => *witness,
            Err(_) => {
                let mut witness = PathWitness::new(SelectedPath::Unknown);
                witness.lose_continuity();
                witness
            }
        }
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
        self.request_with_total_limit_checked(request, total_limit, || Ok::<_, CarrierError>(()))
            .await
            .map(|(response, ())| response)
    }

    /// Sends one bounded exchange after a synchronous, carrier-adjacent check.
    ///
    /// `before_write` runs after the bidirectional QUIC stream is available and
    /// immediately before the first application byte is written. If it fails,
    /// the stream is dropped without writing `request`. This lets a higher
    /// layer recheck short-lived authority without leaving an unbounded
    /// bidirectional-stream acquisition wait between that check and the
    /// carrier handoff.
    pub async fn request_with_total_limit_checked<F, T, E>(
        &self,
        request: &[u8],
        total_limit: usize,
        before_write: F,
    ) -> Result<(Vec<u8>, T), E>
    where
        F: FnOnce() -> Result<T, E>,
        E: From<CarrierError>,
    {
        let request_maximum = self.max_exchange_bytes.min(total_limit);
        ensure_frame_bound(request.len(), request_maximum).map_err(E::from)?;
        let response_maximum = self
            .max_exchange_bytes
            .min(total_limit.saturating_sub(request.len()));
        let result = timeout(self.exchange_timeout, async {
            let (mut send, mut receive) = self
                .inner
                .open_bi()
                .await
                .map_err(|error| E::from(CarrierError::Transport(error.to_string())))?;
            let checked = before_write()?;
            send.write_all(request)
                .await
                .map_err(|error| E::from(CarrierError::Transport(error.to_string())))?;
            send.finish()
                .map_err(|error| E::from(CarrierError::Transport(error.to_string())))?;
            let response = receive
                .read_to_end(response_maximum)
                .await
                .map_err(|error| E::from(map_read_error(error, response_maximum)))?;
            Ok::<_, E>((response, checked))
        })
        .await;
        match result {
            Ok(result) => result,
            Err(_) => {
                self.inner.close(2u8.into(), b"exchange timeout");
                Err(E::from(CarrierError::Timeout("request/response")))
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

    /// Signals that the initiator consumed the final response, then waits for
    /// the responder to close the completed connection.
    pub async fn finish_as_initiator(&self) -> Result<(), CarrierError> {
        let result = timeout(self.exchange_timeout, async {
            let (mut send, _receive) = self
                .inner
                .open_bi()
                .await
                .map_err(|error| CarrierError::Transport(error.to_string()))?;
            send.write_all(RESPONSE_CONSUMED_MARKER)
                .await
                .map_err(|error| CarrierError::Transport(error.to_string()))?;
            send.finish()
                .map_err(|error| CarrierError::Transport(error.to_string()))?;
            match self.inner.closed().await {
                ConnectionError::ApplicationClosed(close)
                    if close.error_code == 0u8.into() && close.reason.as_ref() == b"complete" =>
                {
                    Ok(())
                }
                error => Err(CarrierError::Transport(error.to_string())),
            }
        })
        .await;
        match result {
            Ok(result) => result,
            Err(_) => {
                self.inner.close(2u8.into(), b"completion timeout");
                Err(CarrierError::Timeout("initiator session completion"))
            }
        }
    }

    /// Waits for proof that the initiator consumed the final response, then
    /// closes the completed connection without racing that response's read.
    pub async fn finish_as_responder(&self) -> Result<(), CarrierError> {
        let result = timeout(self.exchange_timeout, async {
            let (_send, mut receive) = self
                .inner
                .accept_bi()
                .await
                .map_err(|error| CarrierError::Transport(error.to_string()))?;
            let marker = receive
                .read_to_end(RESPONSE_CONSUMED_MARKER.len())
                .await
                .map_err(|error| map_read_error(error, RESPONSE_CONSUMED_MARKER.len()))?;
            if marker != RESPONSE_CONSUMED_MARKER {
                return Err(CarrierError::Transport(
                    "invalid session completion marker".into(),
                ));
            }
            self.inner.close(0u8.into(), b"complete");
            Ok(())
        })
        .await;
        match result {
            Ok(result) => result,
            Err(_) => {
                self.inner.close(2u8.into(), b"completion timeout");
                Err(CarrierError::Timeout("responder session completion"))
            }
        }
    }

    /// Closes this connection.
    pub fn close(&self) {
        self.inner.close(0u8.into(), b"complete");
    }
}

fn selected_path(address: &TransportAddr) -> SelectedPath {
    if address.is_ip() {
        SelectedPath::Direct
    } else if address.is_relay() {
        SelectedPath::Relay
    } else {
        SelectedPath::Unknown
    }
}

fn selected_path_snapshot(connection: &iroh::endpoint::Connection) -> SelectedPath {
    connection
        .paths()
        .iter()
        .find(|path| path.is_selected())
        .map_or(SelectedPath::Unknown, |path| {
            selected_path(path.remote_addr())
        })
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

/// Local, TLS-verifying relay support for integration tests.
#[cfg(feature = "test-utils")]
pub mod test_utils {
    use std::net::Ipv4Addr;

    use iroh_relay::server::{
        CertConfig, RelayConfig as RelayServerConfig, Server, ServerConfig, TlsConfig,
        testing::self_signed_tls_certs_and_config,
    };

    use super::{CarrierError, PinnedRelay, RelayUrl};

    /// A self-hosted relay whose self-signed root is exported for exact trust.
    #[derive(Debug)]
    pub struct RelayFixture {
        server: Option<Server>,
        relay: PinnedRelay,
    }

    impl RelayFixture {
        /// Starts an HTTPS relay on an operating-system-assigned loopback port.
        pub async fn spawn() -> Result<Self, CarrierError> {
            let (certificates, server_tls) = self_signed_tls_certs_and_config();
            let tls = TlsConfig::new(
                (Ipv4Addr::LOCALHOST, 0),
                CertConfig::Manual {
                    server_config: server_tls,
                },
            );
            let mut relay_config = RelayServerConfig::new((Ipv4Addr::LOCALHOST, 0));
            relay_config.tls = Some(tls);
            relay_config.key_cache_capacity = Some(1_024);
            let mut server_config = ServerConfig::default();
            server_config.relay = Some(relay_config);
            server_config.quic = None;
            let server = Server::spawn(server_config)
                .await
                .map_err(|error| CarrierError::Transport(error.to_string()))?;
            let address = server.https_addr().ok_or_else(|| {
                CarrierError::Transport("test relay did not bind an HTTPS socket".into())
            })?;
            let relay_url: RelayUrl = format!("https://127.0.0.1:{}/", address.port())
                .parse()
                .map_err(|error| {
                    CarrierError::Configuration(format!("invalid test relay URL: {error}"))
                })?;
            let relay = PinnedRelay::with_ca_roots(
                relay_url,
                certificates
                    .into_iter()
                    .map(|certificate| certificate.as_ref().to_vec()),
            )?;
            Ok(Self {
                server: Some(server),
                relay,
            })
        }

        /// Returns a clone of the endpoint-side relay pin and trust boundary.
        pub fn pinned_relay(&self) -> PinnedRelay {
            self.relay.clone()
        }

        /// Returns the relay URL for constructing exact peer routes.
        pub fn relay_url(&self) -> &RelayUrl {
            self.relay.url()
        }

        /// Returns the fixture's DER trust root for subprocess test setup.
        pub fn ca_roots_der(&self) -> &[Vec<u8>] {
            self.relay.ca_roots_der()
        }

        /// Stops the relay and waits for its tasks to exit.
        pub async fn shutdown(mut self) -> Result<(), CarrierError> {
            let server = self
                .server
                .take()
                .ok_or_else(|| CarrierError::Transport("test relay was already stopped".into()))?;
            server
                .shutdown()
                .await
                .map_err(|error| CarrierError::Transport(error.to_string()))
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[cfg(feature = "test-utils")]
    use super::test_utils::RelayFixture;

    fn loopback(endpoint: &Endpoint) -> SocketAddr {
        endpoint
            .bound_sockets()
            .into_iter()
            .find(SocketAddr::is_ipv4)
            .expect("IPv4 loopback binding")
    }

    async fn connect_pair(server: &Endpoint, client: &Endpoint) -> (Connection, Connection) {
        let allowed = BTreeSet::from([client.id()]);
        let server_task = tokio::spawn({
            let server = server.clone();
            async move { server.accept(&allowed).await.expect("accept") }
        });
        let client_connection = client
            .connect(ExpectedPeer {
                id: server.id(),
                address: loopback(server),
            })
            .await
            .expect("connect");
        let server_connection = server_task.await.expect("server task");
        (server_connection, client_connection)
    }

    #[cfg(feature = "test-utils")]
    fn relay_test_config() -> EndpointConfig {
        let mut config = EndpointConfig::direct("127.0.0.1:0".parse().expect("address"));
        config.connect_timeout = Duration::from_secs(4);
        config.exchange_timeout = Duration::from_secs(2);
        config
    }

    async fn wait_for_path(connection: &Connection, expected: SelectedPath) -> PathWitness {
        timeout(Duration::from_secs(4), async {
            loop {
                let witness = connection.path_witness();
                if witness.selected == expected {
                    return witness;
                }
                tokio::time::sleep(Duration::from_millis(20)).await;
            }
        })
        .await
        .expect("selected path observation deadline")
    }

    #[cfg(feature = "test-utils")]
    fn large_valid_ca_root() -> Vec<u8> {
        let mut parameters = rcgen::CertificateParams::new(vec!["large-root.invalid".to_owned()])
            .expect("certificate parameters");
        parameters
            .custom_extensions
            .push(rcgen::CustomExtension::from_oid_content(
                &[1, 3, 6, 1, 4, 1, 55_555, 1],
                vec![0x5a; 48 * 1024],
            ));
        let key = rcgen::KeyPair::generate().expect("certificate key");
        parameters
            .self_signed(&key)
            .expect("self-signed certificate")
            .der()
            .to_vec()
    }

    #[cfg(feature = "test-utils")]
    fn unrelated_valid_ca_root() -> Vec<u8> {
        let mut parameters =
            rcgen::CertificateParams::new(vec!["unrelated-root.invalid".to_owned()])
                .expect("certificate parameters");
        parameters.is_ca = rcgen::IsCa::Ca(rcgen::BasicConstraints::Unconstrained);
        let key = rcgen::KeyPair::generate().expect("certificate key");
        parameters
            .self_signed(&key)
            .expect("self-signed CA certificate")
            .der()
            .to_vec()
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
        assert_eq!(
            server.security_profile(),
            CarrierSecurityProfile::HybridAsterRecordV1
        );
        assert_eq!(
            client.security_profile(),
            CarrierSecurityProfile::HybridAsterRecordV1
        );
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
                let before_close = wait_for_path(&connection, SelectedPath::Direct).await;
                connection
                    .finish_as_responder()
                    .await
                    .expect("finish responder");
                tokio::time::sleep(Duration::from_millis(20)).await;
                (before_close, connection.path_witness())
            }
        });
        let connection = client
            .connect(ExpectedPeer {
                id: server.id(),
                address: loopback(&server),
            })
            .await
            .expect("connect");
        assert_eq!(connection.inner.alpn(), ALPN);
        assert_eq!(
            connection.security_profile(),
            CarrierSecurityProfile::HybridAsterRecordV1
        );
        assert_eq!(connection.request(b"ping").await.expect("request"), b"ping");
        wait_for_path(&connection, SelectedPath::Direct).await;
        connection
            .finish_as_initiator()
            .await
            .expect("finish initiator");
        let (before_close, after_close) = server_task.await.expect("server task");
        assert_eq!(before_close.selected, SelectedPath::Direct);
        assert_eq!(after_close.selected, SelectedPath::Direct);
        assert!(!after_close.transitions_saturated);
        client.close().await;
        server.close().await;
    }

    #[test]
    fn carrier_security_profile_alpns_are_exact_and_distinct() {
        assert_eq!(
            CarrierSecurityProfile::default(),
            CarrierSecurityProfile::HybridAsterRecordV1
        );
        assert_eq!(CarrierSecurityProfile::default().alpn(), ALPN);
        assert_eq!(CarrierSecurityProfile::IrohQuicV1.alpn(), IROH_QUIC_ALPN);
        assert_ne!(ALPN, IROH_QUIC_ALPN);
    }

    #[test]
    fn keepalives_are_limited_to_the_iroh_quic_security_profile() {
        assert_eq!(
            connection_keepalive_interval(CarrierSecurityProfile::HybridAsterRecordV1),
            None
        );
        assert_eq!(
            connection_keepalive_interval(CarrierSecurityProfile::IrohQuicV1),
            Some(CONNECTION_KEEPALIVE_INTERVAL)
        );
    }

    #[test]
    fn channel_binding_context_is_bounded_and_debug_values_are_redacted() {
        assert!(matches!(
            ChannelBindingContext::new(&[]),
            Err(CarrierError::Configuration(_))
        ));
        assert!(matches!(
            ChannelBindingContext::new(&vec![0; MAX_CHANNEL_BINDING_CONTEXT_BYTES + 1]),
            Err(CarrierError::Configuration(_))
        ));
        let context = ChannelBindingContext::new(b"context-secret-marker").expect("context");
        assert_eq!(
            format!("{context:?}"),
            "ChannelBindingContext { bytes: 21 }"
        );
        let binding = ChannelBinding([0x5a; CHANNEL_BINDING_BYTES]);
        assert_eq!(format!("{binding:?}"), "ChannelBinding([REDACTED])");
    }

    #[tokio::test]
    async fn matching_peers_derive_the_same_exact_quic_channel_binding() {
        let config = EndpointConfig::direct("127.0.0.1:0".parse().expect("address"));
        let server = Endpoint::bind_with_security_profile(
            SecretKey::generate(),
            config,
            CarrierSecurityProfile::IrohQuicV1,
        )
        .await
        .expect("server");
        let client = Endpoint::bind_with_security_profile(
            SecretKey::generate(),
            config,
            CarrierSecurityProfile::IrohQuicV1,
        )
        .await
        .expect("client");
        assert_eq!(
            server.security_profile(),
            CarrierSecurityProfile::IrohQuicV1
        );
        assert_eq!(
            client.security_profile(),
            CarrierSecurityProfile::IrohQuicV1
        );

        let (server_connection, client_connection) = connect_pair(&server, &client).await;
        assert_eq!(server_connection.local_id(), server.id());
        assert_eq!(server_connection.remote_id(), client.id());
        assert_eq!(client_connection.local_id(), client.id());
        assert_eq!(client_connection.remote_id(), server.id());
        assert_eq!(server_connection.inner.alpn(), IROH_QUIC_ALPN);
        assert_eq!(client_connection.inner.alpn(), IROH_QUIC_ALPN);
        assert_eq!(
            server_connection.security_profile(),
            CarrierSecurityProfile::IrohQuicV1
        );
        assert_eq!(
            client_connection.security_profile(),
            CarrierSecurityProfile::IrohQuicV1
        );

        let context = ChannelBindingContext::new(b"canonical-mission-contact-context")
            .expect("binding context");
        let server_binding = server_connection
            .channel_binding(context)
            .expect("server binding");
        let client_binding = client_connection
            .channel_binding(context)
            .expect("client binding");
        assert_eq!(server_binding, client_binding);
        assert_ne!(server_binding.as_bytes(), &[0u8; CHANNEL_BINDING_BYTES]);

        server_connection.close();
        client_connection.close();
        client.close().await;
        server.close().await;
    }

    #[tokio::test]
    async fn channel_bindings_separate_contexts_and_fresh_quic_connections() {
        let config = EndpointConfig::direct("127.0.0.1:0".parse().expect("address"));
        let server = Endpoint::bind_with_security_profile(
            SecretKey::generate(),
            config,
            CarrierSecurityProfile::IrohQuicV1,
        )
        .await
        .expect("server");
        let client = Endpoint::bind_with_security_profile(
            SecretKey::generate(),
            config,
            CarrierSecurityProfile::IrohQuicV1,
        )
        .await
        .expect("client");
        let first_context =
            ChannelBindingContext::new(b"mission-contact-context-1").expect("first context");
        let second_context =
            ChannelBindingContext::new(b"mission-contact-context-2").expect("second context");

        let (first_server, first_client) = connect_pair(&server, &client).await;
        let first_binding = first_client
            .channel_binding(first_context)
            .expect("first binding");
        let other_context_binding = first_client
            .channel_binding(second_context)
            .expect("other-context binding");
        assert_ne!(first_binding, other_context_binding);
        assert_eq!(
            first_binding,
            first_server
                .channel_binding(first_context)
                .expect("matching first binding")
        );
        first_client.close();
        first_server.close();

        let (second_server, second_client) = connect_pair(&server, &client).await;
        let second_connection_binding = second_client
            .channel_binding(first_context)
            .expect("second-connection binding");
        assert_eq!(
            second_connection_binding,
            second_server
                .channel_binding(first_context)
                .expect("matching second binding")
        );
        assert_ne!(first_binding, second_connection_binding);

        second_client.close();
        second_server.close();
        client.close().await;
        server.close().await;
    }

    async fn assert_mixed_profiles_fail(
        server_profile: CarrierSecurityProfile,
        client_profile: CarrierSecurityProfile,
    ) {
        let mut config = EndpointConfig::direct("127.0.0.1:0".parse().expect("address"));
        config.connect_timeout = Duration::from_secs(2);
        let server =
            Endpoint::bind_with_security_profile(SecretKey::generate(), config, server_profile)
                .await
                .expect("server");
        let client =
            Endpoint::bind_with_security_profile(SecretKey::generate(), config, client_profile)
                .await
                .expect("client");
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
                id: server.id(),
                address: loopback(&server),
            })
            .await;
        assert!(
            matches!(result, Err(CarrierError::Transport(_))),
            "mixed profile unexpectedly connected or failed outside the handshake"
        );
        timeout(config.connect_timeout, observed_rx)
            .await
            .expect("server observation deadline")
            .expect("server observation sender");
        let handshake = server_task.await.expect("server task");
        assert!(
            matches!(handshake, Ok(Err(_))),
            "server handshake accepted a mixed carrier profile"
        );
        assert!(
            timeout(Duration::from_millis(250), server.inner.accept())
                .await
                .is_err(),
            "client retried or fell back after the profile mismatch"
        );

        client.close().await;
        server.close().await;
    }

    #[tokio::test]
    async fn mixed_carrier_profiles_fail_without_retry_or_fallback() {
        assert_mixed_profiles_fail(
            CarrierSecurityProfile::HybridAsterRecordV1,
            CarrierSecurityProfile::IrohQuicV1,
        )
        .await;
        assert_mixed_profiles_fail(
            CarrierSecurityProfile::IrohQuicV1,
            CarrierSecurityProfile::HybridAsterRecordV1,
        )
        .await;
    }

    #[tokio::test]
    async fn carrier_adjacent_check_failure_writes_no_application_bytes() {
        #[derive(Debug)]
        enum CheckedError {
            Carrier,
            Rejected,
        }

        impl From<CarrierError> for CheckedError {
            fn from(_: CarrierError) -> Self {
                Self::Carrier
            }
        }

        let mut config = EndpointConfig::direct("127.0.0.1:0".parse().expect("address"));
        config.exchange_timeout = Duration::from_secs(1);
        let server = Endpoint::bind(SecretKey::generate(), config)
            .await
            .expect("server");
        let client = Endpoint::bind(SecretKey::generate(), config)
            .await
            .expect("client");
        let allowed = BTreeSet::from([client.id()]);
        let server_task = tokio::spawn({
            let server = server.clone();
            async move {
                let connection = server.accept(&allowed).await.expect("accept");
                // Opening a QUIC stream does not authorize an application
                // byte. A rejected post-open check may leave no peer-visible
                // stream at all, or a reset/empty stream, but never payload.
                if let Ok(Ok((_send, mut receive))) =
                    timeout(Duration::from_millis(250), connection.inner.accept_bi()).await
                {
                    let received =
                        timeout(Duration::from_millis(250), receive.read_to_end(64)).await;
                    assert!(
                        !matches!(received, Ok(Ok(bytes)) if !bytes.is_empty()),
                        "rejected request escaped"
                    );
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
        let callback_ran = std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false));
        let observed = callback_ran.clone();
        let result: Result<(Vec<u8>, ()), CheckedError> = connection
            .request_with_total_limit_checked(b"must-not-escape", usize::MAX, move || {
                observed.store(true, std::sync::atomic::Ordering::SeqCst);
                Err(CheckedError::Rejected)
            })
            .await;
        assert!(matches!(result, Err(CheckedError::Rejected)));
        assert!(callback_ran.load(std::sync::atomic::Ordering::SeqCst));
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
    fn controlled_route_and_trust_bounds_are_exact() {
        let id = SecretKey::generate().public();
        let relay_url: RelayUrl = "https://relay.example.invalid/".parse().expect("relay URL");
        let route = PeerRoute::new(
            id,
            [
                "127.0.0.1:4002".parse().expect("address"),
                "127.0.0.1:4001".parse().expect("address"),
            ],
            relay_url.clone(),
        )
        .expect("route");
        assert_eq!(
            route.direct_addresses(),
            &[
                "127.0.0.1:4001".parse().expect("address"),
                "127.0.0.1:4002".parse().expect("address"),
            ]
        );
        assert_eq!(
            route.to_string().parse::<PeerRoute>().expect("round trip"),
            route
        );

        let relay_only = PeerRoute::new(id, [], relay_url.clone()).expect("relay only");
        assert_eq!(
            relay_only
                .to_string()
                .parse::<PeerRoute>()
                .expect("relay-only round trip"),
            relay_only
        );
        assert!(matches!(
            PeerRoute::new(
                id,
                (0..=MAX_DIRECT_ADDRESSES)
                    .map(|port| SocketAddr::from(([127, 0, 0, 1], 10_000 + port as u16))),
                relay_url.clone(),
            ),
            Err(CarrierError::Configuration(_))
        ));
        let too_many_direct = (0..=MAX_DIRECT_ADDRESSES)
            .map(|port| SocketAddr::from(([127, 0, 0, 1], 20_000 + port as u16)).to_string())
            .collect::<Vec<_>>()
            .join(",");
        let too_many_encoded = format!("{id}@{too_many_direct}#{relay_url}");
        assert!(matches!(
            too_many_encoded.parse::<PeerRoute>(),
            Err(CarrierError::Configuration(message))
                if message.contains("more than 8 direct addresses")
        ));
        let oversized_relay = format!("{id}@#https://{}/", "a".repeat(MAX_RELAY_URL_BYTES));
        assert!(matches!(
            oversized_relay.parse::<PeerRoute>(),
            Err(CarrierError::Configuration(message))
                if message.contains("relay URL exceeds")
        ));
        assert!(matches!(
            "x".repeat(MAX_PEER_ROUTE_TEXT_BYTES + 1).parse::<PeerRoute>(),
            Err(CarrierError::Configuration(message))
                if message.contains("peer route exceeds")
        ));
        assert!(matches!(
            PeerRoute::new(
                id,
                [
                    "127.0.0.1:4001".parse().expect("address"),
                    "127.0.0.1:4001".parse().expect("address"),
                ],
                relay_url.clone(),
            ),
            Err(CarrierError::Configuration(_))
        ));

        for invalid in [
            "http://relay.example.invalid/",
            "https://operator@relay.example.invalid/",
            "https://relay.example.invalid/private-token",
            "https://relay.example.invalid/?token=secret",
            "https://relay.example.invalid/#fragment",
        ] {
            let invalid_url: RelayUrl = invalid.parse().expect("syntactically valid URL");
            assert!(matches!(
                PeerRoute::new(id, [], invalid_url),
                Err(CarrierError::Configuration(_))
            ));
        }

        assert!(matches!(
            PinnedRelay::with_ca_roots(relay_url.clone(), Vec::<Vec<u8>>::new()),
            Err(CarrierError::Configuration(_))
        ));
        assert!(matches!(
            PinnedRelay::with_ca_roots(relay_url.clone(), [vec![0u8; MAX_RELAY_CA_ROOT_BYTES + 1]],),
            Err(CarrierError::Configuration(_))
        ));
        assert!(matches!(
            PinnedRelay::with_ca_roots(relay_url, [vec![1, 2, 3]]),
            Err(CarrierError::Configuration(message))
                if message.contains("invalid relay CA root DER certificate")
        ));

        let mut witness = PathWitness::new(SelectedPath::Relay);
        for index in 0..=usize::from(MAX_PATH_TRANSITIONS) {
            witness.observe(if index % 2 == 0 {
                SelectedPath::Direct
            } else {
                SelectedPath::Relay
            });
        }
        assert_eq!(witness.transition_count, MAX_PATH_TRANSITIONS);
        assert!(witness.transitions_saturated);

        let mut continuity_lost = PathWitness::new(SelectedPath::Direct);
        continuity_lost.observe(SelectedPath::Relay);
        continuity_lost.lose_continuity();
        assert_eq!(continuity_lost.selected, SelectedPath::Unknown);
        assert_eq!(continuity_lost.transition_count, 1);
        assert!(continuity_lost.transitions_saturated);
    }

    #[cfg(feature = "test-utils")]
    #[tokio::test]
    async fn relay_only_exact_peer_succeeds_with_pinned_tls_trust() {
        let fixture = RelayFixture::spawn().await.expect("relay fixture");
        let valid_root = fixture.ca_roots_der()[0].clone();
        assert!(matches!(
            PinnedRelay::with_ca_roots(
                fixture.relay_url().clone(),
                [valid_root.clone(), vec![1, 2, 3]],
            ),
            Err(CarrierError::Configuration(message))
                if message.contains("invalid relay CA root DER certificate")
        ));
        assert!(matches!(
            PinnedRelay::with_ca_roots(
                fixture.relay_url().clone(),
                (0..=MAX_RELAY_CA_ROOTS).map(|_| valid_root.clone()),
            ),
            Err(CarrierError::Configuration(_))
        ));
        let large_root = large_valid_ca_root();
        assert!(large_root.len() <= MAX_RELAY_CA_ROOT_BYTES);
        let copies = MAX_RELAY_CA_ROOT_TOTAL_BYTES / large_root.len() + 1;
        assert!(copies <= MAX_RELAY_CA_ROOTS);
        assert!(matches!(
            PinnedRelay::with_ca_roots(
                fixture.relay_url().clone(),
                (0..copies).map(|_| large_root.clone()),
            ),
            Err(CarrierError::Configuration(_))
        ));
        let pinned = fixture.pinned_relay();
        let cloned = pinned.clone();
        assert!(std::ptr::eq(pinned.ca_roots_der(), cloned.ca_roots_der()));
        let config = relay_test_config();
        let server =
            Endpoint::bind_relay_only(SecretKey::generate(), config, fixture.pinned_relay())
                .await
                .expect("relay-only server");
        let client =
            Endpoint::bind_relay_only(SecretKey::generate(), config, fixture.pinned_relay())
                .await
                .expect("relay-only client");
        server.wait_relay_ready().await.expect("server relay ready");
        client.wait_relay_ready().await.expect("client relay ready");
        assert!(server.bound_sockets().is_empty());
        assert!(client.bound_sockets().is_empty());

        let allowed = BTreeSet::from([client.id()]);
        let server_task = tokio::spawn({
            let server = server.clone();
            async move {
                let connection = server.accept(&allowed).await.expect("accept");
                connection
                    .respond_once(|request| Ok((request.to_vec(), true)))
                    .await
                    .expect("respond");
                wait_for_path(&connection, SelectedPath::Relay).await
            }
        });
        let route = PeerRoute::new(
            server.id(),
            ["127.0.0.1:9".parse().expect("unreachable direct address")],
            fixture.relay_url().clone(),
        )
        .expect("route");
        let connection = client.connect_route(&route).await.expect("relay connect");
        assert_eq!(
            connection.request(b"relay").await.expect("request"),
            b"relay"
        );
        let client_witness = wait_for_path(&connection, SelectedPath::Relay).await;
        assert!(!client_witness.transitions_saturated);
        let server_witness = server_task.await.expect("server task");
        assert_eq!(server_witness.selected, SelectedPath::Relay);

        connection.close();
        client.close().await;
        server.close().await;
        fixture.shutdown().await.expect("relay shutdown");
    }

    #[cfg(feature = "test-utils")]
    #[tokio::test]
    async fn relay_tls_rejects_a_valid_but_unrelated_ca_without_fallback() {
        let fixture = RelayFixture::spawn().await.expect("relay fixture");
        let relay =
            PinnedRelay::with_ca_roots(fixture.relay_url().clone(), [unrelated_valid_ca_root()])
                .expect("valid unrelated CA root");
        let mut config = relay_test_config();
        config.connect_timeout = Duration::from_secs(1);
        let endpoint = Endpoint::bind_relay_only(SecretKey::generate(), config, relay)
            .await
            .expect("relay-only endpoint");

        assert!(matches!(
            endpoint.wait_relay_ready().await,
            Err(CarrierError::Timeout("relay readiness"))
        ));
        assert!(endpoint.bound_sockets().is_empty());

        endpoint.close().await;
        fixture.shutdown().await.expect("relay shutdown");
    }

    #[cfg(feature = "test-utils")]
    #[tokio::test]
    async fn usable_exact_direct_candidate_becomes_selected() {
        let fixture = RelayFixture::spawn().await.expect("relay fixture");
        let config = relay_test_config();
        let server =
            Endpoint::bind_with_relay(SecretKey::generate(), config, fixture.pinned_relay())
                .await
                .expect("server");
        let client =
            Endpoint::bind_with_relay(SecretKey::generate(), config, fixture.pinned_relay())
                .await
                .expect("client");
        server.wait_relay_ready().await.expect("server relay ready");
        client.wait_relay_ready().await.expect("client relay ready");

        let allowed = BTreeSet::from([client.id()]);
        let server_task = tokio::spawn({
            let server = server.clone();
            async move {
                let connection = server.accept(&allowed).await.expect("accept");
                connection
                    .respond_once(|request| Ok((request.to_vec(), true)))
                    .await
                    .expect("respond");
            }
        });
        let route = PeerRoute::new(
            server.id(),
            [loopback(&server)],
            fixture.relay_url().clone(),
        )
        .expect("route");
        let connection = client.connect_route(&route).await.expect("connect");
        let initial_witness = connection.path_witness();
        assert_eq!(
            connection.request(b"direct").await.expect("request"),
            b"direct"
        );
        let witness = wait_for_path(&connection, SelectedPath::Direct).await;
        assert!(!witness.transitions_saturated);
        if initial_witness.selected != SelectedPath::Direct {
            assert!(
                witness.transition_count > initial_witness.transition_count,
                "a non-direct initial path must transition to the usable direct candidate"
            );
        }

        server_task.await.expect("server task");
        connection.close();
        client.close().await;
        server.close().await;
        fixture.shutdown().await.expect("relay shutdown");
    }

    #[cfg(feature = "test-utils")]
    #[tokio::test]
    async fn dead_pinned_relay_still_allows_the_exact_direct_candidate() {
        let fixture = RelayFixture::spawn().await.expect("relay fixture");
        let relay_url = fixture.relay_url().clone();
        let relay = fixture.pinned_relay();
        fixture.shutdown().await.expect("stop relay before bind");
        let config = relay_test_config();
        let server = Endpoint::bind_with_relay(SecretKey::generate(), config, relay.clone())
            .await
            .expect("server");
        let client = Endpoint::bind_with_relay(SecretKey::generate(), config, relay)
            .await
            .expect("client");

        let allowed = BTreeSet::from([client.id()]);
        let server_task = tokio::spawn({
            let server = server.clone();
            async move {
                let connection = server.accept(&allowed).await.expect("accept");
                connection
                    .respond_once(|request| Ok((request.to_vec(), true)))
                    .await
                    .expect("respond");
            }
        });
        let route = PeerRoute::new(server.id(), [loopback(&server)], relay_url).expect("route");
        let connection = client.connect_route(&route).await.expect("direct connect");
        assert_eq!(
            connection.request(b"direct").await.expect("request"),
            b"direct"
        );
        wait_for_path(&connection, SelectedPath::Direct).await;

        server_task.await.expect("server task");
        connection.close();
        client.close().await;
        server.close().await;
    }

    #[cfg(feature = "test-utils")]
    #[tokio::test]
    async fn controlled_route_rejects_the_wrong_authenticated_identity() {
        let fixture = RelayFixture::spawn().await.expect("relay fixture");
        let mut config = relay_test_config();
        config.connect_timeout = Duration::from_secs(2);
        let server =
            Endpoint::bind_with_relay(SecretKey::generate(), config, fixture.pinned_relay())
                .await
                .expect("server");
        let client =
            Endpoint::bind_with_relay(SecretKey::generate(), config, fixture.pinned_relay())
                .await
                .expect("client");
        server.wait_relay_ready().await.expect("server relay ready");
        client.wait_relay_ready().await.expect("client relay ready");
        let substituted_relay: RelayUrl = "https://substitute.example.invalid/"
            .parse()
            .expect("relay URL");
        let substituted_route =
            PeerRoute::new(server.id(), [], substituted_relay).expect("substituted route");
        assert!(matches!(
            client.connect_route(&substituted_route).await,
            Err(CarrierError::Configuration(_))
        ));

        let wrong_id = SecretKey::generate().public();
        let route = PeerRoute::new(wrong_id, [loopback(&server)], fixture.relay_url().clone())
            .expect("route");
        assert!(matches!(
            client.connect_route(&route).await,
            Err(CarrierError::Transport(_) | CarrierError::Timeout(_))
        ));

        client.close().await;
        server.close().await;
        fixture.shutdown().await.expect("relay shutdown");
    }

    #[cfg(feature = "test-utils")]
    #[tokio::test]
    async fn relay_loss_is_bounded_and_has_no_public_relay_substitution() {
        let fixture = RelayFixture::spawn().await.expect("relay fixture");
        let relay_url = fixture.relay_url().clone();
        let relay = fixture.pinned_relay();
        let config = relay_test_config();
        let server = Endpoint::bind_relay_only(SecretKey::generate(), config, relay.clone())
            .await
            .expect("server");
        let client = Endpoint::bind_relay_only(SecretKey::generate(), config, relay)
            .await
            .expect("client");
        server.wait_relay_ready().await.expect("server relay ready");
        client.wait_relay_ready().await.expect("client relay ready");

        let allowed = BTreeSet::from([client.id()]);
        let (first_complete_tx, first_complete_rx) = tokio::sync::oneshot::channel();
        let server_task = tokio::spawn({
            let server = server.clone();
            async move {
                let connection = server.accept(&allowed).await.expect("accept");
                assert!(
                    !connection
                        .respond_once(|request| Ok((request.to_vec(), false)))
                        .await
                        .expect("first response")
                );
                first_complete_tx
                    .send(())
                    .expect("first-response observer open");
                connection
                    .respond_once(|request| Ok((request.to_vec(), true)))
                    .await
            }
        });
        let route = PeerRoute::new(server.id(), [], relay_url).expect("route");
        let connection = client.connect_route(&route).await.expect("connect");
        assert_eq!(
            connection.request(b"before").await.expect("request"),
            b"before"
        );
        first_complete_rx
            .await
            .expect("first response completed before relay loss");
        wait_for_path(&connection, SelectedPath::Relay).await;
        fixture.shutdown().await.expect("stop relay");

        let failed = timeout(Duration::from_secs(3), connection.request(b"after"))
            .await
            .expect("carrier-enforced relay-loss deadline");
        assert!(
            failed.is_err(),
            "request unexpectedly escaped the dead relay"
        );
        let witness = connection.path_witness();
        assert_eq!(witness.selected, SelectedPath::Relay);
        assert!(witness.transition_count <= MAX_PATH_TRANSITIONS);
        assert!(!witness.transitions_saturated);
        assert!(client.bound_sockets().is_empty());
        assert!(server.bound_sockets().is_empty());
        assert!(server_task.await.expect("server task").is_err());

        connection.close();
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
