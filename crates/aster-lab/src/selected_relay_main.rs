//! Bounded, exact-allowlist HTTPS Iroh relay for the selected NAT laboratory.

#![forbid(unsafe_code)]

use iroh::EndpointId;
use iroh_relay::server::{
    Access, AccessControl, CertConfig, ClientRateLimit, ClientRequest, ConnectionId, RelayConfig,
    Server, ServerConfig, TlsConfig,
};
use rustls::pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer};
use rustls::{Error as RustlsError, crypto::KeyProvider, sign::SigningKey};
use std::{
    collections::{BTreeSet, HashSet},
    env,
    error::Error,
    ffi::OsString,
    fs::{self, OpenOptions},
    io::{self, Read},
    net::SocketAddr,
    num::{NonZeroU32, NonZeroUsize},
    path::{Path, PathBuf},
    process::ExitCode,
    sync::{Arc, Mutex},
};
use zeroize::{Zeroize, Zeroizing};

const MAX_CERTIFICATE_BYTES: u64 = 1_048_576;
const MAX_PRIVATE_KEY_BYTES: u64 = 16_384;
const MAX_ADMITTED_CONNECTIONS: usize = 32;
const MAX_CLIENT_RX_BYTES_PER_SECOND: u32 = 64 * 1_048_576;
const MAX_CLIENT_RX_BURST_BYTES: u32 = 64 * 1_048_576;
const MAX_KEY_CACHE_CAPACITY: usize = 4_096;

type Result<T> = std::result::Result<T, Box<dyn Error>>;

#[derive(Debug)]
struct ZeroizingRingKeyProvider;

static ZEROIZING_RING_KEY_PROVIDER: ZeroizingRingKeyProvider = ZeroizingRingKeyProvider;

impl KeyProvider for ZeroizingRingKeyProvider {
    fn load_private_key(
        &self,
        key_der: PrivateKeyDer<'static>,
    ) -> std::result::Result<Arc<dyn SigningKey>, RustlsError> {
        let (parsed, postcondition) = parse_ring_key_and_zeroize_source(key_der);
        if !postcondition.satisfied() {
            return Err(RustlsError::General(
                "relay private-key DER source did not zeroize".into(),
            ));
        }
        parsed
    }
}

fn parse_ring_key_and_zeroize_source(
    mut key_der: PrivateKeyDer<'static>,
) -> (
    std::result::Result<Arc<dyn SigningKey>, RustlsError>,
    KeySourceZeroizePostcondition,
) {
    let source_length = key_der.secret_der().len();
    let parsed = rustls::crypto::ring::sign::any_supported_type(&key_der);
    key_der.zeroize();
    let remaining = key_der.secret_der();
    let postcondition = if source_length != 0 && remaining.is_empty() {
        KeySourceZeroizePostcondition::LengthCleared { source_length }
    } else if source_length != 0
        && remaining.len() == source_length
        && remaining.iter().all(|byte| *byte == 0)
    {
        KeySourceZeroizePostcondition::SameLengthAllZero { source_length }
    } else {
        KeySourceZeroizePostcondition::Failed
    };
    (parsed, postcondition)
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum KeySourceZeroizePostcondition {
    LengthCleared { source_length: usize },
    SameLengthAllZero { source_length: usize },
    Failed,
}

impl KeySourceZeroizePostcondition {
    const fn satisfied(self) -> bool {
        !matches!(self, Self::Failed)
    }
}

#[tokio::main]
async fn main() -> ExitCode {
    match run().await {
        Ok(()) => ExitCode::SUCCESS,
        Err(error) => {
            eprintln!("aster-selected-relay: {error}");
            ExitCode::FAILURE
        }
    }
}

async fn run() -> Result<()> {
    let options = Options::parse(env::args_os().skip(1).collect())?;
    if options.help {
        print_help();
        return Ok(());
    }
    let config = RelayOptions::from_options(options)?;
    let shutdown = ShutdownSignals::register()?;
    let allowlist_count = config.allowlist.len();
    let access = Arc::new(BoundedAllowlist::new(
        config.allowlist,
        config.max_admitted_connections,
    ));
    let certificate = read_public_regular_bounded(
        &config.certificate_der,
        MAX_CERTIFICATE_BYTES,
        "relay certificate",
    )?;
    let mut private_key = read_private_regular_bounded(
        &config.private_key,
        MAX_PRIVATE_KEY_BYTES,
        "relay private key",
    )?;
    let private_key =
        PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(std::mem::take(&mut *private_key)));
    let mut provider = rustls::crypto::ring::default_provider();
    provider.key_provider = &ZEROIZING_RING_KEY_PROVIDER;
    let provider = Arc::new(provider);
    let tls = rustls::ServerConfig::builder_with_provider(provider)
        .with_safe_default_protocol_versions()?
        .with_no_client_auth()
        .with_single_cert(vec![CertificateDer::from(certificate)], private_key)?;

    let mut rate = ClientRateLimit::new(config.client_rx_bytes_per_second);
    rate.max_burst_bytes = Some(config.client_rx_max_burst_bytes);
    let mut relay = RelayConfig::new(config.http_bind);
    relay.tls = Some(TlsConfig::new(
        config.https_bind,
        CertConfig::Manual { server_config: tls },
    ));
    relay.limits.client_rx = Some(rate);
    relay.key_cache_capacity = Some(config.key_cache_capacity.get());
    relay.access = access.clone();
    let mut server_config = ServerConfig::default();
    server_config.relay = Some(relay);
    server_config.quic = None;
    let server = Server::spawn(server_config).await?;
    let https = server
        .https_addr()
        .ok_or_else(|| invalid("relay did not bind its required HTTPS socket"))?;
    let http = server
        .http_addr()
        .ok_or_else(|| invalid("relay did not bind its required HTTP probe socket"))?;
    let metrics = server.metrics().server.clone();
    println!(
        "SELECTED_NAT_RELAY_READY status=ready version=1 https={} http={} tls=manual-der-certificate server_trust_claim=none allowlist=exact-cli-identities allowlist_count={} max_admitted_connections={} pre_auth_connection_cap=not-enforced client_rx_bytes_per_second={} client_rx_max_burst_bytes={} key_cache_capacity={} secrets_logged=false public_relay_fallback=false hosted_discovery=false port_mapper=false",
        https,
        http,
        allowlist_count,
        config.max_admitted_connections,
        config.client_rx_bytes_per_second,
        config.client_rx_max_burst_bytes,
        config.key_cache_capacity,
    );
    shutdown.wait().await?;
    server.shutdown().await?;
    let access_snapshot = access.snapshot()?;
    if access_snapshot.active != 0 {
        return Err(invalid(
            "relay shutdown retained active allowlist connections",
        ));
    }
    println!(
        "SELECTED_NAT_RELAY_STOP status=pass version=1 accepted_connections={} denied_connections={} active_connections=0 peak_active_connections={} sessions={} bytes_up={} bytes_down={} max_admitted_connections={} pre_auth_connection_cap=not-enforced client_rx_bytes_per_second={} client_rx_max_burst_bytes={} key_cache_capacity={} allowlist=exact-cli-identities allowlist_count={} server_trust_claim=none graceful=true",
        access_snapshot.accepted,
        access_snapshot.denied,
        access_snapshot.peak_active,
        metrics.accepts.get(),
        metrics.bytes_recv.get(),
        metrics.bytes_sent.get(),
        config.max_admitted_connections,
        config.client_rx_bytes_per_second,
        config.client_rx_max_burst_bytes,
        config.key_cache_capacity,
        allowlist_count,
    );
    Ok(())
}

fn print_help() {
    println!(
        "Selected-Iroh HTTPS relay with bounded authenticated admission\n\n\
         Usage:\n\
           aster-selected-relay --https-bind 0.0.0.0:8443 \\\n\
             --http-bind 0.0.0.0:8080 --certificate-der PATH \\\n\
             --private-key-pkcs8-der PATH --allow-carrier HEX64 \\\n\
             --allow-carrier HEX64 [OPTIONS]\n\n\
         Options:\n\
           --max-admitted-connections N  default 8; maximum 32\n\
           --client-rx-bytes-per-second N  default 1048576; maximum 67108864\n\
           --client-rx-max-burst-bytes N   default 1048576; maximum 67108864\n\
           --key-cache-capacity N    default 256; maximum 4096\n\n\
         Exactly two canonical CLI carrier identities are required. The connection\n\
         cap applies only after the Iroh handshake authenticates an identity. The\n\
         rate and burst bounds apply only to authenticated client-to-relay receive\n\
         traffic; neither limits relay-to-client transmission. A whole-listener/\n\
         pre-authentication connection cap is not enforced. The\n\
         server loads a manual DER certificate but makes no client trust/pinning\n\
         claim. Loopback binds, plaintext relay service, public fallback, hosted\n\
         discovery, and port mapping are not available. Startup file custody must\n\
         exclude concurrent writers running as the same effective UID."
    );
}

#[derive(Debug)]
struct Options {
    values: Vec<(String, String)>,
    help: bool,
}

impl Options {
    fn parse(arguments: Vec<OsString>) -> Result<Self> {
        if arguments.len() == 1
            && arguments[0]
                .to_str()
                .is_some_and(|value| matches!(value, "help" | "--help" | "-h"))
        {
            return Ok(Self {
                values: Vec::new(),
                help: true,
            });
        }
        let mut values = Vec::new();
        let mut arguments = arguments.into_iter();
        while let Some(name) = arguments.next() {
            let name = name
                .into_string()
                .map_err(|_| invalid("option name must be valid UTF-8"))?;
            if !name.starts_with("--") || name.len() == 2 {
                return Err(invalid(format!("expected --option, found {name}")));
            }
            let value = arguments
                .next()
                .ok_or_else(|| invalid(format!("{name} requires a value")))?
                .into_string()
                .map_err(|_| invalid(format!("{name} value must be valid UTF-8")))?;
            values.push((name.trim_start_matches("--").to_owned(), value));
        }
        Ok(Self {
            values,
            help: false,
        })
    }

    fn take_one(&mut self, name: &str) -> Result<String> {
        let positions = self
            .values
            .iter()
            .enumerate()
            .filter_map(|(index, (key, _))| (key == name).then_some(index))
            .collect::<Vec<_>>();
        if positions.len() != 1 {
            return Err(invalid(format!("--{name} must be specified exactly once")));
        }
        Ok(self.values.remove(positions[0]).1)
    }

    fn take_optional(&mut self, name: &str, default: &str) -> Result<String> {
        let positions = self
            .values
            .iter()
            .enumerate()
            .filter_map(|(index, (key, _))| (key == name).then_some(index))
            .collect::<Vec<_>>();
        match positions.as_slice() {
            [] => Ok(default.to_owned()),
            [position] => Ok(self.values.remove(*position).1),
            _ => Err(invalid(format!("--{name} may be specified at most once"))),
        }
    }

    fn take_repeated(&mut self, name: &str) -> Vec<String> {
        let mut selected = Vec::new();
        self.values.retain(|(key, value)| {
            if key == name {
                selected.push(value.clone());
                false
            } else {
                true
            }
        });
        selected
    }
}

#[derive(Debug)]
struct RelayOptions {
    https_bind: SocketAddr,
    http_bind: SocketAddr,
    certificate_der: PathBuf,
    private_key: PathBuf,
    allowlist: BTreeSet<String>,
    max_admitted_connections: usize,
    client_rx_bytes_per_second: NonZeroU32,
    client_rx_max_burst_bytes: NonZeroU32,
    key_cache_capacity: NonZeroUsize,
}

impl RelayOptions {
    fn from_options(mut options: Options) -> Result<Self> {
        let https_bind: SocketAddr = options.take_one("https-bind")?.parse()?;
        let http_bind: SocketAddr = options.take_one("http-bind")?.parse()?;
        validate_bind(https_bind, "HTTPS")?;
        validate_bind(http_bind, "HTTP")?;
        if https_bind == http_bind {
            return Err(invalid("HTTPS and HTTP relay binds must be distinct"));
        }
        let certificate_der = PathBuf::from(options.take_one("certificate-der")?);
        let private_key = PathBuf::from(options.take_one("private-key-pkcs8-der")?);
        let carriers = options.take_repeated("allow-carrier");
        if carriers.len() != 2 {
            return Err(invalid("exactly two --allow-carrier values are required"));
        }
        let mut allowlist = BTreeSet::new();
        for carrier in carriers {
            let id: EndpointId = carrier.parse()?;
            if id.to_string() != carrier {
                return Err(invalid(
                    "carrier allowlist ID is not canonical lowercase hex",
                ));
            }
            if !allowlist.insert(carrier) {
                return Err(invalid("carrier allowlist contains a duplicate ID"));
            }
        }
        let max_admitted_connections = parse_bounded_usize(
            &options.take_optional("max-admitted-connections", "8")?,
            "max admitted connections",
            1,
            MAX_ADMITTED_CONNECTIONS,
        )?;
        let client_rx_bytes_per_second = NonZeroU32::new(parse_bounded_u32(
            &options.take_optional("client-rx-bytes-per-second", "1048576")?,
            "client receive bytes per second",
            1_024,
            MAX_CLIENT_RX_BYTES_PER_SECOND,
        )?)
        .ok_or_else(|| invalid("client receive bytes per second must be nonzero"))?;
        let client_rx_max_burst_bytes = NonZeroU32::new(parse_bounded_u32(
            &options.take_optional("client-rx-max-burst-bytes", "1048576")?,
            "client receive max burst bytes",
            1_024,
            MAX_CLIENT_RX_BURST_BYTES,
        )?)
        .ok_or_else(|| invalid("client receive max burst bytes must be nonzero"))?;
        let key_cache_capacity = NonZeroUsize::new(parse_bounded_usize(
            &options.take_optional("key-cache-capacity", "256")?,
            "key cache capacity",
            2,
            MAX_KEY_CACHE_CAPACITY,
        )?)
        .ok_or_else(|| invalid("key cache capacity must be nonzero"))?;
        if !options.values.is_empty() {
            return Err(invalid(format!(
                "unexpected option --{}",
                options.values[0].0
            )));
        }
        Ok(Self {
            https_bind,
            http_bind,
            certificate_der,
            private_key,
            allowlist,
            max_admitted_connections,
            client_rx_bytes_per_second,
            client_rx_max_burst_bytes,
            key_cache_capacity,
        })
    }
}

#[derive(Debug, Default)]
struct AccessState {
    active: HashSet<(String, ConnectionId)>,
    accepted: u64,
    denied: u64,
    peak_active: usize,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct AccessSnapshot {
    active: usize,
    accepted: u64,
    denied: u64,
    peak_active: usize,
}

#[derive(Debug)]
struct BoundedAllowlist {
    allowed: BTreeSet<String>,
    max_admitted_connections: usize,
    state: Mutex<AccessState>,
}

impl BoundedAllowlist {
    fn new(allowed: BTreeSet<String>, max_admitted_connections: usize) -> Self {
        Self {
            allowed,
            max_admitted_connections,
            state: Mutex::new(AccessState::default()),
        }
    }

    fn snapshot(&self) -> Result<AccessSnapshot> {
        let state = self
            .state
            .lock()
            .map_err(|_| invalid("relay allowlist state is poisoned"))?;
        Ok(AccessSnapshot {
            active: state.active.len(),
            accepted: state.accepted,
            denied: state.denied,
            peak_active: state.peak_active,
        })
    }
}

impl AccessControl for BoundedAllowlist {
    async fn on_connect(&self, request: &ClientRequest) -> Access {
        let endpoint = request.endpoint_id().to_string();
        let Ok(mut state) = self.state.lock() else {
            return Access::Deny { reason: None };
        };
        if !self.allowed.contains(&endpoint) || state.active.len() >= self.max_admitted_connections
        {
            state.denied = state.denied.saturating_add(1);
            return Access::Deny { reason: None };
        }
        if !state.active.insert((endpoint, request.connection_id())) {
            state.denied = state.denied.saturating_add(1);
            return Access::Deny { reason: None };
        }
        state.accepted = state.accepted.saturating_add(1);
        state.peak_active = state.peak_active.max(state.active.len());
        Access::Allow
    }

    fn on_disconnect(&self, endpoint_id: EndpointId, connection_id: ConnectionId) {
        if let Ok(mut state) = self.state.lock() {
            state
                .active
                .remove(&(endpoint_id.to_string(), connection_id));
        }
    }
}

#[cfg(unix)]
struct ShutdownSignals {
    interrupt: tokio::signal::unix::Signal,
    terminate: tokio::signal::unix::Signal,
}

#[cfg(unix)]
impl ShutdownSignals {
    fn register() -> Result<Self> {
        Ok(Self {
            interrupt: tokio::signal::unix::signal(tokio::signal::unix::SignalKind::interrupt())?,
            terminate: tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate())?,
        })
    }

    async fn wait(mut self) -> Result<()> {
        tokio::select! {
            _ = self.interrupt.recv() => {},
            _ = self.terminate.recv() => {},
        }
        Ok(())
    }
}

#[cfg(windows)]
struct ShutdownSignals {
    interrupt: tokio::signal::windows::CtrlC,
}

#[cfg(windows)]
impl ShutdownSignals {
    fn register() -> Result<Self> {
        Ok(Self {
            interrupt: tokio::signal::windows::ctrl_c()?,
        })
    }

    async fn wait(mut self) -> Result<()> {
        let _ = self.interrupt.recv().await;
        Ok(())
    }
}

#[cfg(not(any(unix, windows)))]
struct ShutdownSignals;

#[cfg(not(any(unix, windows)))]
impl ShutdownSignals {
    fn register() -> Result<Self> {
        Err(invalid(
            "early shutdown-signal registration is unavailable on this platform",
        ))
    }

    async fn wait(self) -> Result<()> {
        let _ = self;
        Err(invalid(
            "early shutdown-signal registration is unavailable on this platform",
        ))
    }
}

fn validate_bind(address: SocketAddr, label: &str) -> Result<()> {
    if !matches!(address.ip(), std::net::IpAddr::V4(_))
        || address.port() == 0
        || address.ip().is_loopback()
        || address.ip().is_multicast()
    {
        return Err(invalid(format!(
            "{label} bind must be a non-loopback IPv4 address with a nonzero port"
        )));
    }
    Ok(())
}

fn parse_bounded_usize(value: &str, label: &str, minimum: usize, maximum: usize) -> Result<usize> {
    let value: usize = value.parse()?;
    if !(minimum..=maximum).contains(&value) {
        return Err(invalid(format!(
            "{label} must be within {minimum}..={maximum}"
        )));
    }
    Ok(value)
}

fn parse_bounded_u32(value: &str, label: &str, minimum: u32, maximum: u32) -> Result<u32> {
    let value: u32 = value.parse()?;
    if !(minimum..=maximum).contains(&value) {
        return Err(invalid(format!(
            "{label} must be within {minimum}..={maximum}"
        )));
    }
    Ok(value)
}

fn read_public_regular_bounded(path: &Path, maximum: u64, label: &str) -> Result<Vec<u8>> {
    let before = fs::symlink_metadata(path)?;
    if before.file_type().is_symlink() || !before.is_file() || before.len() > maximum {
        return Err(invalid(format!("{label} is not a bounded regular file")));
    }
    let mut options = OpenOptions::new();
    options.read(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt as _;
        options.custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK);
    }
    let mut file = options.open(path)?;
    let opened = file.metadata()?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt as _;
        if before.dev() != opened.dev() || before.ino() != opened.ino() {
            return Err(invalid(format!("{label} changed while opening")));
        }
    }
    let mut bytes = Vec::with_capacity(usize::try_from(opened.len().min(maximum))?);
    file.by_ref()
        .take(maximum.saturating_add(1))
        .read_to_end(&mut bytes)?;
    if bytes.is_empty() || u64::try_from(bytes.len())? > maximum {
        return Err(invalid(format!("{label} is empty or exceeds its bound")));
    }
    Ok(bytes)
}

#[cfg(unix)]
fn read_private_regular_bounded(
    path: &Path,
    maximum: u64,
    label: &str,
) -> Result<Zeroizing<Vec<u8>>> {
    use std::{ffi::OsString, os::unix::fs::MetadataExt as _, path::Component};

    if !path.is_absolute() {
        return Err(invalid(format!("{label} path must be absolute")));
    }
    let parent = path
        .parent()
        .ok_or_else(|| invalid(format!("{label} path has no parent")))?;
    let name: OsString = path
        .file_name()
        .ok_or_else(|| invalid(format!("{label} path has no final component")))?
        .to_owned();

    let open_directory_chain = |path: &Path| -> Result<(fs::File, Vec<(u64, u64)>)> {
        let mut components = path.components();
        if components.next() != Some(Component::RootDir) {
            return Err(invalid(format!("{label} parent is not absolute")));
        }
        let flags = rustix::fs::OFlags::RDONLY
            | rustix::fs::OFlags::DIRECTORY
            | rustix::fs::OFlags::NOFOLLOW
            | rustix::fs::OFlags::CLOEXEC
            | rustix::fs::OFlags::NONBLOCK;
        let descriptor = rustix::fs::open("/", flags, rustix::fs::Mode::empty())?;
        let mut directory = fs::File::from(descriptor);
        let metadata = directory.metadata()?;
        let mut identities = vec![(metadata.dev(), metadata.ino())];
        for component in components {
            let Component::Normal(component) = component else {
                return Err(invalid(format!(
                    "{label} path contains a non-canonical component"
                )));
            };
            let descriptor =
                rustix::fs::openat(&directory, component, flags, rustix::fs::Mode::empty())?;
            directory = fs::File::from(descriptor);
            let metadata = directory.metadata()?;
            if !metadata.is_dir() {
                return Err(invalid(format!(
                    "{label} ancestry contains a non-directory"
                )));
            }
            identities.push((metadata.dev(), metadata.ino()));
        }
        Ok((directory, identities))
    };

    let (parent_directory, ancestry) = open_directory_chain(parent)?;
    let descriptor = rustix::fs::openat(
        &parent_directory,
        &name,
        rustix::fs::OFlags::RDONLY
            | rustix::fs::OFlags::NOFOLLOW
            | rustix::fs::OFlags::CLOEXEC
            | rustix::fs::OFlags::NONBLOCK,
        rustix::fs::Mode::empty(),
    )?;
    let mut file = fs::File::from(descriptor);
    let before = file.metadata()?;
    let effective_uid = rustix::process::geteuid().as_raw();
    if !before.is_file()
        || before.len() > maximum
        || before.uid() != effective_uid
        || before.mode() & 0o7777 != 0o600
        || before.nlink() != 1
    {
        return Err(invalid(format!(
            "{label} must be a uniquely linked, effective-user-owned, exact-mode-0600 bounded regular file"
        )));
    }
    let buffer_length = usize::try_from(
        maximum
            .checked_add(1)
            .ok_or_else(|| invalid(format!("{label} byte bound overflow")))?,
    )?;
    let mut bytes = Zeroizing::new(Vec::new());
    bytes.resize(buffer_length, 0);
    let mut length = 0usize;
    while length < bytes.len() {
        match file.read(&mut bytes[length..]) {
            Ok(0) => break,
            Ok(read) => length = length.saturating_add(read),
            Err(error) if error.kind() == io::ErrorKind::Interrupted => {}
            Err(error) => return Err(error.into()),
        }
    }
    bytes.truncate(length);
    let opened_after_read = file.metadata()?;
    if before.dev() != opened_after_read.dev()
        || before.ino() != opened_after_read.ino()
        || before.len() != opened_after_read.len()
        || opened_after_read.uid() != effective_uid
        || opened_after_read.mode() & 0o7777 != 0o600
        || opened_after_read.nlink() != 1
    {
        return Err(invalid(format!("{label} changed while reading")));
    }
    let (reopened_parent, reopened_ancestry) = open_directory_chain(parent)?;
    if reopened_ancestry != ancestry {
        return Err(invalid(format!("{label} ancestry changed while reading")));
    }
    let reopened_descriptor = rustix::fs::openat(
        &reopened_parent,
        &name,
        rustix::fs::OFlags::RDONLY
            | rustix::fs::OFlags::NOFOLLOW
            | rustix::fs::OFlags::CLOEXEC
            | rustix::fs::OFlags::NONBLOCK,
        rustix::fs::Mode::empty(),
    )?;
    let reopened = fs::File::from(reopened_descriptor);
    let pathname = reopened.metadata()?;
    if before.dev() != pathname.dev()
        || before.ino() != pathname.ino()
        || before.len() != pathname.len()
        || pathname.uid() != effective_uid
        || pathname.mode() & 0o7777 != 0o600
        || pathname.nlink() != 1
    {
        return Err(invalid(format!("{label} pathname changed while reading")));
    }
    if bytes.is_empty() || u64::try_from(bytes.len())? > maximum {
        return Err(invalid(format!("{label} is empty or exceeds its bound")));
    }
    Ok(bytes)
}

#[cfg(not(unix))]
fn read_private_regular_bounded(
    _path: &Path,
    _maximum: u64,
    label: &str,
) -> Result<Zeroizing<Vec<u8>>> {
    Err(invalid(format!(
        "{label} private-file validation requires Unix"
    )))
}

fn invalid(message: impl Into<String>) -> Box<dyn Error> {
    io::Error::new(io::ErrorKind::InvalidInput, message.into()).into()
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicU64, Ordering};

    #[cfg(unix)]
    struct TestDirectory(PathBuf);

    #[cfg(unix)]
    impl TestDirectory {
        fn new(label: &str) -> Self {
            use std::os::unix::fs::PermissionsExt as _;

            static NEXT: AtomicU64 = AtomicU64::new(0);
            let path = env::temp_dir()
                .canonicalize()
                .expect("canonical temporary base")
                .join(format!(
                    "aster-selected-relay-{label}-{}-{}",
                    std::process::id(),
                    NEXT.fetch_add(1, Ordering::Relaxed)
                ));
            fs::create_dir(&path).expect("create test directory");
            fs::set_permissions(&path, fs::Permissions::from_mode(0o700))
                .expect("test directory mode");
            Self(path)
        }
    }

    #[cfg(unix)]
    impl Drop for TestDirectory {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.0);
        }
    }

    #[test]
    fn ring_key_parse_zeroizes_the_owned_source_der_before_returning() {
        let key_pair = rcgen::KeyPair::generate().expect("generate PKCS#8 key");
        let source = key_pair.serialize_der();
        let source_length = source.len();
        assert!(source.iter().any(|byte| *byte != 0));
        let key_der = PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(source));
        let (signing_key, postcondition) = parse_ring_key_and_zeroize_source(key_der);
        let signing_key = signing_key.expect("ring parses generated key");

        assert_eq!(
            postcondition,
            KeySourceZeroizePostcondition::LengthCleared { source_length }
        );
        assert!(postcondition.satisfied());
        assert!(
            signing_key
                .choose_scheme(&[rustls::SignatureScheme::ECDSA_NISTP256_SHA256])
                .is_some()
        );

        let invalid_source = vec![0xa5; 32];
        let invalid_source_length = invalid_source.len();
        let invalid_der = PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(invalid_source));
        let (invalid_parse, invalid_postcondition) = parse_ring_key_and_zeroize_source(invalid_der);
        assert!(invalid_parse.is_err());
        assert_eq!(
            invalid_postcondition,
            KeySourceZeroizePostcondition::LengthCleared {
                source_length: invalid_source_length
            }
        );
    }

    #[cfg(unix)]
    #[test]
    fn private_key_reader_binds_absolute_unique_effective_user_mode_0600_inode() {
        use std::os::unix::fs::PermissionsExt as _;

        let root = TestDirectory::new("private-key-reader");
        let key = root.0.join("server.key.pkcs8.der");
        fs::write(&key, [0xa5; 32]).expect("write key fixture");
        fs::set_permissions(&key, fs::Permissions::from_mode(0o600)).expect("key mode");
        assert_eq!(
            read_private_regular_bounded(&key, 64, "test key")
                .expect("private read")
                .as_slice(),
            &[0xa5; 32]
        );

        fs::set_permissions(&key, fs::Permissions::from_mode(0o640)).expect("broad key mode");
        assert!(read_private_regular_bounded(&key, 64, "test key").is_err());
        fs::set_permissions(&key, fs::Permissions::from_mode(0o600)).expect("restore key mode");
        let alias = root.0.join("alias.der");
        fs::hard_link(&key, &alias).expect("key hard link");
        assert!(read_private_regular_bounded(&key, 64, "test key").is_err());
        fs::remove_file(alias).expect("remove hard link");
        assert!(
            read_private_regular_bounded(Path::new("relative-key.der"), 64, "test key").is_err()
        );
    }

    #[test]
    fn bounds_and_non_loopback_binds_fail_closed() {
        assert!(validate_bind("127.0.0.1:8443".parse().expect("address"), "test").is_err());
        assert!(validate_bind("[::]:8443".parse().expect("address"), "test").is_err());
        validate_bind("0.0.0.0:8443".parse().expect("address"), "test").expect("wildcard v4");
        assert!(parse_bounded_usize("0", "test", 1, 32).is_err());
        assert!(parse_bounded_usize("33", "test", 1, 32).is_err());
        assert_eq!(parse_bounded_usize("8", "test", 1, 32).expect("bound"), 8);
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn shutdown_signal_handlers_register_before_any_wait() {
        let registered = ShutdownSignals::register().expect("register interrupt and terminate");
        tokio::task::yield_now().await;
        drop(registered);
    }

    #[test]
    fn exact_allowlist_requires_two_canonical_unique_ids() {
        let one = "11".repeat(32);
        let two = "22".repeat(32);
        let base = vec![
            "--https-bind".into(),
            "0.0.0.0:8443".into(),
            "--http-bind".into(),
            "0.0.0.0:8080".into(),
            "--certificate-der".into(),
            "cert.der".into(),
            "--private-key-pkcs8-der".into(),
            "key.der".into(),
        ];
        let mut valid = base.clone();
        valid.extend([
            OsString::from("--allow-carrier"),
            one.clone().into(),
            OsString::from("--allow-carrier"),
            two.into(),
        ]);
        RelayOptions::from_options(Options::parse(valid).expect("parse")).expect("valid");

        let mut old_rate_flag = base.clone();
        old_rate_flag.extend([
            OsString::from("--allow-carrier"),
            one.clone().into(),
            OsString::from("--allow-carrier"),
            "22".repeat(32).into(),
            OsString::from("--bytes-per-second"),
            "1048576".into(),
        ]);
        assert!(
            RelayOptions::from_options(Options::parse(old_rate_flag).expect("parse old flag"))
                .is_err()
        );
        let mut duplicate = base;
        duplicate.extend([
            OsString::from("--allow-carrier"),
            one.clone().into(),
            OsString::from("--allow-carrier"),
            one.into(),
        ]);
        assert!(RelayOptions::from_options(Options::parse(duplicate).expect("parse")).is_err());
    }
}
