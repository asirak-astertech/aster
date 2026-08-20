//! Optional relay fallback that forwards length-delimited opaque ciphertext.

use aster_mesh::link::{Link, LinkCharacteristics, ReceivedFrame};
use aster_mesh::model::NodeId;
use std::collections::BTreeMap;
use std::fmt;
use std::future::{Future, poll_fn};
use std::io::{self, Read, Write};
use std::net::{IpAddr, Shutdown, SocketAddr, TcpListener, TcpStream};
use std::pin::Pin;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex, OnceLock};
use std::task::{Context, Poll};
use std::time::{Duration, Instant};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, ReadBuf, copy_bidirectional};
use tokio::net::{TcpListener as TokioTcpListener, TcpStream as TokioTcpStream};
use tokio::runtime::{Builder as RuntimeBuilder, Runtime};
use tokio::sync::{OwnedSemaphorePermit, Semaphore, mpsc, watch};
use tokio::task::{AbortHandle, JoinSet};
use tokio::time::{Instant as TokioInstant, timeout as tokio_timeout, timeout_at};

const JOIN_VERSION: u8 = 1;
const READY: u8 = 0xa5;
const MAX_RELAY_FRAME: usize = u16::MAX as usize;
const MAX_WAITING_CHANNELS: usize = 4_096;
const MAX_PENDING_JOINS: usize = 256;
const MAX_ACTIVE_PAIRS: usize = 256;
const MAX_CONNECTIONS_PER_SOURCE: usize = 64;
const MAX_QUEUED_FRAMES: usize = 256;
const MAX_QUEUED_BYTES: usize = 4 * 1024 * 1024;
const JOIN_TIMEOUT: Duration = Duration::from_secs(10);
const WRITE_DEADLINE: Duration = Duration::from_secs(10 * 60);
const READ_HEADER_DEADLINE: Duration = Duration::from_secs(120);
const READ_BODY_BASE_DEADLINE: Duration = Duration::from_secs(30);
const MIN_READ_BITS_PER_SECOND: u64 = 1_024;
const ACTIVE_PAIR_IDLE_TIMEOUT: Duration = Duration::from_secs(120);
const WAITING_TTL: Duration = Duration::from_secs(120);
const WAITING_SWEEP_INTERVAL: Duration = Duration::from_secs(5);
const RELAY_RUNTIME_THREADS: usize = 1;

static RELAY_RUNTIME: OnceLock<Result<Runtime, String>> = OnceLock::new();

/// Availability limits for a [`CipherRelayServer`].
///
/// Source accounting uses the remote IP address and follows each accepted
/// socket across join validation, rendezvous waiting, and active forwarding.
/// Deployments behind a large shared NAT can raise the per-source limit while
/// retaining the global active-pair bound.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct RelayServerConfig {
    max_active_pairs: usize,
    max_connections_per_source: usize,
    active_pair_idle_timeout: Duration,
}

impl RelayServerConfig {
    /// Creates validated relay availability limits.
    ///
    /// # Errors
    ///
    /// Returns an invalid-input error when either count is zero, the active
    /// pair count exceeds Tokio's semaphore limit, or the idle timeout is zero
    /// or cannot be represented as a monotonic deadline.
    fn new(
        max_active_pairs: usize,
        max_connections_per_source: usize,
        active_pair_idle_timeout: Duration,
    ) -> io::Result<Self> {
        if max_active_pairs == 0 || max_active_pairs > Semaphore::MAX_PERMITS {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "relay active-pair limit is invalid",
            ));
        }
        if max_connections_per_source == 0 {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "relay per-source connection limit must be positive",
            ));
        }
        if active_pair_idle_timeout.is_zero() {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "relay active-pair idle timeout must be positive",
            ));
        }
        if TokioInstant::now()
            .checked_add(active_pair_idle_timeout)
            .is_none()
        {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "relay active-pair idle timeout is too large",
            ));
        }
        Ok(Self {
            max_active_pairs,
            max_connections_per_source,
            active_pair_idle_timeout,
        })
    }

    fn max_active_pairs(self) -> usize {
        self.max_active_pairs
    }

    fn max_connections_per_source(self) -> usize {
        self.max_connections_per_source
    }

    fn active_pair_idle_timeout(self) -> Duration {
        self.active_pair_idle_timeout
    }
}

impl Default for RelayServerConfig {
    fn default() -> Self {
        Self {
            max_active_pairs: MAX_ACTIVE_PAIRS,
            max_connections_per_source: MAX_CONNECTIONS_PER_SOURCE,
            active_pair_idle_timeout: ACTIVE_PAIR_IDLE_TIMEOUT,
        }
    }
}

fn relay_runtime() -> io::Result<&'static Runtime> {
    RELAY_RUNTIME
        .get_or_init(|| {
            RuntimeBuilder::new_multi_thread()
                .worker_threads(RELAY_RUNTIME_THREADS)
                .thread_name("aster-relay-io")
                .enable_io()
                .enable_time()
                .build()
                .map_err(|error| error.to_string())
        })
        .as_ref()
        .map_err(|message| io::Error::other(message.clone()))
}

/// A separately deployable, untrusted relay. It pairs two outbound TCP
/// connections sharing a random channel value and copies bytes without parsing.
#[derive(Debug)]
pub struct CipherRelayServer {
    listener: TcpListener,
    config: RelayServerConfig,
}

impl CipherRelayServer {
    /// Binds the relay listener. Defaults allow 256 active pairs, 64 accepted
    /// sockets per source IP, and 120 seconds of active-pair inactivity.
    ///
    /// # Errors
    ///
    /// Returns an operating-system bind error.
    pub fn bind(address: SocketAddr) -> io::Result<Self> {
        Self::bind_with_config(address, RelayServerConfig::default())
    }

    /// Binds the relay listener with explicit availability limits. The source
    /// limit counts accepted sockets, so one active pair normally consumes two
    /// permits when both peers share a public IP address.
    ///
    /// # Errors
    ///
    /// Returns an invalid-input error for a zero or unsupported limit, or an
    /// operating-system bind error.
    pub fn bind_with_limits(
        address: SocketAddr,
        max_active_pairs: usize,
        max_connections_per_source: usize,
        active_pair_idle_timeout: Duration,
    ) -> io::Result<Self> {
        let config = RelayServerConfig::new(
            max_active_pairs,
            max_connections_per_source,
            active_pair_idle_timeout,
        )?;
        Self::bind_with_config(address, config)
    }

    fn bind_with_config(address: SocketAddr, config: RelayServerConfig) -> io::Result<Self> {
        Ok(Self {
            listener: TcpListener::bind(address)?,
            config,
        })
    }

    /// Returns the bound address.
    ///
    /// # Errors
    ///
    /// Returns an operating-system address error.
    pub fn local_addr(&self) -> io::Result<SocketAddr> {
        self.listener.local_addr()
    }

    /// Serves at most `pair_limit` channel pairs. A limit of zero serves forever.
    /// Every relay in this process shares one bounded Tokio host runtime. Each
    /// paired channel is an async task rather than two dedicated OS threads.
    ///
    /// # Errors
    ///
    /// Returns on runtime or listener failure. Invalid client joins and
    /// per-client handshake failures are closed and do not consume a pair.
    pub fn serve(self, pair_limit: usize) -> io::Result<()> {
        if tokio::runtime::Handle::try_current().is_ok() {
            return Err(io::Error::new(
                io::ErrorKind::WouldBlock,
                "blocking relay serve must run outside an async runtime",
            ));
        }
        self.listener.set_nonblocking(true)?;
        let runtime = relay_runtime()?;
        let listener = {
            let _entered = runtime.enter();
            TokioTcpListener::from_std(self.listener)?
        };
        runtime.block_on(serve_relay(listener, pair_limit, self.config))
    }
}

#[derive(Debug)]
struct SourceAdmissions {
    maximum: usize,
    counts: Mutex<BTreeMap<IpAddr, usize>>,
}

impl SourceAdmissions {
    fn new(maximum: usize) -> Self {
        Self {
            maximum,
            counts: Mutex::new(BTreeMap::new()),
        }
    }

    fn try_acquire(self: &Arc<Self>, source: IpAddr) -> Option<SourceAdmission> {
        let source = canonical_source(source);
        let mut counts = self
            .counts
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let count = counts.entry(source).or_default();
        if *count >= self.maximum {
            return None;
        }
        *count += 1;
        Some(SourceAdmission {
            source,
            admissions: Arc::clone(self),
        })
    }

    #[cfg(test)]
    fn count(&self, source: IpAddr) -> usize {
        *self
            .counts
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .get(&canonical_source(source))
            .unwrap_or(&0)
    }
}

#[derive(Debug)]
struct SourceAdmission {
    source: IpAddr,
    admissions: Arc<SourceAdmissions>,
}

impl Drop for SourceAdmission {
    fn drop(&mut self) {
        let mut counts = self
            .admissions
            .counts
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let Some(count) = counts.get_mut(&self.source) else {
            return;
        };
        *count = count.saturating_sub(1);
        if *count == 0 {
            counts.remove(&self.source);
        }
    }
}

fn canonical_source(source: IpAddr) -> IpAddr {
    match source {
        IpAddr::V6(source) => source
            .to_ipv4_mapped()
            .map_or(IpAddr::V6(source), IpAddr::V4),
        IpAddr::V4(_) => source,
    }
}

async fn serve_relay(
    listener: TokioTcpListener,
    pair_limit: usize,
    config: RelayServerConfig,
) -> io::Result<()> {
    let (joined_tx, mut joined_rx) = mpsc::channel(MAX_PENDING_JOINS);
    let source_admissions = Arc::new(SourceAdmissions::new(config.max_connections_per_source()));
    let accept_task = relay_runtime()?.spawn(accept_joins(listener, joined_tx, source_admissions));
    let mut waiting: BTreeMap<[u8; 32], (TokioTcpStream, Instant, SourceAdmission)> =
        BTreeMap::new();
    let active = Arc::new(Semaphore::new(config.max_active_pairs()));
    let mut paired = 0_usize;
    let result = loop {
        let now = Instant::now();
        waiting.retain(|_, (_, registered, _)| {
            now.saturating_duration_since(*registered) <= WAITING_TTL
        });
        let joined = match tokio_timeout(WAITING_SWEEP_INTERVAL, joined_rx.recv()).await {
            Ok(Some(joined)) => joined,
            Ok(None) => {
                break Err(io::Error::new(
                    io::ErrorKind::BrokenPipe,
                    "relay accept loop stopped",
                ));
            }
            Err(_) => continue,
        };
        let (channel, mut stream, now, source_admission) = match joined {
            Ok(joined) => joined,
            Err(error) => break Err(error),
        };
        if let Some((mut first, _, first_source_admission)) = waiting.remove(&channel) {
            let permit = match Arc::clone(&active).try_acquire_owned() {
                Ok(permit) => permit,
                Err(tokio::sync::TryAcquireError::NoPermits) => continue,
                Err(tokio::sync::TryAcquireError::Closed) => {
                    break Err(io::Error::other("relay active-pair limiter closed"));
                }
            };
            let ready = tokio_timeout(JOIN_TIMEOUT, async {
                first.write_all(&[READY]).await?;
                stream.write_all(&[READY]).await
            })
            .await;
            if !matches!(ready, Ok(Ok(()))) {
                continue;
            }
            relay_runtime()?.spawn(async move {
                let _permit = permit;
                let _source_admissions = (first_source_admission, source_admission);
                let _ = copy_bidirectional_with_idle(
                    &mut first,
                    &mut stream,
                    config.active_pair_idle_timeout(),
                )
                .await;
            });
            paired += 1;
            if pair_limit != 0 && paired >= pair_limit {
                break Ok(());
            }
        } else if waiting.len() < MAX_WAITING_CHANNELS {
            waiting.insert(channel, (stream, now, source_admission));
        }
    };
    accept_task.abort();
    let _ = accept_task.await;
    result
}

type Joined = io::Result<([u8; 32], TokioTcpStream, Instant, SourceAdmission)>;

async fn accept_joins(
    listener: TokioTcpListener,
    joined: mpsc::Sender<Joined>,
    source_admissions: Arc<SourceAdmissions>,
) {
    let pending = Arc::new(Semaphore::new(MAX_PENDING_JOINS));
    let mut handshakes = JoinSet::new();
    loop {
        while handshakes.try_join_next().is_some() {}
        let Ok(permit) = Arc::clone(&pending).acquire_owned().await else {
            return;
        };
        let (stream, source) = match listener.accept().await {
            Ok(accepted) => accepted,
            Err(error) => {
                let _ = joined.send(Err(error)).await;
                return;
            }
        };
        let Some(source_admission) = source_admissions.try_acquire(source.ip()) else {
            continue;
        };
        let joined = joined.clone();
        handshakes.spawn(async move {
            let _permit = permit;
            if let Some(validated) = validate_join(stream, source_admission).await {
                let _ = joined.send(Ok(validated)).await;
            }
        });
    }
}

async fn validate_join(
    mut stream: TokioTcpStream,
    source_admission: SourceAdmission,
) -> Option<([u8; 32], TokioTcpStream, Instant, SourceAdmission)> {
    if stream.set_nodelay(true).is_err() {
        return None;
    }
    let mut join = [0_u8; 33];
    if !matches!(
        tokio_timeout(JOIN_TIMEOUT, stream.read_exact(&mut join)).await,
        Ok(Ok(_))
    ) || join[0] != JOIN_VERSION
    {
        return None;
    }
    let mut channel = [0_u8; 32];
    channel.copy_from_slice(&join[1..]);
    (channel != [0; 32]).then_some((channel, stream, Instant::now(), source_admission))
}

struct ActivityTracked<T> {
    inner: T,
    activity: watch::Sender<TokioInstant>,
}

impl<T> AsyncRead for ActivityTracked<T>
where
    T: AsyncRead + Unpin,
{
    fn poll_read(
        mut self: Pin<&mut Self>,
        context: &mut Context<'_>,
        buffer: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        let before = buffer.filled().len();
        let result = Pin::new(&mut self.inner).poll_read(context, buffer);
        if matches!(result, Poll::Ready(Ok(()))) && buffer.filled().len() > before {
            self.activity.send_replace(TokioInstant::now());
        }
        result
    }
}

impl<T> AsyncWrite for ActivityTracked<T>
where
    T: AsyncWrite + Unpin,
{
    fn poll_write(
        mut self: Pin<&mut Self>,
        context: &mut Context<'_>,
        bytes: &[u8],
    ) -> Poll<io::Result<usize>> {
        let result = Pin::new(&mut self.inner).poll_write(context, bytes);
        if matches!(result, Poll::Ready(Ok(written)) if written > 0) {
            self.activity.send_replace(TokioInstant::now());
        }
        result
    }

    fn poll_flush(mut self: Pin<&mut Self>, context: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.inner).poll_flush(context)
    }

    fn poll_shutdown(mut self: Pin<&mut Self>, context: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.inner).poll_shutdown(context)
    }
}

async fn copy_bidirectional_with_idle<A, B>(
    first: &mut A,
    second: &mut B,
    idle_timeout: Duration,
) -> io::Result<(u64, u64)>
where
    A: AsyncRead + AsyncWrite + Unpin,
    B: AsyncRead + AsyncWrite + Unpin,
{
    enum Event {
        Transfer(io::Result<(u64, u64)>),
        Activity(Result<(), watch::error::RecvError>),
        Idle,
    }

    let (activity, mut observed) = watch::channel(TokioInstant::now());
    let mut first = ActivityTracked {
        inner: first,
        activity: activity.clone(),
    };
    let mut second = ActivityTracked {
        inner: second,
        activity,
    };
    let mut transfer = Box::pin(copy_bidirectional(&mut first, &mut second));
    loop {
        let last_activity = *observed.borrow_and_update();
        let deadline = last_activity.checked_add(idle_timeout).ok_or_else(|| {
            io::Error::new(
                io::ErrorKind::InvalidInput,
                "relay active-pair idle deadline overflow",
            )
        })?;
        let mut changed = Box::pin(observed.changed());
        let mut idle = Box::pin(tokio::time::sleep_until(deadline));
        let event = poll_fn(|context| {
            if let Poll::Ready(result) = transfer.as_mut().poll(context) {
                return Poll::Ready(Event::Transfer(result));
            }
            if let Poll::Ready(result) = changed.as_mut().poll(context) {
                return Poll::Ready(Event::Activity(result));
            }
            if idle.as_mut().poll(context).is_ready() {
                return Poll::Ready(Event::Idle);
            }
            Poll::Pending
        })
        .await;
        match event {
            Event::Transfer(result) => return result,
            Event::Activity(Ok(())) => {}
            Event::Activity(Err(_)) => {
                return Err(io::Error::new(
                    io::ErrorKind::BrokenPipe,
                    "relay activity monitor stopped",
                ));
            }
            Event::Idle => {
                return Err(io::Error::new(
                    io::ErrorKind::TimedOut,
                    "relay active pair idle timeout reached",
                ));
            }
        }
    }
}

#[derive(Debug)]
struct QueuedFrame {
    bytes: Vec<u8>,
    _byte_permit: Option<OwnedSemaphorePermit>,
}

#[derive(Debug)]
struct WriteRequest {
    encoded: Vec<u8>,
    deadline: Instant,
    _byte_permit: OwnedSemaphorePermit,
}

/// Client-side relay adapter. Mesh identity and content remain protected by the
/// core; `channel` is only an unguessable rendezvous capability.
pub struct RelayLink {
    name: String,
    outgoing: mpsc::Sender<WriteRequest>,
    outgoing_bytes: Arc<Semaphore>,
    incoming: Mutex<mpsc::Receiver<QueuedFrame>>,
    peer: NodeId,
    alive: Arc<AtomicBool>,
    shutdown: Arc<TcpStream>,
    reader_task: AbortHandle,
    writer_task: AbortHandle,
}

impl fmt::Debug for RelayLink {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("RelayLink")
            .field("name", &self.name)
            .field("peer", &self.peer)
            .field("alive", &self.alive.load(Ordering::Acquire))
            .finish_non_exhaustive()
    }
}

impl RelayLink {
    /// Connects and waits for a second endpoint to join the same channel.
    ///
    /// # Errors
    ///
    /// Returns for an all-zero channel, connection/handshake failure, or timeout.
    pub fn connect(
        name: impl Into<String>,
        address: SocketAddr,
        channel: [u8; 32],
        peer: NodeId,
        timeout: Duration,
    ) -> io::Result<Self> {
        if channel == [0; 32] {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "relay channel must be random",
            ));
        }
        let deadline = Instant::now().checked_add(timeout).ok_or_else(|| {
            io::Error::new(io::ErrorKind::InvalidInput, "relay timeout too large")
        })?;
        let mut stream = TcpStream::connect_timeout(&address, remaining(deadline)?)?;
        stream.set_nodelay(true)?;
        stream.set_read_timeout(Some(remaining(deadline)?))?;
        stream.set_write_timeout(Some(remaining(deadline)?))?;
        let mut join = [0_u8; 33];
        join[0] = JOIN_VERSION;
        join[1..].copy_from_slice(&channel);
        stream.write_all(&join)?;
        stream.set_read_timeout(Some(remaining(deadline)?))?;
        let mut ready = [0_u8; 1];
        stream.read_exact(&mut ready)?;
        if ready[0] != READY {
            return Err(io::Error::new(
                io::ErrorKind::PermissionDenied,
                "relay rejected channel",
            ));
        }
        stream.set_read_timeout(None)?;
        stream.set_write_timeout(None)?;
        let shutdown = Arc::new(stream.try_clone()?);
        stream.set_nonblocking(true)?;
        let runtime = relay_runtime()?;
        let stream = {
            let _entered = runtime.enter();
            TokioTcpStream::from_std(stream)?
        };
        let (reader, writer) = stream.into_split();
        let (incoming_tx, incoming_rx) = mpsc::channel(MAX_QUEUED_FRAMES);
        let incoming_bytes = Arc::new(Semaphore::new(MAX_QUEUED_BYTES));
        let (outgoing_tx, outgoing_rx) = mpsc::channel(MAX_QUEUED_FRAMES);
        let outgoing_bytes = Arc::new(Semaphore::new(MAX_QUEUED_BYTES));
        let alive = Arc::new(AtomicBool::new(true));
        let writer_alive = Arc::clone(&alive);
        let writer_shutdown = Arc::clone(&shutdown);
        let writer_join = runtime.spawn(relay_writer(
            writer,
            outgoing_rx,
            writer_alive,
            writer_shutdown,
        ));
        let writer_task = writer_join.abort_handle();
        let reader_alive = Arc::clone(&alive);
        let reader_join = runtime.spawn(relay_reader(
            reader,
            incoming_tx,
            incoming_bytes,
            reader_alive,
            Arc::clone(&shutdown),
            writer_task.clone(),
        ));
        let reader_task = reader_join.abort_handle();
        Ok(Self {
            name: name.into(),
            outgoing: outgoing_tx,
            outgoing_bytes,
            incoming: Mutex::new(incoming_rx),
            peer,
            alive,
            shutdown,
            reader_task,
            writer_task,
        })
    }
}

fn remaining(deadline: Instant) -> io::Result<Duration> {
    deadline
        .checked_duration_since(Instant::now())
        .filter(|remaining| !remaining.is_zero())
        .ok_or_else(|| io::Error::new(io::ErrorKind::TimedOut, "relay handshake timed out"))
}

async fn read_exact_with_deadline<R>(
    reader: &mut R,
    bytes: &mut [u8],
    deadline: Duration,
    message: &'static str,
) -> io::Result<()>
where
    R: AsyncRead + Unpin,
{
    match tokio_timeout(deadline, reader.read_exact(bytes)).await {
        Ok(Ok(_)) => Ok(()),
        Ok(Err(error)) => Err(error),
        Err(_) => Err(io::Error::new(io::ErrorKind::TimedOut, message)),
    }
}

async fn read_length_with_deadline<R>(reader: &mut R, deadline: Duration) -> io::Result<usize>
where
    R: AsyncRead + Unpin,
{
    let mut bytes = [0_u8; 4];
    read_exact_with_deadline(
        reader,
        &mut bytes,
        deadline,
        "relay header deadline reached",
    )
    .await?;
    usize::try_from(u32::from_be_bytes(bytes))
        .map_err(|_| io::Error::new(io::ErrorKind::InvalidData, "frame length overflow"))
}

async fn read_length<R>(reader: &mut R) -> io::Result<usize>
where
    R: AsyncRead + Unpin,
{
    read_length_with_deadline(reader, READ_HEADER_DEADLINE).await
}

fn body_read_deadline(length: usize) -> Duration {
    let bits = u64::try_from(length).unwrap_or(u64::MAX).saturating_mul(8);
    let transfer_seconds = bits.div_ceil(MIN_READ_BITS_PER_SECOND);
    READ_BODY_BASE_DEADLINE.saturating_add(Duration::from_secs(transfer_seconds))
}

async fn read_body_with_deadline<R>(
    reader: &mut R,
    length: usize,
    deadline: Duration,
) -> io::Result<Vec<u8>>
where
    R: AsyncRead + Unpin,
{
    let mut frame = vec![0_u8; length];
    read_exact_with_deadline(reader, &mut frame, deadline, "relay body deadline reached").await?;
    Ok(frame)
}

async fn relay_reader(
    mut reader: tokio::net::tcp::OwnedReadHalf,
    incoming: mpsc::Sender<QueuedFrame>,
    incoming_bytes: Arc<Semaphore>,
    alive: Arc<AtomicBool>,
    shutdown: Arc<TcpStream>,
    writer_task: AbortHandle,
) {
    while let Ok(length) = read_length(&mut reader).await {
        if length > MAX_RELAY_FRAME {
            break;
        }
        let Ok(frame_slot) = incoming.clone().reserve_owned().await else {
            break;
        };
        let byte_permit = if length == 0 {
            None
        } else {
            let Ok(length) = u32::try_from(length) else {
                break;
            };
            let Ok(permit) = Arc::clone(&incoming_bytes).acquire_many_owned(length).await else {
                break;
            };
            Some(permit)
        };
        let Ok(frame) =
            read_body_with_deadline(&mut reader, length, body_read_deadline(length)).await
        else {
            break;
        };
        frame_slot.send(QueuedFrame {
            bytes: frame,
            _byte_permit: byte_permit,
        });
    }
    alive.store(false, Ordering::Release);
    let _ = shutdown.shutdown(Shutdown::Both);
    writer_task.abort();
}

async fn relay_writer(
    mut writer: tokio::net::tcp::OwnedWriteHalf,
    mut outgoing: mpsc::Receiver<WriteRequest>,
    alive: Arc<AtomicBool>,
    shutdown: Arc<TcpStream>,
) {
    let _ = write_requests(&mut writer, &mut outgoing).await;
    alive.store(false, Ordering::Release);
    let _ = writer.shutdown().await;
    let _ = shutdown.shutdown(Shutdown::Both);
}

async fn write_requests<W>(
    writer: &mut W,
    outgoing: &mut mpsc::Receiver<WriteRequest>,
) -> io::Result<()>
where
    W: AsyncWrite + Unpin,
{
    while let Some(request) = outgoing.recv().await {
        let result = match timeout_at(
            TokioInstant::from_std(request.deadline),
            writer.write_all(&request.encoded),
        )
        .await
        {
            Ok(result) => result,
            Err(_) => Err(io::Error::new(
                io::ErrorKind::TimedOut,
                "relay write deadline reached",
            )),
        };
        result?;
    }
    Ok(())
}

impl Link for RelayLink {
    fn name(&self) -> &str {
        &self.name
    }

    fn characteristics(&self) -> LinkCharacteristics {
        LinkCharacteristics {
            mtu: u16::MAX,
            bits_per_second: None,
            cost: 96,
            emission: 32,
            broadcast: false,
        }
    }

    fn send(&self, peer: Option<NodeId>, frame: &[u8]) -> io::Result<()> {
        if peer.is_some_and(|candidate| candidate != self.peer) {
            return Err(io::Error::new(
                io::ErrorKind::NotConnected,
                "wrong relay peer",
            ));
        }
        if frame.len() > MAX_RELAY_FRAME {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "relay frame too large",
            ));
        }
        if !self.alive.load(Ordering::Acquire) {
            return Err(io::Error::new(
                io::ErrorKind::BrokenPipe,
                "relay disconnected",
            ));
        }
        let length = u32::try_from(frame.len())
            .map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "relay frame too large"))?;
        let encoded_len = 4_usize
            .checked_add(frame.len())
            .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidInput, "relay frame too large"))?;
        let permit_count = u32::try_from(encoded_len)
            .map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "relay frame too large"))?;
        let byte_permit = Arc::clone(&self.outgoing_bytes)
            .try_acquire_many_owned(permit_count)
            .map_err(|error| match error {
                tokio::sync::TryAcquireError::NoPermits => io::Error::new(
                    io::ErrorKind::WouldBlock,
                    "relay outgoing byte limit reached",
                ),
                tokio::sync::TryAcquireError::Closed => {
                    io::Error::new(io::ErrorKind::BrokenPipe, "relay disconnected")
                }
            })?;
        let mut encoded = Vec::with_capacity(encoded_len);
        encoded.extend_from_slice(&length.to_be_bytes());
        encoded.extend_from_slice(frame);
        let deadline = Instant::now().checked_add(WRITE_DEADLINE).ok_or_else(|| {
            io::Error::new(io::ErrorKind::InvalidInput, "relay write deadline overflow")
        })?;
        self.outgoing
            .try_send(WriteRequest {
                encoded,
                deadline,
                _byte_permit: byte_permit,
            })
            .map_err(|error| match error {
                mpsc::error::TrySendError::Full(_) => io::Error::new(
                    io::ErrorKind::WouldBlock,
                    "relay outgoing frame limit reached",
                ),
                mpsc::error::TrySendError::Closed(_) => {
                    io::Error::new(io::ErrorKind::BrokenPipe, "relay disconnected")
                }
            })
    }

    fn try_receive(&self) -> io::Result<Option<ReceivedFrame>> {
        let mut queue = self
            .incoming
            .lock()
            .map_err(|_| io::Error::other("relay queue poisoned"))?;
        match queue.try_recv() {
            Ok(QueuedFrame {
                bytes,
                _byte_permit,
            }) => Ok(Some(ReceivedFrame {
                peer: Some(self.peer),
                bytes,
            })),
            Err(mpsc::error::TryRecvError::Empty) => Ok(None),
            Err(mpsc::error::TryRecvError::Disconnected) => Ok(None),
        }
    }

    fn set_discovery(&self, _enabled: bool) -> io::Result<()> {
        Ok(())
    }

    fn next_wakeup(&self) -> Option<Instant> {
        None
    }
}

impl Drop for RelayLink {
    fn drop(&mut self) {
        self.alive.store(false, Ordering::Release);
        let _ = self.shutdown.shutdown(Shutdown::Both);
        self.reader_task.abort();
        self.writer_task.abort();
    }
}

#[cfg(test)]
mod tests {
    use super::{
        ACTIVE_PAIR_IDLE_TIMEOUT, CipherRelayServer, MAX_ACTIVE_PAIRS, MAX_CONNECTIONS_PER_SOURCE,
        MAX_PENDING_JOINS, MAX_QUEUED_BYTES, MAX_QUEUED_FRAMES, MAX_RELAY_FRAME,
        MAX_WAITING_CHANNELS, MIN_READ_BITS_PER_SECOND, QueuedFrame, READ_BODY_BASE_DEADLINE,
        READ_HEADER_DEADLINE, RelayLink, RelayServerConfig, SourceAdmissions, WriteRequest,
        body_read_deadline, read_body_with_deadline, read_length_with_deadline, relay_runtime,
        write_requests,
    };
    use aster_mesh::link::Link;
    use std::io::{self, Read, Write};
    use std::net::{IpAddr, Ipv4Addr, Shutdown, SocketAddr, TcpListener, TcpStream};
    use std::sync::atomic::{AtomicBool, Ordering};
    use std::sync::{Arc, mpsc as std_mpsc};
    use std::thread;
    use std::time::{Duration, Instant};
    use tokio::sync::{Semaphore, mpsc};

    const RAW_JOIN_VERSION: u8 = 0x01;
    const RAW_READY: u8 = 0xa5;
    const TEST_TIMEOUT: Duration = Duration::from_secs(5);

    fn loopback() -> SocketAddr {
        SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 0)
    }

    fn configure(stream: &TcpStream) {
        stream.set_read_timeout(Some(TEST_TIMEOUT)).unwrap();
        stream.set_write_timeout(Some(TEST_TIMEOUT)).unwrap();
    }

    fn raw_join_write(stream: &mut TcpStream, channel: [u8; 32]) {
        let mut join = [0_u8; 33];
        join[0] = RAW_JOIN_VERSION;
        join[1..].copy_from_slice(&channel);
        stream.write_all(&join).unwrap();
    }

    fn raw_ready_read(stream: &mut TcpStream) {
        let mut ready = [0_u8; 1];
        stream.read_exact(&mut ready).unwrap();
        assert_eq!(ready, [RAW_READY]);
    }

    fn raw_server_handshake(stream: &mut TcpStream, channel: [u8; 32]) {
        let mut join = [0_u8; 33];
        stream.read_exact(&mut join).unwrap();
        let mut expected = [0_u8; 33];
        expected[0] = RAW_JOIN_VERSION;
        expected[1..].copy_from_slice(&channel);
        assert_eq!(join, expected);
        stream.write_all(&[RAW_READY]).unwrap();
    }

    fn raw_frame_write(stream: &mut TcpStream, frame: &[u8]) {
        let length = u32::try_from(frame.len()).unwrap();
        stream.write_all(&length.to_be_bytes()).unwrap();
        stream.write_all(frame).unwrap();
    }

    fn raw_frame_read(stream: &mut TcpStream) -> Vec<u8> {
        let mut prefix = [0_u8; 4];
        stream.read_exact(&mut prefix).unwrap();
        let length = usize::try_from(u32::from_be_bytes(prefix)).unwrap();
        assert!(length <= 65_535, "raw oracle rejected oversized frame");
        let mut frame = vec![0_u8; length];
        stream.read_exact(&mut frame).unwrap();
        frame
    }

    fn receive(link: &RelayLink) -> Vec<u8> {
        let deadline = Instant::now() + TEST_TIMEOUT;
        loop {
            if let Some(frame) = link.try_receive().unwrap() {
                return frame.bytes;
            }
            assert!(Instant::now() < deadline, "relay receive timed out");
            thread::yield_now();
        }
    }

    fn wait_for_queue_len(link: &RelayLink, expected: usize) {
        let deadline = Instant::now() + TEST_TIMEOUT;
        loop {
            let length = link.incoming.lock().unwrap().len();
            if length == expected {
                return;
            }
            assert!(
                Instant::now() < deadline,
                "relay queue length was {length}, expected {expected}"
            );
            thread::yield_now();
        }
    }

    fn start_server(pair_limit: usize) -> (SocketAddr, thread::JoinHandle<()>) {
        start_server_with_config(pair_limit, RelayServerConfig::default())
    }

    fn start_server_with_config(
        pair_limit: usize,
        config: RelayServerConfig,
    ) -> (SocketAddr, thread::JoinHandle<()>) {
        let server = CipherRelayServer::bind_with_limits(
            loopback(),
            config.max_active_pairs(),
            config.max_connections_per_source(),
            config.active_pair_idle_timeout(),
        )
        .unwrap();
        let address = server.local_addr().unwrap();
        let task = thread::spawn(move || server.serve(pair_limit).unwrap());
        (address, task)
    }

    fn raw_pair(address: SocketAddr, channel: [u8; 32]) -> (TcpStream, TcpStream) {
        let mut first = TcpStream::connect(address).unwrap();
        let mut second = TcpStream::connect(address).unwrap();
        configure(&first);
        configure(&second);
        raw_join_write(&mut first, channel);
        raw_join_write(&mut second, channel);
        raw_ready_read(&mut first);
        raw_ready_read(&mut second);
        (first, second)
    }

    fn assert_stream_closed(stream: &mut TcpStream) {
        let mut byte = [0_u8; 1];
        match stream.read(&mut byte) {
            Ok(0) => {}
            Err(error)
                if matches!(
                    error.kind(),
                    io::ErrorKind::ConnectionReset
                        | io::ErrorKind::BrokenPipe
                        | io::ErrorKind::UnexpectedEof
                ) => {}
            result => panic!("relay stream remained open: {result:?}"),
        }
    }

    fn detached_test_link(
        outgoing: mpsc::Sender<WriteRequest>,
        outgoing_bytes: Arc<Semaphore>,
        alive: Arc<AtomicBool>,
        writer_task: tokio::task::AbortHandle,
    ) -> RelayLink {
        let listener = TcpListener::bind(loopback()).unwrap();
        let shutdown = Arc::new(TcpStream::connect(listener.local_addr().unwrap()).unwrap());
        let (_peer, _) = listener.accept().unwrap();
        let (_incoming_tx, incoming) = mpsc::channel::<QueuedFrame>(1);
        let reader_join = relay_runtime().unwrap().spawn(std::future::pending::<()>());
        RelayLink {
            name: "detached-test".to_owned(),
            outgoing,
            outgoing_bytes,
            incoming: std::sync::Mutex::new(incoming),
            peer: [2; 32],
            alive,
            shutdown,
            reader_task: reader_join.abort_handle(),
            writer_task,
        }
    }

    #[test]
    fn raw_clients_interoperate_and_outlive_server_admission() {
        let (address, server) = start_server(1);
        let channel = [42; 32];
        let (mut first, mut second) = raw_pair(address, channel);
        server.join().unwrap();

        for length in [0, 1, 1_200, 65_535] {
            let outbound = vec![u8::try_from(length % 251).unwrap(); length];
            raw_frame_write(&mut first, &outbound);
            assert_eq!(raw_frame_read(&mut second), outbound);

            let response = vec![u8::try_from((length + 1) % 251).unwrap(); length];
            raw_frame_write(&mut second, &response);
            assert_eq!(raw_frame_read(&mut first), response);
        }
    }

    #[test]
    fn relay_server_config_rejects_unrepresentable_idle_deadline() {
        assert_eq!(
            RelayServerConfig::new(1, 1, Duration::MAX)
                .unwrap_err()
                .kind(),
            io::ErrorKind::InvalidInput
        );
        assert!(RelayServerConfig::new(1, 1, Duration::from_secs(1)).is_ok());
    }

    #[test]
    fn slow_join_does_not_block_valid_pair() {
        let (address, server) = start_server(1);
        let mut invalid_version = TcpStream::connect(address).unwrap();
        configure(&invalid_version);
        invalid_version.write_all(&[2_u8; 33]).unwrap();
        let mut byte = [0_u8; 1];
        assert_eq!(invalid_version.read(&mut byte).unwrap(), 0);

        let mut zero_channel = TcpStream::connect(address).unwrap();
        configure(&zero_channel);
        raw_join_write(&mut zero_channel, [0; 32]);
        assert_eq!(zero_channel.read(&mut byte).unwrap(), 0);

        let mut slow = TcpStream::connect(address).unwrap();
        configure(&slow);
        slow.write_all(&[RAW_JOIN_VERSION]).unwrap();

        let (first, second) = raw_pair(address, [43; 32]);
        server.join().unwrap();
        drop((first, second, slow));
    }

    #[test]
    fn relay_link_rejects_zero_channel_and_wrong_ready_byte() {
        let listener = TcpListener::bind(loopback()).unwrap();
        let address = listener.local_addr().unwrap();
        assert_eq!(
            RelayLink::connect("zero", address, [0; 32], [2; 32], TEST_TIMEOUT)
                .unwrap_err()
                .kind(),
            io::ErrorKind::InvalidInput
        );

        let channel = [49; 32];
        let server = thread::spawn(move || {
            let (mut stream, _) = listener.accept().unwrap();
            configure(&stream);
            let mut join = [0_u8; 33];
            stream.read_exact(&mut join).unwrap();
            let mut expected = [0_u8; 33];
            expected[0] = RAW_JOIN_VERSION;
            expected[1..].copy_from_slice(&channel);
            assert_eq!(join, expected);
            stream.write_all(&[0_u8]).unwrap();
        });
        assert_eq!(
            RelayLink::connect("wrong-ready", address, channel, [2; 32], TEST_TIMEOUT)
                .unwrap_err()
                .kind(),
            io::ErrorKind::PermissionDenied
        );
        server.join().unwrap();
    }

    #[test]
    fn relay_server_preserves_directional_half_close() {
        let (address, server) = start_server(1);
        let (mut first, mut second) = raw_pair(address, [44; 32]);
        server.join().unwrap();

        raw_frame_write(&mut first, b"request");
        first.shutdown(Shutdown::Write).unwrap();
        assert_eq!(raw_frame_read(&mut second), b"request");
        let mut byte = [0_u8; 1];
        assert_eq!(second.read(&mut byte).unwrap(), 0);

        raw_frame_write(&mut second, b"response");
        second.shutdown(Shutdown::Write).unwrap();
        assert_eq!(raw_frame_read(&mut first), b"response");
        assert_eq!(first.read(&mut byte).unwrap(), 0);
    }

    #[test]
    fn source_admission_is_bounded_and_released_across_lifecycles() {
        let admissions = Arc::new(SourceAdmissions::new(2));
        let source = IpAddr::V4(Ipv4Addr::LOCALHOST);
        let mapped = IpAddr::V6(Ipv4Addr::LOCALHOST.to_ipv6_mapped());
        let first = admissions.try_acquire(source).unwrap();
        let second = admissions.try_acquire(mapped).unwrap();
        assert_eq!(admissions.count(source), 2);
        assert!(admissions.try_acquire(source).is_none());

        drop(first);
        assert_eq!(admissions.count(source), 1);
        let replacement = admissions.try_acquire(source).unwrap();
        assert_eq!(admissions.count(source), 2);

        drop((second, replacement));
        assert_eq!(admissions.count(source), 0);
    }

    #[test]
    fn active_pair_idle_timeout_releases_global_slot() {
        let config = RelayServerConfig::new(1, 8, Duration::from_secs(1)).unwrap();
        let (address, server) = start_server_with_config(2, config);
        let (mut first, mut second) = raw_pair(address, [51; 32]);

        let mut rejected_first = TcpStream::connect(address).unwrap();
        let mut rejected_second = TcpStream::connect(address).unwrap();
        configure(&rejected_first);
        configure(&rejected_second);
        raw_join_write(&mut rejected_first, [52; 32]);
        raw_join_write(&mut rejected_second, [52; 32]);
        assert_stream_closed(&mut rejected_first);
        assert_stream_closed(&mut rejected_second);

        assert_stream_closed(&mut first);
        assert_stream_closed(&mut second);
        let pair = raw_pair(address, [53; 32]);
        server.join().unwrap();
        drop(pair);
    }

    #[test]
    fn per_source_limit_covers_active_pairs_and_releases_after_idle() {
        let config = RelayServerConfig::new(2, 2, Duration::from_secs(1)).unwrap();
        let (address, server) = start_server_with_config(2, config);
        let (mut first, mut second) = raw_pair(address, [54; 32]);

        let mut excess = TcpStream::connect(address).unwrap();
        configure(&excess);
        raw_join_write(&mut excess, [55; 32]);
        assert_stream_closed(&mut excess);

        assert_stream_closed(&mut first);
        assert_stream_closed(&mut second);
        let pair = raw_pair(address, [56; 32]);
        server.join().unwrap();
        drop(pair);
    }

    #[test]
    fn relay_server_admits_256_pairs_on_one_runtime_worker() {
        let config = RelayServerConfig::new(256, 512, ACTIVE_PAIR_IDLE_TIMEOUT).unwrap();
        let (address, server) = start_server_with_config(256, config);
        let mut pairs = Vec::with_capacity(256);
        for index in 1_u16..=256 {
            let mut channel = [0_u8; 32];
            channel[..2].copy_from_slice(&index.to_be_bytes());
            pairs.push(raw_pair(address, channel));
        }
        server.join().unwrap();

        for (index, (first, second)) in pairs.iter_mut().enumerate() {
            let payload = vec![u8::try_from(index % 251).unwrap(); 65_535];
            raw_frame_write(first, &payload);
            assert_eq!(raw_frame_read(second), payload);
        }
    }

    #[test]
    fn relay_link_interoperates_with_raw_server_and_drop_closes_socket() {
        let listener = TcpListener::bind(loopback()).unwrap();
        let address = listener.local_addr().unwrap();
        let channel = [45; 32];
        let server = thread::spawn(move || {
            let (mut stream, _) = listener.accept().unwrap();
            configure(&stream);
            raw_server_handshake(&mut stream, channel);
            assert_eq!(raw_frame_read(&mut stream), Vec::<u8>::new());
            assert_eq!(raw_frame_read(&mut stream), vec![7; 65_535]);
            raw_frame_write(&mut stream, &[]);
            raw_frame_write(&mut stream, &vec![8; 1_200]);
            let mut byte = [0_u8; 1];
            assert_eq!(stream.read(&mut byte).unwrap(), 0);
        });

        let link = RelayLink::connect("raw", address, channel, [2; 32], TEST_TIMEOUT).unwrap();
        link.send(Some([2; 32]), &[]).unwrap();
        link.send(Some([2; 32]), &vec![7; 65_535]).unwrap();
        assert_eq!(receive(&link), Vec::<u8>::new());
        assert_eq!(receive(&link), vec![8; 1_200]);
        drop(link);
        server.join().unwrap();
    }

    #[test]
    fn relay_link_rejects_invalid_output_and_oversized_input() {
        let listener = TcpListener::bind(loopback()).unwrap();
        let address = listener.local_addr().unwrap();
        let channel = [46; 32];
        let (oversize_sent, oversize_received) = std_mpsc::channel();
        let server = thread::spawn(move || {
            let (mut stream, _) = listener.accept().unwrap();
            configure(&stream);
            raw_server_handshake(&mut stream, channel);
            assert_eq!(raw_frame_read(&mut stream), b"sentinel");
            stream.write_all(&65_536_u32.to_be_bytes()).unwrap();
            oversize_sent.send(()).unwrap();
            let mut byte = [0_u8; 1];
            assert_eq!(stream.read(&mut byte).unwrap(), 0);
        });

        let link =
            RelayLink::connect("validation", address, channel, [2; 32], TEST_TIMEOUT).unwrap();
        assert_eq!(
            link.send(Some([3; 32]), b"wrong peer").unwrap_err().kind(),
            io::ErrorKind::NotConnected
        );
        assert_eq!(
            link.send(Some([2; 32]), &vec![0; 65_536])
                .unwrap_err()
                .kind(),
            io::ErrorKind::InvalidInput
        );
        link.send(Some([2; 32]), b"sentinel").unwrap();
        oversize_received.recv_timeout(TEST_TIMEOUT).unwrap();
        let deadline = Instant::now() + TEST_TIMEOUT;
        while link.alive.load(Ordering::Acquire) {
            assert!(
                Instant::now() < deadline,
                "oversized input did not close link"
            );
            thread::yield_now();
        }
        assert_eq!(
            link.send(Some([2; 32]), b"after oversize")
                .unwrap_err()
                .kind(),
            io::ErrorKind::BrokenPipe
        );
        assert!(link.try_receive().unwrap().is_none());
        drop(link);
        server.join().unwrap();
    }

    #[test]
    fn relay_link_backpressures_at_exact_frame_capacity() {
        let listener = TcpListener::bind(loopback()).unwrap();
        let address = listener.local_addr().unwrap();
        let channel = [47; 32];
        let server = thread::spawn(move || {
            let (mut stream, _) = listener.accept().unwrap();
            configure(&stream);
            raw_server_handshake(&mut stream, channel);
            for _ in 0..=256 {
                raw_frame_write(&mut stream, &[]);
            }
            let mut byte = [0_u8; 1];
            assert_eq!(stream.read(&mut byte).unwrap(), 0);
        });

        let link =
            RelayLink::connect("frame-cap", address, channel, [2; 32], TEST_TIMEOUT).unwrap();
        wait_for_queue_len(&link, 256);
        for _ in 0..=256 {
            assert_eq!(receive(&link), Vec::<u8>::new());
        }
        drop(link);
        server.join().unwrap();
    }

    #[test]
    fn relay_link_backpressures_at_exact_byte_capacity() {
        let listener = TcpListener::bind(loopback()).unwrap();
        let address = listener.local_addr().unwrap();
        let channel = [48; 32];
        let server = thread::spawn(move || {
            let (mut stream, _) = listener.accept().unwrap();
            configure(&stream);
            raw_server_handshake(&mut stream, channel);
            for value in 0_u8..65 {
                raw_frame_write(&mut stream, &vec![value; 65_535]);
            }
            let mut byte = [0_u8; 1];
            assert_eq!(stream.read(&mut byte).unwrap(), 0);
        });

        let link = RelayLink::connect("byte-cap", address, channel, [2; 32], TEST_TIMEOUT).unwrap();
        wait_for_queue_len(&link, 64);
        for value in 0_u8..65 {
            assert_eq!(receive(&link), vec![value; 65_535]);
        }
        drop(link);
        server.join().unwrap();
    }

    #[test]
    fn relay_send_returns_when_bounded_queue_accepts() {
        let runtime = relay_runtime().unwrap();
        let (outgoing, mut receiver) = mpsc::channel(1);
        let outgoing_bytes = Arc::new(Semaphore::new(64));
        let alive = Arc::new(AtomicBool::new(true));
        let stalled_writer = runtime.spawn(std::future::pending::<()>());
        let link = Arc::new(detached_test_link(
            outgoing,
            Arc::clone(&outgoing_bytes),
            alive,
            stalled_writer.abort_handle(),
        ));
        let sender = Arc::clone(&link);
        let (completed, completion) = std_mpsc::sync_channel(1);
        let send_task = thread::spawn(move || {
            completed
                .send(sender.send(Some([2; 32]), b"queued"))
                .unwrap();
        });
        completion
            .recv_timeout(Duration::from_secs(1))
            .expect("relay send blocked on writer progress")
            .unwrap();
        send_task.join().unwrap();

        assert_eq!(
            link.send(Some([2; 32]), b"queue-full").unwrap_err().kind(),
            io::ErrorKind::WouldBlock
        );
        let request = receiver.blocking_recv().unwrap();
        assert_eq!(&request.encoded[4..], b"queued");
        drop(request);
        assert_eq!(outgoing_bytes.available_permits(), 64);
    }

    #[test]
    fn asynchronous_writer_failure_marks_link_dead() {
        let runtime = relay_runtime().unwrap();
        let (writer, reader) = tokio::io::duplex(1);
        drop(reader);
        let (outgoing, receiver) = mpsc::channel(2);
        let outgoing_bytes = Arc::new(Semaphore::new(64));
        let alive = Arc::new(AtomicBool::new(true));
        let writer_alive = Arc::clone(&alive);
        let writer_task = runtime.spawn(async move {
            let mut writer = writer;
            let mut receiver = receiver;
            let result = write_requests(&mut writer, &mut receiver).await;
            writer_alive.store(false, Ordering::Release);
            result
        });
        let link = detached_test_link(
            outgoing,
            Arc::clone(&outgoing_bytes),
            Arc::clone(&alive),
            writer_task.abort_handle(),
        );

        link.send(Some([2; 32]), b"accepted-before-failure")
            .unwrap();
        let deadline = Instant::now() + TEST_TIMEOUT;
        while alive.load(Ordering::Acquire) {
            assert!(Instant::now() < deadline, "writer failure was not observed");
            thread::yield_now();
        }
        assert_eq!(
            link.send(Some([2; 32]), b"after-failure")
                .unwrap_err()
                .kind(),
            io::ErrorKind::BrokenPipe
        );
        assert_eq!(
            runtime.block_on(writer_task).unwrap().unwrap_err().kind(),
            io::ErrorKind::BrokenPipe
        );
        assert_eq!(outgoing_bytes.available_permits(), 64);
    }

    #[test]
    fn asynchronous_writer_deadline_releases_queued_bytes() {
        let runtime = relay_runtime().unwrap();
        let (writer, _reader) = tokio::io::duplex(1);
        let (outgoing, receiver) = mpsc::channel(1);
        let task = runtime.spawn(async move {
            let mut writer = writer;
            let mut receiver = receiver;
            write_requests(&mut writer, &mut receiver).await
        });
        let permits = Arc::new(Semaphore::new(64));
        let permit = Arc::clone(&permits).try_acquire_many_owned(8).unwrap();
        outgoing
            .blocking_send(WriteRequest {
                encoded: vec![10; 8],
                deadline: Instant::now() + Duration::from_millis(25),
                _byte_permit: permit,
            })
            .unwrap();
        assert_eq!(
            runtime.block_on(task).unwrap().unwrap_err().kind(),
            io::ErrorKind::TimedOut
        );
        assert_eq!(permits.available_permits(), 64);
    }

    #[test]
    fn relay_header_and_body_reads_have_enforced_deadlines() {
        let runtime = relay_runtime().unwrap();
        runtime.block_on(async {
            let (mut header_writer, mut header_reader) = tokio::io::duplex(8);
            tokio::io::AsyncWriteExt::write_all(&mut header_writer, &[0_u8])
                .await
                .unwrap();
            assert_eq!(
                read_length_with_deadline(&mut header_reader, Duration::from_millis(20))
                    .await
                    .unwrap_err()
                    .kind(),
                io::ErrorKind::TimedOut
            );

            let (mut body_writer, mut body_reader) = tokio::io::duplex(8);
            tokio::io::AsyncWriteExt::write_all(&mut body_writer, &[1_u8; 2])
                .await
                .unwrap();
            assert_eq!(
                read_body_with_deadline(&mut body_reader, 4, Duration::from_millis(20))
                    .await
                    .unwrap_err()
                    .kind(),
                io::ErrorKind::TimedOut
            );
        });
    }

    #[test]
    fn relay_body_deadline_preserves_low_bitrate_full_frames() {
        assert_eq!(READ_HEADER_DEADLINE, Duration::from_secs(120));
        assert_eq!(READ_BODY_BASE_DEADLINE, Duration::from_secs(30));
        assert_eq!(MIN_READ_BITS_PER_SECOND, 1_024);
        assert_eq!(
            body_read_deadline(MAX_RELAY_FRAME),
            Duration::from_secs(542)
        );
        // At the requirements profile's 3 kbps, even discounting half the
        // throughput leaves a complete maximum frame comfortably inside 542s.
        let half_rate_seconds = (u64::try_from(MAX_RELAY_FRAME).unwrap() * 8).div_ceil(1_500);
        assert!(Duration::from_secs(half_rate_seconds) < body_read_deadline(MAX_RELAY_FRAME));
    }

    #[test]
    fn relay_resource_limits_are_explicit() {
        assert_eq!(MAX_RELAY_FRAME, 65_535);
        assert_eq!(MAX_QUEUED_FRAMES, 256);
        assert_eq!(MAX_QUEUED_BYTES, 4 * 1024 * 1024);
        assert_eq!(MAX_PENDING_JOINS, 256);
        assert_eq!(MAX_WAITING_CHANNELS, 4_096);
        assert_eq!(MAX_ACTIVE_PAIRS, 256);
        assert_eq!(MAX_CONNECTIONS_PER_SOURCE, 64);
        assert_eq!(ACTIVE_PAIR_IDLE_TIMEOUT, Duration::from_secs(120));
    }
}
