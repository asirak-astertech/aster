//! Optional relay fallback that forwards length-delimited opaque ciphertext.

use aster_mesh::link::{Link, LinkCharacteristics, ReceivedFrame};
use aster_mesh::model::NodeId;
use std::collections::BTreeMap;
use std::fmt;
use std::io::{self, Read, Write};
use std::net::{Shutdown, SocketAddr, TcpListener, TcpStream};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::mpsc as std_mpsc;
use std::sync::{Arc, Mutex, OnceLock};
use std::time::{Duration, Instant};
use tokio::io::{AsyncReadExt, AsyncWrite, AsyncWriteExt, copy_bidirectional};
use tokio::net::{TcpListener as TokioTcpListener, TcpStream as TokioTcpStream};
use tokio::runtime::{Builder as RuntimeBuilder, Runtime};
use tokio::sync::{OwnedSemaphorePermit, Semaphore, mpsc};
use tokio::task::{AbortHandle, JoinSet};
use tokio::time::{Instant as TokioInstant, timeout as tokio_timeout, timeout_at};

const JOIN_VERSION: u8 = 1;
const READY: u8 = 0xa5;
const MAX_RELAY_FRAME: usize = u16::MAX as usize;
const MAX_WAITING_CHANNELS: usize = 4_096;
const MAX_PENDING_JOINS: usize = 256;
const MAX_ACTIVE_PAIRS: usize = 256;
const MAX_QUEUED_FRAMES: usize = 256;
const MAX_QUEUED_BYTES: usize = 4 * 1024 * 1024;
const JOIN_TIMEOUT: Duration = Duration::from_secs(10);
const WRITE_DEADLINE: Duration = Duration::from_secs(10 * 60);
const WAITING_TTL: Duration = Duration::from_secs(120);
const WAITING_SWEEP_INTERVAL: Duration = Duration::from_secs(5);
const RELAY_RUNTIME_THREADS: usize = 1;

static RELAY_RUNTIME: OnceLock<Result<Runtime, String>> = OnceLock::new();

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
}

impl CipherRelayServer {
    /// Binds the relay listener.
    ///
    /// # Errors
    ///
    /// Returns an operating-system bind error.
    pub fn bind(address: SocketAddr) -> io::Result<Self> {
        Ok(Self {
            listener: TcpListener::bind(address)?,
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
        runtime.block_on(serve_relay(listener, pair_limit))
    }
}

async fn serve_relay(listener: TokioTcpListener, pair_limit: usize) -> io::Result<()> {
    let (joined_tx, mut joined_rx) = mpsc::channel(MAX_PENDING_JOINS);
    let accept_task = relay_runtime()?.spawn(accept_joins(listener, joined_tx));
    let mut waiting: BTreeMap<[u8; 32], (TokioTcpStream, Instant)> = BTreeMap::new();
    let active = Arc::new(Semaphore::new(MAX_ACTIVE_PAIRS));
    let mut paired = 0_usize;
    let result = loop {
        let now = Instant::now();
        waiting
            .retain(|_, (_, registered)| now.saturating_duration_since(*registered) <= WAITING_TTL);
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
        let (channel, mut stream, now) = match joined {
            Ok(joined) => joined,
            Err(error) => break Err(error),
        };
        if let Some((mut first, _)) = waiting.remove(&channel) {
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
                let _ = copy_bidirectional(&mut first, &mut stream).await;
            });
            paired += 1;
            if pair_limit != 0 && paired >= pair_limit {
                break Ok(());
            }
        } else if waiting.len() < MAX_WAITING_CHANNELS {
            waiting.insert(channel, (stream, now));
        }
    };
    accept_task.abort();
    let _ = accept_task.await;
    result
}

type Joined = io::Result<([u8; 32], TokioTcpStream, Instant)>;

async fn accept_joins(listener: TokioTcpListener, joined: mpsc::Sender<Joined>) {
    let pending = Arc::new(Semaphore::new(MAX_PENDING_JOINS));
    let mut handshakes = JoinSet::new();
    loop {
        while handshakes.try_join_next().is_some() {}
        let Ok(permit) = Arc::clone(&pending).acquire_owned().await else {
            return;
        };
        let (stream, _) = match listener.accept().await {
            Ok(accepted) => accepted,
            Err(error) => {
                let _ = joined.send(Err(error)).await;
                return;
            }
        };
        let joined = joined.clone();
        handshakes.spawn(async move {
            let _permit = permit;
            if let Some(validated) = validate_join(stream).await {
                let _ = joined.send(Ok(validated)).await;
            }
        });
    }
}

async fn validate_join(mut stream: TokioTcpStream) -> Option<([u8; 32], TokioTcpStream, Instant)> {
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
    (channel != [0; 32]).then_some((channel, stream, Instant::now()))
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
    completion: std_mpsc::SyncSender<io::Result<()>>,
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

async fn read_length(reader: &mut tokio::net::tcp::OwnedReadHalf) -> io::Result<usize> {
    let mut bytes = [0_u8; 4];
    reader.read_exact(&mut bytes).await?;
    usize::try_from(u32::from_be_bytes(bytes))
        .map_err(|_| io::Error::new(io::ErrorKind::InvalidData, "frame length overflow"))
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
        let mut frame = vec![0_u8; length];
        if reader.read_exact(&mut frame).await.is_err() {
            break;
        }
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
    write_requests(&mut writer, &mut outgoing).await;
    alive.store(false, Ordering::Release);
    let _ = writer.shutdown().await;
    let _ = shutdown.shutdown(Shutdown::Both);
}

async fn write_requests<W>(writer: &mut W, outgoing: &mut mpsc::Receiver<WriteRequest>)
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
        let failed = result.is_err();
        let _ = request.completion.send(result);
        if failed {
            break;
        }
    }
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
        let (completion, completed) = std_mpsc::sync_channel(1);
        self.outgoing
            .try_send(WriteRequest {
                encoded,
                deadline,
                completion,
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
            })?;
        completed.recv().map_err(|_| {
            io::Error::new(
                io::ErrorKind::BrokenPipe,
                "relay disconnected before write completed",
            )
        })?
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
        CipherRelayServer, MAX_ACTIVE_PAIRS, MAX_PENDING_JOINS, MAX_QUEUED_BYTES,
        MAX_QUEUED_FRAMES, MAX_RELAY_FRAME, MAX_WAITING_CHANNELS, RelayLink, WriteRequest,
        relay_runtime, write_requests,
    };
    use aster_mesh::link::Link;
    use std::io::{self, Read, Write};
    use std::net::{IpAddr, Ipv4Addr, Shutdown, SocketAddr, TcpListener, TcpStream};
    use std::sync::atomic::Ordering;
    use std::sync::{Arc, mpsc as std_mpsc};
    use std::thread;
    use std::time::{Duration, Instant};
    use tokio::io::AsyncReadExt;
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
        let server = CipherRelayServer::bind(loopback()).unwrap();
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
    fn relay_server_admits_256_pairs_on_one_runtime_worker() {
        let (address, server) = start_server(256);
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
    fn write_acknowledgement_follows_full_write_and_deadline() {
        let runtime = relay_runtime().unwrap();
        let (writer, mut reader) = tokio::io::duplex(1);
        let (outgoing, receiver) = mpsc::channel(1);
        let task = runtime.spawn(async move {
            let mut writer = writer;
            let mut receiver = receiver;
            write_requests(&mut writer, &mut receiver).await;
        });
        let permits = Arc::new(Semaphore::new(64));
        let permit = permits.try_acquire_many_owned(8).unwrap();
        let (completion, completed) = std_mpsc::sync_channel(1);
        outgoing
            .blocking_send(WriteRequest {
                encoded: vec![9; 8],
                deadline: Instant::now() + TEST_TIMEOUT,
                completion,
                _byte_permit: permit,
            })
            .unwrap();
        assert!(matches!(
            completed.recv_timeout(Duration::from_millis(25)),
            Err(std_mpsc::RecvTimeoutError::Timeout)
        ));
        let mut bytes = [0_u8; 8];
        runtime.block_on(reader.read_exact(&mut bytes)).unwrap();
        assert_eq!(bytes, [9; 8]);
        completed.recv_timeout(TEST_TIMEOUT).unwrap().unwrap();
        drop(outgoing);
        runtime.block_on(task).unwrap();

        let (writer, _reader) = tokio::io::duplex(1);
        let (outgoing, receiver) = mpsc::channel(1);
        let task = runtime.spawn(async move {
            let mut writer = writer;
            let mut receiver = receiver;
            write_requests(&mut writer, &mut receiver).await;
        });
        let permit = Arc::new(Semaphore::new(64))
            .try_acquire_many_owned(8)
            .unwrap();
        let (completion, completed) = std_mpsc::sync_channel(1);
        outgoing
            .blocking_send(WriteRequest {
                encoded: vec![10; 8],
                deadline: Instant::now() + Duration::from_millis(25),
                completion,
                _byte_permit: permit,
            })
            .unwrap();
        assert_eq!(
            completed
                .recv_timeout(TEST_TIMEOUT)
                .unwrap()
                .unwrap_err()
                .kind(),
            io::ErrorKind::TimedOut
        );
        runtime.block_on(task).unwrap();

        let (writer, reader) = tokio::io::duplex(1);
        drop(reader);
        let (outgoing, receiver) = mpsc::channel(2);
        let task = runtime.spawn(async move {
            let mut writer = writer;
            let mut receiver = receiver;
            write_requests(&mut writer, &mut receiver).await;
        });
        let permits = Arc::new(Semaphore::new(64));
        let first_permit = Arc::clone(&permits).try_acquire_many_owned(8).unwrap();
        let second_permit = permits.try_acquire_many_owned(8).unwrap();
        let (first_completion, first_completed) = std_mpsc::sync_channel(1);
        let (second_completion, second_completed) = std_mpsc::sync_channel(1);
        for (completion, permit) in [
            (first_completion, first_permit),
            (second_completion, second_permit),
        ] {
            outgoing
                .blocking_send(WriteRequest {
                    encoded: vec![11; 8],
                    deadline: Instant::now() + TEST_TIMEOUT,
                    completion,
                    _byte_permit: permit,
                })
                .unwrap();
        }
        assert_eq!(
            first_completed
                .recv_timeout(TEST_TIMEOUT)
                .unwrap()
                .unwrap_err()
                .kind(),
            io::ErrorKind::BrokenPipe
        );
        assert!(matches!(
            second_completed.recv_timeout(TEST_TIMEOUT),
            Err(std_mpsc::RecvTimeoutError::Disconnected)
        ));
        runtime.block_on(task).unwrap();
    }

    #[test]
    fn relay_resource_limits_are_explicit() {
        assert_eq!(MAX_RELAY_FRAME, 65_535);
        assert_eq!(MAX_QUEUED_FRAMES, 256);
        assert_eq!(MAX_QUEUED_BYTES, 4 * 1024 * 1024);
        assert_eq!(MAX_PENDING_JOINS, 256);
        assert_eq!(MAX_WAITING_CHANNELS, 4_096);
        assert_eq!(MAX_ACTIVE_PAIRS, 256);
    }
}
