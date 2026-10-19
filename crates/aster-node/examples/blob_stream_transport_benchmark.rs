//! Device benchmark for the complete semantic-v9 stream control/data exchange.

use aster_iroh::{CarrierSecurityProfile, Endpoint, EndpointConfig, ExpectedPeer, SecretKey};
use aster_mesh::{
    BlobMetadata, BlobPublicationStreamId, BlobStreamFinalCommitment, BlobStreamOpen, Priority,
    ProvisioningAccess, ProvisioningBundle, ReferenceEnvelopeSealer, ReferenceProvisioner, Scope,
    Topic, VerifiedBlobStreamOpen, VersionVector,
};
use aster_node::stream_validation::{self, StreamValidationReport};
use aster_node::{application::blob_stream::publish_blob_stream, stream_pipeline::PipelineLimits};
use aster_redb_store::Store;
use std::{
    collections::BTreeSet,
    error::Error,
    io::{Read, Write as _},
    net::SocketAddr,
    path::{Path, PathBuf},
    sync::Arc,
    time::{Duration, Instant},
};

type AnyError = Box<dyn Error + Send + Sync>;

fn config(bind: SocketAddr) -> EndpointConfig {
    EndpointConfig {
        bind,
        connect_timeout: Duration::from_secs(30),
        exchange_timeout: Duration::from_secs(60),
        max_exchange_bytes: 2 * 1024 * 1024,
    }
}

fn print_report(role: &str, report: &StreamValidationReport, path: &aster_iroh::PathWitness) {
    let digest = report
        .digest
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect::<String>();
    println!(
        "ASTER_STREAM_NETWORK {{\"role\":\"{role}\",\"bytes\":{},\"elapsed_ns\":{},\"mib_s\":{:.3},\"checkpoints\":{},\"digest\":\"{digest}\",\"path\":\"{:?}\"}}",
        report.bytes, report.elapsed_ns, report.mib_per_second, report.checkpoints, path.selected,
    );
}

struct TempPack(PathBuf);

impl TempPack {
    fn new(role: &str) -> std::io::Result<Self> {
        let mut random = [0; 8];
        getrandom::fill(&mut random).map_err(std::io::Error::other)?;
        let root = std::env::temp_dir().join(format!(
            "aster-stream-pack-{role}-{}-{}",
            std::process::id(),
            u64::from_be_bytes(random)
        ));
        std::fs::create_dir(&root)?;
        Ok(Self(root))
    }
}

impl Drop for TempPack {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

struct PatternReader {
    offset: u64,
    total: u64,
}

impl Read for PatternReader {
    fn read(&mut self, output: &mut [u8]) -> std::io::Result<usize> {
        let len = usize::try_from((self.total - self.offset).min(output.len() as u64))
            .expect("bounded read length");
        for (relative, byte) in output[..len].iter_mut().enumerate() {
            *byte = ((self.offset + relative as u64) % 251) as u8;
        }
        self.offset += len as u64;
        Ok(len)
    }
}

fn blob_fixture(
    fixture_path: &Path,
    signed_open_path: &Path,
    total_len: u64,
) -> Result<(Arc<ReferenceEnvelopeSealer>, VerifiedBlobStreamOpen), AnyError> {
    let provider = Arc::new(ReferenceEnvelopeSealer::open(
        ProvisioningBundle::from_bytes(&std::fs::read(fixture_path)?)?,
    )?);
    let verified = provider.verify_blob_stream_open(&std::fs::read(signed_open_path)?)?;
    if verified.open().total_len() != total_len {
        return Err("signed Blob open length differs from requested validation length".into());
    }
    Ok((provider, verified))
}

fn create_signed_blob_open(
    fixture_path: &Path,
    signed_open_path: &Path,
    total_len: u64,
) -> Result<(), AnyError> {
    use std::os::unix::fs::OpenOptionsExt as _;

    let topic = Topic::new("imagery")?;
    let scope = Scope::new("mission/validation")?;
    let provider = ReferenceEnvelopeSealer::open(ProvisioningBundle::from_bytes(&std::fs::read(
        fixture_path,
    )?)?)?;
    let open = BlobStreamOpen::new(
        BlobPublicationStreamId::from_bytes([0x12; 32]).expect("stream ID"),
        provider.identity(),
        b"device-network-pipeline".to_vec(),
        provider.mission_authority_id(),
        1,
        VersionVector::default(),
        topic,
        scope.clone(),
        BlobMetadata::new(Some("application/octet-stream".into()), Vec::new()).expect("metadata"),
        Priority::Immediate,
        None,
        None,
        total_len,
        1,
        1,
        provider
            .blob_stream_authorization_digest(&scope, 1)
            .ok_or("missing Blob stream authorization")?,
        [0x52; 32],
    )?;
    let signed = provider.seal_blob_stream_open(&open)?;
    let mut file = std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o644)
        .open(signed_open_path)?;
    file.write_all(&signed)?;
    file.sync_all()?;
    println!(
        "ASTER_BLOB_OPEN {{\"path\":\"{}\",\"bytes\":{},\"digest\":\"{}\"}}",
        signed_open_path.display(),
        signed.len(),
        open.digest()
            .iter()
            .map(|byte| format!("{byte:02x}"))
            .collect::<String>()
    );
    Ok(())
}

fn initialize_blob_fixture(path: &Path) -> Result<(), AnyError> {
    use std::os::unix::fs::OpenOptionsExt as _;

    let topic = Topic::new("imagery")?;
    let scope = Scope::new("mission/validation")?;
    let access = ProvisioningAccess::member(scope, vec![1], vec![topic])?;
    let mut provisioner = ReferenceProvisioner::from_seed([0x84; 32])?;
    let bundle = provisioner.issue_control_authority(1, &[access])?;
    let encoded = bundle.to_bytes()?;
    let mut file = std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(path)?;
    file.write_all(&encoded)?;
    file.sync_all()?;
    println!(
        "ASTER_BLOB_FIXTURE {{\"path\":\"{}\",\"bytes\":{}}}",
        path.display(),
        encoded.len()
    );
    Ok(())
}

fn pack_limits() -> PipelineLimits {
    PipelineLimits::new(2, 4, 5 * 1024 * 1024, 4).expect("pipeline limits")
}

fn print_pack_report(
    role: &str,
    report: &stream_validation::BlobNetworkReport,
    elapsed: Duration,
    path: &aster_iroh::PathWitness,
) {
    let roots = [report.roots.0, report.roots.1]
        .into_iter()
        .map(|root| {
            root.into_iter()
                .map(|byte| format!("{byte:02x}"))
                .collect::<String>()
        })
        .collect::<Vec<_>>();
    let mib_s = report.attempt_bytes as f64 / (1024.0 * 1024.0) / elapsed.as_secs_f64();
    let completed = report
        .pipeline
        .as_ref()
        .map_or(0, |value| value.completed_items());
    println!(
        "ASTER_BLOB_NETWORK {{\"role\":\"{role}\",\"wire_bytes\":{},\"resumed_from\":{},\"attempt_bytes\":{},\"elapsed_ns\":{},\"mib_s\":{mib_s:.3},\"checkpoints\":{},\"segments\":{completed},\"plaintext_root\":\"{}\",\"ciphertext_root\":\"{}\",\"path\":\"{:?}\"}}",
        report.wire_bytes,
        report.resumed_from,
        report.attempt_bytes,
        elapsed.as_nanos(),
        report.checkpoints,
        roots[0],
        roots[1],
        path.selected,
    );
}

async fn pack_receive(
    fixture_path: PathBuf,
    signed_open_path: PathBuf,
    bind: SocketAddr,
    plaintext_len: u64,
) -> Result<(), AnyError> {
    let root = TempPack::new("receive")?;
    let (provider, verified) = blob_fixture(&fixture_path, &signed_open_path, plaintext_len)?;
    let open = verified.open();
    let wire_len =
        stream_validation::expected_pack_wire_len(plaintext_len).map_err(std::io::Error::other)?;
    let endpoint = Endpoint::bind_with_security_profile(
        SecretKey::from_bytes(&[0x71; 32]),
        config(bind),
        CarrierSecurityProfile::IrohQuicV1,
    )
    .await?;
    println!(
        "ASTER_STREAM_LISTEN {{\"id\":\"{}\",\"bind\":\"{}\"}}",
        endpoint.id(),
        bind
    );
    let connection = endpoint
        .accept(&BTreeSet::from([
            SecretKey::from_bytes(&[0x72; 32]).public()
        ]))
        .await?;
    let path = connection.path_witness();
    let started = Instant::now();
    let report = stream_validation::receive_completed_pack(
        connection.clone(),
        open,
        provider.blob_stream_segment_opener(&verified)?,
        &root.0,
        wire_len,
        pack_limits(),
    )
    .await
    .map_err(std::io::Error::other)?;
    print_pack_report("receive", &report, started.elapsed(), &path);
    connection.close();
    endpoint.close().await;
    Ok(())
}

async fn pack_store_receive(
    state_root: PathBuf,
    fixture_path: PathBuf,
    signed_open_path: PathBuf,
    bind: SocketAddr,
    plaintext_len: u64,
) -> Result<(), AnyError> {
    std::fs::create_dir_all(&state_root)?;
    let pack_root = state_root.join("pack");
    std::fs::create_dir_all(&pack_root)?;
    let (provider, verified) = blob_fixture(&fixture_path, &signed_open_path, plaintext_len)?;
    let wire_len =
        stream_validation::expected_pack_wire_len(plaintext_len).map_err(std::io::Error::other)?;
    let store = Arc::new(Store::open_for_mission(
        state_root.join("state.redb"),
        provider.mission_authority_id(),
    )?);
    let policy = store.control_policy_snapshot()?;
    let verifier = {
        let provider = Arc::clone(&provider);
        Arc::new(move |open: &VerifiedBlobStreamOpen, bytes: &[u8]| {
            provider
                .verify_blob_stream_commitment(open, bytes)
                .map_err(|error| error.to_string())
        }) as stream_validation::BlobCommitmentVerifier
    };
    let session = stream_validation::BlobReceiveStoreSession::new(
        Arc::clone(&store),
        policy,
        verified.clone(),
        verified.open().publisher(),
        verifier,
    )
    .map_err(std::io::Error::other)?;
    let endpoint = Endpoint::bind_with_security_profile(
        SecretKey::from_bytes(&[0x71; 32]),
        config(bind),
        CarrierSecurityProfile::IrohQuicV1,
    )
    .await?;
    println!(
        "ASTER_STREAM_LISTEN {{\"id\":\"{}\",\"bind\":\"{}\",\"state_root\":\"{}\"}}",
        endpoint.id(),
        bind,
        state_root.display()
    );
    std::io::stdout().flush()?;
    let connection = endpoint
        .accept(&BTreeSet::from([
            SecretKey::from_bytes(&[0x72; 32]).public()
        ]))
        .await?;
    let path = connection.path_witness();
    let started = Instant::now();
    let report = stream_validation::receive_completed_pack_with_store(
        connection.clone(),
        session,
        provider.blob_stream_segment_opener(&verified)?,
        &pack_root,
        wire_len,
        pack_limits(),
    )
    .await
    .map_err(std::io::Error::other)?;
    print_pack_report("store-receive", &report, started.elapsed(), &path);
    let publications = store.blob_stream_publications_with_policy(&policy)?;
    println!(
        "ASTER_BLOB_STORE {{\"publications\":{},\"state_root\":\"{}\"}}",
        publications.len(),
        state_root.display()
    );
    connection.close();
    endpoint.close().await;
    Ok(())
}

async fn pack_send(
    fixture_path: PathBuf,
    signed_open_path: PathBuf,
    bind: SocketAddr,
    peer: SocketAddr,
    plaintext_len: u64,
) -> Result<(), AnyError> {
    let root = TempPack::new("send")?;
    let (provider, verified) = blob_fixture(&fixture_path, &signed_open_path, plaintext_len)?;
    let open = verified.open();
    let published = publish_blob_stream(
        PatternReader {
            offset: 0,
            total: plaintext_len,
        },
        open,
        provider.blob_stream_segment_sealer(&verified)?,
        &root.0,
        pack_limits(),
    )
    .await?;
    let roots = (published.plaintext_root, published.ciphertext_root);
    let commitment =
        BlobStreamFinalCommitment::new(&verified, roots.0, roots.1, published.segment_count, None)?;
    let signed_commitment = provider.seal_blob_stream_commitment(&commitment)?;
    println!(
        "ASTER_BLOB_PACK_READY {{\"plaintext_bytes\":{plaintext_len},\"segments\":{}}}",
        published.segment_count
    );
    std::io::stdout().flush()?;
    let endpoint = Endpoint::bind_with_security_profile(
        SecretKey::from_bytes(&[0x72; 32]),
        config(bind),
        CarrierSecurityProfile::IrohQuicV1,
    )
    .await?;
    let connection = endpoint
        .connect(ExpectedPeer {
            id: SecretKey::from_bytes(&[0x71; 32]).public(),
            address: peer,
        })
        .await?;
    let path = connection.path_witness();
    let started = Instant::now();
    let report = stream_validation::send_completed_pack(
        connection.clone(),
        open,
        &root.0,
        roots,
        signed_commitment,
    )
    .await
    .map_err(std::io::Error::other)?;
    print_pack_report("send", &report, started.elapsed(), &path);
    connection.close();
    endpoint.close().await;
    Ok(())
}

async fn receive(bind: SocketAddr, bytes: u64) -> Result<(), AnyError> {
    let client_key = SecretKey::from_bytes(&[0x72; 32]);
    let endpoint = Endpoint::bind_with_security_profile(
        SecretKey::from_bytes(&[0x71; 32]),
        config(bind),
        CarrierSecurityProfile::IrohQuicV1,
    )
    .await?;
    println!(
        "ASTER_STREAM_LISTEN {{\"id\":\"{}\",\"bind\":\"{}\"}}",
        endpoint.id(),
        bind
    );
    let connection = endpoint
        .accept(&BTreeSet::from([client_key.public()]))
        .await?;
    let path = connection.path_witness();
    let report = stream_validation::receive(connection.clone(), bytes)
        .await
        .map_err(std::io::Error::other)?;
    print_report("receive", &report, &path);
    connection.close();
    endpoint.close().await;
    Ok(())
}

async fn send(bind: SocketAddr, peer: SocketAddr, bytes: u64) -> Result<(), AnyError> {
    let server_key = SecretKey::from_bytes(&[0x71; 32]);
    let endpoint = Endpoint::bind_with_security_profile(
        SecretKey::from_bytes(&[0x72; 32]),
        config(bind),
        CarrierSecurityProfile::IrohQuicV1,
    )
    .await?;
    let connection = endpoint
        .connect(ExpectedPeer {
            id: server_key.public(),
            address: peer,
        })
        .await?;
    let path = connection.path_witness();
    let report = stream_validation::send(connection.clone(), bytes)
        .await
        .map_err(std::io::Error::other)?;
    print_report("send", &report, &path);
    connection.close();
    endpoint.close().await;
    Ok(())
}

async fn loopback(bytes: u64) -> Result<(), AnyError> {
    let server_key = SecretKey::from_bytes(&[0x71; 32]);
    let client_key = SecretKey::from_bytes(&[0x72; 32]);
    let server = Endpoint::bind_with_security_profile(
        server_key.clone(),
        config("127.0.0.1:0".parse()?),
        CarrierSecurityProfile::IrohQuicV1,
    )
    .await?;
    let client = Endpoint::bind_with_security_profile(
        client_key.clone(),
        config("127.0.0.1:0".parse()?),
        CarrierSecurityProfile::IrohQuicV1,
    )
    .await?;
    let address = server
        .bound_sockets()
        .into_iter()
        .find(SocketAddr::is_ipv4)
        .ok_or("server has no IPv4 socket")?;
    let server_task = tokio::spawn({
        let server = server.clone();
        async move {
            let connection = server
                .accept(&BTreeSet::from([client_key.public()]))
                .await?;
            let path = connection.path_witness();
            let report = stream_validation::receive(connection, bytes)
                .await
                .map_err(std::io::Error::other)?;
            Ok::<_, AnyError>((report, path))
        }
    });
    let connection = client
        .connect(ExpectedPeer {
            id: server_key.public(),
            address,
        })
        .await?;
    let send_path = connection.path_witness();
    let sent = stream_validation::send(connection, bytes)
        .await
        .map_err(std::io::Error::other)?;
    let (received, receive_path) = server_task.await??;
    if sent.digest != received.digest {
        return Err("loopback digests differed".into());
    }
    print_report("send", &sent, &send_path);
    print_report("receive", &received, &receive_path);
    client.close().await;
    server.close().await;
    Ok(())
}

#[tokio::main(flavor = "multi_thread")]
async fn main() -> Result<(), AnyError> {
    let args = std::env::args().collect::<Vec<_>>();
    match args.as_slice() {
        [_, role, fixture] if role == "fixture-init" => {
            initialize_blob_fixture(Path::new(fixture))
        }
        [_, role, fixture, signed_open, bytes] if role == "open-init" => create_signed_blob_open(
            Path::new(fixture),
            Path::new(signed_open),
            bytes.parse()?,
        ),
        [_, role, bytes] if role == "loopback" => loopback(bytes.parse()?).await,
        [_, role, bind, bytes] if role == "receive" => {
            receive(bind.parse()?, bytes.parse()?).await
        }
        [_, role, bind, peer, bytes] if role == "send" => {
            send(bind.parse()?, peer.parse()?, bytes.parse()?).await
        }
        [_, role, fixture, signed_open, bind, bytes] if role == "pack-receive" => {
            pack_receive(
                PathBuf::from(fixture),
                PathBuf::from(signed_open),
                bind.parse()?,
                bytes.parse()?,
            )
            .await
        }
        [_, role, root, fixture, signed_open, bind, bytes]
            if role == "pack-store-receive" =>
        {
            pack_store_receive(
                PathBuf::from(root),
                PathBuf::from(fixture),
                PathBuf::from(signed_open),
                bind.parse()?,
                bytes.parse()?,
            )
            .await
        }
        [_, role, fixture, signed_open, bind, peer, bytes] if role == "pack-send" => {
            pack_send(
                PathBuf::from(fixture),
                PathBuf::from(signed_open),
                bind.parse()?,
                peer.parse()?,
                bytes.parse()?,
            )
            .await
        }
        _ => Err("usage: blob_stream_transport_benchmark fixture-init FIXTURE | open-init FIXTURE SIGNED_OPEN PLAINTEXT_BYTES | loopback BYTES | receive BIND BYTES | send BIND PEER BYTES | pack-receive FIXTURE SIGNED_OPEN BIND PLAINTEXT_BYTES | pack-store-receive STATE_ROOT FIXTURE SIGNED_OPEN BIND PLAINTEXT_BYTES | pack-send FIXTURE SIGNED_OPEN BIND PEER PLAINTEXT_BYTES".into()),
    }
}
