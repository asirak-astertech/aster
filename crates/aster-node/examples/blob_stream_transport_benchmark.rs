//! Device benchmark for the complete semantic-v9 stream control/data exchange.

use aster_iroh::{CarrierSecurityProfile, Endpoint, EndpointConfig, ExpectedPeer, SecretKey};
use aster_node::stream_validation::{self, StreamValidationReport};
use std::{collections::BTreeSet, error::Error, net::SocketAddr, time::Duration};

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
        [_, role, bytes] if role == "loopback" => loopback(bytes.parse()?).await,
        [_, role, bind, bytes] if role == "receive" => {
            receive(bind.parse()?, bytes.parse()?).await
        }
        [_, role, bind, peer, bytes] if role == "send" => {
            send(bind.parse()?, peer.parse()?, bytes.parse()?).await
        }
        _ => Err("usage: blob_stream_transport_benchmark loopback BYTES | receive BIND BYTES | send BIND PEER BYTES".into()),
    }
}
