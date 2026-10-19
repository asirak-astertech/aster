//! Instrumented end-to-end driver for the semantic-v9 stream protocol.
//!
//! This is intentionally not an application API. It exercises the same framing,
//! state machines, credit, settlement, and selected transport used by the runtime
//! while the Blob lifecycle adapter is composed around them.

use crate::{
    stream_transfer::{
        MAX_STREAM_CHECKPOINT_BATCH_BYTES, StreamAction, StreamClass, StreamDirection, StreamFrame,
        StreamOpenV1, StreamReceiverState, StreamResultCode, StreamSenderState,
    },
    stream_transport::{AttemptOpenRequest, IrohQuicV1Adapter, StreamTransportAdapter},
};
use aster_iroh::Connection;
use sha2::{Digest, Sha256};
use std::time::{Duration, Instant as StdInstant};
use tokio::time::Instant;

pub use crate::runtime::blob_stream::{
    BlobCommitmentVerifier, BlobNetworkReport, BlobReceiveStoreSession,
};
use aster_mesh::{BlobStreamOpen, BlobStreamSegmentOpener};
use std::path::Path;

pub fn completed_pack_wire_len(root: &Path, open: &BlobStreamOpen) -> Result<u64, String> {
    crate::runtime::blob_stream::completed_pack_wire_len(root, open)
}

pub fn expected_pack_wire_len(plaintext_len: u64) -> Result<u64, String> {
    crate::runtime::blob_stream::expected_pack_wire_len(plaintext_len)
}

pub async fn send_completed_pack(
    connection: Connection,
    open: &BlobStreamOpen,
    root: &Path,
    roots: ([u8; 32], [u8; 32]),
    semantic_commitment: Vec<u8>,
) -> Result<BlobNetworkReport, String> {
    crate::runtime::blob_stream::send_completed_pack(
        connection,
        open,
        root,
        roots,
        semantic_commitment,
    )
    .await
}

pub async fn receive_completed_pack(
    connection: Connection,
    open: &BlobStreamOpen,
    opener: BlobStreamSegmentOpener,
    root: &Path,
    wire_len: u64,
    limits: crate::stream_pipeline::PipelineLimits,
) -> Result<BlobNetworkReport, String> {
    crate::runtime::blob_stream::receive_completed_pack(
        connection, open, opener, root, wire_len, limits,
    )
    .await
}

pub async fn receive_completed_pack_with_store(
    connection: Connection,
    session: BlobReceiveStoreSession,
    opener: BlobStreamSegmentOpener,
    root: &Path,
    wire_len: u64,
    limits: crate::stream_pipeline::PipelineLimits,
) -> Result<BlobNetworkReport, String> {
    crate::runtime::blob_stream::receive_completed_pack_with_store(
        connection, session, opener, root, wire_len, limits,
    )
    .await
}

const EXTENT_BYTES: usize = 256 * 1024;
const ATTEMPT_TIMEOUT: Duration = Duration::from_secs(10 * 60);

#[derive(Clone, Debug, PartialEq)]
pub struct StreamValidationReport {
    pub bytes: u64,
    pub elapsed_ns: u128,
    pub mib_per_second: f64,
    pub checkpoints: u64,
    pub digest: [u8; 32],
}

fn payload(offset: u64, len: usize) -> Vec<u8> {
    let extent = offset / EXTENT_BYTES as u64;
    vec![(extent as u8).wrapping_mul(31).wrapping_add(0x5a); len]
}

fn rate(bytes: u64, elapsed_ns: u128) -> f64 {
    bytes as f64 / (1024.0 * 1024.0) / (elapsed_ns as f64 / 1_000_000_000.0)
}

fn attempt_bounds(bytes: u64) -> Result<(usize, usize), String> {
    let extents = bytes.div_ceil(EXTENT_BYTES as u64);
    let checkpoints = bytes.div_ceil(u64::from(MAX_STREAM_CHECKPOINT_BATCH_BYTES));
    let data = usize::try_from(bytes)
        .ok()
        .and_then(|value| {
            usize::try_from(extents)
                .ok()
                .and_then(|count| count.checked_mul(128))
                .and_then(|overhead| value.checked_add(overhead))
        })
        .and_then(|value| value.checked_add(4096))
        .ok_or("data stream bound overflow")?;
    let control = usize::try_from(checkpoints)
        .ok()
        .and_then(|count| count.checked_mul(192))
        .and_then(|value| value.checked_add(4096))
        .ok_or("control stream bound overflow")?;
    Ok((data, control))
}

fn encoded(frame: StreamFrame) -> Result<Vec<u8>, String> {
    frame
        .encode_for_context(9, 5)
        .map_err(|error| error.to_string())
}

fn decoded(bytes: &[u8]) -> Result<StreamFrame, String> {
    StreamFrame::decode_for_context(9, 5, bytes).map_err(|error| error.to_string())
}

pub async fn send(connection: Connection, bytes: u64) -> Result<StreamValidationReport, String> {
    if bytes == 0 {
        return Err("validation payload must be nonempty".into());
    }
    let (max_data_bytes, max_control_bytes) = attempt_bounds(bytes)?;
    let adapter = IrohQuicV1Adapter::new(connection);
    let attempt = adapter
        .open_attempt(AttemptOpenRequest {
            deadline: Instant::now() + ATTEMPT_TIMEOUT,
            max_data_bytes,
            max_control_bytes,
        })
        .await
        .map_err(|error| format!("open attempt: {error:?}"))?;
    let transfer_id = [0x31; 32];
    let attempt_nonce = [0x41; 32];
    let open = StreamOpenV1 {
        class: StreamClass::Blob,
        direction: StreamDirection::ToSessionResponder,
        session_transcript: [0x21; 32],
        exchange_id: 1,
        transfer_id,
        source_transfer_id: [0x32; 32],
        publication_id: [0x33; 32],
        variant_id: [0x34; 32],
        total_len: bytes,
        attempt_nonce,
        checkpoint_generation: 0,
        custody_digest: None,
    };
    attempt
        .send_data(&encoded(StreamFrame::Open(open))?)
        .await
        .map_err(|error| format!("send open: {error:?}"))?;
    let accept = attempt
        .receive_control()
        .await
        .map_err(|error| format!("receive accept: {error:?}"))?
        .ok_or("control stream closed before accept")?;
    let StreamFrame::Accept(accept) = decoded(&accept)? else {
        return Err("first control frame was not accept".into());
    };
    let mut state = StreamSenderState::new(transfer_id, attempt_nonce, bytes);
    state.accept(accept).map_err(|error| error.to_string())?;
    let started = StdInstant::now();
    let mut offset = 0_u64;
    let mut checkpoints = 0_u64;
    let mut hasher = Sha256::new();
    while offset < bytes {
        let len = (bytes - offset).min(EXTENT_BYTES as u64) as usize;
        let extent = payload(offset, len);
        match state
            .send_extent(extent.clone())
            .map_err(|error| error.to_string())?
        {
            StreamAction::Send(frame) => {
                attempt
                    .send_data(&encoded(frame)?)
                    .await
                    .map_err(|error| format!("send data: {error:?}"))?;
                hasher.update(&extent);
                offset += len as u64;
            }
            StreamAction::Retry(crate::stream_transfer::StreamRetry::CreditBlocked) => {
                let checkpoint = attempt
                    .receive_control()
                    .await
                    .map_err(|error| format!("receive checkpoint: {error:?}"))?
                    .ok_or("control stream closed before checkpoint")?;
                let StreamFrame::Checkpoint(checkpoint) = decoded(&checkpoint)? else {
                    return Err("credit wait received a non-checkpoint frame".into());
                };
                state
                    .checkpoint(checkpoint)
                    .map_err(|error| error.to_string())?;
                checkpoints += 1;
            }
            _ => return Err("sender produced an invalid data action".into()),
        }
    }
    // The receiver always makes the final byte durable before accepting Finish.
    // Consume that cumulative checkpoint even when the last extent did not need
    // additional credit, so subsequent control sequence numbers remain aligned.
    let final_checkpoint = attempt
        .receive_control()
        .await
        .map_err(|error| format!("receive final checkpoint: {error:?}"))?
        .ok_or("control stream closed before final checkpoint")?;
    let StreamFrame::Checkpoint(final_checkpoint) = decoded(&final_checkpoint)? else {
        return Err("final data control frame was not checkpoint".into());
    };
    state
        .checkpoint(final_checkpoint)
        .map_err(|error| error.to_string())?;
    checkpoints += 1;
    let StreamAction::Send(finish) = state
        .finish(hasher.clone().finalize().to_vec())
        .map_err(|error| error.to_string())?
    else {
        return Err("sender did not produce finish".into());
    };
    attempt
        .send_data(&encoded(finish)?)
        .await
        .map_err(|error| format!("send finish: {error:?}"))?;
    let result = attempt
        .receive_control()
        .await
        .map_err(|error| format!("receive result: {error:?}"))?
        .ok_or("control stream closed before result")?;
    let StreamFrame::Result(result) = decoded(&result)? else {
        return Err("terminal control frame was not result".into());
    };
    let digest: [u8; 32] = hasher.finalize().into();
    if result.code != StreamResultCode::Promoted || result.result_digest != digest {
        return Err("receiver result did not verify the complete payload".into());
    }
    let (StreamAction::Send(ack), StreamAction::Terminal(StreamResultCode::Promoted)) =
        state.result(result).map_err(|error| error.to_string())?
    else {
        return Err("sender settlement action differed".into());
    };
    attempt
        .send_data(&encoded(ack)?)
        .await
        .map_err(|error| format!("send result ack: {error:?}"))?;
    attempt
        .finish_data()
        .await
        .map_err(|error| format!("finish data stream: {error:?}"))?;
    if attempt
        .receive_control()
        .await
        .map_err(|error| format!("receive control EOF: {error:?}"))?
        .is_some()
    {
        return Err("control stream contained data after terminal result".into());
    }
    let elapsed_ns = started.elapsed().as_nanos();
    Ok(StreamValidationReport {
        bytes,
        elapsed_ns,
        mib_per_second: rate(bytes, elapsed_ns),
        checkpoints,
        digest,
    })
}

pub async fn receive(
    connection: Connection,
    expected_bytes: u64,
) -> Result<StreamValidationReport, String> {
    let (max_data_bytes, max_control_bytes) = attempt_bounds(expected_bytes)?;
    let adapter = IrohQuicV1Adapter::new(connection);
    let attempt = adapter
        .accept_attempt(AttemptOpenRequest {
            deadline: Instant::now() + ATTEMPT_TIMEOUT,
            max_data_bytes,
            max_control_bytes,
        })
        .await
        .map_err(|error| format!("accept attempt: {error:?}"))?;
    let open = attempt
        .receive_data()
        .await
        .map_err(|error| format!("receive open: {error:?}"))?
        .ok_or("data stream closed before open")?;
    let StreamFrame::Open(open) = decoded(&open)? else {
        return Err("first data frame was not open".into());
    };
    if open.class != StreamClass::Blob || open.total_len != expected_bytes {
        return Err("stream open differs from expected Blob transfer".into());
    }
    let batch = u64::from(MAX_STREAM_CHECKPOINT_BATCH_BYTES);
    let mut state =
        StreamReceiverState::new(&open, 0, 0, expected_bytes.min(batch), EXTENT_BYTES as u32)
            .map_err(|error| error.to_string())?;
    let StreamAction::Send(accept) = state
        .accept(MAX_STREAM_CHECKPOINT_BATCH_BYTES)
        .map_err(|error| error.to_string())?
    else {
        return Err("receiver did not produce accept".into());
    };
    attempt
        .send_control(&encoded(accept)?)
        .await
        .map_err(|error| format!("send accept: {error:?}"))?;
    let started = StdInstant::now();
    let mut hasher = Sha256::new();
    let mut durable = 0_u64;
    let mut generation = 0_u64;
    let mut checkpoints = 0_u64;
    loop {
        let bytes = attempt
            .receive_data()
            .await
            .map_err(|error| format!("receive data: {error:?}"))?
            .ok_or("data stream closed before settlement")?;
        match decoded(&bytes)? {
            StreamFrame::Data(data) => {
                let through = data.offset + data.bytes.len() as u64;
                let StreamAction::Persist { through: accepted } = state
                    .data(data.clone())
                    .map_err(|error| error.to_string())?
                else {
                    return Err("receiver did not persist new data".into());
                };
                if through != accepted {
                    return Err("receiver persistence offset differed".into());
                }
                hasher.update(&data.bytes);
                if through == expected_bytes || through - durable >= batch {
                    generation += 1;
                    let limit = expected_bytes.min(through.saturating_add(batch));
                    let StreamAction::Send(checkpoint) = state
                        .persisted(through, generation, limit)
                        .map_err(|error| error.to_string())?
                    else {
                        return Err("receiver did not produce checkpoint".into());
                    };
                    attempt
                        .send_control(&encoded(checkpoint)?)
                        .await
                        .map_err(|error| format!("send checkpoint: {error:?}"))?;
                    durable = through;
                    checkpoints += 1;
                }
            }
            StreamFrame::Finish(finish) => {
                let StreamAction::Promote =
                    state.finish(finish).map_err(|error| error.to_string())?
                else {
                    return Err("receiver did not promote complete stream".into());
                };
                let digest: [u8; 32] = hasher.finalize().into();
                let StreamAction::Send(result) = state
                    .promoted(StreamResultCode::Promoted, digest)
                    .map_err(|error| error.to_string())?
                else {
                    return Err("receiver did not produce result".into());
                };
                attempt
                    .send_control(&encoded(result)?)
                    .await
                    .map_err(|error| format!("send result: {error:?}"))?;
                let ack = attempt
                    .receive_data()
                    .await
                    .map_err(|error| format!("receive result ack: {error:?}"))?
                    .ok_or("data stream closed before result ack")?;
                let StreamFrame::ResultAck(ack) = decoded(&ack)? else {
                    return Err("settlement frame was not result ack".into());
                };
                let StreamAction::Terminal(StreamResultCode::Promoted) = state
                    .result_ack(ack, StreamResultCode::Promoted)
                    .map_err(|error| error.to_string())?
                else {
                    return Err("receiver settlement action differed".into());
                };
                if attempt
                    .receive_data()
                    .await
                    .map_err(|error| format!("receive data EOF: {error:?}"))?
                    .is_some()
                {
                    return Err("data stream contained data after result ack".into());
                }
                attempt
                    .finish_control()
                    .await
                    .map_err(|error| format!("finish control stream: {error:?}"))?;
                let elapsed_ns = started.elapsed().as_nanos();
                return Ok(StreamValidationReport {
                    bytes: expected_bytes,
                    elapsed_ns,
                    mib_per_second: rate(expected_bytes, elapsed_ns),
                    checkpoints,
                    digest,
                });
            }
            _ => return Err("unexpected frame on data stream".into()),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use aster_iroh::{CarrierSecurityProfile, Endpoint, EndpointConfig, ExpectedPeer, SecretKey};
    use std::collections::BTreeSet;

    #[tokio::test]
    async fn semantic_v9_driver_transfers_and_settles_over_selected_transport() {
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
        let address = server
            .bound_sockets()
            .into_iter()
            .find(std::net::SocketAddr::is_ipv4)
            .expect("IPv4 server address");
        let bytes = 2 * 1024 * 1024;
        let receiver = tokio::spawn({
            let server = server.clone();
            let allowed = BTreeSet::from([client.id()]);
            async move {
                let connection = server.accept(&allowed).await.expect("accept");
                receive(connection, bytes).await.expect("receive")
            }
        });
        let connection = client
            .connect(ExpectedPeer {
                id: server.id(),
                address,
            })
            .await
            .expect("connect");
        let sent = send(connection, bytes).await.expect("send");
        let received = receiver.await.expect("receiver task");
        assert_eq!(sent.bytes, bytes);
        assert_eq!(received.bytes, bytes);
        assert_eq!(sent.digest, received.digest);
        assert_eq!(sent.checkpoints, 1);
        assert_eq!(received.checkpoints, 1);
        client.close().await;
        server.close().await;
    }
}
