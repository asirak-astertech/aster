//! Instrumented end-to-end driver for the semantic-v9 stream protocol.
//!
//! This is intentionally not an application API. It exercises the same ABX1
//! DATA grammar, state machines, credit, settlement, size-derived hard bound,
//! and selected transport used by the runtime. The retired PR95 ASTRBS02 pack
//! path is test-only and cannot be emitted through this production module.

use crate::{
    stream_transfer::{
        CanonicalBlobExtentV1, MAX_STREAM_CHECKPOINT_BATCH_BYTES,
        PROFILE5_CANONICAL_CARRIER_RECORD_BYTES, PROFILE5_CANONICAL_EXTENT_BYTES, StreamAction,
        StreamClass, StreamDirection, StreamExtentAction, StreamFrame, StreamOpenV1,
        StreamReceiverState, StreamResultCode, StreamSenderState, profile5_attempt_bounds,
        profile5_attempt_hard_timeout, profile5_receive_limit,
    },
    stream_transport::{AttemptOpenRequest, IrohQuicV1Adapter, StreamTransportAdapter},
};
use aster_iroh::Connection;
use sha2::{Digest, Sha256};
use std::time::Instant as StdInstant;
use tokio::time::Instant;

#[derive(Clone, Debug, PartialEq)]
pub struct StreamValidationReport {
    pub bytes: u64,
    pub elapsed_ns: u128,
    pub mib_per_second: f64,
    pub checkpoints: u64,
    pub digest: [u8; 32],
}

fn payload(offset: u64, len: usize) -> Vec<u8> {
    let extent = offset / PROFILE5_CANONICAL_CARRIER_RECORD_BYTES as u64;
    vec![(extent as u8).wrapping_mul(31).wrapping_add(0x5a); len]
}

fn validation_wire_len(payload_len: u64) -> Result<u64, String> {
    let carriers = payload_len.div_ceil(PROFILE5_CANONICAL_CARRIER_RECORD_BYTES as u64);
    payload_len
        .checked_add(
            carriers
                .checked_mul(20)
                .ok_or("validation wire length overflow")?,
        )
        .ok_or_else(|| "validation wire length overflow".into())
}

fn rate(bytes: u64, elapsed_ns: u128) -> f64 {
    bytes as f64 / (1024.0 * 1024.0) / (elapsed_ns as f64 / 1_000_000_000.0)
}

fn encoded(frame: StreamFrame) -> Result<Vec<u8>, String> {
    frame
        .encode_for_context(9, 5)
        .map_err(|error| error.to_string())
}

fn decoded(bytes: &[u8]) -> Result<StreamFrame, String> {
    StreamFrame::decode_for_context(9, 5, bytes).map_err(|error| error.to_string())
}

pub(crate) fn decode_validation_extent(bytes: &[u8]) -> Result<CanonicalBlobExtentV1, String> {
    CanonicalBlobExtentV1::decode(bytes).map_err(|error| error.to_string())
}

pub async fn send(connection: Connection, bytes: u64) -> Result<StreamValidationReport, String> {
    if bytes == 0 {
        return Err("validation payload must be nonempty".into());
    }
    let wire_len = validation_wire_len(bytes)?;
    let (max_data_bytes, max_control_bytes) =
        profile5_attempt_bounds(wire_len).map_err(|error| error.to_string())?;
    let adapter = IrohQuicV1Adapter::new(connection);
    let attempt = adapter
        .open_attempt(AttemptOpenRequest {
            deadline: Instant::now() + profile5_attempt_hard_timeout(wire_len),
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
        total_len: wire_len,
        attempt_nonce,
        checkpoint_generation: 0,
        custody_digest: None,
        source_len: 1,
        source_digest: [0x35; 32],
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
    let mut state = StreamSenderState::new(transfer_id, attempt_nonce, wire_len);
    state.accept(accept).map_err(|error| error.to_string())?;
    let started = StdInstant::now();
    let mut payload_offset = 0_u64;
    let mut checkpoints = 0_u64;
    let mut hasher = Sha256::new();
    let mut pending: Option<(Vec<u8>, usize)> = None;
    let mut carrier_index = 0_u64;
    while payload_offset < bytes {
        let len =
            (bytes - payload_offset).min(PROFILE5_CANONICAL_CARRIER_RECORD_BYTES as u64) as usize;
        let (extent, payload_len) = match pending.take() {
            Some(pending) => pending,
            None => {
                let carrier = payload(payload_offset, len);
                hasher.update(&carrier);
                let encoded = CanonicalBlobExtentV1 {
                    first_chunk_index: carrier_index,
                    carriers: vec![carrier],
                }
                .encode()
                .map_err(|error| error.to_string())?;
                (encoded, len)
            }
        };
        match state
            .send_extent(extent)
            .map_err(|error| error.to_string())?
        {
            StreamExtentAction::Send(data) => {
                attempt
                    .send_data(&encoded(StreamFrame::Data(data))?)
                    .await
                    .map_err(|error| format!("send data: {error:?}"))?;
                payload_offset += payload_len as u64;
                carrier_index += 1;
            }
            StreamExtentAction::Retry {
                reason: crate::stream_transfer::StreamRetry::CreditBlocked,
                bytes,
            } => {
                pending = Some((bytes, payload_len));
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
            StreamExtentAction::Retry { .. } => {
                return Err("sender produced an invalid extent retry".into());
            }
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
    receive_with_batch(
        connection,
        expected_bytes,
        MAX_STREAM_CHECKPOINT_BATCH_BYTES,
    )
    .await
}

async fn receive_with_batch(
    connection: Connection,
    expected_bytes: u64,
    checkpoint_batch: u32,
) -> Result<StreamValidationReport, String> {
    let (max_data_bytes, max_control_bytes) =
        profile5_attempt_bounds(validation_wire_len(expected_bytes)?)
            .map_err(|error| error.to_string())?;
    let expected_wire = validation_wire_len(expected_bytes)?;
    let adapter = IrohQuicV1Adapter::new(connection);
    let attempt = adapter
        .accept_attempt(AttemptOpenRequest {
            deadline: Instant::now() + profile5_attempt_hard_timeout(expected_wire),
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
    if open.class != StreamClass::Blob || open.total_len != expected_wire {
        return Err("stream open differs from expected Blob transfer".into());
    }
    let batch = u64::from(checkpoint_batch);
    let mut state = StreamReceiverState::new(
        &open,
        0,
        0,
        profile5_receive_limit(expected_wire, 0, checkpoint_batch),
        PROFILE5_CANONICAL_EXTENT_BYTES as u32,
    )
    .map_err(|error| error.to_string())?;
    let StreamAction::Send(accept) = state
        .accept(checkpoint_batch)
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
    let mut payload_bytes = 0_u64;
    let mut carrier_index = 0_u64;
    loop {
        let bytes = attempt
            .receive_data()
            .await
            .map_err(|error| format!("receive data: {error:?}"))?
            .ok_or("data stream closed before settlement")?;
        match decoded(&bytes)? {
            StreamFrame::Data(data) => {
                let through = data.offset + data.bytes.len() as u64;
                let StreamAction::Persist { through: accepted } =
                    state.data(&data).map_err(|error| error.to_string())?
                else {
                    return Err("receiver did not persist new data".into());
                };
                if through != accepted {
                    return Err("receiver persistence offset differed".into());
                }
                let extent = decode_validation_extent(&data.bytes)?;
                if extent.first_chunk_index != carrier_index || extent.carriers.len() != 1 {
                    return Err("validation DATA is not one ordered canonical carrier".into());
                }
                let carrier = &extent.carriers[0];
                payload_bytes = payload_bytes
                    .checked_add(carrier.len() as u64)
                    .ok_or("validation payload length overflow")?;
                if payload_bytes > expected_bytes {
                    return Err("validation payload exceeds expected length".into());
                }
                carrier_index += 1;
                hasher.update(carrier);
                if through == expected_wire || through - durable >= batch {
                    generation += 1;
                    let limit = profile5_receive_limit(expected_wire, through, checkpoint_batch);
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
                if payload_bytes != expected_bytes {
                    return Err("validation payload ended before expected length".into());
                }
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

    #[test]
    fn semantic_v9_validation_rejects_raw_pack_data() {
        // Mutation caught: accepting the retired ASTRBS02 body would restore a
        // second semantic-v9 DATA grammar alongside production ABX1.
        let mut raw = Vec::from(8_u32.to_be_bytes());
        raw.extend_from_slice(b"ASTRBS02");
        assert!(decode_validation_extent(&raw).is_err());

        let encoded = CanonicalBlobExtentV1 {
            first_chunk_index: 0,
            carriers: vec![vec![0x5a; 32]],
        }
        .encode()
        .unwrap();
        assert_eq!(
            decode_validation_extent(&encoded).unwrap().carriers[0],
            vec![0x5a; 32]
        );
    }

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

    #[tokio::test]
    async fn semantic_v9_driver_crosses_credit_checkpoint_without_deadlock() {
        const TEST_CHECKPOINT_BATCH: u32 = 8 * 1_048_576;
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
        let bytes = u64::from(TEST_CHECKPOINT_BATCH)
            + u64::try_from(PROFILE5_CANONICAL_EXTENT_BYTES).expect("extent bytes");
        let receiver = tokio::spawn({
            let server = server.clone();
            let allowed = BTreeSet::from([client.id()]);
            async move {
                let connection = server.accept(&allowed).await.expect("accept");
                receive_with_batch(connection, bytes, TEST_CHECKPOINT_BATCH)
                    .await
                    .expect("receive")
            }
        });
        let connection = client
            .connect(ExpectedPeer {
                id: server.id(),
                address,
            })
            .await
            .expect("connect");
        let sent = tokio::time::timeout(std::time::Duration::from_secs(5), send(connection, bytes))
            .await
            .expect("credit checkpoint must not deadlock")
            .expect("send");
        let received = receiver.await.expect("receiver task");
        assert_eq!(sent.bytes, bytes);
        assert_eq!(received.bytes, bytes);
        assert_eq!(sent.digest, received.digest);
        assert!(sent.checkpoints > 1);
        assert_eq!(received.checkpoints, sent.checkpoints);
        client.close().await;
        server.close().await;
    }
}
