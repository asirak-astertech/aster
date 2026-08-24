use aster_negentropy::MAX_FRAME_SIZE_LIMIT;
use aster_redb_store::{ControlTransferId, EventTransferId};

use crate::NodeError;

const MAGIC: &[u8; 4] = b"ASM\x01";
const INVENTORY_QUERY: u8 = 0x11;
const INVENTORY_REPLY: u8 = 0x12;
const INVENTORY_COMPLETE: u8 = 0x13;
const INVENTORY_COMPLETE_ACK: u8 = 0x14;
const DIFFERENCE_QUERY: u8 = 0x15;
const DIFFERENCE_REPLY: u8 = 0x16;
const DIFFERENCE_BOUND: u8 = 0x17;
const DIFFERENCE_BOUND_ACK: u8 = 0x18;
const FETCH: u8 = 0x21;
const OBJECT: u8 = 0x22;
const OFFER: u8 = 0x23;
const APPLY_RESULT: u8 = 0x24;
const FINISH: u8 = 0x31;
const FINISHED: u8 = 0x32;
const CONTROL_INVENTORY_QUERY: u8 = 0x41;
const CONTROL_INVENTORY_REPLY: u8 = 0x42;
const CONTROL_INVENTORY_COMPLETE: u8 = 0x43;
const CONTROL_INVENTORY_COMPLETE_ACK: u8 = 0x44;
const CONTROL_DIFFERENCE_QUERY: u8 = 0x45;
const CONTROL_DIFFERENCE_REPLY: u8 = 0x46;
const CONTROL_DIFFERENCE_BOUND: u8 = 0x47;
const CONTROL_DIFFERENCE_BOUND_ACK: u8 = 0x48;
const CONTROL_FETCH: u8 = 0x51;
const CONTROL_OBJECT: u8 = 0x52;
const CONTROL_OFFER: u8 = 0x53;
const CONTROL_APPLY_RESULT: u8 = 0x54;
const CONTROL_FINISH: u8 = 0x61;
const CONTROL_FINISHED: u8 = 0x62;
pub(crate) const MAX_OBJECT_BYTES: usize = 1024 * 1024;

#[derive(Debug, Eq, PartialEq)]
pub(crate) enum Frame {
    InventoryQuery(Vec<u8>),
    InventoryReply(Vec<u8>),
    InventoryComplete,
    InventoryCompleteAck,
    DifferenceQuery(Vec<u8>),
    DifferenceReply(Vec<u8>),
    DifferenceBound,
    DifferenceBoundAck,
    Fetch(EventTransferId),
    Object {
        id: EventTransferId,
        bytes: Vec<u8>,
    },
    Offer {
        id: EventTransferId,
        bytes: Vec<u8>,
    },
    ApplyResult {
        id: EventTransferId,
        inserted: bool,
    },
    ControlInventoryQuery(Vec<u8>),
    ControlInventoryReply(Vec<u8>),
    ControlInventoryComplete,
    ControlInventoryCompleteAck,
    ControlDifferenceQuery(Vec<u8>),
    ControlDifferenceReply(Vec<u8>),
    ControlDifferenceBound,
    ControlDifferenceBoundAck,
    ControlFetch(ControlTransferId),
    ControlObject {
        id: ControlTransferId,
        bytes: Vec<u8>,
    },
    ControlOffer {
        id: ControlTransferId,
        bytes: Vec<u8>,
    },
    ControlApplyResult {
        id: ControlTransferId,
        retained: bool,
    },
    ControlFinish,
    ControlFinished,
    Finish,
    Finished,
}

impl Frame {
    pub(crate) fn encode(&self) -> Result<Vec<u8>, NodeError> {
        let mut output = Vec::new();
        output.extend_from_slice(MAGIC);
        match self {
            Self::InventoryQuery(bytes) => {
                output.push(INVENTORY_QUERY);
                encode_bytes(&mut output, bytes, MAX_FRAME_SIZE_LIMIT, "inventory query")?;
            }
            Self::InventoryReply(bytes) => {
                output.push(INVENTORY_REPLY);
                encode_bytes(&mut output, bytes, MAX_FRAME_SIZE_LIMIT, "inventory reply")?;
            }
            Self::InventoryComplete => output.push(INVENTORY_COMPLETE),
            Self::InventoryCompleteAck => output.push(INVENTORY_COMPLETE_ACK),
            Self::DifferenceQuery(bytes) => {
                output.push(DIFFERENCE_QUERY);
                encode_bytes(&mut output, bytes, MAX_FRAME_SIZE_LIMIT, "difference query")?;
            }
            Self::DifferenceReply(bytes) => {
                output.push(DIFFERENCE_REPLY);
                encode_bytes(&mut output, bytes, MAX_FRAME_SIZE_LIMIT, "difference reply")?;
            }
            Self::DifferenceBound => output.push(DIFFERENCE_BOUND),
            Self::DifferenceBoundAck => output.push(DIFFERENCE_BOUND_ACK),
            Self::Fetch(id) => {
                output.push(FETCH);
                output.extend_from_slice(id.as_bytes());
            }
            Self::Object { id, bytes } => {
                output.push(OBJECT);
                output.extend_from_slice(id.as_bytes());
                encode_bytes(&mut output, bytes, MAX_OBJECT_BYTES, "Event object")?;
            }
            Self::Offer { id, bytes } => {
                output.push(OFFER);
                output.extend_from_slice(id.as_bytes());
                encode_bytes(&mut output, bytes, MAX_OBJECT_BYTES, "Event offer")?;
            }
            Self::ApplyResult { id, inserted } => {
                output.push(APPLY_RESULT);
                output.extend_from_slice(id.as_bytes());
                output.push(u8::from(*inserted));
            }
            Self::ControlInventoryQuery(bytes) => {
                output.push(CONTROL_INVENTORY_QUERY);
                encode_bytes(
                    &mut output,
                    bytes,
                    MAX_FRAME_SIZE_LIMIT,
                    "control inventory query",
                )?;
            }
            Self::ControlInventoryReply(bytes) => {
                output.push(CONTROL_INVENTORY_REPLY);
                encode_bytes(
                    &mut output,
                    bytes,
                    MAX_FRAME_SIZE_LIMIT,
                    "control inventory reply",
                )?;
            }
            Self::ControlInventoryComplete => output.push(CONTROL_INVENTORY_COMPLETE),
            Self::ControlInventoryCompleteAck => output.push(CONTROL_INVENTORY_COMPLETE_ACK),
            Self::ControlDifferenceQuery(bytes) => {
                output.push(CONTROL_DIFFERENCE_QUERY);
                encode_bytes(
                    &mut output,
                    bytes,
                    MAX_FRAME_SIZE_LIMIT,
                    "control difference query",
                )?;
            }
            Self::ControlDifferenceReply(bytes) => {
                output.push(CONTROL_DIFFERENCE_REPLY);
                encode_bytes(
                    &mut output,
                    bytes,
                    MAX_FRAME_SIZE_LIMIT,
                    "control difference reply",
                )?;
            }
            Self::ControlDifferenceBound => output.push(CONTROL_DIFFERENCE_BOUND),
            Self::ControlDifferenceBoundAck => output.push(CONTROL_DIFFERENCE_BOUND_ACK),
            Self::ControlFetch(id) => {
                output.push(CONTROL_FETCH);
                output.extend_from_slice(id.as_bytes());
            }
            Self::ControlObject { id, bytes } => {
                output.push(CONTROL_OBJECT);
                output.extend_from_slice(id.as_bytes());
                encode_bytes(&mut output, bytes, MAX_OBJECT_BYTES, "control object")?;
            }
            Self::ControlOffer { id, bytes } => {
                output.push(CONTROL_OFFER);
                output.extend_from_slice(id.as_bytes());
                encode_bytes(&mut output, bytes, MAX_OBJECT_BYTES, "control offer")?;
            }
            Self::ControlApplyResult { id, retained } => {
                output.push(CONTROL_APPLY_RESULT);
                output.extend_from_slice(id.as_bytes());
                output.push(u8::from(*retained));
            }
            Self::ControlFinish => output.push(CONTROL_FINISH),
            Self::ControlFinished => output.push(CONTROL_FINISHED),
            Self::Finish => output.push(FINISH),
            Self::Finished => output.push(FINISHED),
        }
        Ok(output)
    }

    pub(crate) fn decode(input: &[u8]) -> Result<Self, NodeError> {
        if input.len() < 5 || &input[..4] != MAGIC {
            return Err(NodeError::Protocol(
                "invalid mechanics frame version".into(),
            ));
        }
        let tag = input[4];
        let body = &input[5..];
        match tag {
            INVENTORY_QUERY => Ok(Self::InventoryQuery(
                decode_bytes(body, MAX_FRAME_SIZE_LIMIT, "inventory query")?.to_vec(),
            )),
            INVENTORY_REPLY => Ok(Self::InventoryReply(
                decode_bytes(body, MAX_FRAME_SIZE_LIMIT, "inventory reply")?.to_vec(),
            )),
            INVENTORY_COMPLETE if body.is_empty() => Ok(Self::InventoryComplete),
            INVENTORY_COMPLETE_ACK if body.is_empty() => Ok(Self::InventoryCompleteAck),
            DIFFERENCE_QUERY => Ok(Self::DifferenceQuery(
                decode_bytes(body, MAX_FRAME_SIZE_LIMIT, "difference query")?.to_vec(),
            )),
            DIFFERENCE_REPLY => Ok(Self::DifferenceReply(
                decode_bytes(body, MAX_FRAME_SIZE_LIMIT, "difference reply")?.to_vec(),
            )),
            DIFFERENCE_BOUND if body.is_empty() => Ok(Self::DifferenceBound),
            DIFFERENCE_BOUND_ACK if body.is_empty() => Ok(Self::DifferenceBoundAck),
            FETCH => Ok(Self::Fetch(decode_exact_id(body)?)),
            OBJECT | OFFER => {
                if body.len() < 32 {
                    return Err(NodeError::Protocol("object frame is truncated".into()));
                }
                let id = decode_exact_id(&body[..32])?;
                let bytes = decode_bytes(&body[32..], MAX_OBJECT_BYTES, "Event object")?.to_vec();
                if tag == OBJECT {
                    Ok(Self::Object { id, bytes })
                } else {
                    Ok(Self::Offer { id, bytes })
                }
            }
            APPLY_RESULT => {
                if body.len() != 33 || body[32] > 1 {
                    return Err(NodeError::Protocol("apply result frame differs".into()));
                }
                Ok(Self::ApplyResult {
                    id: decode_exact_id(&body[..32])?,
                    inserted: body[32] == 1,
                })
            }
            CONTROL_INVENTORY_QUERY => Ok(Self::ControlInventoryQuery(
                decode_bytes(body, MAX_FRAME_SIZE_LIMIT, "control inventory query")?.to_vec(),
            )),
            CONTROL_INVENTORY_REPLY => Ok(Self::ControlInventoryReply(
                decode_bytes(body, MAX_FRAME_SIZE_LIMIT, "control inventory reply")?.to_vec(),
            )),
            CONTROL_INVENTORY_COMPLETE if body.is_empty() => Ok(Self::ControlInventoryComplete),
            CONTROL_INVENTORY_COMPLETE_ACK if body.is_empty() => {
                Ok(Self::ControlInventoryCompleteAck)
            }
            CONTROL_DIFFERENCE_QUERY => Ok(Self::ControlDifferenceQuery(
                decode_bytes(body, MAX_FRAME_SIZE_LIMIT, "control difference query")?.to_vec(),
            )),
            CONTROL_DIFFERENCE_REPLY => Ok(Self::ControlDifferenceReply(
                decode_bytes(body, MAX_FRAME_SIZE_LIMIT, "control difference reply")?.to_vec(),
            )),
            CONTROL_DIFFERENCE_BOUND if body.is_empty() => Ok(Self::ControlDifferenceBound),
            CONTROL_DIFFERENCE_BOUND_ACK if body.is_empty() => Ok(Self::ControlDifferenceBoundAck),
            CONTROL_FETCH => Ok(Self::ControlFetch(decode_control_id(body)?)),
            CONTROL_OBJECT | CONTROL_OFFER => {
                if body.len() < 32 {
                    return Err(NodeError::Protocol(
                        "control object frame is truncated".into(),
                    ));
                }
                let id = decode_control_id(&body[..32])?;
                let bytes = decode_bytes(&body[32..], MAX_OBJECT_BYTES, "control object")?.to_vec();
                if tag == CONTROL_OBJECT {
                    Ok(Self::ControlObject { id, bytes })
                } else {
                    Ok(Self::ControlOffer { id, bytes })
                }
            }
            CONTROL_APPLY_RESULT => {
                if body.len() != 33 || body[32] > 1 {
                    return Err(NodeError::Protocol(
                        "control apply result frame differs".into(),
                    ));
                }
                Ok(Self::ControlApplyResult {
                    id: decode_control_id(&body[..32])?,
                    retained: body[32] == 1,
                })
            }
            CONTROL_FINISH if body.is_empty() => Ok(Self::ControlFinish),
            CONTROL_FINISHED if body.is_empty() => Ok(Self::ControlFinished),
            FINISH if body.is_empty() => Ok(Self::Finish),
            FINISHED if body.is_empty() => Ok(Self::Finished),
            _ => Err(NodeError::Protocol(
                "unknown or malformed mechanics frame".into(),
            )),
        }
    }
}

fn decode_control_id(input: &[u8]) -> Result<ControlTransferId, NodeError> {
    if input.len() != 32 {
        return Err(NodeError::Protocol(
            "control transfer identifier length differs".into(),
        ));
    }
    let mut bytes = [0u8; 32];
    bytes.copy_from_slice(input);
    Ok(ControlTransferId::new(bytes))
}

fn encode_bytes(
    output: &mut Vec<u8>,
    bytes: &[u8],
    maximum: usize,
    label: &str,
) -> Result<(), NodeError> {
    if bytes.len() > maximum {
        return Err(NodeError::Protocol(format!(
            "{label} body exceeds {maximum} bytes"
        )));
    }
    let length = u32::try_from(bytes.len())
        .map_err(|_| NodeError::Protocol("frame body exceeds u32".into()))?;
    output.extend_from_slice(&length.to_be_bytes());
    output.extend_from_slice(bytes);
    Ok(())
}

fn decode_bytes<'a>(input: &'a [u8], maximum: usize, label: &str) -> Result<&'a [u8], NodeError> {
    if input.len() < 4 {
        return Err(NodeError::Protocol(
            "length-prefixed body is truncated".into(),
        ));
    }
    let length = u32::from_be_bytes(
        input[..4]
            .try_into()
            .map_err(|_| NodeError::Protocol("body length differs".into()))?,
    ) as usize;
    if length > maximum {
        return Err(NodeError::Protocol(format!(
            "{label} body exceeds {maximum} bytes"
        )));
    }
    let expected = 4usize
        .checked_add(length)
        .ok_or_else(|| NodeError::Protocol("body length overflows usize".into()))?;
    if input.len() != expected {
        return Err(NodeError::Protocol("body length differs".into()));
    }
    Ok(&input[4..])
}

fn decode_exact_id(input: &[u8]) -> Result<EventTransferId, NodeError> {
    if input.len() != 32 {
        return Err(NodeError::Protocol(
            "Event transfer identifier length differs".into(),
        ));
    }
    let mut bytes = [0u8; 32];
    bytes.copy_from_slice(input);
    Ok(EventTransferId::new(bytes))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn every_frame_round_trips_and_rejects_trailing_bytes() {
        let id = EventTransferId::new([0x44; 32]);
        let control_id = ControlTransferId::new([0x55; 32]);
        let frames = [
            Frame::InventoryQuery(vec![1, 2]),
            Frame::InventoryReply(vec![3, 4]),
            Frame::InventoryComplete,
            Frame::InventoryCompleteAck,
            Frame::DifferenceQuery(vec![5, 6]),
            Frame::DifferenceReply(vec![7, 8]),
            Frame::DifferenceBound,
            Frame::DifferenceBoundAck,
            Frame::Fetch(id),
            Frame::Object {
                id,
                bytes: b"object".to_vec(),
            },
            Frame::Offer {
                id,
                bytes: b"offer".to_vec(),
            },
            Frame::ApplyResult { id, inserted: true },
            Frame::ControlInventoryQuery(vec![9, 10]),
            Frame::ControlInventoryReply(vec![11, 12]),
            Frame::ControlInventoryComplete,
            Frame::ControlInventoryCompleteAck,
            Frame::ControlDifferenceQuery(vec![13, 14]),
            Frame::ControlDifferenceReply(vec![15, 16]),
            Frame::ControlDifferenceBound,
            Frame::ControlDifferenceBoundAck,
            Frame::ControlFetch(control_id),
            Frame::ControlObject {
                id: control_id,
                bytes: b"control-object".to_vec(),
            },
            Frame::ControlOffer {
                id: control_id,
                bytes: b"control-offer".to_vec(),
            },
            Frame::ControlApplyResult {
                id: control_id,
                retained: true,
            },
            Frame::ControlFinish,
            Frame::ControlFinished,
            Frame::Finish,
            Frame::Finished,
        ];
        for frame in frames {
            let encoded = frame.encode().expect("encode");
            assert_eq!(Frame::decode(&encoded).expect("decode"), frame);
            let mut trailing = encoded;
            trailing.push(0);
            assert!(Frame::decode(&trailing).is_err());
        }
    }

    #[test]
    fn unknown_version_and_tag_fail_closed() {
        assert!(Frame::decode(b"BAD!\x11\0\0\0\0").is_err());
        assert!(Frame::decode(b"ASM\x01\xff").is_err());
    }

    #[test]
    fn tag_specific_plaintext_limits_reject_before_body_clone() {
        let oversized = vec![0u8; MAX_OBJECT_BYTES + 1];
        let event_id = EventTransferId::new([0x61; 32]);
        let control_id = ControlTransferId::new([0x62; 32]);
        assert!(
            Frame::Object {
                id: event_id,
                bytes: oversized.clone(),
            }
            .encode()
            .is_err()
        );
        assert!(
            Frame::ControlOffer {
                id: control_id,
                bytes: oversized.clone(),
            }
            .encode()
            .is_err()
        );

        for (tag, id) in [
            (OBJECT, event_id.as_bytes()),
            (CONTROL_OBJECT, control_id.as_bytes()),
        ] {
            let mut encoded = Vec::with_capacity(5 + 32 + 4 + oversized.len());
            encoded.extend_from_slice(MAGIC);
            encoded.push(tag);
            encoded.extend_from_slice(id);
            encoded.extend_from_slice(
                &u32::try_from(oversized.len())
                    .expect("length")
                    .to_be_bytes(),
            );
            encoded.extend_from_slice(&oversized);
            assert!(Frame::decode(&encoded).is_err());
        }

        let oversized_reconciliation = vec![0u8; MAX_FRAME_SIZE_LIMIT + 1];
        let mut encoded = Vec::with_capacity(9 + oversized_reconciliation.len());
        encoded.extend_from_slice(MAGIC);
        encoded.push(INVENTORY_QUERY);
        encoded.extend_from_slice(
            &u32::try_from(oversized_reconciliation.len())
                .expect("reconciliation length")
                .to_be_bytes(),
        );
        encoded.extend_from_slice(&oversized_reconciliation);
        assert!(Frame::decode(&encoded).is_err());
    }
}
