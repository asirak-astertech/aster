use aster_mesh::{Scope, Topic};
use aster_negentropy::MAX_FRAME_SIZE_LIMIT;
use aster_redb_store::{ControlTransferId, EventTransferId};

use crate::NodeError;

const MAGIC: &[u8; 4] = b"ASM\x01";
const EVENT_INTEREST: u8 = 0x09;
const EVENT_INTEREST_REPLY: u8 = 0x0a;
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
pub(crate) const MAX_EVENT_INTEREST_SELECTORS: usize = 256;
const MAX_EVENT_NAME_BYTES: usize = 128;
const MAX_EVENT_INTEREST_BYTES: usize =
    2 + MAX_EVENT_INTEREST_SELECTORS * (2 + MAX_EVENT_NAME_BYTES + 2 + MAX_EVENT_NAME_BYTES + 1);

/// Receiver of Events selected by one directional reconciliation lane.
///
/// The role is stable for the complete authenticated contact; it is never
/// interpreted relative to the endpoint currently encoding a frame.
#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub(crate) enum EventDirection {
    ToSessionInitiator,
    ToSessionResponder,
}

impl EventDirection {
    const fn encode(self) -> u8 {
        match self {
            Self::ToSessionInitiator => 1,
            Self::ToSessionResponder => 2,
        }
    }

    fn decode(value: u8) -> Result<Self, NodeError> {
        match value {
            1 => Ok(Self::ToSessionInitiator),
            2 => Ok(Self::ToSessionResponder),
            _ => Err(NodeError::Protocol(
                "Event direction is unknown or missing".into(),
            )),
        }
    }
}

/// One exact topic/scope pair requested for Event replication.
#[derive(Clone, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub(crate) struct EventInterestSelector {
    topic: Topic,
    scope: Scope,
    include_descendant_scopes: bool,
}

impl EventInterestSelector {
    pub(crate) const fn new(topic: Topic, scope: Scope, include_descendant_scopes: bool) -> Self {
        Self {
            topic,
            scope,
            include_descendant_scopes,
        }
    }

    pub(crate) const fn topic(&self) -> &Topic {
        &self.topic
    }

    pub(crate) const fn scope(&self) -> &Scope {
        &self.scope
    }

    pub(crate) const fn include_descendant_scopes(&self) -> bool {
        self.include_descendant_scopes
    }

    pub(crate) fn matches(&self, topic: &Topic, scope: &Scope) -> bool {
        &self.topic == topic
            && if self.include_descendant_scopes {
                self.scope.contains(scope)
            } else {
                &self.scope == scope
            }
    }
}

/// Canonical bounded receive interest authenticated inside one mission session.
///
/// An empty interest is valid and means receive no Events. This value can only
/// narrow the provider's independent scope/epoch route authorization.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub(crate) struct EventInterest(Vec<EventInterestSelector>);

impl EventInterest {
    pub(crate) fn new(mut selectors: Vec<EventInterestSelector>) -> Result<Self, NodeError> {
        if selectors.len() > MAX_EVENT_INTEREST_SELECTORS {
            return Err(NodeError::Protocol(format!(
                "Event interest selector count exceeds {MAX_EVENT_INTEREST_SELECTORS}"
            )));
        }
        selectors.sort_unstable();
        selectors.dedup();
        Ok(Self(selectors))
    }

    pub(crate) const fn empty() -> Self {
        Self(Vec::new())
    }

    pub(crate) fn selectors(&self) -> &[EventInterestSelector] {
        &self.0
    }

    pub(crate) fn is_empty(&self) -> bool {
        self.0.is_empty()
    }

    pub(crate) fn len(&self) -> usize {
        self.0.len()
    }

    pub(crate) fn matches(&self, topic: &Topic, scope: &Scope) -> bool {
        self.0.iter().any(|selector| selector.matches(topic, scope))
    }
}

#[derive(Debug, Eq, PartialEq)]
pub(crate) enum Frame {
    EventInterest(EventInterest),
    EventInterestReply(EventInterest),
    InventoryQuery {
        direction: EventDirection,
        bytes: Vec<u8>,
    },
    InventoryReply {
        direction: EventDirection,
        bytes: Vec<u8>,
    },
    InventoryComplete {
        direction: EventDirection,
    },
    InventoryCompleteAck {
        direction: EventDirection,
    },
    DifferenceQuery {
        direction: EventDirection,
        bytes: Vec<u8>,
    },
    DifferenceReply {
        direction: EventDirection,
        bytes: Vec<u8>,
    },
    DifferenceBound {
        direction: EventDirection,
    },
    DifferenceBoundAck {
        direction: EventDirection,
    },
    Fetch {
        direction: EventDirection,
        id: EventTransferId,
    },
    Object {
        direction: EventDirection,
        id: EventTransferId,
        bytes: Vec<u8>,
    },
    Offer {
        direction: EventDirection,
        id: EventTransferId,
        bytes: Vec<u8>,
    },
    ApplyResult {
        direction: EventDirection,
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
    Finish {
        direction: EventDirection,
    },
    Finished {
        direction: EventDirection,
    },
}

impl Frame {
    pub(crate) fn encode(&self) -> Result<Vec<u8>, NodeError> {
        let mut output = Vec::new();
        output.extend_from_slice(MAGIC);
        match self {
            Self::EventInterest(interest) => {
                output.push(EVENT_INTEREST);
                encode_event_interest(&mut output, interest)?;
            }
            Self::EventInterestReply(interest) => {
                output.push(EVENT_INTEREST_REPLY);
                encode_event_interest(&mut output, interest)?;
            }
            Self::InventoryQuery { direction, bytes } => {
                output.push(INVENTORY_QUERY);
                output.push(direction.encode());
                encode_bytes(&mut output, bytes, MAX_FRAME_SIZE_LIMIT, "inventory query")?;
            }
            Self::InventoryReply { direction, bytes } => {
                output.push(INVENTORY_REPLY);
                output.push(direction.encode());
                encode_bytes(&mut output, bytes, MAX_FRAME_SIZE_LIMIT, "inventory reply")?;
            }
            Self::InventoryComplete { direction } => {
                output.push(INVENTORY_COMPLETE);
                output.push(direction.encode());
            }
            Self::InventoryCompleteAck { direction } => {
                output.push(INVENTORY_COMPLETE_ACK);
                output.push(direction.encode());
            }
            Self::DifferenceQuery { direction, bytes } => {
                output.push(DIFFERENCE_QUERY);
                output.push(direction.encode());
                encode_bytes(&mut output, bytes, MAX_FRAME_SIZE_LIMIT, "difference query")?;
            }
            Self::DifferenceReply { direction, bytes } => {
                output.push(DIFFERENCE_REPLY);
                output.push(direction.encode());
                encode_bytes(&mut output, bytes, MAX_FRAME_SIZE_LIMIT, "difference reply")?;
            }
            Self::DifferenceBound { direction } => {
                output.push(DIFFERENCE_BOUND);
                output.push(direction.encode());
            }
            Self::DifferenceBoundAck { direction } => {
                output.push(DIFFERENCE_BOUND_ACK);
                output.push(direction.encode());
            }
            Self::Fetch { direction, id } => {
                output.push(FETCH);
                output.push(direction.encode());
                output.extend_from_slice(id.as_bytes());
            }
            Self::Object {
                direction,
                id,
                bytes,
            } => {
                output.push(OBJECT);
                output.push(direction.encode());
                output.extend_from_slice(id.as_bytes());
                encode_bytes(&mut output, bytes, MAX_OBJECT_BYTES, "Event object")?;
            }
            Self::Offer {
                direction,
                id,
                bytes,
            } => {
                output.push(OFFER);
                output.push(direction.encode());
                output.extend_from_slice(id.as_bytes());
                encode_bytes(&mut output, bytes, MAX_OBJECT_BYTES, "Event offer")?;
            }
            Self::ApplyResult {
                direction,
                id,
                inserted,
            } => {
                output.push(APPLY_RESULT);
                output.push(direction.encode());
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
            Self::Finish { direction } => {
                output.push(FINISH);
                output.push(direction.encode());
            }
            Self::Finished { direction } => {
                output.push(FINISHED);
                output.push(direction.encode());
            }
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
            EVENT_INTEREST => Ok(Self::EventInterest(decode_event_interest(body)?)),
            EVENT_INTEREST_REPLY => Ok(Self::EventInterestReply(decode_event_interest(body)?)),
            INVENTORY_QUERY => {
                let (direction, body) = decode_direction(body)?;
                Ok(Self::InventoryQuery {
                    direction,
                    bytes: decode_bytes(body, MAX_FRAME_SIZE_LIMIT, "inventory query")?.to_vec(),
                })
            }
            INVENTORY_REPLY => {
                let (direction, body) = decode_direction(body)?;
                Ok(Self::InventoryReply {
                    direction,
                    bytes: decode_bytes(body, MAX_FRAME_SIZE_LIMIT, "inventory reply")?.to_vec(),
                })
            }
            INVENTORY_COMPLETE => Ok(Self::InventoryComplete {
                direction: decode_direction_only(body)?,
            }),
            INVENTORY_COMPLETE_ACK => Ok(Self::InventoryCompleteAck {
                direction: decode_direction_only(body)?,
            }),
            DIFFERENCE_QUERY => {
                let (direction, body) = decode_direction(body)?;
                Ok(Self::DifferenceQuery {
                    direction,
                    bytes: decode_bytes(body, MAX_FRAME_SIZE_LIMIT, "difference query")?.to_vec(),
                })
            }
            DIFFERENCE_REPLY => {
                let (direction, body) = decode_direction(body)?;
                Ok(Self::DifferenceReply {
                    direction,
                    bytes: decode_bytes(body, MAX_FRAME_SIZE_LIMIT, "difference reply")?.to_vec(),
                })
            }
            DIFFERENCE_BOUND => Ok(Self::DifferenceBound {
                direction: decode_direction_only(body)?,
            }),
            DIFFERENCE_BOUND_ACK => Ok(Self::DifferenceBoundAck {
                direction: decode_direction_only(body)?,
            }),
            FETCH => {
                let (direction, body) = decode_direction(body)?;
                Ok(Self::Fetch {
                    direction,
                    id: decode_exact_id(body)?,
                })
            }
            OBJECT | OFFER => {
                let (direction, body) = decode_direction(body)?;
                if body.len() < 32 {
                    return Err(NodeError::Protocol("object frame is truncated".into()));
                }
                let id = decode_exact_id(&body[..32])?;
                let bytes = decode_bytes(&body[32..], MAX_OBJECT_BYTES, "Event object")?.to_vec();
                if tag == OBJECT {
                    Ok(Self::Object {
                        direction,
                        id,
                        bytes,
                    })
                } else {
                    Ok(Self::Offer {
                        direction,
                        id,
                        bytes,
                    })
                }
            }
            APPLY_RESULT => {
                let (direction, body) = decode_direction(body)?;
                if body.len() != 33 || body[32] > 1 {
                    return Err(NodeError::Protocol("apply result frame differs".into()));
                }
                Ok(Self::ApplyResult {
                    direction,
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
            FINISH => Ok(Self::Finish {
                direction: decode_direction_only(body)?,
            }),
            FINISHED => Ok(Self::Finished {
                direction: decode_direction_only(body)?,
            }),
            _ => Err(NodeError::Protocol(
                "unknown or malformed mechanics frame".into(),
            )),
        }
    }
}

fn encode_event_interest(output: &mut Vec<u8>, interest: &EventInterest) -> Result<(), NodeError> {
    if interest.len() > MAX_EVENT_INTEREST_SELECTORS {
        return Err(NodeError::Protocol(format!(
            "Event interest selector count exceeds {MAX_EVENT_INTEREST_SELECTORS}"
        )));
    }
    let count = u16::try_from(interest.len())
        .map_err(|_| NodeError::Protocol("Event interest selector count exceeds u16".into()))?;
    let start = output.len();
    output.extend_from_slice(&count.to_be_bytes());
    let mut previous = None;
    for selector in interest.selectors() {
        if previous.is_some_and(|previous| previous >= selector) {
            return Err(NodeError::Protocol(
                "Event interest selectors are not strictly canonical".into(),
            ));
        }
        encode_event_name(output, selector.topic().as_str(), "topic")?;
        encode_event_name(output, selector.scope().as_str(), "scope")?;
        output.push(u8::from(selector.include_descendant_scopes()));
        previous = Some(selector);
    }
    let encoded = output
        .len()
        .checked_sub(start)
        .ok_or_else(|| NodeError::Protocol("Event interest length underflow".into()))?;
    if encoded > MAX_EVENT_INTEREST_BYTES {
        return Err(NodeError::Protocol(format!(
            "Event interest exceeds {MAX_EVENT_INTEREST_BYTES} bytes"
        )));
    }
    Ok(())
}

fn encode_event_name(output: &mut Vec<u8>, value: &str, label: &str) -> Result<(), NodeError> {
    if value.is_empty() || value.len() > MAX_EVENT_NAME_BYTES {
        return Err(NodeError::Protocol(format!(
            "Event interest {label} length is outside 1..={MAX_EVENT_NAME_BYTES}"
        )));
    }
    let length = u16::try_from(value.len())
        .map_err(|_| NodeError::Protocol("Event interest name exceeds u16".into()))?;
    output.extend_from_slice(&length.to_be_bytes());
    output.extend_from_slice(value.as_bytes());
    Ok(())
}

fn decode_event_interest(input: &[u8]) -> Result<EventInterest, NodeError> {
    if input.len() > MAX_EVENT_INTEREST_BYTES {
        return Err(NodeError::Protocol(format!(
            "Event interest exceeds {MAX_EVENT_INTEREST_BYTES} bytes"
        )));
    }
    let mut input = input;
    let count = usize::from(take_u16(&mut input, "Event interest selector count")?);
    if count > MAX_EVENT_INTEREST_SELECTORS {
        return Err(NodeError::Protocol(format!(
            "Event interest selector count exceeds {MAX_EVENT_INTEREST_SELECTORS}"
        )));
    }
    let mut selectors = Vec::with_capacity(count);
    for _ in 0..count {
        let topic = decode_event_topic(&mut input)?;
        let scope = decode_event_scope(&mut input)?;
        let include_descendant_scopes = match take_exact(&mut input, 1, "Event interest flags")?[0]
        {
            0 => false,
            1 => true,
            _ => {
                return Err(NodeError::Protocol(
                    "Event interest descendant flag is not boolean".into(),
                ));
            }
        };
        let selector = EventInterestSelector::new(topic, scope, include_descendant_scopes);
        if selectors
            .last()
            .is_some_and(|previous| previous >= &selector)
        {
            return Err(NodeError::Protocol(
                "Event interest selectors are not strictly canonical".into(),
            ));
        }
        selectors.push(selector);
    }
    if !input.is_empty() {
        return Err(NodeError::Protocol(
            "Event interest has trailing bytes".into(),
        ));
    }
    Ok(EventInterest(selectors))
}

fn decode_event_topic(input: &mut &[u8]) -> Result<Topic, NodeError> {
    let value = decode_event_name(input, "topic")?;
    Topic::new(value)
        .map_err(|_| NodeError::Protocol("Event interest topic is not canonical".into()))
}

fn decode_event_scope(input: &mut &[u8]) -> Result<Scope, NodeError> {
    let value = decode_event_name(input, "scope")?;
    Scope::new(value)
        .map_err(|_| NodeError::Protocol("Event interest scope is not canonical".into()))
}

fn decode_event_name(input: &mut &[u8], label: &str) -> Result<String, NodeError> {
    let length = usize::from(take_u16(input, "Event interest name length")?);
    if length == 0 || length > MAX_EVENT_NAME_BYTES {
        return Err(NodeError::Protocol(format!(
            "Event interest {label} length is outside 1..={MAX_EVENT_NAME_BYTES}"
        )));
    }
    let encoded = take_exact(input, length, "Event interest name")?;
    std::str::from_utf8(encoded)
        .map(str::to_owned)
        .map_err(|_| NodeError::Protocol(format!("Event interest {label} is not UTF-8")))
}

fn take_u16(input: &mut &[u8], label: &str) -> Result<u16, NodeError> {
    let bytes = take_exact(input, 2, label)?;
    Ok(u16::from_be_bytes(bytes.try_into().map_err(|_| {
        NodeError::Protocol(format!("{label} length differs"))
    })?))
}

fn take_exact<'a>(input: &mut &'a [u8], length: usize, label: &str) -> Result<&'a [u8], NodeError> {
    if input.len() < length {
        return Err(NodeError::Protocol(format!("{label} is truncated")));
    }
    let (head, tail) = input.split_at(length);
    *input = tail;
    Ok(head)
}

fn decode_direction(input: &[u8]) -> Result<(EventDirection, &[u8]), NodeError> {
    let Some((&direction, body)) = input.split_first() else {
        return Err(NodeError::Protocol("Event direction is missing".into()));
    };
    Ok((EventDirection::decode(direction)?, body))
}

fn decode_direction_only(input: &[u8]) -> Result<EventDirection, NodeError> {
    let (direction, body) = decode_direction(input)?;
    if !body.is_empty() {
        return Err(NodeError::Protocol(
            "directional Event control has trailing bytes".into(),
        ));
    }
    Ok(direction)
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

    fn selector(topic: &str, scope: &str, descendants: bool) -> EventInterestSelector {
        EventInterestSelector::new(
            Topic::new(topic).expect("topic"),
            Scope::new(scope).expect("scope"),
            descendants,
        )
    }

    #[test]
    fn every_frame_round_trips_and_rejects_trailing_bytes() {
        let id = EventTransferId::new([0x44; 32]);
        let control_id = ControlTransferId::new([0x55; 32]);
        let interest = EventInterest::new(vec![
            selector("zulu", "mission/bravo", true),
            selector("alpha", "mission/alpha", false),
        ])
        .expect("interest");
        let to_initiator = EventDirection::ToSessionInitiator;
        let to_responder = EventDirection::ToSessionResponder;
        let frames = [
            Frame::EventInterest(EventInterest::empty()),
            Frame::EventInterestReply(interest),
            Frame::InventoryQuery {
                direction: to_responder,
                bytes: vec![1, 2],
            },
            Frame::InventoryReply {
                direction: to_responder,
                bytes: vec![3, 4],
            },
            Frame::InventoryComplete {
                direction: to_responder,
            },
            Frame::InventoryCompleteAck {
                direction: to_responder,
            },
            Frame::DifferenceQuery {
                direction: to_responder,
                bytes: vec![5, 6],
            },
            Frame::DifferenceReply {
                direction: to_responder,
                bytes: vec![7, 8],
            },
            Frame::DifferenceBound {
                direction: to_responder,
            },
            Frame::DifferenceBoundAck {
                direction: to_responder,
            },
            Frame::Fetch {
                direction: to_initiator,
                id,
            },
            Frame::Object {
                direction: to_initiator,
                id,
                bytes: b"object".to_vec(),
            },
            Frame::Offer {
                direction: to_responder,
                id,
                bytes: b"offer".to_vec(),
            },
            Frame::ApplyResult {
                direction: to_responder,
                id,
                inserted: true,
            },
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
            Frame::Finish {
                direction: to_responder,
            },
            Frame::Finished {
                direction: to_initiator,
            },
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
                direction: EventDirection::ToSessionInitiator,
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
            let is_event = tag == OBJECT;
            let mut encoded = Vec::with_capacity(6 + 32 + 4 + oversized.len());
            encoded.extend_from_slice(MAGIC);
            encoded.push(tag);
            if is_event {
                encoded.push(EventDirection::ToSessionInitiator.encode());
            }
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
        encoded.push(EventDirection::ToSessionResponder.encode());
        encoded.extend_from_slice(
            &u32::try_from(oversized_reconciliation.len())
                .expect("reconciliation length")
                .to_be_bytes(),
        );
        encoded.extend_from_slice(&oversized_reconciliation);
        assert!(Frame::decode(&encoded).is_err());
    }

    #[test]
    fn interest_constructor_canonicalizes_and_empty_means_receive_none() {
        let alpha = selector("alpha", "mission/alpha", false);
        let descendants = selector("zulu", "mission/bravo", true);
        let interest = EventInterest::new(vec![descendants.clone(), alpha.clone(), alpha.clone()])
            .expect("canonical interest");
        assert_eq!(interest.selectors(), &[alpha, descendants]);
        assert_eq!(interest.len(), 2);
        assert!(!interest.is_empty());
        assert!(interest.matches(
            &Topic::new("zulu").expect("topic"),
            &Scope::new("mission/bravo/child").expect("scope")
        ));
        assert!(!interest.matches(
            &Topic::new("alpha").expect("topic"),
            &Scope::new("mission/alpha/child").expect("scope")
        ));

        let empty = EventInterest::empty();
        assert!(empty.is_empty());
        assert!(!empty.matches(
            &Topic::new("alpha").expect("topic"),
            &Scope::new("mission/alpha").expect("scope")
        ));
        let encoded = Frame::EventInterest(empty)
            .encode()
            .expect("empty interest");
        assert_eq!(
            Frame::decode(&encoded).expect("decode empty interest"),
            Frame::EventInterest(EventInterest::empty())
        );
    }

    #[test]
    fn interest_maximum_round_trips_and_constructor_rejects_cap_plus_one() {
        let selectors = (0..MAX_EVENT_INTEREST_SELECTORS)
            .map(|index| selector(&format!("topic-{index:03}"), "mission/maximum", false))
            .collect::<Vec<_>>();
        let interest = EventInterest::new(selectors.clone()).expect("maximum interest");
        assert_eq!(interest.len(), MAX_EVENT_INTEREST_SELECTORS);
        let frame = Frame::EventInterestReply(interest);
        assert_eq!(
            Frame::decode(&frame.encode().expect("encode maximum")).expect("decode maximum"),
            frame
        );

        let mut too_many = selectors;
        too_many.push(selector("topic-overflow", "mission/maximum", false));
        assert!(EventInterest::new(too_many).is_err());
    }

    #[test]
    fn interest_decode_rejects_noncanonical_malformed_and_oversized_input() {
        fn raw_selector(output: &mut Vec<u8>, topic: &[u8], scope: &[u8], descendants: u8) {
            output.extend_from_slice(
                &u16::try_from(topic.len())
                    .expect("topic length")
                    .to_be_bytes(),
            );
            output.extend_from_slice(topic);
            output.extend_from_slice(
                &u16::try_from(scope.len())
                    .expect("scope length")
                    .to_be_bytes(),
            );
            output.extend_from_slice(scope);
            output.push(descendants);
        }

        fn interest_frame(body: &[u8]) -> Vec<u8> {
            let mut frame = Vec::with_capacity(5 + body.len());
            frame.extend_from_slice(MAGIC);
            frame.push(EVENT_INTEREST);
            frame.extend_from_slice(body);
            frame
        }

        let mut duplicate = 2u16.to_be_bytes().to_vec();
        raw_selector(&mut duplicate, b"alpha", b"mission/alpha", 0);
        raw_selector(&mut duplicate, b"alpha", b"mission/alpha", 0);
        assert!(Frame::decode(&interest_frame(&duplicate)).is_err());

        let mut unsorted = 2u16.to_be_bytes().to_vec();
        raw_selector(&mut unsorted, b"zulu", b"mission/zulu", 0);
        raw_selector(&mut unsorted, b"alpha", b"mission/alpha", 0);
        assert!(Frame::decode(&interest_frame(&unsorted)).is_err());

        let mut invalid_flag = 1u16.to_be_bytes().to_vec();
        raw_selector(&mut invalid_flag, b"alpha", b"mission/alpha", 2);
        assert!(Frame::decode(&interest_frame(&invalid_flag)).is_err());

        let mut invalid_topic = 1u16.to_be_bytes().to_vec();
        raw_selector(&mut invalid_topic, b"bad/topic", b"mission/alpha", 0);
        assert!(Frame::decode(&interest_frame(&invalid_topic)).is_err());

        let mut truncated = 1u16.to_be_bytes().to_vec();
        truncated.extend_from_slice(&5u16.to_be_bytes());
        truncated.extend_from_slice(b"four");
        assert!(Frame::decode(&interest_frame(&truncated)).is_err());

        let mut trailing = Frame::EventInterest(EventInterest::empty())
            .encode()
            .expect("empty interest");
        trailing.push(0);
        assert!(Frame::decode(&trailing).is_err());

        let excessive_count = u16::try_from(MAX_EVENT_INTEREST_SELECTORS + 1)
            .expect("count")
            .to_be_bytes();
        assert!(Frame::decode(&interest_frame(&excessive_count)).is_err());

        let oversized = vec![0u8; MAX_EVENT_INTEREST_BYTES + 1];
        assert!(Frame::decode(&interest_frame(&oversized)).is_err());
    }

    #[test]
    fn every_event_lane_frame_requires_and_preserves_its_direction() {
        let id = EventTransferId::new([0x77; 32]);
        let direction = EventDirection::ToSessionResponder;
        let frames = [
            Frame::InventoryQuery {
                direction,
                bytes: vec![1],
            },
            Frame::InventoryReply {
                direction,
                bytes: vec![2],
            },
            Frame::InventoryComplete { direction },
            Frame::InventoryCompleteAck { direction },
            Frame::DifferenceQuery {
                direction,
                bytes: vec![3],
            },
            Frame::DifferenceReply {
                direction,
                bytes: vec![4],
            },
            Frame::DifferenceBound { direction },
            Frame::DifferenceBoundAck { direction },
            Frame::Fetch { direction, id },
            Frame::Object {
                direction,
                id,
                bytes: vec![5],
            },
            Frame::Offer {
                direction,
                id,
                bytes: vec![6],
            },
            Frame::ApplyResult {
                direction,
                id,
                inserted: false,
            },
            Frame::Finish { direction },
            Frame::Finished { direction },
        ];
        for frame in frames {
            let encoded = frame.encode().expect("directional encode");
            assert_eq!(encoded[5], direction.encode());
            assert_eq!(Frame::decode(&encoded).expect("directional decode"), frame);

            let mut missing = encoded.clone();
            missing.remove(5);
            assert!(Frame::decode(&missing).is_err());

            let mut unknown = encoded;
            unknown[5] = 3;
            assert!(Frame::decode(&unknown).is_err());
        }
    }
}
