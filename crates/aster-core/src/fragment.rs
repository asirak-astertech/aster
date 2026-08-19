//! Link-neutral fragmentation for very small MTUs.

use std::collections::BTreeMap;
use std::error::Error;
use std::fmt::{self, Display, Formatter};

/// Bytes used by the compact fragment header.
pub const HEADER_LEN: usize = 16;

/// Maximum accepted reassembled control/object chunk size.
pub const MAX_MESSAGE_LEN: usize = 1_048_576;

const MAGIC: [u8; 2] = *b"AM";

/// A validated fragment.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Fragment {
    /// Per-message random or monotonic transfer identifier.
    pub transfer_id: u64,
    /// Zero-based fragment index.
    pub index: u16,
    /// Total fragments in this message.
    pub count: u16,
    /// Fragment payload.
    pub payload: Vec<u8>,
}

/// Fragment parsing or assembly failure.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum FragmentError {
    /// MTU cannot fit the header plus one payload byte.
    MtuTooSmall,
    /// The message exceeds the bounded in-memory object-chunk limit.
    MessageTooLarge,
    /// More than 65,535 fragments would be required.
    TooManyFragments,
    /// Frame header or lengths are invalid.
    Malformed,
    /// A transfer reused an index with different bytes or changed its count.
    Inconsistent,
}

impl Display for FragmentError {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
        write!(formatter, "{self:?}")
    }
}

impl Error for FragmentError {}

impl Fragment {
    /// Encodes a fragment into its compact link representation.
    pub fn encode(&self) -> Result<Vec<u8>, FragmentError> {
        if self.count == 0 || self.index >= self.count || self.payload.len() > u16::MAX as usize {
            return Err(FragmentError::Malformed);
        }
        let mut frame = Vec::with_capacity(HEADER_LEN + self.payload.len());
        frame.extend_from_slice(&MAGIC);
        frame.extend_from_slice(&self.transfer_id.to_be_bytes());
        frame.extend_from_slice(&self.index.to_be_bytes());
        frame.extend_from_slice(&self.count.to_be_bytes());
        frame.extend_from_slice(&(self.payload.len() as u16).to_be_bytes());
        frame.extend_from_slice(&self.payload);
        Ok(frame)
    }

    /// Parses and validates a compact link fragment.
    pub fn decode(frame: &[u8]) -> Result<Self, FragmentError> {
        if frame.len() < HEADER_LEN || frame[..2] != MAGIC {
            return Err(FragmentError::Malformed);
        }
        let transfer_id = u64::from_be_bytes(frame[2..10].try_into().unwrap());
        let index = u16::from_be_bytes(frame[10..12].try_into().unwrap());
        let count = u16::from_be_bytes(frame[12..14].try_into().unwrap());
        let payload_len = usize::from(u16::from_be_bytes(frame[14..16].try_into().unwrap()));
        if count == 0 || index >= count || frame.len() != HEADER_LEN + payload_len {
            return Err(FragmentError::Malformed);
        }
        Ok(Self {
            transfer_id,
            index,
            count,
            payload: frame[HEADER_LEN..].to_vec(),
        })
    }
}

/// Splits a bounded message into fragments for a particular link MTU.
pub fn fragment(
    message: &[u8],
    mtu: usize,
    transfer_id: u64,
) -> Result<Vec<Fragment>, FragmentError> {
    if mtu <= HEADER_LEN {
        return Err(FragmentError::MtuTooSmall);
    }
    if message.len() > MAX_MESSAGE_LEN {
        return Err(FragmentError::MessageTooLarge);
    }
    let payload_size = mtu - HEADER_LEN;
    let count = message.len().max(1).div_ceil(payload_size);
    if count > u16::MAX as usize {
        return Err(FragmentError::TooManyFragments);
    }
    let count = count as u16;
    if message.is_empty() {
        return Ok(vec![Fragment {
            transfer_id,
            index: 0,
            count,
            payload: Vec::new(),
        }]);
    }
    Ok(message
        .chunks(payload_size)
        .enumerate()
        .map(|(index, payload)| Fragment {
            transfer_id,
            index: index as u16,
            count,
            payload: payload.to_vec(),
        })
        .collect())
}

/// Bounded, duplicate-safe out-of-order reassembly state.
#[derive(Debug)]
pub struct Reassembler {
    transfers: BTreeMap<u64, PartialTransfer>,
    max_transfers: usize,
    max_buffered_bytes: usize,
    buffered_bytes: usize,
}

impl Default for Reassembler {
    fn default() -> Self {
        Self::new(64)
    }
}

#[derive(Debug)]
struct PartialTransfer {
    count: u16,
    parts: BTreeMap<u16, Vec<u8>>,
    bytes: usize,
}

impl Reassembler {
    /// Creates a reassembler with an explicit concurrency bound.
    pub fn new(max_transfers: usize) -> Self {
        Self::with_budget(
            max_transfers,
            max_transfers.max(1).saturating_mul(MAX_MESSAGE_LEN),
        )
    }

    /// Creates a reassembler with both concurrency and aggregate-memory bounds.
    pub fn with_budget(max_transfers: usize, max_buffered_bytes: usize) -> Self {
        Self {
            transfers: BTreeMap::new(),
            max_transfers: max_transfers.max(1),
            max_buffered_bytes: max_buffered_bytes.max(1),
            buffered_bytes: 0,
        }
    }

    /// Adds a fragment. Duplicate fragments are harmless. Completion removes and
    /// returns the assembled message.
    pub fn push(&mut self, fragment: Fragment) -> Result<Option<Vec<u8>>, FragmentError> {
        if !self.transfers.contains_key(&fragment.transfer_id)
            && self.transfers.len() >= self.max_transfers
        {
            return Err(FragmentError::MessageTooLarge);
        }
        let transfer = self
            .transfers
            .entry(fragment.transfer_id)
            .or_insert_with(|| PartialTransfer {
                count: fragment.count,
                parts: BTreeMap::new(),
                bytes: 0,
            });
        if transfer.count != fragment.count {
            return Err(FragmentError::Inconsistent);
        }
        if let Some(existing) = transfer.parts.get(&fragment.index) {
            return if existing == &fragment.payload {
                Ok(None)
            } else {
                Err(FragmentError::Inconsistent)
            };
        }
        let next_buffered = self
            .buffered_bytes
            .checked_add(fragment.payload.len())
            .ok_or(FragmentError::MessageTooLarge)?;
        if next_buffered > self.max_buffered_bytes {
            if let Some(removed) = self.transfers.remove(&fragment.transfer_id) {
                self.buffered_bytes = self.buffered_bytes.saturating_sub(removed.bytes);
            }
            return Err(FragmentError::MessageTooLarge);
        }
        let next_transfer_bytes = transfer
            .bytes
            .checked_add(fragment.payload.len())
            .ok_or(FragmentError::MessageTooLarge)?;
        if next_transfer_bytes > MAX_MESSAGE_LEN {
            if let Some(removed) = self.transfers.remove(&fragment.transfer_id) {
                self.buffered_bytes = self.buffered_bytes.saturating_sub(removed.bytes);
            }
            return Err(FragmentError::MessageTooLarge);
        }
        transfer.bytes = next_transfer_bytes;
        self.buffered_bytes = next_buffered;
        transfer.parts.insert(fragment.index, fragment.payload);
        if transfer.parts.len() != usize::from(transfer.count) {
            return Ok(None);
        }
        let completed = self.transfers.remove(&fragment.transfer_id).unwrap();
        self.buffered_bytes = self.buffered_bytes.saturating_sub(completed.bytes);
        let mut message = Vec::with_capacity(completed.bytes);
        for index in 0..completed.count {
            message.extend_from_slice(
                completed
                    .parts
                    .get(&index)
                    .ok_or(FragmentError::Malformed)?,
            );
        }
        Ok(Some(message))
    }
}

#[cfg(test)]
mod tests {
    use super::{Fragment, Reassembler, fragment};

    #[test]
    fn works_at_a_tiny_mtu_and_out_of_order() {
        let message = b"a payload crossing a constrained tactical link";
        let mut parts = fragment(message, 24, 9).unwrap();
        assert!(parts.len() > 1);
        parts.reverse();
        let mut reassembler = Reassembler::new(2);
        let mut result = None;
        for part in parts {
            let wire = part.encode().unwrap();
            result = reassembler
                .push(Fragment::decode(&wire).unwrap())
                .unwrap()
                .or(result);
        }
        assert_eq!(result.as_deref(), Some(message.as_slice()));
    }

    #[test]
    fn duplicate_is_harmless() {
        let part = fragment(b"small", 32, 1).unwrap().remove(0);
        let mut reassembler = Reassembler::new(1);
        assert_eq!(
            reassembler.push(part.clone()).unwrap(),
            Some(b"small".to_vec())
        );
        assert_eq!(reassembler.push(part).unwrap(), Some(b"small".to_vec()));
    }

    #[test]
    fn aggregate_partial_memory_is_bounded() {
        let first = Fragment {
            transfer_id: 1,
            index: 0,
            count: 2,
            payload: vec![1; 8],
        };
        let second = Fragment {
            transfer_id: 2,
            index: 0,
            count: 2,
            payload: vec![2; 8],
        };
        let mut reassembler = Reassembler::with_budget(4, 12);
        assert!(reassembler.push(first).unwrap().is_none());
        assert!(matches!(
            reassembler.push(second),
            Err(super::FragmentError::MessageTooLarge)
        ));
    }
}
