//! Selected-stack Aster node composition.
//!
//! The selected runtime composes a mission-authenticated Iroh carrier, bounded
//! Negentropy reconciliation, mission-bound redb state, and the existing
//! `aster-core` source-authenticated Event semantics. Its stopped-state
//! application boundary also composes source-authenticated latest-value State,
//! explicit-conflict Record, and streaming immutable Blob operations. State and
//! Record additionally use class-specific, explicitly interested reconciliation
//! lanes; Blob remains local. The State and Record application handles remain
//! stopped/exclusive even though their durable objects can cross a live contact.
//! The caller-identified opaque API remains isolated for compatibility and is
//! not advertised by the production Event reconciliation path.

#![forbid(unsafe_code)]

pub mod application;
mod frame;
mod identity;
pub mod mission;
mod runtime;

pub use identity::{IdentityError, NodeIdentity};
pub use runtime::{
    ControlPublicationReceipt, DemoScenario, MissionExpectedPeer, MutableSourceInterests,
    NodeApplication, NodeConfig, NodeError, NodeReceipt, PeerReceipt, RunningNode,
    SoftwareZeroizationPathState, SoftwareZeroizationReceipt, SoftwareZeroizationState,
    SourceInterestSelector, StoreReceipt, ensure_state_accepts_normal_operation,
    format_control_transfer_id, inspect_store, publish_revocation_control,
    publish_scope_rekey_control, put_opaque, run_demo, run_demo_scenario, run_node, start_node,
    zeroize_node,
};

use aster_mesh::NodeId;
use aster_profile::ItemId;

/// Parses a complete lowercase or uppercase hexadecimal item identifier.
pub fn parse_item_id(value: &str) -> Result<ItemId, NodeError> {
    parse_hex_32(value, "item").map(ItemId::new)
}

/// Formats a complete item identifier as lowercase hexadecimal.
pub fn format_item_id(id: ItemId) -> String {
    let mut output = String::with_capacity(64);
    for byte in id.as_bytes() {
        use std::fmt::Write as _;
        let _ = write!(&mut output, "{byte:02x}");
    }
    output
}

/// Parses a complete hexadecimal mission NodeId without accepting short forms.
pub fn parse_node_id(value: &str) -> Result<NodeId, NodeError> {
    parse_hex_32(value, "mission node")
}

/// Formats the complete independently authenticated mission NodeId.
pub fn format_node_id(id: NodeId) -> String {
    format_hex_32(&id)
}

fn parse_hex_32(value: &str, label: &str) -> Result<[u8; 32], NodeError> {
    let encoded = value.as_bytes();
    if encoded.len() != 64 {
        return Err(NodeError::Configuration(format!(
            "{label} identifier must contain exactly 64 hexadecimal characters"
        )));
    }
    let mut bytes = [0u8; 32];
    for (pair, output) in encoded.chunks_exact(2).zip(&mut bytes) {
        let high = hex_nibble(pair[0]).ok_or_else(|| {
            NodeError::Configuration(format!("{label} identifier is not hexadecimal"))
        })?;
        let low = hex_nibble(pair[1]).ok_or_else(|| {
            NodeError::Configuration(format!("{label} identifier is not hexadecimal"))
        })?;
        *output = (high << 4) | low;
    }
    Ok(bytes)
}

const fn hex_nibble(byte: u8) -> Option<u8> {
    match byte {
        b'0'..=b'9' => Some(byte - b'0'),
        b'a'..=b'f' => Some(byte - b'a' + 10),
        b'A'..=b'F' => Some(byte - b'A' + 10),
        _ => None,
    }
}

/// Encodes a path as one delimiter-safe structured receipt field.
pub fn format_path_field(path: &std::path::Path) -> String {
    #[cfg(unix)]
    {
        use std::os::unix::ffi::OsStrExt as _;
        format_receipt_bytes(path.as_os_str().as_bytes())
    }
    #[cfg(not(unix))]
    {
        format_receipt_bytes(path.to_string_lossy().as_bytes())
    }
}

/// Encodes arbitrary text as one delimiter-safe structured receipt field.
pub fn format_receipt_field(value: &str) -> String {
    format_receipt_bytes(value.as_bytes())
}

fn format_receipt_bytes(bytes: &[u8]) -> String {
    let mut output = String::with_capacity(bytes.len());
    for byte in bytes {
        if byte.is_ascii_alphanumeric() || matches!(*byte, b'-' | b'_' | b'.' | b'/' | b':') {
            output.push(char::from(*byte));
        } else {
            use std::fmt::Write as _;
            let _ = write!(&mut output, "%{byte:02X}");
        }
    }
    output
}

fn format_hex_32(bytes: &[u8; 32]) -> String {
    let mut output = String::with_capacity(64);
    for byte in bytes {
        use std::fmt::Write as _;
        let _ = write!(&mut output, "{byte:02x}");
    }
    output
}

/// Exercises the selected-stack mechanics-frame decoder for hostile-input fuzzing.
///
/// This deliberately returns only an accepted/rejected disposition. Accepted
/// frames are also required to survive a canonical encode/decode round trip.
/// The opt-in API carries no protocol, mission-security, or semantic credit.
#[cfg(feature = "fuzzing")]
#[doc(hidden)]
pub fn fuzz_decode_mechanics_frame(input: &[u8]) -> bool {
    let Ok(frame) = frame::Frame::decode(input) else {
        return false;
    };
    let canonical = frame
        .encode()
        .expect("an accepted mechanics frame must re-encode");
    assert_eq!(canonical.as_slice(), input);
    assert_eq!(
        frame::Frame::decode(&canonical).expect("canonical mechanics frame must decode"),
        frame
    );
    true
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn item_id_text_round_trips_without_short_forms() {
        let id = ItemId::new([0xab; 32]);
        let text = format_item_id(id);
        assert_eq!(text.len(), 64);
        assert_eq!(parse_item_id(&text).expect("parse"), id);
        assert!(parse_item_id("ab").is_err());
    }

    #[test]
    fn mission_node_id_text_round_trips_without_short_forms() {
        let id = [0xcd; 32];
        let text = format_node_id(id);
        assert_eq!(text.len(), 64);
        assert_eq!(parse_node_id(&text).expect("parse"), id);
        assert!(parse_node_id("cd").is_err());
    }

    #[test]
    fn non_ascii_hex_and_receipt_control_characters_fail_closed() {
        let mut hostile = "0".repeat(61);
        hostile.push('€');
        assert_eq!(hostile.len(), 64);
        assert!(parse_item_id(&hostile).is_err());
        assert!(parse_node_id(&hostile).is_err());
        assert_eq!(
            format_path_field(std::path::Path::new("safe/line\nfield=value%")),
            "safe/line%0Afield%3Dvalue%25"
        );
    }
}
