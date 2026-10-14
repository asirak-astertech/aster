use super::*;

fn candidate(offset: u64) -> BlobRangeCandidate {
    BlobRangeCandidate {
        source: BlobTransferId::new([1; 32]),
        object: BlobCarrierObjectId::new([2; 33]).unwrap(),
        total_len: (2 * MAX_BLOB_NETWORK_RANGE_BYTES) as u64,
        offset,
        requested_len: MAX_BLOB_NETWORK_RANGE_BYTES as u32,
        proof: [3; crate::frame::BLOB_CONTENT_PROOF_BYTES],
    }
}

#[test]
fn schedule_rejects_duplicate_conflict_order_truncation_and_oversize() {
    let direction = EventDirection::ToSessionResponder;
    let first = candidate(0);
    let second = candidate(MAX_BLOB_NETWORK_RANGE_BYTES as u64);
    let encoded = encode_schedule(&[first, second], direction).unwrap();
    assert_eq!(decode_schedule(&encoded, direction).unwrap().len(), 2);
    for end in 0..encoded.len() {
        assert!(decode_schedule(&encoded[..end], direction).is_err());
    }
    let mut trailing = encoded.clone();
    trailing.push(0);
    assert!(decode_schedule(&trailing, direction).is_err());
    assert!(decode_schedule(&encoded, EventDirection::ToSessionInitiator).is_err());
    for ranges in [
        vec![first, first],
        vec![second, first],
        vec![
            first,
            BlobRangeCandidate {
                total_len: first.total_len + 1,
                ..second
            },
        ],
        vec![
            first,
            BlobRangeCandidate {
                source: BlobTransferId::new([4; 32]),
                ..second
            },
        ],
        vec![
            first,
            BlobRangeCandidate {
                proof: [4; crate::frame::BLOB_CONTENT_PROOF_BYTES],
                ..second
            },
        ],
    ] {
        assert!(decode_schedule(&encode_schedule(&ranges, direction).unwrap(), direction).is_err());
    }
    assert!(encode_schedule(&vec![first; MAX_RANGES + 1], direction).is_err());
    let mut excessive = REQUEST_PREFIX.to_vec();
    excessive.extend_from_slice(&u16::MAX.to_be_bytes());
    assert!(decode_schedule(&excessive, direction).is_err());
}

#[test]
fn terminal_binds_schedule_count_and_frame_kind() {
    let hash = schedule_hash(
        &encode_schedule(&[candidate(0)], EventDirection::ToSessionResponder).unwrap(),
    );
    let terminal = envelope(END_PREFIX, hash, 1);
    assert!(
        check_envelope(&terminal, END_PREFIX, hash, 1)
            .unwrap()
            .is_empty()
    );
    assert!(check_envelope(&terminal, DATA_PREFIX, hash, 1).is_err());
    assert!(check_envelope(&terminal, END_PREFIX, hash, 0).is_err());
    assert!(check_envelope(&terminal, END_PREFIX, [0; 32], 1).is_err());
    for end in 0..terminal.len() {
        assert!(check_envelope(&terminal[..end], END_PREFIX, hash, 1).is_err());
    }
}

#[test]
fn streaming_fits_original_one_range_boundary_and_preserves_reverse_and_bridge() {
    for direction in [
        EventDirection::ToSessionResponder,
        EventDirection::ToSessionInitiator,
    ] {
        let (future_exchanges, future_bytes) = future_blob_carrier_lane_reserve(direction);
        let reserve = ContactReserve {
            items: EVENT_BRIDGE_CONTACT_RESERVE_ITEMS,
            protected_frames: future_exchanges * EXCHANGE_FRAMES
                + EVENT_BRIDGE_CONTACT_RESERVE_FRAMES,
            protected_bytes: future_bytes + EVENT_BRIDGE_CONTACT_RESERVE_BYTES,
        };
        let receipt = PeerReceipt {
            protected_frames: MAX_CONTACT_FRAMES
                - reserve.protected_frames
                - BLOB_CARRIER_LANE_RESERVE_EXCHANGES * EXCHANGE_FRAMES,
            protected_bytes: MAX_CONTACT_BYTES
                - reserve.protected_bytes
                - BLOB_CARRIER_LANE_RESERVE_BYTES,
            ..PeerReceipt::default()
        };
        assert_eq!(capacity(&receipt, reserve).unwrap(), 1);
    }
    assert_eq!(BLOB_CARRIER_LANE_RESERVE_BYTES, 17_127);
    assert_eq!(BLOB_CARRIER_LANE_RESERVE_EXCHANGES, 3);
}
