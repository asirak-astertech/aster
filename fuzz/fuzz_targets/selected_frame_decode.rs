#![no_main]

use aster_redb_store::{ControlTransferId, EventTransferId};
use libfuzzer_sys::fuzz_target;

const TAGS: [u8; 30] = [
    0x09, 0x0a, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x21, 0x22, 0x23, 0x24, 0x31, 0x32,
    0x41, 0x42, 0x43, 0x44, 0x45, 0x46, 0x47, 0x48, 0x51, 0x52, 0x53, 0x54, 0x61, 0x62,
];

fn structured_transfer_id(payload: &[u8]) -> EventTransferId {
    let mut bytes = [0u8; 32];
    let copied = payload.len().min(bytes.len());
    bytes[..copied].copy_from_slice(&payload[..copied]);
    EventTransferId::new(bytes)
}

fn structured_control_id(payload: &[u8]) -> ControlTransferId {
    let mut bytes = [0u8; 32];
    let copied = payload.len().min(bytes.len());
    bytes[..copied].copy_from_slice(&payload[..copied]);
    ControlTransferId::new(bytes)
}

fn structured_candidate(input: &[u8]) -> Vec<u8> {
    let (selector, payload) = input.split_first().unwrap_or((&0, &[]));
    let tag = TAGS[usize::from(*selector) % TAGS.len()];
    let event_direction = 1 + (selector & 1);
    let mut candidate = b"ASM\x01".to_vec();
    candidate.push(tag);
    match tag {
        0x09 | 0x0a => candidate.extend_from_slice(&0u16.to_be_bytes()),
        0x11 | 0x12 | 0x15 | 0x16 => {
            candidate.push(event_direction);
            candidate.extend_from_slice(
                &u32::try_from(payload.len())
                    .expect("fuzzer input length fits in u32")
                    .to_be_bytes(),
            );
            candidate.extend_from_slice(payload);
        }
        0x41 | 0x42 | 0x45 | 0x46 => {
            candidate.extend_from_slice(
                &u32::try_from(payload.len())
                    .expect("fuzzer input length fits in u32")
                    .to_be_bytes(),
            );
            candidate.extend_from_slice(payload);
        }
        0x13 | 0x14 | 0x17 | 0x18 | 0x31 | 0x32 => candidate.push(event_direction),
        0x21 => {
            candidate.push(event_direction);
            candidate.extend_from_slice(structured_transfer_id(payload).as_bytes());
        }
        0x22 | 0x23 => {
            candidate.push(event_direction);
            candidate.extend_from_slice(structured_transfer_id(payload).as_bytes());
            let object = payload.get(32..).unwrap_or_default();
            candidate.extend_from_slice(
                &u32::try_from(object.len())
                    .expect("fuzzer input length fits in u32")
                    .to_be_bytes(),
            );
            candidate.extend_from_slice(object);
        }
        0x24 => {
            candidate.push(event_direction);
            candidate.extend_from_slice(structured_transfer_id(payload).as_bytes());
            candidate.push(selector & 1);
        }
        0x51 => candidate.extend_from_slice(structured_control_id(payload).as_bytes()),
        0x52 | 0x53 => {
            candidate.extend_from_slice(structured_control_id(payload).as_bytes());
            let object = payload.get(32..).unwrap_or_default();
            candidate.extend_from_slice(
                &u32::try_from(object.len())
                    .expect("fuzzer input length fits in u32")
                    .to_be_bytes(),
            );
            candidate.extend_from_slice(object);
        }
        0x54 => {
            candidate.extend_from_slice(structured_control_id(payload).as_bytes());
            candidate.push(selector & 1);
        }
        0x43 | 0x44 | 0x47 | 0x48 | 0x61 | 0x62 => {}
        _ => unreachable!("tag selected from the complete fixed table"),
    }
    candidate
}

fuzz_target!(|input: &[u8]| {
    let _accepted = aster_node::fuzz_decode_mechanics_frame(input);
    assert!(aster_node::fuzz_decode_mechanics_frame(
        &structured_candidate(input)
    ));
});
