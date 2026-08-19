//! Self-conformance vector and invariant runner for the Aster protocol.
//!
//! Canonical wire vectors are emitted by the current `aster-core` encoder.
//! They detect regressions within this implementation; they are not an
//! independent protocol oracle.

use std::env;
use std::process::ExitCode;

use aster_mesh::batch::conformance as batch_conformance;
use aster_mesh::causal::{CausalOrder, compare};
use aster_mesh::fragment::{Fragment, Reassembler, fragment};
use aster_mesh::inventory::SparseInventory;
use aster_mesh::model::{Dot, VersionVector};
use aster_mesh::wire::{
    ByteRange, ChildSummary, Data, Interest, Limits, Message, Node, ObjectId, ObjectKind, Offer,
    Probe, Receipt, Summary, Value, Want, WantItem, decode_message, decode_value, encode_message,
    encode_value,
};

const GOLDEN_INTEREST: &[u8] = &[
    0xa7, 0x00, 0x01, 0x01, 0x01, 0x02, 0x07, 0x03, 0x81, 0x61, 0x61, 0x04, 0x81, 0x61, 0x73, 0x05,
    0x02, 0x06, 0x0a,
];

struct Check {
    id: &'static str,
    passed: bool,
    detail: String,
}

impl Check {
    fn pass(id: &'static str) -> Self {
        Self {
            id,
            passed: true,
            detail: "ok".into(),
        }
    }

    fn fail(id: &'static str, detail: impl Into<String>) -> Self {
        Self {
            id,
            passed: false,
            detail: detail.into(),
        }
    }
}

fn main() -> ExitCode {
    let args: Vec<String> = env::args().skip(1).collect();
    match args.as_slice() {
        [flag] if flag == "--self-test" => self_test(),
        [flag] if flag == "--emit-vectors" => emit_vectors(),
        [flag] if flag == "--emit-batch-vectors" => emit_batch_vectors(),
        [flag, encoded] if flag == "--check-wire-hex" => check_wire_hex(encoded),
        [] | [_] => {
            eprintln!(
                "usage: aster-conformance --self-test | --emit-vectors | --emit-batch-vectors | --check-wire-hex HEX"
            );
            ExitCode::from(2)
        }
        _ => {
            eprintln!("invalid arguments");
            ExitCode::from(2)
        }
    }
}

fn self_test() -> ExitCode {
    let checks = [
        check_golden_wire(),
        check_all_message_kinds(),
        check_decoder_rejections(),
        check_wire_corpus(),
        check_batch_corpus(),
        check_batch_overhead(),
        check_batch_semantic_gate(),
        check_resource_bounds(),
        check_merkle_difference(),
        check_tiny_mtu_resume(),
        check_causal_concurrency(),
    ];
    let passed = checks.iter().all(|check| check.passed);

    println!(
        "{{\"schema\":\"aster-conformance-result/v1\",\"protocol\":{},\"oracle\":\"self\",\"result\":\"{}\",\"checks\":[",
        aster_mesh::PROTOCOL_VERSION,
        if passed { "pass" } else { "fail" }
    );
    for (index, check) in checks.iter().enumerate() {
        let comma = if index + 1 == checks.len() { "" } else { "," };
        println!(
            "{{\"id\":\"{}\",\"result\":\"{}\",\"detail\":\"{}\"}}{}",
            check.id,
            if check.passed { "pass" } else { "fail" },
            json_escape(&check.detail),
            comma
        );
    }
    println!("]}}");

    if passed {
        ExitCode::SUCCESS
    } else {
        ExitCode::FAILURE
    }
}

fn check_batch_corpus() -> Check {
    let document = match batch_conformance::vector_document() {
        Ok(document) => document,
        Err(error) => return Check::fail("V-BATCH-CORPUS", error),
    };
    match batch_conformance::verify_vector_document(&document) {
        Ok((canonical, structural_unverified, pending, rejected)) => Check {
            id: "V-BATCH-CORPUS",
            passed: true,
            detail: format!(
                "{canonical} canonical components, {structural_unverified} structural-unverified, {pending} proof-dependent pending, and {rejected} rejected vectors; sha256={} (no authenticated ACCEPT disposition)",
                batch_conformance::VECTOR_DOCUMENT_SHA256_HEX
            ),
        },
        Err(error) => Check::fail("V-BATCH-CORPUS", error),
    }
}

fn check_batch_overhead() -> Check {
    match batch_conformance::verify_overhead_claims() {
        Ok(detail) => Check {
            id: "V-BATCH-OVERHEAD",
            passed: true,
            detail,
        },
        Err(error) => Check::fail("V-BATCH-OVERHEAD", error),
    }
}

fn check_batch_semantic_gate() -> Check {
    let proof_id = ObjectId::new(ObjectKind::SourceBatchProof, [0xb3; 32]);
    if ObjectId::from_wire_bytes(proof_id.to_wire_bytes()) != Some(proof_id) {
        return Check::fail(
            "V-BATCH-SEMANTIC-GATE",
            "ObjectKind 3 registry round-trip failed",
        );
    }
    let v1_message = Message::Offer(Offer {
        exchange_id: 1,
        object_ids: vec![proof_id],
        snapshot_id: 9,
    });
    if encode_message(&v1_message, Limits::default()).is_ok() {
        return Check::fail(
            "V-BATCH-SEMANTIC-GATE",
            "semantic-v1 encoder accepted ObjectKind 3",
        );
    }
    let raw_v2_offer = raw_message(
        5,
        [
            (
                3,
                Value::Array(vec![raw_object_id(ObjectKind::SourceBatchProof, 0xb3)]),
            ),
            (4, Value::Unsigned(9)),
        ],
    );
    let raw_v2_offer = match encode_value(&raw_v2_offer, Limits::default()) {
        Ok(bytes) => bytes,
        Err(error) => {
            return Check::fail(
                "V-BATCH-SEMANTIC-GATE",
                format!("raw semantic-v2 kind-3 Offer did not encode: {error}"),
            );
        }
    };
    if decode_message(&raw_v2_offer, Limits::default()).is_ok() {
        return Check::fail(
            "V-BATCH-SEMANTIC-GATE",
            "semantic-v1 decoder accepted raw semantic-v2 kind-3 CBOR",
        );
    }
    if let Err(error) = batch_conformance::verify_semantic_v1_envelope_rejection() {
        return Check::fail("V-BATCH-SEMANTIC-GATE", error);
    }
    Check {
        id: "V-BATCH-SEMANTIC-GATE",
        passed: true,
        detail: "semantic-v1 receive decoders reject raw kind-3 CBOR and raw ASTRENV3; semantic-v2 proof structures remain explicitly crypto-unverified in V-BATCH-CORPUS".into(),
    }
}

fn check_golden_wire() -> Check {
    let message = interest_message();
    match encode_message(&message, Limits::default()) {
        Ok(bytes) if bytes == GOLDEN_INTEREST => match decode_message(&bytes, Limits::default()) {
            Ok(decoded) if decoded == message => Check::pass("V-WIRE-GOLDEN"),
            Ok(_) => Check::fail("V-WIRE-GOLDEN", "decoded value differs"),
            Err(error) => Check::fail("V-WIRE-GOLDEN", format!("decode: {error}")),
        },
        Ok(bytes) => Check::fail(
            "V-WIRE-GOLDEN",
            format!(
                "expected {}, got {}",
                to_hex(GOLDEN_INTEREST),
                to_hex(&bytes)
            ),
        ),
        Err(error) => Check::fail("V-WIRE-GOLDEN", format!("encode: {error}")),
    }
}

fn check_all_message_kinds() -> Check {
    for (name, message) in canonical_messages() {
        let encoded = match encode_message(&message, Limits::default()) {
            Ok(encoded) => encoded,
            Err(error) => {
                return Check::fail("V-WIRE-REGISTRY", format!("{name} encode: {error}"));
            }
        };
        match decode_message(&encoded, Limits::default()) {
            Ok(decoded) if decoded == message => {}
            Ok(_) => return Check::fail("V-WIRE-REGISTRY", format!("{name} changed")),
            Err(error) => {
                return Check::fail("V-WIRE-REGISTRY", format!("{name} decode: {error}"));
            }
        }
    }
    Check::pass("V-WIRE-REGISTRY")
}

fn check_decoder_rejections() -> Check {
    let invalid = [
        &[0x18, 0x17][..],
        &[0x9f, 0xff][..],
        &[0xa2, 0x00, 0x01, 0x00, 0x02][..],
        &[0xa2, 0x01, 0x01, 0x00, 0x02][..],
    ];
    if invalid
        .iter()
        .any(|bytes| decode_value(bytes, Limits::default()).is_ok())
    {
        return Check::fail("V-WIRE-NEGATIVE", "invalid deterministic CBOR accepted");
    }

    let unknown_critical = [0xa4, 0x00, 0x01, 0x01, 0x02, 0x02, 0x01, 0x18, 0x3f, 0x00];
    if decode_message(&unknown_critical, Limits::default()).is_ok() {
        return Check::fail("V-WIRE-NEGATIVE", "unknown critical field accepted");
    }
    let invalid_ids = match invalid_object_id_vectors() {
        Ok(vectors) => vectors,
        Err(error) => return Check::fail("V-WIRE-NEGATIVE", error),
    };
    for (name, bytes) in invalid_ids {
        if decode_message(&bytes, Limits::default()).is_ok() {
            return Check::fail("V-WIRE-NEGATIVE", format!("{name} accepted"));
        }
    }
    Check::pass("V-WIRE-NEGATIVE")
}

fn check_wire_corpus() -> Check {
    let document = match vector_document() {
        Ok(document) => document,
        Err(error) => return Check::fail("V-WIRE-CORPUS", error),
    };
    match verify_vector_document(&document) {
        Ok((accepted, rejected)) => Check {
            id: "V-WIRE-CORPUS",
            passed: true,
            detail: format!("{accepted} accepted and {rejected} rejected vectors"),
        },
        Err(error) => Check::fail("V-WIRE-CORPUS", error),
    }
}

fn check_resource_bounds() -> Check {
    let shallow = Limits {
        max_depth: 1,
        ..Limits::default()
    };
    let tiny = Limits {
        max_byte_string: 2,
        ..Limits::default()
    };
    if decode_value(&[0x81, 0x81, 0x00], shallow).is_ok()
        || decode_value(&[0x43, 1, 2, 3], tiny).is_ok()
    {
        Check::fail("V-WIRE-BOUNDS", "decoder allocation bound was bypassed")
    } else {
        Check::pass("V-WIRE-BOUNDS")
    }
}

fn check_merkle_difference() -> Check {
    let first = ObjectId::new(ObjectKind::SourceEnvelope, [0x11; 32]);
    let shared = ObjectId::new(ObjectKind::BlobChunk, [0x22; 32]);
    let second = ObjectId::new(ObjectKind::SourceEnvelope, [0x33; 32]);
    let left = SparseInventory::from_ids([first, shared]);
    let right = SparseInventory::from_ids([shared, second]);
    let difference = left.difference(&right);
    if difference.only_left == vec![first]
        && difference.only_right == vec![second]
        && left.root_hash() != right.root_hash()
    {
        Check::pass("V-MERKLE-DIFFERENCE")
    } else {
        Check::fail("V-MERKLE-DIFFERENCE", "difference was not exact")
    }
}

fn check_tiny_mtu_resume() -> Check {
    let message = b"a payload crossing a constrained tactical link";
    let mut parts = match fragment(message, 24, 9) {
        Ok(parts) => parts,
        Err(error) => return Check::fail("V-FRAG-TINY-MTU", error.to_string()),
    };
    parts.reverse();
    let mut reassembler = Reassembler::new(2);
    let mut result = None;
    for part in parts {
        let encoded = match part.encode() {
            Ok(encoded) => encoded,
            Err(error) => return Check::fail("V-FRAG-TINY-MTU", error.to_string()),
        };
        let decoded = match Fragment::decode(&encoded) {
            Ok(decoded) => decoded,
            Err(error) => return Check::fail("V-FRAG-TINY-MTU", error.to_string()),
        };
        match reassembler.push(decoded) {
            Ok(Some(completed)) => result = Some(completed),
            Ok(None) => {}
            Err(error) => return Check::fail("V-FRAG-TINY-MTU", error.to_string()),
        }
    }
    if result.as_deref() == Some(message.as_slice()) {
        Check::pass("V-FRAG-TINY-MTU")
    } else {
        Check::fail("V-FRAG-TINY-MTU", "out-of-order reassembly changed bytes")
    }
}

fn check_causal_concurrency() -> Check {
    let mut left = VersionVector::default();
    left.observe(Dot {
        publisher: [0x0a; 32],
        counter: 2,
    });
    let mut right = VersionVector::default();
    right.observe(Dot {
        publisher: [0x0b; 32],
        counter: 1,
    });
    if compare(&left, &right) == CausalOrder::Concurrent {
        Check::pass("V-CAUSAL-CONCURRENT")
    } else {
        Check::fail("V-CAUSAL-CONCURRENT", "concurrent edits were ordered")
    }
}

fn emit_vectors() -> ExitCode {
    match vector_document() {
        Ok(document) => {
            print!("{document}");
            ExitCode::SUCCESS
        }
        Err(error) => {
            eprintln!("could not emit self-conformance vectors: {error}");
            ExitCode::FAILURE
        }
    }
}

fn emit_batch_vectors() -> ExitCode {
    match batch_conformance::vector_document() {
        Ok(document) => {
            print!("{document}");
            ExitCode::SUCCESS
        }
        Err(error) => {
            eprintln!("could not emit batch conformance vectors: {error}");
            ExitCode::FAILURE
        }
    }
}

fn check_wire_hex(encoded: &str) -> ExitCode {
    let bytes = match from_hex(encoded) {
        Ok(bytes) => bytes,
        Err(error) => {
            eprintln!("invalid hex: {error}");
            return ExitCode::from(2);
        }
    };
    let value = match decode_value(&bytes, Limits::default()) {
        Ok(value) => value,
        Err(error) => {
            eprintln!("wire rejection: {error}");
            return ExitCode::FAILURE;
        }
    };
    let canonical = match encode_value(&value, Limits::default()) {
        Ok(canonical) if canonical == bytes => canonical,
        Ok(canonical) => {
            eprintln!("non-canonical; canonical={}", to_hex(&canonical));
            return ExitCode::FAILURE;
        }
        Err(error) => {
            eprintln!("wire rejection: {error}");
            return ExitCode::FAILURE;
        }
    };
    let message = match decode_message(&canonical, Limits::default()) {
        Ok(message) => message,
        Err(error) => {
            eprintln!("wire rejection: {error}");
            return ExitCode::FAILURE;
        }
    };
    println!(
        "ACCEPT\texchange={}\t{}",
        message.exchange_id(),
        to_hex(&canonical)
    );
    ExitCode::SUCCESS
}

fn canonical_messages() -> Vec<(&'static str, Message)> {
    let hash_a = [0x11; 32];
    let hash_b = [0x22; 32];
    let source_id = ObjectId::new(ObjectKind::SourceEnvelope, hash_a);
    let blob_id = ObjectId::new(ObjectKind::BlobChunk, hash_b);
    vec![
        ("interest", interest_message()),
        (
            "summary",
            Message::Summary(Summary {
                exchange_id: 1,
                root_hash: hash_a,
                item_count: 2,
                snapshot_id: 9,
            }),
        ),
        (
            "probe",
            Message::Probe(Probe {
                exchange_id: 1,
                prefix: vec![0xa0],
                prefix_nibbles: 1,
                snapshot_id: 9,
            }),
        ),
        (
            "node",
            Message::Node(Node {
                exchange_id: 1,
                prefix: vec![],
                prefix_nibbles: 0,
                hash: hash_b,
                item_count: 2,
                children: vec![ChildSummary {
                    nibble: 1,
                    hash: hash_a,
                    item_count: 2,
                }],
                snapshot_id: 9,
            }),
        ),
        (
            "offer",
            Message::Offer(Offer {
                exchange_id: 1,
                object_ids: vec![source_id, blob_id],
                snapshot_id: 9,
            }),
        ),
        (
            "want",
            Message::Want(Want {
                exchange_id: 1,
                items: vec![
                    WantItem {
                        object_id: source_id,
                        total_len: Some(100),
                        missing: vec![ByteRange {
                            start: 10,
                            end: 100,
                        }],
                        need_forwarding: true,
                    },
                    WantItem {
                        object_id: blob_id,
                        total_len: Some(64),
                        missing: vec![ByteRange { start: 0, end: 64 }],
                        need_forwarding: false,
                    },
                ],
            }),
        ),
        (
            "data-source",
            Message::Data(Data {
                exchange_id: 1,
                object_id: source_id,
                total_len: 3,
                offset: 1,
                payload: vec![2, 3],
                forwarding: vec![9],
            }),
        ),
        (
            "data-blob",
            Message::Data(Data {
                exchange_id: 1,
                object_id: blob_id,
                total_len: 2,
                offset: 0,
                payload: vec![4, 5],
                forwarding: Vec::new(),
            }),
        ),
        (
            "receipt",
            Message::Receipt(Receipt {
                exchange_id: 1,
                object_id: source_id,
                total_len: 3,
                received: vec![ByteRange { start: 0, end: 3 }],
                complete: true,
            }),
        ),
    ]
}

fn invalid_object_id_vectors() -> Result<Vec<(&'static str, Vec<u8>)>, String> {
    let mut unknown_kind = vec![0x44; ObjectId::WIRE_LEN];
    unknown_kind[0] = 0x7f;
    let mut truncated_id = vec![0x55; ObjectId::WIRE_LEN - 1];
    truncated_id[0] = ObjectKind::SourceEnvelope as u8;
    [
        ("unknown-object-kind", unknown_kind),
        ("truncated-object-id", truncated_id),
    ]
    .into_iter()
    .map(|(name, object_id)| {
        let value = Value::Map(vec![
            (0, Value::Unsigned(1)),
            (1, Value::Unsigned(5)),
            (2, Value::Unsigned(1)),
            (3, Value::Array(vec![Value::Bytes(object_id)])),
            (4, Value::Unsigned(9)),
        ]);
        encode_value(&value, Limits::default())
            .map(|bytes| (name, bytes))
            .map_err(|error| format!("{name} construction: {error}"))
    })
    .collect()
}

fn raw_message(kind: u64, fields: impl IntoIterator<Item = (u64, Value)>) -> Value {
    let mut map = vec![
        (0, Value::Unsigned(u64::from(aster_mesh::PROTOCOL_VERSION))),
        (1, Value::Unsigned(kind)),
        (2, Value::Unsigned(1)),
    ];
    map.extend(fields);
    Value::Map(map)
}

fn raw_object_id(kind: ObjectKind, fill: u8) -> Value {
    let mut bytes = vec![fill; ObjectId::WIRE_LEN];
    bytes[0] = kind as u8;
    Value::Bytes(bytes)
}

fn raw_ranges(ranges: &[(u64, u64)]) -> Value {
    Value::Array(
        ranges
            .iter()
            .map(|(start, end)| Value::Array(vec![Value::Unsigned(*start), Value::Unsigned(*end)]))
            .collect(),
    )
}

fn raw_want_entry(
    object_id: Value,
    total_len: Option<u64>,
    ranges: &[(u64, u64)],
    need_forwarding: bool,
) -> Value {
    Value::Map(vec![
        (0, object_id),
        (1, total_len.map(Value::Unsigned).unwrap_or(Value::Null)),
        (2, raw_ranges(ranges)),
        (3, Value::Bool(need_forwarding)),
    ])
}

fn encode_vector_value(
    name: &'static str,
    value: Value,
) -> Result<(&'static str, Vec<u8>), String> {
    encode_value(&value, Limits::default())
        .map(|bytes| (name, bytes))
        .map_err(|error| format!("{name} construction: {error}"))
}

fn optional_extension_vectors() -> Result<Vec<(&'static str, Vec<u8>)>, String> {
    let bounded_nested_extension = Value::Map(vec![
        (64, Value::Negative(0)),
        (
            65,
            Value::Array(vec![
                Value::Bool(true),
                Value::Null,
                Value::Map(vec![(64, Value::Bytes(vec![0xaa, 0x55]))]),
            ]),
        ),
    ]);
    encode_vector_value(
        "optional-extension-bounded-nested",
        raw_message(
            2,
            [
                (3, Value::Bytes(vec![0x11; 32])),
                (4, Value::Unsigned(0)),
                (5, Value::Unsigned(9)),
                (64, bounded_nested_extension),
            ],
        ),
    )
    .map(|vector| vec![vector])
}

fn adversarial_wire_vectors() -> Result<Vec<(&'static str, Vec<u8>)>, String> {
    let source_id = || raw_object_id(ObjectKind::SourceEnvelope, 0x11);
    let blob_id = || raw_object_id(ObjectKind::BlobChunk, 0x22);
    let want = |entry| raw_message(6, [(3, Value::Array(vec![entry]))]);
    let probe = |prefix: Vec<u8>, nibbles| {
        raw_message(
            3,
            [
                (3, Value::Bytes(prefix)),
                (4, Value::Unsigned(nibbles)),
                (5, Value::Unsigned(9)),
            ],
        )
    };
    let receipt = |ranges: &[(u64, u64)], complete| {
        raw_message(
            8,
            [
                (3, source_id()),
                (4, Value::Unsigned(10)),
                (5, raw_ranges(ranges)),
                (6, Value::Bool(complete)),
            ],
        )
    };
    let child = Value::Map(vec![
        (0, Value::Unsigned(1)),
        (1, Value::Bytes(vec![0x11; 32])),
        (2, Value::Unsigned(1)),
    ]);

    [
        (
            "unknown-critical-key",
            raw_message(
                2,
                [
                    (3, Value::Bytes(vec![0x11; 32])),
                    (4, Value::Unsigned(0)),
                    (5, Value::Unsigned(9)),
                    (63, Value::Null),
                ],
            ),
        ),
        ("prefix-nibbles-too-large", probe(vec![0; 34], 67)),
        ("prefix-length-mismatch", probe(Vec::new(), 2)),
        ("prefix-padding-nonzero", probe(vec![0xaf], 1)),
        (
            "want-ranges-unsorted",
            want(raw_want_entry(
                source_id(),
                Some(10),
                &[(5, 10), (0, 4)],
                true,
            )),
        ),
        (
            "want-ranges-overlap",
            want(raw_want_entry(
                source_id(),
                Some(10),
                &[(0, 6), (5, 10)],
                true,
            )),
        ),
        (
            "want-ranges-adjacent-uncoalesced",
            want(raw_want_entry(
                source_id(),
                Some(10),
                &[(0, 5), (5, 10)],
                true,
            )),
        ),
        (
            "blob-data-forwarding-wrapper",
            raw_message(
                7,
                [
                    (3, blob_id()),
                    (4, Value::Unsigned(1)),
                    (5, Value::Unsigned(0)),
                    (6, Value::Bytes(vec![0x01])),
                    (7, Value::Bytes(vec![0x09])),
                ],
            ),
        ),
        (
            "blob-want-forwarding-wrapper",
            want(raw_want_entry(blob_id(), None, &[], true)),
        ),
        (
            "want-no-work",
            want(raw_want_entry(source_id(), Some(10), &[], false)),
        ),
        ("receipt-partial-marked-complete", receipt(&[(0, 5)], true)),
        ("receipt-full-marked-incomplete", receipt(&[(0, 10)], false)),
        (
            "data-empty-payload-and-forwarding",
            raw_message(
                7,
                [
                    (3, source_id()),
                    (4, Value::Unsigned(0)),
                    (5, Value::Unsigned(0)),
                    (6, Value::Bytes(Vec::new())),
                    (7, Value::Bytes(Vec::new())),
                ],
            ),
        ),
        (
            "node-child-count-mismatch",
            raw_message(
                4,
                [
                    (3, Value::Bytes(Vec::new())),
                    (4, Value::Unsigned(0)),
                    (5, Value::Bytes(vec![0x22; 32])),
                    (6, Value::Unsigned(2)),
                    (7, Value::Array(vec![child])),
                    (8, Value::Unsigned(9)),
                ],
            ),
        ),
        (
            "interest-max-offers-u32-overflow",
            raw_message(
                1,
                [
                    (3, Value::Array(Vec::new())),
                    (4, Value::Array(Vec::new())),
                    (5, Value::Unsigned(0)),
                    (6, Value::Unsigned(u64::from(u32::MAX) + 1)),
                ],
            ),
        ),
    ]
    .into_iter()
    .map(|(name, value)| encode_vector_value(name, value))
    .collect()
}

fn verify_vector_document(document: &str) -> Result<(usize, usize), String> {
    let mut accepted = 0_usize;
    let mut rejected = 0_usize;
    for (line_index, line) in document.lines().enumerate() {
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        let mut fields = line.split('\t');
        let disposition = fields
            .next()
            .ok_or_else(|| format!("vector row {} has no disposition", line_index + 1))?;
        let name = fields
            .next()
            .ok_or_else(|| format!("vector row {} has no name", line_index + 1))?;
        let encoded = fields
            .next()
            .ok_or_else(|| format!("vector row {} has no bytes", line_index + 1))?;
        if fields.next().is_some() {
            return Err(format!("vector row {} has extra fields", line_index + 1));
        }
        let bytes = from_hex(encoded).map_err(|error| format!("{name}: {error}"))?;
        match disposition {
            "ACCEPT" => {
                let value = decode_value(&bytes, Limits::default())
                    .map_err(|error| format!("{name} raw decode: {error}"))?;
                let canonical = encode_value(&value, Limits::default())
                    .map_err(|error| format!("{name} raw encode: {error}"))?;
                if canonical != bytes {
                    return Err(format!("{name}: canonical re-encoding changed bytes"));
                }
                decode_message(&bytes, Limits::default())
                    .map_err(|error| format!("{name} semantic decode: {error}"))?;
                accepted += 1;
            }
            "REJECT" => {
                if decode_message(&bytes, Limits::default()).is_ok() {
                    return Err(format!("{name}: Rust decoder unexpectedly accepted"));
                }
                rejected += 1;
            }
            _ => return Err(format!("{name}: unknown disposition {disposition}")),
        }
    }
    Ok((accepted, rejected))
}

fn vector_document() -> Result<String, String> {
    let mut document = format!(
        "# aster-conformance-vectors/v1\tprotocol={}\toracle=self\n",
        aster_mesh::PROTOCOL_VERSION
    );
    for (name, message) in canonical_messages() {
        let encoded = encode_message(&message, Limits::default())
            .map_err(|error| format!("{name} encode: {error}"))?;
        document.push_str(&format!("ACCEPT\t{name}\t{}\n", to_hex(&encoded)));
    }
    for (name, bytes) in optional_extension_vectors()? {
        document.push_str(&format!("ACCEPT\t{name}\t{}\n", to_hex(&bytes)));
    }
    let mut rejected = vec![
        ("non-minimal-integer", vec![0x18, 0x17]),
        ("indefinite-array", vec![0x9f, 0xff]),
        ("duplicate-map-key", vec![0xa2, 0x00, 0x01, 0x00, 0x02]),
        ("unsorted-map", vec![0xa2, 0x01, 0x01, 0x00, 0x02]),
    ];
    rejected.extend(invalid_object_id_vectors()?);
    rejected.extend(adversarial_wire_vectors()?);
    for (name, bytes) in rejected {
        document.push_str(&format!("REJECT\t{name}\t{}\n", to_hex(&bytes)));
    }
    Ok(document)
}

fn interest_message() -> Message {
    Message::Interest(Interest {
        exchange_id: 7,
        topics: vec!["a".into()],
        scopes: vec!["s".into()],
        min_priority: 2,
        max_offers: 10,
    })
}

fn to_hex(bytes: &[u8]) -> String {
    const DIGITS: &[u8; 16] = b"0123456789abcdef";
    let mut output = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        output.push(char::from(DIGITS[usize::from(byte >> 4)]));
        output.push(char::from(DIGITS[usize::from(byte & 0x0f)]));
    }
    output
}

fn from_hex(value: &str) -> Result<Vec<u8>, &'static str> {
    if !value.len().is_multiple_of(2) {
        return Err("odd digit count");
    }
    value
        .as_bytes()
        .chunks_exact(2)
        .map(|pair| {
            let high = hex_nibble(pair[0]).ok_or("non-hex digit")?;
            let low = hex_nibble(pair[1]).ok_or("non-hex digit")?;
            Ok((high << 4) | low)
        })
        .collect()
}

fn hex_nibble(value: u8) -> Option<u8> {
    match value {
        b'0'..=b'9' => Some(value - b'0'),
        b'a'..=b'f' => Some(value - b'a' + 10),
        b'A'..=b'F' => Some(value - b'A' + 10),
        _ => None,
    }
}

fn json_escape(value: &str) -> String {
    value
        .replace('\\', "\\\\")
        .replace('"', "\\\"")
        .replace('\n', "\\n")
}

#[cfg(test)]
mod tests {
    use super::{
        check_batch_semantic_gate, from_hex, interest_message, to_hex, vector_document,
        verify_vector_document,
    };
    use aster_mesh::batch::conformance as batch_conformance;
    use aster_mesh::wire::{Limits, encode_message};

    #[test]
    fn hex_round_trip() {
        let encoded = encode_message(&interest_message(), Limits::default())
            .expect("canonical interest encodes");
        assert_eq!(from_hex(&to_hex(&encoded)), Ok(encoded));
    }

    #[test]
    fn checked_in_wire_vectors_match_current_encoder() {
        let checked_in = include_str!("../../../conformance/vectors/wire-v1.tsv");
        assert_eq!(vector_document().expect("vectors encode"), checked_in);
    }

    #[test]
    fn every_vector_has_the_expected_rust_disposition() {
        let document = vector_document().expect("vectors encode");
        let (accepted, rejected) =
            verify_vector_document(&document).expect("vectors match Rust decoder");
        assert_eq!((accepted, rejected), (10, 21));
    }

    #[test]
    fn checked_in_batch_vectors_match_current_encoder() {
        let checked_in = include_str!("../../../conformance/vectors/batch-semantic-v2.tsv");
        assert_eq!(
            batch_conformance::vector_document().expect("batch vectors encode"),
            checked_in
        );
    }

    #[test]
    fn every_batch_vector_has_the_expected_reference_disposition() {
        let document = batch_conformance::vector_document().expect("batch vectors encode");
        let counts = batch_conformance::verify_vector_document(&document)
            .expect("batch vectors match reference codecs");
        assert_eq!(
            counts,
            (
                batch_conformance::CANONICAL_COMPONENT_VECTOR_COUNT,
                batch_conformance::STRUCTURAL_UNVERIFIED_VECTOR_COUNT,
                batch_conformance::PENDING_VECTOR_COUNT,
                batch_conformance::REJECTED_VECTOR_COUNT,
            )
        );
    }

    #[test]
    fn semantic_v1_receive_paths_reject_raw_semantic_v2_inputs() {
        let check = check_batch_semantic_gate();
        assert!(check.passed, "{}", check.detail);
    }
}
