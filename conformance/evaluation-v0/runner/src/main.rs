use ciborium::Value;
use minicbor::{Decoder, Encoder};
use sha2::{Digest, Sha256};
use std::collections::BTreeSet;
use std::fmt::Write as _;
use std::fs;
use std::io::Cursor;
use std::path::{Path, PathBuf};

const PROFILE_VERSION: u64 = 0;
const MAX_INPUT: usize = 128 * 1024;
const MAX_TEXT: usize = 128;
const MAX_PARENTS: usize = 64;
const MAX_EXTENSIONS: usize = 32;
const MAX_EXTENSION_VALUE: usize = 4096;
const MAX_PROTECTED: usize = 65_536;
const KNOWN_EXTENSION: u64 = 1;

type EvalResult<T> = Result<T, String>;

#[derive(Clone, Debug, PartialEq, Eq)]
struct Extension {
    id: u64,
    critical: bool,
    value: Vec<u8>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
struct Envelope {
    version: u64,
    item_id: Vec<u8>,
    class: u64,
    topic: String,
    scope: String,
    priority: u64,
    ttl_seconds: u64,
    publisher_id: Vec<u8>,
    parents: Vec<Vec<u8>>,
    extensions: Vec<Extension>,
    protected_source_object: Vec<u8>,
}

#[derive(Clone)]
struct Vector {
    name: &'static str,
    expected: bool,
    bytes: Vec<u8>,
}

fn encode(envelope: &Envelope) -> EvalResult<Vec<u8>> {
    let mut bytes = Vec::new();
    let mut encoder = Encoder::new(&mut bytes);
    encoder.map(11).map_err(debug_error)?;
    encode_pair_u64(&mut encoder, 0, envelope.version)?;
    encode_pair_bytes(&mut encoder, 1, &envelope.item_id)?;
    encode_pair_u64(&mut encoder, 2, envelope.class)?;
    encoder
        .u64(3)
        .and_then(|e| e.str(&envelope.topic))
        .map_err(debug_error)?;
    encoder
        .u64(4)
        .and_then(|e| e.str(&envelope.scope))
        .map_err(debug_error)?;
    encode_pair_u64(&mut encoder, 5, envelope.priority)?;
    encode_pair_u64(&mut encoder, 6, envelope.ttl_seconds)?;
    encode_pair_bytes(&mut encoder, 7, &envelope.publisher_id)?;
    encoder
        .u64(8)
        .and_then(|e| e.array(envelope.parents.len() as u64))
        .map_err(debug_error)?;
    for parent in &envelope.parents {
        encoder.bytes(parent).map_err(debug_error)?;
    }
    encoder
        .u64(9)
        .and_then(|e| e.map(envelope.extensions.len() as u64))
        .map_err(debug_error)?;
    let mut extensions = envelope.extensions.clone();
    extensions.sort_by_key(|extension| extension.id);
    for extension in extensions {
        encoder
            .u64(extension.id)
            .and_then(|e| e.array(2))
            .and_then(|e| e.bool(extension.critical))
            .and_then(|e| e.bytes(&extension.value))
            .map_err(debug_error)?;
    }
    encode_pair_bytes(&mut encoder, 10, &envelope.protected_source_object)?;
    Ok(bytes)
}

fn encode_pair_u64<W: minicbor::encode::Write>(
    encoder: &mut Encoder<W>,
    key: u64,
    value: u64,
) -> EvalResult<()>
where
    W::Error: std::fmt::Debug,
{
    encoder
        .u64(key)
        .and_then(|e| e.u64(value))
        .map(|_| ())
        .map_err(debug_error)
}

fn encode_pair_bytes<W: minicbor::encode::Write>(
    encoder: &mut Encoder<W>,
    key: u64,
    value: &[u8],
) -> EvalResult<()>
where
    W::Error: std::fmt::Debug,
{
    encoder
        .u64(key)
        .and_then(|e| e.bytes(value))
        .map(|_| ())
        .map_err(debug_error)
}

fn debug_error<E: std::fmt::Debug>(error: E) -> String {
    format!("{error:?}")
}

fn parse_minicbor(input: &[u8]) -> EvalResult<Envelope> {
    check_input_bound(input)?;
    let mut decoder = Decoder::new(input);
    let count = definite(decoder.map().map_err(debug_error)?, "top map")?;
    if count > 32 {
        return Err("top map exceeds 32 entries".into());
    }

    let mut seen = BTreeSet::new();
    let mut version = None;
    let mut item_id = None;
    let mut class = None;
    let mut topic = None;
    let mut scope = None;
    let mut priority = None;
    let mut ttl_seconds = None;
    let mut publisher_id = None;
    let mut parents = None;
    let mut extensions = None;
    let mut protected_source_object = None;

    for _ in 0..count {
        let key = decoder.u64().map_err(debug_error)?;
        if !seen.insert(key) {
            return Err(format!("duplicate top-level key {key}"));
        }
        match key {
            0 => version = Some(decoder.u64().map_err(debug_error)?),
            1 => item_id = Some(decoder.bytes().map_err(debug_error)?.to_vec()),
            2 => class = Some(decoder.u64().map_err(debug_error)?),
            3 => topic = Some(decoder.str().map_err(debug_error)?.to_owned()),
            4 => scope = Some(decoder.str().map_err(debug_error)?.to_owned()),
            5 => priority = Some(decoder.u64().map_err(debug_error)?),
            6 => ttl_seconds = Some(decoder.u64().map_err(debug_error)?),
            7 => publisher_id = Some(decoder.bytes().map_err(debug_error)?.to_vec()),
            8 => parents = Some(decode_parents_minicbor(&mut decoder)?),
            9 => extensions = Some(decode_extensions_minicbor(&mut decoder)?),
            10 => {
                protected_source_object = Some(decoder.bytes().map_err(debug_error)?.to_vec());
            }
            _ => return Err(format!("unknown top-level key {key}")),
        }
    }
    if decoder.position() != input.len() {
        return Err("trailing bytes".into());
    }
    let envelope = Envelope {
        version: required(version, "version")?,
        item_id: required(item_id, "item_id")?,
        class: required(class, "class")?,
        topic: required(topic, "topic")?,
        scope: required(scope, "scope")?,
        priority: required(priority, "priority")?,
        ttl_seconds: required(ttl_seconds, "ttl_seconds")?,
        publisher_id: required(publisher_id, "publisher_id")?,
        parents: required(parents, "parents")?,
        extensions: required(extensions, "extensions")?,
        protected_source_object: required(protected_source_object, "protected_source_object")?,
    };
    finish_parse(input, envelope)
}

fn decode_parents_minicbor(decoder: &mut Decoder<'_>) -> EvalResult<Vec<Vec<u8>>> {
    let count = definite(decoder.array().map_err(debug_error)?, "parents array")?;
    if count as usize > MAX_PARENTS {
        return Err("too many causal parents".into());
    }
    let mut parents = Vec::with_capacity(count as usize);
    for _ in 0..count {
        parents.push(decoder.bytes().map_err(debug_error)?.to_vec());
    }
    Ok(parents)
}

fn decode_extensions_minicbor(decoder: &mut Decoder<'_>) -> EvalResult<Vec<Extension>> {
    let count = definite(decoder.map().map_err(debug_error)?, "extensions map")?;
    if count as usize > MAX_EXTENSIONS {
        return Err("too many extensions".into());
    }
    let mut seen = BTreeSet::new();
    let mut extensions = Vec::with_capacity(count as usize);
    for _ in 0..count {
        let id = decoder.u64().map_err(debug_error)?;
        if !seen.insert(id) {
            return Err(format!("duplicate extension {id}"));
        }
        let fields = definite(decoder.array().map_err(debug_error)?, "extension tuple")?;
        if fields != 2 {
            return Err("extension tuple must contain two fields".into());
        }
        extensions.push(Extension {
            id,
            critical: decoder.bool().map_err(debug_error)?,
            value: decoder.bytes().map_err(debug_error)?.to_vec(),
        });
    }
    Ok(extensions)
}

fn parse_ciborium(input: &[u8]) -> EvalResult<Envelope> {
    check_input_bound(input)?;
    let mut cursor = Cursor::new(input);
    let value: Value = ciborium::de::from_reader(&mut cursor).map_err(debug_error)?;
    if cursor.position() as usize != input.len() {
        return Err("trailing bytes".into());
    }
    let entries = match value {
        Value::Map(entries) => entries,
        _ => return Err("top value is not a map".into()),
    };
    if entries.len() > 32 {
        return Err("top map exceeds 32 entries".into());
    }

    let mut seen = BTreeSet::new();
    let mut version = None;
    let mut item_id = None;
    let mut class = None;
    let mut topic = None;
    let mut scope = None;
    let mut priority = None;
    let mut ttl_seconds = None;
    let mut publisher_id = None;
    let mut parents = None;
    let mut extensions = None;
    let mut protected_source_object = None;

    for (key, value) in entries {
        let key = value_u64(key, "top-level key")?;
        if !seen.insert(key) {
            return Err(format!("duplicate top-level key {key}"));
        }
        match key {
            0 => version = Some(value_u64(value, "version")?),
            1 => item_id = Some(value_bytes(value, "item_id")?),
            2 => class = Some(value_u64(value, "class")?),
            3 => topic = Some(value_text(value, "topic")?),
            4 => scope = Some(value_text(value, "scope")?),
            5 => priority = Some(value_u64(value, "priority")?),
            6 => ttl_seconds = Some(value_u64(value, "ttl_seconds")?),
            7 => publisher_id = Some(value_bytes(value, "publisher_id")?),
            8 => parents = Some(value_parents(value)?),
            9 => extensions = Some(value_extensions(value)?),
            10 => protected_source_object = Some(value_bytes(value, "protected_source_object")?),
            _ => return Err(format!("unknown top-level key {key}")),
        }
    }
    let envelope = Envelope {
        version: required(version, "version")?,
        item_id: required(item_id, "item_id")?,
        class: required(class, "class")?,
        topic: required(topic, "topic")?,
        scope: required(scope, "scope")?,
        priority: required(priority, "priority")?,
        ttl_seconds: required(ttl_seconds, "ttl_seconds")?,
        publisher_id: required(publisher_id, "publisher_id")?,
        parents: required(parents, "parents")?,
        extensions: required(extensions, "extensions")?,
        protected_source_object: required(protected_source_object, "protected_source_object")?,
    };
    finish_parse(input, envelope)
}

fn value_u64(value: Value, label: &str) -> EvalResult<u64> {
    let integer = value
        .as_integer()
        .ok_or_else(|| format!("{label} is not an integer"))?;
    u64::try_from(integer).map_err(|_| format!("{label} is outside uint range"))
}

fn value_bytes(value: Value, label: &str) -> EvalResult<Vec<u8>> {
    match value {
        Value::Bytes(bytes) => Ok(bytes),
        _ => Err(format!("{label} is not a byte string")),
    }
}

fn value_text(value: Value, label: &str) -> EvalResult<String> {
    match value {
        Value::Text(text) => Ok(text),
        _ => Err(format!("{label} is not text")),
    }
}

fn value_parents(value: Value) -> EvalResult<Vec<Vec<u8>>> {
    let values = match value {
        Value::Array(values) => values,
        _ => return Err("parents is not an array".into()),
    };
    if values.len() > MAX_PARENTS {
        return Err("too many causal parents".into());
    }
    values
        .into_iter()
        .map(|value| value_bytes(value, "causal parent"))
        .collect()
}

fn value_extensions(value: Value) -> EvalResult<Vec<Extension>> {
    let entries = match value {
        Value::Map(entries) => entries,
        _ => return Err("extensions is not a map".into()),
    };
    if entries.len() > MAX_EXTENSIONS {
        return Err("too many extensions".into());
    }
    let mut seen = BTreeSet::new();
    let mut extensions = Vec::with_capacity(entries.len());
    for (id, value) in entries {
        let id = value_u64(id, "extension id")?;
        if !seen.insert(id) {
            return Err(format!("duplicate extension {id}"));
        }
        let tuple = match value {
            Value::Array(tuple) => tuple,
            _ => return Err("extension value is not an array".into()),
        };
        if tuple.len() != 2 {
            return Err("extension tuple must contain two fields".into());
        }
        let mut tuple = tuple.into_iter();
        let critical = match tuple.next() {
            Some(Value::Bool(value)) => value,
            _ => return Err("extension critical flag is not boolean".into()),
        };
        let value = value_bytes(tuple.next().expect("length checked"), "extension value")?;
        extensions.push(Extension {
            id,
            critical,
            value,
        });
    }
    Ok(extensions)
}

fn finish_parse(input: &[u8], envelope: Envelope) -> EvalResult<Envelope> {
    validate(&envelope)?;
    let canonical = encode(&envelope)?;
    if canonical != input {
        return Err("not deterministic canonical CBOR for profile v0".into());
    }
    Ok(envelope)
}

fn validate(envelope: &Envelope) -> EvalResult<()> {
    if envelope.version != PROFILE_VERSION {
        return Err("unsupported profile version".into());
    }
    fixed_32(&envelope.item_id, "item_id")?;
    if envelope.class > 3 {
        return Err("unknown data class".into());
    }
    bounded_text(&envelope.topic, "topic")?;
    bounded_text(&envelope.scope, "scope")?;
    if envelope.priority > 3 {
        return Err("priority outside provisional four-value profile".into());
    }
    fixed_32(&envelope.publisher_id, "publisher_id")?;
    if envelope.parents.len() > MAX_PARENTS {
        return Err("too many causal parents".into());
    }
    let mut parent_set = BTreeSet::new();
    for parent in &envelope.parents {
        fixed_32(parent, "causal parent")?;
        if !parent_set.insert(parent) {
            return Err("duplicate causal parent".into());
        }
    }
    if envelope.extensions.len() > MAX_EXTENSIONS {
        return Err("too many extensions".into());
    }
    let mut extension_set = BTreeSet::new();
    for extension in &envelope.extensions {
        if !extension_set.insert(extension.id) {
            return Err("duplicate extension".into());
        }
        if extension.value.len() > MAX_EXTENSION_VALUE {
            return Err("extension value exceeds bound".into());
        }
        if extension.id != KNOWN_EXTENSION && extension.critical {
            return Err(format!("unknown critical extension {}", extension.id));
        }
    }
    if envelope.protected_source_object.is_empty()
        || envelope.protected_source_object.len() > MAX_PROTECTED
    {
        return Err("protected source object outside profile bound".into());
    }
    Ok(())
}

fn check_input_bound(input: &[u8]) -> EvalResult<()> {
    if input.len() > MAX_INPUT {
        return Err("input exceeds 128 KiB parser bound".into());
    }
    Ok(())
}

fn fixed_32(bytes: &[u8], label: &str) -> EvalResult<()> {
    if bytes.len() != 32 {
        return Err(format!("{label} must be 32 bytes"));
    }
    Ok(())
}

fn bounded_text(text: &str, label: &str) -> EvalResult<()> {
    if text.is_empty() || text.len() > MAX_TEXT {
        return Err(format!("{label} outside 1..={MAX_TEXT} byte bound"));
    }
    Ok(())
}

fn definite(value: Option<u64>, label: &str) -> EvalResult<u64> {
    value.ok_or_else(|| format!("{label} must use a definite length"))
}

fn required<T>(value: Option<T>, label: &str) -> EvalResult<T> {
    value.ok_or_else(|| format!("missing {label}"))
}

fn base_envelope(class: u64) -> Envelope {
    Envelope {
        version: PROFILE_VERSION,
        item_id: vec![0x11 + class as u8; 32],
        class,
        topic: format!("topic/class-{class}"),
        scope: "mission/alpha".into(),
        priority: class.min(3),
        ttl_seconds: 3600,
        publisher_id: vec![0x80 + class as u8; 32],
        parents: Vec::new(),
        extensions: vec![Extension {
            id: KNOWN_EXTENSION,
            critical: true,
            value: b"known-v0".to_vec(),
        }],
        protected_source_object: format!("opaque-source-object-class-{class}").into_bytes(),
    }
}

fn duplicate_top_key(envelope: &Envelope) -> EvalResult<Vec<u8>> {
    let canonical = encode(envelope)?;
    if canonical.first() != Some(&0xab) {
        return Err("unexpected canonical top-map prefix".into());
    }
    let mut bytes = Vec::with_capacity(canonical.len() + 2);
    bytes.push(0xac);
    bytes.extend_from_slice(&canonical[1..]);
    bytes.extend_from_slice(&[0x00, 0x00]);
    Ok(bytes)
}

fn missing_scope(envelope: &Envelope) -> EvalResult<Vec<u8>> {
    let mut bytes = Vec::new();
    let mut encoder = Encoder::new(&mut bytes);
    encoder.map(10).map_err(debug_error)?;
    encode_pair_u64(&mut encoder, 0, envelope.version)?;
    encode_pair_bytes(&mut encoder, 1, &envelope.item_id)?;
    encode_pair_u64(&mut encoder, 2, envelope.class)?;
    encoder
        .u64(3)
        .and_then(|e| e.str(&envelope.topic))
        .map_err(debug_error)?;
    encode_pair_u64(&mut encoder, 5, envelope.priority)?;
    encode_pair_u64(&mut encoder, 6, envelope.ttl_seconds)?;
    encode_pair_bytes(&mut encoder, 7, &envelope.publisher_id)?;
    encoder
        .u64(8)
        .and_then(|e| e.array(0))
        .map_err(debug_error)?;
    encoder.u64(9).and_then(|e| e.map(0)).map_err(debug_error)?;
    encode_pair_bytes(&mut encoder, 10, &envelope.protected_source_object)?;
    Ok(bytes)
}

fn out_of_order(envelope: &Envelope) -> EvalResult<Vec<u8>> {
    let mut bytes = Vec::new();
    let mut encoder = Encoder::new(&mut bytes);
    encoder.map(11).map_err(debug_error)?;
    encode_pair_bytes(&mut encoder, 1, &envelope.item_id)?;
    encode_pair_u64(&mut encoder, 0, envelope.version)?;
    encode_pair_u64(&mut encoder, 2, envelope.class)?;
    encoder
        .u64(3)
        .and_then(|e| e.str(&envelope.topic))
        .map_err(debug_error)?;
    encoder
        .u64(4)
        .and_then(|e| e.str(&envelope.scope))
        .map_err(debug_error)?;
    encode_pair_u64(&mut encoder, 5, envelope.priority)?;
    encode_pair_u64(&mut encoder, 6, envelope.ttl_seconds)?;
    encode_pair_bytes(&mut encoder, 7, &envelope.publisher_id)?;
    encoder
        .u64(8)
        .and_then(|e| e.array(0))
        .map_err(debug_error)?;
    encoder.u64(9).and_then(|e| e.map(0)).map_err(debug_error)?;
    encode_pair_bytes(&mut encoder, 10, &envelope.protected_source_object)?;
    Ok(bytes)
}

fn vectors() -> EvalResult<Vec<Vector>> {
    let state = base_envelope(0);
    let event = base_envelope(1);
    let mut record = base_envelope(2);
    record.parents = vec![vec![0x31; 32], vec![0x32; 32]];
    let mut blob = base_envelope(3);
    blob.protected_source_object = vec![0x5a; 4096];
    let mut ignorable = base_envelope(0);
    ignorable.extensions.push(Extension {
        id: 99,
        critical: false,
        value: b"future-ignorable".to_vec(),
    });

    let mut unknown_critical = ignorable.clone();
    unknown_critical
        .extensions
        .last_mut()
        .expect("present")
        .critical = true;
    let mut bad_class = state.clone();
    bad_class.class = 4;
    let mut bad_priority = state.clone();
    bad_priority.priority = 4;
    let mut duplicate_parent = record.clone();
    duplicate_parent.parents[1] = duplicate_parent.parents[0].clone();
    let mut long_topic = state.clone();
    long_topic.topic = "t".repeat(129);
    let mut empty_protected = state.clone();
    empty_protected.protected_source_object.clear();
    let mut too_many_parents = state.clone();
    too_many_parents.parents = (0..65).map(|index| vec![index as u8; 32]).collect();

    let canonical_state = encode(&state)?;
    let mut truncated = canonical_state.clone();
    truncated.pop();
    let mut trailing = canonical_state.clone();
    trailing.push(0);
    let mut noncanonical_integer = canonical_state.clone();
    if noncanonical_integer.get(0..3) != Some(&[0xab, 0x00, 0x00]) {
        return Err("unexpected canonical prefix".into());
    }
    noncanonical_integer.splice(2..3, [0x18, 0x00]);

    Ok(vec![
        Vector {
            name: "positive-state",
            expected: true,
            bytes: canonical_state,
        },
        Vector {
            name: "positive-event",
            expected: true,
            bytes: encode(&event)?,
        },
        Vector {
            name: "positive-record-two-parents",
            expected: true,
            bytes: encode(&record)?,
        },
        Vector {
            name: "positive-blob-chunk",
            expected: true,
            bytes: encode(&blob)?,
        },
        Vector {
            name: "positive-unknown-ignorable-extension",
            expected: true,
            bytes: encode(&ignorable)?,
        },
        Vector {
            name: "negative-unknown-critical-extension",
            expected: false,
            bytes: encode(&unknown_critical)?,
        },
        Vector {
            name: "negative-unknown-class",
            expected: false,
            bytes: encode(&bad_class)?,
        },
        Vector {
            name: "negative-priority-out-of-range",
            expected: false,
            bytes: encode(&bad_priority)?,
        },
        Vector {
            name: "negative-missing-scope",
            expected: false,
            bytes: missing_scope(&state)?,
        },
        Vector {
            name: "negative-duplicate-top-key",
            expected: false,
            bytes: duplicate_top_key(&state)?,
        },
        Vector {
            name: "negative-duplicate-parent",
            expected: false,
            bytes: encode(&duplicate_parent)?,
        },
        Vector {
            name: "negative-topic-too-long",
            expected: false,
            bytes: encode(&long_topic)?,
        },
        Vector {
            name: "negative-truncated",
            expected: false,
            bytes: truncated,
        },
        Vector {
            name: "negative-trailing-byte",
            expected: false,
            bytes: trailing,
        },
        Vector {
            name: "negative-noncanonical-integer",
            expected: false,
            bytes: noncanonical_integer,
        },
        Vector {
            name: "negative-out-of-order-map",
            expected: false,
            bytes: out_of_order(&state)?,
        },
        Vector {
            name: "negative-empty-protected-object",
            expected: false,
            bytes: encode(&empty_protected)?,
        },
        Vector {
            name: "negative-too-many-parents",
            expected: false,
            bytes: encode(&too_many_parents)?,
        },
    ])
}

fn sha256(bytes: &[u8]) -> String {
    let digest = Sha256::digest(bytes);
    let mut output = String::with_capacity(64);
    for byte in digest {
        write!(&mut output, "{byte:02x}").expect("String writes cannot fail");
    }
    output
}

fn write_vectors(root: &Path, vectors: &[Vector]) -> EvalResult<()> {
    fs::create_dir_all(root).map_err(debug_error)?;
    for vector in vectors {
        fs::write(root.join(format!("{}.cbor", vector.name)), &vector.bytes)
            .map_err(debug_error)?;
    }
    Ok(())
}

fn json_escape(value: &str) -> String {
    value.replace('\\', "\\\\").replace('"', "\\\"")
}

fn main() -> EvalResult<()> {
    let vectors = vectors()?;
    let output_root = std::env::args_os()
        .nth(1)
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from("vectors"));
    write_vectors(&output_root, &vectors)?;

    let mut failures = Vec::new();
    let mut rows = Vec::new();
    for vector in &vectors {
        let minicbor_result = parse_minicbor(&vector.bytes);
        let ciborium_result = parse_ciborium(&vector.bytes);
        let minicbor_accept = minicbor_result.is_ok();
        let ciborium_accept = ciborium_result.is_ok();
        let agreed = minicbor_accept == ciborium_accept;
        let expected_match =
            minicbor_accept == vector.expected && ciborium_accept == vector.expected;
        if !agreed || !expected_match {
            failures.push(vector.name);
        }
        rows.push(format!(
            "    {{\"name\":\"{}\",\"expected\":\"{}\",\"minicbor\":\"{}\",\"ciborium\":\"{}\",\"bytes\":{},\"sha256\":\"{}\",\"minicbor_error\":{},\"ciborium_error\":{}}}",
            vector.name,
            if vector.expected { "accept" } else { "reject" },
            if minicbor_accept { "accept" } else { "reject" },
            if ciborium_accept { "accept" } else { "reject" },
            vector.bytes.len(),
            sha256(&vector.bytes),
            minicbor_result.err().map(|error| format!("\"{}\"", json_escape(&error))).unwrap_or_else(|| "null".into()),
            ciborium_result.err().map(|error| format!("\"{}\"", json_escape(&error))).unwrap_or_else(|| "null".into()),
        ));
    }
    let accepted = vectors.iter().filter(|vector| vector.expected).count();
    let rejected = vectors.len() - accepted;
    println!(
        "{{\n  \"artifact_kind\": \"candidate_neutral_conformance_vector_result\",\n  \"profile\": \"mesh-eval-envelope-v0\",\n  \"outcome\": \"{}\",\n  \"vector_count\": {},\n  \"positive_count\": {},\n  \"negative_count\": {},\n  \"decoder_agreement_count\": {},\n  \"vectors\": [\n{}\n  ],\n  \"no_credit\": [\"not a product wire protocol\",\"not an independent spec-built implementation\",\"not a hostile-input fuzz or resource-exhaustion proof\",\"not a security profile or carrier interoperability result\"]\n}}",
        if failures.is_empty() { "pass" } else { "fail" },
        vectors.len(),
        accepted,
        rejected,
        vectors.len() - failures.len(),
        rows.join(",\n")
    );
    if failures.is_empty() {
        Ok(())
    } else {
        Err(format!("vector failures: {}", failures.join(", ")))
    }
}
