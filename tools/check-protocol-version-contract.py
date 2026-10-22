#!/usr/bin/env python3
# Copyright 2026 Defense Unicorns, Inc.
# SPDX-License-Identifier: Apache-2.0
"""Keep the implemented and normative semantic-version registries aligned."""

from __future__ import annotations

from pathlib import Path
import ast
import json
import re
import subprocess
import sys


ROOT = Path(__file__).resolve().parents[1]
VERSIONS = tuple(range(1, 10))
DEFAULT_OFFER = tuple(reversed(VERSIONS))
PROTOCOL_ROWS = {
    1: ("—", "stable Event and Blob-chunk transfer"),
    2: ("v1", "compact batch and bridge objects"),
    3: ("v2", "session custody record"),
    4: ("v3", "State and Record reconciliation"),
    5: ("v4", "historical direct Blob frame allocation"),
    6: ("v5 ordinary lanes byte-for-byte", "Event bridge transfer"),
    7: (
        "v6 byte-for-byte",
        "per-lane profiles, receipt-free Event pages, and durable Blob range streams",
    ),
    8: (
        "v7 byte-for-byte except the lane AAD domain and Blob custody fields",
        "authenticated finite Blob custody over `BlobRangesStreamV1`",
    ),
    9: (
        "v8 fixed lanes byte-for-byte except the Blob transfer profile and Blob chunk kind",
        "independently authenticated Blob streams over `BlobStreamV1`",
    ),
}
CDDL_ALIASES = {
    1: "1 / 2",
    2: "semantic-v1-object-kind / 3 / 4 / 5",
    3: "semantic-v2-object-kind",
    4: "semantic-v3-object-kind",
    5: "semantic-v4-object-kind",
    6: "semantic-v5-object-kind",
    7: "semantic-v6-object-kind",
    8: "semantic-v7-object-kind",
    9: "1 / 3 / 4 / 5",
}
PROTOCOL_DEFAULT_OFFER_PATTERNS = (
    r"default semantic offer is\s*`\[([^\]]+)\]`",
    r"default\s+descending\s+offer\s+is\s*`\[([^\]]+)\]`",
    r"default initiator offers\s+semantic versions\s*`\[([^\]]+)\]`",
)
PROFILE4_LIMITS = (67_108_864, 1_024, 1_048_576)
PROFILE5_LIMIT_NAMES = (
    "MAX_SELECTED_BLOB_STREAM_BYTES",
    "MAX_BLOB_CHUNKS",
    "MAX_STREAM_AUTHENTICATED_OPEN_BYTES",
    "MAX_BLOB_CHUNK_SIZE",
    "MAX_BLOB_TRANSFER_OBJECT_BYTES",
    "PROFILE5_CANONICAL_EXTENT_BYTES",
    "MAX_STREAM_CHECKPOINT_BATCH_BYTES",
    "DEFAULT_MAX_EXCHANGE_BYTES",
)
PROFILE5_PIPELINE = (
    "PLAN -> OPEN -> SOURCE -> ACCEPT -> ABX1 DATA -> CHECKPOINT -> FINISH -> RESULT -> ACK"
)
PROFILE5_EMPTY_PIPELINE = (
    "OPEN -> SOURCE -> ACCEPT -> FINISH(final_offset=0) -> RESULT -> ACK, "
    "with no DATA or CHECKPOINT"
)
PROFILE5_RECORDS = {
    "OPEN": (0xD6, ["class", "direction", "semantic_version", "profile_id", "session_transcript", "exchange_id", "transfer_id", "source_transfer_id", "publication_id", "variant_id", "total_len", "attempt_nonce", "checkpoint_generation", "custody_present", "custody_digest", "source_len", "source_digest"]),
    "SOURCE": (0xDD, ["attempt", "source_offset", "source_total_len", "source_chunk_len", "source_chunk"]),
    "ACCEPT": (0xD7, ["attempt", "durable_offset", "checkpoint_generation", "absolute_receive_limit", "max_extent_bytes", "checkpoint_batch_bytes"]),
    "DATA": (0xD8, ["attempt", "offset", "extent_len", "abx1_extent"]),
    "CHECKPOINT": (0xD9, ["attempt", "durable_offset", "checkpoint_generation", "absolute_receive_limit"]),
    "FINISH": (0xDA, ["attempt", "final_offset", "commitment_len", "semantic_commitment"]),
    "RESULT": (0xDB, ["attempt", "final_offset", "result_code", "result_digest"]),
    "ACK": (0xDC, ["attempt", "result_digest"]),
}
PROFILE5_FIELDS = {
    "OPEN": [["class", "u8-enum:1"], ["direction", "u8-enum:1,2"], ["semantic_version", "u16=9"], ["profile_id", "u16=5"], ["session_transcript", "bytes32"], ["exchange_id", "u64"], ["transfer_id", "bytes32"], ["source_transfer_id", "bytes32"], ["publication_id", "bytes32"], ["variant_id", "bytes32"], ["total_len", "u64<=8589934592"], ["attempt_nonce", "bytes32-nonzero"], ["checkpoint_generation", "u64"], ["custody_present", "u8-enum:0,1"], ["custody_digest", "bytes32-if-present"], ["source_len", "u32:1..16777216"], ["source_digest", "bytes32"]],
    "SOURCE": [["attempt", "attempt_fields"], ["source_offset", "u32"], ["source_total_len", "u32:1..16777216"], ["source_chunk_len", "u32:1..1048576"], ["source_chunk", "bytes[source_chunk_len]"]],
    "ACCEPT": [["attempt", "attempt_fields"], ["durable_offset", "u64"], ["checkpoint_generation", "u64"], ["absolute_receive_limit", "u64>=durable_offset"], ["max_extent_bytes", "u32:1..1048576"], ["checkpoint_batch_bytes", "u32:1..134217728"]],
    "DATA": [["attempt", "attempt_fields"], ["offset", "u64"], ["extent_len", "u32:1..1048576"], ["abx1_extent", "bytes[extent_len]"]],
    "CHECKPOINT": [["attempt", "attempt_fields"], ["durable_offset", "u64"], ["checkpoint_generation", "u64"], ["absolute_receive_limit", "u64>=durable_offset"]],
    "FINISH": [["attempt", "attempt_fields"], ["final_offset", "u64"], ["commitment_len", "u32:1..65536"], ["semantic_commitment", "bytes[commitment_len]"]],
    "RESULT": [["attempt", "attempt_fields"], ["final_offset", "u64"], ["result_code", "u8-enum:1,2,3,4,5,6"], ["result_digest", "bytes32"]],
    "ACK": [["attempt", "attempt_fields"], ["result_digest", "bytes32"]],
}
PROFILE5_RUST_ORDER = {
    "OPEN": ["o.push(0xd6)", "x.class as u8", "x.direction as u8", "9u16.to_be_bytes()", "5u16.to_be_bytes()", "x.session_transcript", "x.exchange_id", "x.transfer_id", "x.source_transfer_id", "x.publication_id", "x.variant_id", "x.total_len", "x.attempt_nonce", "x.checkpoint_generation", "match x.custody_digest", "x.source_len", "x.source_digest"],
    "SOURCE": ["o.push(0xdd)", "put_attempt", "x.offset", "x.total_len", "x.bytes.len()", "o.extend(&x.bytes)"],
    "ACCEPT": ["o.push(0xd7)", "put_attempt", "x.durable_offset", "x.checkpoint_generation", "x.absolute_receive_limit", "x.max_extent_bytes", "x.checkpoint_batch_bytes"],
    "DATA": ["o.push(0xd8)", "put_attempt", "x.offset", "l.to_be_bytes()", "o.extend(&x.bytes)"],
    "CHECKPOINT": ["o.push(0xd9)", "put_attempt", "x.durable_offset", "x.checkpoint_generation", "x.absolute_receive_limit"],
    "FINISH": ["o.push(0xda)", "put_attempt", "x.final_offset", "x.semantic_commitment.len()", "o.extend(&x.semantic_commitment)"],
    "RESULT": ["o.push(0xdb)", "put_attempt", "x.final_offset", "x.code as u8", "x.result_digest"],
    "ACK": ["o.push(0xdc)", "put_attempt", "x.result_digest"],
}


class ContractViolation(ValueError):
    """A normative semantic-version declaration drifted from implementation."""


def fail(message: str) -> None:
    raise ContractViolation(message)


def require_version_sequence(
    text: str, pattern: str, expected: tuple[int, ...], label: str
) -> None:
    matches = re.findall(pattern, text, re.DOTALL)
    if len(matches) != 1:
        fail(f"{label} declaration must occur exactly once; found {len(matches)}")
    actual = tuple(int(version) for version in re.findall(r"\d+", matches[0]))
    if actual != expected:
        fail(f"{label} must be {expected}; found {actual}")


def require_once(text: str, declaration: str, label: str) -> None:
    count = text.count(declaration)
    if count != 1:
        fail(f"{label} declaration must occur exactly once; found {count}")


def parse_numeric_declaration(text: str, label: str) -> tuple[int, ...]:
    match = re.search(rf"^{re.escape(label)}:\s*([^\n]+)$", text, re.MULTILINE)
    if match is None:
        fail(f"{label} declaration is missing")
    body = re.sub(r"[A-Za-z_]+\d+[A-Za-z_]*", "", match.group(1))
    return tuple(int(value.replace(",", "")) for value in re.findall(r"\d[\d,]*", body))


def parse_profile_contract(protocol: str) -> None:
    require_once(
        protocol,
        "Blob profile registry: semantic v7/v8 select profile 4; semantic v9 selects profile 5.",
        "Blob profile registry",
    )
    if parse_numeric_declaration(protocol, "Profile 4 limits") != PROFILE4_LIMITS:
        fail("profile 4 limits differ from the executable compatibility bounds")
    expected_profile5 = (
        8_589_934_592,
        131_072,
        16_777_216,
    )
    if parse_numeric_declaration(protocol, "Profile 5 limits") != expected_profile5:
        fail("profile 5 limits differ from the executable streaming bounds")
    expected_sizes = (65_536, 66_215, 1_048_576, 134_217_728, 2_097_152)
    if parse_numeric_declaration(protocol, "Profile 5 size classes") != expected_sizes:
        fail("profile 5 limits must distinguish chunk, carrier, extent, checkpoint, and frame sizes")
    require_once(protocol, f"Profile 5 order: {PROFILE5_PIPELINE}.", "profile 5 grammar")
    require_once(
        protocol,
        f"Profile 5 exact empty transfer: {PROFILE5_EMPTY_PIPELINE}.",
        "profile 5 grammar",
    )


def parse_implementation(core: str) -> None:
    declarations = re.findall(
        r"^pub\(crate\) const SEMANTIC_PROTOCOL_V(\d+): u16 = (\d+);$",
        core,
        re.MULTILINE,
    )
    actual_versions = tuple(sorted(int(name) for name, _ in declarations))
    expected_versions = VERSIONS
    mismatched = [
        int(name) for name, value in declarations if int(name) != int(value)
    ]
    if actual_versions != expected_versions or mismatched:
        missing = tuple(sorted(set(expected_versions) - set(actual_versions)))
        extra = tuple(sorted(set(actual_versions) - set(expected_versions)))
        fail(
            "implementation versions must be exactly 1 through 9 with matching values; "
            f"missing {missing}, extra {extra}, mismatched {tuple(mismatched)}"
        )

    offer_match = re.search(
        r"SUPPORTED_SEMANTIC_PROTOCOL_VERSIONS:\s*&\[u16\]\s*=\s*&\[(.*?)\];",
        core,
        re.DOTALL,
    )
    if offer_match is None:
        fail("implementation default offer declaration is missing")
    offer = tuple(
        int(version)
        for version in re.findall(r"SEMANTIC_PROTOCOL_V(\d+)", offer_match.group(1))
    )
    if offer != DEFAULT_OFFER:
        fail(f"implementation default offer must be {DEFAULT_OFFER}; found {offer}")


def parse_protocol(protocol: str) -> None:
    require_version_sequence(
        protocol,
        r"default and\s+highest-supported semantic-version surfaces report\s+(`\d+`)",
        (DEFAULT_OFFER[0],),
        "protocol highest-supported version",
    )
    for pattern in PROTOCOL_DEFAULT_OFFER_PATTERNS:
        require_version_sequence(
            protocol, pattern, DEFAULT_OFFER, "protocol default offer"
        )
    require_version_sequence(
        protocol,
        r"current handshake negotiates\s+semantic versions\s+(.+?)\s+and the complete suite",
        DEFAULT_OFFER,
        "protocol negotiated versions",
    )

    rows = {
        int(version): (inheritance.strip(), mechanics.strip())
        for version, inheritance, mechanics in re.findall(
            r"^\| `(\d+)` \| ([^|]+) \| ([^|]+) \|$",
            protocol,
            re.MULTILINE,
        )
    }
    actual_versions = tuple(sorted(rows))
    if actual_versions != VERSIONS:
        missing = tuple(sorted(set(VERSIONS) - set(actual_versions)))
        extra = tuple(sorted(set(actual_versions) - set(VERSIONS)))
        fail(
            "protocol registry must contain exactly semantic versions 1 through 9; "
            f"missing {missing}, extra {extra}"
        )
    if rows[6][0] != PROTOCOL_ROWS[6][0]:
        fail(
            "protocol v6 inheritance must preserve v5 ordinary lanes byte-for-byte; "
            f"found {rows[6][0]!r}"
        )
    if rows[7][0] != PROTOCOL_ROWS[7][0]:
        fail(
            "protocol v7 inheritance must preserve v6 byte-for-byte; "
            f"found {rows[7][0]!r}"
        )
    if rows[8][0] != PROTOCOL_ROWS[8][0]:
        fail(
            "protocol v8 inheritance must preserve v7 bytes except the lane AAD domain and Blob custody fields; "
            f"found {rows[8][0]!r}"
        )
    if rows[9][0] != PROTOCOL_ROWS[9][0]:
        fail(
            "protocol v9 inheritance must preserve v8 fixed lanes while replacing the Blob profile and legacy chunk kind; "
            f"found {rows[9][0]!r}"
        )
    if rows != PROTOCOL_ROWS:
        fail(f"protocol registry semantics drifted; found {rows!r}")
    parse_profile_contract(protocol)


def parse_envelope(envelope: str) -> None:
    require_version_sequence(
        envelope,
        r"(?m)^- Negotiated semantic versions:\s+default/highest\s+([^\n]+)$",
        DEFAULT_OFFER,
        "envelope version summary",
    )
    require_version_sequence(
        envelope,
        r"default semantic-version list is\s*`\[([^\]]+)\]`",
        DEFAULT_OFFER,
        "envelope default offer",
    )

    match = re.search(
        r"^selected_semantic_version\s+u16\s*=\s*([^\n]+)$",
        envelope,
        re.MULTILINE,
    )
    if match is None:
        fail("envelope selection registry is missing")
    selected = tuple(int(version) for version in re.findall(r"\d+", match.group(1)))
    if selected != VERSIONS:
        fail(f"envelope selection registry must be {VERSIONS}; found {selected}")


def parse_cddl(cddl: str) -> None:
    aliases = {
        int(version): expression.strip()
        for version, expression in re.findall(
            r"^semantic-v(\d+)-object-kind\s*=\s*([^\n]+)$",
            cddl,
            re.MULTILINE,
        )
    }
    actual_versions = tuple(sorted(aliases))
    if actual_versions != VERSIONS:
        missing = tuple(sorted(set(VERSIONS) - set(actual_versions)))
        extra = tuple(sorted(set(actual_versions) - set(VERSIONS)))
        fail(
            "CDDL object-kind aliases must cover exactly semantic versions 1 through 9; "
            f"missing {missing}, extra {extra}"
        )
    if aliases[6] != CDDL_ALIASES[6]:
        fail(
            "CDDL v6 inheritance must reuse the semantic-v5 object-kind registry; "
            f"found {aliases[6]!r}"
        )
    if aliases[7] != CDDL_ALIASES[7]:
        fail(
            "CDDL v7 inheritance must reuse the semantic-v6 object-kind registry; "
            f"found {aliases[7]!r}"
        )
    if aliases[8] != CDDL_ALIASES[8]:
        fail(
            "CDDL v8 inheritance must reuse the semantic-v7 object-kind registry; "
            f"found {aliases[8]!r}"
        )
    if aliases[9] != CDDL_ALIASES[9]:
        fail(
            "CDDL v9 object kinds must exclude the legacy Blob chunk kind; "
            f"found {aliases[9]!r}"
        )
    if aliases != CDDL_ALIASES:
        fail(f"CDDL object-kind registry drifted; found {aliases!r}")
    for declaration in (
        "stream-profile-v5 = stream-open-v1 / stream-source-v1 / stream-accept-v1 / stream-data-v1 / stream-checkpoint-v1 / stream-finish-v1 / stream-result-v1 / stream-result-ack-v1",
        'stream-data-v1 = "ASM\\x01\\xd8" attempt-tuple offset-u64 extent-len-u32 abx1-extent',
        'abx1-extent = "ABX1" first-chunk-index-u64 carrier-count-u32 1*(carrier-len-u32 canonical-carrier)',
    ):
        require_once(cddl, declaration, "CDDL profile 5 grammar")


def rust_numeric_constants(*sources: str) -> dict[str, int]:
    declarations: dict[str, str] = {}
    for source in sources:
        for name, expression in re.findall(
            r"(?ms)^(?:pub(?:\([^)]*\))?\s+)?const\s+([A-Z][A-Z0-9_]*)\s*(?::[^=]+)?=\s*(.*?);",
            source,
        ):
            declarations.setdefault(name, re.sub(r"//.*", "", expression).strip())
    resolved: dict[str, int] = {}

    def resolve(name: str, stack: tuple[str, ...] = ()) -> int:
        if name in resolved:
            return resolved[name]
        if name in stack or name not in declarations:
            fail(f"executable numeric constant {name} cannot be resolved")
        expression = re.sub(r"\bas\s+(?:u|i|usize)[0-9]*\b", "", declarations[name])
        expression = re.sub(r"(?<=\d)_(?=\d)", "", expression)
        expression = re.sub(r"(?<=\d)(?:u|i)(?:8|16|32|64|128|size)\b", "", expression)
        for dependency in sorted(set(re.findall(r"\b[A-Z][A-Z0-9_]*\b", expression)), key=len, reverse=True):
            expression = re.sub(rf"\b{dependency}\b", str(resolve(dependency, stack + (name,))), expression)
        try:
            node = ast.parse(expression, mode="eval")
        except SyntaxError as error:
            fail(f"executable numeric constant {name} is not a supported expression: {error}")

        def calculate(value: ast.AST) -> int:
            if isinstance(value, ast.Expression):
                return calculate(value.body)
            if isinstance(value, ast.Constant) and isinstance(value.value, int):
                return value.value
            if isinstance(value, ast.BinOp) and isinstance(value.op, (ast.Add, ast.Sub, ast.Mult, ast.Div, ast.FloorDiv)):
                left, right = calculate(value.left), calculate(value.right)
                if isinstance(value.op, ast.Add):
                    return left + right
                if isinstance(value.op, ast.Sub):
                    return left - right
                if isinstance(value.op, ast.Mult):
                    return left * right
                return left // right
            fail(f"executable numeric constant {name} uses an unsupported expression")
        resolved[name] = calculate(node)
        return resolved[name]

    for name in PROFILE5_LIMIT_NAMES:
        resolve(name)
    return resolved


def validate_executable_profile_contract(
    profile: str,
    application_blob: str,
    core_blob: str,
    core_blob_stream: str,
    stream_transfer: str,
    iroh: str,
) -> None:
    values = rust_numeric_constants(application_blob, core_blob, core_blob_stream, stream_transfer, iroh)
    expected = {
        "MAX_SELECTED_BLOB_STREAM_BYTES": 8_589_934_592,
        "MAX_BLOB_CHUNKS": 131_072,
        "MAX_STREAM_AUTHENTICATED_OPEN_BYTES": 16_777_216,
        "MAX_BLOB_CHUNK_SIZE": 65_536,
        "MAX_BLOB_TRANSFER_OBJECT_BYTES": 66_215,
        "PROFILE5_CANONICAL_EXTENT_BYTES": 1_048_576,
        "MAX_STREAM_CHECKPOINT_BATCH_BYTES": 134_217_728,
        "DEFAULT_MAX_EXCHANGE_BYTES": 2_097_152,
    }
    if {name: values[name] for name in expected} != expected:
        fail(f"executable profile 5 limits drifted; found {values!r}")
    required_profile_fragments = (
        "BlobRangesStreamV1 = 4",
        "BlobStreamV1 = 5",
        "SEMANTIC_PROTOCOL_V7 | SEMANTIC_PROTOCOL_V8 => Ok(Self::current())",
        "SEMANTIC_PROTOCOL_V9 => Ok(Self::stream_v9())",
        "vec![TransferProfileId::BlobRangesStreamV1 as u16]",
        "vec![TransferProfileId::BlobStreamV1 as u16]",
    )
    if any(fragment not in profile for fragment in required_profile_fragments):
        fail("executable Blob profile registry must bind v7/v8 to profile 4 and v9 to profile 5")
    required_extent_fragments = (
        "MAX_STREAM_EXTENT_BYTES: usize = PROFILE5_CANONICAL_EXTENT_BYTES",
        "profile5_attempt_bounds_for_extents",
        "8 + MAX_PROTECTED_STREAM_DATA_HEADER_BYTES + 192",
        "PROFILE5_CANONICAL_EXTENT_BYTES as u64",
    )
    if any(fragment not in stream_transfer for fragment in required_extent_fragments):
        fail("production extent admission and attempt bounds must use canonical ABX1 limits")
    if "MAX_STREAM_EXTENT_BYTES: usize = PROFILE5_EXTENT_BYTES" in stream_transfer:
        fail("retired ASTRBS02 extent aliases production admission")


def validate_profile5_schema(schema: dict, stream_transfer: str) -> None:
    if schema.get("format") != "aster-profile5-fixed-binary-v1" or schema.get("magic") != "41534d01":
        fail("profile 5 schema identity differs")
    records = schema.get("records")
    if not isinstance(records, list) or len(records) != len(PROFILE5_RECORDS):
        fail("profile 5 schema record set differs")
    for record in records:
        name = record.get("name")
        if name not in PROFILE5_RECORDS:
            fail("profile 5 schema record name differs")
        tag, fields = PROFILE5_RECORDS[name]
        if record.get("tag") != tag or record.get("fields") != PROFILE5_FIELDS[name]:
            fail(f"profile 5 schema {name} tag or field order differs")
        rust_name = "ResultAck" if name == "ACK" else name.title()
        marker = f"Self::{rust_name}(x) =>"
        encoder = stream_transfer.find("pub(crate) fn encode_for_context")
        start = stream_transfer.find(marker, encoder)
        if start < 0:
            fail(f"executable profile 5 encoder lacks {name}")
        end = stream_transfer.find("\n            Self::", start + len(marker))
        arm = stream_transfer[start:end if end >= 0 else None]
        if f"o.push(0x{tag:02x})" not in arm:
            fail(f"executable profile 5 {name} tag differs")
        cursor = -1
        for token in PROFILE5_RUST_ORDER[name]:
            position = arm.find(token, cursor + 1)
            if position < 0:
                fail(f"executable profile 5 {name} field order differs at {token}")
            cursor = position
    abx1 = schema.get("abx1", {})
    if abx1.get("magic") != "41425831" or abx1.get("max_encoded_bytes") != 1_048_576:
        fail("profile 5 ABX1 schema differs")
    if [field[0] for field in abx1.get("fields", [])] != ["first_chunk_index", "carrier_count", "carriers", "carrier_len", "carrier"]:
        fail("profile 5 ABX1 carrier_len or field order differs")
    composite = schema.get("composite", {})
    if composite.get("magic") != "41534431" or composite.get("max_encoded_bytes") != 1_050_632:
        fail("profile 5 ASD1 composite schema differs")
    if schema.get("flow", {}).get("empty") != ["PLAN", "OPEN", "SOURCE", "ACCEPT", "FINISH", "RESULT", "ACK"]:
        fail("profile 5 empty flow differs")
    result = next(record for record in records if record["name"] == "RESULT")
    if dict(result["fields"])["result_code"] != "u8-enum:1,2,3,4,5,6":
        fail("profile 5 result-code enum differs")


def validate_profile5_oracle(root: Path = ROOT) -> None:
    result = subprocess.run(
        [sys.executable, str(root / "conformance/blob_stream_oracle.py")],
        cwd=root, capture_output=True, text=True,
    )
    if result.returncode != 0:
        fail(f"profile 5 oracle/vectors drifted: {result.stderr.strip() or result.stdout.strip()}")


def validate_contract_texts(
    core: str, protocol: str, envelope: str, cddl: str
) -> None:
    parse_implementation(core)
    parse_protocol(protocol)
    parse_envelope(envelope)
    parse_cddl(cddl)


def main() -> int:
    try:
        validate_contract_texts(
            (ROOT / "crates/aster-core/src/crypto.rs").read_text(),
            (ROOT / "docs/protocol.md").read_text(),
            (ROOT / "docs/envelope.md").read_text(),
            (ROOT / "docs/wire.cddl").read_text(),
        )
        validate_executable_profile_contract(
            (ROOT / "crates/aster-core/src/transfer_profile.rs").read_text(),
            (ROOT / "crates/aster-node/src/application/blob.rs").read_text(),
            (ROOT / "crates/aster-core/src/blob.rs").read_text(),
            (ROOT / "crates/aster-core/src/blob_stream.rs").read_text(),
            (ROOT / "crates/aster-node/src/stream_transfer.rs").read_text(),
            (ROOT / "crates/aster-iroh/src/lib.rs").read_text(),
        )
        validate_profile5_schema(
            json.loads((ROOT / "conformance/profile5-wire-schema.json").read_text()),
            (ROOT / "crates/aster-node/src/stream_transfer.rs").read_text(),
        )
        validate_profile5_oracle()
    except (ContractViolation, OSError) as error:
        print(f"protocol version contract check failed: {error}", file=sys.stderr)
        return 1
    print("protocol version contract check passed: semantic versions 1 through 9 align")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
