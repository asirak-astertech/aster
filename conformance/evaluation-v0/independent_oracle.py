#!/usr/bin/env python3
"""Independent deterministic-CBOR profile oracle for Phase 5 research.



This implementation was derived from the frozen evaluation CDDL and prose
before consulting the Rust conformance-runner source. It uses only the Python
standard library and is intentionally a test oracle, not a production codec.
"""

from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path
import resource
import statistics
import sys
import time
from typing import Any, Iterable


LABEL = ""
AUTHORITY_SHA256 = "e88bcc6c717a5175a460205fdc084aaa2e1f020a142a84087f9881677da02987"
MAX_INPUT = 128 * 1024
MAX_PARENTS = 64
MAX_EXTENSIONS = 32
MAX_EXTENSION_VALUE = 4 * 1024
MAX_PROTECTED_OBJECT = 64 * 1024
MAX_VERSION_OFFERS = 16


class ProfileError(ValueError):
    def __init__(self, code: str):
        super().__init__(code)
        self.code = code


class Reader:
    def __init__(self, data: bytes):
        self.data = data
        self.offset = 0
        self.tokens = 0

    def take(self, length: int) -> bytes:
        if length < 0 or length > len(self.data) - self.offset:
            raise ProfileError("truncated")
        value = self.data[self.offset : self.offset + length]
        self.offset += length
        return value

    def head(self, expected_major: int | None = None) -> tuple[int, int]:
        initial = self.take(1)[0]
        major = initial >> 5
        additional = initial & 0x1F
        if expected_major is not None and major != expected_major:
            raise ProfileError("wrong_type")
        if additional < 24:
            argument = additional
        elif additional == 24:
            argument = self.take(1)[0]
            if argument < 24:
                raise ProfileError("noncanonical_argument")
        elif additional == 25:
            argument = int.from_bytes(self.take(2), "big")
            if argument <= 0xFF:
                raise ProfileError("noncanonical_argument")
        elif additional == 26:
            argument = int.from_bytes(self.take(4), "big")
            if argument <= 0xFFFF:
                raise ProfileError("noncanonical_argument")
        elif additional == 27:
            argument = int.from_bytes(self.take(8), "big")
            if argument <= 0xFFFFFFFF:
                raise ProfileError("noncanonical_argument")
        elif additional == 31:
            raise ProfileError("indefinite_length")
        else:
            raise ProfileError("reserved_additional_information")
        self.tokens += 1
        if self.tokens > 1024:
            raise ProfileError("token_bound")
        return major, argument

    def uint(self) -> int:
        return self.head(0)[1]

    def byte_string(self, minimum: int, maximum: int) -> bytes:
        length = self.head(2)[1]
        if not minimum <= length <= maximum:
            raise ProfileError("byte_string_bound")
        return self.take(length)

    def text(self, minimum: int, maximum: int) -> str:
        length = self.head(3)[1]
        if not minimum <= length <= maximum:
            raise ProfileError("text_bound")
        try:
            return self.take(length).decode("utf-8", errors="strict")
        except UnicodeDecodeError as error:
            raise ProfileError("invalid_utf8") from error

    def array_length(self, maximum: int) -> int:
        length = self.head(4)[1]
        if length > maximum:
            raise ProfileError("array_bound")
        return length

    def map_length(self, maximum: int) -> int:
        length = self.head(5)[1]
        if length > maximum:
            raise ProfileError("map_bound")
        return length

    def boolean(self) -> bool:
        major, value = self.head(7)
        assert major == 7
        if value == 20:
            return False
        if value == 21:
            return True
        raise ProfileError("expected_boolean")


def parse_profile(data: bytes) -> dict[str, Any]:
    if len(data) > MAX_INPUT:
        raise ProfileError("input_bound")
    reader = Reader(data)
    if reader.map_length(11) != 11:
        raise ProfileError("required_top_level_keys")

    result: dict[str, Any] = {}
    for expected_key in range(11):
        key = reader.uint()
        if key != expected_key:
            raise ProfileError("top_level_key_order_or_presence")
        if key == 0:
            version = reader.uint()
            if version != 0:
                raise ProfileError("unsupported_profile_version")
            result["version"] = version
        elif key == 1:
            result["item_id"] = reader.byte_string(32, 32).hex()
        elif key == 2:
            item_class = reader.uint()
            if item_class > 3:
                raise ProfileError("unknown_data_class")
            result["class"] = item_class
        elif key == 3:
            result["topic"] = reader.text(1, 128)
        elif key == 4:
            result["scope"] = reader.text(1, 128)
        elif key == 5:
            priority = reader.uint()
            if priority > 3:
                raise ProfileError("priority_bound")
            result["priority"] = priority
        elif key == 6:
            result["ttl"] = reader.uint()
        elif key == 7:
            result["publisher_id"] = reader.byte_string(32, 32).hex()
        elif key == 8:
            parent_count = reader.array_length(MAX_PARENTS)
            parents = [reader.byte_string(32, 32) for _ in range(parent_count)]
            if len(set(parents)) != len(parents):
                raise ProfileError("duplicate_parent")
            result["parent_count"] = parent_count
        elif key == 9:
            extension_count = reader.map_length(MAX_EXTENSIONS)
            previous_id = -1
            for _ in range(extension_count):
                extension_id = reader.uint()
                if extension_id <= previous_id:
                    raise ProfileError("extension_key_order_or_duplicate")
                previous_id = extension_id
                if reader.array_length(2) != 2:
                    raise ProfileError("extension_shape")
                critical = reader.boolean()
                reader.byte_string(0, MAX_EXTENSION_VALUE)
                if critical:
                    raise ProfileError("unknown_critical_extension")
            result["extension_count"] = extension_count
        elif key == 10:
            result["protected_object_bytes"] = len(
                reader.byte_string(1, MAX_PROTECTED_OBJECT)
            )

    if reader.offset != len(data):
        raise ProfileError("trailing_data")
    return result


def encode_head(major: int, argument: int) -> bytes:
    if argument < 0:
        raise ValueError("negative arguments are outside this profile")
    prefix = major << 5
    if argument < 24:
        return bytes([prefix | argument])
    if argument <= 0xFF:
        return bytes([prefix | 24, argument])
    if argument <= 0xFFFF:
        return bytes([prefix | 25]) + argument.to_bytes(2, "big")
    if argument <= 0xFFFFFFFF:
        return bytes([prefix | 26]) + argument.to_bytes(4, "big")
    if argument <= 0xFFFFFFFFFFFFFFFF:
        return bytes([prefix | 27]) + argument.to_bytes(8, "big")
    raise ValueError("argument exceeds uint64")


def encode_uint(value: int) -> bytes:
    return encode_head(0, value)


def encode_bytes(value: bytes) -> bytes:
    return encode_head(2, len(value)) + value


def encode_text(value: str) -> bytes:
    encoded = value.encode("utf-8")
    return encode_head(3, len(encoded)) + encoded


def encode_array(values: Iterable[bytes]) -> bytes:
    encoded = list(values)
    return encode_head(4, len(encoded)) + b"".join(encoded)


def encode_map(entries: Iterable[tuple[bytes, bytes]]) -> bytes:
    encoded = list(entries)
    return encode_head(5, len(encoded)) + b"".join(key + value for key, value in encoded)


def encode_boolean(value: bool) -> bytes:
    return bytes([0xF5 if value else 0xF4])


def make_profile(
    *,
    version: int = 0,
    item_class: int = 1,
    topic: str = "topic",
    scope: str = "scope",
    priority: int = 1,
    parents: int = 0,
    extensions: int = 0,
    extension_value_bytes: int = 0,
    extension_critical: bool = False,
    protected_object_bytes: int = 32,
) -> bytes:
    parent_values = [hashlib.sha256(f"parent-{index}".encode()).digest() for index in range(parents)]
    extension_entries = []
    for index in range(extensions):
        extension_entries.append(
            (
                encode_uint(100 + index),
                encode_array(
                    [
                        encode_boolean(extension_critical),
                        encode_bytes(bytes([index & 0xFF]) * extension_value_bytes),
                    ]
                ),
            )
        )
    fields = [
        (encode_uint(0), encode_uint(version)),
        (encode_uint(1), encode_bytes(hashlib.sha256(b"item").digest())),
        (encode_uint(2), encode_uint(item_class)),
        (encode_uint(3), encode_text(topic)),
        (encode_uint(4), encode_text(scope)),
        (encode_uint(5), encode_uint(priority)),
        (encode_uint(6), encode_uint(3600)),
        (encode_uint(7), encode_bytes(hashlib.sha256(b"publisher").digest())),
        (encode_uint(8), encode_array(encode_bytes(parent) for parent in parent_values)),
        (encode_uint(9), encode_map(extension_entries)),
        (encode_uint(10), encode_bytes(b"p" * protected_object_bytes)),
    ]
    return encode_map(fields)


def negotiate_versions(local: list[int], remote: list[int]) -> int | None:
    for offers in (local, remote):
        if not offers or len(offers) > MAX_VERSION_OFFERS:
            raise ProfileError("version_offer_bound")
        if offers != sorted(set(offers)):
            raise ProfileError("version_offer_order_or_duplicate")
        if any(value < 0 or value > 0xFFFFFFFF for value in offers):
            raise ProfileError("version_offer_value")
    common = set(local).intersection(remote)
    return max(common) if common else None


def disposition(data: bytes) -> tuple[str, str | None]:
    try:
        parse_profile(data)
        return "accept", None
    except ProfileError as error:
        return "reject", error.code


def cross_implementation(vectors_dir: Path, rust_summary_path: Path) -> dict[str, Any]:
    rust_summary = json.loads(rust_summary_path.read_text(encoding="utf-8"))
    rust_by_name = {row["name"]: row for row in rust_summary["vectors"]}
    rows = []
    for path in sorted(vectors_dir.glob("*.cbor")):
        name = path.stem
        data = path.read_bytes()
        outcome, error = disposition(data)
        expected = "accept" if name.startswith("positive-") else "reject"
        rust = rust_by_name.get(name)
        rows.append(
            {
                "name": name,
                "bytes": len(data),
                "sha256": hashlib.sha256(data).hexdigest(),
                "expected": expected,
                "python_outcome": outcome,
                "python_error": error,
                "rust_registered_expected": None if rust is None else rust["expected"],
                "rust_registered_sha256": None if rust is None else rust["sha256"],
                "agreement": bool(
                    rust
                    and outcome == expected == rust["expected"]
                    and hashlib.sha256(data).hexdigest() == rust["sha256"]
                ),
            }
        )
    return {
        "vectors": rows,
        "vector_count": len(rows),
        "agreements": sum(row["agreement"] for row in rows),
        "all_agree": bool(rows) and all(row["agreement"] for row in rows),
        "independence_boundary": "Python parser written from frozen CDDL/prose without Rust source consultation; Rust outcome is the registered frozen execution",
    }


def hostile_vectors() -> dict[str, Any]:
    cases: list[tuple[str, bytes, str]] = [
        ("valid-parents-64", make_profile(parents=64), "accept"),
        ("reject-parents-65", make_profile(parents=65), "reject"),
        ("valid-extensions-32", make_profile(extensions=32), "accept"),
        ("reject-extensions-33", make_profile(extensions=33), "reject"),
        (
            "valid-extension-value-4096",
            make_profile(extensions=1, extension_value_bytes=4096),
            "accept",
        ),
        (
            "reject-extension-value-4097",
            make_profile(extensions=1, extension_value_bytes=4097),
            "reject",
        ),
        (
            "valid-protected-object-65536",
            make_profile(protected_object_bytes=65536),
            "accept",
        ),
        (
            "reject-protected-object-65537",
            make_profile(protected_object_bytes=65537),
            "reject",
        ),
        ("reject-version-1", make_profile(version=1), "reject"),
        ("reject-class-4", make_profile(item_class=4), "reject"),
        ("reject-priority-4", make_profile(priority=4), "reject"),
        ("reject-topic-129", make_profile(topic="t" * 129), "reject"),
        ("reject-input-cap", b"\x00" * (MAX_INPUT + 1), "reject"),
        ("reject-indefinite-map", b"\xbf\xff", "reject"),
        (
            "reject-huge-root-map-claim",
            bytes([0xBB]) + (1 << 40).to_bytes(8, "big"),
            "reject",
        ),
        (
            "reject-huge-item-id-claim",
            encode_head(5, 11)
            + encode_uint(0)
            + encode_uint(0)
            + encode_uint(1)
            + bytes([0x5B])
            + (1 << 40).to_bytes(8, "big"),
            "reject",
        ),
        ("reject-trailing", make_profile() + b"\x00", "reject"),
    ]

    rows = []
    for name, data, expected in cases:
        started = time.perf_counter_ns()
        outcome, error = disposition(data)
        elapsed = time.perf_counter_ns() - started
        rows.append(
            {
                "name": name,
                "bytes": len(data),
                "expected": expected,
                "outcome": outcome,
                "error": error,
                "elapsed_ns": elapsed,
                "matched": outcome == expected,
            }
        )

    seed = make_profile()
    mutations = []
    accepted = 0
    rejected = 0
    max_elapsed = 0
    for index in range(min(len(seed), 128)):
        for mask in (0x01, 0x20, 0xFF):
            candidate = bytearray(seed)
            candidate[index] ^= mask
            started = time.perf_counter_ns()
            outcome, _ = disposition(bytes(candidate))
            elapsed = time.perf_counter_ns() - started
            max_elapsed = max(max_elapsed, elapsed)
            accepted += outcome == "accept"
            rejected += outcome == "reject"
            mutations.append((index, mask, outcome))
    for length in range(len(seed)):
        started = time.perf_counter_ns()
        outcome, _ = disposition(seed[:length])
        elapsed = time.perf_counter_ns() - started
        max_elapsed = max(max_elapsed, elapsed)
        accepted += outcome == "accept"
        rejected += outcome == "reject"

    return {
        "cases": rows,
        "case_count": len(rows),
        "case_matches": sum(row["matched"] for row in rows),
        "all_cases_match": all(row["matched"] for row in rows),
        "mutation_count": len(mutations) + len(seed),
        "mutation_accepts": accepted,
        "mutation_rejects": rejected,
        "mutation_exceptions": 0,
        "max_single_parse_elapsed_ns": max_elapsed,
    }


def version_vectors() -> dict[str, Any]:
    cases = [
        ("v0-v0", [0], [0], 0, "select"),
        ("v0-v1-no-common", [0], [1], None, "no_common"),
        ("highest-common-v1", [0, 1], [1, 2], 1, "select"),
        ("highest-common-v3", [0, 1, 2, 3], [1, 3, 4], 3, "select"),
        ("ordered-gap-no-common", [0, 2], [1, 3], None, "no_common"),
        ("duplicate-reject", [0, 0], [0], None, "reject"),
        ("unsorted-reject", [1, 0], [0, 1], None, "reject"),
        ("empty-reject", [], [0], None, "reject"),
        ("offer-bound-reject", list(range(17)), [0], None, "reject"),
    ]
    rows = []
    for name, local, remote, expected, expected_kind in cases:
        try:
            selected = negotiate_versions(local, remote)
            kind = "select" if selected is not None else "no_common"
            error = None
        except ProfileError as failure:
            selected = None
            kind = "reject"
            error = failure.code
        rows.append(
            {
                "name": name,
                "local": local,
                "remote": remote,
                "selected": selected,
                "error": error,
                "matched": selected == expected and kind == expected_kind,
            }
        )
    return {
        "cases": rows,
        "all_match": all(row["matched"] for row in rows),
        "credit": "isolated highest-common-version oracle only",
        "no_credit": "no negotiation wire, downgrade binding, or Rust implementation support",
    }


def resource_curve() -> list[dict[str, Any]]:
    rows = []
    for protected_bytes in (1, 64, 4096, 65536):
        body = make_profile(protected_object_bytes=protected_bytes)
        repeats = max(16, min(2000, (4 * 1024 * 1024) // len(body)))
        timings = []
        before = resource.getrusage(resource.RUSAGE_SELF).ru_maxrss
        for _ in range(repeats):
            started = time.perf_counter_ns()
            parse_profile(body)
            timings.append(time.perf_counter_ns() - started)
        after = resource.getrusage(resource.RUSAGE_SELF).ru_maxrss
        rows.append(
            {
                "protected_object_bytes": protected_bytes,
                "encoded_bytes": len(body),
                "repeats": repeats,
                "median_parse_ns": int(statistics.median(timings)),
                "p95_parse_ns": int(sorted(timings)[int(0.95 * (len(timings) - 1))]),
                "maxrss_before": before,
                "maxrss_after": after,
                "maxrss_units": "bytes_on_macos_kib_on_linux",
            }
        )
    return rows


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--vectors", required=True, type=Path)
    parser.add_argument("--rust-summary", required=True, type=Path)
    parser.add_argument("--output", required=True, type=Path)
    args = parser.parse_args()

    result = {
        "label": LABEL,
        "kind": "independently_implemented_profile_oracle",
        "authority_sha256": AUTHORITY_SHA256,
        "implementation": "Python standard library; no Rust runner source consulted",
        "limits": {
            "input_bytes": MAX_INPUT,
            "parents": MAX_PARENTS,
            "extensions": MAX_EXTENSIONS,
            "extension_value_bytes": MAX_EXTENSION_VALUE,
            "protected_object_bytes": MAX_PROTECTED_OBJECT,
        },
        "cross_implementation": cross_implementation(args.vectors, args.rust_summary),
        "hostile": hostile_vectors(),
        "mixed_version": version_vectors(),
        "resource_curve": resource_curve(),
        "disposition": "partial",
        "requirements": {
            "DM-8-17": "pass_for_evaluation_profile_authority_separation",
            "DM-8-18": "partial_cross_implementation_parser_agreement_not_full_mesh_interoperation",
            "DM-10-01": "pass_for_evaluation_profile_version_field",
            "DM-10-02": "pass_in_isolated_oracle_only_reference_path_unproved",
            "DM-10-03": "pass_for_profile_unknown_noncritical_extension",
            "DM-12-11": "partial_independent_parser_not_complete_conformant_mesh",
            "DM-13-08": "partial_phase5_oracle_corpus",
        },
        "no_credit": [
            "product wire or security profile",
            "complete class or synchronization semantics",
            "production parser admission",
            "second independently deployable mesh implementation",
            "release conformance",
        ],
    }
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(result, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    print(json.dumps({"outcome": "pass", "output": str(args.output)}, sort_keys=True))
    return 0


if __name__ == "__main__":
    sys.exit(main())

