#!/usr/bin/env python3
"""Separate standard-library decoder for the checked-in Aster wire corpus.

This code path does not import, execute, or bind the Rust reference encoder. It
is authored by the same project team, so it is explicitly not an
independent-team oracle or SUT claim. Passing it demonstrates only code-path and
language diversity.
"""

from __future__ import annotations

import json
import sys
from dataclasses import dataclass
from pathlib import Path
from typing import Any


MAX_DEPTH = 16
MAX_CONTAINER_ITEMS = 4_096
MAX_MESSAGE_BYTES = 1024 * 1024
MAX_BYTE_STRING = 1024 * 1024
MAX_TEXT_BYTES = 4_096


class Rejected(ValueError):
    """A noncanonical, malformed, unsupported, or semantically invalid value."""


@dataclass
class Reader:
    data: bytes
    offset: int = 0

    def take(self, length: int) -> bytes:
        if length < 0 or self.offset + length > len(self.data):
            raise Rejected("truncated value")
        value = self.data[self.offset : self.offset + length]
        self.offset += length
        return value

    def byte(self) -> int:
        return self.take(1)[0]

    def argument(self, additional: int) -> int:
        if additional < 24:
            return additional
        widths = {24: 1, 25: 2, 26: 4, 27: 8}
        width = widths.get(additional)
        if width is None:
            raise Rejected("indefinite or reserved additional information")
        value = int.from_bytes(self.take(width), "big")
        minimum = {1: 24, 2: 1 << 8, 4: 1 << 16, 8: 1 << 32}[width]
        if value < minimum:
            raise Rejected("nonminimal integer or length")
        return value


def decode_one(reader: Reader, depth: int = 0) -> Any:
    if depth > MAX_DEPTH:
        raise Rejected("nesting limit")
    initial = reader.byte()
    major, additional = initial >> 5, initial & 0x1F
    if major == 7:
        if additional == 20:
            return False
        if additional == 21:
            return True
        if additional == 22:
            return None
        raise Rejected("unsupported simple, float, or break value")
    argument = reader.argument(additional)
    if major == 0:
        return argument
    if major == 1:
        return -1 - argument
    if major == 2:
        if argument > MAX_BYTE_STRING:
            raise Rejected("byte string limit")
        return reader.take(argument)
    if major == 3:
        if argument > MAX_TEXT_BYTES:
            raise Rejected("text limit")
        try:
            return reader.take(argument).decode("utf-8", "strict")
        except UnicodeDecodeError as error:
            raise Rejected("invalid UTF-8") from error
    if major == 4:
        if argument > MAX_CONTAINER_ITEMS:
            raise Rejected("array limit")
        return [decode_one(reader, depth + 1) for _ in range(argument)]
    if major == 5:
        if argument > MAX_CONTAINER_ITEMS:
            raise Rejected("map limit")
        result: dict[int, Any] = {}
        previous = -1
        for _ in range(argument):
            key = decode_one(reader, depth + 1)
            if type(key) is not int or key <= previous:
                raise Rejected("map keys must be unique increasing unsigned integers")
            previous = key
            result[key] = decode_one(reader, depth + 1)
        return result
    raise Rejected("tags are outside the profile")


def decode(encoded: bytes) -> Any:
    if len(encoded) > MAX_MESSAGE_BYTES:
        raise Rejected("message limit")
    reader = Reader(encoded)
    value = decode_one(reader)
    if reader.offset != len(encoded):
        raise Rejected("trailing bytes")
    return value


def head(major: int, value: int) -> bytes:
    if value < 0:
        raise AssertionError("negative canonical value")
    if value < 24:
        return bytes([(major << 5) | value])
    if value < 1 << 8:
        return bytes([(major << 5) | 24, value])
    if value < 1 << 16:
        return bytes([(major << 5) | 25]) + value.to_bytes(2, "big")
    if value < 1 << 32:
        return bytes([(major << 5) | 26]) + value.to_bytes(4, "big")
    if value < 1 << 64:
        return bytes([(major << 5) | 27]) + value.to_bytes(8, "big")
    raise Rejected("integer exceeds u64")


def encode(value: Any) -> bytes:
    if value is False:
        return b"\xf4"
    if value is True:
        return b"\xf5"
    if value is None:
        return b"\xf6"
    if type(value) is int:
        return head(0, value) if value >= 0 else head(1, -1 - value)
    if isinstance(value, bytes):
        return head(2, len(value)) + value
    if isinstance(value, str):
        encoded = value.encode("utf-8")
        return head(3, len(encoded)) + encoded
    if isinstance(value, list):
        return head(4, len(value)) + b"".join(encode(item) for item in value)
    if isinstance(value, dict):
        keys = sorted(value)
        return head(5, len(keys)) + b"".join(
            encode(key) + encode(value[key]) for key in keys
        )
    raise AssertionError(f"unsupported decoded type: {type(value)!r}")


def unsigned(value: Any, field: str) -> int:
    if type(value) is not int or value < 0:
        raise Rejected(f"{field} must be unsigned")
    return value


def array(value: Any, field: str) -> list[Any]:
    if not isinstance(value, list):
        raise Rejected(f"{field} must be an array")
    return value


def byte_string(value: Any, field: str, length: int | None = None) -> bytes:
    if not isinstance(value, bytes) or (length is not None and len(value) != length):
        raise Rejected(f"{field} byte length")
    return value


def boolean(value: Any, field: str) -> bool:
    if type(value) is not bool:
        raise Rejected(f"{field} must be boolean")
    return value


def protocol_map(value: Any, required: set[int], allowed: set[int], field: str) -> dict[int, Any]:
    if not isinstance(value, dict):
        raise Rejected(f"{field} must be a map")
    missing = required.difference(value)
    if missing:
        raise Rejected(f"{field} missing fields")
    for key in value:
        if key <= 63 and key not in allowed:
            raise Rejected(f"{field} unknown critical field")
    return value


def sorted_unique(values: list[Any], field: str) -> None:
    if any(left >= right for left, right in zip(values, values[1:])):
        raise Rejected(f"{field} must be strictly increasing")


def text(value: Any, field: str) -> str:
    if not isinstance(value, str):
        raise Rejected(f"{field} must be text")
    return value


def object_id(value: Any) -> bytes:
    encoded = byte_string(value, "ObjectID", 33)
    if encoded[0] not in (1, 2):
        raise Rejected("unknown ObjectID kind")
    return encoded


def ranges(value: Any, total: int | None = None) -> list[tuple[int, int]]:
    decoded: list[tuple[int, int]] = []
    prior_end: int | None = None
    for pair in array(value, "ranges"):
        pair = array(pair, "range")
        if len(pair) != 2:
            raise Rejected("range arity")
        start, end = unsigned(pair[0], "range start"), unsigned(pair[1], "range end")
        if (
            start >= end
            or (prior_end is not None and start <= prior_end)
            or (total is not None and end > total)
        ):
            raise Rejected("invalid or overlapping range")
        decoded.append((start, end))
        prior_end = end
    return decoded


def packed_prefix(value: Any, nibbles: Any) -> None:
    prefix = byte_string(value, "prefix")
    count = unsigned(nibbles, "prefix nibbles")
    if count > 66 or len(prefix) != (count + 1) // 2:
        raise Rejected("prefix length")
    if count % 2 and prefix and prefix[-1] & 0x0F:
        raise Rejected("nonzero unused prefix nibble")


def validate_message(value: Any) -> None:
    common = protocol_map(value, {0, 1, 2}, set(range(64)), "message")
    if unsigned(common[0], "version") != 1:
        raise Rejected("unsupported protocol version")
    kind = unsigned(common[1], "kind")
    unsigned(common[2], "exchange")
    fields = {
        1: {0, 1, 2, 3, 4, 5, 6},
        2: {0, 1, 2, 3, 4, 5},
        3: {0, 1, 2, 3, 4, 5},
        4: {0, 1, 2, 3, 4, 5, 6, 7, 8},
        5: {0, 1, 2, 3, 4},
        6: {0, 1, 2, 3},
        7: {0, 1, 2, 3, 4, 5, 6, 7},
        8: {0, 1, 2, 3, 4, 5, 6},
    }.get(kind)
    if fields is None:
        raise Rejected("unknown message kind")
    message = protocol_map(value, fields, fields, "message")

    if kind == 1:
        topics = [text(item, "topic") for item in array(message[3], "topics")]
        scopes = [text(item, "scope") for item in array(message[4], "scopes")]
        sorted_unique(topics, "topics")
        sorted_unique(scopes, "scopes")
        max_offers = unsigned(message[6], "max offers")
        if unsigned(message[5], "priority") > 3 or not 1 <= max_offers <= 0xFFFF_FFFF:
            raise Rejected("interest bounds")
    elif kind == 2:
        byte_string(message[3], "root", 32)
        unsigned(message[4], "item count")
        unsigned(message[5], "snapshot")
    elif kind == 3:
        packed_prefix(message[3], message[4])
        unsigned(message[5], "snapshot")
    elif kind == 4:
        packed_prefix(message[3], message[4])
        byte_string(message[5], "node hash", 32)
        unsigned(message[6], "node count")
        children = array(message[7], "children")
        if len(children) > 16:
            raise Rejected("too many children")
        prior = -1
        child_count = 0
        for child_value in children:
            child = protocol_map(child_value, {0, 1, 2}, {0, 1, 2}, "child")
            nibble = unsigned(child[0], "child nibble")
            if nibble > 15 or nibble <= prior:
                raise Rejected("child order")
            prior = nibble
            byte_string(child[1], "child hash", 32)
            count = unsigned(child[2], "child count")
            if count == 0:
                raise Rejected("empty child")
            child_count += count
        prefix_nibbles = unsigned(message[4], "prefix nibbles")
        item_count = unsigned(message[6], "node count")
        if prefix_nibbles < 66 and child_count != item_count:
            raise Rejected("node child count mismatch")
        if prefix_nibbles == 66 and (children or item_count > 1):
            raise Rejected("invalid leaf node")
        unsigned(message[8], "snapshot")
    elif kind == 5:
        identifiers = [object_id(item) for item in array(message[3], "offers")]
        sorted_unique(identifiers, "offers")
        unsigned(message[4], "snapshot")
    elif kind == 6:
        identifiers: list[bytes] = []
        for entry_value in array(message[3], "wants"):
            entry = protocol_map(entry_value, {0, 1, 2, 3}, {0, 1, 2, 3}, "want entry")
            identifier = object_id(entry[0])
            identifiers.append(identifier)
            total_value = entry[1]
            total = None if total_value is None else unsigned(total_value, "total")
            missing = ranges(entry[2], total)
            forwarding = boolean(entry[3], "forwarding")
            if identifier[0] == 2 and forwarding:
                raise Rejected("Blob forwarding wrapper")
            if total is None and missing:
                raise Rejected("unknown total with ranges")
            if total is not None and not missing and not forwarding:
                raise Rejected("want requests no work")
        sorted_unique(identifiers, "wants")
    elif kind == 7:
        identifier = object_id(message[3])
        total = unsigned(message[4], "total")
        offset = unsigned(message[5], "offset")
        payload = byte_string(message[6], "payload")
        forwarding = byte_string(message[7], "forwarding")
        if (
            offset + len(payload) > total
            or (not payload and not forwarding)
            or (identifier[0] == 2 and forwarding)
        ):
            raise Rejected("DATA bounds")
    elif kind == 8:
        object_id(message[3])
        total = unsigned(message[4], "total")
        received = ranges(message[5], total)
        complete = boolean(message[6], "complete")
        covered = total == 0 or received == [(0, total)]
        if complete != covered:
            raise Rejected("Receipt completeness mismatch")


def evaluate(path: Path) -> dict[str, Any]:
    accepted = rejected = failures = 0
    cases: list[dict[str, str]] = []
    header = ""
    for line_number, raw_line in enumerate(path.read_text(encoding="utf-8").splitlines(), 1):
        if not raw_line:
            continue
        if raw_line.startswith("#"):
            header = raw_line[1:].strip()
            continue
        try:
            disposition, case_id, encoded_hex = raw_line.split("\t")
            encoded = bytes.fromhex(encoded_hex)
        except (ValueError, TypeError) as error:
            raise Rejected(f"invalid corpus row {line_number}") from error
        passed = False
        detail = ""
        try:
            value = decode(encoded)
            validate_message(value)
            if encode(value) != encoded:
                raise Rejected("canonical re-encoding differs")
            passed = disposition == "ACCEPT"
            detail = "accepted" if passed else "unexpected acceptance"
        except Rejected as error:
            passed = disposition == "REJECT"
            detail = "rejected" if passed else str(error)
        if disposition == "ACCEPT":
            accepted += 1
        elif disposition == "REJECT":
            rejected += 1
        else:
            raise Rejected(f"unknown disposition on row {line_number}")
        if not passed:
            failures += 1
        cases.append({"id": case_id, "result": "pass" if passed else "fail", "detail": detail})
    return {
        "schema": "aster-python-wire-oracle/v1",
        "protocol": 1,
        "oracle": "same-team-not-independent-python-codepath",
        "corpus_header": header,
        "accepted_cases": accepted,
        "rejected_cases": rejected,
        "result": "pass" if failures == 0 else "fail",
        "cases": cases,
    }


def main() -> int:
    if len(sys.argv) > 2:
        print(f"usage: {Path(sys.argv[0]).name} [WIRE_VECTORS_TSV]", file=sys.stderr)
        return 2
    path = (
        Path(sys.argv[1])
        if len(sys.argv) == 2
        else Path(__file__).with_name("vectors") / "wire-v1.tsv"
    )
    try:
        result = evaluate(path)
    except (OSError, Rejected) as error:
        print(json.dumps({"schema": "aster-python-wire-oracle/v1", "result": "error", "detail": str(error)}, sort_keys=True))
        return 2
    print(json.dumps(result, sort_keys=True, separators=(",", ":")))
    return 0 if result["result"] == "pass" else 1


if __name__ == "__main__":
    raise SystemExit(main())
