#!/usr/bin/env python3
"""Verify the exact source and manifest-only netlink compatibility patch."""

from __future__ import annotations

import hashlib
import sys
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
VENDOR = ROOT / "third-party/netlink-packet-core-0.8.2-aster"
MANIFEST = VENDOR / "ASTER-UPSTREAM.sha256"
OMITTED = {
    ".github/workflows/clippy-rustfmt.yml",
    ".github/workflows/license.yml",
    ".github/workflows/main.yml",
    "Cargo.lock",
}
ADDED = {"ASTER-PATCH.md", "ASTER-UPSTREAM.sha256"}
PATCHED = {"Cargo.toml", "Cargo.toml.orig"}
ARCHIVE_SHA256 = "b897d7bd4f0af82e68d40d0344cf37e97f9c97ddf74a098de3e4da05e96ca395"


def digest(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def read_manifest() -> dict[str, str]:
    entries: dict[str, str] = {}
    for line_number, line in enumerate(
        MANIFEST.read_text(encoding="utf-8").splitlines(), start=1
    ):
        checksum, separator, relative = line.partition("  ")
        if (
            not separator
            or len(checksum) != 64
            or any(character not in "0123456789abcdef" for character in checksum)
            or not relative
            or relative in entries
        ):
            raise ValueError(f"invalid upstream manifest line {line_number}")
        entries[relative] = checksum
    return entries


def reconstruct_upstream(relative: str, patched: bytes) -> bytes:
    if relative == "Cargo.toml":
        old = b'[dependencies.paste]\npackage = "pastey"\nversion = "=0.2.2"'
        new = b'[dependencies.paste]\nversion = "1"'
    elif relative == "Cargo.toml.orig":
        old = b'paste = { package = "pastey", version = "=0.2.2" }'
        new = b'paste = "1"'
    else:
        raise ValueError(f"unexpected patched path: {relative}")
    if patched.count(old) != 1:
        raise ValueError(f"{relative}: exact pastey manifest delta not found once")
    return patched.replace(old, new)


def main() -> int:
    try:
        upstream = read_manifest()
        actual = {
            path.relative_to(VENDOR).as_posix()
            for path in VENDOR.rglob("*")
            if path.is_file()
        }
        expected = (set(upstream) - OMITTED) | ADDED
        if actual != expected:
            missing = sorted(expected - actual)
            extra = sorted(actual - expected)
            raise ValueError(f"vendored file-set drift: missing={missing}, extra={extra}")

        for relative, expected_digest in upstream.items():
            if relative in OMITTED:
                continue
            contents = (VENDOR / relative).read_bytes()
            if relative in PATCHED:
                contents = reconstruct_upstream(relative, contents)
            if digest(contents) != expected_digest:
                raise ValueError(f"{relative}: differs from the registered upstream bytes")

        patch_note = (VENDOR / "ASTER-PATCH.md").read_text(encoding="utf-8")
        normalized_patch_note = " ".join(patch_note.split())
        if (
            ARCHIVE_SHA256 not in patch_note
            or "No Rust source files are modified" not in normalized_patch_note
        ):
            raise ValueError("ASTER-PATCH.md is missing its archive or source-equivalence binding")

        root_manifest = (ROOT / "Cargo.toml").read_text(encoding="utf-8")
        expected_patch = 'netlink-packet-core = { path = "third-party/netlink-packet-core-0.8.2-aster" }'
        if root_manifest.count(expected_patch) != 1:
            raise ValueError("root Cargo patch is missing or duplicated")

        lock = (ROOT / "Cargo.lock").read_text(encoding="utf-8")
        if '\nname = "paste"\n' in lock:
            raise ValueError("unmaintained paste package remains in Cargo.lock")
        if lock.count('\nname = "pastey"\nversion = "0.2.2"\n') != 1:
            raise ValueError("Cargo.lock does not contain exact pastey 0.2.2 once")
    except (OSError, ValueError) as error:
        print(f"netlink patch verification failed: {error}", file=sys.stderr)
        return 1

    retained = len(upstream) - len(OMITTED)
    print(
        "netlink patch verification passed: "
        f"{retained} retained upstream files, two exact manifest deltas, "
        "no Rust-source drift, paste absent"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
