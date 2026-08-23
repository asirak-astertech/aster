#!/usr/bin/env python3
"""Verify the frozen v0-r1 evidence and corrected v0-r2 result."""

from __future__ import annotations

import hashlib
import json
import os
import subprocess
import tempfile
from pathlib import Path
from typing import Any


CORPUS_ROOT = Path(__file__).resolve().parent
REPOSITORY_ROOT = CORPUS_ROOT.parents[1]
RUNNER_MANIFEST = CORPUS_ROOT / "runner" / "Cargo.toml"


def fail(message: str) -> None:
    raise SystemExit(message)


def require(condition: bool, message: str) -> None:
    if not condition:
        fail(message)


def sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as artifact:
        for chunk in iter(lambda: artifact.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def verify_manifest(name: str, expected_entries: int) -> None:
    manifest = CORPUS_ROOT / name
    seen: set[Path] = set()
    entries = 0

    for line_number, line in enumerate(manifest.read_text(encoding="utf-8").splitlines(), 1):
        expected, separator, relative_name = line.partition("  ")
        require(separator == "  ", f"{name}:{line_number}: malformed manifest entry")
        require(
            len(expected) == 64 and all(character in "0123456789abcdef" for character in expected),
            f"{name}:{line_number}: invalid SHA-256",
        )
        require(relative_name != "", f"{name}:{line_number}: empty artifact path")

        artifact = (CORPUS_ROOT / relative_name).resolve()
        try:
            artifact.relative_to(REPOSITORY_ROOT)
        except ValueError:
            fail(f"{name}:{line_number}: artifact escapes the repository")
        require(artifact not in seen, f"{name}:{line_number}: duplicate artifact path")
        require(artifact.is_file(), f"{name}:{line_number}: missing {relative_name}")
        require(sha256(artifact) == expected, f"{name}:{line_number}: digest mismatch for {relative_name}")

        seen.add(artifact)
        entries += 1

    require(entries == expected_entries, f"{name}: expected {expected_entries} entries, found {entries}")


def load_json(name: str) -> dict[str, Any]:
    artifact = CORPUS_ROOT / name
    try:
        value = json.loads(artifact.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as error:
        fail(f"{name}: invalid JSON: {error}")
    require(isinstance(value, dict), f"{name}: top-level JSON value must be an object")
    return value


def verify_reproduction() -> None:
    with tempfile.TemporaryDirectory(prefix="aster-profile-v0-r2-") as temporary:
        temporary_root = Path(temporary)
        target = temporary_root / "target"
        generated_vectors = temporary_root / "vectors"
        generated_summary = temporary_root / "summary.json"
        environment = os.environ.copy()
        environment["CARGO_TARGET_DIR"] = str(target)

        try:
            subprocess.run(
                [
                    "cargo",
                    "build",
                    "--release",
                    "--locked",
                    "--offline",
                    "--manifest-path",
                    str(RUNNER_MANIFEST),
                ],
                cwd=REPOSITORY_ROOT,
                env=environment,
                check=True,
            )
            executable = target / "release" / (
                "mesh-eval-conformance.exe" if os.name == "nt" else "mesh-eval-conformance"
            )
            with generated_summary.open("wb") as output:
                subprocess.run(
                    [str(executable), str(generated_vectors)],
                    cwd=REPOSITORY_ROOT,
                    stdout=output,
                    check=True,
                )
        except (OSError, subprocess.CalledProcessError) as error:
            fail(f"v0-r2 reproduction failed: {error}")

        committed_vectors = CORPUS_ROOT / "vectors-v0-r2"
        expected_names = sorted(path.name for path in committed_vectors.glob("*.cbor"))
        generated_names = sorted(path.name for path in generated_vectors.glob("*.cbor"))
        require(len(expected_names) == 18, "vectors-v0-r2: expected exactly 18 committed vectors")
        require(generated_names == expected_names, "v0-r2 reproduction produced a different vector set")
        for vector_name in expected_names:
            require(
                (generated_vectors / vector_name).read_bytes()
                == (committed_vectors / vector_name).read_bytes(),
                f"v0-r2 reproduction differs for {vector_name}",
            )
        require(
            generated_summary.read_bytes() == (CORPUS_ROOT / "summary-v0-r2.json").read_bytes(),
            "v0-r2 reproduction differs from summary-v0-r2.json",
        )


def verify_summary() -> dict[str, dict[str, Any]]:
    name = "summary-v0-r2.json"
    summary = load_json(name)
    required_header = {
        "artifact_kind": "candidate_neutral_conformance_vector_result",
        "profile": "mesh-eval-envelope-v0",
        "corpus_revision": "v0-r2",
        "known_extension_ids": [],
        "outcome": "pass",
        "vector_count": 18,
        "positive_count": 5,
        "negative_count": 13,
        "decoder_agreement_count": 18,
    }
    for key, expected in required_header.items():
        require(summary.get(key) == expected, f"{name}: {key} must be {expected!r}")

    vectors = summary.get("vectors")
    require(isinstance(vectors, list) and len(vectors) == 18, f"{name}: expected 18 vector rows")
    by_name: dict[str, dict[str, Any]] = {}
    positive_count = 0
    for index, vector in enumerate(vectors):
        require(isinstance(vector, dict), f"{name}: vector row {index} must be an object")
        vector_name = vector.get("name")
        require(isinstance(vector_name, str) and vector_name, f"{name}: vector row {index} has no name")
        require(vector_name not in by_name, f"{name}: duplicate vector {vector_name}")

        expected = vector.get("expected")
        require(expected in {"accept", "reject"}, f"{name}: invalid expected outcome for {vector_name}")
        require(vector.get("minicbor") == expected, f"{name}: minicbor disagrees for {vector_name}")
        require(vector.get("ciborium") == expected, f"{name}: ciborium disagrees for {vector_name}")

        vector_path = CORPUS_ROOT / "vectors-v0-r2" / f"{vector_name}.cbor"
        require(vector_path.is_file(), f"{name}: missing bytes for {vector_name}")
        require(vector.get("bytes") == vector_path.stat().st_size, f"{name}: byte count mismatch for {vector_name}")
        require(vector.get("sha256") == sha256(vector_path), f"{name}: SHA-256 mismatch for {vector_name}")

        positive_count += expected == "accept"
        by_name[vector_name] = vector

    require(positive_count == 5, f"{name}: expected 5 accepting vectors")
    require(len(by_name) - positive_count == 13, f"{name}: expected 13 rejecting vectors")
    return by_name


def verify_independent(summary_by_name: dict[str, dict[str, Any]]) -> None:
    name = "independent-v0-r2.json"
    independent = load_json(name)
    comparison = independent.get("cross_implementation")
    require(isinstance(comparison, dict), f"{name}: cross_implementation must be an object")
    require(comparison.get("all_agree") is True, f"{name}: all_agree must be true")
    require(comparison.get("agreements") == 18, f"{name}: agreements must be 18")
    require(comparison.get("vector_count") == 18, f"{name}: vector_count must be 18")

    vectors = comparison.get("vectors")
    require(isinstance(vectors, list) and len(vectors) == 18, f"{name}: expected 18 comparison rows")
    seen: set[str] = set()
    for index, vector in enumerate(vectors):
        require(isinstance(vector, dict), f"{name}: comparison row {index} must be an object")
        vector_name = vector.get("name")
        require(isinstance(vector_name, str) and vector_name, f"{name}: comparison row {index} has no name")
        require(vector_name not in seen, f"{name}: duplicate vector {vector_name}")
        require(vector_name in summary_by_name, f"{name}: unknown vector {vector_name}")

        summary_vector = summary_by_name[vector_name]
        expected = summary_vector["expected"]
        require(vector.get("agreement") is True, f"{name}: disagreement for {vector_name}")
        require(vector.get("expected") == expected, f"{name}: expected outcome mismatch for {vector_name}")
        require(vector.get("python_outcome") == expected, f"{name}: Python outcome mismatch for {vector_name}")
        require(
            vector.get("rust_registered_expected") == expected,
            f"{name}: registered Rust outcome mismatch for {vector_name}",
        )
        require(vector.get("bytes") == summary_vector["bytes"], f"{name}: byte count mismatch for {vector_name}")
        require(vector.get("sha256") == summary_vector["sha256"], f"{name}: SHA-256 mismatch for {vector_name}")
        require(
            vector.get("rust_registered_sha256") == summary_vector["sha256"],
            f"{name}: registered Rust SHA-256 mismatch for {vector_name}",
        )
        seen.add(vector_name)

    require(seen == set(summary_by_name), f"{name}: comparison vector set is incomplete")
    expected_reasons = {
        "negative-empty-protected-object": "byte_string_bound",
        "negative-truncated": "truncated",
        "negative-trailing-byte": "trailing_data",
        "negative-unknown-critical-extension": "unknown_critical_extension",
    }
    independent_by_name = {vector["name"]: vector for vector in vectors}
    for vector_name, expected_reason in expected_reasons.items():
        require(
            independent_by_name[vector_name].get("python_error") == expected_reason,
            f"{name}: wrong independent failure reason for {vector_name}",
        )


def main() -> None:
    verify_manifest("MANIFEST.sha256", 18)
    verify_manifest("HISTORICAL-v0-r1.sha256", 6)
    verify_manifest("MANIFEST-v0-r2.sha256", 25)
    summary_by_name = verify_summary()
    verify_independent(summary_by_name)
    verify_reproduction()
    print(
        "conformance profile v0-r2: manifests valid; fresh Rust reproduction and independent "
        "results agree 18/18"
    )


if __name__ == "__main__":
    main()
