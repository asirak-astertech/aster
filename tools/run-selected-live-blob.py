#!/usr/bin/env python3
# Copyright 2026 Defense Unicorns, Inc.
# SPDX-License-Identifier: Apache-2.0
"""Create one exclusive raw root for interrupted selected live Blob acceptance."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
from pathlib import Path
import pwd
import re
import shutil
import signal
import stat
import subprocess
import sys
from typing import Any


RAW_SCHEMA = "aster-selected-live-blob-raw/v2"
CLAIM = "selected-live-blob-one-host-direct-iroh-peerless-publish-seed-interrupt-reopen-different-peer-resume-read-restart-acceptance"
BINARY_NAME = "aster-live-blob-acceptance"
TRANSCRIPT_PREFIX = b"LIVE_BLOB\t"
TRANSCRIPT_RECORDS = 81
MAX_STDOUT_BYTES = 8 * 1024 * 1024
MAX_TRANSCRIPT_BYTES = 64 * 1024
RUN_TIMEOUT_SECONDS = 240
BUILD_TIMEOUT_SECONDS = 900
SIGNER_FINGERPRINT = re.compile(r"(?:[0-9A-F]{40,64}|SHA256:[A-Za-z0-9+/]{43})\Z")
BUILD_ARGV = [
    "cargo",
    "build",
    "--release",
    "--locked",
    "-p",
    "aster-node",
    "--example",
    "live_blob_acceptance",
]
ADMITTED_PATHS = tuple(
    sorted(
        (
            "Cargo.toml",
            "Cargo.lock",
            "mise.toml",
            "crates/aster-core/Cargo.toml",
            "crates/aster-core/src/blob.rs",
            "crates/aster-core/src/source_blob.rs",
            "crates/aster-core/src/store.rs",
            "crates/aster-core/src/crypto/reference.rs",
            "crates/aster-redb-store/Cargo.toml",
            "crates/aster-redb-store/src/blob.rs",
            "crates/aster-redb-store/src/blob/depot.rs",
            "crates/aster-redb-store/src/lib.rs",
            "crates/aster-node/Cargo.toml",
            "crates/aster-node/src/lib.rs",
            "crates/aster-node/src/application.rs",
            "crates/aster-node/src/application/blob.rs",
            "crates/aster-node/src/frame.rs",
            "crates/aster-node/src/runtime.rs",
            "crates/aster-node/examples/live_blob_acceptance.rs",
            "tools/run-selected-live-blob.py",
            "tools/check-selected-live-blob-receipt.py",
            "tools/test-selected-live-blob-receipt.py",
        )
    )
)
TOOL_PATHS = {
    "producer": "crates/aster-node/examples/live_blob_acceptance.rs",
    "runner": "tools/run-selected-live-blob.py",
    "checker": "tools/check-selected-live-blob-receipt.py",
    "test": "tools/test-selected-live-blob-receipt.py",
}


class RunnerFailure(Exception):
    """Sanitized local runner failure."""


def fail() -> None:
    print("selected live Blob runner failed", file=sys.stderr)
    raise SystemExit(1)


def sha256_bytes(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def file_record(path: Path, relative: str, *, max_bytes: int = 64 * 1024 * 1024) -> dict[str, Any]:
    metadata = path.lstat()
    if not stat.S_ISREG(metadata.st_mode) or metadata.st_nlink != 1:
        raise RunnerFailure()
    if metadata.st_size < 0 or metadata.st_size > max_bytes:
        raise RunnerFailure()
    data = path.read_bytes()
    if len(data) != metadata.st_size:
        raise RunnerFailure()
    return {"path": relative, "bytes": len(data), "sha256": sha256_bytes(data)}


def stable_stat_witness(metadata: os.stat_result) -> tuple[int | float | None, ...]:
    """Return metadata that must not change when a regular file is only read or executed."""
    return (
        metadata.st_dev,
        metadata.st_ino,
        metadata.st_mode,
        metadata.st_nlink,
        metadata.st_uid,
        metadata.st_gid,
        metadata.st_size,
        metadata.st_mtime_ns,
        metadata.st_ctime_ns,
        getattr(metadata, "st_birthtime", None),
        getattr(metadata, "st_flags", None),
        getattr(metadata, "st_gen", None),
    )


def executable_record(
    path: Path, relative: str
) -> tuple[dict[str, Any], tuple[int | float | None, ...]]:
    flags = os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0)
    descriptor = os.open(path, flags)
    try:
        before = os.fstat(descriptor)
        if not stat.S_ISREG(before.st_mode) or before.st_nlink != 1:
            raise RunnerFailure()
        if before.st_size <= 0 or before.st_size > 128 * 1024 * 1024:
            raise RunnerFailure()
        if before.st_mode & 0o111 == 0:
            raise RunnerFailure()
        witness = stable_stat_witness(before)
        if stable_stat_witness(path.lstat()) != witness:
            raise RunnerFailure()

        digest = hashlib.sha256()
        byte_count = 0
        while True:
            chunk = os.read(descriptor, 1024 * 1024)
            if not chunk:
                break
            byte_count += len(chunk)
            if byte_count > before.st_size:
                raise RunnerFailure()
            digest.update(chunk)

        if byte_count != before.st_size:
            raise RunnerFailure()
        if stable_stat_witness(os.fstat(descriptor)) != witness:
            raise RunnerFailure()
        if stable_stat_witness(path.lstat()) != witness:
            raise RunnerFailure()
        return (
            {"path": relative, "bytes": byte_count, "sha256": digest.hexdigest()},
            witness,
        )
    finally:
        os.close(descriptor)


def exclusive_file(path: Path, mode: int):
    descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, mode)
    os.fchmod(descriptor, mode)
    return os.fdopen(descriptor, "wb", buffering=0)


def write_exclusive(path: Path, data: bytes, mode: int = 0o600) -> None:
    with exclusive_file(path, mode) as output:
        output.write(data)
        os.fsync(output.fileno())


def reviewer_home_directory() -> str:
    try:
        home = pwd.getpwuid(os.getuid()).pw_dir
    except (KeyError, OSError) as error:
        raise RunnerFailure() from error
    if not os.path.isabs(home) or os.path.realpath(home) != home:
        raise RunnerFailure()
    metadata = os.lstat(home)
    if (
        not stat.S_ISDIR(metadata.st_mode)
        or metadata.st_uid != os.getuid()
        or stat.S_IMODE(metadata.st_mode) & 0o022
    ):
        raise RunnerFailure()
    return home


def safe_git_environment(global_config: str = os.devnull) -> dict[str, str]:
    environment = os.environ.copy()
    for name in list(environment):
        if name in {
            "GIT_DIR",
            "GIT_WORK_TREE",
            "GIT_COMMON_DIR",
            "GIT_OBJECT_DIRECTORY",
            "GIT_ALTERNATE_OBJECT_DIRECTORIES",
            "GIT_INDEX_FILE",
            "GIT_NAMESPACE",
            "GIT_CONFIG_PARAMETERS",
            "GIT_CONFIG_SYSTEM",
            "GIT_CONFIG_GLOBAL",
        } or name.startswith("GIT_CONFIG_KEY_") or name.startswith("GIT_CONFIG_VALUE_"):
            environment.pop(name, None)
    environment.pop("GIT_CONFIG_COUNT", None)
    environment.pop("GNUPGHOME", None)
    environment.pop("GPG_TTY", None)
    environment.update(
        {
            "GIT_NO_REPLACE_OBJECTS": "1",
            "GIT_CONFIG_NOSYSTEM": "1",
            "GIT_CONFIG_GLOBAL": global_config,
            "GIT_OPTIONAL_LOCKS": "0",
            "HOME": reviewer_home_directory(),
            "LC_ALL": "C",
            "LANG": "C",
        }
    )
    return environment


def trusted_executable(path: str) -> str:
    if not os.path.isabs(path) or os.path.realpath(path) != path:
        raise RunnerFailure()
    metadata = os.lstat(path)
    if (
        not stat.S_ISREG(metadata.st_mode)
        or metadata.st_uid not in {0, os.getuid()}
        or metadata.st_nlink < 1
        or (metadata.st_uid != 0 and metadata.st_nlink != 1)
        or metadata.st_size <= 0
        or stat.S_IMODE(metadata.st_mode) & 0o022
        or stat.S_IMODE(metadata.st_mode) & 0o111 == 0
    ):
        raise RunnerFailure()
    return path


def system_executable(name: str) -> str:
    search_path = os.confstr("CS_PATH") or "/bin:/usr/bin"
    resolved = shutil.which(name, path=search_path)
    if resolved is None:
        raise RunnerFailure()
    return trusted_executable(os.path.realpath(resolved))


def reviewer_signature_options() -> tuple[str, list[str]]:
    git_executable = system_executable("git")
    reviewer_home = reviewer_home_directory()
    reviewer_global = os.path.abspath(os.path.join(reviewer_home, ".gitconfig"))
    if os.path.realpath(reviewer_global) != reviewer_global:
        raise RunnerFailure()
    metadata = os.lstat(reviewer_global)
    if (
        not stat.S_ISREG(metadata.st_mode)
        or metadata.st_nlink != 1
        or metadata.st_uid != os.getuid()
        or metadata.st_mode & 0o022 != 0
        or metadata.st_size <= 0
        or metadata.st_size > 1024 * 1024
    ):
        raise RunnerFailure()
    environment = safe_git_environment(reviewer_global)

    def global_value(arguments: list[str]) -> str:
        completed = subprocess.run(
            [git_executable, "config", "--global", *arguments],
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.DEVNULL,
            env=environment,
            check=False,
            timeout=10,
        )
        if completed.returncode != 0 or completed.stderr or len(completed.stdout) > 4096:
            raise RunnerFailure()
        try:
            value = completed.stdout.decode("utf-8", errors="strict").strip()
        except UnicodeDecodeError as error:
            raise RunnerFailure() from error
        if not value or "\n" in value or "\x00" in value:
            raise RunnerFailure()
        return value

    signature_format = global_value(["--get", "gpg.format"])
    if signature_format == "ssh":
        allowed = global_value(["--path", "--get", "gpg.ssh.allowedSignersFile"])
        if allowed.startswith("~/"):
            allowed_signers = os.path.join(reviewer_home, allowed[2:])
        elif os.path.isabs(allowed):
            allowed_signers = allowed
        else:
            raise RunnerFailure()
        allowed_signers = os.path.abspath(allowed_signers)
        if os.path.realpath(allowed_signers) != allowed_signers:
            raise RunnerFailure()
        allowed_metadata = os.lstat(allowed_signers)
        if (
            not stat.S_ISREG(allowed_metadata.st_mode)
            or allowed_metadata.st_nlink != 1
            or allowed_metadata.st_uid != os.getuid()
            or allowed_metadata.st_mode & 0o022 != 0
            or allowed_metadata.st_size <= 0
            or allowed_metadata.st_size > 1024 * 1024
        ):
            raise RunnerFailure()
        ssh_keygen = system_executable("ssh-keygen")
        return git_executable, [
            "-c",
            "gpg.format=ssh",
            "-c",
            f"gpg.ssh.allowedSignersFile={allowed_signers}",
            "-c",
            f"gpg.ssh.program={ssh_keygen}",
            "-c",
            "gpg.minTrustLevel=fully",
        ]
    if signature_format == "openpgp":
        gpg = trusted_executable(global_value(["--path", "--get", "gpg.program"]))
        return git_executable, [
            "-c",
            "gpg.format=openpgp",
            "-c",
            f"gpg.program={gpg}",
            "-c",
            f"gpg.openpgp.program={gpg}",
            "-c",
            "gpg.minTrustLevel=fully",
        ]
    raise RunnerFailure()


def git(
    source: Path,
    arguments: list[str],
    *,
    git_executable: str,
    trusted_options: list[str],
    capture: bool = True,
) -> bytes:
    completed = subprocess.run(
        [
            git_executable,
            "--no-replace-objects",
            *trusted_options,
            "-c",
            "core.fsmonitor=false",
            "-c",
            "core.hooksPath=/dev/null",
            "-C",
            os.fspath(source),
            *arguments,
        ],
        stdin=subprocess.DEVNULL,
        stdout=subprocess.PIPE if capture else subprocess.DEVNULL,
        stderr=subprocess.PIPE,
        env=safe_git_environment(),
        check=False,
        timeout=60,
    )
    stdout = completed.stdout or b""
    stderr = completed.stderr or b""
    if (
        completed.returncode != 0
        or len(stdout) > 64 * 1024 * 1024
        or len(stderr) > 1024 * 1024
    ):
        raise RunnerFailure()
    return stdout


def source_snapshot(
    source: Path, git_executable: str, trusted_options: list[str]
) -> dict[str, Any]:
    def source_git(arguments: list[str], *, capture: bool = True) -> bytes:
        return git(
            source,
            arguments,
            git_executable=git_executable,
            trusted_options=trusted_options,
            capture=capture,
        )

    status = source_git(["status", "--porcelain=v1", "--untracked-files=all"])
    if status:
        raise RunnerFailure()
    commit = source_git(["rev-parse", "--verify", "HEAD^{commit}"]).decode("ascii").strip()
    tree = source_git(["show", "-s", "--format=%T", commit]).decode("ascii").strip()
    if len(commit) != 40 or len(tree) != 40:
        raise RunnerFailure()
    int(commit, 16)
    int(tree, 16)
    top = Path(os.fsdecode(source_git(["rev-parse", "--show-toplevel"]).rstrip(b"\n")))
    if not os.path.samefile(source, top):
        raise RunnerFailure()
    source_git(["verify-commit", commit], capture=False)
    signature_output = source_git(["show", "-s", "--format=%G?%x00%GF", commit])
    if not signature_output.endswith(b"\n") or signature_output.count(b"\x00") != 1:
        raise RunnerFailure()
    status_byte, fingerprint_bytes = signature_output[:-1].split(b"\x00", 1)
    if status_byte != b"G" or not 1 <= len(fingerprint_bytes) <= 512:
        raise RunnerFailure()
    fingerprint = fingerprint_bytes.decode("ascii")
    if SIGNER_FINGERPRINT.fullmatch(fingerprint) is None:
        raise RunnerFailure()
    admitted = []
    for relative in ADMITTED_PATHS:
        path = source / relative
        committed = source_git(["show", f"{commit}:{relative}"])
        metadata = path.lstat()
        if (
            not committed
            or len(committed) > 16 * 1024 * 1024
            or not stat.S_ISREG(metadata.st_mode)
            or metadata.st_nlink != 1
            or metadata.st_size != len(committed)
            or path.read_bytes() != committed
        ):
            raise RunnerFailure()
        admitted.append(
            {"path": relative, "bytes": len(committed), "sha256": sha256_bytes(committed)}
        )
    return {
        "commit": commit,
        "tree": tree,
        "signature": {"status": "good", "fingerprint": fingerprint},
        "admitted": admitted,
    }


def build_release(source: Path) -> Path:
    environment = os.environ.copy()
    for name in (
        "CARGO_TARGET_DIR",
        "RUSTFLAGS",
        "CARGO_ENCODED_RUSTFLAGS",
        "RUSTC_WRAPPER",
        "RUSTC_WORKSPACE_WRAPPER",
        "RUSTDOCFLAGS",
    ):
        environment.pop(name, None)
    environment.update(
        {
            "CARGO_TARGET_DIR": os.fspath(source / "target"),
            "CARGO_INCREMENTAL": "0",
            "LC_ALL": "C",
            "LANG": "C",
        }
    )
    completed = subprocess.run(
        BUILD_ARGV,
        cwd=source,
        stdin=subprocess.DEVNULL,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
        env=environment,
        check=False,
        timeout=BUILD_TIMEOUT_SECONDS,
    )
    if completed.returncode != 0:
        raise RunnerFailure()
    binary = source / "target" / "release" / "examples" / "live_blob_acceptance"
    require_regular_executable(binary)
    return binary


def require_regular_executable(path: Path) -> None:
    metadata = path.lstat()
    if not stat.S_ISREG(metadata.st_mode) or metadata.st_nlink != 1:
        raise RunnerFailure()
    if metadata.st_size <= 0 or metadata.st_size > 128 * 1024 * 1024:
        raise RunnerFailure()
    if metadata.st_mode & 0o111 == 0:
        raise RunnerFailure()


def copy_binary(source: Path, destination: Path) -> None:
    require_regular_executable(source)
    with source.open("rb", buffering=0) as input_file, exclusive_file(destination, 0o700) as output:
        shutil.copyfileobj(input_file, output, length=1024 * 1024)
        os.fsync(output.fileno())
    os.chmod(destination, 0o700, follow_symlinks=False)


def run_binary(binary: Path, raw_root: Path, source: Path, stdout_path: Path, stderr_path: Path) -> int:
    environment = os.environ.copy()
    environment.update({"RUST_BACKTRACE": "0", "LC_ALL": "C", "LANG": "C", "TZ": "UTC"})
    with exclusive_file(stdout_path, 0o600) as stdout_file, exclusive_file(
        stderr_path, 0o600
    ) as stderr_file:
        process = subprocess.Popen(
            [os.fspath(binary), os.fspath(raw_root)],
            cwd=source,
            stdin=subprocess.DEVNULL,
            stdout=stdout_file,
            stderr=stderr_file,
            env=environment,
            close_fds=True,
            start_new_session=True,
        )
        try:
            return process.wait(timeout=RUN_TIMEOUT_SECONDS)
        except subprocess.TimeoutExpired:
            os.killpg(process.pid, signal.SIGTERM)
            try:
                process.wait(timeout=5)
            except subprocess.TimeoutExpired:
                os.killpg(process.pid, signal.SIGKILL)
                process.wait()
            raise RunnerFailure() from None


def extract_transcript(stdout_path: Path) -> bytes:
    metadata = stdout_path.lstat()
    if not stat.S_ISREG(metadata.st_mode) or metadata.st_nlink != 1:
        raise RunnerFailure()
    if metadata.st_size <= 0 or metadata.st_size > MAX_STDOUT_BYTES:
        raise RunnerFailure()
    stdout = stdout_path.read_bytes()
    if len(stdout) != metadata.st_size:
        raise RunnerFailure()
    records = []
    for line in stdout.splitlines(keepends=True):
        if line.startswith(TRANSCRIPT_PREFIX):
            if not line.endswith(b"\n") or line.endswith(b"\r\n"):
                raise RunnerFailure()
            records.append(line)
    if len(records) != TRANSCRIPT_RECORDS:
        raise RunnerFailure()
    transcript = b"".join(records)
    if len(transcript) == 0 or len(transcript) > MAX_TRANSCRIPT_BYTES:
        raise RunnerFailure()
    if any(byte > 0x7F or (byte < 0x20 and byte not in (0x09, 0x0A)) for byte in transcript):
        raise RunnerFailure()
    return transcript


def canonical_json(value: Any) -> bytes:
    return (
        json.dumps(value, ensure_ascii=True, allow_nan=False, sort_keys=True, separators=(",", ":"))
        + "\n"
    ).encode("ascii")


def parse_arguments() -> argparse.Namespace:
    parser = argparse.ArgumentParser(add_help=True)
    parser.add_argument("--source", required=True)
    parser.add_argument("--raw-root", required=True)
    return parser.parse_args()


def main() -> None:
    arguments = parse_arguments()
    source_input = Path(arguments.source)
    raw_input = Path(arguments.raw_root)
    if not source_input.is_absolute() or not raw_input.is_absolute():
        raise RunnerFailure()
    source = source_input.resolve(strict=True)
    raw_parent = raw_input.parent.resolve(strict=True)
    raw_root = raw_parent / raw_input.name
    if raw_root != raw_input or raw_root.exists() or raw_root.is_relative_to(source):
        raise RunnerFailure()
    if not source.is_dir() or not raw_parent.is_dir():
        raise RunnerFailure()

    git_executable, trusted_options = reviewer_signature_options()
    before = source_snapshot(source, git_executable, trusted_options)
    binary = build_release(source)
    after_build = source_snapshot(source, git_executable, trusted_options)
    if after_build != before:
        raise RunnerFailure()
    os.mkdir(raw_root, 0o700)
    os.chmod(raw_root, 0o700, follow_symlinks=False)
    binary_root = raw_root / "binary"
    os.mkdir(binary_root, 0o700)
    os.chmod(binary_root, 0o700, follow_symlinks=False)
    copied_binary = binary_root / BINARY_NAME
    copy_binary(binary, copied_binary)
    binary_before, binary_witness = executable_record(
        copied_binary, f"binary/{BINARY_NAME}"
    )

    stdout_path = raw_root / "stdout.log"
    stderr_path = raw_root / "stderr.log"
    exit_code = run_binary(copied_binary, raw_root, source, stdout_path, stderr_path)
    if exit_code != 0 or stderr_path.stat().st_size != 0:
        raise RunnerFailure()
    transcript = extract_transcript(stdout_path)
    transcript_path = raw_root / "transcript.tsv"
    write_exclusive(transcript_path, transcript)

    after = source_snapshot(source, git_executable, trusted_options)
    if after != before:
        raise RunnerFailure()

    binary_after, binary_after_witness = executable_record(
        copied_binary, f"binary/{BINARY_NAME}"
    )
    if binary_after != binary_before or binary_after_witness != binary_witness:
        raise RunnerFailure()

    artifacts = {
        "binary": binary_after,
        "stdout": file_record(stdout_path, "stdout.log", max_bytes=MAX_STDOUT_BYTES),
        "stderr": file_record(stderr_path, "stderr.log", max_bytes=MAX_STDOUT_BYTES),
        "transcript": file_record(
            transcript_path, "transcript.tsv", max_bytes=MAX_TRANSCRIPT_BYTES
        ),
    }
    tools = {
        name: file_record(source / relative, relative, max_bytes=16 * 1024 * 1024)
        for name, relative in TOOL_PATHS.items()
    }
    raw = {
        "schema": RAW_SCHEMA,
        "claim": CLAIM,
        "run_id": sha256_bytes(transcript)[:16],
        "source": before,
        "commands": {
            "build_argv": BUILD_ARGV,
            "run_argv": [os.fspath(copied_binary), os.fspath(raw_root)],
        },
        "execution": {
            "exit_code": 0,
            "worktree_clean_at_run": True,
            "source_binary_execution_link": "operator-attested-not-cryptographically-proven",
        },
        "artifacts": artifacts,
        "tools": tools,
    }
    write_exclusive(raw_root / "run.json", canonical_json(raw))
    directory_descriptor = os.open(raw_root, os.O_RDONLY | os.O_DIRECTORY)
    try:
        os.fsync(directory_descriptor)
    finally:
        os.close(directory_descriptor)
    print(os.fspath(raw_root))


if __name__ == "__main__":
    try:
        main()
    except (OSError, ValueError, RunnerFailure, subprocess.SubprocessError):
        fail()
