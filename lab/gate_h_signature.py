#!/usr/bin/env python3
"""Hermetic SSH commit-signature trust contract for Proposal 0004 Gate H."""

from __future__ import annotations

import base64
import binascii
import copy
from dataclasses import dataclass
import hashlib
import os
from pathlib import Path
import re
import stat
from typing import Any, Callable, Sequence


SCHEMA = "aster-gate-h-signature-trust/v1"
ANCHOR_SCHEMA = "aster-gate-h-signature-anchor/v1"
MAX_ALLOWED_SIGNERS_BYTES = 1024 * 1024
MAX_COMPLETE_STREAM_BYTES = 4 * 1024 * 1024
GIT_ENVIRONMENT = {
    "GIT_CONFIG_GLOBAL": "/dev/null",
    "GIT_CONFIG_NOSYSTEM": "1",
    "GIT_NO_REPLACE_OBJECTS": "1",
    "GIT_OPTIONAL_LOCKS": "0",
    "GIT_TERMINAL_PROMPT": "0",
}
FORBIDDEN_LOCAL_KEY = re.compile(
    r"(?:^include(?:if)?\.|^gpg\.|^extensions\.worktreeconfig$|"
    r"^core\.(?:usereplacerefs|worktree)$|"
    r"signingkey|allowedsigners|revocation|mintrust)",
    re.IGNORECASE,
)
SAFE_PRINCIPAL = re.compile(r"^[^\s\x00-\x1f\x7f]{1,256}$")
HEX_40 = re.compile(r"^[0-9a-f]{40}$")
HEX_64 = re.compile(r"^[0-9a-f]{64}$")
SAFE_FINGERPRINT = re.compile(r"^[^\s\x00-\x1f\x7f]{1,512}$")
TRUST_KEYS = frozenset(
    {
        "schema",
        "principal",
        "tools",
        "allowed_signers",
        "git_environment",
        "git_config",
        "ssh_version",
        "allowed_signer_fingerprints",
        "fingerprint_command",
        "replacement_refs",
        "local_config",
        "passed",
    }
)
TOOL_BINDING_KEYS = frozenset(
    {"name", "invocation", "path", "size_bytes", "sha256"}
)
ALLOWED_SIGNERS_KEYS = frozenset(
    {
        "invocation",
        "path",
        "size_bytes",
        "sha256",
        "base64",
        "created_frozen_path",
        "frozen_path",
        "frozen_size_bytes",
        "frozen_sha256",
    }
)
ANCHOR_KEYS = frozenset(
    {
        "schema",
        "principal",
        "tools",
        "allowed_signers",
        "allowed_signer_fingerprints",
        "fingerprint_command",
        "git_environment",
        "passed",
    }
)
ANCHOR_ALLOWED_SIGNERS_KEYS = frozenset(
    {"invocation", "path", "size_bytes", "sha256", "base64"}
)
VERIFICATION_KEYS = frozenset(
    {
        "commit",
        "status",
        "principal",
        "fingerprint",
        "local_config_before",
        "replacement_refs_before",
        "verify_commit",
        "status_query",
        "local_config_after",
        "replacement_refs_after",
        "passed",
    }
)
GIT_CONFIG_KEYS = (
    "gpg.format",
    "gpg.ssh.program",
    "gpg.ssh.allowedSignersFile",
    "gpg.ssh.revocationFile",
    "gpg.minTrustLevel",
)
__all__ = (
    "ANCHOR_SCHEMA",
    "GIT_CONFIG_KEYS",
    "GIT_ENVIRONMENT",
    "MAX_ALLOWED_SIGNERS_BYTES",
    "SAFE_PRINCIPAL",
    "SCHEMA",
    "SignatureRequest",
    "SignatureTrustError",
    "bind_executable",
    "git_argv",
    "git_config",
    "git_environment",
    "prepare_signature_trust",
    "rebind_signature_trust",
    "validate_signature_request_matches_trust",
    "validate_signature_anchor_receipt",
    "validate_signature_trust_receipt",
    "validate_signature_verification_receipt",
    "verify_commit",
    "verify_signature_inputs_unchanged",
    "verify_signature_source_unchanged",
)


class SignatureTrustError(RuntimeError):
    """A fail-closed signature trust or verification error."""


@dataclass(frozen=True)
class SignatureRequest:
    git: Path
    ssh_keygen: Path
    ssh: Path
    allowed_signers: Path
    principal: str


CommandRunner = Callable[..., tuple[dict[str, Any], bytes | None, bytes | None]]


def sha256_bytes(value: bytes) -> str:
    return hashlib.sha256(value).hexdigest()


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def complete_stream(value: bytes) -> dict[str, Any]:
    complete = len(value) <= MAX_COMPLETE_STREAM_BYTES
    return {
        "bytes": len(value),
        "complete": complete,
        "base64": base64.b64encode(value).decode("ascii") if complete else None,
    }


def _exact_keys(value: Any, expected: frozenset[str], context: str) -> None:
    if not isinstance(value, dict) or set(value) != expected:
        raise SignatureTrustError(f"{context} keys differ from the trust contract")


def _absolute_path(value: Any, context: str) -> Path:
    if not isinstance(value, str) or not value:
        raise SignatureTrustError(f"{context} is not a nonempty path")
    path = Path(value)
    if not path.is_absolute():
        raise SignatureTrustError(f"{context} is not absolute")
    return path


def _validate_bound_executable(
    binding: dict[str, Any], name: str, *, verify_file: bool
) -> None:
    _exact_keys(binding, TOOL_BINDING_KEYS, f"{name} tool binding")
    if binding["name"] != name:
        raise SignatureTrustError(f"{name} tool binding has the wrong name")
    invocation = _absolute_path(binding["invocation"], f"{name} invocation")
    path = _absolute_path(binding["path"], f"{name} resolved path")
    if (
        not isinstance(binding["size_bytes"], int)
        or isinstance(binding["size_bytes"], bool)
        or binding["size_bytes"] < 0
        or not isinstance(binding["sha256"], str)
        or HEX_64.fullmatch(binding["sha256"]) is None
    ):
        raise SignatureTrustError(f"{name} tool identity is malformed")
    if not verify_file:
        return
    try:
        resolved_invocation = invocation.resolve(strict=True)
        resolved_path = path.resolve(strict=True)
        metadata = path.stat()
    except OSError as error:
        raise SignatureTrustError(f"bound {name} executable is unavailable") from error
    if resolved_invocation != path or resolved_path != path:
        raise SignatureTrustError(f"bound {name} invocation no longer resolves exactly")
    if (
        not stat.S_ISREG(metadata.st_mode)
        or not os.access(path, os.X_OK)
        or metadata.st_size != binding["size_bytes"]
        or sha256_file(path) != binding["sha256"]
    ):
        raise SignatureTrustError(f"bound {name} executable changed")


def bind_executable(invocation: Path, name: str) -> dict[str, Any]:
    if not isinstance(invocation, Path) or not invocation.is_absolute():
        raise SignatureTrustError(f"{name} invocation is not absolute")
    try:
        resolved = invocation.resolve(strict=True)
        metadata = resolved.stat()
    except OSError as error:
        raise SignatureTrustError(f"{name} executable is unavailable") from error
    if not stat.S_ISREG(metadata.st_mode) or not os.access(resolved, os.X_OK):
        raise SignatureTrustError(f"{name} is not a regular executable")
    binding = {
        "name": name,
        "invocation": str(invocation),
        "path": str(resolved),
        "size_bytes": metadata.st_size,
        "sha256": sha256_file(resolved),
    }
    _validate_bound_executable(binding, name, verify_file=True)
    return binding


def git_environment(base_environment: dict[str, str]) -> dict[str, str]:
    if not isinstance(base_environment, dict) or any(
        not isinstance(key, str) or not isinstance(value, str)
        for key, value in base_environment.items()
    ):
        raise SignatureTrustError("base environment is not a string map")
    ambient_git = sorted(key for key in base_environment if key.startswith("GIT_"))
    if ambient_git:
        raise SignatureTrustError(
            f"base environment contains Git controls: {', '.join(ambient_git)}"
        )
    return {**base_environment, **GIT_ENVIRONMENT}


def _git_config_for_frozen_path(
    trust: dict[str, Any], frozen_path: str
) -> list[tuple[str, str]]:
    return [
        ("gpg.format", "ssh"),
        ("gpg.ssh.program", trust["tools"]["ssh-keygen"]["path"]),
        ("gpg.ssh.allowedSignersFile", frozen_path),
        ("gpg.ssh.revocationFile", "/dev/null"),
        ("gpg.minTrustLevel", "fully"),
    ]


def git_config(trust: dict[str, Any]) -> list[tuple[str, str]]:
    """Return the sole ordered Git signature-verification configuration."""

    return _git_config_for_frozen_path(
        trust, trust["allowed_signers"]["frozen_path"]
    )


def _git_argv_with_config(
    trust: dict[str, Any], arguments: Sequence[str], config: Sequence[tuple[str, str]]
) -> list[str]:
    if not arguments or any(not isinstance(value, str) or not value for value in arguments):
        raise SignatureTrustError("Git arguments must be nonempty strings")
    argv = [trust["tools"]["git"]["path"], "--no-replace-objects"]
    for key, value in config:
        argv.extend(["-c", f"{key}={value}"])
    return [*argv, *arguments]


def git_argv(trust: dict[str, Any], arguments: Sequence[str]) -> list[str]:
    """Construct one exact hermetic Git argv from a validated trust contract."""

    return _git_argv_with_config(trust, arguments, git_config(trust))


def _run(
    run_command: CommandRunner,
    argv: Sequence[str],
    *,
    environment: dict[str, str],
    workspace: Path,
    context: str,
    timeout_seconds: int = 30,
) -> tuple[dict[str, Any], bytes, bytes]:
    receipt, stdout, stderr = run_command(
        argv,
        environment=environment,
        stdin_value=None,
        timeout_seconds=timeout_seconds,
        context=context,
    )
    if (
        receipt.get("returncode") != 0
        or receipt.get("timed_out") is not False
        or receipt.get("execution_error") is not None
        or stdout is None
        or stderr is None
        or receipt.get("stdout", {}).get("complete") is not True
        or receipt.get("stderr", {}).get("complete") is not True
    ):
        raise SignatureTrustError(f"signature trust command failed: {context}")
    retained_stdout, retained_stderr = _validate_successful_command(
        receipt,
        argv=argv,
        environment=environment,
        workspace=workspace,
        context=context,
    )
    if retained_stdout != stdout or retained_stderr != stderr:
        raise SignatureTrustError(f"signature command streams differ: {context}")
    return receipt, stdout, stderr


def _allowed_signers_binding(
    source: Path, frozen_directory: Path
) -> tuple[dict[str, Any], bytes]:
    source_binding, value = _read_allowed_signers_source(source)
    if (
        not frozen_directory.is_absolute()
        or frozen_directory.is_symlink()
        or not frozen_directory.is_dir()
    ):
        raise SignatureTrustError("signature freeze directory is unavailable")
    frozen_path = frozen_directory / "gate-h-allowed-signers"
    _write_exclusive_frozen_signers(frozen_path, value)
    return (
        {
            **source_binding,
            "created_frozen_path": str(frozen_path),
            "frozen_path": str(frozen_path),
            "frozen_size_bytes": len(value),
            "frozen_sha256": source_binding["sha256"],
        },
        value,
    )


def _read_allowed_signers_source(source: Path) -> tuple[dict[str, Any], bytes]:
    if (
        not isinstance(source, Path)
        or not source.is_absolute()
        or source.is_symlink()
    ):
        raise SignatureTrustError("allowed-signers input must be an absolute regular file")
    try:
        resolved = source.resolve(strict=True)
        metadata = resolved.stat()
        value = resolved.read_bytes()
    except OSError as error:
        raise SignatureTrustError("allowed-signers input is unavailable") from error
    if (
        not stat.S_ISREG(metadata.st_mode)
        or not value
        or len(value) > MAX_ALLOWED_SIGNERS_BYTES
        or b"\0" in value
    ):
        raise SignatureTrustError("allowed-signers input is empty, oversized, or invalid")
    try:
        value.decode("utf-8")
    except UnicodeError as error:
        raise SignatureTrustError("allowed-signers input is not UTF-8") from error
    digest = sha256_bytes(value)
    return (
        {
            "invocation": str(source),
            "path": str(resolved),
            "size_bytes": len(value),
            "sha256": digest,
            "base64": base64.b64encode(value).decode("ascii"),
        },
        value,
    )


def _write_exclusive_frozen_signers(path: Path, value: bytes) -> None:
    if not path.is_absolute() or path.exists() or path.is_symlink():
        raise SignatureTrustError("frozen allowed-signers path already exists or is unsafe")
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL
    flags |= getattr(os, "O_NOFOLLOW", 0)
    descriptor: int | None = None
    try:
        descriptor = os.open(path, flags, 0o400)
        with os.fdopen(descriptor, "wb", closefd=True) as stream:
            descriptor = None
            if stream.write(value) != len(value):
                raise OSError("short allowed-signers write")
            stream.flush()
            os.fsync(stream.fileno())
        directory_descriptor = os.open(path.parent, os.O_RDONLY)
        try:
            os.fsync(directory_descriptor)
        finally:
            os.close(directory_descriptor)
    except OSError as error:
        if descriptor is not None:
            os.close(descriptor)
        raise SignatureTrustError("unable to freeze allowed-signers bytes") from error


def parse_local_config(value: bytes) -> list[dict[str, str]]:
    try:
        text = value.decode("utf-8")
    except UnicodeError as error:
        raise SignatureTrustError("local Git config output is not UTF-8") from error
    entries = []
    for record in text.split("\0"):
        if not record:
            continue
        key, separator, setting = record.partition("\n")
        if not separator or not key:
            raise SignatureTrustError("local Git config output is malformed")
        entries.append({"key": key, "value": setting})
    forbidden = sorted(
        entry["key"] for entry in entries if FORBIDDEN_LOCAL_KEY.search(entry["key"])
    )
    if forbidden:
        raise SignatureTrustError(
            f"local Git config contains verification controls: {', '.join(forbidden)}"
        )
    return entries


def _parse_fingerprints(value: bytes) -> list[str]:
    try:
        text = value.decode("utf-8")
    except UnicodeError as error:
        raise SignatureTrustError("allowed-signer fingerprints are not UTF-8") from error
    fingerprints = sorted(
        {
            fields[1]
            for line in text.splitlines()
            if len(fields := line.split()) >= 2
        }
    )
    if not fingerprints or any(
        SAFE_FINGERPRINT.fullmatch(fingerprint) is None
        for fingerprint in fingerprints
    ):
        raise SignatureTrustError("allowed-signers has no exact key fingerprints")
    return fingerprints


def _decode_command_stream(command: dict[str, Any], name: str) -> bytes:
    stream = command.get(name)
    if (
        not isinstance(stream, dict)
        or not {"bytes", "complete", "base64"}.issubset(stream)
        or stream.get("complete") is not True
        or not isinstance(stream.get("bytes"), int)
        or isinstance(stream.get("bytes"), bool)
        or stream["bytes"] < 0
        or not isinstance(stream.get("base64"), str)
    ):
        raise SignatureTrustError(f"signature command {name} stream is incomplete")
    try:
        value = base64.b64decode(stream["base64"], validate=True)
    except (binascii.Error, ValueError) as error:
        raise SignatureTrustError(f"signature command {name} stream is invalid") from error
    digest = command.get(f"{name}_sha256")
    if (
        len(value) != stream["bytes"]
        or not isinstance(digest, str)
        or HEX_64.fullmatch(digest) is None
        or sha256_bytes(value) != digest
    ):
        raise SignatureTrustError(f"signature command {name} stream digest differs")
    return value


def _validate_successful_command(
    command: Any,
    *,
    argv: Sequence[str],
    environment: dict[str, str],
    workspace: Path,
    context: str,
) -> tuple[bytes, bytes]:
    if not isinstance(command, dict):
        raise SignatureTrustError(f"{context} command receipt is absent")
    if (
        command.get("context") != context
        or command.get("argv") != list(argv)
        or command.get("cwd") != str(workspace)
        or command.get("environment") != environment
        or command.get("stdin_mode") != "devnull"
        or command.get("stdin_sha256") != sha256_bytes(b"")
        or not isinstance(command.get("returncode"), int)
        or isinstance(command.get("returncode"), bool)
        or command["returncode"] != 0
        or not isinstance(command.get("terminal_returncode"), int)
        or isinstance(command.get("terminal_returncode"), bool)
        or command["terminal_returncode"] != 0
        or command.get("timed_out") is not False
        or command.get("execution_error") is not None
        or command.get("process_group_reaped") is not True
        or command.get("interrupted") is not False
        or not isinstance(command.get("started_utc"), str)
        or not command["started_utc"]
        or not isinstance(command.get("completed_utc"), str)
        or not command["completed_utc"]
        or not isinstance(command.get("duration_ms"), int)
        or isinstance(command.get("duration_ms"), bool)
        or command["duration_ms"] < 0
    ):
        raise SignatureTrustError(f"{context} command metadata differs")
    stdin = command.get("stdin")
    if (
        not isinstance(stdin, dict)
        or stdin.get("bytes") != 0
        or stdin.get("complete") is not True
        or stdin.get("base64") != ""
    ):
        raise SignatureTrustError(f"{context} command stdin metadata differs")
    return _decode_command_stream(command, "stdout"), _decode_command_stream(
        command, "stderr"
    )


def _decoded_allowed_signers(allowed: Any) -> bytes:
    _exact_keys(allowed, ALLOWED_SIGNERS_KEYS, "allowed-signers binding")
    for name in ("invocation", "path", "created_frozen_path", "frozen_path"):
        _absolute_path(allowed[name], f"allowed-signers {name}")
    if (
        not isinstance(allowed["base64"], str)
        or not isinstance(allowed["size_bytes"], int)
        or isinstance(allowed["size_bytes"], bool)
        or not isinstance(allowed["frozen_size_bytes"], int)
        or isinstance(allowed["frozen_size_bytes"], bool)
        or not isinstance(allowed["sha256"], str)
        or HEX_64.fullmatch(allowed["sha256"]) is None
        or not isinstance(allowed["frozen_sha256"], str)
        or HEX_64.fullmatch(allowed["frozen_sha256"]) is None
    ):
        raise SignatureTrustError("allowed-signers identity is malformed")
    try:
        value = base64.b64decode(allowed["base64"], validate=True)
    except (binascii.Error, ValueError) as error:
        raise SignatureTrustError("allowed-signers base64 is invalid") from error
    if (
        not value
        or len(value) > MAX_ALLOWED_SIGNERS_BYTES
        or b"\0" in value
        or len(value) != allowed["size_bytes"]
        or len(value) != allowed["frozen_size_bytes"]
        or sha256_bytes(value) != allowed["sha256"]
        or sha256_bytes(value) != allowed["frozen_sha256"]
        or base64.b64encode(value).decode("ascii") != allowed["base64"]
    ):
        raise SignatureTrustError("allowed-signers embedded bytes differ")
    try:
        value.decode("utf-8")
    except UnicodeError as error:
        raise SignatureTrustError("allowed-signers embedded bytes are not UTF-8") from error
    return value


def _decoded_anchor_allowed_signers(allowed: Any) -> bytes:
    _exact_keys(
        allowed, ANCHOR_ALLOWED_SIGNERS_KEYS, "external allowed-signers binding"
    )
    for name in ("invocation", "path"):
        _absolute_path(allowed[name], f"external allowed-signers {name}")
    if (
        not isinstance(allowed["base64"], str)
        or not isinstance(allowed["size_bytes"], int)
        or isinstance(allowed["size_bytes"], bool)
        or not isinstance(allowed["sha256"], str)
        or HEX_64.fullmatch(allowed["sha256"]) is None
    ):
        raise SignatureTrustError("external allowed-signers identity is malformed")
    try:
        value = base64.b64decode(allowed["base64"], validate=True)
    except (binascii.Error, ValueError) as error:
        raise SignatureTrustError("external allowed-signers base64 is invalid") from error
    if (
        not value
        or len(value) > MAX_ALLOWED_SIGNERS_BYTES
        or b"\0" in value
        or len(value) != allowed["size_bytes"]
        or sha256_bytes(value) != allowed["sha256"]
        or base64.b64encode(value).decode("ascii") != allowed["base64"]
    ):
        raise SignatureTrustError("external allowed-signers embedded bytes differ")
    try:
        value.decode("utf-8")
    except UnicodeError as error:
        raise SignatureTrustError(
            "external allowed-signers embedded bytes are not UTF-8"
        ) from error
    return value


def _historical_git_config(trust: dict[str, Any]) -> list[tuple[str, str]]:
    return _git_config_for_frozen_path(
        trust, trust["allowed_signers"]["created_frozen_path"]
    )


def validate_signature_trust_receipt(
    trust: Any,
    *,
    workspace: Path,
    expected_principal: str | None = None,
    verify_tool_files: bool = True,
    verify_frozen_file: bool = False,
) -> bytes:
    """Validate a complete trust receipt and return its embedded signer bytes.

    The original source and target paths are evidence only.  Callers may validate
    and rehydrate a copied receipt without trusting either old path.
    """

    _exact_keys(trust, TRUST_KEYS, "signature trust receipt")
    if trust["schema"] != SCHEMA or trust["passed"] is not True:
        raise SignatureTrustError("signature trust schema or outcome differs")
    if not isinstance(workspace, Path) or not workspace.is_absolute():
        raise SignatureTrustError("signature trust workspace is not absolute")
    if not isinstance(trust["principal"], str) or not SAFE_PRINCIPAL.fullmatch(
        trust["principal"]
    ):
        raise SignatureTrustError("signature trust principal is empty or unsafe")
    if expected_principal is not None and trust["principal"] != expected_principal:
        raise SignatureTrustError("signature trust principal differs")
    if not isinstance(trust["tools"], dict) or set(trust["tools"]) != {
        "git",
        "ssh-keygen",
        "ssh",
    }:
        raise SignatureTrustError("signature trust tools differ")
    for name in ("git", "ssh-keygen", "ssh"):
        _validate_bound_executable(
            trust["tools"][name], name, verify_file=verify_tool_files
        )
    allowed_value = _decoded_allowed_signers(trust["allowed_signers"])
    if verify_frozen_file:
        frozen_path = Path(trust["allowed_signers"]["frozen_path"])
        try:
            frozen_metadata = frozen_path.stat()
            frozen_value = frozen_path.read_bytes()
        except OSError as error:
            raise SignatureTrustError("frozen allowed-signers is unavailable") from error
        if (
            frozen_path.is_symlink()
            or not stat.S_ISREG(frozen_metadata.st_mode)
            or stat.S_IMODE(frozen_metadata.st_mode) != 0o400
            or frozen_metadata.st_size != len(allowed_value)
            or frozen_value != allowed_value
        ):
            raise SignatureTrustError("frozen allowed-signers bytes changed")
    environment = trust["git_environment"]
    if (
        not isinstance(environment, dict)
        or any(not isinstance(key, str) or not isinstance(value, str) for key, value in environment.items())
        or {key for key in environment if key.startswith("GIT_")} != set(GIT_ENVIRONMENT)
        or any(environment.get(key) != value for key, value in GIT_ENVIRONMENT.items())
    ):
        raise SignatureTrustError("signature Git environment differs")
    base_environment = {
        key: value for key, value in environment.items() if key not in GIT_ENVIRONMENT
    }
    expected_config = [
        {"key": key, "value": value} for key, value in git_config(trust)
    ]
    if trust["git_config"] != expected_config or tuple(
        entry["key"] for entry in expected_config
    ) != GIT_CONFIG_KEYS:
        raise SignatureTrustError("signature Git configuration differs")
    ssh_stdout, ssh_stderr = _validate_successful_command(
        trust["ssh_version"],
        argv=[trust["tools"]["ssh"]["path"], "-V"],
        environment=base_environment,
        workspace=workspace,
        context="signature-trust:ssh-version",
    )
    if not ssh_stdout and not ssh_stderr:
        raise SignatureTrustError("ssh -V returned empty version evidence")
    fingerprint_stdout, _ = _validate_successful_command(
        trust["fingerprint_command"],
        argv=[
            trust["tools"]["ssh-keygen"]["path"],
            "-lf",
            trust["allowed_signers"]["created_frozen_path"],
        ],
        environment=base_environment,
        workspace=workspace,
        context="signature-trust:allowed-signer-fingerprints",
    )
    observed_fingerprints = _parse_fingerprints(fingerprint_stdout)
    fingerprints = trust["allowed_signer_fingerprints"]
    if (
        not isinstance(fingerprints, list)
        or not fingerprints
        or fingerprints != observed_fingerprints
        or fingerprints != sorted(set(fingerprints))
        or any(
            not isinstance(value, str) or SAFE_FINGERPRINT.fullmatch(value) is None
            for value in fingerprints
        )
    ):
        raise SignatureTrustError("allowed-signer fingerprint evidence differs")
    replacement_refs = trust["replacement_refs"]
    if not isinstance(replacement_refs, dict) or set(replacement_refs) != {
        "command",
        "refs",
        "stdout_sha256",
    }:
        raise SignatureTrustError("replacement-ref receipt differs")
    historical_config = _historical_git_config(trust)
    replacement_stdout, _ = _validate_successful_command(
        replacement_refs["command"],
        argv=_git_argv_with_config(
            trust,
            ["for-each-ref", "--format=%(refname)", "refs/replace/"],
            historical_config,
        ),
        environment=environment,
        workspace=workspace,
        context="signature-trust:replacement-refs",
    )
    if (
        replacement_stdout != b""
        or replacement_refs["refs"] != []
        or replacement_refs["stdout_sha256"] != sha256_bytes(b"")
    ):
        raise SignatureTrustError("Git replacement refs are forbidden")
    local_config = trust["local_config"]
    if not isinstance(local_config, dict) or set(local_config) != {
        "command",
        "entries",
        "stdout_sha256",
    }:
        raise SignatureTrustError("local Git config receipt differs")
    local_stdout, _ = _validate_successful_command(
        local_config["command"],
        argv=_git_argv_with_config(
            trust,
            ["config", "--local", "--no-includes", "--null", "--list"],
            historical_config,
        ),
        environment=environment,
        workspace=workspace,
        context="signature-trust:local-config",
    )
    if (
        local_config["stdout_sha256"] != sha256_bytes(local_stdout)
        or local_config["entries"] != parse_local_config(local_stdout)
    ):
        raise SignatureTrustError("local Git config evidence differs")
    return allowed_value


def validate_signature_anchor_receipt(
    anchor: Any,
    trust: dict[str, Any],
    *,
    workspace: Path,
    base_environment: dict[str, str],
) -> bytes:
    """Validate retained external-anchor evidence without executing a command."""

    _exact_keys(anchor, ANCHOR_KEYS, "signature anchor receipt")
    expected_signers = validate_signature_trust_receipt(
        trust,
        workspace=workspace,
        expected_principal=anchor.get("principal") if isinstance(anchor, dict) else None,
        verify_tool_files=False,
        verify_frozen_file=False,
    )
    if (
        anchor["schema"] != ANCHOR_SCHEMA
        or anchor["passed"] is not True
        or anchor["principal"] != trust["principal"]
        or anchor["tools"] != trust["tools"]
    ):
        raise SignatureTrustError("signature anchor identity differs")
    for name in ("git", "ssh-keygen", "ssh"):
        _validate_bound_executable(anchor["tools"][name], name, verify_file=False)
    signer_bytes = _decoded_anchor_allowed_signers(anchor["allowed_signers"])
    if signer_bytes != expected_signers:
        raise SignatureTrustError("signature anchor allowed-signers bytes differ")
    environment = git_environment(base_environment)
    if anchor["git_environment"] != environment:
        raise SignatureTrustError("signature anchor Git environment differs")
    fingerprint_stdout, _ = _validate_successful_command(
        anchor["fingerprint_command"],
        argv=[
            anchor["tools"]["ssh-keygen"]["path"],
            "-lf",
            anchor["allowed_signers"]["path"],
        ],
        environment=base_environment,
        workspace=workspace,
        context="signature-anchor:allowed-signer-fingerprints",
    )
    fingerprints = _parse_fingerprints(fingerprint_stdout)
    if (
        anchor["allowed_signer_fingerprints"] != fingerprints
        or fingerprints != trust["allowed_signer_fingerprints"]
    ):
        raise SignatureTrustError("signature anchor fingerprints differ")
    return signer_bytes


def _validate_local_config_evidence(
    value: Any,
    trust: dict[str, Any],
    *,
    workspace: Path,
    environment: dict[str, str],
    context: str,
) -> None:
    if not isinstance(value, dict) or set(value) != {
        "command",
        "entries",
        "stdout_sha256",
    }:
        raise SignatureTrustError(f"{context} local-config evidence differs")
    stdout, _ = _validate_successful_command(
        value["command"],
        argv=git_argv(
            trust, ["config", "--local", "--no-includes", "--null", "--list"]
        ),
        environment=environment,
        workspace=workspace,
        context=context,
    )
    if (
        value["stdout_sha256"] != sha256_bytes(stdout)
        or value["entries"] != parse_local_config(stdout)
        or value["stdout_sha256"] != trust["local_config"]["stdout_sha256"]
    ):
        raise SignatureTrustError(f"{context} local Git config changed")


def _validate_replacement_refs_evidence(
    value: Any,
    trust: dict[str, Any],
    *,
    workspace: Path,
    environment: dict[str, str],
    context: str,
) -> None:
    if not isinstance(value, dict) or set(value) != {
        "command",
        "refs",
        "stdout_sha256",
    }:
        raise SignatureTrustError(f"{context} replacement-ref evidence differs")
    stdout, _ = _validate_successful_command(
        value["command"],
        argv=git_argv(
            trust, ["for-each-ref", "--format=%(refname)", "refs/replace/"]
        ),
        environment=environment,
        workspace=workspace,
        context=context,
    )
    if (
        stdout != b""
        or value["refs"] != []
        or value["stdout_sha256"] != sha256_bytes(b"")
    ):
        raise SignatureTrustError("Git replacement refs are forbidden")


def _parse_signature_status(value: bytes) -> tuple[str, str, str]:
    fields = value.rstrip(b"\r\n").split(b"\0")
    try:
        decoded = [field.decode("utf-8") for field in fields]
    except UnicodeError as error:
        raise SignatureTrustError("signature status is not UTF-8") from error
    if len(decoded) != 3:
        raise SignatureTrustError("signature status output is malformed")
    return decoded[0], decoded[1], decoded[2]


def validate_signature_verification_receipt(
    receipt: Any,
    commit: str,
    trust: dict[str, Any],
    *,
    workspace: Path,
    base_environment: dict[str, str],
) -> None:
    """Validate retained exact commit-verification evidence without execution."""

    _exact_keys(receipt, VERIFICATION_KEYS, "signature verification receipt")
    if not HEX_40.fullmatch(commit):
        raise SignatureTrustError("commit is not a full lowercase object ID")
    validate_signature_trust_receipt(
        trust,
        workspace=workspace,
        expected_principal=trust.get("principal") if isinstance(trust, dict) else None,
        verify_tool_files=False,
        verify_frozen_file=False,
    )
    environment = git_environment(base_environment)
    _validate_local_config_evidence(
        receipt["local_config_before"],
        trust,
        workspace=workspace,
        environment=environment,
        context="signature-verify:local-config-before",
    )
    _validate_replacement_refs_evidence(
        receipt["replacement_refs_before"],
        trust,
        workspace=workspace,
        environment=environment,
        context="signature-verify:replacement-refs-before",
    )
    _validate_successful_command(
        receipt["verify_commit"],
        argv=git_argv(trust, ["verify-commit", commit]),
        environment=environment,
        workspace=workspace,
        context="signature-verify:verify-commit",
    )
    status_stdout, _ = _validate_successful_command(
        receipt["status_query"],
        argv=git_argv(
            trust,
            [
                "log",
                "-1",
                "--no-show-signature",
                "--format=%G?%x00%GS%x00%GF",
                commit,
            ],
        ),
        environment=environment,
        workspace=workspace,
        context="signature-verify:status",
    )
    status, principal, fingerprint = _parse_signature_status(status_stdout)
    if (
        receipt["commit"] != commit
        or receipt["status"] != status
        or receipt["principal"] != principal
        or receipt["fingerprint"] != fingerprint
        or status != "G"
        or principal != trust["principal"]
        or not fingerprint
        or fingerprint not in trust["allowed_signer_fingerprints"]
        or receipt["passed"] is not True
    ):
        raise SignatureTrustError("commit signature identity or fingerprint differs")
    _validate_local_config_evidence(
        receipt["local_config_after"],
        trust,
        workspace=workspace,
        environment=environment,
        context="signature-verify:local-config-after",
    )
    _validate_replacement_refs_evidence(
        receipt["replacement_refs_after"],
        trust,
        workspace=workspace,
        environment=environment,
        context="signature-verify:replacement-refs-after",
    )


def rebind_signature_trust(
    trust: dict[str, Any],
    *,
    workspace: Path,
    frozen_directory: Path,
    expected_principal: str,
) -> dict[str, Any]:
    """Rehydrate signer bytes after external-anchor validation.

    The caller must first use :func:`validate_signature_request_matches_trust`;
    this function reconstructs evidence but intentionally does not choose the
    external trust root.
    """

    allowed_value = validate_signature_trust_receipt(
        trust,
        workspace=workspace,
        expected_principal=expected_principal,
        verify_tool_files=True,
        verify_frozen_file=False,
    )
    if (
        not frozen_directory.is_absolute()
        or frozen_directory.is_symlink()
        or not frozen_directory.is_dir()
    ):
        raise SignatureTrustError("signature rebind directory is unavailable")
    frozen_path = frozen_directory / "gate-h-allowed-signers"
    _write_exclusive_frozen_signers(frozen_path, allowed_value)
    rebound = copy.deepcopy(trust)
    rebound["allowed_signers"]["frozen_path"] = str(frozen_path)
    rebound["git_config"] = [
        {"key": key, "value": value} for key, value in git_config(rebound)
    ]
    validate_signature_trust_receipt(
        rebound,
        workspace=workspace,
        expected_principal=expected_principal,
        verify_tool_files=True,
        verify_frozen_file=True,
    )
    return rebound


def validate_signature_request_matches_trust(
    request: SignatureRequest,
    trust: dict[str, Any],
    *,
    workspace: Path,
    base_environment: dict[str, str],
    run_command: CommandRunner,
) -> dict[str, Any]:
    """Bind an external trust anchor and require it to match a trust receipt."""

    if not isinstance(request.principal, str) or not SAFE_PRINCIPAL.fullmatch(
        request.principal
    ):
        raise SignatureTrustError("external signer principal is empty or unsafe")
    expected_signers = validate_signature_trust_receipt(
        trust,
        workspace=workspace,
        expected_principal=request.principal,
        verify_tool_files=False,
        verify_frozen_file=False,
    )
    tools = {
        "git": bind_executable(request.git, "git"),
        "ssh-keygen": bind_executable(request.ssh_keygen, "ssh-keygen"),
        "ssh": bind_executable(request.ssh, "ssh"),
    }
    if tools != trust["tools"]:
        raise SignatureTrustError("external signature tool identities differ")
    source_binding, signer_bytes = _read_allowed_signers_source(
        request.allowed_signers
    )
    if signer_bytes != expected_signers:
        raise SignatureTrustError("external allowed-signers bytes differ")
    environment = git_environment(base_environment)
    fingerprint_command, fingerprint_stdout, _ = _run(
        run_command,
        [tools["ssh-keygen"]["path"], "-lf", source_binding["path"]],
        environment=base_environment,
        workspace=workspace,
        context="signature-anchor:allowed-signer-fingerprints",
    )
    fingerprints = _parse_fingerprints(fingerprint_stdout)
    if fingerprints != trust["allowed_signer_fingerprints"]:
        raise SignatureTrustError("external allowed-signer fingerprints differ")
    for name in ("git", "ssh-keygen", "ssh"):
        _validate_bound_executable(tools[name], name, verify_file=True)
    final_source_binding, final_signer_bytes = _read_allowed_signers_source(
        request.allowed_signers
    )
    if final_source_binding != source_binding or final_signer_bytes != signer_bytes:
        raise SignatureTrustError("external allowed-signers changed during validation")
    anchor = {
        "schema": ANCHOR_SCHEMA,
        "principal": request.principal,
        "tools": tools,
        "allowed_signers": source_binding,
        "allowed_signer_fingerprints": fingerprints,
        "fingerprint_command": fingerprint_command,
        "git_environment": environment,
        "passed": True,
    }
    validate_signature_anchor_receipt(
        anchor,
        trust,
        workspace=workspace,
        base_environment=base_environment,
    )
    return anchor


def _local_config_receipt(
    trust: dict[str, Any],
    *,
    workspace: Path,
    environment: dict[str, str],
    run_command: CommandRunner,
    context: str,
) -> dict[str, Any]:
    argv = git_argv(
        trust,
        ["config", "--local", "--no-includes", "--null", "--list"],
    )
    command, stdout, _ = _run(
        run_command,
        argv,
        environment=environment,
        workspace=workspace,
        context=context,
    )
    return {
        "command": command,
        "entries": parse_local_config(stdout),
        "stdout_sha256": sha256_bytes(stdout),
    }


def _replacement_refs_receipt(
    trust: dict[str, Any],
    *,
    workspace: Path,
    environment: dict[str, str],
    run_command: CommandRunner,
    context: str,
) -> dict[str, Any]:
    argv = git_argv(
        trust,
        ["for-each-ref", "--format=%(refname)", "refs/replace/"],
    )
    command, stdout, _ = _run(
        run_command,
        argv,
        environment=environment,
        workspace=workspace,
        context=context,
    )
    try:
        decoded = stdout.decode("utf-8")
    except UnicodeError as error:
        raise SignatureTrustError("replacement-ref output is not UTF-8") from error
    refs = [value for value in decoded.splitlines() if value]
    if refs:
        raise SignatureTrustError("Git replacement refs are forbidden")
    return {"command": command, "refs": refs, "stdout_sha256": sha256_bytes(stdout)}


def prepare_signature_trust(
    request: SignatureRequest,
    *,
    workspace: Path,
    frozen_directory: Path,
    base_environment: dict[str, str],
    run_command: CommandRunner,
) -> dict[str, Any]:
    if not isinstance(request.principal, str) or not SAFE_PRINCIPAL.fullmatch(
        request.principal
    ):
        raise SignatureTrustError("signer principal is empty or unsafe")
    tools = {
        "git": bind_executable(request.git, "git"),
        "ssh-keygen": bind_executable(request.ssh_keygen, "ssh-keygen"),
        "ssh": bind_executable(request.ssh, "ssh"),
    }
    allowed_signers, _ = _allowed_signers_binding(
        request.allowed_signers, frozen_directory
    )
    trust: dict[str, Any] = {
        "schema": SCHEMA,
        "principal": request.principal,
        "tools": tools,
        "allowed_signers": allowed_signers,
    }
    environment = git_environment(base_environment)
    trust["git_environment"] = environment
    trust["git_config"] = [
        {"key": key, "value": value} for key, value in git_config(trust)
    ]
    ssh_version, stdout, stderr = _run(
        run_command,
        [tools["ssh"]["path"], "-V"],
        environment=base_environment,
        workspace=workspace,
        context="signature-trust:ssh-version",
    )
    if not stdout and not stderr:
        raise SignatureTrustError("ssh -V returned empty version evidence")
    trust["ssh_version"] = ssh_version
    fingerprint_command, fingerprint_stdout, _ = _run(
        run_command,
        [tools["ssh-keygen"]["path"], "-lf", allowed_signers["frozen_path"]],
        environment=base_environment,
        workspace=workspace,
        context="signature-trust:allowed-signer-fingerprints",
    )
    fingerprints = _parse_fingerprints(fingerprint_stdout)
    trust["allowed_signer_fingerprints"] = fingerprints
    trust["fingerprint_command"] = fingerprint_command
    trust["replacement_refs"] = _replacement_refs_receipt(
        trust,
        workspace=workspace,
        environment=environment,
        run_command=run_command,
        context="signature-trust:replacement-refs",
    )
    trust["local_config"] = _local_config_receipt(
        trust,
        workspace=workspace,
        environment=environment,
        run_command=run_command,
        context="signature-trust:local-config",
    )
    trust["passed"] = True
    validate_signature_trust_receipt(
        trust,
        workspace=workspace,
        expected_principal=request.principal,
        verify_tool_files=True,
        verify_frozen_file=True,
    )
    return trust


def verify_signature_inputs_unchanged(trust: dict[str, Any]) -> None:
    for name in ("git", "ssh-keygen", "ssh"):
        _validate_bound_executable(trust["tools"][name], name, verify_file=True)
    allowed = trust["allowed_signers"]
    expected = _decoded_allowed_signers(allowed)
    frozen_path = Path(allowed["frozen_path"])
    try:
        frozen_value = frozen_path.read_bytes()
        frozen_metadata = frozen_path.stat()
    except OSError as error:
        raise SignatureTrustError("frozen allowed-signers is unavailable") from error
    if (
        frozen_path.is_symlink()
        or not stat.S_ISREG(frozen_metadata.st_mode)
        or stat.S_IMODE(frozen_metadata.st_mode) != 0o400
        or frozen_metadata.st_size != len(expected)
        or frozen_value != expected
    ):
        raise SignatureTrustError("frozen allowed-signers bytes changed")


def verify_signature_source_unchanged(trust: dict[str, Any]) -> None:
    """Verify the original allowed-signers provenance path when it still exists."""

    allowed = trust["allowed_signers"]
    expected = _decoded_allowed_signers(allowed)
    invocation = Path(allowed["invocation"])
    path = Path(allowed["path"])
    try:
        resolved = invocation.resolve(strict=True)
        metadata = path.stat()
        value = path.read_bytes()
    except OSError as error:
        raise SignatureTrustError("source allowed-signers is unavailable") from error
    if (
        invocation.is_symlink()
        or resolved != path
        or path.resolve(strict=True) != path
        or not stat.S_ISREG(metadata.st_mode)
        or metadata.st_size != len(expected)
        or value != expected
    ):
        raise SignatureTrustError("source allowed-signers bytes changed")


def verify_commit(
    commit: str,
    trust: dict[str, Any],
    *,
    workspace: Path,
    base_environment: dict[str, str],
    run_command: CommandRunner,
) -> dict[str, Any]:
    if not HEX_40.fullmatch(commit):
        raise SignatureTrustError("commit is not a full lowercase object ID")
    validate_signature_trust_receipt(
        trust,
        workspace=workspace,
        expected_principal=trust["principal"],
        verify_tool_files=True,
        verify_frozen_file=True,
    )
    verify_signature_inputs_unchanged(trust)
    environment = git_environment(base_environment)
    before = _local_config_receipt(
        trust,
        workspace=workspace,
        environment=environment,
        run_command=run_command,
        context="signature-verify:local-config-before",
    )
    if before["stdout_sha256"] != trust["local_config"]["stdout_sha256"]:
        raise SignatureTrustError("local Git config changed before signature verification")
    replacement_refs_before = _replacement_refs_receipt(
        trust,
        workspace=workspace,
        environment=environment,
        run_command=run_command,
        context="signature-verify:replacement-refs-before",
    )
    verify_command, _, _ = _run(
        run_command,
        git_argv(trust, ["verify-commit", commit]),
        environment=environment,
        workspace=workspace,
        context="signature-verify:verify-commit",
    )
    status_command, stdout, _ = _run(
        run_command,
        git_argv(
            trust,
            [
                "log",
                "-1",
                "--no-show-signature",
                "--format=%G?%x00%GS%x00%GF",
                commit,
            ],
        ),
        environment=environment,
        workspace=workspace,
        context="signature-verify:status",
    )
    status, principal, fingerprint = _parse_signature_status(stdout)
    if (
        status != "G"
        or principal != trust["principal"]
        or not fingerprint
        or fingerprint not in trust["allowed_signer_fingerprints"]
    ):
        raise SignatureTrustError("commit signature identity or fingerprint differs")
    after = _local_config_receipt(
        trust,
        workspace=workspace,
        environment=environment,
        run_command=run_command,
        context="signature-verify:local-config-after",
    )
    if after["stdout_sha256"] != trust["local_config"]["stdout_sha256"]:
        raise SignatureTrustError("local Git config changed during signature verification")
    replacement_refs_after = _replacement_refs_receipt(
        trust,
        workspace=workspace,
        environment=environment,
        run_command=run_command,
        context="signature-verify:replacement-refs-after",
    )
    verify_signature_inputs_unchanged(trust)
    receipt = {
        "commit": commit,
        "status": status,
        "principal": principal,
        "fingerprint": fingerprint,
        "local_config_before": before,
        "replacement_refs_before": replacement_refs_before,
        "verify_commit": verify_command,
        "status_query": status_command,
        "local_config_after": after,
        "replacement_refs_after": replacement_refs_after,
        "passed": True,
    }
    validate_signature_verification_receipt(
        receipt,
        commit,
        trust,
        workspace=workspace,
        base_environment=base_environment,
    )
    return receipt
