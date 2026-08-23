#!/usr/bin/env python3
"""Exact signed-Git-tree materialization for formal Proposal 0004 Gate H."""

from __future__ import annotations

import copy
import hashlib
import json
import os
from pathlib import Path, PurePosixPath
import re
import stat
import tarfile
from typing import Any, Sequence

try:
    import gate_h_signature
except ModuleNotFoundError:  # Imported as ``lab.gate_h_source`` in tests.
    from lab import gate_h_signature


SCHEMA = "aster-gate-h-signed-source/v1"
HEX_40 = re.compile(r"^[0-9a-f]{40}$")
HEX_64 = re.compile(r"^[0-9a-f]{64}$")
MAX_TIMEOUT_SECONDS = 1_800
MAX_FILES = 100_000
MAX_FILE_BYTES = 256 * 1024 * 1024
MAX_TOTAL_BYTES = 2 * 1024 * 1024 * 1024
RECEIPT_KEYS = frozenset(
    {
        "schema",
        "commit",
        "tree",
        "workspace",
        "signature_trust_sha256",
        "git_environment",
        "info_attributes",
        "commands",
        "archive",
        "export",
        "files",
        "files_sha256",
        "passed",
    }
)
FILE_KEYS = frozenset(
    {"path", "mode", "git_blob", "size_bytes", "sha256"}
)
ARCHIVE_KEYS = frozenset(
    {"created_path", "path", "size_bytes", "sha256"}
)
EXPORT_KEYS = frozenset(
    {"created_path", "path", "file_count", "total_bytes"}
)
INFO_ATTRIBUTES_KEYS = frozenset({"path", "before", "after"})
INFO_ATTRIBUTES_STATE_KEYS = frozenset(
    {"exists", "size_bytes", "sha256"}
)


class SignedSourceError(RuntimeError):
    """A fail-closed signed-source materialization or validation error."""


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def canonical_sha256(value: Any) -> str:
    return hashlib.sha256(
        json.dumps(
            value,
            sort_keys=True,
            separators=(",", ":"),
            ensure_ascii=False,
        ).encode("utf-8")
    ).hexdigest()


def _exact_keys(value: Any, expected: frozenset[str], context: str) -> None:
    if not isinstance(value, dict) or set(value) != expected:
        raise SignedSourceError(f"{context} keys differ")


def _absolute_path(value: Any, context: str) -> Path:
    if not isinstance(value, str) or not value:
        raise SignedSourceError(f"{context} is not a nonempty path")
    path = Path(value)
    if not path.is_absolute():
        raise SignedSourceError(f"{context} is not absolute")
    return path


def _safe_relative_path(value: str) -> PurePosixPath:
    if (
        not value
        or "\\" in value
        or "\x00" in value
        or any(ord(character) < 32 or ord(character) == 127 for character in value)
    ):
        raise SignedSourceError("signed source contains an unsafe path")
    path = PurePosixPath(value)
    if path.is_absolute() or any(part in ("", ".", "..") for part in path.parts):
        raise SignedSourceError("signed source path escapes its export root")
    return path


def _git_blob_id(value: bytes) -> str:
    return hashlib.sha1(
        f"blob {len(value)}\0".encode("ascii") + value,
        usedforsecurity=False,
    ).hexdigest()


def _git_object_id(kind: str, value: bytes) -> str:
    return hashlib.sha1(
        f"{kind} {len(value)}\0".encode("ascii") + value,
        usedforsecurity=False,
    ).hexdigest()


def _parse_ls_tree(value: bytes) -> list[dict[str, Any]]:
    bindings: list[dict[str, Any]] = []
    observed: set[str] = set()
    for record in value.split(b"\0"):
        if not record:
            continue
        metadata, separator, raw_path = record.partition(b"\t")
        fields = metadata.split()
        if (
            not separator
            or len(fields) != 4
            or fields[0] not in (b"100644", b"100755")
            or fields[1] != b"blob"
            or re.fullmatch(rb"[0-9a-f]{40}", fields[2]) is None
            or not fields[3].isdigit()
        ):
            raise SignedSourceError(
                "signed source tree contains a non-regular or malformed entry"
            )
        try:
            path = raw_path.decode("utf-8")
        except UnicodeError as error:
            raise SignedSourceError("signed source tree path is not UTF-8") from error
        path = _safe_relative_path(path).as_posix()
        size = int(fields[3])
        if path in observed or size > MAX_FILE_BYTES:
            raise SignedSourceError("signed source tree entry is duplicated or oversized")
        observed.add(path)
        bindings.append(
            {
                "path": path,
                "mode": fields[0].decode("ascii"),
                "git_blob": fields[2].decode("ascii"),
                "size_bytes": size,
            }
        )
        if len(bindings) > MAX_FILES:
            raise SignedSourceError("signed source tree has too many files")
    if not bindings:
        raise SignedSourceError("signed source tree is empty")
    bindings.sort(key=lambda item: item["path"].encode("utf-8"))
    return bindings


def _reject_archive_local_config(entries: Any) -> None:
    if not isinstance(entries, list):
        raise SignedSourceError("signed source local Git config is malformed")
    forbidden = []
    for entry in entries:
        if not isinstance(entry, dict) or set(entry) != {"key", "value"}:
            raise SignedSourceError("signed source local Git config entry is malformed")
        key = entry["key"].casefold()
        if key == "core.attributesfile" or key.startswith("tar."):
            forbidden.append(entry["key"])
    if forbidden:
        raise SignedSourceError(
            "signed source local Git config controls archive output: "
            + ", ".join(sorted(forbidden))
        )


def _info_attributes_state(workspace: Path) -> tuple[Path, dict[str, Any]]:
    git_directory = workspace / ".git"
    info_directory = git_directory / "info"
    path = info_directory / "attributes"
    if git_directory.is_symlink() or not git_directory.is_dir():
        raise SignedSourceError("signed source workspace has no exact .git directory")
    if info_directory.exists() and (
        info_directory.is_symlink() or not info_directory.is_dir()
    ):
        raise SignedSourceError("signed source .git/info path is unsafe")
    if not path.exists():
        if path.is_symlink():
            raise SignedSourceError("signed source info attributes is a broken symlink")
        return path, {"exists": False, "size_bytes": 0, "sha256": None}
    try:
        metadata = path.stat()
        value = path.read_bytes()
    except OSError as error:
        raise SignedSourceError("signed source info attributes is unreadable") from error
    if path.is_symlink() or not stat.S_ISREG(metadata.st_mode) or value:
        raise SignedSourceError("signed source info attributes must be absent or empty")
    return path, {
        "exists": True,
        "size_bytes": 0,
        "sha256": hashlib.sha256(b"").hexdigest(),
    }


def _local_config_command(
    run_command: Any,
    trust: dict[str, Any],
    *,
    environment: dict[str, str],
    workspace: Path,
    timeout_seconds: int,
    context: str,
) -> tuple[dict[str, Any], list[dict[str, str]]]:
    argv = gate_h_signature.git_argv(
        trust, ["config", "--local", "--no-includes", "--null", "--list"]
    )
    receipt, stdout, _stderr = _run_command(
        run_command,
        argv,
        environment=environment,
        workspace=workspace,
        timeout_seconds=timeout_seconds,
        context=context,
    )
    try:
        entries = gate_h_signature.parse_local_config(stdout)
    except gate_h_signature.SignatureTrustError as error:
        raise SignedSourceError("signed source local Git config is invalid") from error
    _reject_archive_local_config(entries)
    if entries != trust["local_config"]["entries"]:
        raise SignedSourceError("signed source local Git config changed")
    return receipt, entries


def _ls_tree_argv(trust: dict[str, Any], tree: str) -> list[str]:
    return gate_h_signature.git_argv(
        trust, ["ls-tree", "-r", "-z", "--full-tree", "--long", tree]
    )


def _archive_argv(
    trust: dict[str, Any], commit: str, archive_path: Path
) -> list[str]:
    return gate_h_signature.git_argv(
        trust,
        [
            "-c",
            "core.attributesFile=/dev/null",
            "-c",
            "tar.umask=0022",
            "archive",
            "--format=tar",
            f"--output={archive_path}",
            commit,
        ],
    )


def _tree_id(files: Sequence[dict[str, Any]]) -> str:
    root: dict[bytes, Any] = {}
    for binding in files:
        parts = tuple(part.encode("utf-8") for part in PurePosixPath(binding["path"]).parts)
        node = root
        for part in parts[:-1]:
            existing = node.setdefault(part, {})
            if not isinstance(existing, dict):
                raise SignedSourceError("signed source has a file/directory collision")
            node = existing
        leaf = parts[-1]
        if leaf in node:
            raise SignedSourceError("signed source contains a duplicate path")
        node[leaf] = ("file", binding)

    def encode_tree(node: dict[bytes, Any]) -> str:
        entries: list[tuple[bytes, bytes]] = []
        for name, value in node.items():
            if isinstance(value, dict):
                object_id = encode_tree(value)
                mode = "40000"
                sort_key = name + b"/"
            else:
                binding = value[1]
                object_id = binding["git_blob"]
                mode = binding["mode"]
                sort_key = name + b"\0"
            entry = (
                mode.encode("ascii")
                + b" "
                + name
                + b"\0"
                + bytes.fromhex(object_id)
            )
            entries.append((sort_key, entry))
        encoded = b"".join(entry for _key, entry in sorted(entries))
        return _git_object_id("tree", encoded)

    return encode_tree(root)


def _archive_files(path: Path, *, commit: str) -> list[tuple[dict[str, Any], bytes]]:
    try:
        with tarfile.open(path, mode="r:") as archive:
            if archive.pax_headers != {"comment": commit}:
                raise SignedSourceError(
                    "signed source archive has noncanonical global PAX headers"
                )
            members = archive.getmembers()
            observed_paths: set[str] = set()
            observed_casefold: set[str] = set()
            observed_directories: set[str] = set()
            values: list[tuple[dict[str, Any], bytes]] = []
            total_bytes = 0
            for member in members:
                relative = _safe_relative_path(member.name.rstrip("/"))
                name = relative.as_posix()
                if name in observed_paths or name.casefold() in observed_casefold:
                    raise SignedSourceError(
                        "signed source archive has duplicate or case-colliding paths"
                    )
                observed_paths.add(name)
                observed_casefold.add(name.casefold())
                if member.pax_headers != {"comment": commit}:
                    raise SignedSourceError(
                        "signed source archive has noncanonical member PAX headers"
                    )
                if member.isdir():
                    if member.mode != 0o755:
                        raise SignedSourceError(
                            "signed source archive directory mode differs"
                        )
                    observed_directories.add(name)
                    continue
                if not member.isreg():
                    raise SignedSourceError(
                        "signed source archive contains a non-regular entry"
                    )
                if member.size < 0 or member.size > MAX_FILE_BYTES:
                    raise SignedSourceError("signed source file size is out of bounds")
                stream = archive.extractfile(member)
                if stream is None:
                    raise SignedSourceError("signed source archive file is unreadable")
                value = stream.read(MAX_FILE_BYTES + 1)
                if len(value) != member.size or len(value) > MAX_FILE_BYTES:
                    raise SignedSourceError("signed source archive file is truncated")
                total_bytes += len(value)
                if total_bytes > MAX_TOTAL_BYTES:
                    raise SignedSourceError("signed source archive is too large")
                if member.mode not in (0o644, 0o755):
                    raise SignedSourceError("signed source archive file mode differs")
                executable = member.mode == 0o755
                binding = {
                    "path": name,
                    "mode": "100755" if executable else "100644",
                    "git_blob": _git_blob_id(value),
                    "size_bytes": len(value),
                    "sha256": hashlib.sha256(value).hexdigest(),
                }
                values.append((binding, value))
                if len(values) > MAX_FILES:
                    raise SignedSourceError("signed source archive has too many files")
    except (OSError, tarfile.TarError) as error:
        raise SignedSourceError("signed source archive is invalid") from error
    values.sort(key=lambda item: item[0]["path"].encode("utf-8"))
    if not values:
        raise SignedSourceError("signed source archive is empty")
    expected_directories = {
        PurePosixPath(*PurePosixPath(binding["path"]).parts[:index]).as_posix()
        for binding, _value in values
        for index in range(1, len(PurePosixPath(binding["path"]).parts))
    }
    if observed_directories != expected_directories:
        raise SignedSourceError("signed source archive directory inventory differs")
    return values


def _create_export(
    archive_path: Path,
    export_root: Path,
    *,
    commit: str,
) -> list[dict[str, Any]]:
    if export_root.exists() or export_root.is_symlink():
        raise SignedSourceError("signed source export path already exists")
    values = _archive_files(archive_path, commit=commit)
    try:
        export_root.mkdir(mode=0o700)
        directories = {export_root}
        for binding, value in values:
            destination = export_root.joinpath(*PurePosixPath(binding["path"]).parts)
            parent = destination.parent
            parent.mkdir(mode=0o700, parents=True, exist_ok=True)
            current = parent
            while current != export_root.parent:
                directories.add(current)
                if current == export_root:
                    break
                current = current.parent
            flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL
            flags |= getattr(os, "O_NOFOLLOW", 0)
            descriptor = os.open(destination, flags, 0o600)
            try:
                with os.fdopen(descriptor, "wb", closefd=True) as stream:
                    descriptor = -1
                    if stream.write(value) != len(value):
                        raise OSError("short signed source write")
                    stream.flush()
                    os.fsync(stream.fileno())
            finally:
                if descriptor >= 0:
                    os.close(descriptor)
            destination.chmod(0o555 if binding["mode"] == "100755" else 0o444)
        for directory in sorted(directories, key=lambda item: len(item.parts), reverse=True):
            directory.chmod(0o555)
    except OSError as error:
        raise SignedSourceError("unable to materialize signed source export") from error
    return [binding for binding, _value in values]


def _validate_files(value: Any, *, expected_tree: str) -> list[dict[str, Any]]:
    if not isinstance(value, list) or not value or len(value) > MAX_FILES:
        raise SignedSourceError("signed source file inventory is malformed")
    paths: list[str] = []
    casefolded: set[str] = set()
    total_bytes = 0
    for binding in value:
        _exact_keys(binding, FILE_KEYS, "signed source file binding")
        path = _safe_relative_path(binding["path"]).as_posix()
        if path != binding["path"] or path.casefold() in casefolded:
            raise SignedSourceError("signed source file paths differ")
        casefolded.add(path.casefold())
        paths.append(path)
        if binding["mode"] not in ("100644", "100755"):
            raise SignedSourceError("signed source file mode is unsupported")
        if not isinstance(binding["git_blob"], str) or HEX_40.fullmatch(
            binding["git_blob"]
        ) is None:
            raise SignedSourceError("signed source blob ID is malformed")
        if (
            isinstance(binding["size_bytes"], bool)
            or not isinstance(binding["size_bytes"], int)
            or binding["size_bytes"] < 0
            or binding["size_bytes"] > MAX_FILE_BYTES
            or not isinstance(binding["sha256"], str)
            or HEX_64.fullmatch(binding["sha256"]) is None
        ):
            raise SignedSourceError("signed source file identity is malformed")
        total_bytes += binding["size_bytes"]
    if paths != sorted(paths, key=lambda item: item.encode("utf-8")):
        raise SignedSourceError("signed source file inventory is not ordered")
    if len(set(paths)) != len(paths) or total_bytes > MAX_TOTAL_BYTES:
        raise SignedSourceError("signed source file inventory is duplicated or oversized")
    if _tree_id(value) != expected_tree:
        raise SignedSourceError("signed source files do not reconstruct the signed tree")
    return value


def _validate_file_materialization(
    root: Path, files: Sequence[dict[str, Any]]
) -> None:
    if root.is_symlink() or not root.is_dir():
        raise SignedSourceError("signed source export root is unavailable")
    expected = {binding["path"]: binding for binding in files}
    observed: dict[str, Path] = {}
    for path in root.rglob("*"):
        if path.is_symlink():
            raise SignedSourceError("signed source export contains a symlink")
        if path.is_dir():
            if stat.S_IMODE(path.stat().st_mode) != 0o555:
                raise SignedSourceError("signed source directory mode differs")
            continue
        if not path.is_file():
            raise SignedSourceError("signed source export contains a special file")
        relative = path.relative_to(root).as_posix()
        if relative in observed:
            raise SignedSourceError("signed source export contains a duplicate file")
        observed[relative] = path
    if set(observed) != set(expected):
        raise SignedSourceError("signed source export files differ")
    if stat.S_IMODE(root.stat().st_mode) != 0o555:
        raise SignedSourceError("signed source export root mode differs")
    for relative, binding in expected.items():
        path = observed[relative]
        mode = stat.S_IMODE(path.stat().st_mode)
        expected_mode = 0o555 if binding["mode"] == "100755" else 0o444
        if (
            mode != expected_mode
            or path.stat().st_size != binding["size_bytes"]
            or sha256_file(path) != binding["sha256"]
        ):
            raise SignedSourceError(f"signed source export file differs: {relative}")


def _run_command(
    run_command: Any,
    argv: Sequence[str],
    *,
    environment: dict[str, str],
    workspace: Path,
    timeout_seconds: int,
    context: str,
) -> tuple[dict[str, Any], bytes, bytes]:
    receipt, stdout, stderr = run_command(
        argv,
        environment=environment,
        stdin_value=None,
        timeout_seconds=timeout_seconds,
        context=context,
    )
    if stdout is None or stderr is None:
        raise SignedSourceError(f"signed source command streams are incomplete: {context}")
    try:
        retained_stdout, retained_stderr = (
            gate_h_signature._validate_successful_command(
                receipt,
                argv=argv,
                environment=environment,
                workspace=workspace,
                context=context,
            )
        )
    except gate_h_signature.SignatureTrustError as error:
        raise SignedSourceError(f"signed source command failed: {context}: {error}") from error
    if retained_stdout != stdout or retained_stderr != stderr:
        raise SignedSourceError(f"signed source command streams differ: {context}")
    return receipt, stdout, stderr


def materialize_signed_tree(
    commit: str,
    tree: str,
    trust: dict[str, Any],
    *,
    workspace: Path,
    archive_path: Path,
    export_root: Path,
    base_environment: dict[str, str],
    run_command: Any,
    timeout_seconds: int = 120,
) -> dict[str, Any]:
    """Create a read-only Docker context containing exactly one signed Git tree."""

    if HEX_40.fullmatch(commit) is None or HEX_40.fullmatch(tree) is None:
        raise SignedSourceError("signed source commit or tree ID is malformed")
    if not workspace.is_absolute() or not workspace.is_dir():
        raise SignedSourceError("signed source workspace is unavailable")
    if (
        not archive_path.is_absolute()
        or not export_root.is_absolute()
        or archive_path.exists()
        or archive_path.is_symlink()
        or export_root.exists()
        or export_root.is_symlink()
        or not archive_path.parent.is_dir()
        or not export_root.parent.is_dir()
    ):
        raise SignedSourceError("signed source output paths are unsafe or already exist")
    if (
        isinstance(timeout_seconds, bool)
        or not isinstance(timeout_seconds, int)
        or timeout_seconds < 1
        or timeout_seconds > MAX_TIMEOUT_SECONDS
    ):
        raise SignedSourceError("signed source timeout is out of bounds")
    try:
        gate_h_signature.validate_signature_trust_receipt(
            trust,
            workspace=workspace,
            expected_principal=trust.get("principal"),
            verify_tool_files=True,
            verify_frozen_file=True,
        )
        environment = gate_h_signature.git_environment(base_environment)
    except gate_h_signature.SignatureTrustError as error:
        raise SignedSourceError(f"signed source signature trust is invalid: {error}") from error
    if environment != trust["git_environment"]:
        raise SignedSourceError("signed source Git environment differs from live trust")
    info_path, info_before = _info_attributes_state(workspace)
    local_before_command, _local_before = _local_config_command(
        run_command,
        trust,
        environment=environment,
        workspace=workspace,
        timeout_seconds=timeout_seconds,
        context="signed-source:local-config-before",
    )
    tree_argv = gate_h_signature.git_argv(
        trust, ["rev-parse", f"{commit}^{{tree}}"]
    )
    tree_command, tree_stdout, _ = _run_command(
        run_command,
        tree_argv,
        environment=environment,
        workspace=workspace,
        timeout_seconds=timeout_seconds,
        context="signed-source:tree",
    )
    if tree_stdout.rstrip(b"\r\n") != tree.encode("ascii"):
        raise SignedSourceError("signed source commit resolves to another tree")
    ls_tree_argv = _ls_tree_argv(trust, tree)
    ls_tree_command, ls_tree_stdout, _ = _run_command(
        run_command,
        ls_tree_argv,
        environment=environment,
        workspace=workspace,
        timeout_seconds=timeout_seconds,
        context="signed-source:ls-tree",
    )
    tree_inventory = _parse_ls_tree(ls_tree_stdout)
    archive_argv = _archive_argv(trust, commit, archive_path)
    archive_command, archive_stdout, _ = _run_command(
        run_command,
        archive_argv,
        environment=environment,
        workspace=workspace,
        timeout_seconds=timeout_seconds,
        context="signed-source:archive",
    )
    if archive_stdout != b"":
        raise SignedSourceError("signed source archive command wrote unexpected stdout")
    try:
        archive_metadata = archive_path.stat()
    except OSError as error:
        raise SignedSourceError("signed source archive was not created") from error
    if archive_path.is_symlink() or not stat.S_ISREG(archive_metadata.st_mode):
        raise SignedSourceError("signed source archive is not a regular file")
    files = _create_export(archive_path, export_root, commit=commit)
    archive_tree_inventory = [
        {key: binding[key] for key in ("path", "mode", "git_blob", "size_bytes")}
        for binding in files
    ]
    if archive_tree_inventory != tree_inventory:
        raise SignedSourceError("signed source archive differs from exact ls-tree")
    if _tree_id(files) != tree:
        raise SignedSourceError("signed source archive does not reconstruct the signed tree")
    local_after_command, _local_after = _local_config_command(
        run_command,
        trust,
        environment=environment,
        workspace=workspace,
        timeout_seconds=timeout_seconds,
        context="signed-source:local-config-after",
    )
    final_info_path, info_after = _info_attributes_state(workspace)
    if final_info_path != info_path or info_after != info_before:
        raise SignedSourceError("signed source info attributes changed")
    archive_path.chmod(0o444)
    receipt = {
        "schema": SCHEMA,
        "commit": commit,
        "tree": tree,
        "workspace": str(workspace),
        "signature_trust_sha256": canonical_sha256(trust),
        "git_environment": environment,
        "info_attributes": {
            "path": str(info_path),
            "before": info_before,
            "after": info_after,
        },
        "commands": {
            "local_config_before": local_before_command,
            "tree": tree_command,
            "ls_tree": ls_tree_command,
            "archive": archive_command,
            "local_config_after": local_after_command,
        },
        "archive": {
            "created_path": str(archive_path),
            "path": str(archive_path),
            "size_bytes": archive_path.stat().st_size,
            "sha256": sha256_file(archive_path),
        },
        "export": {
            "created_path": str(export_root),
            "path": str(export_root),
            "file_count": len(files),
            "total_bytes": sum(binding["size_bytes"] for binding in files),
        },
        "files": files,
        "files_sha256": canonical_sha256(files),
        "passed": True,
    }
    validate_signed_tree_receipt(
        receipt,
        workspace=workspace,
        trust=trust,
        verify_archive_file=True,
        verify_export=True,
    )
    return receipt


def validate_signed_tree_receipt(
    receipt: Any,
    *,
    workspace: Path,
    trust: dict[str, Any],
    verify_archive_file: bool = True,
    verify_export: bool = True,
) -> Path:
    """Validate a signed-tree receipt and return its current export root."""

    _exact_keys(receipt, RECEIPT_KEYS, "signed source receipt")
    if (
        receipt["schema"] != SCHEMA
        or receipt["passed"] is not True
        or HEX_40.fullmatch(receipt["commit"]) is None
        or HEX_40.fullmatch(receipt["tree"]) is None
        or receipt["workspace"] != str(workspace)
        or receipt["signature_trust_sha256"] != canonical_sha256(trust)
    ):
        raise SignedSourceError("signed source identity differs")
    try:
        gate_h_signature.validate_signature_trust_receipt(
            trust,
            workspace=workspace,
            expected_principal=trust.get("principal"),
            verify_tool_files=True,
            verify_frozen_file=False,
        )
    except gate_h_signature.SignatureTrustError as error:
        raise SignedSourceError(f"signed source signature trust is invalid: {error}") from error
    if receipt["git_environment"] != trust["git_environment"]:
        raise SignedSourceError("signed source Git environment differs")
    info_attributes = receipt["info_attributes"]
    _exact_keys(info_attributes, INFO_ATTRIBUTES_KEYS, "info attributes receipt")
    for state_value in (info_attributes["before"], info_attributes["after"]):
        _exact_keys(
            state_value,
            INFO_ATTRIBUTES_STATE_KEYS,
            "info attributes state",
        )
        if state_value not in (
            {"exists": False, "size_bytes": 0, "sha256": None},
            {
                "exists": True,
                "size_bytes": 0,
                "sha256": hashlib.sha256(b"").hexdigest(),
            },
        ):
            raise SignedSourceError("info attributes state is not absent or empty")
    current_info_path, current_info_state = _info_attributes_state(workspace)
    if (
        info_attributes["path"] != str(current_info_path)
        or info_attributes["before"] != info_attributes["after"]
        or current_info_state != info_attributes["after"]
    ):
        raise SignedSourceError("signed source info attributes receipt differs")
    commands = receipt["commands"]
    expected_command_keys = {
        "local_config_before",
        "tree",
        "ls_tree",
        "archive",
        "local_config_after",
    }
    if not isinstance(commands, dict) or set(commands) != expected_command_keys:
        raise SignedSourceError("signed source command receipts differ")
    archive = receipt["archive"]
    export = receipt["export"]
    _exact_keys(archive, ARCHIVE_KEYS, "signed source archive binding")
    _exact_keys(export, EXPORT_KEYS, "signed source export binding")
    created_archive = _absolute_path(archive["created_path"], "created archive")
    current_archive = _absolute_path(archive["path"], "current archive")
    created_export = _absolute_path(export["created_path"], "created export")
    current_export = _absolute_path(export["path"], "current export")
    if (
        isinstance(archive["size_bytes"], bool)
        or not isinstance(archive["size_bytes"], int)
        or archive["size_bytes"] <= 0
        or not isinstance(archive["sha256"], str)
        or HEX_64.fullmatch(archive["sha256"]) is None
    ):
        raise SignedSourceError("signed source archive identity is malformed")
    files = _validate_files(receipt["files"], expected_tree=receipt["tree"])
    total_bytes = sum(binding["size_bytes"] for binding in files)
    if (
        receipt["files_sha256"] != canonical_sha256(files)
        or export["file_count"] != len(files)
        or export["total_bytes"] != total_bytes
        or isinstance(export["file_count"], bool)
        or isinstance(export["total_bytes"], bool)
    ):
        raise SignedSourceError("signed source aggregate identity differs")
    try:
        local_argv = gate_h_signature.git_argv(
            trust,
            ["config", "--local", "--no-includes", "--null", "--list"],
        )
        local_before_stdout, _ = gate_h_signature._validate_successful_command(
            commands["local_config_before"],
            argv=local_argv,
            environment=receipt["git_environment"],
            workspace=workspace,
            context="signed-source:local-config-before",
        )
        tree_stdout, _ = gate_h_signature._validate_successful_command(
            commands["tree"],
            argv=gate_h_signature.git_argv(
                trust, ["rev-parse", f"{receipt['commit']}^{{tree}}"]
            ),
            environment=receipt["git_environment"],
            workspace=workspace,
            context="signed-source:tree",
        )
        ls_tree_stdout, _ = gate_h_signature._validate_successful_command(
            commands["ls_tree"],
            argv=_ls_tree_argv(trust, receipt["tree"]),
            environment=receipt["git_environment"],
            workspace=workspace,
            context="signed-source:ls-tree",
        )
        archive_stdout, _ = gate_h_signature._validate_successful_command(
            commands["archive"],
            argv=_archive_argv(trust, receipt["commit"], created_archive),
            environment=receipt["git_environment"],
            workspace=workspace,
            context="signed-source:archive",
        )
        local_after_stdout, _ = gate_h_signature._validate_successful_command(
            commands["local_config_after"],
            argv=local_argv,
            environment=receipt["git_environment"],
            workspace=workspace,
            context="signed-source:local-config-after",
        )
    except gate_h_signature.SignatureTrustError as error:
        raise SignedSourceError(f"signed source command receipt is invalid: {error}") from error
    try:
        local_before = gate_h_signature.parse_local_config(local_before_stdout)
        local_after = gate_h_signature.parse_local_config(local_after_stdout)
    except gate_h_signature.SignatureTrustError as error:
        raise SignedSourceError("signed source local config receipt is invalid") from error
    _reject_archive_local_config(local_before)
    _reject_archive_local_config(local_after)
    if (
        local_before != trust["local_config"]["entries"]
        or local_after != local_before
    ):
        raise SignedSourceError("signed source local config receipt changed")
    if tree_stdout.rstrip(b"\r\n").decode("ascii", errors="replace") != receipt["tree"]:
        raise SignedSourceError("signed source tree command output differs")
    if archive_stdout != b"":
        raise SignedSourceError("signed source archive command output differs")
    tree_inventory = _parse_ls_tree(ls_tree_stdout)
    receipt_tree_inventory = [
        {key: binding[key] for key in ("path", "mode", "git_blob", "size_bytes")}
        for binding in files
    ]
    if tree_inventory != receipt_tree_inventory:
        raise SignedSourceError("signed source ls-tree inventory differs")
    if verify_archive_file:
        try:
            metadata = current_archive.stat()
        except OSError as error:
            raise SignedSourceError("signed source archive is unavailable") from error
        if (
            current_archive.is_symlink()
            or not stat.S_ISREG(metadata.st_mode)
            or stat.S_IMODE(metadata.st_mode) != 0o444
            or metadata.st_size != archive["size_bytes"]
            or sha256_file(current_archive) != archive["sha256"]
        ):
            raise SignedSourceError("signed source archive file differs")
        archived = [binding for binding, _value in _archive_files(
            current_archive, commit=receipt["commit"]
        )]
        if archived != files:
            raise SignedSourceError("signed source archive inventory differs")
    if verify_export:
        _validate_file_materialization(current_export, files)
    if created_export == current_export and verify_export and not current_export.is_dir():
        raise SignedSourceError("signed source created export is unavailable")
    return current_export


def rematerialize_signed_tree(
    receipt: dict[str, Any],
    *,
    workspace: Path,
    trust: dict[str, Any],
    archive_path: Path,
    export_root: Path,
) -> dict[str, Any]:
    """Rebind a retained archive and reconstruct its exact read-only source tree."""

    validate_signed_tree_receipt(
        receipt,
        workspace=workspace,
        trust=trust,
        verify_archive_file=False,
        verify_export=False,
    )
    if not archive_path.is_absolute() or not export_root.is_absolute():
        raise SignedSourceError("signed source rebound paths are not absolute")
    archive = receipt["archive"]
    try:
        metadata = archive_path.stat()
    except OSError as error:
        raise SignedSourceError("retained signed source archive is unavailable") from error
    if (
        archive_path.is_symlink()
        or not stat.S_ISREG(metadata.st_mode)
        or metadata.st_size != archive["size_bytes"]
        or sha256_file(archive_path) != archive["sha256"]
    ):
        raise SignedSourceError("retained signed source archive differs")
    files = _create_export(archive_path, export_root, commit=receipt["commit"])
    if files != receipt["files"]:
        raise SignedSourceError("rematerialized signed source files differ")
    rebound = copy.deepcopy(receipt)
    rebound["archive"]["path"] = str(archive_path)
    rebound["export"]["path"] = str(export_root)
    validate_signed_tree_receipt(
        rebound,
        workspace=workspace,
        trust=trust,
        verify_archive_file=True,
        verify_export=True,
    )
    return rebound


__all__ = (
    "SCHEMA",
    "SignedSourceError",
    "materialize_signed_tree",
    "rematerialize_signed_tree",
    "validate_signed_tree_receipt",
)
