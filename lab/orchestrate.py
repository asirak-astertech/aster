#!/usr/bin/env python3
"""Reproducible, fail-closed OrbStack/Docker controller for the Aster lab.

The controller is dry-run by default.  Docker mutation requires the explicit
``--execute`` option.  It never invokes a shell and never pulls an image.
"""

from __future__ import annotations

import argparse
import dataclasses
import datetime as dt
import hashlib
import ipaddress
import json
import math
import os
from pathlib import Path
import re
import secrets
import shlex
import shutil
import subprocess
import sys
import time
from typing import Any, Iterable, Sequence


SCHEMA = "aster-lab-controller/v1"
PREFIX = "aster-lab-"
IMAGE = "aster-lab:validation"
LAB_BASE_IMAGE = "rust@sha256:0e2bcaef56d041a486784e54104a81aebe0da44bd03019bd70bc0401e42e4a97"
MANAGED_LABEL = "com.defenseunicorns.aster-lab.managed"
RUN_LABEL = "com.defenseunicorns.aster-lab.run-id"
ROLE_LABEL = "com.defenseunicorns.aster-lab.role"
IMAGE_SCHEMA_LABEL = "com.defenseunicorns.aster-lab.image-schema"
IMAGE_INPUT_LABEL = "com.defenseunicorns.aster-lab.build-input-sha256"
IMAGE_BASE_LABEL = "com.defenseunicorns.aster-lab.base-image"
IMAGE_SCHEMA = "aster-lab-image/v1"

WORKSPACE = Path(__file__).resolve().parents[1]
DOCKERFILE = WORKSPACE / "lab" / "Dockerfile"
DEFAULT_EVIDENCE_ROOT = WORKSPACE / "lab" / "runs"

DIRECT_NETWORK = "aster-lab-direct"
NAT_NETWORKS = {
    "lan-a": ("aster-lab-lan-a", "10.250.1.0/24", "10.250.1.254"),
    "wan": ("aster-lab-wan", "10.250.0.0/24", "10.250.0.254"),
    "lan-b": ("aster-lab-lan-b", "10.250.2.0/24", "10.250.2.254"),
}
DIRECT_SPEC = (DIRECT_NETWORK, "10.250.10.0/24", "10.250.10.254")

FIXED_CONTAINER_NAMES = {
    "transfer": "aster-lab-transfer",
    "blob": "aster-lab-blob",
    "scale": "aster-lab-scale",
    "resource": "aster-lab-resource",
    "provision": "aster-lab-provision",
    "node-a": "aster-lab-node-a",
    "node-b": "aster-lab-node-b",
    "nat-a": "aster-lab-nat-a",
    "nat-b": "aster-lab-nat-b",
    "infra": "aster-lab-infra",
}

RESOURCE_NAME = re.compile(r"^aster-lab-[a-z0-9][a-z0-9-]{0,62}$")
RUN_ID = re.compile(r"^[0-9a-f]{16}$")
MEMORY_VALUE = re.compile(r"^[1-9][0-9]*(?:[kmgt]b?|b)?$", re.IGNORECASE)
CPU_VALUE = re.compile(r"^(?:[1-9][0-9]*|0\.[0-9]+|[1-9][0-9]*\.[0-9]+)$")
EXPECTED_DOCKERIGNORE = """**
!Cargo.toml
!Cargo.lock
!LICENSE
!THIRD_PARTY_NOTICES.md
!crates/
!crates/**
!lab/
!lab/Dockerfile
!lab/Dockerfile.dockerignore
!lab/debian.sources
"""
TIMEOUT_CAPTURE_LIMIT = 4 * 1024 * 1024


class LabError(RuntimeError):
    """Controlled laboratory failure."""


@dataclasses.dataclass(frozen=True)
class NetworkSpec:
    name: str
    subnet: ipaddress.IPv4Network
    gateway: ipaddress.IPv4Address

    @classmethod
    def from_tuple(cls, value: tuple[str, str, str]) -> "NetworkSpec":
        result = cls(
            name=value[0],
            subnet=ipaddress.ip_network(value[1]),
            gateway=ipaddress.ip_address(value[2]),
        )
        if result.gateway not in result.subnet:
            raise LabError(f"gateway {result.gateway} is outside {result.subnet}")
        validate_resource_name(result.name)
        return result


@dataclasses.dataclass(frozen=True)
class PlannedResource:
    kind: str
    name: str
    role: str

    def as_dict(self) -> dict[str, str]:
        return dataclasses.asdict(self)


@dataclasses.dataclass(frozen=True)
class BuildInput:
    relative_path: str
    content: bytes
    sha256: str

    def receipt(self) -> dict[str, Any]:
        return {
            "path": self.relative_path,
            "bytes": len(self.content),
            "sha256": self.sha256,
        }


class CommandRunner:
    """Runs explicit argument arrays and appends a command receipt."""

    def __init__(self, run_dir: Path):
        self.run_dir = run_dir
        self.sequence = existing_command_sequence(run_dir / "commands.jsonl")

    def run(
        self,
        arguments: Sequence[str],
        *,
        input_text: str | None = None,
        check: bool = True,
        timeout: float | None = None,
    ) -> subprocess.CompletedProcess[str]:
        args = [str(value) for value in arguments]
        if not args or any("\x00" in value for value in args):
            raise LabError("invalid empty command or NUL-containing argument")
        self.sequence += 1
        sequence = self.sequence
        stdout_name = f"command-{sequence:04d}.stdout"
        stderr_name = f"command-{sequence:04d}.stderr"
        started = utc_now()
        monotonic_start = time.monotonic()
        try:
            completed = subprocess.run(
                args,
                input=input_text,
                text=True,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                shell=False,
                check=False,
                timeout=timeout,
            )
        except subprocess.TimeoutExpired as error:
            full_stdout = timeout_output(error.stdout)
            full_stderr = timeout_output(error.stderr)
            stdout, stdout_truncated = bounded_timeout_output(full_stdout)
            stderr, stderr_truncated = bounded_timeout_output(full_stderr)
            write_exclusive_text(self.run_dir / stdout_name, stdout)
            write_exclusive_text(self.run_dir / stderr_name, stderr)
            append_jsonl(
                self.run_dir / "commands.jsonl",
                {
                    "schema": SCHEMA,
                    "sequence": sequence,
                    "started_utc": started,
                    "elapsed_ms": int((time.monotonic() - monotonic_start) * 1000),
                    "arguments": args,
                    "stdin_sha256": sha256_text(input_text) if input_text is not None else None,
                    "timed_out": True,
                    "partial_stdout_sha256": sha256_text(full_stdout),
                    "partial_stderr_sha256": sha256_text(full_stderr),
                    "stdout_truncated": stdout_truncated,
                    "stderr_truncated": stderr_truncated,
                    "stdout": stdout_name,
                    "stderr": stderr_name,
                    "error": str(error),
                },
            )
            raise LabError(f"command could not run: {shlex.join(args)}: {error}") from error
        except OSError as error:
            write_exclusive_text(self.run_dir / stdout_name, "")
            write_exclusive_text(self.run_dir / stderr_name, "")
            append_jsonl(
                self.run_dir / "commands.jsonl",
                {
                    "schema": SCHEMA,
                    "sequence": sequence,
                    "started_utc": started,
                    "elapsed_ms": int((time.monotonic() - monotonic_start) * 1000),
                    "arguments": args,
                    "stdin_sha256": sha256_text(input_text) if input_text is not None else None,
                    "stdout": stdout_name,
                    "stderr": stderr_name,
                    "error": str(error),
                },
            )
            raise LabError(f"command could not run: {shlex.join(args)}: {error}") from error
        write_exclusive_text(self.run_dir / stdout_name, completed.stdout)
        write_exclusive_text(self.run_dir / stderr_name, completed.stderr)
        append_jsonl(
            self.run_dir / "commands.jsonl",
            {
                "schema": SCHEMA,
                "sequence": sequence,
                "started_utc": started,
                "elapsed_ms": int((time.monotonic() - monotonic_start) * 1000),
                "arguments": args,
                "stdin_sha256": sha256_text(input_text) if input_text is not None else None,
                "returncode": completed.returncode,
                "stdout": stdout_name,
                "stderr": stderr_name,
            },
        )
        if check and completed.returncode != 0:
            detail = completed.stderr.strip() or completed.stdout.strip()
            raise LabError(
                f"command failed ({completed.returncode}): {shlex.join(args)}"
                + (f": {detail}" if detail else "")
            )
        return completed

    def start(self, arguments: Sequence[str]) -> "RunningCommand":
        """Start one long-running command while retaining ordered evidence."""
        args = [str(value) for value in arguments]
        if not args or any("\x00" in value for value in args):
            raise LabError("invalid empty command or NUL-containing argument")
        self.sequence += 1
        sequence = self.sequence
        stdout_name = f"command-{sequence:04d}.stdout"
        stderr_name = f"command-{sequence:04d}.stderr"
        started = utc_now()
        monotonic_start = time.monotonic()
        stdout_stream = (self.run_dir / stdout_name).open("x", encoding="utf-8")
        try:
            stderr_stream = (self.run_dir / stderr_name).open("x", encoding="utf-8")
        except BaseException:
            stdout_stream.close()
            raise
        try:
            process = subprocess.Popen(
                args,
                text=True,
                stdout=stdout_stream,
                stderr=stderr_stream,
                shell=False,
            )
        except OSError as error:
            stdout_stream.close()
            stderr_stream.close()
            append_jsonl(
                self.run_dir / "commands.jsonl",
                {
                    "schema": SCHEMA,
                    "sequence": sequence,
                    "phase": "start-failed",
                    "started_utc": started,
                    "elapsed_ms": int((time.monotonic() - monotonic_start) * 1000),
                    "arguments": args,
                    "stdout": stdout_name,
                    "stderr": stderr_name,
                    "error": str(error),
                },
            )
            raise LabError(f"command could not start: {shlex.join(args)}: {error}") from error
        stdout_stream.close()
        stderr_stream.close()
        append_jsonl(
            self.run_dir / "commands.jsonl",
            {
                "schema": SCHEMA,
                "sequence": sequence,
                "phase": "started",
                "started_utc": started,
                "arguments": args,
                "stdout": stdout_name,
                "stderr": stderr_name,
            },
        )
        return RunningCommand(
            runner=self,
            process=process,
            arguments=args,
            sequence=sequence,
            started_utc=started,
            monotonic_start=monotonic_start,
            stdout_name=stdout_name,
            stderr_name=stderr_name,
        )


@dataclasses.dataclass
class RunningCommand:
    runner: CommandRunner
    process: subprocess.Popen[str]
    arguments: list[str]
    sequence: int
    started_utc: str
    monotonic_start: float
    stdout_name: str
    stderr_name: str
    finished: bool = False

    def poll(self) -> int | None:
        return self.process.poll()

    def finish(self, *, check: bool = True) -> int:
        if self.finished:
            if self.process.returncode is None:
                raise LabError("finished command has no return code")
            return self.process.returncode
        returncode = self.process.wait()
        self.finished = True
        append_jsonl(
            self.runner.run_dir / "commands.jsonl",
            {
                "schema": SCHEMA,
                "sequence": self.sequence,
                "phase": "completed",
                "started_utc": self.started_utc,
                "elapsed_ms": int((time.monotonic() - self.monotonic_start) * 1000),
                "arguments": self.arguments,
                "returncode": returncode,
                "stdout": self.stdout_name,
                "stderr": self.stderr_name,
            },
        )
        if check and returncode != 0:
            stderr = (self.runner.run_dir / self.stderr_name).read_text(
                encoding="utf-8", errors="replace"
            ).strip()
            raise LabError(
                f"command failed ({returncode}): {shlex.join(self.arguments)}"
                + (f": {stderr}" if stderr else "")
            )
        return returncode

    def terminate(self) -> int:
        if self.poll() is None:
            self.process.terminate()
            try:
                self.process.wait(timeout=5)
            except subprocess.TimeoutExpired:
                self.process.kill()
        return self.finish(check=False)


@dataclasses.dataclass
class RunContext:
    label: str
    run_id: str
    run_dir: Path
    resources: list[PlannedResource]
    runner: CommandRunner
    image_id: str | None = None
    daemon_architecture: str | None = None

    @classmethod
    def create(
        cls,
        evidence_root: Path,
        label: str,
        resources: Iterable[PlannedResource],
    ) -> "RunContext":
        if not re.fullmatch(r"[a-z0-9-]{1,32}", label):
            raise LabError("invalid run label")
        root = evidence_root.resolve()
        root.mkdir(parents=True, exist_ok=True)
        run_id = secrets.token_hex(8)
        timestamp = dt.datetime.now(dt.timezone.utc).strftime("%Y%m%dT%H%M%SZ")
        run_dir = root / f"{timestamp}-{label}-{run_id}"
        run_dir.mkdir(mode=0o700)
        planned = list(resources)
        manifest = {
            "schema": SCHEMA,
            "created_utc": utc_now(),
            "run_id": run_id,
            "label": label,
            "workspace": str(WORKSPACE),
            "evidence_dir": str(run_dir),
            "image": IMAGE,
            "resources": [resource.as_dict() for resource in planned],
        }
        write_exclusive_json(run_dir / "controller.json", manifest)
        return cls(label, run_id, run_dir, planned, CommandRunner(run_dir))

    def event(self, event: str, **fields: Any) -> None:
        append_jsonl(
            self.run_dir / "events.jsonl",
            {"schema": SCHEMA, "utc": utc_now(), "event": event, **fields},
        )


def utc_now() -> str:
    return dt.datetime.now(dt.timezone.utc).isoformat().replace("+00:00", "Z")


def sha256_text(value: str) -> str:
    return hashlib.sha256(value.encode("utf-8")).hexdigest()


def timeout_output(value: str | bytes | None) -> str:
    if value is None:
        return ""
    if isinstance(value, bytes):
        return value.decode("utf-8", errors="replace")
    return value


def bounded_timeout_output(value: str) -> tuple[str, bool]:
    if len(value) <= TIMEOUT_CAPTURE_LIMIT:
        return value, False
    half = TIMEOUT_CAPTURE_LIMIT // 2
    marker = "\n[... timeout output truncated by controller ...]\n"
    return value[:half] + marker + value[-half:], True


def write_exclusive_json(path: Path, value: Any) -> None:
    with path.open("x", encoding="utf-8") as stream:
        json.dump(value, stream, indent=2, sort_keys=True)
        stream.write("\n")


def write_atomic_exclusive_json(path: Path, value: Any) -> None:
    """Publish a complete state marker atomically without overwriting evidence."""
    temporary = path.with_name(f"{path.name}.pending-{secrets.token_hex(8)}")
    try:
        with temporary.open("x", encoding="utf-8") as stream:
            json.dump(value, stream, indent=2, sort_keys=True)
            stream.write("\n")
            stream.flush()
            os.fsync(stream.fileno())
        os.link(temporary, path)
    finally:
        try:
            temporary.unlink()
        except FileNotFoundError:
            pass


def write_exclusive_text(path: Path, value: str) -> None:
    with path.open("x", encoding="utf-8") as stream:
        stream.write(value)


def append_jsonl(path: Path, value: Any) -> None:
    with path.open("a", encoding="utf-8") as stream:
        stream.write(json.dumps(value, sort_keys=True, separators=(",", ":")))
        stream.write("\n")


def existing_command_sequence(path: Path) -> int:
    maximum = 0
    if path.exists():
        with path.open(encoding="utf-8") as stream:
            for line in stream:
                try:
                    value = json.loads(line)
                except json.JSONDecodeError as error:
                    raise LabError("existing command receipt is malformed") from error
                sequence = value.get("sequence")
                if not isinstance(sequence, int) or sequence <= 0:
                    raise LabError("existing command receipt has an invalid sequence")
                maximum = max(maximum, sequence)
    for candidate in path.parent.glob("command-*.*"):
        match = re.fullmatch(r"command-([0-9]{4,})\.(?:stdout|stderr)", candidate.name)
        if match is not None:
            maximum = max(maximum, int(match.group(1)))
    return maximum


def validate_resource_name(name: str) -> None:
    if not RESOURCE_NAME.fullmatch(name):
        raise LabError(f"resource name is outside the fixed Aster lab namespace: {name}")


def network_specs(values: Iterable[tuple[str, str, str]]) -> list[NetworkSpec]:
    result = [NetworkSpec.from_tuple(value) for value in values]
    for index, left in enumerate(result):
        for right in result[index + 1 :]:
            if left.subnet.overlaps(right.subnet):
                raise LabError(f"fixed lab CIDRs overlap: {left.subnet} and {right.subnet}")
    return result


def labels(ctx: RunContext, role: str) -> list[str]:
    return [
        "--label",
        f"{MANAGED_LABEL}=true",
        "--label",
        f"{RUN_LABEL}={ctx.run_id}",
        "--label",
        f"{ROLE_LABEL}={role}",
    ]


def require_docker() -> str:
    executable = shutil.which("docker")
    if executable is None:
        raise LabError("docker executable is not available")
    return executable


def normalized_architecture(value: Any) -> str:
    if value in {"arm64", "aarch64"}:
        return "arm64"
    if isinstance(value, str):
        return value.lower()
    return ""


def verify_orbstack(ctx: RunContext) -> tuple[str, dict[str, Any]]:
    """Require the intended daemon and return its executable/capabilities."""
    docker = require_docker()
    context = ctx.runner.run([docker, "context", "show"]).stdout.strip()
    if context != "orbstack":
        raise LabError(f"refusing non-OrbStack Docker context: {context!r}")
    ctx.runner.run([docker, "version", "--format", "{{.Server.Version}}"])
    result = ctx.runner.run(
        [
            docker,
            "info",
            "--format",
            '{"architecture":{{json .Architecture}},"cgroup_version":{{json .CgroupVersion}},"cpus":{{json .NCPU}},"memory":{{json .MemTotal}},"warnings":{{json .Warnings}}}',
        ]
    )
    try:
        capabilities = json.loads(result.stdout)
    except json.JSONDecodeError as error:
        raise LabError("Docker returned malformed capability JSON") from error
    if not isinstance(capabilities, dict):
        raise LabError("Docker capability result is not an object")
    architecture = normalized_architecture(capabilities.get("architecture"))
    if architecture != "arm64":
        raise LabError(
            f"this evidence profile requires ARM64 OrbStack, found {capabilities.get('architecture')!r}"
        )
    ctx.daemon_architecture = architecture
    capability_path = ctx.run_dir / "docker-capabilities.json"
    if not capability_path.exists():
        write_exclusive_text(
            capability_path,
            json.dumps(capabilities, indent=2, sort_keys=True) + "\n",
        )
    return docker, capabilities


def docker_resource_present(ctx: RunContext, kind: str, name: str) -> bool:
    """Determine exact-name presence with a command whose failure is never absence."""
    docker = require_docker()
    if kind == "container":
        arguments = [docker, "container", "ls", "--all", "--format", "{{.Names}}"]
    elif kind == "network":
        arguments = [docker, "network", "ls", "--format", "{{.Name}}"]
    else:
        raise LabError(f"unsupported Docker resource kind: {kind}")
    result = ctx.runner.run(arguments)
    return name in {line.strip() for line in result.stdout.splitlines() if line.strip()}


def resolve_lab_image(ctx: RunContext) -> str:
    docker = require_docker()
    result = ctx.runner.run(
        [
            docker,
            "image",
            "inspect",
            IMAGE,
            "--format",
            '{"id":{{json .Id}},"repo_digests":{{json .RepoDigests}},"labels":{{json .Config.Labels}},"architecture":{{json .Architecture}}}',
        ]
    )
    try:
        record = json.loads(result.stdout)
    except json.JSONDecodeError as error:
        raise LabError("Docker returned malformed image identity JSON") from error
    if not isinstance(record, dict):
        raise LabError("Docker image identity is not an object")
    if ctx.daemon_architecture is None:
        raise LabError("image resolution requires a verified Docker daemon architecture")
    if normalized_architecture(record.get("architecture")) != ctx.daemon_architecture:
        raise LabError("lab image architecture differs from the verified Docker daemon")
    image_id = record.get("id")
    if not isinstance(image_id, str) or not re.fullmatch(r"sha256:[0-9a-f]{64}", image_id):
        raise LabError("Docker image has an invalid immutable identifier")
    labels_value = record.get("labels")
    if not isinstance(labels_value, dict):
        raise LabError("lab image has no provenance labels")
    expected_input = build_input_digest(collect_build_inputs())
    expected_labels = {
        MANAGED_LABEL: "true",
        IMAGE_SCHEMA_LABEL: IMAGE_SCHEMA,
        IMAGE_INPUT_LABEL: expected_input,
        IMAGE_BASE_LABEL: LAB_BASE_IMAGE,
    }
    for key, expected in expected_labels.items():
        if labels_value.get(key) != expected:
            raise LabError(f"lab image provenance label differs: {key}")
    build_run_id = labels_value.get(RUN_LABEL)
    if not isinstance(build_run_id, str) or not RUN_ID.fullmatch(build_run_id):
        raise LabError("lab image has no valid build run identifier")
    write_exclusive_text(
        ctx.run_dir / "image-identity.json",
        json.dumps(record, indent=2, sort_keys=True) + "\n",
    )
    ctx.image_id = image_id
    return image_id


def docker_preflight(
    ctx: RunContext,
    *,
    containers: Iterable[str],
    networks: Iterable[NetworkSpec],
    require_image: bool = True,
    require_cgroup_v2: bool = False,
) -> None:
    _, capabilities = verify_orbstack(ctx)
    if require_cgroup_v2 and str(capabilities.get("cgroup_version")) != "2":
        raise LabError("resource evidence requires Docker cgroup v2")
    if require_image:
        resolve_lab_image(ctx)
    for name in containers:
        validate_resource_name(name)
        if docker_resource_present(ctx, "container", name):
            raise LabError(f"container name collision: {name}")
    desired = list(networks)
    for spec in desired:
        if docker_resource_present(ctx, "network", spec.name):
            raise LabError(f"network name collision: {spec.name}")
    preflight_cidrs(ctx, desired)


def preflight_cidrs(ctx: RunContext, desired: Sequence[NetworkSpec]) -> None:
    """Compare desired CIDRs with custom Docker IPAM configurations only."""
    if not desired:
        return
    docker = require_docker()
    listing = ctx.runner.run(
        [docker, "network", "ls", "--quiet", "--filter", "type=custom"]
    )
    for network_id in listing.stdout.split():
        if not re.fullmatch(r"[0-9a-f]{12,64}", network_id):
            raise LabError("Docker returned a malformed custom-network identifier")
        configured = ctx.runner.run(
            [docker, "network", "inspect", network_id, "--format", "{{json .IPAM.Config}}"]
        )
        try:
            records = json.loads(configured.stdout)
        except json.JSONDecodeError as error:
            raise LabError("Docker returned malformed network IPAM JSON") from error
        for record in records or []:
            subnet_text = record.get("Subnet") if isinstance(record, dict) else None
            if not subnet_text:
                continue
            try:
                existing = ipaddress.ip_network(subnet_text)
            except ValueError as error:
                raise LabError(f"Docker returned an invalid network CIDR: {subnet_text}") from error
            for wanted in desired:
                if wanted.subnet.overlaps(existing):
                    raise LabError(
                        f"CIDR collision: {wanted.subnet} overlaps custom network {network_id[:12]} ({existing})"
                    )


def network_create_args(ctx: RunContext, spec: NetworkSpec, role: str) -> list[str]:
    return [
        require_docker(),
        "network",
        "create",
        "--driver",
        "bridge",
        "--internal",
        "--subnet",
        str(spec.subnet),
        "--gateway",
        str(spec.gateway),
        *labels(ctx, role),
        spec.name,
    ]


def confined_run_path(ctx: RunContext, path: Path) -> Path:
    root = ctx.run_dir.resolve()
    resolved = path.resolve()
    if resolved == root or root not in resolved.parents:
        raise LabError(f"container mount escapes its run directory: {resolved}")
    return resolved


def create_output_directory(ctx: RunContext, role: str) -> Path:
    if not re.fullmatch(r"[a-z0-9-]{1,32}", role):
        raise LabError(f"invalid output role: {role}")
    path = ctx.run_dir / "outputs" / role
    path.parent.mkdir(mode=0o700, exist_ok=True)
    path.mkdir(mode=0o700)
    return confined_run_path(ctx, path)


def mount_argument(ctx: RunContext, source: Path, destination: str, *, read_only: bool) -> str:
    resolved = confined_run_path(ctx, source)
    value = str(resolved)
    if "," in value:
        raise LabError("lab mount path cannot contain a comma for Docker --mount")
    if not destination.startswith("/") or "," in destination:
        raise LabError(f"invalid in-container mount destination: {destination}")
    suffix = ",readonly" if read_only else ""
    return f"type=bind,src={value},dst={destination}{suffix}"


def container_run_args(
    ctx: RunContext,
    *,
    name: str,
    role: str,
    command: Sequence[str],
    network: str = "none",
    ip: str | None = None,
    detach: bool = False,
    cpus: str = "1",
    memory: str = "1g",
    pids: int = 256,
    capabilities: Sequence[str] = (),
    root_user: bool = False,
    entrypoint: str | None = None,
    sysctls: Sequence[str] = (),
    output_dir: Path | None = None,
    read_only_mounts: Sequence[tuple[Path, str]] = (),
) -> list[str]:
    validate_resource_name(name)
    if not MEMORY_VALUE.fullmatch(memory):
        raise LabError(f"invalid memory limit: {memory}")
    if not CPU_VALUE.fullmatch(cpus) or float(cpus) <= 0:
        raise LabError(f"invalid CPU limit: {cpus}")
    args = [
        require_docker(),
        "run",
        "--pull=never",
        "--name",
        name,
        *labels(ctx, role),
    ]
    if detach:
        args.append("--detach")
    args.extend(
        [
            "--init",
            "--read-only",
            "--cap-drop=ALL",
            "--security-opt=no-new-privileges",
            "--cgroupns=private",
            "--cpus",
            cpus,
            "--memory",
            memory,
            "--memory-swap",
            memory,
            "--pids-limit",
            str(pids),
            "--ulimit",
            "nofile=65536:65536",
            "--tmpfs",
            "/tmp:rw,nosuid,nodev,noexec,size=32m",
            "--tmpfs",
            "/run:rw,nosuid,nodev,noexec,size=8m",
            "--network",
            network,
        ]
    )
    if output_dir is not None:
        if output_dir.is_symlink() or not output_dir.is_dir():
            raise LabError(f"output mount source is not a real directory: {output_dir}")
        args.extend(
            ["--mount", mount_argument(ctx, output_dir, "/output", read_only=False)]
        )
    for source, destination in read_only_mounts:
        if source.is_symlink() or not source.is_file():
            raise LabError(f"read-only mount source is not a regular file: {source}")
        if destination == "/output" or destination.startswith("/output/"):
            raise LabError("read-only secret mounts cannot overlap /output")
        args.extend(
            ["--mount", mount_argument(ctx, source, destination, read_only=True)]
        )
    if ip is not None:
        ipaddress.ip_address(ip)
        args.extend(["--ip", ip])
    for capability in capabilities:
        if capability not in {"NET_ADMIN", "NET_RAW", "SETGID", "SETUID"}:
            raise LabError(f"unsupported lab capability: {capability}")
        args.extend(["--cap-add", capability])
    for sysctl in sysctls:
        if not sysctl.startswith("net.ipv4."):
            raise LabError(f"unsupported lab sysctl: {sysctl}")
        args.extend(["--sysctl", sysctl])
    if not root_user:
        args.extend(["--user", f"{os.getuid()}:{os.getgid()}"])
    if entrypoint is not None:
        if not entrypoint.startswith("/"):
            raise LabError("entrypoint must be an absolute in-image path")
        args.extend(["--entrypoint", entrypoint])
    if ctx.image_id is None or not re.fullmatch(r"sha256:[0-9a-f]{64}", ctx.image_id):
        raise LabError("container execution requires a preflight-resolved immutable image ID")
    args.append(ctx.image_id)
    args.extend(str(value) for value in command)
    return args


def fault_args(args: argparse.Namespace) -> list[str]:
    return [
        "--seed",
        str(args.seed),
        "--mtu",
        str(args.mtu),
        "--bps",
        str(args.bps),
        "--loss-per-mille",
        str(args.loss_per_mille),
        "--reorder-ticks",
        str(args.reorder_ticks),
        "--tick-ms",
        str(args.tick_ms),
    ]


def plan_output(label: str, resources: Iterable[PlannedResource], commands: Any) -> None:
    print(
        json.dumps(
            {
                "schema": SCHEMA,
                "dry_run": True,
                "preview_kind": "structural",
                "label": label,
                "image": IMAGE,
                "resources": [resource.as_dict() for resource in resources],
                "commands": commands,
                "note": (
                    "Structural preview only: generated run IDs, immutable image IDs, mounts, "
                    "ownership labels, and preflight-expanded commands exist only under --execute. "
                    "No Docker or filesystem mutation was performed."
                ),
            },
            indent=2,
            sort_keys=True,
        )
    )


def scenario_metrics(
    ctx: RunContext,
    relative: str,
    expected: dict[str, Any] | None = None,
) -> dict[str, Any]:
    path = ctx.run_dir / relative / "metrics.json"
    if not path.is_file():
        raise LabError(f"scenario emitted no metrics: {path}")
    with path.open(encoding="utf-8") as stream:
        metrics = json.load(stream)
    if metrics.get("schema") != "aster-lab-metrics/v1":
        raise LabError("scenario metrics schema mismatch")
    if metrics.get("converged") is not True:
        raise LabError("scenario did not report convergence")
    if expected is not None:
        for key, value in expected.items():
            observed = metrics.get(key)
            if type(observed) is not type(value) or observed != value:
                raise LabError(
                    f"scenario metrics differ for {key}: expected {value!r}, "
                    f"found {observed!r}"
                )
    return metrics


def write_scenario_request(ctx: RunContext, **values: Any) -> None:
    write_exclusive_json(
        ctx.run_dir / "scenario-request.json",
        {"schema": SCHEMA, "operation": ctx.label, **values},
    )


def read_key_value_record(path: Path, prefix: str) -> dict[str, str]:
    if not path.is_file() or path.stat().st_size > 16_384:
        raise LabError(f"missing or oversized evidence record: {path}")
    lines = path.read_text(encoding="utf-8").splitlines()
    if len(lines) != 1:
        raise LabError(f"evidence record must contain exactly one line: {path}")
    fields = lines[0].split("\t")
    if not fields or fields[0] != prefix:
        raise LabError(f"evidence record header mismatch: {path}")
    values: dict[str, str] = {}
    for field in fields[1:]:
        if "=" not in field:
            raise LabError(f"malformed evidence record field: {path}")
        key, value = field.split("=", 1)
        if not key or key in values:
            raise LabError(f"duplicate or empty evidence record field: {path}")
        values[key] = value
    return values


def verify_live_node_metrics(
    ctx: RunContext,
    relative: str,
    *,
    own_identity: str,
    peer_identity: str,
    peer_endpoint: str,
    seed: int,
    items: int,
) -> None:
    expected_total = items * 2
    scenario_metrics(
        ctx,
        relative,
        {
            "scenario": "node-udp",
            "seed": seed,
            "shards": 1,
            "nodes": 1,
            "published_items": items,
            "delivered_items": expected_total,
        },
    )
    live = read_key_value_record(
        ctx.run_dir / relative / "live-metrics.txt", "ASTER_LAB_LIVE_METRICS"
    )
    expected = {
        "version": "1",
        "node": own_identity,
        "peer": peer_identity,
        "carrier": "fixed-udp",
        "local_endpoint": "0.0.0.0:44000",
        "resolved_peer_endpoint": peer_endpoint,
        "durable_reopen": "false",
        "published_this_run": str(items),
        "reused_publications": "0",
        "observed_items": str(expected_total),
        "authenticated": "true",
        "converged": "true",
    }
    for key, value in expected.items():
        if live.get(key) != value:
            raise LabError(
                f"live metrics differ for {relative} {key}: expected {value!r}, "
                f"found {live.get(key)!r}"
            )
    try:
        authenticated_pumps = int(live.get("authenticated_pumps", ""))
    except ValueError as error:
        raise LabError("live metrics authenticated_pumps is not numeric") from error
    if authenticated_pumps <= 0:
        raise LabError("live node reported no authenticated pump")


def exact_resources(label: str, names: Iterable[tuple[str, str]]) -> list[PlannedResource]:
    result = []
    for kind, role in names:
        name = FIXED_CONTAINER_NAMES[role] if kind == "container" else role
        validate_resource_name(name)
        result.append(PlannedResource(kind, name, role))
    return result


def collect_build_inputs() -> list[BuildInput]:
    """Read the complete, deny-all build context into an immutable in-memory set."""
    root_ignore = WORKSPACE / ".dockerignore"
    dockerfile_ignore = WORKSPACE / "lab" / "Dockerfile.dockerignore"
    for path in [root_ignore, dockerfile_ignore]:
        try:
            value = path.read_text(encoding="utf-8")
        except OSError as error:
            raise LabError(f"required deny-all Docker ignore file is unavailable: {path}") from error
        if value != EXPECTED_DOCKERIGNORE:
            raise LabError(f"deny-all Docker ignore policy differs from the reviewed form: {path}")
    dockerfile_text = (WORKSPACE / "lab" / "Dockerfile").read_text(encoding="utf-8")
    expected_base_line = f"ARG LAB_BASE_IMAGE={LAB_BASE_IMAGE}\n"
    if not dockerfile_text.startswith(expected_base_line):
        raise LabError("Dockerfile pinned base differs from the controller allowlist")
    from_sources = [
        line.split()[1]
        for line in dockerfile_text.splitlines()
        if line.strip().upper().startswith("FROM ") and len(line.split()) >= 2
    ]
    if not from_sources or any(source != "${LAB_BASE_IMAGE}" for source in from_sources):
        raise LabError("Dockerfile contains a base outside the single pinned build argument")
    prohibited = {".git", ".agents", ".codex"}
    admitted_files = [
        root_ignore,
        WORKSPACE / "Cargo.toml",
        WORKSPACE / "Cargo.lock",
        WORKSPACE / "LICENSE",
        WORKSPACE / "THIRD_PARTY_NOTICES.md",
        WORKSPACE / "lab" / "Dockerfile",
        dockerfile_ignore,
        WORKSPACE / "lab" / "debian.sources",
    ]
    crates = WORKSPACE / "crates"
    if not crates.is_dir() or crates.is_symlink():
        raise LabError("crates build input is missing or is a symbolic link")
    for directory, names, files in os.walk(crates, followlinks=False):
        names.sort()
        files.sort()
        directory_path = Path(directory)
        if directory_path.is_symlink() or any(part in prohibited for part in directory_path.parts):
            raise LabError(f"prohibited or symbolic build input directory: {directory_path}")
        for name in [*names, *files]:
            path = directory_path / name
            if name in prohibited or path.is_symlink():
                raise LabError(f"prohibited or symbolic build input: {path}")
        admitted_files.extend(directory_path / name for name in files)
    inputs = []
    seen = set()
    for path in sorted(admitted_files):
        if not path.is_file() or path.is_symlink():
            raise LabError(f"admitted build input is not a regular file: {path}")
        relative = str(path.relative_to(WORKSPACE))
        if relative in seen:
            raise LabError(f"duplicate admitted build path: {relative}")
        seen.add(relative)
        content = path.read_bytes()
        inputs.append(BuildInput(relative, content, hashlib.sha256(content).hexdigest()))
    return inputs


def build_input_digest(inputs: Sequence[BuildInput]) -> str:
    receipt = {
        "dockerignore_sha256": sha256_text(EXPECTED_DOCKERIGNORE),
        "files": [item.receipt() for item in inputs],
    }
    encoded = json.dumps(receipt, sort_keys=True, separators=(",", ":"))
    return sha256_text(encoded)


def canonical_runtime_package_inventory(value: str) -> str:
    """Validate and canonicalize the exact admitted runtime utility versions."""
    expected = {"iproute2", "iputils-ping", "nftables", "procps", "tcpdump"}
    versions: dict[str, str] = {}
    for line in value.splitlines():
        fields = line.split("\t")
        if len(fields) != 2 or not fields[0] or not fields[1]:
            raise LabError("runtime package inventory contains a malformed row")
        name, version = fields
        if name not in expected:
            raise LabError(f"runtime package inventory contains an unadmitted package: {name}")
        if name in versions:
            raise LabError(f"runtime package inventory repeats package: {name}")
        if any(character.isspace() for character in version):
            raise LabError(f"runtime package inventory contains malformed version: {name}")
        versions[name] = version
    missing = expected.difference(versions)
    if missing:
        raise LabError(
            "runtime package inventory is missing admitted packages: "
            + ", ".join(sorted(missing))
        )
    return "".join(f"{name}\t{versions[name]}\n" for name in sorted(versions))


def seal_build_context(ctx: RunContext, inputs: Sequence[BuildInput]) -> Path:
    destination = ctx.run_dir / "build-context"
    destination.mkdir(mode=0o700)
    for item in inputs:
        target = destination / item.relative_path
        confined_run_path(ctx, target)
        target.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
        with target.open("xb") as stream:
            stream.write(item.content)
        if hashlib.sha256(target.read_bytes()).hexdigest() != item.sha256:
            raise LabError(f"sealed build input verification failed: {item.relative_path}")
    return destination


def verify_build_boundary(ctx: RunContext) -> tuple[Path, str]:
    """Seal exactly the bytes described by the build-input receipt."""
    inputs = collect_build_inputs()
    digest = build_input_digest(inputs)
    write_exclusive_json(
        ctx.run_dir / "build-inputs.json",
        {
            "schema": SCHEMA,
            "dockerignore_sha256": sha256_text(EXPECTED_DOCKERIGNORE),
            "aggregate_sha256": digest,
            "files": [item.receipt() for item in inputs],
        },
    )
    sealed = seal_build_context(ctx, inputs)
    ctx.event("build-boundary-verified", files=len(inputs), aggregate_sha256=digest)
    return sealed, digest


def run_build(args: argparse.Namespace) -> None:
    resources: list[PlannedResource] = []
    network_mode = "default" if args.allow_build_network else "none"
    cache_options = ["--no-cache"] if args.allow_build_network else []
    command_preview = [
        "docker",
        "build",
        "--pull=false",
        f"--network={network_mode}",
        *cache_options,
        "--load",
        "--file",
        str(DOCKERFILE),
        "--tag",
        IMAGE,
        str(WORKSPACE),
    ]
    if not args.execute:
        plan_output("build", resources, [command_preview])
        return
    ctx = RunContext.create(args.evidence_root, "build", resources)
    sealed_context, input_digest = verify_build_boundary(ctx)
    docker, _ = verify_orbstack(ctx)
    images = ctx.runner.run(
        [docker, "image", "ls", "--no-trunc", "--format", "{{.Repository}}:{{.Tag}}"]
    )
    if IMAGE in {line.strip() for line in images.stdout.splitlines()} and not args.replace_image:
        raise LabError(f"image tag {IMAGE} already exists; pass --replace-image intentionally")
    base = ctx.runner.run(
        [
            docker,
            "image",
            "inspect",
            LAB_BASE_IMAGE,
            "--format",
            '{"id":{{json .Id}},"digests":{{json .RepoDigests}}}',
        ],
        check=False,
    )
    if base.returncode != 0:
        raise LabError(
            "pinned base image is not local; refusing a build that could fetch it: "
            + LAB_BASE_IMAGE
        )
    write_exclusive_text(ctx.run_dir / "base-image-identity.json", base.stdout)
    command = [
        docker,
        "build",
        "--pull=false",
        f"--network={network_mode}",
        *cache_options,
        "--load",
        "--progress=plain",
        "--file",
        str(sealed_context / "lab" / "Dockerfile"),
        "--tag",
        IMAGE,
        "--label",
        f"{MANAGED_LABEL}=true",
        "--label",
        f"{RUN_LABEL}={ctx.run_id}",
        "--label",
        f"{IMAGE_SCHEMA_LABEL}={IMAGE_SCHEMA}",
        "--label",
        f"{IMAGE_INPUT_LABEL}={input_digest}",
        "--label",
        f"{IMAGE_BASE_LABEL}={LAB_BASE_IMAGE}",
        "--build-arg",
        f"LAB_BASE_IMAGE={LAB_BASE_IMAGE}",
        "--iidfile",
        str(ctx.run_dir / "image-id.txt"),
        "--metadata-file",
        str(ctx.run_dir / "build-metadata.json"),
        str(sealed_context),
    ]
    ctx.runner.run(command, timeout=args.timeout)
    image_id = resolve_lab_image(ctx)
    iid_path = ctx.run_dir / "image-id.txt"
    if not iid_path.is_file() or iid_path.read_text(encoding="utf-8").strip() != image_id:
        raise LabError("Docker iidfile does not match the inspected immutable image ID")
    inventory = ctx.runner.run(
        [
            docker,
            "run",
            "--rm",
            "--network",
            "none",
            "--read-only",
            "--cap-drop",
            "ALL",
            "--security-opt",
            "no-new-privileges",
            "--label",
            f"{MANAGED_LABEL}=true",
            "--label",
            f"{RUN_LABEL}={ctx.run_id}",
            "--entrypoint",
            "/bin/cat",
            image_id,
            "/usr/share/aster-lab/runtime-package-inventory.tsv",
        ]
    )
    canonical_inventory = canonical_runtime_package_inventory(inventory.stdout)
    write_exclusive_text(
        ctx.run_dir / "runtime-package-inventory.tsv", canonical_inventory
    )
    ctx.event(
        "runtime-package-inventory-captured",
        sha256=sha256_text(canonical_inventory),
        packages=5,
    )
    ctx.event("build-complete", image=IMAGE, image_id=image_id, network=network_mode)
    print(ctx.run_dir)


def run_self_contained(args: argparse.Namespace) -> None:
    role = "transfer" if args.scenario == "transfer" else "blob"
    if args.scenario == "blob-recovery" and args.restart_after_frames == 0:
        raise LabError("Blob recovery requires a positive restart checkpoint")
    name = FIXED_CONTAINER_NAMES[role]
    resources = [PlannedResource("container", name, role)]
    command = [args.scenario, "--root", "/output/run", *fault_args(args)]
    if args.scenario == "transfer":
        command.extend(
            [
                "--items",
                str(args.items),
                "--payload-bytes",
                str(args.payload_bytes),
                "--restart-after-frames",
                str(args.restart_after_frames),
                "--max-pumps",
                str(args.max_pumps),
            ]
        )
    else:
        command.extend(
            [
                "--blob-bytes",
                str(args.blob_bytes),
                "--chunk-bytes",
                str(args.chunk_bytes),
                "--restart-after-frames",
                str(args.restart_after_frames),
                "--max-pumps",
                str(args.max_pumps),
            ]
        )
    if not args.execute:
        plan_output(
            role,
            resources,
            [
                {
                    "docker_run": command,
                    "security": "--pull=never, network=none, read-only, cap-drop=ALL",
                }
            ],
        )
        return
    ctx = RunContext.create(args.evidence_root, role, resources)
    docker_preflight(ctx, containers=[name], networks=[])
    write_scenario_request(
        ctx,
        scenario=args.scenario,
        seed=args.seed,
        items=args.items if args.scenario == "transfer" else None,
        payload_bytes=args.payload_bytes if args.scenario == "transfer" else None,
        blob_bytes=args.blob_bytes if args.scenario == "blob-recovery" else None,
        chunk_bytes=args.chunk_bytes if args.scenario == "blob-recovery" else None,
        restart_after_frames=args.restart_after_frames,
        max_pumps=args.max_pumps,
        mtu=args.mtu,
        bits_per_second=args.bps,
        loss_per_mille=args.loss_per_mille,
        reorder_ticks=args.reorder_ticks,
        tick_ms=args.tick_ms,
    )
    verified = False
    try:
        output_dir = create_output_directory(ctx, role)
        completed = ctx.runner.run(
            container_run_args(
                ctx,
                name=name,
                role=role,
                command=command,
                cpus=args.cpus,
                memory=args.memory,
                pids=512,
                output_dir=output_dir,
            ),
            check=False,
            timeout=args.timeout,
        )
        ctx.event("container-run-complete", name=name, returncode=completed.returncode)
        if completed.returncode != 0:
            raise LabError(f"{args.scenario} container failed with {completed.returncode}")
        verify_container_configuration(
            ctx,
            name,
            output_dir=output_dir,
            memory=args.memory,
            cpus=args.cpus,
            pids=512,
            network="none",
        )
        expected = {
            "scenario": args.scenario,
            "seed": args.seed,
            "shards": 1,
            "nodes": 2 if args.scenario == "transfer" else 3,
            "published_items": args.items if args.scenario == "transfer" else 1,
            "delivered_items": args.items if args.scenario == "transfer" else 2,
            "blob_bytes": 0 if args.scenario == "transfer" else args.blob_bytes,
            "configured_bits_per_second": args.bps,
            "configured_loss_per_mille": args.loss_per_mille,
            "loss_window_frames": 1_000,
        }
        if args.scenario == "blob-recovery":
            expected["partial_restart_observed"] = True
            expected["durable_progress_preserved"] = True
        metrics = scenario_metrics(ctx, f"outputs/{role}/run", expected)
        if args.scenario == "blob-recovery":
            partial_bytes = metrics.get("partial_durable_blob_bytes")
            reopened_bytes = metrics.get("reopened_durable_blob_bytes")
            if (
                type(partial_bytes) is not int
                or type(reopened_bytes) is not int
                or partial_bytes <= 0
                or reopened_bytes < partial_bytes
            ):
                raise LabError(
                    "Blob recovery did not preserve measured durable partial bytes across reopen"
                )
        ctx.event("scenario-verified", scenario=args.scenario)
        verified = True
    finally:
        cleanup_context(ctx, tolerate_errors=not verified)
    print(ctx.run_dir)


def create_network(ctx: RunContext, spec: NetworkSpec, role: str) -> None:
    ctx.runner.run(network_create_args(ctx, spec, role))
    ctx.event("resource-created", kind="network", name=spec.name, role=role)


def parse_provision_manifest(path: Path, expected: int) -> list[dict[str, str]]:
    if not path.is_file():
        raise LabError("provisioning manifest is missing")
    lines = path.read_text(encoding="utf-8").splitlines()
    if not lines or not lines[0].startswith("ASTER_LAB_NODE_MANIFEST\t"):
        raise LabError("provisioning manifest header mismatch")
    header = {}
    for field in lines[0].split("\t")[1:]:
        if "=" not in field:
            raise LabError("malformed provisioning manifest header")
        key, value = field.split("=", 1)
        if key in header:
            raise LabError("duplicate provisioning manifest header field")
        header[key] = value
    if (
        header.get("version") != "1"
        or header.get("topic") != "lab.live-ip"
        or header.get("scope") != "lab/live-ip"
        or header.get("nodes") != str(expected)
    ):
        raise LabError("provisioning manifest parameters mismatch")
    if len(lines) < 2 or lines[1] != "index\tserial\tnode_id":
        raise LabError("provisioning manifest column header mismatch")
    records = []
    for expected_index, line in enumerate(lines[2:]):
        fields = line.split("\t")
        if (
            len(fields) != 3
            or fields[0] != str(expected_index)
            or not fields[1].isdigit()
            or int(fields[1]) <= 0
            or not re.fullmatch(r"[0-9a-f]{64}", fields[2])
        ):
            raise LabError("malformed provisioning manifest record")
        records.append(
            {"index": fields[0], "serial": fields[1], "identity": fields[2]}
        )
    if len(records) != expected:
        raise LabError(f"expected {expected} provisioned nodes, found {len(records)}")
    return records


def wait_for_containers(ctx: RunContext, names: Sequence[str], timeout: float) -> None:
    deadline = time.monotonic() + timeout
    pending = set(names)
    while pending:
        if time.monotonic() >= deadline:
            raise LabError(f"container timeout: {', '.join(sorted(pending))}")
        for name in list(pending):
            state = ctx.runner.run(
                [require_docker(), "container", "inspect", name, "--format", "{{json .State}}"]
            )
            try:
                decoded = json.loads(state.stdout)
            except json.JSONDecodeError as error:
                raise LabError("Docker returned malformed container state") from error
            if not decoded.get("Running", False):
                pending.remove(name)
        if pending:
            time.sleep(1.0)


def verify_container_exit(ctx: RunContext, name: str) -> None:
    state = ctx.runner.run(
        [require_docker(), "container", "inspect", name, "--format", "{{json .State}}"]
    )
    decoded = json.loads(state.stdout)
    if decoded.get("ExitCode") != 0:
        logs = ctx.runner.run([require_docker(), "container", "logs", name], check=False)
        raise LabError(
            f"container {name} exited {decoded.get('ExitCode')}: "
            f"{(logs.stderr or logs.stdout).strip()}"
        )
    logs = ctx.runner.run([require_docker(), "container", "logs", name])
    write_exclusive_text(ctx.run_dir / f"{name}.log", logs.stdout + logs.stderr)


def run_two_node(args: argparse.Namespace) -> None:
    spec = NetworkSpec.from_tuple(DIRECT_SPEC)
    names = [
        FIXED_CONTAINER_NAMES["provision"],
        FIXED_CONTAINER_NAMES["node-a"],
        FIXED_CONTAINER_NAMES["node-b"],
    ]
    resources = [
        PlannedResource("network", spec.name, "direct"),
        PlannedResource("container", names[0], "provision"),
        PlannedResource("container", names[1], "node-a"),
        PlannedResource("container", names[2], "node-b"),
    ]
    if not args.execute:
        plan_output(
            "two-node",
            resources,
            [
                "create one internal bridge at 10.250.10.0/24",
                "provision two identities in an offline container",
                "run two unprivileged node-udp containers at .10 and .11",
                "require both metrics records to report authenticated convergence",
            ],
        )
        return
    ctx = RunContext.create(args.evidence_root, "two-node", resources)
    docker_preflight(ctx, containers=names, networks=[spec])
    write_scenario_request(
        ctx,
        scenario="two-node-live-udp",
        workload_seed=args.seed,
        items_per_node=args.items,
        expected_items_per_node=args.items * 2,
        payload_bytes=args.payload_bytes,
        duration_ms=args.duration_ms,
        max_pumps=args.max_pumps,
        responder_settle_ms=args.responder_settle_ms,
    )
    verified = False
    try:
        create_network(ctx, spec, "direct")
        provision_output = create_output_directory(ctx, "provision")
        provision = container_run_args(
            ctx,
            name=names[0],
            role="provision",
            command=[
                "provision",
                "--root",
                "/output",
                "--nodes",
                "2",
                "--scope",
                "lab/live-ip",
                "--topic",
                "lab.live-ip",
            ],
            memory="1g",
            output_dir=provision_output,
        )
        ctx.runner.run(provision, timeout=120)
        verify_container_configuration(
            ctx,
            names[0],
            output_dir=provision_output,
            memory="1g",
            cpus="1",
            pids=256,
            network="none",
        )
        records = parse_provision_manifest(provision_output / "manifest.tsv", 2)
        if records[0]["identity"] == records[1]["identity"]:
            raise LabError("provisioner emitted duplicate node identities")
        scenario_metrics(
            ctx,
            "outputs/provision",
            {"scenario": "provision", "shards": 1, "nodes": 2},
        )
        bundle_a = provision_output / "private" / "node-0000.bundle"
        bundle_b = provision_output / "private" / "node-0001.bundle"
        private_dir = provision_output / "private"
        if private_dir.is_symlink() or not private_dir.is_dir():
            raise LabError("provisioning private directory is missing or symbolic")
        if private_dir.stat().st_mode & 0o777 != 0o700:
            raise LabError("provisioning private directory mode is not 0700")
        for bundle in [bundle_a, bundle_b]:
            if bundle.is_symlink() or not bundle.is_file():
                raise LabError(f"provisioning bundle is missing or symbolic: {bundle}")
            if bundle.resolve().parent != private_dir.resolve():
                raise LabError(f"provisioning bundle escapes its private directory: {bundle}")
            if bundle.stat().st_mode & 0o777 != 0o600:
                raise LabError(f"provisioning bundle mode is not 0600: {bundle}")
        node_a_output = create_output_directory(ctx, "node-a")
        node_b_output = create_output_directory(ctx, "node-b")
        common = [
            "--seed",
            str(args.seed),
            "--duration-ms",
            str(args.duration_ms),
            "--max-pumps",
            str(args.max_pumps),
            "--payload-bytes",
            str(args.payload_bytes),
            "--expect-items",
            str(args.items * 2),
        ]
        node_a = container_run_args(
            ctx,
            name=names[1],
            role="node-a",
            detach=True,
            network=spec.name,
            ip="10.250.10.10",
            memory=args.memory,
            cpus=args.cpus,
            command=[
                "node-udp",
                "--root",
                "/output",
                "--bundle",
                "/run/secrets/node.bundle",
                "--bind",
                "0.0.0.0:44000",
                "--peer-id",
                records[1]["identity"],
                "--peer-address",
                "10.250.10.11:44000",
                "--publish-items",
                str(args.items),
                *common,
            ],
            output_dir=node_a_output,
            read_only_mounts=[(bundle_a, "/run/secrets/node.bundle")],
        )
        node_b = container_run_args(
            ctx,
            name=names[2],
            role="node-b",
            detach=True,
            network=spec.name,
            ip="10.250.10.11",
            memory=args.memory,
            cpus=args.cpus,
            command=[
                "node-udp",
                "--root",
                "/output",
                "--bundle",
                "/run/secrets/node.bundle",
                "--bind",
                "0.0.0.0:44000",
                "--peer-id",
                records[0]["identity"],
                "--peer-address",
                "10.250.10.10:44000",
                "--publish-items",
                str(args.items),
                *common,
            ],
            output_dir=node_b_output,
            read_only_mounts=[(bundle_b, "/run/secrets/node.bundle")],
        )
        commands = [(records[0]["identity"], node_a), (records[1]["identity"], node_b)]
        # MeshService assigns the lexicographically higher NodeID the responder
        # role; start it first so it is listening when the initiator emits flight 1.
        commands.sort(key=lambda value: value[0], reverse=True)
        ctx.runner.run(commands[0][1])
        time.sleep(args.responder_settle_ms / 1000)
        ctx.event("responder-settled", milliseconds=args.responder_settle_ms)
        ctx.runner.run(commands[1][1])
        verify_container_configuration(
            ctx,
            names[1],
            output_dir=node_a_output,
            memory=args.memory,
            cpus=args.cpus,
            pids=256,
            network=spec.name,
            read_only_mounts=[(bundle_a, "/run/secrets/node.bundle")],
        )
        verify_container_configuration(
            ctx,
            names[2],
            output_dir=node_b_output,
            memory=args.memory,
            cpus=args.cpus,
            pids=256,
            network=spec.name,
            read_only_mounts=[(bundle_b, "/run/secrets/node.bundle")],
        )
        wait_for_containers(ctx, names[1:], args.duration_ms / 1000 + 30)
        for name in names[1:]:
            verify_container_exit(ctx, name)
        verify_live_node_metrics(
            ctx,
            "outputs/node-a",
            own_identity=records[0]["identity"],
            peer_identity=records[1]["identity"],
            peer_endpoint="10.250.10.11:44000",
            seed=args.seed,
            items=args.items,
        )
        verify_live_node_metrics(
            ctx,
            "outputs/node-b",
            own_identity=records[1]["identity"],
            peer_identity=records[0]["identity"],
            peer_endpoint="10.250.10.10:44000",
            seed=args.seed,
            items=args.items,
        )
        ctx.event("scenario-verified", scenario="two-node-live-udp")
        verified = True
    finally:
        cleanup_context(ctx, tolerate_errors=not verified)
    print(ctx.run_dir)


CGROUP_FILES = [
    "/sys/fs/cgroup/memory.current",
    "/sys/fs/cgroup/memory.max",
    "/sys/fs/cgroup/memory.peak",
    "/sys/fs/cgroup/memory.events",
    "/sys/fs/cgroup/memory.stat",
    "/sys/fs/cgroup/memory.swap.current",
    "/sys/fs/cgroup/memory.swap.max",
    "/sys/fs/cgroup/cpu.stat",
    "/sys/fs/cgroup/io.stat",
    "/sys/fs/cgroup/pids.current",
    "/sys/fs/cgroup/pids.events",
]

# Pressure Stall Information is a Linux kernel/configuration capability, not a
# cgroups-v2 invariant. OrbStack may expose the cpu controller and cpu.stat
# without exposing cpu.pressure inside a private container cgroup. Preserve an
# explicit availability marker and the failed read receipt, but do not discard
# the mandatory memory-limit/OOM/CPU/accounting evidence when PSI is absent.
OPTIONAL_CGROUP_FILES = ["/sys/fs/cgroup/cpu.pressure"]


def parse_nonnegative_integer(value: Any, label: str) -> int:
    if not isinstance(value, str) or not re.fullmatch(r"[0-9]+", value.strip()):
        raise LabError(f"resource sample {label} is not a nonnegative integer")
    return int(value.strip())


def parse_counter_file(value: Any, label: str) -> dict[str, int]:
    if not isinstance(value, str) or not value.strip():
        raise LabError(f"resource sample {label} is empty")
    counters: dict[str, int] = {}
    for line in value.splitlines():
        fields = line.split()
        if len(fields) != 2 or fields[0] in counters or not fields[1].isdigit():
            raise LabError(f"resource sample {label} is malformed")
        counters[fields[0]] = int(fields[1])
    return counters


def parse_io_stat(value: Any) -> list[dict[str, int | str]]:
    if not isinstance(value, str) or not value.strip():
        raise LabError("resource sample io.stat is empty")
    records: list[dict[str, int | str]] = []
    for line in value.splitlines():
        fields = line.split()
        if not fields or not re.fullmatch(r"[0-9]+:[0-9]+", fields[0]):
            raise LabError("resource sample io.stat has a malformed device")
        record: dict[str, int | str] = {"device": fields[0]}
        for field in fields[1:]:
            if "=" not in field:
                raise LabError("resource sample io.stat has a malformed counter")
            key, counter = field.split("=", 1)
            if not key or key in record or not counter.isdigit():
                raise LabError("resource sample io.stat has a malformed counter")
            record[key] = int(counter)
        if len(record) == 1:
            raise LabError("resource sample io.stat has no counters")
        records.append(record)
    return records


def validate_resource_sample(
    sample: dict[str, Any], expected_memory_bytes: int, *, require_process: bool = True
) -> None:
    for key in ["memory.current", "memory.peak", "pids.current"]:
        parse_nonnegative_integer(sample.get(key), key)
    if parse_nonnegative_integer(sample.get("memory.max"), "memory.max") != expected_memory_bytes:
        raise LabError("cgroup memory.max differs from the requested Docker limit")
    parse_nonnegative_integer(sample.get("memory.swap.current"), "memory.swap.current")
    if parse_nonnegative_integer(sample.get("memory.swap.max"), "memory.swap.max") != 0:
        raise LabError("resource cgroup unexpectedly permits swap")
    memory_events = parse_counter_file(sample.get("memory.events"), "memory.events")
    for key in ["oom", "oom_kill"]:
        if key not in memory_events:
            raise LabError(f"memory.events is missing {key}")
        if memory_events[key] != 0:
            raise LabError(f"resource cgroup reports {key}={memory_events[key]}")
    parse_counter_file(sample.get("memory.stat"), "memory.stat")
    parse_counter_file(sample.get("cpu.stat"), "cpu.stat")
    parse_counter_file(sample.get("pids.events"), "pids.events")
    pressure_available = sample.get("cpu.pressure_available")
    if not isinstance(pressure_available, bool):
        raise LabError("cpu.pressure availability marker is missing")
    pressure = sample.get("cpu.pressure")
    if pressure_available:
        if not isinstance(pressure, str) or "some " not in pressure or "total=" not in pressure:
            raise LabError("available cpu.pressure has malformed pressure counters")
    elif pressure is not None:
        raise LabError("unavailable cpu.pressure unexpectedly contains counters")
    parse_io_stat(sample.get("io.stat"))
    if require_process:
        for key in ["smaps_rollup", "status"]:
            value = sample.get(key)
            if not isinstance(value, str) or not value.strip():
                raise LabError(f"process {key} evidence is missing")
    stats = sample.get("docker_stats")
    if not isinstance(stats, dict) or not stats:
        raise LabError("Docker stats evidence is missing or malformed")


def docker_memory_bytes(value: str) -> int:
    match = re.fullmatch(r"([1-9][0-9]*)([kmgt]?)(?:b)?", value.lower())
    if match is None:
        raise LabError(f"cannot convert Docker memory value: {value}")
    powers = {"": 0, "k": 1, "m": 2, "g": 3, "t": 4}
    return int(match.group(1)) * (1024 ** powers[match.group(2)])


def verify_container_configuration(
    ctx: RunContext,
    name: str,
    *,
    output_dir: Path,
    memory: str,
    cpus: str,
    pids: int,
    network: str,
    capabilities: Sequence[str] = (),
    read_only_mounts: Sequence[tuple[Path, str]] = (),
    root_user: bool = False,
    sysctls: dict[str, str] | None = None,
    entrypoint: str = "/usr/local/bin/aster-lab",
) -> None:
    result = ctx.runner.run(
        [require_docker(), "container", "inspect", name, "--format", "{{json .}}"]
    )
    try:
        value = json.loads(result.stdout)
    except json.JSONDecodeError as error:
        raise LabError("Docker returned malformed container configuration JSON") from error
    if not isinstance(value, dict):
        raise LabError("Docker container configuration is not an object")
    host = value.get("HostConfig")
    config = value.get("Config")
    mounts = value.get("Mounts")
    if not isinstance(host, dict) or not isinstance(config, dict) or not isinstance(mounts, list):
        raise LabError("Docker container configuration is incomplete")
    expected_user = "" if root_user else f"{os.getuid()}:{os.getgid()}"
    checks = {
        "immutable image": (value.get("Image"), ctx.image_id),
        "read-only root": (host.get("ReadonlyRootfs"), True),
        "memory": (host.get("Memory"), docker_memory_bytes(memory)),
        "memory swap": (host.get("MemorySwap"), docker_memory_bytes(memory)),
        "pids": (host.get("PidsLimit"), pids),
        "CPU": (host.get("NanoCpus"), int(float(cpus) * 1_000_000_000)),
        "network": (host.get("NetworkMode"), network),
        "cgroup namespace": (host.get("CgroupnsMode"), "private"),
        "user": (config.get("User"), expected_user),
        "entrypoint": (config.get("Entrypoint"), [entrypoint]),
    }
    for label, (observed, expected) in checks.items():
        if observed != expected:
            raise LabError(
                f"container {name} {label} differs: expected {expected!r}, found {observed!r}"
            )
    normalize_capability = lambda item: str(item).upper().removeprefix("CAP_")
    cap_drop = {normalize_capability(item) for item in host.get("CapDrop") or []}
    cap_add = {normalize_capability(item) for item in host.get("CapAdd") or []}
    if cap_drop != {"ALL"} or cap_add != {normalize_capability(item) for item in capabilities}:
        raise LabError(f"container {name} capability configuration differs")
    security = [str(item) for item in host.get("SecurityOpt") or []]
    if not any(item.startswith("no-new-privileges") for item in security):
        raise LabError(f"container {name} lacks no-new-privileges")
    if {str(key): str(value) for key, value in (host.get("Sysctls") or {}).items()} != (
        sysctls or {}
    ):
        raise LabError(f"container {name} sysctl configuration differs")
    expected_mounts = {
        "/output": (str(output_dir.resolve()), True),
        **{
            destination: (str(source.resolve()), False)
            for source, destination in read_only_mounts
        },
    }
    observed_mounts: dict[str, tuple[str, bool]] = {}
    for mount in mounts:
        if isinstance(mount, dict) and mount.get("Type") == "bind":
            observed_mounts[str(mount.get("Destination"))] = (
                str(mount.get("Source")),
                bool(mount.get("RW")),
            )
    if observed_mounts != expected_mounts:
        raise LabError(f"container {name} bind mounts differ from the isolated mount plan")
    write_exclusive_json(ctx.run_dir / f"{name}-configuration.json", value)


def resource_sample(
    ctx: RunContext, name: str, expected_memory_bytes: int
) -> dict[str, Any]:
    docker = require_docker()
    sample: dict[str, Any] = {"utc": utc_now(), "monotonic_ns": time.monotonic_ns()}
    stats = ctx.runner.run(
        [docker, "stats", "--no-stream", "--format", "{{json .}}", name], check=False
    )
    if stats.returncode != 0 or not stats.stdout.strip():
        raise LabError("Docker stats failed during mandatory resource sampling")
    try:
        sample["docker_stats"] = json.loads(stats.stdout)
    except json.JSONDecodeError as error:
        raise LabError("Docker stats returned malformed JSON") from error
    for path in CGROUP_FILES:
        result = ctx.runner.run([docker, "exec", name, "/usr/bin/cat", path], check=False)
        if result.returncode != 0:
            raise LabError(f"mandatory cgroup read failed: {path}")
        sample[path.rsplit("/", 1)[-1]] = result.stdout.strip()
    for path in OPTIONAL_CGROUP_FILES:
        result = ctx.runner.run([docker, "exec", name, "/usr/bin/cat", path], check=False)
        key = path.rsplit("/", 1)[-1]
        available = result.returncode == 0
        sample[f"{key}_available"] = available
        sample[key] = result.stdout.strip() if available else None
    process = ctx.runner.run(
        [docker, "exec", name, "/usr/bin/pgrep", "--oldest", "--exact", "aster-lab"],
        check=False,
    )
    if process.returncode not in {0, 1}:
        raise LabError("aster-lab process state probe failed")
    process_id = process.stdout.strip() if process.returncode == 0 else ""
    process_observed = bool(re.fullmatch(r"[1-9][0-9]*", process_id))
    if process.returncode == 0 and not process_observed:
        raise LabError("aster-lab process state probe returned a malformed PID")
    if process_observed:
        sample["process_pid"] = int(process_id)
        for path in [f"/proc/{process_id}/smaps_rollup", f"/proc/{process_id}/status"]:
            result = ctx.runner.run([docker, "exec", name, "/usr/bin/cat", path], check=False)
            if result.returncode != 0:
                # The workload may have exited between pgrep and this read. The
                # already captured cgroup counters remain a valid terminal sample.
                sample.pop("smaps_rollup", None)
                sample.pop("status", None)
                sample.pop("process_pid", None)
                process_observed = False
                break
            sample[path.rsplit("/", 1)[-1]] = result.stdout
    sample["process_observed"] = process_observed
    sample["phase"] = "running" if process_observed else "terminal-cgroup"
    validate_resource_sample(
        sample, expected_memory_bytes, require_process=process_observed
    )
    append_jsonl(ctx.run_dir / "resource-samples.jsonl", sample)
    return sample


def run_resource(args: argparse.Namespace) -> None:
    name = FIXED_CONTAINER_NAMES["resource"]
    resources = [PlannedResource("container", name, "resource")]
    command = [
        "scale",
        "--root",
        "/output/run",
        "--nodes",
        "1",
        "--shards",
        "1",
        "--items",
        str(args.items),
        "--payload-bytes",
        str(args.payload_bytes),
        "--max-pumps",
        str(args.max_pumps),
        *fault_args(args),
    ]
    if not args.execute:
        plan_output(
            "resource",
            resources,
            [
                {
                    "container_pid1": ["/usr/bin/sleep", "infinity"],
                    "foreground_receipted_exec": command,
                    "limits": {"cpus": args.cpus, "memory": args.memory, "swap": args.memory},
                    "capture": CGROUP_FILES
                    + OPTIONAL_CGROUP_FILES
                    + ["/proc/<oldest-exact-aster-lab-pid>/smaps_rollup", "/proc/<pid>/status"],
                }
            ],
        )
        return
    ctx = RunContext.create(args.evidence_root, "resource", resources)
    docker_preflight(ctx, containers=[name], networks=[], require_cgroup_v2=True)
    write_scenario_request(
        ctx,
        scenario="scale-resource",
        seed=args.seed,
        nodes=1,
        shards=1,
        items=args.items,
        payload_bytes=args.payload_bytes,
        max_pumps=args.max_pumps,
        mtu=args.mtu,
        bits_per_second=args.bps,
        loss_per_mille=args.loss_per_mille,
        reorder_ticks=args.reorder_ticks,
        tick_ms=args.tick_ms,
        cpus=args.cpus,
        memory=args.memory,
    )
    verified = False
    try:
        output_dir = create_output_directory(ctx, "resource")
        ctx.runner.run(
            container_run_args(
                ctx,
                name=name,
                role="resource",
                command=["infinity"],
                detach=True,
                cpus=args.cpus,
                memory=args.memory,
                pids=128,
                output_dir=output_dir,
                entrypoint="/usr/bin/sleep",
            )
        )
        verify_container_configuration(
            ctx,
            name,
            output_dir=output_dir,
            memory=args.memory,
            cpus=args.cpus,
            pids=128,
            network="none",
            entrypoint="/usr/bin/sleep",
        )
        workload = ctx.runner.start(
            [
                require_docker(),
                "exec",
                name,
                "/usr/local/bin/aster-lab",
                *command,
            ]
        )
        try:
            deadline = time.monotonic() + args.timeout
            startup_deadline = min(deadline, time.monotonic() + 10.0)
            while workload.poll() is None:
                process = ctx.runner.run(
                    [
                        require_docker(),
                        "exec",
                        name,
                        "/usr/bin/pgrep",
                        "--oldest",
                        "--exact",
                        "aster-lab",
                    ],
                    check=False,
                )
                if process.returncode == 0:
                    break
                if process.returncode != 1:
                    raise LabError("resource workload process state probe failed")
                if time.monotonic() >= startup_deadline:
                    raise LabError("resource workload did not become observable")
                time.sleep(0.05)
            if workload.poll() is not None:
                workload.finish(check=True)
                raise LabError("resource workload ended before its process became observable")

            samples = 0
            expected_memory_bytes = docker_memory_bytes(args.memory)
            while workload.poll() is None:
                sample = resource_sample(ctx, name, expected_memory_bytes)
                if sample["process_observed"] is True:
                    samples += 1
                    sleep_interval = args.sample_interval
                else:
                    sleep_interval = min(args.sample_interval, 0.05)
                if time.monotonic() >= deadline:
                    workload.terminate()
                    raise LabError("resource scenario timed out")
                time.sleep(sleep_interval)
            returncode = workload.finish(check=False)
            terminal_sample = resource_sample(ctx, name, expected_memory_bytes)
            if terminal_sample["process_observed"] is not False:
                raise LabError("terminal cgroup snapshot still observed the workload process")
            if returncode != 0:
                stderr = (ctx.run_dir / workload.stderr_name).read_text(
                    encoding="utf-8", errors="replace"
                ).strip()
                raise LabError(
                    f"resource workload failed with {returncode}"
                    + (f": {stderr}" if stderr else "")
                )
        finally:
            if not workload.finished:
                workload.terminate()
        scenario_metrics(
            ctx,
            "outputs/resource/run",
            {
                "scenario": "scale",
                "seed": args.seed,
                "shards": 1,
                "nodes": 1,
                "published_items": args.items,
                "delivered_items": args.items,
                "configured_bits_per_second": args.bps,
                "configured_loss_per_mille": args.loss_per_mille,
                "loss_window_frames": 1_000,
            },
        )
        if samples == 0:
            raise LabError("resource scenario ended before process RSS was captured")
        ctx.event(
            "resource-capture-verified",
            running_samples=samples,
            terminal_cgroup_samples=1,
        )
        verified = True
    finally:
        cleanup_context(ctx, tolerate_errors=not verified)
    print(ctx.run_dir)


def interface_for_address(ctx: RunContext, container: str, address: str) -> str:
    result = ctx.runner.run(
        [require_docker(), "exec", container, "/usr/sbin/ip", "-j", "-4", "address", "show"]
    )
    try:
        interfaces = json.loads(result.stdout)
    except json.JSONDecodeError as error:
        raise LabError("ip returned malformed interface JSON") from error
    for interface in interfaces:
        for record in interface.get("addr_info", []):
            if record.get("local") == address:
                name = interface.get("ifname")
                if isinstance(name, str) and re.fullmatch(r"[A-Za-z0-9_.-]{1,32}", name):
                    return name
    raise LabError(f"could not resolve interface for {container} address {address}")


def nft_rules(
    *,
    profile: str,
    lan_if: str,
    wan_if: str,
    lan_subnet: str,
    node_ip: str,
    external_ip: str,
) -> str:
    if profile not in {"cone", "restrictive"}:
        raise LabError(f"unsupported NAT profile: {profile}")
    if profile == "cone":
        forward = f'''\
        iifname "{lan_if}" oifname "{wan_if}" counter accept
        iifname "{wan_if}" oifname "{lan_if}" ip daddr {node_ip} udp dport 44000 counter accept
        ct state established,related counter accept'''
        prerouting = f'''\
        iifname "{wan_if}" ip daddr {external_ip} udp dport 44000 counter dnat to {node_ip}:44000'''
        fixed_snat = f'''\
        oifname "{wan_if}" ip saddr {node_ip} udp sport 44000 counter snat to {external_ip}:44000'''
    else:
        forward = f'''\
        iifname "{lan_if}" oifname "{wan_if}" ip daddr 10.250.0.20 udp dport 4476 counter accept
        iifname "{lan_if}" oifname "{wan_if}" ip daddr 10.250.0.20 tcp dport 4477 counter accept
        iifname "{wan_if}" oifname "{lan_if}" ct state established,related counter accept'''
        prerouting = ""
        fixed_snat = ""
    return f'''flush ruleset
table inet aster_lab_filter {{
    chain forward {{
        type filter hook forward priority filter; policy drop;
{forward}
    }}
}}
table ip aster_lab_nat {{
    chain prerouting {{
        type nat hook prerouting priority dstnat;
{prerouting}
    }}
    chain postrouting {{
        type nat hook postrouting priority srcnat;
{fixed_snat}
        oifname "{wan_if}" ip saddr {lan_subnet} counter masquerade
    }}
}}
'''


def nat_container(
    ctx: RunContext,
    *,
    name: str,
    role: str,
    network: str,
    address: str,
    capabilities: Sequence[str],
    output_dir: Path,
    forwarding: bool = False,
) -> list[str]:
    return container_run_args(
        ctx,
        name=name,
        role=role,
        network=network,
        ip=address,
        detach=True,
        memory="256m",
        cpus="0.5",
        pids=64,
        capabilities=capabilities,
        root_user=True,
        entrypoint="/usr/bin/sleep",
        sysctls=["net.ipv4.ip_forward=1"] if forwarding else [],
        output_dir=output_dir,
        command=["infinity"],
    )


def wait_for_log_marker(
    ctx: RunContext, name: str, marker: str, timeout: float = 10.0
) -> None:
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        state = ctx.runner.run(
            [require_docker(), "container", "inspect", name, "--format", "{{json .State}}"]
        )
        try:
            decoded = json.loads(state.stdout)
        except json.JSONDecodeError as error:
            raise LabError("Docker returned malformed detached-container state") from error
        logs = ctx.runner.run([require_docker(), "container", "logs", name], check=False)
        if logs.returncode != 0:
            raise LabError(f"could not read readiness logs for {name}")
        if marker in logs.stdout or marker in logs.stderr:
            if decoded.get("Running") is not True:
                raise LabError(f"container {name} emitted readiness then exited")
            return
        if decoded.get("Running") is not True:
            raise LabError(f"container {name} exited before readiness")
        time.sleep(0.25)
    raise LabError(f"container {name} did not emit readiness marker {marker!r}")


def capture_process_running(ctx: RunContext, container: str, capture_path: str) -> bool:
    process_table = ctx.runner.run(
        [require_docker(), "top", container, "-eo", "pid,comm,args"],
        check=False,
    )
    if process_table.returncode != 0:
        raise LabError(f"could not inspect capture process in {container}")
    return any(
        "tcpdump" in line and capture_path in line
        for line in process_table.stdout.splitlines()[1:]
    )


def wait_for_capture_ready(
    ctx: RunContext, container: str, in_container_path: str, host_path: Path
) -> None:
    deadline = time.monotonic() + 10.0
    while time.monotonic() < deadline:
        nonempty = ctx.runner.run(
            [require_docker(), "exec", container, "/usr/bin/test", "-s", in_container_path],
            check=False,
        )
        if capture_process_running(ctx, container, in_container_path) and nonempty.returncode == 0:
            if host_path.is_file() and host_path.stat().st_size >= 24:
                return
        time.sleep(0.25)
    raise LabError(f"tcpdump did not become ready in {container}")


def validate_pcap(path: Path) -> int:
    if path.is_symlink() or not path.is_file():
        raise LabError(f"packet capture is missing or symbolic: {path}")
    size = path.stat().st_size
    if size < 24:
        raise LabError(f"packet capture has no complete global header: {path}")
    with path.open("rb") as stream:
        magic = stream.read(4)
    if magic not in {
        bytes.fromhex("a1b2c3d4"),
        bytes.fromhex("d4c3b2a1"),
        bytes.fromhex("a1b23c4d"),
        bytes.fromhex("4d3cb2a1"),
    }:
        raise LabError(f"packet capture has an unknown pcap header: {path}")
    return size


def nested_values(value: Any, names: set[str]) -> list[Any]:
    result = []
    if isinstance(value, dict):
        for key, item in value.items():
            if str(key).lower() in names:
                result.append(item)
            result.extend(nested_values(item, names))
    elif isinstance(value, list):
        for item in value:
            result.extend(nested_values(item, names))
    return result


def tc_rate_bits(value: Any) -> int | None:
    if isinstance(value, bool):
        return None
    if isinstance(value, (int, float)) and float(value).is_integer():
        # Linux tc JSON exposes the kernel rate value in bytes per second.
        return int(value) * 8
    if not isinstance(value, str):
        return None
    match = re.fullmatch(
        r"([0-9]+(?:\.[0-9]+)?)\s*(bit|kbit|mbit|gbit|tbit|bps)?",
        value.strip().lower(),
    )
    if match is None:
        return None
    multiplier = {
        None: 1,
        "bit": 1,
        "bps": 1,
        "kbit": 1_000,
        "mbit": 1_000_000,
        "gbit": 1_000_000_000,
        "tbit": 1_000_000_000_000,
    }[match.group(2)]
    return round(float(match.group(1)) * multiplier)


def loss_probability_matches(value: Any, expected_percent: int) -> bool:
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        return False
    observed = float(value)
    expected_fraction = expected_percent / 100
    if math.isclose(observed, expected_fraction, rel_tol=1e-6, abs_tol=1e-9):
        return True
    if math.isclose(observed, float(expected_percent), rel_tol=1e-6, abs_tol=1e-9):
        return True
    if 0 <= observed <= 2**32 - 1:
        encoded_percent = observed / (2**32 - 1) * 100
        return math.isclose(encoded_percent, expected_percent, rel_tol=1e-5, abs_tol=1e-5)
    return False


def verify_qdisc_json(
    value: str,
    *,
    expected_bps: int | None = None,
    expected_loss_percent: int | None = None,
    expected_limit: int | None = None,
    expected_seed: int | None = None,
) -> None:
    try:
        decoded = json.loads(value)
    except json.JSONDecodeError as error:
        raise LabError("tc returned malformed qdisc JSON") from error
    if not isinstance(decoded, list):
        raise LabError("tc qdisc result is not a list")
    netem = [item for item in decoded if isinstance(item, dict) and item.get("kind") == "netem"]
    if len(netem) != 1:
        raise LabError("requested netem qdisc is not installed")
    if all(value is None for value in [expected_bps, expected_loss_percent, expected_limit, expected_seed]):
        return
    options = netem[0].get("options")
    if not isinstance(options, dict):
        raise LabError("netem qdisc has no structured options")
    if expected_limit is not None and expected_limit not in nested_values(options, {"limit"}):
        raise LabError("netem limit differs from the requested value")
    if expected_seed is not None and expected_seed not in nested_values(options, {"seed"}):
        raise LabError("netem random seed differs from the requested value")
    if expected_bps is not None:
        rates = nested_values(options, {"rate", "rate64"})
        if expected_bps not in {rate for item in rates if (rate := tc_rate_bits(item)) is not None}:
            raise LabError("netem rate differs from the requested value")
    if expected_loss_percent is not None:
        probabilities = nested_values(options, {"probability", "loss"})
        if expected_loss_percent == 0 and not probabilities:
            return
        if not any(loss_probability_matches(item, expected_loss_percent) for item in probabilities):
            raise LabError("netem loss differs from the requested value")


def run_nat_up(args: argparse.Namespace) -> None:
    specs = network_specs(NAT_NETWORKS.values())
    by_role = {key: NetworkSpec.from_tuple(value) for key, value in NAT_NETWORKS.items()}
    container_roles = ["node-a", "nat-a", "infra", "nat-b", "node-b"]
    resources = [PlannedResource("network", spec.name, role) for role, spec in by_role.items()]
    resources.extend(
        PlannedResource("container", FIXED_CONTAINER_NAMES[role], role)
        for role in container_roles
    )
    if not args.execute:
        plan_output(
            "nat",
            resources,
            [
                "create three internal bridges with fixed, collision-checked CIDRs",
                "start five exact-name containers: NET_ADMIN on endpoint scaffolds, NET_ADMIN+NET_RAW+SETUID+SETGID on router capture points, no added capability on infra",
                "attach each NAT router to its LAN and WAN",
                f"install explicit {args.profile} nftables rules and node default routes",
                "run the combined unprivileged UDP-rendezvous/TCP-relay service on WAN .20",
                "start WAN-interface packet capture in each NAT namespace",
                "leave topology running; no NAT acceptance is claimed until live node carrier scenarios pass",
            ],
        )
        return
    ctx = RunContext.create(args.evidence_root, "nat", resources)
    names = [FIXED_CONTAINER_NAMES[role] for role in container_roles]
    docker_preflight(ctx, containers=names, networks=specs)
    write_scenario_request(
        ctx,
        scenario="nat-topology",
        profile=args.profile,
        shape_bps=args.shape_bps,
        loss_percent=args.loss_percent,
        requested_netem_seed=args.seed,
        infrastructure_duration_ms=args.duration_ms,
        acceptance_claim=False,
    )
    succeeded = False
    try:
        outputs = {
            role: create_output_directory(ctx, role) for role in container_roles
        }
        for role in ["lan-a", "wan", "lan-b"]:
            create_network(ctx, by_role[role], role)
        ctx.runner.run(
            nat_container(
                ctx,
                name=FIXED_CONTAINER_NAMES["node-a"],
                role="node-a",
                network=by_role["lan-a"].name,
                address="10.250.1.10",
                capabilities=["NET_ADMIN"],
                output_dir=outputs["node-a"],
            )
        )
        ctx.runner.run(
            nat_container(
                ctx,
                name=FIXED_CONTAINER_NAMES["nat-a"],
                role="nat-a",
                network=by_role["lan-a"].name,
                address="10.250.1.1",
                capabilities=["NET_ADMIN", "NET_RAW", "SETUID", "SETGID"],
                output_dir=outputs["nat-a"],
                forwarding=True,
            )
        )
        ctx.runner.run(
            container_run_args(
                ctx,
                name=FIXED_CONTAINER_NAMES["infra"],
                role="infra",
                command=[
                    "infra",
                    "--rendezvous-bind",
                    "0.0.0.0:4476",
                    "--relay-bind",
                    "0.0.0.0:4477",
                    "--duration-ms",
                    str(args.duration_ms),
                    "--poll-ms",
                    "1",
                ],
                detach=True,
                network=by_role["wan"].name,
                ip="10.250.0.20",
                memory="256m",
                cpus="0.5",
                pids=128,
                output_dir=outputs["infra"],
            )
        )
        ctx.runner.run(
            nat_container(
                ctx,
                name=FIXED_CONTAINER_NAMES["nat-b"],
                role="nat-b",
                network=by_role["lan-b"].name,
                address="10.250.2.1",
                capabilities=["NET_ADMIN", "NET_RAW", "SETUID", "SETGID"],
                output_dir=outputs["nat-b"],
                forwarding=True,
            )
        )
        ctx.runner.run(
            nat_container(
                ctx,
                name=FIXED_CONTAINER_NAMES["node-b"],
                role="node-b",
                network=by_role["lan-b"].name,
                address="10.250.2.10",
                capabilities=["NET_ADMIN"],
                output_dir=outputs["node-b"],
            )
        )
        docker = require_docker()
        ctx.runner.run(
            [docker, "network", "connect", "--ip", "10.250.0.11", by_role["wan"].name, FIXED_CONTAINER_NAMES["nat-a"]]
        )
        ctx.runner.run(
            [docker, "network", "connect", "--ip", "10.250.0.12", by_role["wan"].name, FIXED_CONTAINER_NAMES["nat-b"]]
        )
        ctx.runner.run(
            [docker, "exec", FIXED_CONTAINER_NAMES["node-a"], "/usr/sbin/ip", "route", "replace", "default", "via", "10.250.1.1"]
        )
        ctx.runner.run(
            [docker, "exec", FIXED_CONTAINER_NAMES["node-b"], "/usr/sbin/ip", "route", "replace", "default", "via", "10.250.2.1"]
        )
        router_values = [
            ("nat-a", "10.250.1.1", "10.250.0.11", "10.250.1.0/24", "10.250.1.10"),
            ("nat-b", "10.250.2.1", "10.250.0.12", "10.250.2.0/24", "10.250.2.10"),
        ]
        runtime_routers = []
        netem_seed_statuses: set[str] = set()
        for role, lan_address, wan_address, lan_subnet, node_ip in router_values:
            container = FIXED_CONTAINER_NAMES[role]
            lan_if = interface_for_address(ctx, container, lan_address)
            wan_if = interface_for_address(ctx, container, wan_address)
            rules = nft_rules(
                profile=args.profile,
                lan_if=lan_if,
                wan_if=wan_if,
                lan_subnet=lan_subnet,
                node_ip=node_ip,
                external_ip=wan_address,
            )
            rules_path = ctx.run_dir / f"{role}.nft"
            with rules_path.open("x", encoding="utf-8") as stream:
                stream.write(rules)
            ctx.runner.run(
                [docker, "exec", "--interactive", container, "/usr/sbin/nft", "-f", "-"],
                input_text=rules,
            )
            if args.shape_bps > 0:
                netem = [
                    docker,
                    "exec",
                    container,
                    "/usr/sbin/tc",
                    "qdisc",
                    "replace",
                    "dev",
                    wan_if,
                    "root",
                    "netem",
                    "limit",
                    "64",
                    "rate",
                    f"{args.shape_bps}bit",
                    "loss",
                    "random",
                    f"{args.loss_percent}%",
                ]
                seeded = ctx.runner.run(
                    [*netem, "seed", str(args.seed)],
                    check=False,
                )
                if seeded.returncode == 0:
                    seed_status = "applied"
                    applied_seed: int | None = args.seed
                elif 'What is "seed"?' in seeded.stderr:
                    ctx.runner.run(netem)
                    seed_status = "unsupported"
                    applied_seed = None
                else:
                    raise LabError(
                        f"netem seed setup failed unexpectedly on {container} "
                        f"with status {seeded.returncode}"
                    )
                netem_seed_statuses.add(seed_status)
                ctx.event(
                    "netem-seed-capability",
                    role=role,
                    requested_seed=args.seed,
                    status=seed_status,
                )
                stats = ctx.runner.run(
                    [docker, "exec", container, "/usr/sbin/tc", "-s", "-j", "qdisc", "show", "dev", wan_if]
                )
                verify_qdisc_json(
                    stats.stdout,
                    expected_bps=args.shape_bps,
                    expected_loss_percent=args.loss_percent,
                    expected_limit=64,
                    expected_seed=applied_seed,
                )
                write_exclusive_text(ctx.run_dir / f"{role}-qdisc-initial.json", stats.stdout)
            capture_in_container = f"/output/{role}-wan.pcap"
            capture_host = outputs[role] / f"{role}-wan.pcap"
            capture_program = [
                "/usr/bin/tcpdump",
                "-Z",
                "tcpdump",
                "-i",
                wan_if,
                "-s",
                "0",
                "-U",
                "-w",
                capture_in_container,
                "udp",
                "or",
                "tcp",
            ]
            ctx.runner.run(
                [
                    docker,
                    "exec",
                    "--detach",
                    container,
                    *capture_program,
                ]
            )
            try:
                wait_for_capture_ready(ctx, container, capture_in_container, capture_host)
            except LabError as readiness_error:
                diagnostic_capture = f"/tmp/{role}-diagnostic.pcap"
                diagnostic_program = [
                    *capture_program[:9],
                    diagnostic_capture,
                    *capture_program[10:],
                ]
                diagnostic = ctx.runner.run(
                    [
                        docker,
                        "exec",
                        container,
                        "/usr/bin/timeout",
                        "--signal=INT",
                        "2",
                        *diagnostic_program,
                    ],
                    check=False,
                    timeout=5,
                )
                raise LabError(
                    f"{readiness_error}; foreground tcpdump diagnostic exited "
                    f"with status {diagnostic.returncode}"
                ) from readiness_error
            runtime_routers.append(
                {
                    "role": role,
                    "container": container,
                    "wan_interface": wan_if,
                    "capture_container_path": capture_in_container,
                    "capture_relative_path": str(capture_host.relative_to(ctx.run_dir)),
                }
            )
        wait_for_log_marker(
            ctx,
            FIXED_CONTAINER_NAMES["infra"],
            "ASTER_LAB_INFRA_READY\tversion=1",
        )
        verify_container_configuration(
            ctx,
            FIXED_CONTAINER_NAMES["node-a"],
            output_dir=outputs["node-a"],
            memory="256m",
            cpus="0.5",
            pids=64,
            network=by_role["lan-a"].name,
            capabilities=["NET_ADMIN"],
            root_user=True,
            entrypoint="/usr/bin/sleep",
        )
        verify_container_configuration(
            ctx,
            FIXED_CONTAINER_NAMES["node-b"],
            output_dir=outputs["node-b"],
            memory="256m",
            cpus="0.5",
            pids=64,
            network=by_role["lan-b"].name,
            capabilities=["NET_ADMIN"],
            root_user=True,
            entrypoint="/usr/bin/sleep",
        )
        for role, lan_role in [("nat-a", "lan-a"), ("nat-b", "lan-b")]:
            verify_container_configuration(
                ctx,
                FIXED_CONTAINER_NAMES[role],
                output_dir=outputs[role],
                memory="256m",
                cpus="0.5",
                pids=64,
                network=by_role[lan_role].name,
                capabilities=["NET_ADMIN", "NET_RAW", "SETUID", "SETGID"],
                root_user=True,
                sysctls={"net.ipv4.ip_forward": "1"},
                entrypoint="/usr/bin/sleep",
            )
        verify_container_configuration(
            ctx,
            FIXED_CONTAINER_NAMES["infra"],
            output_dir=outputs["infra"],
            memory="256m",
            cpus="0.5",
            pids=128,
            network=by_role["wan"].name,
        )
        if args.shape_bps > 0:
            if len(netem_seed_statuses) != 1:
                raise LabError("NAT routers disagree on netem seed capability")
            netem_seed_status = next(iter(netem_seed_statuses))
            netem_seed = args.seed if netem_seed_status == "applied" else None
        else:
            netem_seed_status = "not-requested"
            netem_seed = None
        write_exclusive_json(
            ctx.run_dir / "nat-runtime.json",
            {
                "schema": SCHEMA,
                "profile": args.profile,
                "shape_bps": args.shape_bps,
                "loss_percent": args.loss_percent,
                "netem_limit": 64,
                "netem_seed_requested": args.seed,
                "netem_seed_status": netem_seed_status,
                "netem_seed": netem_seed,
                "routers": runtime_routers,
                "infra": FIXED_CONTAINER_NAMES["infra"],
            },
        )
        for role in container_roles:
            ctx.event("resource-created", kind="container", name=FIXED_CONTAINER_NAMES[role], role=role)
        ctx.event(
            "nat-topology-ready",
            profile=args.profile,
            acceptance_claim=False,
            limitation="combined rendezvous/relay infra is live; node carrier scenarios are not invoked",
        )
        succeeded = True
    finally:
        if not succeeded:
            cleanup_context(ctx, tolerate_errors=True)
    print(ctx.run_dir)


def run_scale(args: argparse.Namespace) -> None:
    name = FIXED_CONTAINER_NAMES["scale"]
    resources = [PlannedResource("container", name, "scale")]
    command = [
        "scale",
        "--root",
        "/output/run",
        "--nodes",
        str(args.nodes),
        "--shards",
        str(args.shards),
        "--items",
        str(args.items),
        "--payload-bytes",
        str(args.payload_bytes),
        "--max-pumps",
        str(args.max_pumps),
        *fault_args(args),
    ]
    if not args.execute:
        plan_output(
            "scale",
            resources,
            [
                {
                    "docker_run": command,
                    "limits": {"cpus": args.cpus, "memory": args.memory},
                    "interpretation": "process-sharded deterministic chain simulation; not bridged live-IP acceptance",
                }
            ],
        )
        return
    ctx = RunContext.create(args.evidence_root, "scale", resources)
    docker_preflight(ctx, containers=[name], networks=[])
    write_scenario_request(
        ctx,
        scenario="scale",
        seed=args.seed,
        nodes=args.nodes,
        shards=args.shards,
        items_per_shard=args.items,
        payload_bytes=args.payload_bytes,
        max_pumps=args.max_pumps,
        mtu=args.mtu,
        bits_per_second=args.bps,
        loss_per_mille=args.loss_per_mille,
        reorder_ticks=args.reorder_ticks,
        tick_ms=args.tick_ms,
        cpus=args.cpus,
        memory=args.memory,
    )
    verified = False
    try:
        output_dir = create_output_directory(ctx, "scale")
        pids = max(128, args.shards * 4 + 32)
        completed = ctx.runner.run(
            container_run_args(
                ctx,
                name=name,
                role="scale",
                command=command,
                cpus=args.cpus,
                memory=args.memory,
                pids=pids,
                output_dir=output_dir,
            ),
            check=False,
            timeout=args.timeout,
        )
        if completed.returncode != 0:
            raise LabError(f"scale container failed with {completed.returncode}")
        verify_container_configuration(
            ctx,
            name,
            output_dir=output_dir,
            memory=args.memory,
            cpus=args.cpus,
            pids=pids,
            network="none",
        )
        scenario_metrics(
            ctx,
            "outputs/scale/run",
            {
                "scenario": "scale",
                "seed": args.seed,
                "nodes": args.nodes,
                "shards": args.shards,
                "published_items": args.items * args.shards,
                "delivered_items": args.items * args.nodes,
                "configured_bits_per_second": args.bps,
                "configured_loss_per_mille": args.loss_per_mille,
                "loss_window_frames": 1_000,
            },
        )
        ctx.event("scenario-verified", scenario="scale", nodes=args.nodes, shards=args.shards)
        verified = True
    finally:
        cleanup_context(ctx, tolerate_errors=not verified)
    print(ctx.run_dir)


def inspect_labels(ctx: RunContext, resource: PlannedResource) -> dict[str, str] | None:
    docker = require_docker()
    if not docker_resource_present(ctx, resource.kind, resource.name):
        return None
    if resource.kind == "container":
        args = [docker, "container", "inspect", resource.name, "--format", "{{json .Config.Labels}}"]
    elif resource.kind == "network":
        args = [docker, "network", "inspect", resource.name, "--format", "{{json .Labels}}"]
    else:
        raise LabError(f"unsupported cleanup resource kind: {resource.kind}")
    result = ctx.runner.run(args)
    try:
        value = json.loads(result.stdout)
    except json.JSONDecodeError as error:
        raise LabError(f"malformed labels for {resource.kind} {resource.name}") from error
    if not isinstance(value, dict):
        raise LabError(f"labels are not an object for {resource.kind} {resource.name}")
    return {str(key): str(item) for key, item in value.items()}


def require_owned_labels(
    ctx: RunContext, resource: PlannedResource, current: dict[str, str]
) -> None:
    expected = {
        MANAGED_LABEL: "true",
        RUN_LABEL: ctx.run_id,
        ROLE_LABEL: resource.role,
    }
    if any(current.get(key) != value for key, value in expected.items()):
        raise LabError(
            f"refusing operation on {resource.kind} {resource.name}: ownership labels differ"
        )


def write_command_linked_receipt(
    ctx: RunContext, stem: str, suffix: str, value: str
) -> Path:
    path = ctx.run_dir / f"{stem}-command-{ctx.runner.sequence:04d}.{suffix}"
    write_exclusive_text(path, value)
    return path


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def validate_linked_receipt(
    ctx: RunContext,
    record: dict[str, Any],
    field: str,
    *,
    prefix: str,
    suffix: str,
) -> str:
    name = record.get(field)
    digest = record.get(f"{field}_sha256")
    if not isinstance(name, str) or not re.fullmatch(
        rf"{re.escape(prefix)}-command-[0-9]{{4,}}\.{re.escape(suffix)}", name
    ):
        raise LabError(f"NAT linked receipt name is invalid: {field}")
    if not isinstance(digest, str) or not re.fullmatch(r"[0-9a-f]{64}", digest):
        raise LabError(f"NAT linked receipt digest is invalid: {field}")
    path = confined_run_path(ctx, ctx.run_dir / name)
    if path.is_symlink() or not path.is_file() or sha256_file(path) != digest:
        raise LabError(f"NAT linked receipt is missing or differs: {field}")
    return path.read_text(encoding="utf-8")


def container_is_running(ctx: RunContext, name: str) -> bool:
    result = ctx.runner.run(
        [require_docker(), "container", "inspect", name, "--format", "{{json .State}}"]
    )
    try:
        state = json.loads(result.stdout)
    except json.JSONDecodeError as error:
        raise LabError("Docker returned malformed container state") from error
    if not isinstance(state, dict) or type(state.get("Running")) is not bool:
        raise LabError("Docker container state has no Running boolean")
    return state["Running"]


def validate_nat_terminal_receipts(
    ctx: RunContext, receipt: dict[str, Any], runtime: dict[str, Any]
) -> list[dict[str, Any]]:
    if receipt.get("schema") != SCHEMA or receipt.get("run_id") != ctx.run_id:
        raise LabError("NAT terminal receipt schema or run ID differs")
    routers = receipt.get("routers")
    if not isinstance(routers, list) or len(routers) != 2:
        raise LabError("NAT terminal receipt has no exact router set")
    seen = set()
    for record in routers:
        if not isinstance(record, dict) or record.get("role") not in {"nat-a", "nat-b"}:
            raise LabError("NAT terminal router receipt is invalid")
        role = record["role"]
        if role in seen:
            raise LabError("NAT terminal router receipt is duplicated")
        seen.add(role)
        qdisc = validate_linked_receipt(
            ctx, record, "qdisc_receipt", prefix=f"{role}-qdisc-final", suffix="json"
        )
        if runtime["shape_bps"] > 0:
            verify_qdisc_json(
                qdisc,
                expected_bps=runtime["shape_bps"],
                expected_loss_percent=runtime["loss_percent"],
                expected_limit=runtime["netem_limit"],
                expected_seed=runtime["netem_seed"],
            )
        else:
            try:
                if not isinstance(json.loads(qdisc), list):
                    raise LabError("terminal qdisc receipt is not a list")
            except json.JSONDecodeError as error:
                raise LabError("terminal qdisc receipt is malformed") from error
        nft = validate_linked_receipt(
            ctx, record, "nft_receipt", prefix=f"{role}-nft-final", suffix="json"
        )
        try:
            if not isinstance(json.loads(nft), dict):
                raise LabError("terminal nft receipt is not an object")
        except json.JSONDecodeError as error:
            raise LabError("terminal nft receipt is malformed") from error
    if seen != {"nat-a", "nat-b"}:
        raise LabError("NAT terminal router roles differ")
    infra = validate_linked_receipt(
        ctx, receipt, "infra_log_receipt", prefix="nat-infra-final", suffix="log"
    )
    if "ASTER_LAB_INFRA_READY\tversion=1" not in infra:
        raise LabError("terminal infrastructure receipt lacks its readiness marker")
    return routers


def finalize_nat(ctx: RunContext) -> None:
    """Idempotently stop captures after binding terminal counter/log receipts."""
    runtime_path = ctx.run_dir / "nat-runtime.json"
    if runtime_path.is_symlink():
        raise LabError("NAT runtime receipt cannot be symbolic")
    if not runtime_path.is_file():
        return
    try:
        runtime = json.loads(runtime_path.read_text(encoding="utf-8"))
    except json.JSONDecodeError as error:
        raise LabError("NAT runtime receipt is malformed") from error
    if not isinstance(runtime, dict) or runtime.get("schema") != SCHEMA:
        raise LabError("NAT runtime receipt schema mismatch")
    if runtime.get("profile") not in {"cone", "restrictive"}:
        raise LabError("NAT runtime profile is invalid")
    integer_fields = {
        "shape_bps": (0, 1_000_000_000),
        "loss_percent": (0, 100),
        "netem_limit": (64, 64),
        "netem_seed_requested": (1, 2**31 - 1),
    }
    for field, (minimum, maximum) in integer_fields.items():
        value = runtime.get(field)
        if type(value) is not int or not minimum <= value <= maximum:
            raise LabError(f"NAT runtime {field} is invalid")
    seed_status = runtime.get("netem_seed_status")
    if seed_status not in {"applied", "unsupported", "not-requested"}:
        raise LabError("NAT runtime netem seed status is invalid")
    applied_seed = runtime.get("netem_seed")
    if seed_status == "applied":
        if applied_seed != runtime["netem_seed_requested"]:
            raise LabError("NAT runtime applied netem seed differs from the request")
    elif applied_seed is not None:
        raise LabError("NAT runtime records a seed that was not applied")
    if runtime["shape_bps"] > 0 and seed_status == "not-requested":
        raise LabError("NAT runtime omitted netem seed capability status")
    if runtime["shape_bps"] == 0 and seed_status != "not-requested":
        raise LabError("NAT runtime records a netem seed for an unshaped topology")
    if runtime.get("infra") != FIXED_CONTAINER_NAMES["infra"]:
        raise LabError("NAT runtime infrastructure differs from the fixed allowlist")
    routers = runtime.get("routers")
    if not isinstance(routers, list) or len(routers) != 2:
        raise LabError("NAT runtime receipt has no exact router set")

    final_path = ctx.run_dir / "nat-finalization.json"
    if final_path.is_symlink():
        raise LabError("NAT finalization receipt cannot be symbolic")
    if final_path.is_file():
        try:
            prior = json.loads(final_path.read_text(encoding="utf-8"))
        except json.JSONDecodeError as error:
            raise LabError("existing NAT finalization receipt is malformed") from error
        if not isinstance(prior, dict):
            raise LabError("existing NAT finalization receipt is not an object")
        final_routers = validate_nat_terminal_receipts(ctx, prior, runtime)
        for record in final_routers:
            role = record["role"]
            expected = f"outputs/{role}/{role}-wan.pcap"
            if record.get("capture") != expected:
                raise LabError("existing NAT finalization capture path differs")
            capture = confined_run_path(ctx, ctx.run_dir / expected)
            size = validate_pcap(capture)
            if size != record.get("capture_bytes") or sha256_file(capture) != record.get(
                "capture_sha256"
            ):
                raise LabError("existing NAT finalization capture differs")
        return

    runtime_by_role: dict[str, dict[str, Any]] = {}
    for record in routers:
        if not isinstance(record, dict):
            raise LabError("NAT router runtime entry is malformed")
        role = record.get("role")
        if role not in {"nat-a", "nat-b"} or role in runtime_by_role:
            raise LabError("NAT router runtime role is invalid or duplicated")
        container = FIXED_CONTAINER_NAMES[role]
        if record.get("container") != container:
            raise LabError("NAT router runtime container differs from the fixed allowlist")
        if record.get("capture_container_path") != f"/output/{role}-wan.pcap":
            raise LabError("NAT capture container path differs from the fixed plan")
        if record.get("capture_relative_path") != f"outputs/{role}/{role}-wan.pcap":
            raise LabError("NAT capture host path differs from the isolated output plan")
        wan_if = record.get("wan_interface")
        if not isinstance(wan_if, str) or not re.fullmatch(r"[A-Za-z0-9_.-]{1,32}", wan_if):
            raise LabError("NAT runtime WAN interface is invalid")
        resource = PlannedResource("container", container, role)
        current = inspect_labels(ctx, resource)
        if current is None:
            raise LabError(f"cannot finalize absent NAT router {container}")
        require_owned_labels(ctx, resource, current)
        runtime_by_role[role] = record

    started_path = ctx.run_dir / "nat-finalization-started.json"
    if started_path.is_symlink():
        raise LabError("NAT finalization-start receipt cannot be symbolic")
    if started_path.is_file():
        try:
            started = json.loads(started_path.read_text(encoding="utf-8"))
        except json.JSONDecodeError as error:
            raise LabError("NAT finalization-start receipt is malformed") from error
        if not isinstance(started, dict):
            raise LabError("NAT finalization-start receipt is not an object")
        terminal_routers = validate_nat_terminal_receipts(ctx, started, runtime)
    else:
        docker = require_docker()
        terminal_routers = []
        for role in ["nat-a", "nat-b"]:
            record = runtime_by_role[role]
            container = FIXED_CONTAINER_NAMES[role]
            if not container_is_running(ctx, container):
                raise LabError(f"NAT router stopped before finalization began: {container}")
            if not capture_process_running(
                ctx, container, record["capture_container_path"]
            ):
                raise LabError(f"tcpdump was not live when finalization began: {container}")
            qdisc = ctx.runner.run(
                [
                    docker,
                    "exec",
                    container,
                    "/usr/sbin/tc",
                    "-s",
                    "-j",
                    "qdisc",
                    "show",
                    "dev",
                    record["wan_interface"],
                ]
            )
            if runtime["shape_bps"] > 0:
                verify_qdisc_json(
                    qdisc.stdout,
                    expected_bps=runtime["shape_bps"],
                    expected_loss_percent=runtime["loss_percent"],
                    expected_limit=runtime["netem_limit"],
                    expected_seed=runtime["netem_seed"],
                )
            else:
                try:
                    if not isinstance(json.loads(qdisc.stdout), list):
                        raise LabError("terminal qdisc output is not a list")
                except json.JSONDecodeError as error:
                    raise LabError("terminal qdisc output is malformed") from error
            qdisc_path = write_command_linked_receipt(
                ctx, f"{role}-qdisc-final", "json", qdisc.stdout
            )
            rules = ctx.runner.run(
                [docker, "exec", container, "/usr/sbin/nft", "--json", "list", "ruleset"]
            )
            try:
                if not isinstance(json.loads(rules.stdout), dict):
                    raise LabError("terminal nft output is not an object")
            except json.JSONDecodeError as error:
                raise LabError("terminal nft output is malformed") from error
            nft_path = write_command_linked_receipt(
                ctx, f"{role}-nft-final", "json", rules.stdout
            )
            terminal_routers.append(
                {
                    "role": role,
                    "qdisc_receipt": qdisc_path.name,
                    "qdisc_receipt_sha256": sha256_file(qdisc_path),
                    "nft_receipt": nft_path.name,
                    "nft_receipt_sha256": sha256_file(nft_path),
                }
            )
        infra_resource = PlannedResource("container", FIXED_CONTAINER_NAMES["infra"], "infra")
        infra_labels = inspect_labels(ctx, infra_resource)
        if infra_labels is None:
            raise LabError("cannot finalize absent NAT infrastructure container")
        require_owned_labels(ctx, infra_resource, infra_labels)
        infra_logs = ctx.runner.run([docker, "container", "logs", infra_resource.name])
        if "ASTER_LAB_INFRA_READY\tversion=1" not in infra_logs.stdout + infra_logs.stderr:
            raise LabError("NAT infrastructure readiness marker is absent at finalization")
        infra_path = write_command_linked_receipt(
            ctx, "nat-infra-final", "log", infra_logs.stdout + infra_logs.stderr
        )
        started = {
            "schema": SCHEMA,
            "run_id": ctx.run_id,
            "started_utc": utc_now(),
            "infra_log_receipt": infra_path.name,
            "infra_log_receipt_sha256": sha256_file(infra_path),
            "routers": terminal_routers,
        }
        validate_nat_terminal_receipts(ctx, started, runtime)
        write_atomic_exclusive_json(started_path, started)

    docker = require_docker()
    summaries = []
    terminal_by_role = {record["role"]: record for record in terminal_routers}
    for role in ["nat-a", "nat-b"]:
        container = FIXED_CONTAINER_NAMES[role]
        if container_is_running(ctx, container):
            stop_capture = ctx.runner.run(
                [
                    docker,
                    "exec",
                    "--user",
                    "tcpdump",
                    container,
                    "/usr/bin/pkill",
                    "--signal",
                    "INT",
                    "--exact",
                    "tcpdump",
                ],
                check=False,
            )
            if stop_capture.returncode not in {0, 1}:
                raise LabError(f"could not signal tcpdump cleanly in {container}")
            deadline = time.monotonic() + 10.0
            while True:
                if not capture_process_running(
                    ctx,
                    container,
                    runtime_by_role[role]["capture_container_path"],
                ):
                    break
                if time.monotonic() >= deadline:
                    raise LabError(f"tcpdump did not stop cleanly in {container}")
                time.sleep(0.25)
        capture_relative = f"outputs/{role}/{role}-wan.pcap"
        capture = confined_run_path(ctx, ctx.run_dir / capture_relative)
        size = validate_pcap(capture)
        summaries.append(
            {
                **terminal_by_role[role],
                "capture": capture_relative,
                "capture_bytes": size,
                "capture_sha256": sha256_file(capture),
            }
        )
    final = {
        "schema": SCHEMA,
        "run_id": ctx.run_id,
        "finalized_utc": utc_now(),
        "infra_log_receipt": started["infra_log_receipt"],
        "infra_log_receipt_sha256": started["infra_log_receipt_sha256"],
        "routers": summaries,
    }
    validate_nat_terminal_receipts(ctx, final, runtime)
    write_atomic_exclusive_json(final_path, final)
    ctx.event("nat-finalized", routers=len(summaries))


def validate_cleanup_resource(resource: PlannedResource, run_id: str) -> None:
    if resource.kind not in {"container", "network"}:
        raise LabError(f"cleanup kind not permitted: {resource.kind}")
    validate_resource_name(resource.name)
    if resource.kind == "container" and resource.name not in FIXED_CONTAINER_NAMES.values():
        raise LabError(f"container is not in the exact cleanup allowlist: {resource.name}")
    allowed_networks = {DIRECT_NETWORK, *(value[0] for value in NAT_NETWORKS.values())}
    if resource.kind == "network" and resource.name not in allowed_networks:
        raise LabError(f"network is not in the exact cleanup allowlist: {resource.name}")
    if not RUN_ID.fullmatch(run_id):
        raise LabError("malformed cleanup run identifier")


def cleanup_context(ctx: RunContext, *, tolerate_errors: bool) -> None:
    errors = []
    try:
        verify_orbstack(ctx)
    except LabError as error:
        ctx.event("cleanup-error", kind="daemon", name="orbstack", error=str(error))
        if tolerate_errors:
            return
        raise
    has_nat_resources = any(
        resource.kind == "container" and resource.role in {"nat-a", "nat-b", "infra"}
        for resource in ctx.resources
    )
    if has_nat_resources:
        try:
            if not (ctx.run_dir / "nat-runtime.json").is_file() and not tolerate_errors:
                raise LabError("NAT cleanup requires its readiness/runtime receipt")
            finalize_nat(ctx)
        except LabError as error:
            errors.append(str(error))
            ctx.event("cleanup-error", kind="finalization", name="nat", error=str(error))
            if not tolerate_errors:
                raise LabError(f"NAT finalization failed; resources were retained: {error}") from error
    ordered = [resource for resource in ctx.resources if resource.kind == "container"]
    ordered.extend(resource for resource in ctx.resources if resource.kind == "network")
    for resource in ordered:
        try:
            validate_cleanup_resource(resource, ctx.run_id)
            current = inspect_labels(ctx, resource)
            if current is None:
                ctx.event("cleanup-absent", kind=resource.kind, name=resource.name)
                continue
            require_owned_labels(ctx, resource, current)
            if resource.kind == "container":
                if has_nat_resources and (ctx.run_dir / "nat-finalization.json").is_file():
                    if container_is_running(ctx, resource.name):
                        ctx.runner.run(
                            [
                                require_docker(),
                                "container",
                                "stop",
                                "--time",
                                "5",
                                resource.name,
                            ]
                        )
                logs = ctx.runner.run(
                    [require_docker(), "container", "logs", resource.name], check=False
                )
                if logs.returncode != 0:
                    raise LabError(f"could not preserve final logs for {resource.name}")
                write_command_linked_receipt(
                    ctx,
                    f"cleanup-{resource.name}",
                    "log",
                    logs.stdout + logs.stderr,
                )
                command = [require_docker(), "container", "rm", "--force", resource.name]
            else:
                command = [require_docker(), "network", "rm", resource.name]
            ctx.runner.run(command)
            ctx.event("resource-removed", kind=resource.kind, name=resource.name)
        except LabError as error:
            errors.append(str(error))
            ctx.event("cleanup-error", kind=resource.kind, name=resource.name, error=str(error))
    if errors and not tolerate_errors:
        raise LabError("cleanup failed: " + "; ".join(errors))


def load_cleanup_context(run_dir: Path) -> RunContext:
    resolved = run_dir.resolve()
    manifest_path = resolved / "controller.json"
    if not manifest_path.is_file():
        raise LabError("cleanup requires an Aster lab controller.json manifest")
    with manifest_path.open(encoding="utf-8") as stream:
        manifest = json.load(stream)
    if manifest.get("schema") != SCHEMA or manifest.get("evidence_dir") != str(resolved):
        raise LabError("cleanup manifest schema or evidence path mismatch")
    run_id = manifest.get("run_id")
    label = manifest.get("label")
    if not isinstance(run_id, str) or not RUN_ID.fullmatch(run_id):
        raise LabError("cleanup manifest run identifier is invalid")
    if not isinstance(label, str) or not re.fullmatch(r"[a-z0-9-]{1,32}", label):
        raise LabError("cleanup manifest label is invalid")
    resources = []
    for value in manifest.get("resources", []):
        if not isinstance(value, dict):
            raise LabError("cleanup manifest resource is invalid")
        resource = PlannedResource(
            kind=str(value.get("kind", "")),
            name=str(value.get("name", "")),
            role=str(value.get("role", "")),
        )
        validate_cleanup_resource(resource, run_id)
        resources.append(resource)
    return RunContext(label, run_id, resolved, resources, CommandRunner(resolved))


def run_cleanup(args: argparse.Namespace) -> None:
    if not args.execute:
        print(
            json.dumps(
                {
                    "schema": SCHEMA,
                    "dry_run": True,
                    "operation": "cleanup",
                    "run_dir": str(args.run_dir.resolve()),
                    "safety": "Only exact manifest resources with matching ownership labels are removable.",
                },
                indent=2,
                sort_keys=True,
            )
        )
        return
    ctx = load_cleanup_context(args.run_dir)
    cleanup_context(ctx, tolerate_errors=False)
    print(ctx.run_dir)


def positive_int(value: str) -> int:
    parsed = int(value)
    if parsed <= 0:
        raise argparse.ArgumentTypeError("must be positive")
    return parsed


def nonnegative_int(value: str) -> int:
    parsed = int(value)
    if parsed < 0:
        raise argparse.ArgumentTypeError("must be nonnegative")
    return parsed


def bounded_int(minimum: int, maximum: int):
    def parse(value: str) -> int:
        parsed = int(value)
        if not minimum <= parsed <= maximum:
            raise argparse.ArgumentTypeError(f"must be in {minimum}..{maximum}")
        return parsed

    return parse


def memory_value(value: str) -> str:
    if not MEMORY_VALUE.fullmatch(value):
        raise argparse.ArgumentTypeError("use a Docker byte value such as 64m or 3g")
    return value.lower()


def cpu_value(value: str) -> str:
    if not CPU_VALUE.fullmatch(value) or float(value) <= 0:
        raise argparse.ArgumentTypeError("use a positive Docker CPU value such as 1 or 1.5")
    return value


def add_execution(parser: argparse.ArgumentParser) -> None:
    parser.add_argument(
        "--execute",
        action="store_true",
        help="perform mutations; without this option only a plan is printed",
    )
    parser.add_argument(
        "--evidence-root",
        type=Path,
        default=DEFAULT_EVIDENCE_ROOT,
        help=f"parent for single-use run directories (default: {DEFAULT_EVIDENCE_ROOT})",
    )


def add_faults(parser: argparse.ArgumentParser) -> None:
    parser.add_argument("--seed", type=bounded_int(0, 2**64 - 1), default=1)
    parser.add_argument("--mtu", type=bounded_int(64, 65_535), default=1_200)
    parser.add_argument("--bps", type=positive_int, default=1_000_000)
    parser.add_argument("--loss-per-mille", type=bounded_int(0, 900), default=0)
    parser.add_argument("--reorder-ticks", type=bounded_int(0, 65_535), default=0)
    parser.add_argument("--tick-ms", type=bounded_int(1, 65_535), default=100)


def parser() -> argparse.ArgumentParser:
    result = argparse.ArgumentParser(description=__doc__)
    subparsers = result.add_subparsers(dest="operation", required=True)

    build = subparsers.add_parser(
        "build", help="build the pinned lab image without image pulls (network is opt-in)"
    )
    add_execution(build)
    build.add_argument("--replace-image", action="store_true")
    build.add_argument(
        "--allow-build-network",
        action="store_true",
        help="explicitly permit dependency acquisition with --network=default and --no-cache",
    )
    build.add_argument("--timeout", type=positive_int, default=3_600)
    build.set_defaults(handler=run_build)

    self_contained = subparsers.add_parser(
        "self-contained", help="run deterministic transfer or Blob recovery in one container"
    )
    add_execution(self_contained)
    add_faults(self_contained)
    self_contained.add_argument("scenario", choices=["transfer", "blob-recovery"])
    self_contained.add_argument("--items", type=bounded_int(1, 4_096), default=4)
    self_contained.add_argument("--payload-bytes", type=positive_int, default=65_536)
    self_contained.add_argument("--blob-bytes", type=positive_int, default=105_906_176)
    self_contained.add_argument("--chunk-bytes", type=positive_int, default=65_536)
    self_contained.add_argument("--restart-after-frames", type=nonnegative_int, default=256)
    self_contained.add_argument("--max-pumps", type=positive_int, default=2_000_000)
    self_contained.add_argument("--cpus", type=cpu_value, default="2")
    self_contained.add_argument("--memory", type=memory_value, default="4g")
    self_contained.add_argument("--timeout", type=positive_int, default=1_800)
    self_contained.set_defaults(handler=run_self_contained)

    two_node = subparsers.add_parser("two-node", help="run two real UDP node containers")
    add_execution(two_node)
    two_node.add_argument(
        "--seed",
        type=bounded_int(0, 2**64 - 1),
        default=1,
        help="public canary workload seed; never used for identity or capability material",
    )
    two_node.add_argument("--items", type=bounded_int(1, 2_048), default=4)
    two_node.add_argument("--payload-bytes", type=positive_int, default=1_024)
    two_node.add_argument("--duration-ms", type=positive_int, default=60_000)
    two_node.add_argument("--max-pumps", type=positive_int, default=1_000_000)
    two_node.add_argument("--responder-settle-ms", type=positive_int, default=1_000)
    two_node.add_argument("--cpus", type=cpu_value, default="1")
    two_node.add_argument("--memory", type=memory_value, default="512m")
    two_node.set_defaults(handler=run_two_node)

    resource = subparsers.add_parser("resource", help="capture cgroup-v2 usage for one logical node")
    add_execution(resource)
    add_faults(resource)
    resource.add_argument("--items", type=positive_int, default=10_000)
    resource.add_argument("--payload-bytes", type=positive_int, default=64)
    resource.add_argument("--max-pumps", type=positive_int, default=100_000)
    resource.add_argument("--cpus", type=cpu_value, default="1")
    resource.add_argument("--memory", type=memory_value, default="64m")
    resource.add_argument("--sample-interval", type=float, default=1.0)
    resource.add_argument("--timeout", type=positive_int, default=1_200)
    resource.set_defaults(handler=run_resource)

    nat = subparsers.add_parser("nat-up", help="create the five-unit controlled NAT topology")
    add_execution(nat)
    nat.add_argument("--profile", choices=["cone", "restrictive"], default="cone")
    nat.add_argument("--shape-bps", type=bounded_int(0, 1_000_000_000), default=0)
    nat.add_argument("--loss-percent", type=bounded_int(0, 100), default=0)
    nat.add_argument("--seed", type=bounded_int(1, 2**31 - 1), default=424_242)
    nat.add_argument("--duration-ms", type=positive_int, default=3_600_000)
    nat.set_defaults(handler=run_nat_up)

    scale = subparsers.add_parser("scale", help="run deterministic process-sharded scale simulation")
    add_execution(scale)
    add_faults(scale)
    scale.add_argument("--nodes", type=positive_int, default=100)
    scale.add_argument("--shards", type=positive_int, default=4)
    scale.add_argument("--items", type=bounded_int(1, 4_096), default=1)
    scale.add_argument("--payload-bytes", type=positive_int, default=1_024)
    scale.add_argument("--max-pumps", type=positive_int, default=100_000)
    scale.add_argument("--cpus", type=cpu_value, default="4")
    scale.add_argument("--memory", type=memory_value, default="12g")
    scale.add_argument("--timeout", type=positive_int, default=3_600)
    scale.set_defaults(handler=run_scale)

    cleanup = subparsers.add_parser("cleanup", help="remove only exact, owned resources from one run")
    cleanup.add_argument("--execute", action="store_true")
    cleanup.add_argument("run_dir", type=Path)
    cleanup.set_defaults(handler=run_cleanup)
    return result


def validate_arguments(args: argparse.Namespace) -> None:
    if hasattr(args, "shards") and hasattr(args, "nodes") and args.shards > args.nodes:
        raise LabError("shards cannot exceed nodes")
    if hasattr(args, "sample_interval") and (
        not math.isfinite(args.sample_interval) or args.sample_interval <= 0
    ):
        raise LabError("sample interval must be finite and positive")
    if hasattr(args, "loss_percent") and args.shape_bps == 0 and args.loss_percent != 0:
        raise LabError("--loss-percent requires nonzero --shape-bps")


def main(argv: Sequence[str] | None = None) -> int:
    args = parser().parse_args(argv)
    try:
        validate_arguments(args)
        args.handler(args)
        return 0
    except (LabError, json.JSONDecodeError, OSError, ValueError) as error:
        print(f"aster-lab controller: {error}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
