#!/usr/bin/env python3
# Copyright 2026 Defense Unicorns, Inc.
# SPDX-License-Identifier: Apache-2.0
"""Run one bounded, generated Docker hierarchy-scale diagnostic.

The diagnostic keeps eight leaf scopes behind two regional scopes and one
root scope.  Each selected tier places 1, 4, or 8 offline publishers on every
leaf, then starts the whole rosterless cohort at once.  It is deliberately a
single-host feasibility diagnostic, not production or physical-network proof.
"""

from __future__ import annotations

import argparse
import base64
from collections import Counter, defaultdict
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass
import hashlib
import json
import os
from pathlib import Path
import platform
import re
import secrets
import shutil
import signal
import statistics
import subprocess
import sys
import tempfile
import time
from typing import Callable, Mapping, Sequence, TypeVar


ROOT = Path(__file__).resolve().parents[1]
DOCKERFILE = "docker/hierarchy-mvp/Dockerfile"
IMAGE_VARIABLE = "ASTER_HIERARCHY_SCALE_IMAGE"
DISCOVERY_VARIABLE = "ASTER_HIERARCHY_SCALE_DISCOVER_LAN"
ALLOWED_PUBLISHERS_PER_LEAF = (1, 4, 8)
LEAF_COUNT = 8
REGION_COUNT = 2
LEAVES_PER_REGION = 4
LEAF_SCOPE_EPOCH = 1
ROOT_SCOPE_EPOCH = LEAF_COUNT + REGION_COUNT + 1
NETWORK_COUNT = LEAF_COUNT + REGION_COUNT + 1
STATIC_EDGE_COUNT = LEAF_COUNT + REGION_COUNT
MAX_LOCAL_PEER_BOUND = 32
MAX_INTERFACE_BOUND = 8
MAX_AUTHORIZATION_BOUND = 64
MAX_RESTART_ROUTE_BOUND = 256
MAX_SELECTED_ROOT_ROUTES = 64
MAX_RETAINED_OUTPUT = 8 * 1024 * 1024
MAX_RECEIPT_LINES = 50_000
MAX_RECEIPT_LINE_BYTES = 8_192
MAX_RECEIPT_FIELDS = 96
MAX_RECEIPT_FIELD_BYTES = 1_024
PROJECT_RE = re.compile(r"aster-hierarchy-scale-[0-9]+-[0-9a-f]{8}\Z")
SERVICE_RE = re.compile(
    r"(?:p[0-9]{3}|l0[0-7]|r0[0-1]|root-consumer|outsider)\Z"
)
CONTAINER_ID_RE = re.compile(r"[0-9a-f]{12,64}\Z")
HEX_DIGEST_RE = re.compile(r"[0-9a-f]{64}\Z")
FIELD_KEY_RE = re.compile(r"[A-Za-z][A-Za-z0-9_-]{0,63}\Z")
PAYLOAD_SENTINEL_PREFIX = "HIERARCHY_SCALE_PAYLOAD_SENTINEL_"
ALLOWED_TOPIC = "mesh.allowed"
DENIED_TOPIC = "mesh.denied"
PRIORITY = "immediate"
DEFAULT_FLOW_SECONDS = {1: 240, 4: 420, 8: 600}
DEFAULT_SETTLE_SECONDS = 5
MIN_FLOW_SECONDS = 60
MAX_FLOW_SECONDS = 600
T = TypeVar("T")


class ScaleError(RuntimeError):
    """Expected, sanitized hierarchy-scale failure."""


@dataclass(frozen=True)
class ReadyIdentity:
    """Sanitized process identity fields used to correlate receipts."""

    carrier: str
    mission: str
    authority: str
    nearby: str


@dataclass(frozen=True)
class SourceFixture:
    """One exact deterministic source fixture retained from offline staging."""

    role: str
    case: str
    source_id: str
    topic: str
    priority: str
    payload_sha256: str


class Deadline:
    """One monotonic hard deadline shared by all post-build phases."""

    def __init__(
        self,
        seconds: float,
        clock: Callable[[], float] = time.monotonic,
    ) -> None:
        if not MIN_FLOW_SECONDS <= seconds <= MAX_FLOW_SECONDS:
            raise ScaleError("flow deadline must be between 60 and 600 seconds")
        self._clock = clock
        self.started = clock()
        self._end = self.started + seconds
        self.seconds = seconds

    def remaining(self, label: str) -> float:
        value = self._end - self._clock()
        if value <= 0:
            raise ScaleError(f"hard flow deadline expired while waiting for {label}")
        return value

    def command_timeout(self, maximum: float, label: str) -> float:
        return max(0.1, min(maximum, self.remaining(label)))

    def elapsed(self) -> float:
        return self._clock() - self.started


def validate_publishers_per_leaf(value: int) -> int:
    if value not in ALLOWED_PUBLISHERS_PER_LEAF:
        choices = ", ".join(str(item) for item in ALLOWED_PUBLISHERS_PER_LEAF)
        raise ScaleError(f"publishers per leaf must be one of: {choices}")
    return value


def publisher_services(publishers_per_leaf: int) -> tuple[str, ...]:
    value = validate_publishers_per_leaf(publishers_per_leaf)
    return tuple(f"p{index:03d}" for index in range(LEAF_COUNT * value))


def leaf_services() -> tuple[str, ...]:
    return tuple(f"l{index:02d}" for index in range(LEAF_COUNT))


def region_services() -> tuple[str, ...]:
    return tuple(f"r{index:02d}" for index in range(REGION_COUNT))


def live_services(publishers_per_leaf: int) -> tuple[str, ...]:
    return (
        *publisher_services(publishers_per_leaf),
        *leaf_services(),
        *region_services(),
        "root-consumer",
        "outsider",
    )


def authorized_services(publishers_per_leaf: int) -> tuple[str, ...]:
    return tuple(
        item for item in live_services(publishers_per_leaf) if item != "outsider"
    )


def leaf_for_publisher(role: str, publishers_per_leaf: int) -> int:
    if re.fullmatch(r"p[0-9]{3}", role) is None:
        raise ScaleError("publisher role is malformed")
    index = int(role[1:])
    total = LEAF_COUNT * validate_publishers_per_leaf(publishers_per_leaf)
    if index >= total:
        raise ScaleError("publisher role is outside the selected tier")
    return index // publishers_per_leaf


def region_for_leaf(leaf: int) -> int:
    if not 0 <= leaf < LEAF_COUNT:
        raise ScaleError("leaf index is outside the fixed hierarchy")
    return leaf // LEAVES_PER_REGION


def network_names() -> tuple[str, ...]:
    return (
        *(f"leaf{index:02d}" for index in range(LEAF_COUNT)),
        *(f"region{index:02d}" for index in range(REGION_COUNT)),
        "root",
    )


def network_subnets() -> dict[str, str]:
    result = {
        f"leaf{index:02d}": f"10.231.{index}.0/24" for index in range(LEAF_COUNT)
    }
    result.update(
        {
            f"region{index:02d}": f"10.231.{LEAF_COUNT + index}.0/24"
            for index in range(REGION_COUNT)
        }
    )
    result["root"] = f"10.231.{LEAF_COUNT + REGION_COUNT}.0/24"
    return result


def service_interfaces(
    publishers_per_leaf: int,
) -> dict[str, dict[str, str]]:
    """Return exact service -> local segment -> fixed local address wiring."""

    value = validate_publishers_per_leaf(publishers_per_leaf)
    result: dict[str, dict[str, str]] = {}
    for index, role in enumerate(publisher_services(value)):
        leaf = index // value
        local = index % value
        result[role] = {f"leaf{leaf:02d}": f"10.231.{leaf}.{10 + local}"}
    for leaf, role in enumerate(leaf_services()):
        region = region_for_leaf(leaf)
        result[role] = {
            f"leaf{leaf:02d}": f"10.231.{leaf}.200",
            f"region{region:02d}": (
                f"10.231.{LEAF_COUNT + region}.{10 + leaf % LEAVES_PER_REGION}"
            ),
        }
    for region, role in enumerate(region_services()):
        result[role] = {
            f"region{region:02d}": f"10.231.{LEAF_COUNT + region}.200",
            "root": f"10.231.{LEAF_COUNT + REGION_COUNT}.{10 + region}",
        }
    result["root-consumer"] = {
        "root": f"10.231.{LEAF_COUNT + REGION_COUNT}.20"
    }
    result["outsider"] = {"root": f"10.231.{LEAF_COUNT + REGION_COUNT}.21"}
    return result


def segment_members(publishers_per_leaf: int) -> dict[str, tuple[str, ...]]:
    interfaces = service_interfaces(publishers_per_leaf)
    return {
        network: tuple(
            service for service, attached in interfaces.items() if network in attached
        )
        for network in network_names()
    }


def _node_service(
    service: str,
    interfaces: Mapping[str, str],
) -> dict[str, object]:
    return {
        "image": "${ASTER_HIERARCHY_SCALE_IMAGE:-aster-hierarchy-scale:local}",
        "user": "10001:10001",
        "init": True,
        "read_only": True,
        "restart": "no",
        "command": ["run"],
        "depends_on": {
            "init": {
                "condition": "service_completed_successfully",
                "required": True,
            }
        },
        "environment": {
            "ASTER_STATE_DIR": "/state",
            "ASTER_DISCOVER_LAN": "${ASTER_HIERARCHY_SCALE_DISCOVER_LAN:-0}",
            "ASTER_NEARBY_WINDOW": "3",
            "ASTER_SYNC_MS": "1000",
            "ASTER_HIERARCHY_ROLE": service,
            "ASTER_NEARBY_IPV4_INTERFACES": ",".join(interfaces.values()),
            "TOKIO_WORKER_THREADS": "1",
            "HOME": "/tmp",
        },
        "networks": {
            network: {"ipv4_address": address}
            for network, address in interfaces.items()
        },
        "tmpfs": [
            "/tmp:rw,nosuid,nodev,noexec,size=16m,mode=0700,uid=10001,gid=10001"
        ],
        "cap_drop": ["ALL"],
        "security_opt": ["no-new-privileges:true"],
        "stop_signal": "SIGINT",
        "stop_grace_period": "15s",
        "logging": {
            "driver": "json-file",
            "options": {"max-size": "4m", "max-file": "2"},
        },
        "volumes": [f"{service}-state:/state"],
    }


def compose_model(publishers_per_leaf: int) -> dict[str, object]:
    """Return the deterministic hardened Compose model for exactly one tier."""

    value = validate_publishers_per_leaf(publishers_per_leaf)
    services = live_services(value)
    interfaces = service_interfaces(value)
    volumes = {f"{service}-state": {} for service in services}
    model_services: dict[str, object] = {
        "init": {
            "image": "${ASTER_HIERARCHY_SCALE_IMAGE:-aster-hierarchy-scale:local}",
            "build": {"context": str(ROOT), "dockerfile": DOCKERFILE},
            "user": "0:0",
            "read_only": True,
            "restart": "no",
            "command": [
                "init-scale",
                "--root",
                "/provision",
                "--publishers-per-leaf",
                str(value),
            ],
            "network_mode": "none",
            "environment": {"HOME": "/tmp"},
            "tmpfs": ["/tmp:rw,nosuid,nodev,noexec,size=8m,mode=0700"],
            "cap_drop": ["ALL"],
            "cap_add": ["CHOWN"],
            "security_opt": ["no-new-privileges:true"],
            "volumes": [
                f"{service}-state:/provision/{service}" for service in services
            ],
        }
    }
    for service in services:
        model_services[service] = _node_service(service, interfaces[service])
    networks = {
        name: {
            "driver": "bridge",
            "driver_opts": {"com.docker.network.bridge.enable_icc": "true"},
            "ipam": {"config": [{"subnet": subnet}]},
        }
        for name, subnet in network_subnets().items()
    }
    model: dict[str, object] = {
        "services": model_services,
        "networks": networks,
        "volumes": volumes,
    }
    validate_compose_model(model, value)
    return model


def _require_exact_keys(value: Mapping[str, object], expected: set[str], label: str) -> None:
    if set(value) != expected:
        raise ScaleError(f"{label} changed its exact generated key set")


def capacity_summary(publishers_per_leaf: int) -> dict[str, object]:
    value = validate_publishers_per_leaf(publishers_per_leaf)
    memberships = segment_members(value)
    interfaces = service_interfaces(value)
    local_peers = {
        service: sum(len(memberships[network]) - 1 for network in attached)
        for service, attached in interfaces.items()
    }
    maximum_local = max(local_peers.values())
    maximum_interfaces = max(len(item) for item in interfaces.values())
    root_routes = LEAF_COUNT * value
    if maximum_local > MAX_LOCAL_PEER_BOUND:
        raise ScaleError("generated hierarchy exceeds the local-peer hard bound")
    if maximum_interfaces > MAX_INTERFACE_BOUND:
        raise ScaleError("generated hierarchy exceeds the interface hard bound")
    if STATIC_EDGE_COUNT > MAX_AUTHORIZATION_BOUND:
        raise ScaleError("generated hierarchy exceeds the authorization hard bound")
    if root_routes > MAX_SELECTED_ROOT_ROUTES or root_routes > MAX_RESTART_ROUTE_BOUND:
        raise ScaleError("generated hierarchy exceeds the selected root-route hard bound")
    return {
        "maxLocalPeers": {"selected": maximum_local, "bound": MAX_LOCAL_PEER_BOUND},
        "maxInterfaces": {"selected": maximum_interfaces, "bound": MAX_INTERFACE_BOUND},
        "authorizations": {
            "selected": STATIC_EDGE_COUNT,
            "bound": MAX_AUTHORIZATION_BOUND,
        },
        "rootRoutes": {
            "selected": root_routes,
            "diagnosticLimit": MAX_SELECTED_ROOT_ROUTES,
            "restartBound": MAX_RESTART_ROUTE_BOUND,
        },
    }


def validate_compose_model(model: Mapping[str, object], publishers_per_leaf: int) -> None:
    """Fail closed on any generated topology, privilege, or capacity drift."""

    value = validate_publishers_per_leaf(publishers_per_leaf)
    _require_exact_keys(
        model,
        {"services", "networks", "volumes"},
        "Compose model",
    )
    services = live_services(value)
    expected_service_set = {*services, "init"}
    model_services = model.get("services")
    networks = model.get("networks")
    volumes = model.get("volumes")
    if not isinstance(model_services, dict):
        raise ScaleError("Compose model omitted services")
    if not isinstance(networks, dict) or not isinstance(volumes, dict):
        raise ScaleError("Compose model omitted networks or volumes")
    _require_exact_keys(model_services, expected_service_set, "Compose services")
    _require_exact_keys(networks, set(network_names()), "Compose networks")
    _require_exact_keys(
        volumes,
        {f"{service}-state" for service in services},
        "Compose volumes",
    )

    interfaces = service_interfaces(value)
    seen_addresses: set[str] = set()
    for service in services:
        config = model_services.get(service)
        if not isinstance(config, dict):
            raise ScaleError(f"Compose service {service} is malformed")
        forbidden = ("ports", "extra_hosts", "network_mode", "privileged", "devices")
        if any(config.get(key) for key in forbidden):
            raise ScaleError(f"Compose service {service} exposed an unplanned path")
        required = {
            "image": "${ASTER_HIERARCHY_SCALE_IMAGE:-aster-hierarchy-scale:local}",
            "user": "10001:10001",
            "init": True,
            "read_only": True,
            "restart": "no",
            "command": ["run"],
            "cap_drop": ["ALL"],
            "security_opt": ["no-new-privileges:true"],
            "stop_signal": "SIGINT",
            "stop_grace_period": "15s",
            "tmpfs": [
                "/tmp:rw,nosuid,nodev,noexec,size=16m,mode=0700,uid=10001,gid=10001"
            ],
            "logging": {
                "driver": "json-file",
                "options": {"max-size": "4m", "max-file": "2"},
            },
        }
        if any(config.get(key) != expected for key, expected in required.items()):
            raise ScaleError(f"Compose service {service} changed hardening controls")
        if config.get("cap_add"):
            raise ScaleError(f"Compose service {service} gained a capability")
        depends = config.get("depends_on")
        if depends != {
            "init": {"condition": "service_completed_successfully", "required": True}
        }:
            raise ScaleError(f"Compose service {service} no longer depends on init")
        environment = config.get("environment")
        if not isinstance(environment, dict):
            raise ScaleError(f"Compose service {service} omitted its environment")
        expected_environment = {
            "ASTER_STATE_DIR": "/state",
            "ASTER_DISCOVER_LAN": "${ASTER_HIERARCHY_SCALE_DISCOVER_LAN:-0}",
            "ASTER_NEARBY_WINDOW": "3",
            "ASTER_SYNC_MS": "1000",
            "ASTER_HIERARCHY_ROLE": service,
            "ASTER_NEARBY_IPV4_INTERFACES": ",".join(interfaces[service].values()),
            "TOKIO_WORKER_THREADS": "1",
            "HOME": "/tmp",
        }
        if environment != expected_environment:
            raise ScaleError(f"Compose service {service} changed bounded runtime wiring")
        attached = config.get("networks")
        expected_attached = {
            name: {"ipv4_address": address}
            for name, address in interfaces[service].items()
        }
        if attached != expected_attached:
            raise ScaleError(f"Compose service {service} changed segment membership")
        for address in interfaces[service].values():
            if address in seen_addresses:
                raise ScaleError("generated Compose model reused a local interface address")
            seen_addresses.add(address)
        if config.get("volumes") != [f"{service}-state:/state"]:
            raise ScaleError(f"Compose service {service} changed durable state volume")

    initializer = model_services.get("init")
    if not isinstance(initializer, dict):
        raise ScaleError("Compose initializer is malformed")
    initializer_required = {
        "image": "${ASTER_HIERARCHY_SCALE_IMAGE:-aster-hierarchy-scale:local}",
        "build": {"context": str(ROOT), "dockerfile": DOCKERFILE},
        "user": "0:0",
        "read_only": True,
        "restart": "no",
        "network_mode": "none",
        "cap_drop": ["ALL"],
        "cap_add": ["CHOWN"],
        "security_opt": ["no-new-privileges:true"],
        "environment": {"HOME": "/tmp"},
        "tmpfs": ["/tmp:rw,nosuid,nodev,noexec,size=8m,mode=0700"],
        "command": [
            "init-scale",
            "--root",
            "/provision",
            "--publishers-per-leaf",
            str(value),
        ],
    }
    if any(initializer.get(key) != expected for key, expected in initializer_required.items()):
        raise ScaleError("Compose initializer changed isolation or privilege controls")
    if any(
        initializer.get(key)
        for key in ("networks", "ports", "extra_hosts", "privileged", "devices")
    ):
        raise ScaleError("Compose initializer exposed an unplanned network path")
    expected_mounts = [
        f"{service}-state:/provision/{service}" for service in services
    ]
    if initializer.get("volumes") != expected_mounts:
        raise ScaleError("Compose initializer changed exact provisioning volumes")
    if any(value != {} for value in volumes.values()):
        raise ScaleError("generated hierarchy volumes changed their exact local form")

    subnets = network_subnets()
    for name, subnet in subnets.items():
        expected_network = {
            "driver": "bridge",
            "driver_opts": {"com.docker.network.bridge.enable_icc": "true"},
            "ipam": {"config": [{"subnet": subnet}]},
        }
        if networks.get(name) != expected_network:
            raise ScaleError(f"Compose network {name} changed discovery bridge wiring")
    if len(set(subnets.values())) != NETWORK_COUNT:
        raise ScaleError("generated Compose networks reused a subnet")
    capacity_summary(value)


def write_compose_model(directory: Path, publishers_per_leaf: int) -> Path:
    """Create one no-follow, owner-only generated JSON Compose document."""

    if not directory.is_dir() or directory.is_symlink():
        raise ScaleError("generated Compose directory must be a concrete directory")
    try:
        os.chmod(directory, 0o700)
    except OSError as error:
        raise ScaleError("could not restrict the generated Compose directory") from error
    path = directory / "compose.json"
    data = (
        json.dumps(compose_model(publishers_per_leaf), indent=2, sort_keys=True) + "\n"
    ).encode("utf-8")
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL
    flags |= getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0)
    try:
        descriptor = os.open(path, flags, 0o600)
    except OSError as error:
        raise ScaleError("could not create the private generated Compose model") from error
    complete = False
    try:
        os.fchmod(descriptor, 0o600)
        offset = 0
        while offset < len(data):
            written = os.write(descriptor, data[offset:])
            if written <= 0:
                raise OSError("short Compose-model write")
            offset += written
        os.fsync(descriptor)
        complete = True
    except OSError as error:
        raise ScaleError("could not write the private generated Compose model") from error
    finally:
        os.close(descriptor)
        if not complete:
            try:
                path.unlink()
            except OSError:
                pass
    return path


def project_name(pid: int | None = None, suffix: str | None = None) -> str:
    value = (
        f"aster-hierarchy-scale-{pid or os.getpid()}-"
        f"{suffix or secrets.token_hex(4)}"
    )
    if PROJECT_RE.fullmatch(value) is None:
        raise ScaleError("failed to construct a bounded Compose project name")
    return value


def _read_retained(stream) -> str:
    size = stream.tell()
    if size > MAX_RETAINED_OUTPUT:
        prefix = "[earlier command output omitted]\n"
        retained = MAX_RETAINED_OUTPUT - len(prefix.encode("utf-8")) - 4
        stream.seek(size - retained)
    else:
        stream.seek(0)
        prefix = ""
        retained = MAX_RETAINED_OUTPUT
    return prefix + stream.read(retained).decode("utf-8", errors="replace")


class Docker:
    """Bounded Docker CLI wrapper with no shell evaluation."""

    def __init__(self, executable: str):
        candidate = Path(executable)
        if not candidate.is_absolute() or candidate.name != "docker":
            raise ScaleError("Docker executable must be an absolute path named docker")
        self.executable = str(candidate)

    def run(
        self,
        arguments: Sequence[str],
        *,
        timeout: float,
        environment: Mapping[str, str] | None = None,
    ) -> str:
        if not arguments:
            raise ScaleError("Docker command omitted arguments")
        with tempfile.TemporaryFile() as stdout, tempfile.TemporaryFile() as stderr:
            try:
                completed = subprocess.run(
                    (self.executable, *arguments),
                    cwd=ROOT,
                    env=dict(environment) if environment is not None else dict(os.environ),
                    stdin=subprocess.DEVNULL,
                    stdout=stdout,
                    stderr=stderr,
                    timeout=timeout,
                    check=False,
                )
            except subprocess.TimeoutExpired as error:
                raise ScaleError(
                    f"Docker command timed out after {timeout:.0f} seconds: "
                    f"{arguments[0]}"
                ) from error
            out = _read_retained(stdout)
            err = _read_retained(stderr)
        if completed.returncode != 0:
            detail = (err or out).strip()
            if len(detail) > 2_000:
                detail = detail[-2_000:]
            raise ScaleError(
                f"Docker command failed ({arguments[0]}, exit "
                f"{completed.returncode}): {detail or 'no diagnostic'}"
            )
        return out


class Compose:
    """One exact generated Compose project and its bounded service set."""

    def __init__(
        self,
        docker: Docker,
        compose_file: Path,
        project: str,
        services: Sequence[str],
    ) -> None:
        if PROJECT_RE.fullmatch(project) is None:
            raise ScaleError("invalid Compose project name")
        if not services or any(SERVICE_RE.fullmatch(item) is None for item in services):
            raise ScaleError("invalid generated hierarchy service set")
        if len(set(services)) != len(services):
            raise ScaleError("duplicate generated hierarchy service")
        self.docker = docker
        self.compose_file = compose_file
        self.project = project
        self.services = tuple(services)
        self.service_set = frozenset(services)
        self.image = f"{project}:local"
        self.prefix = (
            "compose",
            "--file",
            str(compose_file),
            "--project-name",
            project,
        )

    def environment(self, discovery: bool) -> dict[str, str]:
        environment = dict(os.environ)
        environment[IMAGE_VARIABLE] = self.image
        environment[DISCOVERY_VARIABLE] = "1" if discovery else "0"
        return environment

    def run(
        self,
        arguments: Sequence[str],
        *,
        timeout: float,
        discovery: bool = False,
    ) -> str:
        return self.docker.run(
            (*self.prefix, *arguments),
            timeout=timeout,
            environment=self.environment(discovery),
        )

    def _service(self, service: str) -> str:
        if service not in self.service_set:
            raise ScaleError("unknown generated hierarchy service")
        return service

    def logs(self, service: str, *, timeout: float = 20) -> str:
        return self.run(
            ("logs", "--no-color", "--tail", "all", self._service(service)),
            timeout=timeout,
        )

    def ps(
        self,
        services: Sequence[str],
        *,
        all_states: bool,
        timeout: float = 20,
    ) -> list[dict[str, object]]:
        for service in services:
            self._service(service)
        arguments = ["ps"]
        if all_states:
            arguments.append("--all")
        arguments.extend(("--no-trunc", "--format", "json", *services))
        return parse_ps_records(self.run(tuple(arguments), timeout=timeout))


def parse_ps_records(raw: str) -> list[dict[str, object]]:
    """Accept Compose arrays and newline-delimited JSON with an exact bound."""

    if len(raw.encode("utf-8", errors="replace")) > MAX_RETAINED_OUTPUT:
        raise ScaleError("Compose ps output exceeded its parser bound")
    try:
        document = json.loads(raw)
        records = document if isinstance(document, list) else [document]
    except (json.JSONDecodeError, UnicodeError):
        try:
            records = [json.loads(line) for line in raw.splitlines() if line.strip()]
        except (json.JSONDecodeError, UnicodeError) as error:
            raise ScaleError("Compose ps returned malformed JSON") from error
    if not records or len(records) > 128 or not all(
        isinstance(record, dict) for record in records
    ):
        raise ScaleError("Compose ps returned an invalid service list")
    return records


def validate_service_records(
    records: Sequence[Mapping[str, object]],
    services: Sequence[str],
    *,
    expected_state: str,
) -> dict[str, str]:
    expected = set(services)
    actual = {str(record.get("Service", "")) for record in records}
    if actual != expected or len(records) != len(expected):
        raise ScaleError("Compose ps omitted or duplicated a hierarchy node")
    container_ids: dict[str, str] = {}
    for record in records:
        service = str(record["Service"])
        state = str(record.get("State", "")).lower()
        if state != expected_state:
            raise ScaleError(
                f"node {service} was {state or 'unknown'}, expected {expected_state}"
            )
        if expected_state == "exited" and record.get("ExitCode") not in (0, "0"):
            raise ScaleError(f"node {service} did not exit cleanly")
        container_id = str(record.get("ID", ""))
        if CONTAINER_ID_RE.fullmatch(container_id) is None:
            raise ScaleError(f"node {service} has a malformed container ID")
        container_ids[service] = container_id
    if len(set(container_ids.values())) != len(expected):
        raise ScaleError("hierarchy nodes did not have distinct containers")
    return container_ids


def receipt_fields(logs: str, receipt: str) -> list[dict[str, str]]:
    """Parse one bounded, whitespace-free sanitized receipt family."""

    if not receipt or len(receipt) > 64 or re.fullmatch(r"[A-Z][A-Z0-9_]*", receipt) is None:
        raise ScaleError("receipt name is malformed")
    if len(logs.encode("utf-8", errors="replace")) > MAX_RETAINED_OUTPUT:
        raise ScaleError("retained node logs exceeded the receipt parser bound")
    lines = logs.splitlines()
    if len(lines) > MAX_RECEIPT_LINES:
        raise ScaleError("retained node logs exceeded the receipt line bound")
    marker = re.compile(rf"(?:^|[|\s]){re.escape(receipt)}\s+(.*)$")
    records: list[dict[str, str]] = []
    for line in lines:
        if len(line.encode("utf-8", errors="replace")) > MAX_RECEIPT_LINE_BYTES:
            raise ScaleError("retained node log line exceeded its parser bound")
        match = marker.search(line)
        if match is None:
            continue
        items = match.group(1).split()
        if len(items) > MAX_RECEIPT_FIELDS:
            raise ScaleError(f"{receipt} receipt exceeded its field bound")
        fields: dict[str, str] = {}
        for item in items:
            key, separator, value = item.partition("=")
            if (
                not separator
                or FIELD_KEY_RE.fullmatch(key) is None
                or not value
                or len(value.encode("utf-8", errors="replace"))
                > MAX_RECEIPT_FIELD_BYTES
                or key in fields
            ):
                raise ScaleError(f"{receipt} receipt contained malformed fields")
            fields[key] = value
        records.append(fields)
    return records


def canonical_identifier(raw: str, label: str) -> str:
    """Accept the repository's exact hex or canonical Base64 32-byte forms."""

    if HEX_DIGEST_RE.fullmatch(raw) is not None:
        return raw
    try:
        decoded = base64.b64decode(raw, validate=True)
    except (ValueError, UnicodeError) as error:
        raise ScaleError(f"{label} is not a canonical identifier") from error
    if len(decoded) != 32 or base64.b64encode(decoded).decode("ascii") != raw:
        raise ScaleError(f"{label} is not a canonical 32-byte identifier")
    return raw


def _matching_receipt(
    logs: str,
    receipt: str,
    expected: Mapping[str, str],
) -> dict[str, str] | None:
    for fields in receipt_fields(logs, receipt):
        if all(fields.get(key) == value for key, value in expected.items()):
            return fields
    return None


def _payload(role: str, case: str) -> bytes:
    return f"{PAYLOAD_SENTINEL_PREFIX}{role}_{case}".encode("utf-8")


def _payload_digest(role: str, case: str) -> str:
    return hashlib.sha256(_payload(role, case)).hexdigest()


def reject_node_error(logs: str, service: str) -> None:
    errors = [
        item
        for item in receipt_fields(logs, "HIERARCHY_DEMO")
        if item.get("status") == "error"
    ]
    if errors:
        detail = errors[-1].get("error", "unspecified")
        raise ScaleError(f"node {service} failed before readiness: {detail}")


def validate_init_receipt(
    logs: str,
    publishers_per_leaf: int,
) -> dict[str, str]:
    value = validate_publishers_per_leaf(publishers_per_leaf)
    expected = {
        "status": "pass",
        "publishers": str(LEAF_COUNT * value),
        "nodes": str(len(live_services(value))),
        "authorities": "2",
        "edges": str(STATIC_EDGE_COUNT),
        "leaf_scopes": str(LEAF_COUNT),
        "regional_scopes": str(REGION_COUNT),
        "provisioning": "unprotected-reference",
    }
    records = [
        item
        for item in receipt_fields(logs, "HIERARCHY_SCALE_INIT")
        if all(item.get(key) == expected_value for key, expected_value in expected.items())
        and item.get("disposition") in {"created", "existing"}
    ]
    if len(records) != 1:
        raise ScaleError("initializer omitted its exact hierarchy-scale receipt")
    return records[0]


def parse_ready_identity(
    logs: str,
    service: str,
    *,
    discovery: bool,
) -> ReadyIdentity:
    reject_node_error(logs, service)
    hierarchy_ready = [
        item
        for item in receipt_fields(logs, "HIERARCHY_READY")
        if item.get("status") == "started" and item.get("role") == service
    ]
    selected = [
        item
        for item in receipt_fields(logs, "READY")
        if item.get("selected") == "true"
    ]
    if not hierarchy_ready or not selected:
        raise ScaleError(f"node {service} did not emit exact readiness receipts")
    latest = selected[-1]
    values = (
        latest.get("carrier_id", ""),
        latest.get("mission_id", ""),
        latest.get("mission_authority", ""),
        latest.get("nearby_discovery", ""),
    )
    if any(not item for item in values):
        raise ScaleError(f"node {service} READY receipt omitted identity fields")
    expected_nearby = "active-evaluation" if discovery else "disabled"
    if values[3] != expected_nearby:
        raise ScaleError(
            f"node {service} did not report nearby discovery {expected_nearby}"
        )
    if hierarchy_ready[-1].get("nearby_discovery") != expected_nearby:
        raise ScaleError(f"node {service} hierarchy readiness changed discovery state")
    return ReadyIdentity(*values)


def validate_identity_cohort(
    identities: Mapping[str, ReadyIdentity],
    publishers_per_leaf: int,
    *,
    discovery: bool,
) -> None:
    services = live_services(publishers_per_leaf)
    authorized = authorized_services(publishers_per_leaf)
    if set(identities) != set(services):
        raise ScaleError("READY identity cohort omitted a hierarchy node")
    if len({item.carrier for item in identities.values()}) != len(services):
        raise ScaleError("hierarchy nodes did not have distinct carrier identities")
    if len({item.mission for item in identities.values()}) != len(services):
        raise ScaleError("hierarchy nodes did not have distinct mission identities")
    authorized_authorities = {identities[item].authority for item in authorized}
    if len(authorized_authorities) != 1:
        raise ScaleError("authorized hierarchy nodes did not share one authority")
    if identities["outsider"].authority in authorized_authorities:
        raise ScaleError("outsider unexpectedly shared the hierarchy authority")
    expected_nearby = "active-evaluation" if discovery else "disabled"
    if any(item.nearby != expected_nearby for item in identities.values()):
        raise ScaleError("READY identity cohort changed its discovery phase")


def validate_source_receipts(
    logs: Mapping[str, str],
    publishers_per_leaf: int,
) -> dict[str, dict[str, SourceFixture]]:
    """Require each publisher's exact deterministic allowed and denied fixtures."""

    publishers = publisher_services(publishers_per_leaf)
    if set(logs) != set(publishers):
        raise ScaleError("offline source logs omitted a publisher")
    result: dict[str, dict[str, SourceFixture]] = {}
    all_ids: set[str] = set()
    for role in publishers:
        published = [
            item
            for item in receipt_fields(logs[role], "HIERARCHY_SCALE_SOURCE")
            if item.get("status") == "published" and item.get("role") == role
        ]
        cases: dict[str, SourceFixture] = {}
        for case, topic in (("allowed", ALLOWED_TOPIC), ("denied", DENIED_TOPIC)):
            matching = [item for item in published if item.get("case") == case]
            if len(matching) != 1:
                raise ScaleError(f"publisher {role} did not emit exactly one {case} fixture")
            item = matching[0]
            source_id = canonical_identifier(
                item.get("source_id", ""), f"publisher {role} {case} source ID"
            )
            expected_digest = _payload_digest(role, case)
            if (
                item.get("topic") != topic
                or item.get("priority") != PRIORITY
                or item.get("payload_sha256") != expected_digest
            ):
                raise ScaleError(f"publisher {role} {case} fixture changed exact fields")
            if source_id in all_ids:
                raise ScaleError("hierarchy source fixture IDs were not globally unique")
            all_ids.add(source_id)
            cases[case] = SourceFixture(
                role=role,
                case=case,
                source_id=source_id,
                topic=topic,
                priority=PRIORITY,
                payload_sha256=expected_digest,
            )
        if len(published) != 2:
            raise ScaleError(f"publisher {role} emitted an unexpected source fixture")
        result[role] = cases
    if len(all_ids) != 2 * len(publishers):
        raise ScaleError("offline source fixture set was incomplete")
    return result


def _source_maps(
    sources: Mapping[str, Mapping[str, SourceFixture]],
) -> tuple[dict[str, SourceFixture], dict[str, SourceFixture]]:
    allowed = {item["allowed"].source_id: item["allowed"] for item in sources.values()}
    denied = {item["denied"].source_id: item["denied"] for item in sources.values()}
    if set(allowed) & set(denied):
        raise ScaleError("allowed and denied hierarchy source IDs overlapped")
    return allowed, denied


def validate_root_deliveries(
    logs: str,
    sources: Mapping[str, Mapping[str, SourceFixture]],
    publishers_per_leaf: int,
    *,
    status: str,
    expected_routes: Mapping[str, str] | None = None,
    require_complete: bool = True,
) -> dict[str, str]:
    """Validate exact root deliveries and return source -> durable route IDs."""

    allowed, denied = _source_maps(sources)
    observed: dict[str, str] = {}
    for item in receipt_fields(logs, "BRIDGE_DELIVERY"):
        source_id = item.get("source_id", "")
        if source_id in denied:
            raise ScaleError("root consumer received a topic-denied hierarchy fixture")
        if item.get("status") != status:
            continue
        if source_id not in allowed:
            raise ScaleError("root consumer delivered an unexpected hierarchy source")
        fixture = allowed[source_id]
        leaf = leaf_for_publisher(fixture.role, publishers_per_leaf)
        expected = {
            "hops": "2",
            "origin_scope": f"demo/leaf{leaf:02d}",
            "origin_epoch": str(LEAF_SCOPE_EPOCH),
            "current_scope": "demo/root",
            "current_epoch": str(ROOT_SCOPE_EPOCH),
            "topic": ALLOWED_TOPIC,
            "priority": PRIORITY,
            "payload_sha256": fixture.payload_sha256,
            "payload_opened": "true",
            "payload_plaintext_logged": "false",
        }
        if any(item.get(key) != value for key, value in expected.items()):
            raise ScaleError("root consumer changed authenticated delivery fields")
        route_id = canonical_identifier(item.get("route_id", ""), "root route ID")
        canonical_identifier(item.get("wrapper_id", ""), "root wrapper ID")
        if source_id in observed and observed[source_id] != route_id:
            raise ScaleError("root consumer crossed one source into multiple route IDs")
        if expected_routes is not None and expected_routes.get(source_id) != route_id:
            raise ScaleError("root consumer did not reopen the same durable route")
        observed[source_id] = route_id
    if len(set(observed.values())) != len(observed):
        raise ScaleError("root consumer reused a route ID across source fixtures")
    if require_complete and set(observed) != set(allowed):
        raise ScaleError("root consumer omitted an allowed hierarchy fixture")
    return observed


def _expected_bridge_sources(
    service: str,
    sources: Mapping[str, Mapping[str, SourceFixture]],
    publishers_per_leaf: int,
) -> tuple[dict[str, SourceFixture], int, str]:
    if service in leaf_services():
        leaf = int(service[1:])
        region = region_for_leaf(leaf)
        selected = {
            fixtures["allowed"].source_id: fixtures["allowed"]
            for role, fixtures in sources.items()
            if leaf_for_publisher(role, publishers_per_leaf) == leaf
        }
        return selected, 1, f"demo/region{region:02d}"
    if service in region_services():
        region = int(service[1:])
        selected = {
            fixtures["allowed"].source_id: fixtures["allowed"]
            for role, fixtures in sources.items()
            if region_for_leaf(leaf_for_publisher(role, publishers_per_leaf)) == region
        }
        return selected, 2, "demo/root"
    raise ScaleError("bridge-forward validation received a non-bridge service")


def validate_bridge_forwards(
    logs: Mapping[str, str],
    sources: Mapping[str, Mapping[str, SourceFixture]],
    publishers_per_leaf: int,
    *,
    require_complete: bool = True,
) -> dict[str, object]:
    """Require every leaf/regional forward and summarize bounded dispositions."""

    bridges = (*leaf_services(), *region_services())
    if set(logs) != set(bridges):
        raise ScaleError("bridge logs omitted a route-only hierarchy node")
    allowed, denied = _source_maps(sources)
    dispositions: Counter[str] = Counter()
    unique_forwarded: dict[str, int] = {}
    unique_promoted: dict[str, int] = {}
    receipt_count = 0
    for service in bridges:
        expected_sources, hops, current_scope = _expected_bridge_sources(
            service, sources, publishers_per_leaf
        )
        observed: set[str] = set()
        promoted: set[str] = set()
        for item in receipt_fields(logs[service], "BRIDGE"):
            source_id = item.get("source_id", "")
            if source_id in denied:
                raise ScaleError("a topic-denied fixture crossed a hierarchy edge")
            if source_id not in allowed:
                raise ScaleError(f"bridge {service} named an unexpected hierarchy source")
            if source_id not in expected_sources:
                raise ScaleError(f"bridge {service} forwarded a source from another branch")
            fixture = allowed[source_id]
            leaf = leaf_for_publisher(fixture.role, publishers_per_leaf)
            status = item.get("status", "")
            if status not in {"forwarded", "not-selected"}:
                raise ScaleError(f"bridge {service} emitted an unknown route status")
            expected = {
                "hops": str(hops),
                "origin_scope": f"demo/leaf{leaf:02d}",
                "origin_epoch": str(LEAF_SCOPE_EPOCH),
                "current_scope": current_scope,
                "current_epoch": str(
                    LEAF_COUNT + region_for_leaf(leaf) + 1
                    if service in leaf_services()
                    else ROOT_SCOPE_EPOCH
                ),
                "payload_opened": "false",
                "payload_plaintext_logged": "false",
            }
            if any(item.get(key) != value for key, value in expected.items()):
                raise ScaleError(f"bridge {service} changed correlated forward metadata")
            canonical_identifier(item.get("route_id", ""), "bridge route ID")
            canonical_identifier(item.get("wrapper_id", ""), "bridge wrapper ID")
            disposition = item.get("disposition", "")
            if disposition not in {
                "promoted",
                "duplicate",
                "stored-inactive",
                "not-selected",
            }:
                raise ScaleError("bridge receipt contained an unknown disposition")
            dispositions[disposition] += 1
            receipt_count += 1
            if status == "not-selected":
                if disposition != "not-selected":
                    raise ScaleError("not-selected bridge status changed its disposition")
                continue
            if disposition == "not-selected":
                raise ScaleError("forwarded bridge status carried not-selected disposition")
            observed.add(source_id)
            if disposition == "promoted":
                promoted.add(source_id)
        if require_complete and (
            observed != set(expected_sources) or promoted != set(expected_sources)
        ):
            raise ScaleError(f"bridge {service} omitted a uniquely promoted source route")
        unique_forwarded[service] = len(observed)
        unique_promoted[service] = len(promoted)
    expected_regional = LEAVES_PER_REGION * publishers_per_leaf
    if require_complete and any(
        unique_forwarded[service] != expected_regional for service in region_services()
    ):
        raise ScaleError("regional bridge omitted a branch route")
    return {
        "receiptCount": receipt_count,
        "dispositions": dict(sorted(dispositions.items())),
        "uniqueForwardedByBridge": dict(sorted(unique_forwarded.items())),
        "uniquePromotedByBridge": dict(sorted(unique_promoted.items())),
        "regionalRoutesEach": expected_regional,
        "beyondEightRouteContactBatch": expected_regional > 8,
    }


def validate_payload_blind_logs(logs: Mapping[str, str]) -> None:
    expected = {*leaf_services(), *region_services()}
    if set(logs) != expected:
        raise ScaleError("payload-blind audit omitted a route-only bridge")
    if PAYLOAD_SENTINEL_PREFIX in "\n".join(logs.values()):
        raise ScaleError("a route-only bridge log exposed fixture payload plaintext")


def _integer_field(item: Mapping[str, str], key: str) -> int:
    raw = item.get(key, "0")
    try:
        value = int(raw)
    except ValueError as error:
        raise ScaleError(f"CONTACT receipt contained malformed {key}") from error
    if value < 0:
        raise ScaleError(f"CONTACT receipt contained negative {key}")
    return value


def _connected(nodes: set[str], edges: set[tuple[str, str]]) -> bool:
    if not nodes:
        return False
    adjacency: dict[str, set[str]] = defaultdict(set)
    for left, right in edges:
        adjacency[left].add(right)
        adjacency[right].add(left)
    visited: set[str] = set()
    frontier = [next(iter(nodes))]
    while frontier:
        node = frontier.pop()
        if node in visited:
            continue
        visited.add(node)
        frontier.extend((adjacency[node] & nodes) - visited)
    return visited == nodes


def contact_graph_summary(
    logs: Mapping[str, str],
    identities: Mapping[str, ReadyIdentity],
    publishers_per_leaf: int,
) -> dict[str, object]:
    """Validate the exact per-segment time-unioned authenticated contact graph."""

    services = live_services(publishers_per_leaf)
    authorized = set(authorized_services(publishers_per_leaf))
    if set(logs) != set(services) or set(identities) != set(services):
        raise ScaleError("contact graph evidence omitted a hierarchy node")
    carriers = {identity.carrier: service for service, identity in identities.items()}
    if len(carriers) != len(identities):
        raise ScaleError("contact carrier identity map was ambiguous")
    interfaces = service_interfaces(publishers_per_leaf)
    members = segment_members(publishers_per_leaf)
    candidate_edges: set[tuple[str, str]] = set()
    pass_edges: set[tuple[str, str]] = set()
    per_segment_pass: dict[str, set[tuple[str, str]]] = defaultdict(set)
    per_segment_candidates: dict[str, set[tuple[str, str]]] = defaultdict(set)
    candidates = 0
    passes = 0
    errors: Counter[str] = Counter()
    contact_bridge = Counter()
    outsider_rejection = False

    def shared_segment(local: str, remote: str) -> str:
        shared = set(interfaces[local]) & set(interfaces[remote])
        if len(shared) != 1:
            raise ScaleError("contact evidence escaped exact hierarchy segment wiring")
        return next(iter(shared))

    for local, text in logs.items():
        reject_node_error(text, local)
        for item in receipt_fields(text, "DISCOVERY"):
            status = item.get("status", "")
            if status == "dropped" and item.get("reason") == "candidate-limit":
                raise ScaleError("automatic discovery exceeded its candidate bound")
            if status != "candidate":
                continue
            remote = carriers.get(item.get("carrier_peer", ""))
            if remote is None or remote == local:
                raise ScaleError("automatic discovery retained an unknown carrier")
            segment = shared_segment(local, remote)
            edge = tuple(sorted((local, remote)))
            candidate_edges.add(edge)
            per_segment_candidates[segment].add(edge)
            candidates += 1
        for item in receipt_fields(text, "CONTACT"):
            status = item.get("status", "")
            error = item.get("error", "")
            if "capacity%20reached" in error or "admission%20capacity" in error:
                raise ScaleError("automatic mission admission exceeded its capacity bound")
            remote = carriers.get(item.get("carrier_peer", ""))
            if status == "pass":
                if remote is None or remote == local:
                    raise ScaleError("authenticated contact named an unknown carrier")
                if local == "outsider" or remote == "outsider":
                    raise ScaleError("outsider completed an authenticated contact")
                if local not in authorized or remote not in authorized:
                    raise ScaleError("authenticated contact escaped the mission cohort")
                segment = shared_segment(local, remote)
                edge = tuple(sorted((local, remote)))
                pass_edges.add(edge)
                per_segment_pass[segment].add(edge)
                passes += 1
                for key in ("bridge_offered", "bridge_applied", "bridge_delivered"):
                    contact_bridge[key] += _integer_field(item, key)
            elif status == "error":
                category = error.split("%20", 1)[0] if error else "unknown"
                errors[category] += 1
                if remote is not None:
                    segment = shared_segment(local, remote)
                    if (
                        segment == "root"
                        and (local == "outsider") != (remote == "outsider")
                        and error.startswith("mission%20authentication")
                    ):
                        outsider_rejection = True

    if not outsider_rejection:
        raise ScaleError("outsider did not produce a correlated mission rejection")
    segment_summary: dict[str, object] = {}
    for segment, all_members in members.items():
        mission_members = set(all_members) - {"outsider"}
        pass_for_segment = per_segment_pass[segment]
        candidate_for_segment = per_segment_candidates[segment]
        if not _connected(mission_members, pass_for_segment):
            raise ScaleError(f"authenticated contact graph for {segment} was disconnected")
        if not _connected(mission_members, candidate_for_segment):
            raise ScaleError(f"automatic discovery graph for {segment} was disconnected")
        segment_summary[segment] = {
            "missionNodes": len(mission_members),
            "authenticatedEdges": len(pass_for_segment),
            "candidateEdges": len(candidate_for_segment),
            "connected": True,
        }
    if not _connected(authorized, pass_edges):
        raise ScaleError("complete hierarchy authenticated contact graph was disconnected")
    if not candidate_edges or not pass_edges:
        raise ScaleError("hierarchy retained no discovery or authenticated contact evidence")
    return {
        "candidateReceipts": candidates,
        "authenticatedPassReceipts": passes,
        "errorReceiptsByCategory": dict(sorted(errors.items())),
        "candidateEdges": len(candidate_edges),
        "authenticatedEdges": len(pass_edges),
        "connected": True,
        "outsiderAuthenticatedPasses": 0,
        "outsiderMissionRejection": True,
        "contactBridgeCounts": dict(sorted(contact_bridge.items())),
        "segments": dict(sorted(segment_summary.items())),
    }


def validate_route_recovery(
    logs: str,
    sources: Mapping[str, Mapping[str, SourceFixture]],
    publishers_per_leaf: int,
    expected_routes: Mapping[str, str],
) -> dict[str, str]:
    """Require every exact route and delivery to reopen without any peer."""

    allowed, denied = _source_maps(sources)
    restored: dict[str, str] = {}
    for item in receipt_fields(logs, "BRIDGE_RESTORE"):
        source_id = item.get("source_id", "")
        if source_id in denied:
            raise ScaleError("root consumer restored a denied hierarchy route")
        if source_id not in allowed or item.get("status") != "pass":
            continue
        route_id = canonical_identifier(item.get("route_id", ""), "restored route ID")
        canonical_identifier(item.get("wrapper_id", ""), "restored wrapper ID")
        if item.get("active") != "true" or expected_routes.get(source_id) != route_id:
            raise ScaleError("root consumer changed a restored route")
        restored[source_id] = route_id
    if restored != dict(expected_routes):
        raise ScaleError("root consumer omitted an exact durable route on restart")
    recovered = validate_root_deliveries(
        logs,
        sources,
        publishers_per_leaf,
        status="recovered",
        expected_routes=expected_routes,
        require_complete=True,
    )
    if recovered != dict(expected_routes):
        raise ScaleError("root consumer omitted a recovered delivery")
    return recovered


def run_parallel(
    services: Sequence[str],
    operation: Callable[[str], T],
    label: str,
) -> dict[str, T]:
    if not services:
        raise ScaleError(f"{label} received an empty service set")
    if len(set(services)) != len(services):
        raise ScaleError(f"{label} received duplicate services")
    results: dict[str, T] = {}
    with ThreadPoolExecutor(max_workers=min(32, len(services))) as executor:
        futures = {executor.submit(operation, service): service for service in services}
        try:
            for future in as_completed(futures):
                service = futures[future]
                results[service] = future.result()
        except Exception as error:
            for future in futures:
                future.cancel()
            if isinstance(error, ScaleError):
                raise
            raise ScaleError(f"{label} worker failed") from error
    if set(results) != set(services):
        raise ScaleError(f"{label} omitted a hierarchy node")
    return results


def collect_logs(
    compose: Compose,
    services: Sequence[str],
    deadline: Deadline,
    label: str,
) -> dict[str, str]:
    timeout = deadline.command_timeout(20, label)
    return run_parallel(
        services,
        lambda service: compose.logs(service, timeout=timeout),
        label,
    )


def ensure_running(
    compose: Compose,
    services: Sequence[str],
    deadline: Deadline,
    label: str,
) -> dict[str, str]:
    records = compose.ps(
        services,
        all_states=False,
        timeout=deadline.command_timeout(20, label),
    )
    return validate_service_records(records, services, expected_state="running")


def wait_for_ready(
    compose: Compose,
    services: Sequence[str],
    deadline: Deadline,
    *,
    discovery: bool,
) -> tuple[dict[str, ReadyIdentity], dict[str, str]]:
    while True:
        logs = collect_logs(compose, services, deadline, "concurrent node readiness")
        identities: dict[str, ReadyIdentity] = {}
        for service in services:
            reject_node_error(logs[service], service)
            has_hierarchy = any(
                item.get("status") == "started" and item.get("role") == service
                for item in receipt_fields(logs[service], "HIERARCHY_READY")
            )
            has_selected = any(
                item.get("selected") == "true"
                for item in receipt_fields(logs[service], "READY")
            )
            if has_hierarchy and has_selected:
                identities[service] = parse_ready_identity(
                    logs[service], service, discovery=discovery
                )
        if len(identities) == len(services):
            return identities, logs
        ensure_running(compose, services, deadline, "readiness exit audit")
        time.sleep(min(0.5, deadline.remaining("node readiness")))


def start_services(
    compose: Compose,
    services: Sequence[str],
    deadline: Deadline,
    *,
    discovery: bool,
) -> tuple[float, dict[str, str]]:
    if not services or not set(services).issubset(compose.service_set):
        raise ScaleError("startup received an invalid hierarchy service set")
    compose.run(
        (
            "create",
            "--no-build",
            "--force-recreate",
            *services,
        ),
        timeout=deadline.command_timeout(180, "concurrent container creation"),
        discovery=discovery,
    )
    validate_service_records(
        compose.ps(
            services,
            all_states=True,
            timeout=deadline.command_timeout(20, "created container audit"),
        ),
        services,
        expected_state="created",
    )
    started = time.monotonic()
    compose.run(
        ("start", *services),
        timeout=deadline.command_timeout(180, "concurrent hierarchy startup"),
        discovery=discovery,
    )
    containers = ensure_running(compose, services, deadline, "startup exit audit")
    return started, containers


def stop_services(
    compose: Compose,
    services: Sequence[str],
    deadline: Deadline,
) -> None:
    compose.run(
        ("stop", "--timeout", "15", *services),
        timeout=deadline.command_timeout(180, "clean hierarchy stop"),
    )
    logs = collect_logs(compose, services, deadline, "clean STOP receipt collection")
    for service in services:
        stops = receipt_fields(logs[service], "STOP")
        if not any(item.get("lifecycle") == "complete" for item in stops):
            raise ScaleError(f"node {service} did not emit a clean STOP receipt")
    validate_service_records(
        compose.ps(
            services,
            all_states=True,
            timeout=deadline.command_timeout(20, "stopped container audit"),
        ),
        services,
        expected_state="exited",
    )


def wait_for_source_fixtures(
    compose: Compose,
    publishers_per_leaf: int,
    deadline: Deadline,
) -> tuple[dict[str, dict[str, SourceFixture]], dict[str, str]]:
    publishers = publisher_services(publishers_per_leaf)
    while True:
        logs = collect_logs(compose, publishers, deadline, "offline source fixtures")
        ready = True
        for service in publishers:
            reject_node_error(logs[service], service)
            cases = {
                item.get("case")
                for item in receipt_fields(logs[service], "HIERARCHY_SCALE_SOURCE")
                if item.get("status") == "published" and item.get("role") == service
            }
            if cases != {"allowed", "denied"}:
                ready = False
        if ready:
            return validate_source_receipts(logs, publishers_per_leaf), logs
        ensure_running(compose, publishers, deadline, "offline publisher exit audit")
        time.sleep(min(0.5, deadline.remaining("offline source fixtures")))


def wait_for_root_deliveries(
    compose: Compose,
    services: Sequence[str],
    sources: Mapping[str, Mapping[str, SourceFixture]],
    publishers_per_leaf: int,
    deadline: Deadline,
) -> tuple[dict[str, str], str]:
    allowed, _denied = _source_maps(sources)
    while True:
        logs = compose.logs(
            "root-consumer",
            timeout=deadline.command_timeout(20, "root delivery receipts"),
        )
        observed = validate_root_deliveries(
            logs,
            sources,
            publishers_per_leaf,
            status="delivered",
            require_complete=False,
        )
        if set(observed) == set(allowed):
            return (
                validate_root_deliveries(
                    logs,
                    sources,
                    publishers_per_leaf,
                    status="delivered",
                    require_complete=True,
                ),
                logs,
            )
        ensure_running(compose, services, deadline, "delivery exit audit")
        time.sleep(min(0.75, deadline.remaining("root delivery receipts")))


def wait_for_bridge_forwards(
    compose: Compose,
    sources: Mapping[str, Mapping[str, SourceFixture]],
    publishers_per_leaf: int,
    deadline: Deadline,
) -> tuple[dict[str, object], dict[str, str]]:
    bridges = (*leaf_services(), *region_services())
    while True:
        logs = collect_logs(compose, bridges, deadline, "bridge-forward receipts")
        summary = validate_bridge_forwards(
            logs,
            sources,
            publishers_per_leaf,
            require_complete=False,
        )
        expected = {
            **{service: publishers_per_leaf for service in leaf_services()},
            **{
                service: LEAVES_PER_REGION * publishers_per_leaf
                for service in region_services()
            },
        }
        forwarded = summary["uniqueForwardedByBridge"]
        promoted = summary["uniquePromotedByBridge"]
        if forwarded == expected and promoted == expected:
            return (
                validate_bridge_forwards(
                    logs,
                    sources,
                    publishers_per_leaf,
                    require_complete=True,
                ),
                logs,
            )
        ensure_running(compose, bridges, deadline, "bridge-forward exit audit")
        time.sleep(min(0.75, deadline.remaining("bridge-forward receipts")))


def _merge_contact_history(early: str, later: str) -> str:
    """Preserve rotated discovery/contact evidence without snapshot duplication."""

    later_lines = set(later.splitlines())
    historical = [
        line
        for line in early.splitlines()
        if ("DISCOVERY " in line or "CONTACT " in line) and line not in later_lines
    ]
    return "\n".join((*historical, later))


_SIZE_UNITS = {
    "B": 1,
    "kB": 1000,
    "MB": 1000**2,
    "GB": 1000**3,
    "TB": 1000**4,
    "KiB": 1024,
    "MiB": 1024**2,
    "GiB": 1024**3,
    "TiB": 1024**4,
}
_SIZE_RE = re.compile(
    r"([0-9]+(?:\.[0-9]+)?)(B|kB|MB|GB|TB|KiB|MiB|GiB|TiB)\Z"
)


def parse_docker_size(raw: str) -> int:
    match = _SIZE_RE.fullmatch(raw.strip())
    if match is None:
        raise ScaleError("Docker stats returned a malformed byte quantity")
    value = int(round(float(match.group(1)) * _SIZE_UNITS[match.group(2)]))
    if value < 0:
        raise ScaleError("Docker stats returned a negative byte quantity")
    return value


def parse_io_pair(raw: str) -> tuple[int, int]:
    parts = [item.strip() for item in raw.split("/")]
    if len(parts) != 2:
        raise ScaleError("Docker stats returned a malformed I/O pair")
    return parse_docker_size(parts[0]), parse_docker_size(parts[1])


def parse_stats_records(raw: str) -> list[dict[str, object]]:
    if len(raw.encode("utf-8", errors="replace")) > MAX_RETAINED_OUTPUT:
        raise ScaleError("Docker stats output exceeded its parser bound")
    records: list[dict[str, object]] = []
    for line in raw.splitlines():
        if not line.strip():
            continue
        try:
            item = json.loads(line)
        except (json.JSONDecodeError, UnicodeError) as error:
            raise ScaleError("Docker stats returned malformed JSON") from error
        if not isinstance(item, dict):
            raise ScaleError("Docker stats returned a non-object record")
        records.append(item)
    if not records or len(records) > 128:
        raise ScaleError("Docker stats returned an invalid record count")
    return records


def resource_snapshot(
    docker: Docker,
    containers: Mapping[str, str],
    deadline: Deadline,
    label: str,
) -> dict[str, object]:
    raw = docker.run(
        (
            "stats",
            "--no-stream",
            "--no-trunc",
            "--format",
            "json",
            *containers.values(),
        ),
        timeout=deadline.command_timeout(30, f"{label} resource snapshot"),
    )
    by_id = {container_id: service for service, container_id in containers.items()}

    def service_for(raw_id: str) -> str:
        matches = [
            service
            for container_id, service in by_id.items()
            if raw_id == container_id
            or raw_id.startswith(container_id)
            or container_id.startswith(raw_id)
        ]
        if len(matches) != 1:
            raise ScaleError("Docker stats returned an unowned container")
        return matches[0]

    observed: dict[str, dict[str, float | int]] = {}
    for item in parse_stats_records(raw):
        service = service_for(str(item.get("ID") or item.get("Container") or ""))
        try:
            cpu_text = str(item["CPUPerc"]).strip()
            if not cpu_text.endswith("%"):
                raise ValueError
            cpu = float(cpu_text[:-1])
            memory, _memory_limit = parse_io_pair(str(item["MemUsage"]))
            network_rx, network_tx = parse_io_pair(str(item["NetIO"]))
            pids = int(item["PIDs"])
        except (KeyError, TypeError, ValueError) as error:
            raise ScaleError("Docker stats returned malformed resource fields") from error
        if cpu < 0 or pids < 0 or service in observed:
            raise ScaleError("Docker stats returned invalid or duplicate resources")
        observed[service] = {
            "cpuPercent": cpu,
            "memoryBytes": memory,
            "pids": pids,
            "networkRxBytes": network_rx,
            "networkTxBytes": network_tx,
        }
    if set(observed) != set(containers):
        raise ScaleError("Docker stats omitted a hierarchy container")
    aggregate = {
        "cpuPercent": sum(float(item["cpuPercent"]) for item in observed.values()),
        **{
            key: sum(int(item[key]) for item in observed.values())
            for key in ("memoryBytes", "pids", "networkRxBytes", "networkTxBytes")
        },
    }
    maxima = {
        "cpuPercent": max(float(item["cpuPercent"]) for item in observed.values()),
        **{
            key: max(int(item[key]) for item in observed.values())
            for key in ("memoryBytes", "pids")
        },
    }
    return {
        "label": label,
        "containers": len(observed),
        "aggregate": aggregate,
        "maxPerNode": maxima,
        "measurementBoundary": (
            "one Docker cgroup/container-interface sample; cumulative network I/O; "
            "not host RSS, physical-wire bytes, energy, or a target-tier threshold"
        ),
    }


def bridge_receipt_counts(logs: Mapping[str, str]) -> Counter[str]:
    counts: Counter[str] = Counter()
    for text in logs.values():
        for item in receipt_fields(text, "BRIDGE"):
            disposition = item.get("disposition", "unknown")
            counts[disposition] += 1
    return counts


def _progress(message: str) -> None:
    print(f"aster-hierarchy-scale-compose: {message}", file=sys.stderr, flush=True)


def _wait_for_recovery(
    compose: Compose,
    sources: Mapping[str, Mapping[str, SourceFixture]],
    publishers_per_leaf: int,
    expected_routes: Mapping[str, str],
    deadline: Deadline,
) -> tuple[dict[str, str], str]:
    expected = set(expected_routes)
    while True:
        logs = compose.logs(
            "root-consumer",
            timeout=deadline.command_timeout(20, "peerless route recovery"),
        )
        reject_node_error(logs, "root-consumer")
        restored = {
            item.get("source_id", "")
            for item in receipt_fields(logs, "BRIDGE_RESTORE")
            if item.get("status") == "pass" and item.get("active") == "true"
        }
        recovered = {
            item.get("source_id", "")
            for item in receipt_fields(logs, "BRIDGE_DELIVERY")
            if item.get("status") == "recovered"
        }
        if restored == expected and recovered == expected:
            return (
                validate_route_recovery(
                    logs,
                    sources,
                    publishers_per_leaf,
                    expected_routes,
                ),
                logs,
            )
        if not restored.issubset(expected) or not recovered.issubset(expected):
            raise ScaleError("peerless restart emitted an unexpected route receipt")
        ensure_running(
            compose,
            ("root-consumer",),
            deadline,
            "peerless recovery exit audit",
        )
        time.sleep(min(0.5, deadline.remaining("peerless route recovery")))


def run_case(
    compose: Compose,
    publishers_per_leaf: int,
    flow_seconds: int,
    settle_seconds: int,
) -> dict[str, object]:
    value = validate_publishers_per_leaf(publishers_per_leaf)
    publishers = publisher_services(value)
    services = live_services(value)
    bridges = (*leaf_services(), *region_services())
    total_publishers = len(publishers)
    warnings: list[str] = []

    compose.run(("config", "--quiet"), timeout=20)
    compose.run(("version",), timeout=20)
    _progress("building the hierarchy demo image (cached after the first run)")
    compose.run(("build", "init"), timeout=1_800)

    deadline = Deadline(flow_seconds)
    phase_started = time.monotonic()
    _progress(
        f"provisioning {total_publishers} publishers across eight leaves and two regions"
    )
    init_logs = compose.run(
        ("run", "--rm", "--no-deps", "init"),
        timeout=deadline.command_timeout(240, "networkless hierarchy provisioning"),
    )
    init_receipt = validate_init_receipt(init_logs, value)
    provision_seconds = time.monotonic() - phase_started

    _progress("staging every publisher once with automatic discovery disabled")
    staging_started, _staging_containers = start_services(
        compose, publishers, deadline, discovery=False
    )
    staged_identities, _staging_ready_logs = wait_for_ready(
        compose, publishers, deadline, discovery=False
    )
    if len({item.carrier for item in staged_identities.values()}) != len(publishers):
        raise ScaleError("offline publishers did not have distinct carrier identities")
    if len({item.authority for item in staged_identities.values()}) != 1:
        raise ScaleError("offline publishers did not share one mission authority")
    sources, _source_logs = wait_for_source_fixtures(compose, value, deadline)
    stage_publish_seconds = time.monotonic() - staging_started
    stop_services(compose, publishers, deadline)

    _progress("starting every live hierarchy node concurrently with rosterless mDNS")
    live_started, containers = start_services(
        compose, services, deadline, discovery=True
    )
    identities, early_logs = wait_for_ready(
        compose, services, deadline, discovery=True
    )
    validate_identity_cohort(identities, value, discovery=True)
    for publisher in publishers:
        staged = staged_identities[publisher]
        live = identities[publisher]
        if (staged.carrier, staged.mission, staged.authority) != (
            live.carrier,
            live.mission,
            live.authority,
        ):
            raise ScaleError(f"publisher {publisher} changed durable identity after staging")
    startup_seconds = time.monotonic() - live_started

    _progress("waiting for every selected route at the root consumer")
    routes, _delivery_logs = wait_for_root_deliveries(
        compose, services, sources, value, deadline
    )
    delivery_seconds = time.monotonic() - live_started
    bridge_summary, bridge_before_logs = wait_for_bridge_forwards(
        compose, sources, value, deadline
    )
    before_counts = bridge_receipt_counts(bridge_before_logs)
    convergence_logs = collect_logs(
        compose, services, deadline, "convergence evidence snapshot"
    )

    resource_snapshots: list[dict[str, object]] = []
    try:
        resource_snapshots.append(
            resource_snapshot(
                compose.docker,
                containers,
                deadline,
                "post-convergence",
            )
        )
    except ScaleError:
        warnings.append("docker-resource-snapshot-unavailable")

    if deadline.remaining("post-convergence settle window") < settle_seconds:
        raise ScaleError("hard flow deadline cannot cover the selected settle window")
    _progress("sampling one short post-convergence duplicate-offer window")
    settle_started = time.monotonic()
    time.sleep(settle_seconds)
    settle_elapsed = time.monotonic() - settle_started
    ensure_running(compose, services, deadline, "post-convergence exit audit")
    late_logs = collect_logs(compose, services, deadline, "final live evidence audit")
    graph_logs = {
        service: _merge_contact_history(
            _merge_contact_history(early_logs[service], convergence_logs[service]),
            late_logs[service],
        )
        for service in services
    }
    graph = contact_graph_summary(graph_logs, identities, value)
    bridge_after_logs = {service: late_logs[service] for service in bridges}
    bridge_summary = validate_bridge_forwards(
        bridge_after_logs,
        sources,
        value,
        require_complete=True,
    )
    validate_payload_blind_logs(bridge_after_logs)
    validate_root_deliveries(
        late_logs["root-consumer"],
        sources,
        value,
        status="delivered",
        expected_routes=routes,
        require_complete=True,
    )
    after_counts = bridge_receipt_counts(bridge_after_logs)
    duplicate_delta = max(
        0, after_counts.get("duplicate", 0) - before_counts.get("duplicate", 0)
    )
    total_offer_delta = max(0, sum(after_counts.values()) - sum(before_counts.values()))
    if duplicate_delta:
        warnings.append("post-convergence-duplicate-offers")
    try:
        resource_snapshots.append(
            resource_snapshot(compose.docker, containers, deadline, "post-settle")
        )
    except ScaleError:
        if "docker-resource-snapshot-unavailable" not in warnings:
            warnings.append("docker-resource-snapshot-unavailable")

    _progress("stopping every live peer before root-only durable recovery")
    stop_services(compose, services, deadline)
    restart_started, _restart_containers = start_services(
        compose, ("root-consumer",), deadline, discovery=False
    )
    restart_identities, _restart_ready_logs = wait_for_ready(
        compose, ("root-consumer",), deadline, discovery=False
    )
    before_restart = identities["root-consumer"]
    after_restart = restart_identities["root-consumer"]
    if (
        before_restart.carrier,
        before_restart.mission,
        before_restart.authority,
    ) != (
        after_restart.carrier,
        after_restart.mission,
        after_restart.authority,
    ):
        raise ScaleError("root consumer changed durable identity across restart")
    recovered, _recovery_logs = _wait_for_recovery(
        compose, sources, value, routes, deadline
    )
    restart_seconds = time.monotonic() - restart_started
    stop_services(compose, ("root-consumer",), deadline)

    convergence_values = [delivery_seconds, startup_seconds]
    return {
        "schema": "aster-hierarchy-scale-compose/v1",
        "status": "pass",
        "publishersPerLeaf": value,
        "publishers": total_publishers,
        "liveNodes": len(services),
        "segments": NETWORK_COUNT,
        "fixtures": {
            "allowed": len(routes),
            "denied": total_publishers,
            "allSourceIdsUnique": True,
        },
        "timingSeconds": {
            "provision": provision_seconds,
            "offlineStage": stage_publish_seconds,
            "liveStartup": startup_seconds,
            "allRootRoutes": delivery_seconds,
            "postConvergenceSettle": settle_elapsed,
            "rootOnlyRestart": restart_seconds,
            "flowTotal": deadline.elapsed(),
            "hardDeadline": flow_seconds,
            "maxObservedConvergencePhase": max(convergence_values),
        },
        "capacity": capacity_summary(value),
        "contactGraph": graph,
        "bridge": bridge_summary,
        "postConvergence": {
            "windowSeconds": settle_seconds,
            "duplicateOfferDelta": duplicate_delta,
            "totalOfferReceiptDelta": total_offer_delta,
            "correctnessGate": False,
        },
        "resources": {
            "snapshots": resource_snapshots,
            "available": bool(resource_snapshots),
        },
        "restart": {
            "discovery": "disabled",
            "peersRunning": 0,
            "exactRoutesRecovered": len(recovered),
            "routeIdsStable": recovered == routes,
            "identityStable": True,
        },
        "initializer": {
            "disposition": init_receipt["disposition"],
            "networkMode": "none",
        },
        "runtimeControls": {
            "syncIntervalMs": 1_000,
            "tokioWorkerThreads": 1,
            "nearbyWindowSeconds": 3,
            "tierSweep": False,
            "tierRetry": False,
        },
        "host": {
            "os": platform.system(),
            "arch": platform.machine(),
            "logicalCpus": os.cpu_count(),
        },
        "diagnosticWarnings": sorted(set(warnings)),
        "boundary": (
            "single-host generated Docker hierarchy with eleven private bridge "
            "segments and NAT egress; same implementation; Event only; deterministic "
            "unprotected reference provisioning and sampled container diagnostics; not "
            "physical, hostile, WAN/NAT traversal, dynamic membership, target-resource, "
            "fault-tolerance, security-ceremony, or production-capacity evidence"
        ),
    }


def validate_cleanup_target(project: str, image: str) -> None:
    if PROJECT_RE.fullmatch(project) is None or image != f"{project}:local":
        raise ScaleError("cleanup target was not the exact hierarchy-scale project")


def audit_cleanup(docker: Docker, project: str, image: str) -> None:
    validate_cleanup_target(project, image)
    label = f"label=com.docker.compose.project={project}"
    checks = (
        ("container", ("ps", "--all", "--quiet", "--filter", label)),
        ("volume", ("volume", "ls", "--quiet", "--filter", label)),
        ("network", ("network", "ls", "--quiet", "--filter", label)),
    )
    for kind, arguments in checks:
        if docker.run(arguments, timeout=20).strip():
            raise ScaleError(f"cleanup left a project-scoped {kind}")
    if docker.run(("image", "ls", "--quiet", "--no-trunc", image), timeout=20).strip():
        raise ScaleError("cleanup left the uniquely named hierarchy-scale image")


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Run one bounded generated Docker Compose hierarchy-scale diagnostic"
    )
    parser.add_argument(
        "--publishers-per-leaf",
        type=int,
        choices=ALLOWED_PUBLISHERS_PER_LEAF,
        default=1,
    )
    parser.add_argument(
        "--deadline-seconds",
        type=int,
        help="one post-build hard deadline (tier default, 60..=600 seconds)",
    )
    parser.add_argument(
        "--settle-seconds",
        type=int,
        default=DEFAULT_SETTLE_SECONDS,
        help="post-convergence diagnostic window (2..=15 seconds)",
    )
    parser.add_argument(
        "--config-only",
        action="store_true",
        help="validate the generated topology without contacting Docker",
    )
    return parser


def _interrupt(_signum: int, _frame: object) -> None:
    raise KeyboardInterrupt


def main(argv: Sequence[str] | None = None) -> int:
    arguments = build_parser().parse_args(argv)
    try:
        value = validate_publishers_per_leaf(arguments.publishers_per_leaf)
        flow_seconds = (
            arguments.deadline_seconds
            if arguments.deadline_seconds is not None
            else DEFAULT_FLOW_SECONDS[value]
        )
        if not MIN_FLOW_SECONDS <= flow_seconds <= MAX_FLOW_SECONDS:
            raise ScaleError("flow deadline must be between 60 and 600 seconds")
        if not 2 <= arguments.settle_seconds <= 15:
            raise ScaleError("settle window must be between 2 and 15 seconds")
    except ScaleError as error:
        print(f"aster-hierarchy-scale-compose: {error}", file=sys.stderr)
        return 2

    signal.signal(signal.SIGINT, _interrupt)
    signal.signal(signal.SIGTERM, _interrupt)
    with tempfile.TemporaryDirectory(
        prefix="aster-hierarchy-scale-compose-"
    ) as directory:
        compose_file = write_compose_model(Path(directory), value)
        if arguments.config_only:
            print(
                json.dumps(
                    {
                        "schema": "aster-hierarchy-scale-compose-config/v1",
                        "status": "pass",
                        "publishersPerLeaf": value,
                        "publishers": len(publisher_services(value)),
                        "liveNodes": len(live_services(value)),
                        "segments": NETWORK_COUNT,
                        "capacity": capacity_summary(value),
                    },
                    sort_keys=True,
                )
            )
            return 0

        executable = shutil.which("docker")
        if executable is None:
            print("aster-hierarchy-scale-compose: docker was not found", file=sys.stderr)
            return 2
        docker = Docker(str(Path(executable).resolve()))
        project = project_name()
        services = live_services(value)
        compose = Compose(docker, compose_file, project, services)
        cleanup_needed = False
        exit_code = 0
        result: dict[str, object] | None = None
        try:
            compose.run(("config", "--quiet"), timeout=20)
            try:
                compose.run(("ps",), timeout=20)
            except ScaleError as error:
                raise ScaleError(
                    "Docker daemon access is required; ensure the current user can "
                    "access the configured Docker socket"
                ) from error
            cleanup_needed = True
            result = run_case(
                compose,
                value,
                flow_seconds,
                arguments.settle_seconds,
            )
        except ScaleError as error:
            print(f"aster-hierarchy-scale-compose: {error}", file=sys.stderr)
            exit_code = 2
        except KeyboardInterrupt:
            print("aster-hierarchy-scale-compose: interrupted", file=sys.stderr)
            exit_code = 130
        finally:
            if cleanup_needed:
                try:
                    validate_cleanup_target(project, compose.image)
                    compose.run(
                        (
                            "down",
                            "--volumes",
                            "--remove-orphans",
                            "--rmi",
                            "all",
                            "--timeout",
                            "15",
                        ),
                        timeout=240,
                    )
                    audit_cleanup(docker, project, compose.image)
                except ScaleError as error:
                    print(
                        f"aster-hierarchy-scale-compose: cleanup warning: {error}",
                        file=sys.stderr,
                    )
                    exit_code = 2
        if result is not None and exit_code == 0:
            print(json.dumps(result, indent=2, sort_keys=True))
        return exit_code


if __name__ == "__main__":
    raise SystemExit(main())
