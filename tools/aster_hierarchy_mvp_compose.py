#!/usr/bin/env python3
# Copyright 2026 Defense Unicorns, Inc.
# SPDX-License-Identifier: Apache-2.0
"""Run the bounded, segmented Docker hierarchy MVP rehearsal.

The proof is intentionally small: five processes, three distinct Docker bridge
segments, rosterless discovery, two authenticated hierarchy hops, one allowed
Event, two policy-negative Events, a foreign-authority peer, and one peerless
consumer restart.  The dedicated demo node owns deterministic provisioning
and fixture publication; this controller only orchestrates and validates
receipts.
"""

from __future__ import annotations

import argparse
import base64
import hashlib
import json
import os
from pathlib import Path
import re
import secrets
import signal
import shutil
import subprocess
import sys
import tempfile
import time
from typing import Callable, Mapping, Sequence, TypeVar


ROOT = Path(__file__).resolve().parents[1]
COMPOSE_FILE = ROOT / "docker" / "hierarchy-mvp" / "compose.yaml"
MAX_RETAINED_OUTPUT = 2 * 1024 * 1024
PROJECT_RE = re.compile(r"aster-hierarchy-mvp-[0-9]+-[0-9a-f]{8}\Z")
HEX_DIGEST_RE = re.compile(r"[0-9a-f]{64}\Z")
SERVICES = (
    "publisher",
    "bridge-alpha",
    "bridge-bravo",
    "consumer",
    "outsider",
)
INIT_SERVICE = "init"
ALL_SERVICES = (*SERVICES, INIT_SERVICE)
MISSION_SERVICES = SERVICES[:-1]
EXPECTED_NETWORKS = {
    "publisher": {"alpha"},
    "bridge-alpha": {"alpha", "parent"},
    "bridge-bravo": {"parent", "bravo"},
    "consumer": {"bravo"},
    "outsider": {"parent"},
}
EXPECTED_INTERFACE_ADDRESSES = {
    "publisher": {"alpha": "172.30.251.10"},
    "bridge-alpha": {
        "alpha": "172.30.251.11",
        "parent": "172.30.252.11",
    },
    "bridge-bravo": {
        "parent": "172.30.252.12",
        "bravo": "172.30.253.12",
    },
    "consumer": {"bravo": "172.30.253.13"},
    "outsider": {"parent": "172.30.252.14"},
}
EXPECTED_NETWORK_SUBNETS = {
    "alpha": "172.30.251.0/24",
    "parent": "172.30.252.0/24",
    "bravo": "172.30.253.0/24",
}
ADJACENCIES = (
    ("publisher", "bridge-alpha"),
    ("bridge-alpha", "bridge-bravo"),
    ("bridge-bravo", "consumer"),
)
ALLOWED_TOPIC = "mesh.allowed"
DENIED_TOPIC = "mesh.denied"
ALLOWED_PRIORITY = "immediate"
DENIED_PRIORITY = "routine"
ALLOWED_PAYLOAD = "HIERARCHY_ALLOWED_PAYLOAD_SENTINEL_4f923b"
DENIED_TOPIC_PAYLOAD = "HIERARCHY_DENIED_TOPIC_SENTINEL_81f2a0"
DENIED_PRIORITY_PAYLOAD = "HIERARCHY_DENIED_PRIORITY_SENTINEL_6d35cc"
FIXTURES = {
    "allowed": (ALLOWED_TOPIC, ALLOWED_PRIORITY, ALLOWED_PAYLOAD),
    "denied-topic": (DENIED_TOPIC, ALLOWED_PRIORITY, DENIED_TOPIC_PAYLOAD),
    "denied-priority": (ALLOWED_TOPIC, DENIED_PRIORITY, DENIED_PRIORITY_PAYLOAD),
}
MIN_FLOW_DEADLINE_SECONDS = 60
MAX_FLOW_DEADLINE_SECONDS = 300
DEFAULT_FLOW_DEADLINE_SECONDS = 180
DENIAL_SETTLE_SECONDS = 2.0
T = TypeVar("T")


class SmokeError(RuntimeError):
    """Expected, sanitized hierarchy rehearsal failure."""


class Deadline:
    """One monotonic hard deadline shared by every post-build operation."""

    def __init__(
        self,
        seconds: float,
        clock: Callable[[], float] = time.monotonic,
    ) -> None:
        if not MIN_FLOW_DEADLINE_SECONDS <= seconds <= MAX_FLOW_DEADLINE_SECONDS:
            raise SmokeError("flow deadline must be between 60 and 300 seconds")
        self._clock = clock
        self._end = clock() + seconds

    def remaining(self, label: str) -> float:
        remaining = self._end - self._clock()
        if remaining <= 0:
            raise SmokeError(f"hard flow deadline expired while waiting for {label}")
        return remaining

    def command_timeout(self, maximum: float, label: str) -> float:
        return max(0.1, min(maximum, self.remaining(label)))


def project_name(pid: int | None = None, suffix: str | None = None) -> str:
    value = f"aster-hierarchy-mvp-{pid or os.getpid()}-{suffix or secrets.token_hex(4)}"
    if PROJECT_RE.fullmatch(value) is None:
        raise SmokeError("failed to construct a bounded Compose project name")
    return value


def discovery_environment(enabled: Sequence[str]) -> dict[str, str]:
    selected = set(enabled)
    if not selected.issubset(SERVICES):
        raise SmokeError("unknown hierarchy node in discovery phase")
    environment = dict(os.environ)
    for service in SERVICES:
        key = service.upper().replace("-", "_")
        environment[f"ASTER_{key}_DISCOVER_LAN"] = (
            "1" if service in selected else "0"
        )
    return environment


def _read_retained(stream) -> str:
    size = stream.tell()
    if size > MAX_RETAINED_OUTPUT:
        stream.seek(size - MAX_RETAINED_OUTPUT)
        prefix = "[earlier command output omitted]\n"
    else:
        stream.seek(0)
        prefix = ""
    return prefix + stream.read(MAX_RETAINED_OUTPUT).decode("utf-8", errors="replace")


class Compose:
    """Bounded subprocess wrapper for one exact Compose project."""

    def __init__(self, docker: str, project: str):
        candidate = Path(docker)
        if not candidate.is_absolute() or candidate.name != "docker":
            raise SmokeError("Docker executable must be an absolute path named docker")
        if PROJECT_RE.fullmatch(project) is None:
            raise SmokeError("invalid Compose project name")
        self.image = f"{project}:local"
        self.prefix = (
            str(candidate),
            "compose",
            "--file",
            str(COMPOSE_FILE),
            "--project-name",
            project,
        )

    def run(
        self,
        arguments: Sequence[str],
        *,
        timeout: float,
        environment: Mapping[str, str] | None = None,
    ) -> str:
        command = [*self.prefix, *arguments]
        run_environment = (
            dict(environment) if environment is not None else dict(os.environ)
        )
        run_environment["ASTER_HIERARCHY_MVP_IMAGE"] = self.image
        with tempfile.TemporaryFile() as stdout, tempfile.TemporaryFile() as stderr:
            try:
                completed = subprocess.run(
                    command,
                    cwd=ROOT,
                    env=run_environment,
                    stdin=subprocess.DEVNULL,
                    stdout=stdout,
                    stderr=stderr,
                    timeout=timeout,
                    check=False,
                )
            except subprocess.TimeoutExpired as error:
                raise SmokeError(
                    f"Compose command timed out after {timeout:.0f} seconds: "
                    f"{arguments[0]}"
                ) from error
            out = _read_retained(stdout)
            err = _read_retained(stderr)
        if completed.returncode != 0:
            detail = (err or out).strip()
            if len(detail) > 2_000:
                detail = detail[-2_000:]
            raise SmokeError(
                f"Compose command failed ({arguments[0]}, exit "
                f"{completed.returncode}): {detail or 'no diagnostic'}"
            )
        return out

    def logs(
        self,
        services: Sequence[str],
        *,
        timeout: float = 15,
    ) -> str:
        if not services or not set(services).issubset(ALL_SERVICES):
            raise SmokeError("invalid hierarchy service log selection")
        return self.run(
            ("logs", "--no-color", "--tail", "2000", *services),
            timeout=timeout,
        )


def _progress(message: str) -> None:
    print(f"aster-hierarchy-mvp-compose: {message}", file=sys.stderr, flush=True)


def _json_object(raw: str, label: str) -> dict[str, object]:
    try:
        value = json.loads(raw)
    except (json.JSONDecodeError, UnicodeError) as error:
        raise SmokeError(f"{label} returned malformed JSON") from error
    if not isinstance(value, dict):
        raise SmokeError(f"{label} returned a non-object JSON value")
    return value


def _network_names(service: Mapping[str, object]) -> set[str]:
    value = service.get("networks", {})
    if isinstance(value, dict):
        return {str(name) for name in value}
    if isinstance(value, list):
        return {str(name) for name in value}
    raise SmokeError("Compose service networks have an unexpected shape")


def validate_compose_topology(raw: str) -> None:
    """Require the exact five-node, three-bridge membership graph."""

    document = _json_object(raw, "Compose config")
    services = document.get("services")
    networks = document.get("networks")
    if not isinstance(services, dict) or not isinstance(networks, dict):
        raise SmokeError("Compose config omitted services or networks")
    if set(services) != set(ALL_SERVICES):
        raise SmokeError("Compose config changed the five-node plus initializer set")
    for service, expected in EXPECTED_NETWORKS.items():
        config = services.get(service)
        if not isinstance(config, dict) or _network_names(config) != expected:
            raise SmokeError(f"Compose service {service} changed network membership")
        if config.get("ports") or config.get("extra_hosts") or config.get("network_mode"):
            raise SmokeError(f"Compose service {service} exposed an unplanned network path")
        environment = config.get("environment")
        if not isinstance(environment, dict) or environment.get(
            "ASTER_HIERARCHY_ROLE"
        ) != service:
            raise SmokeError(f"Compose service {service} changed its demo role")
        local_interfaces = EXPECTED_INTERFACE_ADDRESSES[service]
        advertised = environment.get("ASTER_NEARBY_IPV4_INTERFACES")
        if advertised != ",".join(local_interfaces.values()):
            raise SmokeError(
                f"Compose service {service} changed its local discovery interfaces"
            )
        network_config = config.get("networks")
        if not isinstance(network_config, dict) or any(
            not isinstance(network_config.get(network), dict)
            or network_config[network].get("ipv4_address") != address
            for network, address in local_interfaces.items()
        ):
            raise SmokeError(
                f"Compose service {service} local interface selection is inconsistent"
            )
        mounts = config.get("volumes")
        if not isinstance(mounts, list) or len(mounts) != 1:
            raise SmokeError(f"Compose service {service} changed durable state mounts")
        mount = mounts[0]
        if not isinstance(mount, dict) or mount.get("target") != "/state":
            raise SmokeError(f"Compose service {service} omitted its /state volume")
        depends_on = config.get("depends_on")
        if not isinstance(depends_on, dict) or INIT_SERVICE not in depends_on:
            raise SmokeError(f"Compose service {service} no longer waits for initialization")
    initializer = services.get(INIT_SERVICE)
    if not isinstance(initializer, dict) or initializer.get("network_mode") != "none":
        raise SmokeError("Compose initializer is not networkless")
    if initializer.get("networks") or initializer.get("ports") or initializer.get("extra_hosts"):
        raise SmokeError("Compose initializer exposed an unplanned network path")
    init_mounts = initializer.get("volumes")
    expected_targets = {f"/provision/{service}" for service in SERVICES}
    if not isinstance(init_mounts, list) or {
        str(mount.get("target", ""))
        for mount in init_mounts
        if isinstance(mount, dict)
    } != expected_targets:
        raise SmokeError("Compose initializer changed its five provisioning volumes")
    if set(networks) != {"alpha", "parent", "bravo"}:
        raise SmokeError("Compose config changed the exact hierarchy network set")
    for name, config in networks.items():
        ipam = config.get("ipam") if isinstance(config, dict) else None
        ipam_config = ipam.get("config") if isinstance(ipam, dict) else None
        if (
            not isinstance(config, dict)
            or config.get("driver") != "bridge"
            or config.get("internal") is True
            or not isinstance(ipam_config, list)
            or len(ipam_config) != 1
            or not isinstance(ipam_config[0], dict)
            or ipam_config[0].get("subnet") != EXPECTED_NETWORK_SUBNETS[name]
        ):
            raise SmokeError(
                f"Compose network {name} is not a discovery-compatible bridge"
            )
    if EXPECTED_NETWORKS["publisher"] & EXPECTED_NETWORKS["consumer"]:
        raise SmokeError("publisher and consumer unexpectedly share a network")


def receipt_fields(logs: str, receipt: str) -> list[dict[str, str]]:
    records: list[dict[str, str]] = []
    marker = re.compile(rf"(?:^|[|\s]){re.escape(receipt)}\s+(.*)$")
    for line in logs.splitlines():
        match = marker.search(line)
        if match is None:
            continue
        fields: dict[str, str] = {}
        for item in match.group(1).split():
            key, separator, value = item.partition("=")
            if separator and key and key not in fields:
                fields[key] = value
        records.append(fields)
    return records


def _canonical_id(value: str, label: str) -> str:
    if re.fullmatch(r"[0-9a-f]{64}", value) is not None:
        return value
    try:
        decoded = base64.b64decode(value, validate=True)
    except (ValueError, UnicodeError) as error:
        raise SmokeError(f"{label} is not a canonical identifier") from error
    if len(decoded) != 32 or base64.b64encode(decoded).decode("ascii") != value:
        raise SmokeError(f"{label} is not a canonical 32-byte identifier")
    return value


def _payload_digest(payload: str) -> str:
    return hashlib.sha256(payload.encode("utf-8")).hexdigest()


def ready_identity(
    logs: str,
    label: str,
    *,
    discovery: str | None = None,
) -> tuple[str, str]:
    ready = [
        fields
        for fields in receipt_fields(logs, "READY")
        if fields.get("selected") == "true"
    ]
    if not ready:
        raise SmokeError(f"{label} did not emit a selected READY receipt")
    latest = ready[-1]
    carrier = latest.get("carrier_id", "")
    authority = latest.get("mission_authority", "")
    if not carrier or not authority:
        raise SmokeError(f"{label} READY receipt omitted identity fields")
    observed_discovery = latest.get("nearby_discovery", "")
    if discovery == "enabled" and observed_discovery not in {
        "enabled",
        "active",
        "active-evaluation",
    }:
        raise SmokeError(f"{label} READY receipt did not enable discovery")
    if discovery == "disabled" and observed_discovery != "disabled":
        raise SmokeError(f"{label} READY receipt did not disable discovery")
    return carrier, authority


def reject_node_error(logs: str, label: str) -> None:
    errors = [
        fields
        for fields in receipt_fields(logs, "HIERARCHY_DEMO")
        if fields.get("status") == "error"
    ]
    if errors:
        detail = errors[-1].get("error", "unspecified")
        raise SmokeError(f"{label} failed before readiness: {detail}")


def validate_authority_partition(
    identities: Mapping[str, tuple[str, str]],
) -> None:
    if set(identities) != set(SERVICES):
        raise SmokeError("authority partition omitted a hierarchy node")
    carriers = {identity[0] for identity in identities.values()}
    if len(carriers) != len(SERVICES):
        raise SmokeError("hierarchy nodes did not have distinct carrier identities")
    mission_authorities = {identities[service][1] for service in MISSION_SERVICES}
    if len(mission_authorities) != 1:
        raise SmokeError("publisher, bridges, and consumer did not share one authority")
    if identities["outsider"][1] in mission_authorities:
        raise SmokeError("outsider unexpectedly shared the hierarchy authority")


def outsider_contact_rejected(
    logs: Mapping[str, str],
    identities: Mapping[str, tuple[str, str]],
) -> bool:
    outsider_carrier = identities["outsider"][0]
    bridge_carriers = {
        identities["bridge-alpha"][0],
        identities["bridge-bravo"][0],
    }
    expected = {
        "bridge-alpha": {outsider_carrier},
        "bridge-bravo": {outsider_carrier},
        "outsider": bridge_carriers,
    }
    rejection_seen = False
    for local, peers in expected.items():
        for contact in receipt_fields(logs[local], "CONTACT"):
            if contact.get("carrier_peer") not in peers:
                continue
            if contact.get("status") == "pass":
                raise SmokeError("outsider completed an authenticated hierarchy contact")
            if contact.get("status") == "error" and contact.get("error", "").startswith(
                "mission%20authentication"
            ):
                rejection_seen = True
    return rejection_seen


def validate_source_receipts(logs: str) -> dict[str, dict[str, str]]:
    published = [
        fields
        for fields in receipt_fields(logs, "BRIDGE_SOURCE")
        if fields.get("status") == "published"
    ]
    result: dict[str, dict[str, str]] = {}
    for case, (topic, priority, payload) in FIXTURES.items():
        matches = [fields for fields in published if fields.get("case") == case]
        if len(matches) != 1:
            raise SmokeError(f"publisher did not emit exactly one {case} source receipt")
        fields = matches[0]
        source_id = _canonical_id(fields.get("source_id", ""), f"{case} source ID")
        digest = fields.get("payload_sha256", "")
        if fields.get("topic") != topic or fields.get("priority") != priority:
            raise SmokeError(f"publisher {case} receipt changed fixture policy fields")
        if HEX_DIGEST_RE.fullmatch(digest) is None or digest != _payload_digest(payload):
            raise SmokeError(f"publisher {case} receipt changed fixture payload hash")
        result[case] = dict(fields, source_id=source_id)
    if len({fields["source_id"] for fields in result.values()}) != len(FIXTURES):
        raise SmokeError("publisher fixture source identifiers were not distinct")
    return result


def _matching_receipt(
    logs: str,
    receipt: str,
    expected: Mapping[str, str],
) -> dict[str, str] | None:
    for fields in receipt_fields(logs, receipt):
        if all(fields.get(key) == value for key, value in expected.items()):
            return fields
    return None


def validate_forward_receipt(
    logs: str,
    *,
    service: str,
    source_id: str,
    hops: int,
    scope: str,
) -> dict[str, str]:
    receipt = _matching_receipt(
        logs,
        "BRIDGE",
        {
            "status": "forwarded",
            "source_id": source_id,
            "hops": str(hops),
            "current_scope": scope,
        },
    )
    if receipt is None:
        raise SmokeError(f"{service} omitted its correlated forward receipt")
    if receipt.get("payload_opened") != "false":
        raise SmokeError(f"{service} did not prove payload-blind forwarding")
    return receipt


def validate_delivery_receipt(
    logs: str,
    source: Mapping[str, str],
    *,
    status: str,
    label: str,
    expected_route_id: str | None = None,
) -> dict[str, str]:
    receipt = _matching_receipt(
        logs,
        "BRIDGE_DELIVERY",
        {"status": status, "source_id": source["source_id"]},
    )
    if receipt is None:
        raise SmokeError(f"{label} omitted the correlated delivery receipt")
    expected = {
        "hops": "2",
        "origin_scope": "demo/alpha",
        "current_scope": "demo/bravo",
        "topic": ALLOWED_TOPIC,
        "priority": ALLOWED_PRIORITY,
        "payload_sha256": source["payload_sha256"],
    }
    if any(receipt.get(key) != value for key, value in expected.items()):
        raise SmokeError(f"{label} changed authenticated delivery fields")
    route_id = _canonical_id(receipt.get("route_id", ""), f"{label} route ID")
    _canonical_id(receipt.get("wrapper_id", ""), f"{label} wrapper ID")
    if expected_route_id is not None and route_id != expected_route_id:
        raise SmokeError(f"{label} did not reopen the same durable route")
    return receipt


def validate_denials(
    consumer_logs: str,
    outsider_logs: str,
    sources: Mapping[str, Mapping[str, str]],
) -> None:
    denied = {
        sources["denied-topic"]["source_id"],
        sources["denied-priority"]["source_id"],
    }
    consumer_deliveries = receipt_fields(consumer_logs, "BRIDGE_DELIVERY")
    if any(delivery.get("source_id") in denied for delivery in consumer_deliveries):
        raise SmokeError("consumer received a topic- or priority-denied Event")
    all_sources = {fields["source_id"] for fields in sources.values()}
    outsider_deliveries = receipt_fields(outsider_logs, "BRIDGE_DELIVERY")
    if any(delivery.get("source_id") in all_sources for delivery in outsider_deliveries):
        raise SmokeError("outsider received a hierarchy fixture Event")


def validate_payload_blind_logs(logs: Mapping[str, str]) -> None:
    combined = "\n".join(logs[service] for service in ("bridge-alpha", "bridge-bravo"))
    for payload in (
        ALLOWED_PAYLOAD,
        DENIED_TOPIC_PAYLOAD,
        DENIED_PRIORITY_PAYLOAD,
    ):
        if payload in combined:
            raise SmokeError("a route-only bridge log exposed fixture payload plaintext")


def validate_stopped_services(raw: str, services: Sequence[str]) -> None:
    try:
        document = json.loads(raw)
        records = document if isinstance(document, list) else [document]
    except (json.JSONDecodeError, UnicodeError):
        try:
            records = [json.loads(line) for line in raw.splitlines() if line.strip()]
        except (json.JSONDecodeError, UnicodeError) as error:
            raise SmokeError("Compose ps returned malformed JSON") from error
    if not all(isinstance(record, dict) for record in records):
        raise SmokeError("Compose ps returned an invalid service list")
    expected = set(services)
    actual = {str(record.get("Service", "")) for record in records}
    if actual != expected or len(records) != len(expected):
        raise SmokeError("Compose ps omitted or duplicated a stopped hierarchy node")
    for record in records:
        service = str(record["Service"])
        if str(record.get("State", "")).lower() != "exited" or record.get(
            "ExitCode"
        ) not in (0, "0"):
            raise SmokeError(f"node {service} did not exit cleanly after STOP")


def _wait_until(deadline: Deadline, label: str, predicate: Callable[[], bool]) -> None:
    while True:
        if predicate():
            return
        remaining = deadline.remaining(label)
        time.sleep(min(0.5, remaining))


def _wait_value(
    deadline: Deadline,
    label: str,
    producer: Callable[[], T | None],
) -> T:
    value: T | None = None

    def observed() -> bool:
        nonlocal value
        value = producer()
        return value is not None

    _wait_until(deadline, label, observed)
    if value is None:
        raise SmokeError(f"{label} completed without evidence")
    return value


def _logs(compose: Compose, service: str, deadline: Deadline, label: str) -> str:
    return compose.logs(
        (service,),
        timeout=deadline.command_timeout(8, label),
    )


def wait_ready(
    compose: Compose,
    service: str,
    deadline: Deadline,
    *,
    discovery: str,
) -> tuple[str, str]:
    def observed() -> tuple[str, str] | None:
        logs = _logs(compose, service, deadline, f"{service} readiness")
        reject_node_error(logs, service)
        started = _matching_receipt(
            logs,
            "HIERARCHY_READY",
            {"status": "started", "role": service},
        )
        if not receipt_fields(logs, "READY") or started is None:
            return None
        return ready_identity(
            logs,
            service,
            discovery=discovery,
        )

    return _wait_value(deadline, f"{service} readiness", observed)


def wait_for_peer_evidence(
    compose: Compose,
    left: str,
    right: str,
    identities: Mapping[str, tuple[str, str]],
    deadline: Deadline,
) -> None:
    def observed() -> bool:
        pair = (
            (
                _logs(compose, left, deadline, f"{left}/{right} discovery"),
                identities[right][0],
            ),
            (
                _logs(compose, right, deadline, f"{left}/{right} contact"),
                identities[left][0],
            ),
        )
        candidate = any(
            receipt.get("status") == "candidate"
            and receipt.get("carrier_peer") == remote
            for logs, remote in pair
            for receipt in receipt_fields(logs, "DISCOVERY")
        )
        contact = any(
            receipt.get("status") == "pass"
            and receipt.get("carrier_peer") == remote
            for logs, remote in pair
            for receipt in receipt_fields(logs, "CONTACT")
        )
        return candidate and contact

    _wait_until(deadline, f"correlated {left}/{right} discovery and contact", observed)


def wait_for_outsider_rejection(
    compose: Compose,
    identities: Mapping[str, tuple[str, str]],
    deadline: Deadline,
) -> None:
    def rejected() -> bool:
        logs = {
            service: _logs(compose, service, deadline, "outsider rejection")
            for service in ("bridge-alpha", "bridge-bravo", "outsider")
        }
        return outsider_contact_rejected(logs, identities)

    _wait_until(deadline, "carrier-correlated outsider rejection", rejected)


def wait_for_receipt(
    compose: Compose,
    service: str,
    receipt: str,
    expected: Mapping[str, str],
    deadline: Deadline,
) -> dict[str, str]:
    def observed() -> dict[str, str] | None:
        logs = _logs(compose, service, deadline, f"{service} {receipt} receipt")
        return _matching_receipt(logs, receipt, expected)

    return _wait_value(deadline, f"{service} {receipt} receipt", observed)


def up(
    compose: Compose,
    services: Sequence[str],
    discovery: Sequence[str],
    deadline: Deadline,
    *,
    include_dependencies: bool,
) -> dict[str, tuple[str, str]]:
    dependency_flag: tuple[str, ...] = () if include_dependencies else ("--no-deps",)
    compose.run(
        (
            "up",
            "--detach",
            "--no-build",
            *dependency_flag,
            "--force-recreate",
            *services,
        ),
        timeout=deadline.command_timeout(60, "Compose startup"),
        environment=discovery_environment(discovery),
    )
    return {
        service: wait_ready(
            compose,
            service,
            deadline,
            discovery=("enabled" if service in discovery else "disabled"),
        )
        for service in services
    }


def stop(compose: Compose, services: Sequence[str], deadline: Deadline) -> None:
    compose.run(
        ("stop", "--timeout", "15", *services),
        timeout=deadline.command_timeout(45, "clean node stop"),
    )
    for service in services:
        stops = receipt_fields(
            _logs(compose, service, deadline, f"{service} STOP receipt"),
            "STOP",
        )
        if not any(receipt.get("lifecycle") == "complete" for receipt in stops):
            raise SmokeError(f"node {service} did not emit a clean STOP receipt")
    validate_stopped_services(
        compose.run(
            ("ps", "--all", "--format", "json", *services),
            timeout=deadline.command_timeout(15, "stopped service audit"),
        ),
        services,
    )


def run_smoke(compose: Compose, flow_seconds: int) -> dict[str, object]:
    rendered = compose.run(("config", "--format", "json"), timeout=15)
    validate_compose_topology(rendered)
    compose.run(("version",), timeout=15)
    _progress("building the dedicated hierarchy demo node (cached after the first run)")
    compose.run(("build", INIT_SERVICE), timeout=1_800)

    flow = Deadline(flow_seconds)
    _progress(
        "starting five nodes with rosterless discovery on three distinct Docker bridge segments"
    )
    identities = up(
        compose,
        SERVICES,
        SERVICES,
        flow,
        include_dependencies=True,
    )
    wait_for_receipt(
        compose,
        INIT_SERVICE,
        "HIERARCHY_INIT",
        {"status": "pass", "nodes": "5", "authorities": "2", "edges": "2"},
        flow,
    )
    validate_authority_partition(identities)

    for left, right in ADJACENCIES:
        wait_for_peer_evidence(compose, left, right, identities, flow)
    wait_for_outsider_rejection(compose, identities, flow)

    _progress("waiting for the allowed and two policy-negative source fixtures")

    def sources_ready() -> dict[str, dict[str, str]] | None:
        logs = _logs(compose, "publisher", flow, "source publication")
        cases = {
            fields.get("case")
            for fields in receipt_fields(logs, "BRIDGE_SOURCE")
            if fields.get("status") == "published"
        }
        return validate_source_receipts(logs) if cases == set(FIXTURES) else None

    sources = _wait_value(flow, "three source fixtures", sources_ready)
    allowed = sources["allowed"]

    wait_for_receipt(
        compose,
        "bridge-alpha",
        "BRIDGE",
        {"status": "forwarded", "source_id": allowed["source_id"]},
        flow,
    )
    wait_for_receipt(
        compose,
        "bridge-bravo",
        "BRIDGE",
        {"status": "forwarded", "source_id": allowed["source_id"]},
        flow,
    )
    wait_for_receipt(
        compose,
        "consumer",
        "BRIDGE_DELIVERY",
        {"status": "delivered", "source_id": allowed["source_id"]},
        flow,
    )
    if flow.remaining("policy-negative settle window") < DENIAL_SETTLE_SECONDS:
        raise SmokeError("hard flow deadline cannot cover policy-negative settle window")
    time.sleep(DENIAL_SETTLE_SECONDS)

    logs = {
        service: _logs(compose, service, flow, f"{service} evidence audit")
        for service in SERVICES
    }
    validate_forward_receipt(
        logs["bridge-alpha"],
        service="bridge-alpha",
        source_id=allowed["source_id"],
        hops=1,
        scope="demo/parent",
    )
    validate_forward_receipt(
        logs["bridge-bravo"],
        service="bridge-bravo",
        source_id=allowed["source_id"],
        hops=2,
        scope="demo/bravo",
    )
    delivery = validate_delivery_receipt(
        logs["consumer"],
        allowed,
        status="delivered",
        label="consumer delivery",
    )
    validate_denials(logs["consumer"], logs["outsider"], sources)
    validate_payload_blind_logs(logs)
    outsider_contact_rejected(logs, identities)

    _progress("stopping every peer before the consumer restart")
    stop(compose, SERVICES, flow)
    _progress("restarting only consumer with discovery disabled")
    restart_identity = up(
        compose,
        ("consumer",),
        (),
        flow,
        include_dependencies=False,
    )["consumer"]
    if restart_identity != identities["consumer"]:
        raise SmokeError("consumer restart changed its durable identity")
    wait_for_receipt(
        compose,
        "consumer",
        "BRIDGE_RESTORE",
        {
            "status": "pass",
            "source_id": allowed["source_id"],
            "route_id": delivery["route_id"],
            "active": "true",
        },
        flow,
    )
    wait_for_receipt(
        compose,
        "consumer",
        "BRIDGE_DELIVERY",
        {"status": "recovered", "source_id": allowed["source_id"]},
        flow,
    )
    restart_logs = _logs(compose, "consumer", flow, "peerless consumer reopen")
    reopened = validate_delivery_receipt(
        restart_logs,
        allowed,
        status="recovered",
        label="peerless consumer reopen",
        expected_route_id=delivery["route_id"],
    )
    validate_denials(restart_logs, logs["outsider"], sources)
    stop(compose, ("consumer",), flow)

    return {
        "schema": "aster-hierarchy-mvp-compose-smoke/v1",
        "status": "pass",
        "allowedEventId": allowed["source_id"],
        "deniedTopicEventId": sources["denied-topic"]["source_id"],
        "deniedPriorityEventId": sources["denied-priority"]["source_id"],
        "routeId": delivery["route_id"],
        "restartRouteId": reopened["route_id"],
        "checks": [
            "three-distinct-docker-bridge-segments",
            "rosterless-adjacent-mdns-discovery",
            "mission-authenticated-alpha-parent-bravo",
            "two-hop-allowed-event-delivery",
            "topic-and-priority-non-delivery-after-settle",
            "route-only-payload-open-denial",
            "foreign-authority-rejection",
            "peerless-consumer-restore-after-restart",
        ],
        "boundary": (
            "three distinct single-host Docker bridge segments with NAT egress; same "
            "implementation; Event only; "
            "deterministic demo provisioning; not physical, hostile, WAN/NAT, "
            "bridged-scale, or production evidence"
        ),
    }


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Run the bounded Docker Compose Aster hierarchy MVP rehearsal"
    )
    parser.add_argument(
        "--config-only",
        action="store_true",
        help="validate Compose interpolation/topology without contacting the daemon",
    )
    parser.add_argument(
        "--deadline-seconds",
        type=int,
        default=DEFAULT_FLOW_DEADLINE_SECONDS,
        help="hard post-build flow deadline (60..=300 seconds)",
    )
    return parser


def _interrupt(_signum: int, _frame: object) -> None:
    raise KeyboardInterrupt


def main(argv: Sequence[str] | None = None) -> int:
    arguments = build_parser().parse_args(argv)
    if not (
        MIN_FLOW_DEADLINE_SECONDS
        <= arguments.deadline_seconds
        <= MAX_FLOW_DEADLINE_SECONDS
    ):
        print(
            "aster-hierarchy-mvp-compose: --deadline-seconds must be 60..=300",
            file=sys.stderr,
        )
        return 2
    signal.signal(signal.SIGINT, _interrupt)
    signal.signal(signal.SIGTERM, _interrupt)
    docker = shutil.which("docker")
    if docker is None:
        print("aster-hierarchy-mvp-compose: docker was not found", file=sys.stderr)
        return 2
    compose = Compose(str(Path(docker).resolve()), project_name())
    cleanup_needed = False
    result: dict[str, object] | None = None
    exit_code = 0
    try:
        if arguments.config_only:
            rendered = compose.run(("config", "--format", "json"), timeout=15)
            validate_compose_topology(rendered)
            result = {
                "schema": "aster-hierarchy-mvp-compose-config/v1",
                "status": "pass",
                "composeFile": str(COMPOSE_FILE.relative_to(ROOT)),
                "liveServices": list(SERVICES),
                "networks": sorted(
                    {name for names in EXPECTED_NETWORKS.values() for name in names}
                ),
                "runtimeWiring": "aster-hierarchy-demo-node",
            }
        else:
            cleanup_needed = True
            result = run_smoke(compose, arguments.deadline_seconds)
    except KeyboardInterrupt:
        print("aster-hierarchy-mvp-compose: interrupted", file=sys.stderr)
        exit_code = 130
    except SmokeError as error:
        print(f"aster-hierarchy-mvp-compose: {error}", file=sys.stderr)
        exit_code = 2
    finally:
        if cleanup_needed:
            try:
                compose.run(
                    (
                        "down",
                        "--remove-orphans",
                        "--volumes",
                        "--rmi",
                        "local",
                        "--timeout",
                        "15",
                    ),
                    timeout=120,
                )
            except SmokeError as error:
                print(
                    f"aster-hierarchy-mvp-compose: cleanup warning: {error}",
                    file=sys.stderr,
                )
                result = None
                if exit_code == 0:
                    exit_code = 2
    if exit_code == 0 and result is not None:
        print(json.dumps(result, indent=2, sort_keys=True))
    return exit_code


if __name__ == "__main__":
    raise SystemExit(main())
