#!/usr/bin/env python3
# Copyright 2026 Defense Unicorns, Inc.
# SPDX-License-Identifier: Apache-2.0
"""Live, human-readable presentation for the retained Aster capability tours.

The structured CLI output remains the authority.  This module writes every byte
to the requested receipt before interpreting it for display.  Rendering is a
disposable view over that receipt and never decides whether the demo passed.
"""

from __future__ import annotations

import argparse
from dataclasses import dataclass, field
import os
from pathlib import Path
import queue
import re
import shlex
import shutil
import signal
import subprocess
import sys
import threading
import time
from typing import Callable, Optional, Sequence
from urllib.parse import unquote


SPINNER = ("⠋", "⠙", "⠹", "⠸", "⠼", "⠴", "⠦", "⠧", "⠇", "⠏")
ASCII_SPINNER = ("|", "/", "-", "\\")
ANSI_RESET = "\x1b[0m"
ANSI_BOLD = "\x1b[1m"
ANSI_DIM = "\x1b[2m"
ANSI_RED = "\x1b[31m"
ANSI_GREEN = "\x1b[32m"
ANSI_CYAN = "\x1b[36m"
ANSI_MAGENTA = "\x1b[35m"


def safe_text(value: str, limit: Optional[int] = None) -> str:
    """Remove terminal controls from untrusted receipt fields."""

    cleaned = "".join(
        character if character.isprintable() and character != "\x1b" else "?"
        for character in value
    )
    if limit is not None and len(cleaned) > limit:
        if limit <= 1:
            return cleaned[:limit]
        return f"{cleaned[: limit - 1]}…"
    return cleaned


def decode_field(value: str) -> str:
    return safe_text(unquote(value))


def counted(value: str, singular: str, plural: Optional[str] = None) -> str:
    plural = plural or f"{singular}s"
    return f"{value} {singular if value == '1' else plural}"


def supports_unicode(stream: object = sys.stdout) -> bool:
    encoding = getattr(stream, "encoding", None) or "ascii"
    try:
        "✓⠋─".encode(encoding)
    except (LookupError, UnicodeEncodeError):
        return False
    return True


def terminal_text(value: str, unicode: bool) -> str:
    if unicode:
        return value
    replacements = {
        "✓": "PASS",
        "✗": "FAIL",
        "·": "|",
        "→": "->",
        "…": "...",
        "━": "=",
        "─": "-",
    }
    for source, replacement in replacements.items():
        value = value.replace(source, replacement)
    return value.encode("ascii", errors="replace").decode("ascii")


def print_terminal(value: str = "", *, file: Optional[object] = None) -> bool:
    """Best-effort presentation that cannot replace a retained child status."""

    destination = sys.stdout if file is None else file
    try:
        print(value, file=destination, flush=True)
    except (BrokenPipeError, OSError, UnicodeError):
        return False
    return True


@dataclass(frozen=True)
class Receipt:
    kind: str
    fields: dict[str, str]
    text: str


def parse_receipt(data: bytes) -> Receipt:
    text = data.decode("utf-8", errors="replace").rstrip("\r\n")
    tokens = text.split()
    if not tokens:
        return Receipt("", {}, text)
    fields: dict[str, str] = {}
    for token in tokens[1:]:
        if "=" not in token:
            continue
        key, value = token.split("=", 1)
        if key:
            fields[key] = value
    return Receipt(safe_text(tokens[0], 40), fields, safe_text(text, 500))


def receipt_value(
    receipt: Receipt, key: str, default: str = "?", limit: int = 100
) -> str:
    return safe_text(receipt.fields.get(key, default), limit)


def receipt_succeeded(receipt: Receipt) -> bool:
    expected = {
        "SUBSCRIPTIONS": {"seeded"},
        "PHASE": {"pass"},
        "PING": {"received"},
        "PONG": {"received"},
        "RELAY": {"pass", "not-applicable"},
        "CONTROL_RESULT": {"pass"},
        "DEMO_RESULT": {"pass"},
    }
    return receipt_value(receipt, "status") in expected.get(receipt.kind, set())


@dataclass(frozen=True)
class Phase:
    name: str
    label: str
    active_nodes: tuple[int, ...]


@dataclass(frozen=True)
class TourPlan:
    name: str
    title: str
    subtitle: str
    roles: tuple[str, ...]
    phases: tuple[Phase, ...]

    def phase(self, name: str) -> Optional[Phase]:
        return next((phase for phase in self.phases if phase.name == name), None)


def make_plan(name: str, nodes: int) -> TourPlan:
    if name == "control":
        if nodes != 4:
            raise ValueError("the control tour requires exactly four nodes")
        return TourPlan(
            name="control",
            title="Revocation & rekey",
            subtitle="Forward controls without the authority; exclude a captured member",
            roles=("Authority member", "Blind relay", "Survivor", "Captured"),
            phases=(
                Phase("control-authority-seed", "Seed revoke + rekey to relay", (0, 1)),
                Phase(
                    "control-authority-absent-forward",
                    "Forward controls without authority",
                    (1, 2),
                ),
                Phase(
                    "control-authority-absent-publish",
                    "Survivor publishes epoch-2 Ping offline",
                    (2,),
                ),
                Phase(
                    "control-authority-absent-event-forward",
                    "Blind relay receives epoch-2 Ping",
                    (1, 2),
                ),
                Phase(
                    "captured-publication-denied",
                    "Block captured node's stale Ping at the mesh boundary",
                    (2, 3),
                ),
                Phase(
                    "captured-rejoin-denied",
                    "Reject captured node's rejoin",
                    (2, 3),
                ),
                Phase(
                    "pong-ping-forward",
                    "Relay delivers Ping to eligible member",
                    (0, 1),
                ),
                Phase("pong-publish", "Publish causal epoch-2 Pong offline", (0,)),
                Phase(
                    "pong-relay-forward",
                    "Blind relay receives protected Pong",
                    (0, 1),
                ),
                Phase("pong-return", "Relay returns Pong to survivor", (1, 2)),
                Phase("noop", "Restart eligible mesh: nothing left to sync", (0, 1, 2)),
            ),
        )

    if name not in {"quick", "relay"}:
        raise ValueError(f"unknown tour: {name}")
    if nodes < 2:
        raise ValueError("the Ping/Pong tour requires at least two nodes")
    roles = tuple(
        "Origin" if index == 0 else "Responder" if index == nodes - 1 else "Blind relay"
        for index in range(nodes)
    )
    phases: list[Phase] = [Phase("ping-publish", "Publish Ping offline", (0,))]
    for left in range(nodes - 1):
        right = left + 1
        if nodes == 2:
            label = "Deliver Ping to responder"
        elif left == 0:
            label = "Relay receives protected Ping"
        else:
            label = "Relay delivers Ping"
        phases.append(Phase(f"ping-forward-{left}-to-{right}", label, (left, right)))
    phases.append(
        Phase("pong-publish", "Publish causal Pong offline", (nodes - 1,))
    )
    for left in reversed(range(nodes - 1)):
        right = left + 1
        if nodes == 2:
            label = "Return Pong to origin"
        elif right == nodes - 1:
            label = "Relay receives protected Pong"
        else:
            label = "Relay returns Pong"
        phases.append(Phase(f"pong-return-{right}-to-{left}", label, (left, right)))
    phases.append(
        Phase("noop", "Restart: nothing left to sync", tuple(range(nodes)))
    )
    return TourPlan(
        name=name,
        title="Causal Ping / Pong" if name == "quick" else "Payload-blind relay",
        subtitle=(
            "Publish while disconnected, reconnect, restart, and prove a no-op"
            if name == "quick"
            else "Move protected Events through a relay that cannot read them"
        ),
        roles=roles,
        phases=tuple(phases),
    )


@dataclass
class TourState:
    plan: TourPlan
    started_at: float = field(default_factory=time.monotonic)
    subscriptions: Optional[Receipt] = None
    completed: list[str] = field(default_factory=list)
    current_phase: Optional[str] = None
    authority_logs: set[str] = field(default_factory=set)
    ping: Optional[Receipt] = None
    pong: Optional[Receipt] = None
    relay: Optional[Receipt] = None
    control: Optional[Receipt] = None
    result: Optional[Receipt] = None
    unknown: list[Receipt] = field(default_factory=list)
    stderr_tail: list[str] = field(default_factory=list)

    def observe(self, receipt: Receipt) -> None:
        if receipt.kind == "SUBSCRIPTIONS":
            self.subscriptions = receipt
        elif receipt.kind == "PHASE":
            name = receipt_value(receipt, "name", "", 120)
            if receipt_value(receipt, "status") == "pass" and name:
                if self.plan.phase(name) is None:
                    self.unknown.append(receipt)
                elif name not in self.completed:
                    self.completed.append(name)
                if self.current_phase == name:
                    self.current_phase = None
        elif receipt.kind == "PING":
            self.ping = receipt
        elif receipt.kind == "PONG":
            self.pong = receipt
        elif receipt.kind == "RELAY":
            self.relay = receipt
        elif receipt.kind == "CONTROL_RESULT":
            self.control = receipt
        elif receipt.kind == "DEMO_RESULT":
            self.result = receipt
        elif receipt.kind:
            self.unknown.append(receipt)

    def observe_stderr(self, data: bytes) -> None:
        text = safe_text(data.decode("utf-8", errors="replace").rstrip("\r\n"), 300)
        if text:
            self.stderr_tail.append(text)
            self.stderr_tail = self.stderr_tail[-12:]

    def poll_logs(self, root: Path) -> bool:
        logs = root / "logs"
        if not logs.is_dir():
            return False
        changed = False
        for authority in ("authority-revoke.log", "authority-rekey.log"):
            if (logs / authority).exists() and authority not in self.authority_logs:
                self.authority_logs.add(authority)
                changed = True
        next_running = next(
            (
                phase.name
                for phase in self.plan.phases
                if phase.name not in self.completed
                and any(logs.glob(f"{phase.name}-node-*.log"))
            ),
            None,
        )
        if next_running != self.current_phase:
            self.current_phase = next_running
            changed = True
        return changed

    def current_label(self) -> str:
        if self.result is not None:
            status = receipt_value(self.result, "status")
            if status != "pass":
                return f"Terminal result reported status {status}"
            if len(self.completed) != len(self.plan.phases):
                return "Terminal pass receipt retained; phase receipts incomplete"
            return "All terminal invariants reported pass"
        if self.subscriptions is None:
            return "Preparing independent identities and stores"
        if (
            self.plan.name == "control"
            and len(self.completed) == 0
            and self.current_phase is None
            and "authority-rekey.log" not in self.authority_logs
        ):
            return "Commit Flash revocation and recipient-filtered epoch-2 rekey"
        if self.current_phase is not None:
            phase = self.plan.phase(self.current_phase)
            if phase is not None:
                return phase.label
        next_phase = next(
            (phase for phase in self.plan.phases if phase.name not in self.completed), None
        )
        return next_phase.label if next_phase is not None else "Verify final receipts"

    def active_nodes(self) -> tuple[int, ...]:
        if self.current_phase is None:
            return ()
        phase = self.plan.phase(self.current_phase)
        return phase.active_nodes if phase is not None else ()


def resolve_view(requested: str) -> str:
    if requested != "auto":
        return requested
    term = os.environ.get("TERM", "")
    terminal = shutil.get_terminal_size((88, 24))
    if (
        sys.stdout.isatty()
        and term.lower() not in {"", "dumb", "unknown"}
        and terminal.columns >= 48
        and terminal.lines >= 12
    ):
        return "tui"
    return "plain"


def color(text: str, code: str, enabled: bool) -> str:
    return f"{code}{text}{ANSI_RESET}" if enabled else text


def truncate(value: str, width: int) -> str:
    value = safe_text(value)
    if width <= 0:
        return ""
    if len(value) <= width:
        return value
    if width == 1:
        return value[:1]
    return f"{value[: width - 1]}…"


def topology_lines(state: TourState, width: int, unicode: bool) -> list[str]:
    active = set(state.active_nodes())
    nodes: list[str] = []
    for index, role in enumerate(state.plan.roles):
        if index in active:
            marker = "●" if unicode else "*"
        elif (
            state.plan.name == "control"
            and index == 3
            and "captured-rejoin-denied" in state.completed
        ):
            marker = "×" if unicode else "x"
        else:
            marker = "○" if unicode else "o"
        nodes.append(f"{marker} n{index} {role}")
    separator = " ─── " if unicode else " --- "
    single = separator.join(nodes)
    if len(single) <= width:
        return [single]
    return ["  ".join(nodes[index : index + 2]) for index in range(0, len(nodes), 2)]


def dashboard_lines(state: TourState, width: int, height: int) -> list[str]:
    unicode = supports_unicode()
    elapsed = int(time.monotonic() - state.started_at)
    clock = f"{elapsed // 60:02d}:{elapsed % 60:02d}"
    header = f"ASTER · {state.plan.title.upper()}"
    header_gap = max(1, width - len(header) - len(clock))
    lines = [f"{header}{' ' * header_gap}{clock}", state.plan.subtitle, ""]
    lines.extend(topology_lines(state, width, unicode))
    lines.append("")

    complete = len(state.completed)
    total = len(state.plan.phases)
    bar_width = max(6, min(34, width - 24))
    filled = bar_width if total == 0 else round(bar_width * complete / total)
    if unicode:
        bar = f"{'━' * filled}{'─' * (bar_width - filled)}"
    else:
        bar = f"{'#' * filled}{'-' * (bar_width - filled)}"
    lines.append(f"{bar}  {complete} / {total} verified phases")
    spinner = SPINNER[int(time.monotonic() * 10) % len(SPINNER)] if unicode else ASCII_SPINNER[int(time.monotonic() * 8) % len(ASCII_SPINNER)]
    lines.append(f"{spinner} {state.current_label()}")
    active = state.active_nodes()
    if active:
        phase = state.plan.phase(state.current_phase or "")
        active_label = ", ".join(f"n{node}" for node in active)
        if len(active) == 1:
            detail = "peerless process · durable local commit"
        elif phase is not None and phase.name.startswith("captured-"):
            detail = "revoked peer contact · denial required"
        else:
            detail = "direct Iroh · hybrid-PQ mission"
        lines.append(f"  running: {active_label} · {detail}")
    elif state.subscriptions is not None:
        lines.append("  durable receipts are written before this view is updated")
    lines.append("")

    fixed_rows = len(lines) + 3
    recent_limit = max(2, min(7, height - fixed_rows))
    recent = state.completed[-recent_limit:]
    omitted = complete - len(recent)
    if state.subscriptions is not None and omitted <= 0:
        receipt = state.subscriptions
        consume = receipt_value(receipt, "consume")
        carry = receipt_value(receipt, "carry")
        lines.append(
            f"✓ Receive policy: {counted(consume, 'consumer')} · "
            f"{counted(carry, 'route-only relay')}"
        )
    elif omitted > 0:
        lines.append(f"  … {omitted} earlier verified phase{'s' if omitted != 1 else ''}")
    for name in recent:
        phase = state.plan.phase(name)
        lines.append(f"✓ {phase.label if phase is not None else safe_text(name, 60)}")

    lines.append("")
    lines.append(
        "Bounded demo · one host · loopback · Event only · "
        "unprotected-reference provisioning"
    )
    rendered = [truncate(terminal_text(line, unicode), width) for line in lines]
    if len(rendered) <= height:
        return rendered

    rendered = [line for line in rendered if line]
    if len(rendered) <= height:
        return rendered

    header_line = rendered[0]
    topology = [line for line in rendered if "n0 " in line or line.lstrip().startswith(("o n", "* n", "x n", "○ n", "● n", "× n"))]
    progress = [line for line in rendered if "verified phases" in line]
    activity = [
        line
        for line in rendered
        if line and line[0] in SPINNER + ASCII_SPINNER
    ]
    footer = [line for line in rendered if line.startswith("Bounded demo")]
    essentials = [header_line] + topology + progress + activity + footer
    compact: list[str] = []
    for line in essentials:
        if line not in compact:
            compact.append(line)
    if len(compact) < height:
        for line in rendered:
            if line not in compact:
                compact.insert(max(1, len(compact) - len(footer)), line)
                if len(compact) == height:
                    break
    return compact[:height]


def describe_receipt(state: TourState, receipt: Receipt) -> str:
    if receipt.kind == "SUBSCRIPTIONS":
        if receipt_value(receipt, "status") != "seeded":
            return f"Receive-policy receipt · status {receipt_value(receipt, 'status')}"
        return (
            "Receive policy seeded"
            f" · {counted(receipt_value(receipt, 'consume'), 'consumer')}"
            f" · {counted(receipt_value(receipt, 'carry'), 'route-only relay')}"
        )
    if receipt.kind == "PHASE":
        name = receipt_value(receipt, "name", "", 120)
        phase = state.plan.phase(name)
        label = phase.label if phase is not None else safe_text(name, 80)
        carrier = receipt_value(receipt, "carrier_authenticated_edges")
        mission = receipt_value(receipt, "mission_authenticated_edges")
        if (
            receipt_value(receipt, "status") == "pass"
            and carrier == "denied-as-required"
            and mission == "denied-as-required"
        ):
            return f"{label} · denial verified"
        if (
            receipt_value(receipt, "status") == "pass"
            and carrier == "not-applicable"
            and mission == "not-applicable"
        ):
            return f"{label} · peerless commit verified"
        if (
            receipt_value(receipt, "status") == "pass"
            and carrier == "verified"
            and mission == "verified"
        ):
            return f"{label} · carrier + mission authentication verified"
        return f"{label} · phase receipt retained"
    if receipt.kind == "PING":
        epoch = receipt_value(receipt, "key_epoch", "")
        suffix = f" · epoch {epoch}" if epoch else ""
        authentication = (
            "source authenticated"
            if receipt_value(receipt, "source_authenticated") == "true"
            else f"source auth {receipt_value(receipt, 'source_authenticated')}"
        )
        return (
            "Ping received"
            f" · {receipt_value(receipt, 'producer_state')} → "
            f"{receipt_value(receipt, 'destination_state')}"
            f" · {authentication}{suffix}"
        )
    if receipt.kind == "PONG":
        epoch = receipt_value(receipt, "key_epoch", "")
        suffix = f" · epoch {epoch}" if epoch else ""
        causality = (
            "causal observation verified"
            if receipt_value(receipt, "causal_observation") == "verified"
            else f"causal observation {receipt_value(receipt, 'causal_observation')}"
        )
        return (
            "Pong returned"
            f" · {receipt_value(receipt, 'producer_state')} → "
            f"{receipt_value(receipt, 'destination_state')}"
            f" · {causality}{suffix}"
        )
    if receipt.kind == "RELAY":
        if receipt_value(receipt, "status") == "not-applicable":
            return "Direct path verified · no relay needed"
        if not (
            receipt_value(receipt, "status") == "pass"
            and receipt_value(receipt, "exact_forward") == "true"
            and receipt_value(receipt, "content_access") == "denied"
        ):
            return f"Relay receipt retained · status {receipt_value(receipt, 'status')}"
        return (
            "Payload-blind relay verified"
            f" · {counted(receipt_value(receipt, 'intermediates'), 'intermediate relay')}"
            f" · content access {receipt_value(receipt, 'content_access')}"
        )
    if receipt.kind == "CONTROL_RESULT":
        if receipt_value(receipt, "status") != "pass":
            return f"Control result retained · status {receipt_value(receipt, 'status')}"
        stale_signing = receipt_value(receipt, "captured_local_signing")
        stale_suffix = (
            " · stale epoch-1 signing remains (not zeroized)"
            if stale_signing == "stale-only"
            else f" · local signing {stale_signing}"
        )
        return (
            "Captured node excluded"
            f" · sync {receipt_value(receipt, 'captured_sync')}"
            f" · epoch-2 read {receipt_value(receipt, 'captured_epoch2_read')}"
            f" · survivor epoch {receipt_value(receipt, 'survivor_epoch')}"
            f"{stale_suffix}"
        )
    if receipt.kind == "DEMO_RESULT":
        if receipt_value(receipt, "status") != "pass":
            return f"Demo result retained · status {receipt_value(receipt, 'status')}"
        return (
            "Terminal restart/no-op verified"
            f" · {receipt_value(receipt, 'processes')} OS process executions"
            f" · {receipt_value(receipt, 'nodes')} independent stores"
        )
    return f"Receipt retained · {receipt.text}"


def summary_items(state: TourState) -> list[str]:
    items: list[str] = []
    if state.ping is not None:
        items.append(describe_receipt(state, state.ping))
    if state.pong is not None:
        items.append(describe_receipt(state, state.pong))
    if state.relay is not None:
        items.append(describe_receipt(state, state.relay))
    if state.control is not None:
        items.append(describe_receipt(state, state.control))
    if state.result is not None:
        items.append(describe_receipt(state, state.result))
    return items


class DemoPresenter:
    def __init__(self, state: TourState, mode: str) -> None:
        self.state = state
        self.mode = mode
        self.unicode = supports_unicode()
        self.color_enabled = (
            mode == "tui" and "NO_COLOR" not in os.environ and sys.stdout.isatty()
        )
        self.last_render = 0.0
        self.entered = False
        self.output_failed = False

    def enter(self) -> None:
        if self.mode == "plain":
            heading = (
                f"  Live view · {self.state.plan.title} · "
                f"{len(self.state.plan.roles)} independent nodes"
            )
            if not print_terminal(terminal_text(heading, self.unicode)):
                self.output_failed = True
        elif self.mode == "tui":
            self._write("\x1b[?1049h\x1b[?25l")
            self.entered = True
            self.render(force=True)

    def _write(self, value: str) -> None:
        if self.output_failed:
            return
        try:
            sys.stdout.write(value)
            sys.stdout.flush()
        except (BrokenPipeError, OSError, UnicodeError):
            self.output_failed = True

    def restore(self) -> None:
        if self.entered:
            self._write("\x1b[?25h\x1b[?1049l")
            self.entered = False

    def degrade_to_raw(self) -> None:
        self.restore()
        self.mode = "raw"

    def render(self, force: bool = False) -> None:
        if self.mode != "tui" or self.output_failed:
            return
        now = time.monotonic()
        if not force and now - self.last_render < 0.08:
            return
        terminal = shutil.get_terminal_size((88, 24))
        width = max(1, min(110, terminal.columns))
        height = max(6, terminal.lines)
        lines = dashboard_lines(self.state, width, height)
        rendered: list[str] = []
        for index, line in enumerate(lines):
            if index == 0:
                rendered.append(color(line, ANSI_BOLD + ANSI_MAGENTA, self.color_enabled))
            elif line.startswith("✓"):
                rendered.append(color(line, ANSI_GREEN, self.color_enabled))
            elif line and line[0] in SPINNER + ASCII_SPINNER:
                rendered.append(color(line, ANSI_CYAN, self.color_enabled))
            elif line.startswith("Bounded demo"):
                rendered.append(color(line, ANSI_DIM, self.color_enabled))
            else:
                rendered.append(line)
        self._write("\x1b[H\x1b[2J" + "\n".join(rendered))
        self.last_render = now

    def receipt(self, receipt: Receipt) -> None:
        self.state.observe(receipt)
        if self.mode == "plain":
            if receipt_succeeded(receipt):
                marker = "✓" if self.unicode else "PASS"
            else:
                marker = "·" if self.unicode else "INFO"
            line = f"  {marker} {describe_receipt(self.state, receipt)}"
            if not print_terminal(terminal_text(line, self.unicode)):
                self.output_failed = True
        else:
            self.render(force=True)

    def stderr(self, data: bytes) -> None:
        self.state.observe_stderr(data)
        if self.mode == "plain":
            text = safe_text(data.decode("utf-8", errors="replace").rstrip("\r\n"), 300)
            if text:
                if not print_terminal(
                    terminal_text(f"  ! {text}", self.unicode), file=sys.stderr
                ):
                    self.output_failed = True
        else:
            self.render(force=True)

    def tick(self, demo_root: Path) -> None:
        changed = self.state.poll_logs(demo_root)
        self.render(force=changed)

    def finish(self, returncode: int, elapsed: float, receipt: Path) -> None:
        self.restore()
        if self.mode == "raw" or self.output_failed:
            return
        marker = "✓" if self.unicode else "PASS"
        failure = "✗" if self.unicode else "FAIL"
        if not print_terminal():
            self.output_failed = True
            return
        if returncode == 0:
            completed = len(self.state.completed)
            total = len(self.state.plan.phases)
            result_status = (
                receipt_value(self.state.result, "status")
                if self.state.result is not None
                else None
            )
            if result_status == "pass" and completed == total:
                headline = (
                    f"{marker} {self.state.plan.title} completed"
                    f" · demo reported pass · {completed}/{total} phases"
                    f" · {elapsed:.1f}s"
                )
                headline = terminal_text(headline, self.unicode)
                print_terminal(
                    color(headline, ANSI_BOLD + ANSI_GREEN, self.color_enabled)
                )
            else:
                if result_status is None:
                    issue = "terminal DEMO_RESULT receipt missing"
                elif result_status != "pass":
                    issue = f"DEMO_RESULT status={safe_text(result_status)}"
                else:
                    issue = f"phase receipts incomplete ({completed}/{total})"
                headline = terminal_text(
                    f"! {self.state.plan.title} process exited 0; {issue}"
                    f" · {elapsed:.1f}s",
                    self.unicode,
                )
                print_terminal(color(headline, ANSI_BOLD, self.color_enabled))
            for item in summary_items(self.state):
                bullet = "·" if self.unicode else "-"
                print_terminal(terminal_text(f"  {bullet} {item}", self.unicode))
        else:
            current = self.state.current_label()
            headline = terminal_text(
                f"{failure} Tour stopped during: {current}", self.unicode
            )
            print_terminal(color(headline, ANSI_BOLD + ANSI_RED, self.color_enabled))
            if self.state.stderr_tail:
                print_terminal(
                    terminal_text(f"  {self.state.stderr_tail[-1]}", self.unicode)
                )
            partial = f"  Partial raw receipt: {safe_text(str(receipt))}"
            print_terminal(terminal_text(partial, self.unicode))


@dataclass(frozen=True)
class CaptureResult:
    returncode: int
    elapsed: float


def _reader(
    stream: object,
    stream_name: str,
    events: queue.Queue[tuple[str, Optional[bytes]]],
) -> None:
    try:
        while True:
            data = stream.readline()  # type: ignore[attr-defined]
            if not data:
                break
            events.put((stream_name, data))
    finally:
        events.put((stream_name, None))


def _signal_group(process: subprocess.Popen[bytes], signum: int) -> None:
    try:
        os.killpg(process.pid, signum)
    except ProcessLookupError:
        return
    except PermissionError:
        if process.poll() is not None:
            return
        raise


def _group_exists(process: subprocess.Popen[bytes]) -> bool:
    process.poll()
    try:
        os.killpg(process.pid, 0)
    except ProcessLookupError:
        return False
    except PermissionError:
        return process.poll() is None
    return True


def _stop_group(process: subprocess.Popen[bytes], signum: int = signal.SIGTERM) -> None:
    _signal_group(process, signum)
    deadline = time.monotonic() + 3
    while _group_exists(process) and time.monotonic() < deadline:
        process.poll()
        time.sleep(0.05)
    if _group_exists(process):
        _signal_group(process, signal.SIGKILL)
    if process.poll() is None:
        process.wait()


def _normalized_returncode(returncode: int) -> int:
    return 128 + abs(returncode) if returncode < 0 else returncode


def capture_process(
    command: Sequence[str],
    stdout_receipt: Path,
    stderr_receipt: Path,
    on_stdout: Callable[[bytes], None],
    on_stderr: Callable[[bytes], None],
    on_tick: Callable[[], None],
    on_start: Optional[Callable[[], None]] = None,
) -> CaptureResult:
    """Run a child, retaining bytes before invoking presentation callbacks."""

    start = time.monotonic()
    for receipt in (stdout_receipt, stderr_receipt):
        if receipt.exists():
            raise RuntimeError(f"refusing to overwrite retained receipt: {receipt}")
    try:
        stdout_handle = stdout_receipt.open("xb")
        try:
            stderr_handle = stderr_receipt.open("xb")
        except BaseException:
            stdout_handle.close()
            try:
                stdout_receipt.unlink()
            except FileNotFoundError:
                pass
            raise
    except FileExistsError as error:
        raise RuntimeError(f"refusing to overwrite retained receipt: {error.filename}") from error

    process: Optional[subprocess.Popen[bytes]] = None
    readers: tuple[threading.Thread, ...] = ()
    prior_handlers: dict[int, object] = {}
    requested_signal: Optional[int] = None
    events: queue.Queue[tuple[str, Optional[bytes]]] = queue.Queue()

    def request_signal(signum: int, _frame: object) -> None:
        nonlocal requested_signal
        if requested_signal is None:
            requested_signal = signum

    try:
        for signum in (signal.SIGINT, signal.SIGTERM, signal.SIGHUP):
            handler = signal.getsignal(signum)
            signal.signal(signum, request_signal)
            prior_handlers[signum] = handler
    except ValueError:
        for signum, handler in prior_handlers.items():
            signal.signal(signum, handler)  # type: ignore[arg-type]
        prior_handlers.clear()

    try:
        if requested_signal is not None:
            return CaptureResult(128 + requested_signal, time.monotonic() - start)
        if on_start is not None:
            on_start()
        if requested_signal is not None:
            return CaptureResult(128 + requested_signal, time.monotonic() - start)
        try:
            process = subprocess.Popen(
                list(command),
                stdin=subprocess.DEVNULL,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                start_new_session=True,
            )
        except OSError as error:
            message = (
                f"failed to run {safe_text(command[0])}: {safe_text(str(error))}\n"
            ).encode()
            stderr_handle.write(message)
            stderr_handle.flush()
            on_stderr(message)
            return CaptureResult(127, time.monotonic() - start)

        assert process.stdout is not None
        assert process.stderr is not None
        readers = (
            threading.Thread(
                target=_reader, args=(process.stdout, "stdout", events), daemon=True
            ),
            threading.Thread(
                target=_reader, args=(process.stderr, "stderr", events), daemon=True
            ),
        )
        for reader in readers:
            reader.start()

        open_streams = 2

        def consume(stream_name: str, data: Optional[bytes]) -> None:
            nonlocal open_streams
            if data is None:
                open_streams -= 1
                return
            handle = stdout_handle if stream_name == "stdout" else stderr_handle
            handle.write(data)
            handle.flush()
            callback = on_stdout if stream_name == "stdout" else on_stderr
            callback(data)

        def stop_and_drain_group(signum: int, grace_seconds: float) -> None:
            _signal_group(process, signum)
            grace_deadline = time.monotonic() + grace_seconds
            while (
                (open_streams > 0 or _group_exists(process))
                and time.monotonic() < grace_deadline
            ):
                process.poll()
                try:
                    stream_name, data = events.get(timeout=0.08)
                except queue.Empty:
                    continue
                consume(stream_name, data)
            if _group_exists(process):
                _signal_group(process, signal.SIGKILL)
            drain_deadline = time.monotonic() + 3
            while open_streams > 0 and time.monotonic() < drain_deadline:
                try:
                    stream_name, data = events.get(timeout=0.08)
                except queue.Empty:
                    continue
                consume(stream_name, data)
            for reader in readers:
                reader.join(timeout=0.5)
            while True:
                try:
                    stream_name, data = events.get_nowait()
                except queue.Empty:
                    break
                consume(stream_name, data)

        leader_returncode: Optional[int] = None
        leader_drain_deadline: Optional[float] = None
        while open_streams > 0 or process.poll() is None:
            if requested_signal is not None:
                break
            leader_returncode = process.poll()
            if leader_returncode is not None and open_streams > 0:
                if leader_drain_deadline is None:
                    leader_drain_deadline = time.monotonic() + 0.5
                elif time.monotonic() >= leader_drain_deadline:
                    break
            try:
                stream_name, data = events.get(timeout=0.08)
            except queue.Empty:
                on_tick()
                continue
            consume(stream_name, data)
            on_tick()

        if requested_signal is not None:
            stop_and_drain_group(requested_signal, 3)
            if process.poll() is None:
                process.wait()
            return CaptureResult(128 + requested_signal, time.monotonic() - start)

        if leader_returncode is not None and open_streams > 0:
            stop_and_drain_group(signal.SIGTERM, 1)
            return CaptureResult(
                _normalized_returncode(leader_returncode), time.monotonic() - start
            )

        for reader in readers:
            reader.join()
        return CaptureResult(
            _normalized_returncode(process.wait()), time.monotonic() - start
        )
    except BaseException:
        if process is not None:
            _stop_group(process)
        for reader in readers:
            if reader.ident is not None:
                reader.join(timeout=0.5)
        raise
    finally:
        for signum, handler in prior_handlers.items():
            signal.signal(signum, handler)  # type: ignore[arg-type]
        if process is not None and not any(reader.is_alive() for reader in readers):
            if process.stdout is not None:
                process.stdout.close()
            if process.stderr is not None:
                process.stderr.close()
        stdout_handle.close()
        stderr_handle.close()


class BuildPresenter:
    def __init__(self, mode: str) -> None:
        self.mode = mode
        self.unicode = supports_unicode()
        self.current = "Resolving the pinned workspace"
        self.started_at = time.monotonic()
        self.entered = False
        self.output_failed = False

    def _write(self, value: str) -> None:
        if self.output_failed:
            return
        try:
            sys.stdout.write(value)
            sys.stdout.flush()
        except (BrokenPipeError, OSError, UnicodeError):
            self.output_failed = True

    def enter(self) -> None:
        if self.mode == "plain":
            if not print_terminal(
                terminal_text("  … Preparing the Aster CLI", self.unicode)
            ):
                self.output_failed = True
        elif self.mode == "tui":
            self._write("\x1b[?25l")
            self.entered = True
            self.tick()

    def stdout(self, _data: bytes) -> None:
        return

    def stderr(self, data: bytes) -> None:
        text = safe_text(data.decode("utf-8", errors="replace").rstrip("\r\n"), 180)
        if not text:
            return
        self.current = text
        if self.mode == "raw":
            try:
                sys.stderr.buffer.write(data)
                sys.stderr.buffer.flush()
            except (BrokenPipeError, OSError):
                self.output_failed = True
        elif self.mode == "plain":
            if not print_terminal(terminal_text(f"    {text}", self.unicode)):
                self.output_failed = True
        else:
            self.tick()

    def restore(self) -> None:
        if self.entered:
            self._write("\r\x1b[2K\x1b[?25h")
            self.entered = False

    def degrade_to_raw(self) -> None:
        self.restore()
        self.mode = "raw"

    def tick(self) -> None:
        if self.mode != "tui" or self.output_failed:
            return
        unicode = self.unicode
        spinner_values = SPINNER if unicode else ASCII_SPINNER
        spinner = spinner_values[int(time.monotonic() * 10) % len(spinner_values)]
        terminal_width = max(1, shutil.get_terminal_size((88, 24)).columns)
        elapsed = time.monotonic() - self.started_at
        line = truncate(
            f"  {spinner} Preparing Aster CLI · {self.current} · {elapsed:.0f}s",
            terminal_width,
        )
        self._write(f"\r\x1b[2K{terminal_text(line, unicode)}")

    def finish(self, result: CaptureResult, stderr_receipt: Path) -> None:
        self.restore()
        if self.mode == "raw" or self.output_failed:
            return
        if result.returncode == 0:
            marker = "✓" if self.unicode else "PASS"
            line = f"  {marker} Aster CLI ready · {result.elapsed:.1f}s"
            print_terminal(terminal_text(line, self.unicode))
        else:
            marker = "✗" if self.unicode else "FAIL"
            line = f"  {marker} Aster CLI build failed · {result.elapsed:.1f}s"
            print_terminal(terminal_text(line, self.unicode))
            raw = f"    Raw stderr: {safe_text(str(stderr_receipt))}"
            print_terminal(terminal_text(raw, self.unicode))


def safe_callback(callback: Callable[[bytes], None], fallback: Callable[[bytes], None]) -> Callable[[bytes], None]:
    failed = False

    def guarded(data: bytes) -> None:
        nonlocal failed
        if failed:
            fallback(data)
            return
        try:
            callback(data)
        except Exception:
            failed = True
            fallback(data)

    return guarded


def write_raw_stdout(data: bytes) -> None:
    try:
        sys.stdout.buffer.write(data)
        sys.stdout.buffer.flush()
    except (BrokenPipeError, OSError):
        return


def write_raw_stderr(data: bytes) -> None:
    try:
        sys.stderr.buffer.write(data)
        sys.stderr.buffer.flush()
    except (BrokenPipeError, OSError):
        return


def run_build(args: argparse.Namespace) -> int:
    mode = resolve_view(args.view)
    presenter = BuildPresenter(mode)

    def fallback_stderr(data: bytes) -> None:
        presenter.degrade_to_raw()
        write_raw_stderr(data)

    def tick() -> None:
        try:
            presenter.tick()
        except Exception:
            presenter.degrade_to_raw()

    try:
        result = capture_process(
            args.command,
            args.stdout_receipt,
            args.stderr_receipt,
            safe_callback(presenter.stdout, lambda _data: None),
            safe_callback(presenter.stderr, fallback_stderr),
            tick,
            presenter.enter,
        )
    except KeyboardInterrupt:
        presenter.finish(CaptureResult(130, 0.0), args.stderr_receipt)
        return 130
    except (OSError, RuntimeError) as error:
        presenter.finish(CaptureResult(2, 0.0), args.stderr_receipt)
        print_terminal(safe_text(str(error)), file=sys.stderr)
        return 2
    presenter.finish(result, args.stderr_receipt)
    return result.returncode


def run_demo(args: argparse.Namespace) -> int:
    try:
        plan = make_plan(args.tour, args.nodes)
    except ValueError as error:
        print(f"tour view configuration error: {error}", file=sys.stderr)
        return 2
    mode = resolve_view(args.view)
    state = TourState(plan)
    presenter = DemoPresenter(state, mode)

    def stdout(data: bytes) -> None:
        if presenter.mode == "raw":
            write_raw_stdout(data)
            return
        presenter.receipt(parse_receipt(data))

    def stderr(data: bytes) -> None:
        if presenter.mode == "raw":
            write_raw_stderr(data)
            return
        presenter.stderr(data)

    def fallback_stdout(data: bytes) -> None:
        presenter.degrade_to_raw()
        write_raw_stdout(data)

    def fallback_stderr(data: bytes) -> None:
        presenter.degrade_to_raw()
        write_raw_stderr(data)

    stdout_callback = safe_callback(stdout, fallback_stdout)
    stderr_callback = safe_callback(stderr, fallback_stderr)

    def tick() -> None:
        try:
            presenter.tick(args.demo_root)
        except Exception:
            presenter.degrade_to_raw()

    try:
        result = capture_process(
            args.command,
            args.stdout_receipt,
            args.stderr_receipt,
            stdout_callback,
            stderr_callback,
            tick,
            presenter.enter,
        )
    except KeyboardInterrupt:
        presenter.finish(
            130, time.monotonic() - state.started_at, args.stdout_receipt
        )
        return 130
    except (OSError, RuntimeError) as error:
        presenter.restore()
        print_terminal(safe_text(str(error)), file=sys.stderr)
        return 2
    presenter.finish(result.returncode, result.elapsed, args.stdout_receipt)
    return result.returncode


def inspection_rows(path: Path) -> list[Receipt]:
    return [
        parse_receipt(line)
        for line in path.read_bytes().splitlines(keepends=True)
        if line.strip()
    ]


def node_from_receipt(receipt: Receipt) -> Optional[int]:
    state = decode_field(receipt.fields.get("state", ""))
    match = re.search(r"(?:^|/)node-([0-9]+)$", state)
    return int(match.group(1)) if match else None


def render_inspections(plan: TourPlan, rows: list[Receipt]) -> str:
    headers = (
        "Node",
        "Role",
        "App events",
        "Relay cache",
        "Controls applied/total",
        "Control head",
    )
    values: list[tuple[str, ...]] = []
    unknown: list[str] = []
    valid_nodes: set[int] = set()
    expected_nodes = set(range(len(plan.roles)))
    required_numeric = (
        "events",
        "route_cached_events",
        "controls",
        "applied_controls",
        "control_highwater",
    )
    complete = True
    for row in rows:
        if row.kind != "INSPECT":
            unknown.append(row.text)
            complete = False
            continue
        node = node_from_receipt(row)
        valid = (
            receipt_value(row, "status") == "pass"
            and node is not None
            and node in expected_nodes
            and node not in valid_nodes
            and all(
                re.fullmatch(r"[0-9]+", row.fields.get(field, "")) is not None
                for field in required_numeric
            )
        )
        if valid and node is not None:
            valid_nodes.add(node)
        else:
            complete = False
            unknown.append(row.text)
        role = plan.roles[node] if node is not None and node in expected_nodes else "Unknown"
        controls = receipt_value(row, "controls")
        applied = receipt_value(row, "applied_controls")
        values.append(
            (
                f"n{node}" if node is not None else "?",
                role,
                receipt_value(row, "events"),
                receipt_value(row, "route_cached_events"),
                f"{applied}/{controls}",
                receipt_value(row, "control_highwater"),
            )
        )
    widths = [len(header) for header in headers]
    for value_row in values:
        for index, value in enumerate(value_row):
            widths[index] = max(widths[index], len(value))
    lines = ["Final durable state"]
    lines.append("  " + "  ".join(header.ljust(widths[index]) for index, header in enumerate(headers)))
    lines.append("  " + "  ".join("-" * width for width in widths))
    for value_row in values:
        lines.append("  " + "  ".join(value.ljust(widths[index]) for index, value in enumerate(value_row)))
    complete = complete and valid_nodes == expected_nodes and len(values) == len(expected_nodes)
    relay_rows = [value for value in values if value[1] == "Blind relay"]
    relay_shape = bool(relay_rows) and all(
        value[2] == "0" and value[3].isdigit() and int(value[3]) > 0
        for value in relay_rows
    )
    if complete and relay_shape:
        lines.append("  Relay cache = protected exact bytes; application Events remain zero.")
    captured_rows = [value for value in values if value[0] == "n3"]
    captured_shape = len(captured_rows) == 1 and (
        captured_rows[0][2], captured_rows[0][4], captured_rows[0][5]
    ) == ("1", "0/0", "0")
    if complete and plan.name == "control" and captured_shape:
        lines.append(
            "  Captured n3's one Event is its own stale epoch-1 Ping; it received "
            "zero controls and no epoch-2 content."
        )
        lines.append("  Exclusion is not zeroization; stale local signing material remains.")
    elif not complete:
        lines.append(
            "  Inspection summary incomplete or malformed; scenario conclusions withheld."
        )
    elif (relay_rows and not relay_shape) or (
        plan.name == "control" and not captured_shape
    ):
        lines.append(
            "  Inspection values differ from the expected tour shape; scenario conclusions withheld."
        )
    for line in unknown:
        lines.append(f"  Unverified receipt retained: {safe_text(line, 160)}")
    return "\n".join(lines)


def run_inspect(args: argparse.Namespace) -> int:
    mode = resolve_view(args.view)
    try:
        if mode == "raw":
            write_raw_stdout(args.receipt.read_bytes())
            return 0
        plan = make_plan(args.tour, args.nodes)
        rows = inspection_rows(args.receipt)
    except (OSError, ValueError) as error:
        print_terminal(
            f"could not present inspection receipt: {safe_text(str(error))}",
            file=sys.stderr,
        )
        return 0
    print_terminal()
    print_terminal(terminal_text(render_inspections(plan, rows), supports_unicode()))
    return 0


def run_artifacts(args: argparse.Namespace) -> int:
    root = safe_text(str(args.root))
    demo = safe_text(str(args.demo_receipt))
    inspect = safe_text(str(args.inspect_receipt))
    logs = safe_text(str(args.root / "logs"))
    unicode = supports_unicode()
    lines = ["Receipts retained"]
    if args.root.exists():
        lines.append(f"  Tour root          {root}")
    else:
        lines.append("  Demo root          not created")
    lines.append(f"  Raw demo           {demo}")
    if args.inspect_receipt.exists():
        lines.append(f"  Raw inspection     {inspect}")
    else:
        lines.append("  Inspection         not run")
    if (args.root / "logs").is_dir():
        lines.extend(
            (
                f"  Child process logs {logs}",
                f"  Application events {safe_text('rg ' + shlex.quote('^APPLICATION ') + ' ' + shlex.quote(str(args.root / 'logs')))}",
                f"  Contact events     {safe_text('rg ' + shlex.quote('^CONTACT ') + ' ' + shlex.quote(str(args.root / 'logs')))}",
            )
        )
    else:
        lines.append("  Child process logs not created")
    print_terminal()
    for line in lines:
        print_terminal(terminal_text(line, unicode))
    return 0


def command_after_separator(values: list[str]) -> list[str]:
    if values and values[0] == "--":
        values = values[1:]
    if not values:
        raise argparse.ArgumentTypeError("a command is required after --")
    return values


def parser() -> argparse.ArgumentParser:
    root = argparse.ArgumentParser(description=__doc__)
    subcommands = root.add_subparsers(dest="subcommand", required=True)

    build = subcommands.add_parser("build", help="capture and present the CLI build")
    build.add_argument("--view", choices=("auto", "tui", "plain", "raw"), default="auto")
    build.add_argument("--stdout-receipt", type=Path, required=True)
    build.add_argument("--stderr-receipt", type=Path, required=True)
    build.add_argument("command", nargs=argparse.REMAINDER)
    build.set_defaults(action=run_build)

    demo = subcommands.add_parser("demo", help="capture and present a live tour")
    demo.add_argument("--tour", choices=("quick", "relay", "control"), required=True)
    demo.add_argument("--nodes", type=int, required=True)
    demo.add_argument("--demo-root", type=Path, required=True)
    demo.add_argument("--view", choices=("auto", "tui", "plain", "raw"), default="auto")
    demo.add_argument("--stdout-receipt", type=Path, required=True)
    demo.add_argument("--stderr-receipt", type=Path, required=True)
    demo.add_argument("command", nargs=argparse.REMAINDER)
    demo.set_defaults(action=run_demo)

    inspect = subcommands.add_parser("inspect", help="present retained node inspections")
    inspect.add_argument("--tour", choices=("quick", "relay", "control"), required=True)
    inspect.add_argument("--nodes", type=int, required=True)
    inspect.add_argument("--view", choices=("auto", "tui", "plain", "raw"), default="auto")
    inspect.add_argument("--receipt", type=Path, required=True)
    inspect.set_defaults(action=run_inspect)

    artifacts = subcommands.add_parser("artifacts", help="print retained receipt locations")
    artifacts.add_argument("--root", type=Path, required=True)
    artifacts.add_argument("--demo-receipt", type=Path, required=True)
    artifacts.add_argument("--inspect-receipt", type=Path, required=True)
    artifacts.set_defaults(action=run_artifacts)
    return root


def main(argv: Optional[Sequence[str]] = None) -> int:
    arguments = parser().parse_args(argv)
    if hasattr(arguments, "command"):
        try:
            arguments.command = command_after_separator(arguments.command)
        except argparse.ArgumentTypeError as error:
            print(error, file=sys.stderr)
            return 2
    return int(arguments.action(arguments))


if __name__ == "__main__":
    raise SystemExit(main())
