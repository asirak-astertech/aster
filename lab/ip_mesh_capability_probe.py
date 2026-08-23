#!/usr/bin/env python3
"""Record Proposal 0001 command-surface capability gaps without networking."""

from __future__ import annotations

import argparse
import datetime as dt
import hashlib
import json
from pathlib import Path
import subprocess
from typing import Any, Sequence


IMAGE = "aster-lab:validation"


def utc_now() -> str:
    return dt.datetime.now(dt.timezone.utc).isoformat().replace("+00:00", "Z")


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def probe(binary: Path, command: str, option: str) -> dict[str, Any]:
    argv = [
        "docker",
        "run",
        "--rm",
        "--pull=never",
        "--network",
        "none",
        "--read-only",
        "--cap-drop",
        "ALL",
        "--security-opt",
        "no-new-privileges",
        "--mount",
        f"type=bind,src={binary.resolve()},dst=/experiment/aster-lab,readonly",
        "--entrypoint",
        "/experiment/aster-lab",
        IMAGE,
        command,
        option,
        "probe",
    ]
    result = subprocess.run(argv, text=True, capture_output=True, check=False, timeout=30)
    return {
        "argv": argv,
        "returncode": result.returncode,
        "stdout": result.stdout,
        "stderr": result.stderr,
        "supported": result.returncode == 0,
    }


def parser() -> argparse.ArgumentParser:
    value = argparse.ArgumentParser(description=__doc__)
    value.add_argument("--root", type=Path, required=True)
    value.add_argument("--native", type=Path, required=True)
    value.add_argument("--iroh", type=Path, required=True)
    value.add_argument("--libp2p", type=Path, required=True)
    value.add_argument("--quinn", type=Path, required=True)
    return value


def main(argv: Sequence[str] | None = None) -> int:
    args = parser().parse_args(argv)
    if args.root.exists():
        raise SystemExit(f"capability probe root already exists: {args.root}")
    args.root.mkdir(parents=True)
    binaries = {
        "native": args.native,
        "iroh": args.iroh,
        "libp2p": args.libp2p,
        "quinn": args.quinn,
    }
    for name, binary in binaries.items():
        if not binary.is_file():
            raise SystemExit(f"missing {name} binary: {binary}")
    commands = {
        "native": "mesh-native-node",
        "iroh": "mesh-iroh-node",
        "libp2p": "mesh-libp2p-node",
    }
    options = (
        "--manual-peer",
        "--rendezvous-address",
        "--relay-address",
        "--emission-mode",
    )
    receipts: dict[str, Any] = {}
    for arm, command in commands.items():
        receipts[arm] = {
            option: probe(binaries[arm], command, option) for option in options
        }
    receipts["quinn"] = {
        "mesh-quinn-node": probe(binaries["quinn"], "mesh-quinn-node", "--root")
    }
    result = {
        "schema": "aster-ip-mesh-capability-probe/v1",
        "created_utc": utc_now(),
        "image": IMAGE,
        "binaries": {
            name: {
                "path": str(path.resolve()),
                "bytes": path.stat().st_size,
                "sha256": sha256_file(path),
            }
            for name, path in binaries.items()
        },
        "probes": receipts,
    }
    (args.root / "result.json").write_text(
        json.dumps(result, indent=2, sort_keys=True) + "\n", encoding="utf-8"
    )
    print(json.dumps(result, indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
