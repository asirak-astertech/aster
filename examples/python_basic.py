"""Offline publish/subscribe with Aster's Python application binding."""

from __future__ import annotations

import argparse
from pathlib import Path

from aster_mesh import DataClass, Node, Priority


PROJECT_ROOT = Path(__file__).resolve().parents[1]
DEFAULT_BUNDLE = (
    PROJECT_ROOT / "bindings/testdata/non-production-provisioning.bundle"
)


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--bundle",
        type=Path,
        default=DEFAULT_BUNDLE,
        help="opaque authority-issued bundle (default: disposable test fixture)",
    )
    parser.add_argument(
        "--database",
        type=Path,
        default=Path("aster-python-example.db"),
        help="durable local database",
    )
    args = parser.parse_args()

    # A provisioning bundle gives this node its identity and allowed scopes and
    # topics. Applications treat it as opaque bytes.
    provisioning = args.bundle.read_bytes()

    # Closing the context releases native resources. The database remains, so
    # publications and subscription acknowledgements survive process restarts.
    with Node(str(args.database), provisioning) as node:
        # Subscribe before publishing so this local commit is delivered through
        # the same durable at-least-once path used for remotely received items.
        subscription = node.subscribe("position.current", "mission/team/alpha")

        # No peer or network is required. Success means this State item and its
        # causal metadata are durably committed to the local node.
        receipt = node.publish(
            DataClass.STATE,
            "position.current",
            "mission/team/alpha",
            b'{"lat":38.9,"lon":-77.0}',
            logical_key=b"unit-7",  # Which entity this State describes.
            priority=Priority.IMMEDIATE,
            ttl_ms=60_000,  # Expiry is independent of priority.
        )

        deliveries = subscription.poll(limit=1)
        if not deliveries:
            raise RuntimeError("the local publication was not delivered")

        delivery = deliveries[0]
        print(f"item={receipt.item_id.hex()} payload={delivery.item.payload.decode()}")

        # Acknowledge only after application processing succeeds. Until then,
        # Aster may redeliver the item after a restart.
        subscription.acknowledge(delivery)


if __name__ == "__main__":
    main()
