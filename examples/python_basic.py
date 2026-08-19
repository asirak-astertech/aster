from pathlib import Path

from aster_mesh import DataClass, Node, Priority


with Node("aster-example.db", Path("provisioning.bundle").read_bytes()) as node:
    subscription = node.subscribe("position.current", "mission/team/alpha")
    receipt = node.publish(
        DataClass.STATE,
        "position.current",
        "mission/team/alpha",
        b'{"lat":38.9,"lon":-77.0}',
        logical_key=b"unit-7",
        priority=Priority.IMMEDIATE,
        ttl_ms=60_000,
    )
    delivery = subscription.poll(limit=1)[0]
    print(receipt.item_id.hex(), delivery.item.payload.decode())
    subscription.acknowledge(delivery)
