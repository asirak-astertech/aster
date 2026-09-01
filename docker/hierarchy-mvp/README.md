# Rosterless hierarchy MVP


This Compose scenario demonstrates an Event crossing two authenticated,
payload-blind hierarchy edges after the nodes find adjacent peers with mDNS.
It configures no peer IDs, peer addresses, published ports, hosted discovery,
or relay. Each container has fixed local interface addresses solely so its
bounded mDNS browser can join every Docker segment attached to that container;
those addresses do not identify or locate any remote peer.

```text
publisher -- alpha -- bridge-alpha -- parent -- bridge-bravo -- bravo -- consumer
                                      |
                                   outsider
                              (foreign authority)
```

The five long-running nodes share only the three memberships shown above. A
sixth, networkless one-shot initializer writes the exact randomized mission and
bridge-authorization artifacts into their private volumes before they start.

Run it from the repository root with Docker Compose available to your user:

```sh
mise run hierarchy-mvp-compose
```

The image is built first. After that build, the live proof has one hard
three-minute deadline and always removes its containers, networks, volumes, and
local image. A passing JSON receipt confirms:

- automatic discovery and authenticated contacts on every adjacent segment;
- one `mesh.allowed` Immediate Event delivered after exactly two bridge hops;
- no consumer delivery for a denied topic or Routine priority fixture;
- route-only bridge logs contain none of the three plaintext payload sentinels;
- a discovered peer from another mission authority fails before inventory;
- the consumer reopens the same durable route with every peer stopped and
  discovery disabled.

This is a same-implementation, single-host Docker proof. It is not evidence for
physical networks, WAN/NAT traversal, hostile discovery load, dynamic bridge
administration, other data classes, or large-network capacity.

To validate only the rendered topology without contacting the Docker daemon:

```sh
python3 tools/aster_hierarchy_mvp_compose.py --config-only
```
