# Local ConnectRPC agent quickstart

The alpha `aster-agent` is the first out-of-process application boundary over
the selected Aster node. It serves Connect, gRPC, and gRPC-Web on loopback and
exposes only high-level live Event and status operations. It does not expose
keys, envelopes, carriers, reconciliation messages, sealed bytes, or mission
provisioning over RPC.

State and Record now reconcile on the mesh when configured with
`--state-interest` and `--record-interest`, but their application facades still
require exclusive stopped-store ownership. They are deliberately absent from
this live protocol until handle-backed APIs exist.

## Run it locally

Install the pinned Rust and Buf tools and prepare disposable owner-only inputs:

```sh
mise install
ASTER_AGENT_ROOT="$(mktemp -d)"
install -m 600 bindings/testdata/non-production-provisioning.bundle \
  "$ASTER_AGENT_ROOT/mission.unprotected-reference.bundle"
openssl rand -hex 32 > "$ASTER_AGENT_ROOT/client.token"
chmod 600 "$ASTER_AGENT_ROOT/client.token"
```

Start the agent in one terminal:

```sh
cargo run --locked -p aster-agent -- \
  --state "$ASTER_AGENT_ROOT/state" \
  --mesh-bind 127.0.0.1:0 \
  --listen 127.0.0.1:8181 \
  --mission-bundle-unprotected-reference \
    "$ASTER_AGENT_ROOT/mission.unprotected-reference.bundle" \
  --client-token-file "$ASTER_AGENT_ROOT/client.token"
```

The checked-in mission fixture is public test material and the explicitly
named loader is an unprotected reference path. This command is a local
integration exercise, not operational provisioning.

In a second terminal, use the repository-owned schema and the 35-line sample:

```sh
./examples/connect_agent.sh "$ASTER_AGENT_ROOT/client.token"
```

The sample gets node status, creates a durable subscription, publishes while
the node has no configured peer, polls, and acknowledges the Event. Protobuf
JSON represents `bytes` fields as base64. Re-running the fixed operation keys
returns the original durable effects instead of publishing duplicates.

## Integrate an application

The source of truth is
[`proto/aster/application/v1alpha1/aster.proto`](../../proto/aster/application/v1alpha1/aster.proto).
It is a local Buf module: `buf lint` and `buf build` require no Buf Schema
Registry, and Cargo code generation consumes the checked-in descriptor set
without requiring Buf or `protoc` during a Rust build. Generate your normal
ConnectRPC client from that local module using the plugins already owned by
your Go, TypeScript, Java/Kotlin, Swift, or other application stack.

Point the client at `http://127.0.0.1:8181` and add this header to every call:

```text
Authorization: Bearer <contents of the client token file>
```

Use a stable operation key for the application effect, not for an individual
network attempt. A publish or subscription retry with the same key and request
is idempotent; reusing the key with different content fails closed. Pages are
explicitly bounded. `StreamEvents` is a durable polling convenience with
at-least-once delivery, not an implicit acknowledgement: commit the
application effect and then call `AcknowledgeEvent`. Disconnecting before the
acknowledgement causes redelivery with a higher attempt count.

## Security and lifecycle boundary

The listener rejects non-loopback addresses. Every RPC, including stream
establishment, requires an exact bearer token held in zeroizing memory and
compared in constant time. On Unix, the agent refuses token symlinks,
non-regular files, files not owned by the effective agent user, and files
readable or writable by group or others. Request body, decoded-message,
element-memory, encoded-response, deadline, connection, and concurrent HTTP/2
stream bounds are set by the server. If a query or poll page exceeds the 2 MiB
Protobuf response budget, request a smaller page.

This is still an alpha local boundary. TCP is plaintext, any process that can
read the token has the application's authority, the token is loaded only at
startup, and protected operational mission provisioning is not shipped. Do not
publish the listener through a Kubernetes Service, ingress, host port, or
remote tunnel. Token rotation/reload, an OS-credential socket boundary,
supported-target packaging, and independent interoperability remain release
gates.

## Kubernetes, Zarf, and UDS shape

Run one agent as a same-Pod sidecar beside the application and let both
containers share the loopback namespace. Mount one writable volume for Aster
state and ensure only one agent owns it. Do not create a Service for the RPC
port. A readiness probe should use an authenticated `GetStatus` client; there
is no unauthenticated HTTP health endpoint.

Kubernetes projected Secrets are symlink-based, so the fail-closed token loader
rejects their usual mount shape. An init container can copy the token into a
memory-backed or ordinary `emptyDir` as a regular file with mode `0400`, owned
by the agent UID; mount that file into both sidecars without broadening its
permissions. The same warning applies to the current unprotected-reference
mission file, which should not be used for production provisioning.

A Zarf package can carry the agent/application images, StatefulSet or Pod,
persistent volume claim, local proto module, init-copy step, and NetworkPolicy.
Runtime access to a package registry or the Buf Schema Registry is unnecessary.
A UDS package can wrap that Zarf component and add its namespace, policy,
identity, and monitoring conventions while preserving the no-Service RPC
boundary.

Mesh peers are currently configured as exact carrier/mission identities and
socket addresses. Ordinary changing Pod IPs are therefore not a production
discovery solution. The present bounded deployment needs stable addresses,
host networking or a suitable secondary network, or configuration regeneration;
Kubernetes-native peer discovery and protected dynamic provisioning remain
open work.
