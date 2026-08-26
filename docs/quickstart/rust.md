# Rust quickstart

In this tutorial you will open a durable node, subscribe to a topic, publish
State with no network available, receive it locally, and acknowledge it.

**Time:** about five minutes after the Rust toolchain is installed.

## Prerequisites

- A checkout of this repository
- The [shared Rust toolchain prerequisite](README.md#shared-toolchain-prerequisite)

From the repository root, you can install the pinned tools with:

```sh
mise install
```

## Run the example

```sh
cargo run -p aster-core --example basic -- \
  bindings/testdata/non-production-provisioning.bundle \
  /tmp/aster-rust-example.db
```

The output contains a stable 32-byte ItemID and the payload:

```text
item=<64 hexadecimal characters> payload={"lat":38.9,"lon":-77.0}
```

No peer or network was involved. The example proved that:

- the provisioning bundle was accepted;
- the State item committed durably;
- the durable subscription selected it; and
- the application acknowledged the at-least-once delivery.

Read the fully commented source in
[`crates/aster-core/examples/basic.rs`](../../crates/aster-core/examples/basic.rs).

## What the important lines mean

```rust
let subscription = node.subscribe(topic.clone(), scope.clone(), None, false)?;
```

This creates a durable subscription for one exact topic and scope. `None` accepts
all four data classes; `false` excludes descendant scopes.

```rust
let result = node.publish(PublishRequest {
    class: DataClass::State,
    logical_key: b"unit-7".to_vec(),
    // topic, scope, payload, priority, TTL, and tombstone omitted here
})?;
```

State uses the logical key to identify the entity whose current value is being
updated. The publish result means “committed locally,” not “delivered to a
remote peer.”

```rust
node.acknowledge(subscription, delivery.item.id)?;
```

Acknowledge after your application has committed its own side effect. If it
stops before this call, Aster may deliver the item again.

## Add Aster to a Rust application

The project is currently consumed from source. For an application in the same
workspace, depend on the high-level core without explicitly enabling
`adapter-sdk`:

```toml
[dependencies]
aster-core = { path = "path/to/aster/crates/aster-core" }
```

The package is named `aster-core`; its Rust crate name is `aster_mesh`:

```rust
use aster_mesh::{ApplicationNode, DataClass, PublishRequest};
```

The default surface intentionally omits keys, sealed objects, fragmentation,
handshake, and transport selection. Cargo feature unification enables
`adapter-sdk` when `aster-host` or an adapter crate is also in the dependency
graph, so the narrow application surface is then a convention enforced by which
public modules your code imports. See [Carriers and
contacts](../transports.md).

## Replace the test fixture

The checked-in bundle is public, disposable material authorized only for the
example scope and topics. In an operational integration:

1. obtain a unique bundle from the deployment's authority workflow;
2. wrap it with an admitted `ProvisioningProtector`, then call
   `ApplicationNode::open_protected` with the corresponding least-privilege
   `ProvisioningUnprotector` rather than the raw example path;
3. keep inner plaintext out of source control, logs, and captures;
4. provide persistent secret custody and recovery separately from artifact
   protection;
5. store the database and Blob directory on durable protected storage; and
6. never use the same bundle for two independent nodes.

The repository defines that provider contract but does not yet ship an admitted
operational implementation. See the
[protected-provisioning decision](../decisions/0013-protected-provisioning-boundary.md).

Complete bundle contents are deliberately opaque to the application API.
The fixture's grants and regeneration procedure are documented in
[Non-production binding test material](../../bindings/testdata/README.md).

## Next steps

- Learn when to use each [data class and framework mechanism](../concepts.md).
- Review the [selected implementation boundary](../../README.md#current-implementation-boundary),
  then [connect nodes over IP or BTLE](../transports.md).
- For large immutable content, search the API for `open_blob_service`,
  `publish_finished_blob`, and `open_blob_reader`.
- Run the focused tests with `cargo test -p aster-core`.
