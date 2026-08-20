# Language quickstarts

Choose the API closest to your application:

| Language | API you use | Quickstart |
|---|---|---|
| Rust | Native high-level `ApplicationNode` | [Rust](rust.md) |
| Python | Dependency-free `ctypes` wrapper over the native library | [Python](python.md) |
| Go | cgo wrapper over the native library | [Go](go.md) |
| C / C-compatible FFI | Stable ABI v1 | [C](c.md) |

Every quickstart performs the same flow:

1. Open a node with a disposable, non-production provisioning bundle.
2. Create a durable subscription.
3. Publish State while no peer is connected.
4. Poll the local subscription and acknowledge delivery.
5. Close the node cleanly.

That is intentionally an offline exercise. After it works, continue with
[Carriers and contacts](../transports.md) to understand live synchronization.

## Shared toolchain prerequisite

The repository pins Rust 1.97.1, installed with `mise install`. The crates'
minimum supported Rust version (MSRV) is Rust 1.90. Each language quickstart
uses the pinned toolchain to build the Rust core or native library.

## Shared vocabulary

All four APIs expose the same application concepts:

- a **topic** says what the data is;
- a **scope** says where it is allowed to propagate;
- a **logical key** identifies the thing within State or Record data;
- a **data class** selects convergence behavior;
- **priority** controls scheduling and pressure behavior;
- **TTL** controls how long an item remains useful; and
- a **publish result** identifies a durable local commit.

Read [Core concepts](../concepts.md) before adapting the example to operational
data.
