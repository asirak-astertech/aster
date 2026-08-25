# Language quickstarts

To see real Aster nodes exchange protected Events before embedding an API, run
the one-command [capability tour](capability-tour.md). This page indexes the
offline application and language-binding quickstarts.

For the selected production-lane composition, start with the Rust
[live Event quickstart](selected-event-api.md). It demonstrates peerless publish,
bounded query, durable at-least-once subscribe/poll/ack, idempotent unsubscribe,
freshly verified gap inspection, and bounded peer/last-contact status through
the running actor's sole authority. A focused real-process test publishes
offline and synchronizes later. The separate [selected State
quickstart](selected-state-api.md) demonstrates stopped/local latest-value
publication, causal projection, recoverable versions, and visible authenticated
tombstones. The stopped/local [selected Record
quickstart](selected-record-api.md) demonstrates durable revisions, explicit
conflict siblings, and exact-guard application resolution. Live or replicated
State/Record, automatic registered-policy Record merge, atomic subscription
update, Blob, and selected-node language bindings remain open.

Choose the API closest to your application:

| Language | API you use | Quickstart |
|---|---|---|
| Rust (selected live Event slice) | `aster_node::start_node` + `SelectedEventHandle` | [Selected Event API](selected-event-api.md) |
| Rust (selected stopped Event slice) | `aster-node::application::SelectedEventNode` | [Selected Event API](selected-event-api.md#one-authority-two-application-modes) |
| Rust (selected stopped State slice) | `aster-node::application::SelectedStateNode` | [Selected State API](selected-state-api.md) |
| Rust (selected stopped Record slice) | `aster-node::application::SelectedRecordNode` | [Selected Record API](selected-record-api.md) |
| Rust | Native high-level `ApplicationNode` | [Rust](rust.md) |
| Python | Dependency-free `ctypes` wrapper over the native library | [Python](python.md) |
| Go | cgo wrapper over the native library | [Go](go.md) |
| C / C-compatible FFI | Stable ABI v1 | [C](c.md) |

The four broader semantic language quickstarts perform the same State flow:

1. Open a node with a disposable, non-production provisioning bundle.
2. Create a durable subscription.
3. Publish State while no peer is connected.
4. Poll the local subscription and acknowledge delivery.
5. Close the node cleanly.

The selected Rust Event guide instead adds a live actor and a focused later-sync
process test. The selected Rust State guide uses the production-lane store and
security composition but remains stopped and local. The selected Rust Record
guide adds explicit conflict annotation and guarded resolution over that same
exclusive local authority. The language examples
remain intentionally offline exercises. After one works, continue with
[Carriers and contacts](../transports.md) to understand live synchronization.
The fixture path is unprotected compatibility/test ingestion. Rust now exposes
a provider-owned protection boundary, but no operational provider or protected
C, Go, or Python entry point is shipped; see
[ADR 0013](../decisions/0013-protected-provisioning-boundary.md).

## Shared toolchain prerequisite

The repository pins Rust 1.97.1, installed with `mise install`. The crates'
minimum supported Rust version (MSRV) is Rust 1.91. Each language quickstart
uses the pinned toolchain to build the Rust core or native library.

## Shared vocabulary

The application APIs share these concepts where the selected data class uses
them:

- a **topic** says what the data is;
- a **scope** says where it is allowed to propagate;
- a **logical key** identifies the thing within State or Record data;
- a **data class** selects convergence behavior;
- **priority** expresses scheduling and pressure intent; selected Event, State,
  and Record priority-aware transmission, retry, and eviction remain open;
- **TTL** controls how long an item remains useful; the selected Event, State, and Record
  surfaces omit finite TTL until authenticated forwarding age and expiry exist;
  and
- a **publish result** identifies a durable local commit.

Read [Core concepts](../concepts.md) before adapting the example to operational
data.
