# Decision 0009: Separate the application API from adapter internals

- Status: accepted
- Date: 2026-08-18

The default Rust library and every first-class language binding expose only
application operations: node lifecycle, offline publish, streamed Blob I/O,
subscribe and acknowledge, bounded query, conflict inspection/resolution,
emission policy, bridge policy, peer/sync status, provisioning installation,
and zeroization.

Cryptographic algorithms and keys, source-envelope construction, handshake
flights, fragmentation, inventory trees, reconciliation messages, sealed-object
ingest/emission, and link choice are not application APIs. Rust transport
adapters and conformance tooling require some of these contracts, so the core
places them behind the explicit, non-default `adapter-sdk` feature. The IP,
BTLE, C-boundary implementation, and conformance packages opt into that feature;
ordinary Rust dependents do not.

The adapter feature is a separately versioned implementation contract, not a
license to bypass authentication or inject application data. An adapter moves
opaque authenticated frames through the internal runtime. It cannot select
cryptographic primitives or directly apply decrypted records.

The C header must not export the internal sealed-object emission/ingest seam.
Language bindings are generated from the application portion of that header and
must not reconstruct a transport or sync engine. Internal integration tests may
compile against the adapter feature without turning it into the default public
surface.

The implemented Rust boundary is `ApplicationNode`. It owns the generic engine,
accepts only opaque provisioning bytes, requires bounded query/delivery pages,
rejects generic whole-buffer Blob publication, selects Blob epochs internally,
and maps items/publication receipts to application records that omit causal
vectors and sealed bytes. The explicit application merge-helper input contains
only IDs, publisher IDs, payloads, and tombstone flags; callers must supply it in
ascending full-ItemID order. All underlying modules are private unless
`adapter-sdk` is selected; every workspace adapter/tool that needs them opts in
explicitly.

This separation follows the supplied requirement that application developers
need no knowledge of cryptography, fragmentation, transport selection, or sync
internals while preserving a documented path for future transport packages.

## Implementation correction (2026-08-20)

`register_merge_policy` is retained for API compatibility, but registration is
process-local and its only automatic effect is to associate the policy ID with
high-level Record conflict annotations. Direct and forwarded replicated
ingestion never invoke application policy. Applications inspect siblings and
publish reviewed output through explicit `resolve()`. This prevents
peer-triggered ingestion from creating recursive merge publications and leaves
requirements §5.3 automatic merge partial pending a convergent design.
