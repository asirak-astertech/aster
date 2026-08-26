# Decision 0006: Bundled SQLite behind a Rust store boundary

- Status: accepted with release gates
- Date: 2026-08-18

Durable offline publish needs atomic counters, envelopes, indexes, outbox, wants,
receipts, quotas, and crash recovery. The reference uses `rusqlite` 0.40.2 with
only its bundled SQLite feature and no default cache/WASM features.

SQLite is C rather than memory-safe Rust. The exception is narrower and less
risky than inventing an ACID database: all SQL lives behind `RecordStore`, inputs
are bound parameters, extension loading is disabled, and the store contains
sealed payloads rather than plaintext. Release gates cover power interruption,
corruption, migration, disk-full behavior, quotas, and supported SQLite version.

The bundled engine resolved to SQLite 3.53.2 through libsqlite3-sys 0.38.2.
SQLite declares its source public domain; this is not a proprietary or copyleft
license, but neither is it an OSI-approved license grant. A literal reading of
the requirements therefore leaves legal confirmation as a release gate. If the
policy excludes public-domain dependencies, `RecordStore` must be replaced by an
admitted implementation before an MVP claim.

A deployment can replace the store without changing the public API or wire.

## Semantic-v5 compatibility note (2026-08-25)

The retained core SQLite compatibility store advances schema 14 to 15 only by
widening `transfer_identities.origin_semantic_version` from `1..=4` to
`1..=5`. Its transactional migration preserves every existing v1-v4 row and
restart provenance before admitting v5. This does not add SQLite to the normal
selected `aster-node` graph: selected Event/State/Record/Blob storage and the
semantic-v5 pending Blob source/carrier state remain in `aster-redb-store`.
