# Compatibility and Deprecation Policy

- Policy version: 1
- Applies beginning with protocol 1.0

Protocol 1.x additions are limited to optional fields/messages, new registry
values whose absence has defined behavior, and new complete cryptographic suites.
A 1.x reader must continue accepting every valid, policy-permitted 1.0 object.
Semantic changes require a new major version.

The project will support the latest two minor releases of an active major and no
less than 24 months from each minor release, whichever is longer. A published
major remains readable for at least five years after its successor is released;
adopting programs should retain the conformance corpus and source-envelope
reader for the lifetime of mission data they must recover.

A deprecation announcement includes:

- affected protocol, suite, ABI, binding, or registry values;
- security/operational reason and threat consequence;
- first release that warns, earliest release that may stop producing it, and
  earliest release that may stop consuming it;
- migration and rollback-safe stored-data procedure;
- updated conformance vectors and mixed-version evidence.

Unknown optional extensions remain ignorable throughout a major version.
Unknown critical values fail only the containing object/session and never cause
silent reinterpretation. Stable replication-wire, credential/envelope, crypto-
profile, and handshake-framing encodings remain version `1`. The current
handshake separately negotiates semantic versions `6`, `5`, `4`, `3`, `2`, and
`1` and complete suite `0x0001`; a default offer is `[6, 5, 4, 3, 2, 1]`, and an honest responder selects the
highest common semantic version. Offer and selection are transcript, KDF,
confirmation, and hybrid-authentication bound, so an unauthenticated on-path
rewrite fails.

Semantic version `4` adds the selected protected, class- and direction-separated
State/Record mechanics lanes; semantic version `5` inherits them and adds the
selected direct-content Blob source/carrier mechanics. Semantic version `6`
inherits every v5 ordinary lane unchanged and adds an opt-in selected Event
bridge lane that runs only when both authenticated endpoints enable it. Event
remains compatible across semantic versions `1` through `6`; State/Record
frames are absent from v1-v3 contacts, Blob frames are absent from v1-v4
contacts, and Event-bridge frames are absent from v1-v5 contacts.
This is a negotiated-behavior addition: stable wire/profile, handshake framing,
suite, and source-object formats are not renumbered. A v4 State/Record object is
therefore never silently downgraded into an Event or processed by a v1-v3
mutable lane, and a v5 Blob transfer is never silently accepted as v4 traffic.

Negotiation does not authenticate the responder's full capability set. An
accepted older or modified peer can complete semantic `1`, `2`, or `3`, so production use
that depends on downgrade resistance remains fail-closed at release
authorization until all of the following exist: an authority-signed mission
minimum semantic version, durable per-identity observed high-water state,
explicit signed rollback authorization, mixed-version vectors, and independent
interoperability evidence. Version `1` fallback is compatibility behavior, not
evidence that a downgrade-sensitive deployment may enable it.

Cryptographic emergency response may prohibit producing or accepting a broken
suite sooner than the ordinary window. Such a change requires a signed mission
policy/control update, an advisory, explicit loss-of-connectivity impact, and a
replacement suite; it must never introduce a silent classical-only fallback.

The C ABI is versioned independently. Existing functions and structure prefixes
remain source/binary compatible within ABI major 1; callers set both ABI version
and structure size. Removing a binding method requires the same announcement
window and cannot remove the underlying protocol capability.

Draft 0.x artifacts may change incompatibly. Every such change increments the
draft/specification identifier, replaces rather than mutates vector IDs, and is
recorded in release notes and the compatibility matrix.
