# Decision 0007: Small link adapters, optional infrastructure

- Status: accepted for reference
- Date: 2026-08-18

The IP reference uses nonblocking UDP for local/manual paths, opaque multicast
discovery, a small UDP observed-address rendezvous exchange for hole punching,
and a separately deployable TCP ciphertext relay fallback. Rendezvous is pairing,
not identity; every path still runs the core hybrid handshake. Local operation
has no infrastructure dependency.

The provisioned discovery secret never appears on the network. Each announcement
uses a fresh OS-random nonce and a truncated HKDF-SHA-256 proof. Manual peers,
discovered endpoints, punch capabilities, rendezvous waiters, active relay pairs,
relay frames, and relay queue bytes all have fixed bounds; stale rendezvous
registrations expire. These limits fail closed or drop untrusted hints without
changing durable mesh truth.

This is intentionally smaller than admitting a P2P stack that failed the public
security-process gate. It does not claim every NAT can be crossed directly.

The transport-neutral runtime owns MTU fragmentation and bounded reassembly.
The BTLE reference carries each already-fragmented frame exactly once, and owns
broadcast behavior, negotiated-MTU enforcement, disconnect handling, and
emission policy behind a narrow `BleRadio` platform contract. It prefers L2CAP
credit channels and permits GATT fallback. Simulation verifies protocol
behavior; physical BlueZ/platform evidence remains a release gate and is not
replaced by a fake hardware claim.
