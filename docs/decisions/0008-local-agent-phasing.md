# Decision 0008: Defer the optional out-of-process agent

- Status: accepted deviation from a Should
- Date: 2026-08-18

Decision 0030 supersedes this decision's scheduling deferral with a bounded,
authenticated Event-first alpha. The security, lifecycle, versioning, and
backpressure concerns below remain active production gates.

The requirements mark a gRPC-or-similar local agent as an MVP **Should**, and
explicitly allow it after MVP in the phasing section. This reference prioritizes
the single native library, stable C ABI, and Go/Python wrappers. It does not ship
a network-listening local daemon in the current candidate.

A daemon would add an authorization boundary, local credential storage, service
lifecycle, protocol/API versioning, and another remotely parseable surface. It
should not be added as a thin unauthenticated wrapper merely to check a box.

Post-MVP work may implement a Unix-domain-socket/named-pipe agent from the same
high-level ABI contract. It must authenticate local clients, use OS permissions,
avoid exporting provisioning secrets, provide bounded backpressure, and pass the
same binding/conformance suite. This deferral does not change the mesh wire
protocol or prevent integrators from using the native library now.
