# Decision 0004: Distinguish application silence from literal RF silence

- Status: stakeholder validation required
- Date: 2026-08-18

The requirement combines “radio-silent” with accepting inbound synchronization.
Ordinary IP unicast, BLE GATT, authentication, and reliable link layers emit
acknowledgements or control traffic, so literal zero transmission cannot ingest a
normal bidirectional session.

The framework exposes two explicit modes:

- **Receive-only:** no advertisements, discovery probes, inventory, or item data;
  only mandatory link/authentication/acknowledgement traffic needed to ingest is
  permitted.
- **Passive-only:** no framework-originated bytes at all. It can ingest only a
  transport's unauthenticated-at-link broadcast that is independently protected
  by a valid mesh envelope; ordinary sessions cannot operate.

The operator UI must not label the first mode as physically RF silent. The final
names and the treatment of mandatory link emissions require stakeholder approval.
