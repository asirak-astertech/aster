# Historical runtime-volume diagnostic — not runnable

This directory preserves the retired manual runtime-volume diagnostic. It is
not an active CI workflow, supported replay procedure, or current-stack test.
The former CI caller and active workflow have been removed.

`snapshot/` contains the original diagnostic files, including its README,
manifest, telemetry patch, preflight, driver, and tests. The adjacent workflow
is preserved outside `.github/workflows`. Their original paths, commands,
source identifiers, hashes, and evidence claims are historical; they have not
been refreshed or made runnable against the current source tree. In particular,
do not follow the launch commands in the snapshot README or apply its patch to
the current runtime.

This archive grants no new performance, resource, compatibility, or release
credit. The experimental libp2p provider is being removed separately; historical
research decisions and receipts remain unchanged.
