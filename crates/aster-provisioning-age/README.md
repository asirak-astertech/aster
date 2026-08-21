# Aster age provisioning provider

This opt-in crate implements Aster's replaceable provisioning-protection
boundary with the binary age v1 format and X25519 recipients. It is an
experimental integration candidate, not a production, post-quantum, FIPS, key
custody, recovery, or secure-deletion solution.

The deliberately narrow profile supports only in-memory binary artifacts and
parsed X25519 recipients and identities. It does not enable age armor,
passphrases, SSH keys, plugins, async I/O, CLI helpers, or filesystem loading.
The mesh protocol and wire format do not depend on this crate.

```rust,no_run
use aster_mesh::{ProvisioningBundle, ProvisioningProtector};
use aster_provisioning_age::{AgeIdentity, AgeX25519Protector, AgeX25519Unprotector};

let identity = AgeIdentity::generate();
let recipient = identity.to_public();
let mut protector = AgeX25519Protector::new([recipient])?;
let mut unprotector = AgeX25519Unprotector::new([identity])?;

# let bundle: ProvisioningBundle = todo!();
let artifact = bundle.to_protected_bytes(&mut protector)?;
let restored = ProvisioningBundle::from_protected_bytes(&artifact, &mut unprotector)?;
# Ok::<(), Box<dyn std::error::Error>>(())
```

First-party Aster code is licensed under the Apache License, Version 2.0. The
independently maintained age dependency and its transitive dependencies retain
their own licenses.
