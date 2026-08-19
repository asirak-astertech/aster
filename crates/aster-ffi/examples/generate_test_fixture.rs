//! Generates disposable public test credentials for foreign-binding tests only.

use aster_mesh::{ProvisioningAccess, ReferenceProvisioner, Scope, Topic};
use std::error::Error;
use std::path::PathBuf;

fn main() -> Result<(), Box<dyn Error>> {
    let output = std::env::args_os()
        .nth(1)
        .map(PathBuf::from)
        .ok_or("pass a bindings/testdata output path")?;
    if !output
        .components()
        .any(|part| part.as_os_str() == "testdata")
    {
        return Err("refusing to write public test credentials outside testdata".into());
    }

    // This public constant has no operational secrecy or trust value.
    let mut authority = ReferenceProvisioner::from_seed([0xa5; 32])?;
    let topics = [
        "position.current",
        "record.plan",
        "chat.events",
        "imagery.blob",
    ]
    .into_iter()
    .map(Topic::new)
    .collect::<Result<Vec<_>, _>>()?;
    let access = ProvisioningAccess::member(Scope::new("mission/team/alpha")?, vec![0, 1], topics)?;
    let bundle = authority.issue_node(1, &[access])?.to_bytes()?;
    std::fs::write(output, bundle)?;
    authority.zeroize();
    Ok(())
}
