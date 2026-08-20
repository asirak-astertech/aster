//! Offline publish/subscribe with Aster's native Rust application API.

use aster_mesh::{
    ApplicationNode, ApplicationNodeOptions, DataClass, Priority, PublishRequest, Scope, Topic,
};
use std::error::Error;
use std::path::PathBuf;

fn main() -> Result<(), Box<dyn Error>> {
    let mut arguments = std::env::args_os().skip(1);
    let bundle_path = arguments
        .next()
        .map(PathBuf::from)
        .unwrap_or_else(|| "bindings/testdata/non-production-provisioning.bundle".into());
    let database_path = arguments
        .next()
        .map(PathBuf::from)
        .unwrap_or_else(|| "aster-rust-example.db".into());

    // The authority-issued bundle gives this node its identity and permitted
    // scopes/topics. Application code treats its contents as opaque.
    let provisioning = std::fs::read(bundle_path)?;
    let mut node = ApplicationNode::open(
        database_path,
        &provisioning,
        ApplicationNodeOptions::default(),
    )?;

    let topic = Topic::new("position.current")?;
    let scope = Scope::new("mission/team/alpha")?;

    // Subscribe before publishing so this local commit follows the same
    // durable, at-least-once path as a remotely received item.
    let subscription = node.subscribe(topic.clone(), scope.clone(), None, false)?;

    // No peer or transport is required. A successful receipt means the item and
    // its causal metadata are durable in the local database.
    let receipt = node.publish(PublishRequest {
        class: DataClass::State,
        topic,
        scope,
        priority: Priority::Immediate,
        ttl_ms: Some(60_000),            // Expiry is independent of priority.
        logical_key: b"unit-7".to_vec(), // Which entity this State describes.
        payload: br#"{"lat":38.9,"lon":-77.0}"#.to_vec(),
        tombstone: false,
    })?;

    let delivery = node
        .poll(subscription, 1)?
        .into_iter()
        .next()
        .ok_or("the local publication was not delivered")?;

    println!(
        "item={} payload={}",
        hex(&receipt.id),
        String::from_utf8_lossy(&delivery.item.payload)
    );

    // Acknowledge only after application processing succeeds. Until then Aster
    // may redeliver the item after a restart.
    node.acknowledge(subscription, delivery.item.id)?;
    Ok(())
}

fn hex(id: &aster_mesh::ItemId) -> String {
    id.iter().map(|byte| format!("{byte:02x}")).collect()
}
