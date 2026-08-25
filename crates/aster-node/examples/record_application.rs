//! Minimal selected Record projection example.
//!
//! Run with a state directory and its explicitly unprotected reference mission
//! bundle. Repeating the command resolves the same durable operation keys. A
//! single stopped writer creates causal successors, so this safe facade-only
//! example remains conflict-free; the node tests construct independently
//! source-verified concurrent publishers and exercise guarded resolution.

use std::{env, error::Error, path::PathBuf};

use aster_node::application::{
    Priority, RecordPublishRequest, RecordQuery, Scope, SelectedRecordNode, Topic,
};

fn main() -> Result<(), Box<dyn Error>> {
    let mut arguments = env::args_os().skip(1);
    let state = arguments
        .next()
        .map(PathBuf::from)
        .ok_or("usage: record_application STATE_DIR MISSION_BUNDLE")?;
    let mission = arguments
        .next()
        .map(PathBuf::from)
        .ok_or("usage: record_application STATE_DIR MISSION_BUNDLE")?;
    if arguments.next().is_some() {
        return Err("usage: record_application STATE_DIR MISSION_BUNDLE".into());
    }

    // The capability-tour fixture provisions this topic/scope. Operational
    // applications choose values admitted by their own mission provider.
    let topic = Topic::new("mesh.ping-pong")?;
    let scope = Scope::new("demo/mesh")?;
    let logical_key = b"asset-7".to_vec();
    let mut node = SelectedRecordNode::open_unprotected_reference(&state, &mission)?;

    let publish = |operation_key: &[u8], payload: &[u8]| RecordPublishRequest {
        operation_key: operation_key.to_vec(),
        topic: topic.clone(),
        scope: scope.clone(),
        priority: Priority::Priority,
        logical_key: logical_key.clone(),
        payload: payload.to_vec(),
        tombstone: false,
    };
    let ready = node.publish(publish(b"example/record/asset-7/ready", b"ready"))?;
    let moving = node.publish(publish(b"example/record/asset-7/moving", b"moving"))?;
    let projection = node.query(RecordQuery {
        topic,
        scope,
        logical_key,
        include_superseded_versions: true,
    })?;
    let current = projection.current.ok_or("Record projection is empty")?;
    println!(
        "RECORD current={} value={} counter={} ready_inserted={} moving_inserted={} concurrent={} superseded={} conflict={}",
        current.id,
        String::from_utf8_lossy(&current.payload),
        current.publisher_counter,
        ready.inserted,
        moving.inserted,
        projection.concurrent.len(),
        projection.superseded.len(),
        projection.conflict.is_some(),
    );
    Ok(())
}
