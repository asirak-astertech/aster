//! Minimal selected State latest-value projection example.
//!
//! Run with a state directory and its explicitly unprotected reference mission
//! bundle. Repeating the command resolves the same two durable operation keys
//! instead of creating additional versions.

use std::{env, error::Error, path::PathBuf};

use aster_node::application::{
    Priority, Scope, SelectedStateNode, StatePublishRequest, StateQuery, Topic,
};

fn main() -> Result<(), Box<dyn Error>> {
    let mut arguments = env::args_os().skip(1);
    let state = arguments
        .next()
        .map(PathBuf::from)
        .ok_or("usage: state_application STATE_DIR MISSION_BUNDLE")?;
    let mission = arguments
        .next()
        .map(PathBuf::from)
        .ok_or("usage: state_application STATE_DIR MISSION_BUNDLE")?;
    if arguments.next().is_some() {
        return Err("usage: state_application STATE_DIR MISSION_BUNDLE".into());
    }

    // The capability-tour fixture provisions this topic/scope. Operational
    // applications choose values admitted by their own mission provider.
    let topic = Topic::new("mesh.ping-pong")?;
    let scope = Scope::new("demo/mesh")?;
    let logical_key = b"asset-7".to_vec();
    let mut node = SelectedStateNode::open_unprotected_reference(&state, &mission)?;

    let publish = |operation_key: &[u8], payload: &[u8]| StatePublishRequest {
        operation_key: operation_key.to_vec(),
        topic: topic.clone(),
        scope: scope.clone(),
        priority: Priority::Priority,
        logical_key: logical_key.clone(),
        payload: payload.to_vec(),
        tombstone: false,
    };
    let ready = node.publish(publish(b"example/state/asset-7/ready", b"ready"))?;
    let moving = node.publish(publish(b"example/state/asset-7/moving", b"moving"))?;
    let projection = node.query(StateQuery {
        topic,
        scope,
        logical_key,
        include_recoverable_versions: true,
    })?;
    let current = projection.current.ok_or("State projection is empty")?;
    println!(
        "STATE current={} value={} counter={} ready_inserted={} moving_inserted={} recoverable={}",
        current.id,
        String::from_utf8_lossy(&current.payload),
        current.publisher_counter,
        ready.inserted,
        moving.inserted,
        projection.recoverable.len(),
    );
    Ok(())
}
