//! Minimal stopped selected Blob streaming example.
//!
//! Run with a state directory, its explicitly unprotected reference mission
//! bundle, an input file, and an output file. Repeating the same operation with
//! unchanged input returns the original signed publication.

use std::{env, error::Error, fs::File, path::PathBuf};

use aster_node::application::{
    BlobPublishRequest, BlobReadRequest, Priority, Scope, SelectedBlobNode, Topic,
};

fn main() -> Result<(), Box<dyn Error>> {
    let mut arguments = env::args_os().skip(1);
    let state = next_path(&mut arguments)?;
    let mission = next_path(&mut arguments)?;
    let input = next_path(&mut arguments)?;
    let output = next_path(&mut arguments)?;
    if arguments.next().is_some() {
        return Err(usage().into());
    }

    // The capability-tour fixture provisions this topic/scope. Operational
    // applications choose values admitted by their own mission provider.
    let topic = Topic::new("mesh.ping-pong")?;
    let scope = Scope::new("demo/mesh")?;
    let mut node = SelectedBlobNode::open_unprotected_reference(&state, &mission)?;
    let mut source = File::open(input)?;
    let published = node.publish(
        BlobPublishRequest {
            operation_key: b"example/blob/input-v1".to_vec(),
            topic: topic.clone(),
            scope: scope.clone(),
            priority: Priority::Priority,
            media_type: Some("application/octet-stream".into()),
            schema_id: Vec::new(),
        },
        &mut source,
    )?;
    let mut destination = File::create(output)?;
    let read = node.read_into(
        BlobReadRequest {
            id: published.id,
            topic,
            scope,
        },
        &mut destination,
    )?;
    println!(
        "BLOB id={} bytes={} chunks={} inserted={} media_type={}",
        published.id,
        read.total_len,
        read.verified_chunks,
        published.inserted,
        read.media_type.as_deref().unwrap_or("none"),
    );
    Ok(())
}

fn next_path(arguments: &mut impl Iterator<Item = std::ffi::OsString>) -> Result<PathBuf, String> {
    arguments.next().map(PathBuf::from).ok_or_else(usage)
}

fn usage() -> String {
    "usage: blob_application STATE_DIR MISSION_BUNDLE INPUT_FILE OUTPUT_FILE".into()
}
