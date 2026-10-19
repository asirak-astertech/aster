//! Instrumented semantic-v9 Blob pipeline capacity benchmark.

use aster_mesh::{
    BlobMetadata, BlobPublicationStreamId, BlobStreamOpen, Priority, ProvisioningAccess,
    ReferenceEnvelopeSealer, ReferenceProvisioner, Scope, Topic, VersionVector,
};
use aster_node::{
    application::blob_stream::{publish_blob_stream, read_blob_stream},
    stream_pipeline::{PipelineLimits, PipelineStage},
};
use std::{error::Error, io::Read, path::PathBuf, time::Instant};

type AnyError = Box<dyn Error + Send + Sync>;

struct FixtureReader {
    offset: u64,
    total: u64,
}

impl Read for FixtureReader {
    fn read(&mut self, output: &mut [u8]) -> std::io::Result<usize> {
        let len = (self.total - self.offset).min(output.len() as u64) as usize;
        for (position, byte) in output[..len].iter_mut().enumerate() {
            let absolute = self.offset + position as u64;
            let mut word = (absolute / 8).wrapping_add(0x9e3779b97f4a7c15);
            word = (word ^ (word >> 30)).wrapping_mul(0xbf58476d1ce4e5b9);
            word = (word ^ (word >> 27)).wrapping_mul(0x94d049bb133111eb);
            word ^= word >> 31;
            *byte = (word >> ((absolute % 8) * 8)) as u8;
        }
        self.offset += len as u64;
        Ok(len)
    }
}

fn rate_mib(bytes: u64, elapsed_ns: u128) -> f64 {
    bytes as f64 / (1024.0 * 1024.0) / (elapsed_ns as f64 / 1_000_000_000.0)
}

fn report(
    label: &str,
    bytes: u64,
    elapsed_ns: u128,
    report: &aster_node::stream_pipeline::PipelineReport,
) {
    let admission = report.stage(PipelineStage::Admission);
    let map = report.stage(PipelineStage::Map);
    let reorder = report.stage(PipelineStage::Reorder);
    let sink = report.stage(PipelineStage::Sink);
    println!(
        "ASTER_STREAM_BENCH {{\"phase\":\"{label}\",\"bytes\":{bytes},\"elapsed_ns\":{elapsed_ns},\"mib_s\":{:.3},\"items\":{},\"workers\":{},\"peak_items\":{},\"peak_bytes\":{},\"peak_reorder\":{},\"admission_queue_ns\":{},\"admission_service_ns\":{},\"admission_output_blocked_ns\":{},\"map_queue_ns\":{},\"map_service_ns\":{},\"map_output_blocked_ns\":{},\"reorder_queue_ns\":{},\"reorder_service_ns\":{},\"reorder_output_blocked_ns\":{},\"sink_queue_ns\":{},\"sink_service_ns\":{},\"sink_output_blocked_ns\":{}}}",
        rate_mib(bytes, elapsed_ns),
        report.completed_items(),
        report.worker_count(),
        report.peak_in_flight_items(),
        report.peak_in_flight_bytes(),
        report.peak_reorder_items(),
        admission.queue_wait_ns,
        admission.service_ns,
        admission.output_blocked_ns,
        map.queue_wait_ns,
        map.service_ns,
        map.output_blocked_ns,
        reorder.queue_wait_ns,
        reorder.service_ns,
        reorder.output_blocked_ns,
        sink.queue_wait_ns,
        sink.service_ns,
        sink.output_blocked_ns,
    );
}

#[tokio::main(flavor = "multi_thread")]
async fn main() -> Result<(), AnyError> {
    let args = std::env::args().collect::<Vec<_>>();
    if args.len() != 4 {
        return Err("usage: blob_stream_pipeline_benchmark ROOT BYTES WORKERS".into());
    }
    let root = PathBuf::from(&args[1]).join(format!(
        "run-{}-{}",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)?
            .as_nanos()
    ));
    let bytes: u64 = args[2].parse()?;
    let workers: usize = args[3].parse()?;
    let topic = Topic::new("benchmark.blob")?;
    let scope = Scope::new("test/blob-stream-pipeline")?;
    let access = ProvisioningAccess::member(scope.clone(), vec![1], vec![topic.clone()])?;
    let mut provisioner = ReferenceProvisioner::from_seed([0x41; 32])?;
    let provider = provisioner
        .issue_node(1, &[access])
        .and_then(ReferenceEnvelopeSealer::open)?;
    let authorization = provider
        .blob_stream_authorization_digest(&scope, 1)
        .ok_or("missing Blob stream authorization")?;
    let open = BlobStreamOpen::new(
        BlobPublicationStreamId::from_bytes([0x11; 32])?,
        provider.identity(),
        b"pipeline-benchmark".to_vec(),
        provider.mission_authority_id(),
        1,
        VersionVector::default(),
        topic,
        scope,
        BlobMetadata::new(
            Some("application/octet-stream".into()),
            b"benchmark-v2".to_vec(),
        )?,
        Priority::Immediate,
        None,
        None,
        bytes,
        1,
        1,
        authorization,
        [0x51; 32],
    )?;
    let signed_open = provider.seal_blob_stream_open(&open)?;
    let verified = provider.verify_blob_stream_open(&signed_open)?;
    let sealer = provider.blob_stream_segment_sealer(&verified)?;
    let opener = provider.blob_stream_segment_opener(&verified)?;
    let in_flight = workers.max(2);
    let limits = PipelineLimits::new(
        workers,
        in_flight,
        in_flight * aster_mesh::BLOB_STREAM_SEGMENT_BYTES * 2,
        in_flight,
    )?;

    let started = Instant::now();
    let published = publish_blob_stream(
        FixtureReader {
            offset: 0,
            total: bytes,
        },
        &open,
        sealer,
        &root,
        limits,
    )
    .await?;
    let publish_ns = started.elapsed().as_nanos();
    report("publish", bytes, publish_ns, &published.report);

    let started = Instant::now();
    let read = read_blob_stream(
        &open,
        opener,
        &root,
        &mut std::io::sink(),
        (published.plaintext_root, published.ciphertext_root),
        limits,
    )
    .await?;
    let read_ns = started.elapsed().as_nanos();
    report("read", bytes, read_ns, &read);
    println!(
        "ASTER_STREAM_RESULT {{\"status\":\"ok\",\"bytes\":{bytes},\"segments\":{},\"workers\":{workers},\"root\":\"{}\",\"pack_root\":\"{}\"}}",
        published.segment_count,
        published
            .plaintext_root
            .iter()
            .map(|byte| format!("{byte:02x}"))
            .collect::<String>(),
        root.display(),
    );
    Ok(())
}
