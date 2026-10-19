use std::{
    collections::BTreeMap,
    error::Error,
    fmt::{self, Display, Formatter},
    future::Future,
    sync::Arc,
    time::{Duration, Instant},
};
use tokio::{
    sync::{OwnedSemaphorePermit, Semaphore},
    task::JoinSet,
};

#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub struct StreamJobId([u8; 16]);

impl StreamJobId {
    pub const fn from_bytes(bytes: [u8; 16]) -> Self {
        Self(bytes)
    }
}

#[derive(Debug)]
pub struct StreamPartition {
    index: u64,
    bytes: Vec<u8>,
}

impl StreamPartition {
    pub fn new(index: u64, bytes: Vec<u8>) -> Self {
        Self { index, bytes }
    }

    pub const fn index(&self) -> u64 {
        self.index
    }

    pub fn len(&self) -> usize {
        self.bytes.len()
    }

    pub fn is_empty(&self) -> bool {
        self.bytes.is_empty()
    }

    pub fn into_bytes(self) -> Vec<u8> {
        self.bytes
    }
}

#[derive(Debug)]
pub struct MappedPartition<T> {
    index: u64,
    input_bytes: usize,
    value: T,
}

impl<T> MappedPartition<T> {
    pub const fn index(&self) -> u64 {
        self.index
    }

    pub const fn input_bytes(&self) -> usize {
        self.input_bytes
    }

    pub fn value(&self) -> &T {
        &self.value
    }

    pub fn into_value(self) -> T {
        self.value
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct PipelineLimits {
    workers: usize,
    max_in_flight_items: usize,
    max_in_flight_bytes: usize,
    max_reorder_items: usize,
}

impl PipelineLimits {
    pub fn new(
        workers: usize,
        max_in_flight_items: usize,
        max_in_flight_bytes: usize,
        max_reorder_items: usize,
    ) -> Result<Self, PipelineError> {
        if workers == 0
            || max_in_flight_items == 0
            || max_in_flight_bytes == 0
            || max_in_flight_bytes > u32::MAX as usize
            || max_reorder_items == 0
            || workers > max_in_flight_items
            || max_reorder_items > max_in_flight_items
        {
            return Err(PipelineError::InvalidLimits);
        }
        Ok(Self {
            workers,
            max_in_flight_items,
            max_in_flight_bytes,
            max_reorder_items,
        })
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(usize)]
pub enum PipelineStage {
    Admission = 0,
    Map = 1,
    Reorder = 2,
    Sink = 3,
}

const PIPELINE_STAGE_COUNT: usize = 4;

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct StageObservation {
    pub items: u64,
    pub bytes: u64,
    pub service_ns: u64,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PipelineReport {
    job_id: StreamJobId,
    accepted_items: u64,
    completed_items: u64,
    peak_in_flight_items: usize,
    peak_in_flight_bytes: usize,
    peak_reorder_items: usize,
    stages: [StageObservation; PIPELINE_STAGE_COUNT],
}

impl PipelineReport {
    pub const fn accepted_items(&self) -> u64 {
        self.accepted_items
    }
    pub const fn completed_items(&self) -> u64 {
        self.completed_items
    }
    pub const fn peak_in_flight_items(&self) -> usize {
        self.peak_in_flight_items
    }
    pub const fn peak_in_flight_bytes(&self) -> usize {
        self.peak_in_flight_bytes
    }
    pub const fn peak_reorder_items(&self) -> usize {
        self.peak_reorder_items
    }
    pub const fn stage(&self, stage: PipelineStage) -> StageObservation {
        self.stages[stage as usize]
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum PipelineError {
    InvalidLimits,
    EmptyPartition,
    PartitionTooLarge,
    NonContiguousIndex { expected: u64, actual: u64 },
    WorkerPanicked,
    MapFailed(String),
    SinkFailed(String),
}

impl Display for PipelineError {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
        write!(formatter, "{self:?}")
    }
}

impl Error for PipelineError {}

struct Pending<T> {
    mapped: MappedPartition<T>,
    map_time: Duration,
    _item_permit: OwnedSemaphorePermit,
    _byte_permit: OwnedSemaphorePermit,
}

async fn abort_and_join<T: Send + 'static>(jobs: &mut JoinSet<Result<Pending<T>, PipelineError>>) {
    jobs.abort_all();
    while jobs.join_next().await.is_some() {}
}

fn add_observation(
    stages: &mut [StageObservation; PIPELINE_STAGE_COUNT],
    stage: PipelineStage,
    bytes: usize,
    elapsed: Duration,
) {
    let observation = &mut stages[stage as usize];
    observation.items = observation.items.saturating_add(1);
    observation.bytes = observation.bytes.saturating_add(bytes as u64);
    observation.service_ns = observation
        .service_ns
        .saturating_add(elapsed.as_nanos().min(u128::from(u64::MAX)) as u64);
}

pub async fn run_ordered_pipeline<I, T, Map, Sink, SinkFuture>(
    job_id: StreamJobId,
    partitions: I,
    limits: PipelineLimits,
    map: Map,
    mut sink: Sink,
) -> Result<PipelineReport, PipelineError>
where
    I: IntoIterator<Item = StreamPartition>,
    T: Send + 'static,
    Map: Fn(StreamPartition) -> Result<T, PipelineError> + Send + Sync + 'static,
    Sink: FnMut(MappedPartition<T>) -> SinkFuture,
    SinkFuture: Future<Output = Result<(), PipelineError>>,
{
    let item_budget = Arc::new(Semaphore::new(limits.max_in_flight_items));
    let byte_budget = Arc::new(Semaphore::new(limits.max_in_flight_bytes));
    let map = Arc::new(map);
    let mut jobs = JoinSet::new();
    let mut reorder = BTreeMap::<u64, Pending<T>>::new();
    let mut stages = [StageObservation::default(); PIPELINE_STAGE_COUNT];
    let mut accepted_items = 0_u64;
    let mut completed_items = 0_u64;
    let mut next_index = 0_u64;
    let mut peak_items = 0_usize;
    let mut peak_bytes = 0_usize;
    let mut peak_reorder = 0_usize;
    let mut iterator = partitions.into_iter().peekable();

    loop {
        while jobs.len() < limits.workers
            && jobs.len() + reorder.len() < limits.max_in_flight_items
            && jobs.len() + reorder.len() < limits.max_reorder_items
        {
            let Some(next) = iterator.peek() else { break };
            if next.len() > limits.max_in_flight_bytes {
                jobs.abort_all();
                return Err(PipelineError::PartitionTooLarge);
            }
            if next.len() > byte_budget.available_permits() {
                break;
            }
            let Some(partition) = iterator.next() else {
                break;
            };
            let index = partition.index;
            if partition.is_empty() {
                jobs.abort_all();
                return Err(PipelineError::EmptyPartition);
            }
            let expected = accepted_items;
            if index != expected {
                jobs.abort_all();
                return Err(PipelineError::NonContiguousIndex {
                    expected,
                    actual: index,
                });
            }
            let bytes = partition.len();
            let admission_started = Instant::now();
            let item_permit = Arc::clone(&item_budget)
                .acquire_owned()
                .await
                .map_err(|_| PipelineError::WorkerPanicked)?;
            let byte_permit = Arc::clone(&byte_budget)
                .acquire_many_owned(bytes as u32)
                .await
                .map_err(|_| PipelineError::WorkerPanicked)?;
            add_observation(
                &mut stages,
                PipelineStage::Admission,
                bytes,
                admission_started.elapsed(),
            );
            accepted_items += 1;
            let in_flight_items = limits.max_in_flight_items - item_budget.available_permits();
            let in_flight_bytes = limits.max_in_flight_bytes - byte_budget.available_permits();
            peak_items = peak_items.max(in_flight_items);
            peak_bytes = peak_bytes.max(in_flight_bytes);
            let map = Arc::clone(&map);
            jobs.spawn_blocking(move || {
                let started = Instant::now();
                let value = map(partition)?;
                Ok::<_, PipelineError>(Pending {
                    mapped: MappedPartition {
                        index,
                        input_bytes: bytes,
                        value,
                    },
                    map_time: started.elapsed(),
                    _item_permit: item_permit,
                    _byte_permit: byte_permit,
                })
            });
        }

        if jobs.is_empty() {
            if iterator.peek().is_none() && reorder.is_empty() {
                break;
            }
            if let Some(pending) = reorder.remove(&next_index) {
                let bytes = pending.mapped.input_bytes;
                add_observation(&mut stages, PipelineStage::Map, bytes, pending.map_time);
                let sink_started = Instant::now();
                if let Err(error) = sink(pending.mapped).await {
                    abort_and_join(&mut jobs).await;
                    return Err(PipelineError::SinkFailed(error.to_string()));
                }
                add_observation(
                    &mut stages,
                    PipelineStage::Sink,
                    bytes,
                    sink_started.elapsed(),
                );
                completed_items += 1;
                next_index += 1;
                continue;
            }
            return Err(PipelineError::NonContiguousIndex {
                expected: next_index,
                actual: reorder.keys().next().copied().unwrap_or(next_index),
            });
        }

        let joined = jobs.join_next().await.expect("non-empty join set");
        let pending = match joined {
            Ok(Ok(pending)) => pending,
            Ok(Err(error)) => {
                abort_and_join(&mut jobs).await;
                return Err(error);
            }
            Err(_) => {
                abort_and_join(&mut jobs).await;
                return Err(PipelineError::WorkerPanicked);
            }
        };
        let reorder_started = Instant::now();
        let index = pending.mapped.index;
        let bytes = pending.mapped.input_bytes;
        if reorder.insert(index, pending).is_some() {
            jobs.abort_all();
            return Err(PipelineError::NonContiguousIndex {
                expected: next_index,
                actual: index,
            });
        }
        peak_reorder = peak_reorder.max(reorder.len());
        add_observation(
            &mut stages,
            PipelineStage::Reorder,
            bytes,
            reorder_started.elapsed(),
        );

        while let Some(pending) = reorder.remove(&next_index) {
            let bytes = pending.mapped.input_bytes;
            add_observation(&mut stages, PipelineStage::Map, bytes, pending.map_time);
            let sink_started = Instant::now();
            if let Err(error) = sink(pending.mapped).await {
                abort_and_join(&mut jobs).await;
                return Err(PipelineError::SinkFailed(error.to_string()));
            }
            add_observation(
                &mut stages,
                PipelineStage::Sink,
                bytes,
                sink_started.elapsed(),
            );
            completed_items += 1;
            next_index += 1;
        }
    }

    Ok(PipelineReport {
        job_id,
        accepted_items,
        completed_items,
        peak_in_flight_items: peak_items,
        peak_in_flight_bytes: peak_bytes,
        peak_reorder_items: peak_reorder,
        stages,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::{Arc, Mutex};

    #[tokio::test]
    async fn pipeline_reorders_shuffled_worker_results() {
        let observed = Arc::new(Mutex::new(Vec::new()));
        let sink_observed = Arc::clone(&observed);
        let partitions = (0..8)
            .map(|index| StreamPartition::new(index, vec![index as u8; 32]))
            .collect::<Vec<_>>();
        let report = run_ordered_pipeline(
            StreamJobId::from_bytes([7; 16]),
            partitions,
            PipelineLimits::new(4, 4, 256, 4).expect("limits"),
            |partition| {
                if partition.index() % 2 == 0 {
                    std::thread::sleep(std::time::Duration::from_millis(2));
                }
                Ok(partition.into_bytes())
            },
            move |mapped| {
                sink_observed
                    .lock()
                    .expect("sink lock")
                    .push(mapped.index());
                std::future::ready(Ok(()))
            },
        )
        .await
        .expect("pipeline");
        assert_eq!(
            *observed.lock().expect("observed lock"),
            (0..8).collect::<Vec<_>>()
        );
        assert_eq!(report.accepted_items(), 8);
        assert_eq!(report.completed_items(), 8);
    }

    #[tokio::test]
    async fn pipeline_never_exceeds_byte_or_item_budget() {
        let partitions = (0..32)
            .map(|index| StreamPartition::new(index, vec![0; 64]))
            .collect::<Vec<_>>();
        let report = run_ordered_pipeline(
            StreamJobId::from_bytes([8; 16]),
            partitions,
            PipelineLimits::new(3, 3, 192, 3).expect("limits"),
            |partition| Ok(partition.into_bytes()),
            |_| std::future::ready(Ok(())),
        )
        .await
        .expect("pipeline");
        assert!(report.peak_in_flight_items() <= 3);
        assert!(report.peak_in_flight_bytes() <= 192);
        assert!(report.peak_reorder_items() <= 3);
    }

    #[tokio::test]
    async fn pipeline_worker_panic_is_terminal_not_success() {
        let result = run_ordered_pipeline(
            StreamJobId::from_bytes([9; 16]),
            vec![StreamPartition::new(0, vec![0; 4])],
            PipelineLimits::new(1, 1, 4, 1).expect("limits"),
            |_| -> Result<Vec<u8>, PipelineError> { panic!("worker failure") },
            |_| std::future::ready(Ok(())),
        )
        .await;
        assert!(matches!(result, Err(PipelineError::WorkerPanicked)));
    }

    #[tokio::test]
    async fn pipeline_slow_first_partition_backpressures_at_reorder_limit() {
        let report = run_ordered_pipeline(
            StreamJobId::from_bytes([10; 16]),
            (0..12)
                .map(|index| StreamPartition::new(index, vec![0; 16]))
                .collect::<Vec<_>>(),
            PipelineLimits::new(4, 4, 64, 2).expect("limits"),
            |partition| {
                if partition.index() == 0 {
                    std::thread::sleep(std::time::Duration::from_millis(15));
                }
                Ok(partition.into_bytes())
            },
            |_| std::future::ready(Ok(())),
        )
        .await
        .expect("pipeline");
        assert!(report.peak_reorder_items() <= 2);
        assert!(report.peak_in_flight_items() <= 2);
    }

    #[tokio::test]
    async fn pipeline_sink_failure_joins_workers_and_reclaims_permits() {
        let started = std::time::Instant::now();
        let result = run_ordered_pipeline(
            StreamJobId::from_bytes([11; 16]),
            (0..4)
                .map(|index| StreamPartition::new(index, vec![0; 16]))
                .collect::<Vec<_>>(),
            PipelineLimits::new(4, 4, 64, 4).expect("limits"),
            |partition| {
                if partition.index() != 0 {
                    std::thread::sleep(std::time::Duration::from_millis(15));
                }
                Ok(partition.into_bytes())
            },
            |_| std::future::ready(Err(PipelineError::SinkFailed("cancel".into()))),
        )
        .await;
        assert!(matches!(result, Err(PipelineError::SinkFailed(_))));
        assert!(started.elapsed() >= std::time::Duration::from_millis(10));
    }
}
