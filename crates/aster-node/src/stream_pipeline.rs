use std::{
    collections::BTreeMap,
    error::Error,
    fmt::{self, Display, Formatter},
    future::Future,
    pin::Pin,
    sync::Arc,
    time::{Duration, Instant},
};
use tokio::{
    sync::{OwnedSemaphorePermit, Semaphore, mpsc},
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

    pub const fn max_in_flight_items(&self) -> usize {
        self.max_in_flight_items
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

enum PartitionSourcePoll {
    Ready(Result<Option<StreamPartition>, PipelineError>),
    Pending,
}

trait PartitionSource {
    fn try_next_partition(&mut self) -> PartitionSourcePoll;

    fn next_partition(
        &mut self,
    ) -> Pin<Box<dyn Future<Output = Result<Option<StreamPartition>, PipelineError>> + Send + '_>>;
}

struct IteratorPartitionSource<I> {
    iterator: I,
}

impl<I> PartitionSource for IteratorPartitionSource<I>
where
    I: Iterator<Item = StreamPartition>,
{
    fn try_next_partition(&mut self) -> PartitionSourcePoll {
        PartitionSourcePoll::Ready(Ok(self.iterator.next()))
    }

    fn next_partition(
        &mut self,
    ) -> Pin<Box<dyn Future<Output = Result<Option<StreamPartition>, PipelineError>> + Send + '_>>
    {
        Box::pin(std::future::ready(Ok(self.iterator.next())))
    }
}

struct ChannelPartitionSource {
    receiver: mpsc::Receiver<Result<StreamPartition, PipelineError>>,
}

impl PartitionSource for ChannelPartitionSource {
    fn try_next_partition(&mut self) -> PartitionSourcePoll {
        match self.receiver.try_recv() {
            Ok(partition) => PartitionSourcePoll::Ready(partition.map(Some)),
            Err(mpsc::error::TryRecvError::Empty) => PartitionSourcePoll::Pending,
            Err(mpsc::error::TryRecvError::Disconnected) => PartitionSourcePoll::Ready(Ok(None)),
        }
    }

    fn next_partition(
        &mut self,
    ) -> Pin<Box<dyn Future<Output = Result<Option<StreamPartition>, PipelineError>> + Send + '_>>
    {
        Box::pin(async move { self.receiver.recv().await.transpose() })
    }
}

pub async fn run_ordered_pipeline<I, T, Map, Sink, SinkFuture>(
    job_id: StreamJobId,
    partitions: I,
    limits: PipelineLimits,
    map: Map,
    sink: Sink,
) -> Result<PipelineReport, PipelineError>
where
    I: IntoIterator<Item = StreamPartition>,
    T: Send + 'static,
    Map: Fn(StreamPartition) -> Result<T, PipelineError> + Send + Sync + 'static,
    Sink: FnMut(MappedPartition<T>) -> SinkFuture,
    SinkFuture: Future<Output = Result<(), PipelineError>>,
{
    run_ordered_pipeline_source(
        job_id,
        IteratorPartitionSource {
            iterator: partitions.into_iter(),
        },
        0,
        limits,
        map,
        sink,
    )
    .await
}

pub async fn run_ordered_channel_pipeline<T, Map, Sink, SinkFuture>(
    job_id: StreamJobId,
    receiver: mpsc::Receiver<Result<StreamPartition, PipelineError>>,
    limits: PipelineLimits,
    map: Map,
    sink: Sink,
) -> Result<PipelineReport, PipelineError>
where
    T: Send + 'static,
    Map: Fn(StreamPartition) -> Result<T, PipelineError> + Send + Sync + 'static,
    Sink: FnMut(MappedPartition<T>) -> SinkFuture,
    SinkFuture: Future<Output = Result<(), PipelineError>>,
{
    run_ordered_channel_pipeline_from(job_id, receiver, 0, limits, map, sink).await
}

pub async fn run_ordered_channel_pipeline_from<T, Map, Sink, SinkFuture>(
    job_id: StreamJobId,
    receiver: mpsc::Receiver<Result<StreamPartition, PipelineError>>,
    initial_index: u64,
    limits: PipelineLimits,
    map: Map,
    sink: Sink,
) -> Result<PipelineReport, PipelineError>
where
    T: Send + 'static,
    Map: Fn(StreamPartition) -> Result<T, PipelineError> + Send + Sync + 'static,
    Sink: FnMut(MappedPartition<T>) -> SinkFuture,
    SinkFuture: Future<Output = Result<(), PipelineError>>,
{
    run_ordered_pipeline_source(
        job_id,
        ChannelPartitionSource { receiver },
        initial_index,
        limits,
        map,
        sink,
    )
    .await
}

async fn run_ordered_pipeline_source<Source, T, Map, Sink, SinkFuture>(
    job_id: StreamJobId,
    mut source: Source,
    initial_index: u64,
    limits: PipelineLimits,
    map: Map,
    mut sink: Sink,
) -> Result<PipelineReport, PipelineError>
where
    Source: PartitionSource,
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
    let mut next_index = initial_index;
    let mut peak_items = 0_usize;
    let mut peak_bytes = 0_usize;
    let mut peak_reorder = 0_usize;
    let mut next_partition = None;
    let mut source_done = false;

    loop {
        while jobs.len() < limits.workers
            && jobs.len() + reorder.len() < limits.max_in_flight_items
            && jobs.len() + reorder.len() < limits.max_reorder_items
        {
            if next_partition.is_none() && !source_done {
                let next = if jobs.is_empty() && reorder.is_empty() {
                    source.next_partition().await
                } else {
                    match source.try_next_partition() {
                        PartitionSourcePoll::Ready(next) => next,
                        PartitionSourcePoll::Pending => break,
                    }
                };
                match next {
                    Ok(Some(partition)) => next_partition = Some(partition),
                    Ok(None) => source_done = true,
                    Err(error) => {
                        abort_and_join(&mut jobs).await;
                        return Err(error);
                    }
                }
            }
            let Some(next) = next_partition.as_ref() else {
                break;
            };
            if next.len() > limits.max_in_flight_bytes {
                jobs.abort_all();
                return Err(PipelineError::PartitionTooLarge);
            }
            if next.len() > byte_budget.available_permits() {
                break;
            }
            let partition = next_partition.take().expect("buffered partition");
            let index = partition.index;
            if partition.is_empty() {
                jobs.abort_all();
                return Err(PipelineError::EmptyPartition);
            }
            let expected = initial_index.checked_add(accepted_items).ok_or(
                PipelineError::NonContiguousIndex {
                    expected: u64::MAX,
                    actual: index,
                },
            )?;
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
            if source_done && next_partition.is_none() && reorder.is_empty() {
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
    async fn pipeline_accepts_async_partitions_and_preserves_order() {
        let (sender, receiver) = tokio::sync::mpsc::channel(2);
        let producer = tokio::spawn(async move {
            for index in 0..8 {
                sender
                    .send(Ok(StreamPartition::new(index, vec![index as u8; 32])))
                    .await
                    .expect("pipeline remains open");
            }
        });
        let observed = Arc::new(Mutex::new(Vec::new()));
        let sink_observed = Arc::clone(&observed);
        let report = run_ordered_channel_pipeline(
            StreamJobId::from_bytes([6; 16]),
            receiver,
            PipelineLimits::new(4, 4, 128, 4).expect("limits"),
            |partition| {
                if partition.index() == 0 {
                    std::thread::sleep(std::time::Duration::from_millis(10));
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
        producer.await.expect("producer");

        assert_eq!(
            *observed.lock().expect("observed lock"),
            (0..8).collect::<Vec<_>>()
        );
        assert_eq!(report.completed_items(), 8);
        assert!(report.peak_in_flight_bytes() <= 128);
    }

    #[tokio::test]
    async fn pipeline_propagates_async_source_failure_after_drain() {
        let (sender, receiver) = tokio::sync::mpsc::channel(2);
        sender
            .send(Ok(StreamPartition::new(0, vec![0; 16])))
            .await
            .expect("partition");
        sender
            .send(Err(PipelineError::MapFailed("source".into())))
            .await
            .expect("failure");
        drop(sender);

        let result = run_ordered_channel_pipeline(
            StreamJobId::from_bytes([5; 16]),
            receiver,
            PipelineLimits::new(1, 1, 16, 1).expect("limits"),
            |partition| Ok(partition.into_bytes()),
            |_| std::future::ready(Ok(())),
        )
        .await;

        assert!(matches!(result, Err(PipelineError::MapFailed(message)) if message == "source"));
    }

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

    #[tokio::test]
    async fn resumed_channel_pipeline_starts_at_durable_partition_index() {
        let (sender, receiver) = mpsc::channel(2);
        sender
            .send(Ok(StreamPartition::new(7, vec![7])))
            .await
            .unwrap();
        sender
            .send(Ok(StreamPartition::new(8, vec![8])))
            .await
            .unwrap();
        drop(sender);
        let observed = Arc::new(Mutex::new(Vec::new()));
        let sink_observed = Arc::clone(&observed);
        let report = run_ordered_channel_pipeline_from(
            StreamJobId::from_bytes([12; 16]),
            receiver,
            7,
            PipelineLimits::new(2, 2, 2, 2).unwrap(),
            |partition| Ok(partition.into_bytes()),
            move |mapped| {
                sink_observed.lock().unwrap().push(mapped.index());
                std::future::ready(Ok(()))
            },
        )
        .await
        .unwrap();
        assert_eq!(*observed.lock().unwrap(), vec![7, 8]);
        assert_eq!(report.completed_items(), 2);
    }
}
