use std::{
    collections::BTreeMap,
    error::Error,
    fmt::{self, Display, Formatter},
    future::Future,
    pin::Pin,
    sync::{
        Arc, Mutex,
        atomic::{AtomicBool, Ordering},
        mpsc as std_mpsc,
    },
    time::{Duration, Instant},
};
use tokio::sync::{OwnedSemaphorePermit, Semaphore, mpsc};

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
    source_end: u64,
    bytes: Vec<u8>,
}

impl StreamPartition {
    pub fn new(index: u64, bytes: Vec<u8>) -> Self {
        Self {
            index,
            source_end: 0,
            bytes,
        }
    }

    pub fn new_at(index: u64, source_end: u64, bytes: Vec<u8>) -> Self {
        Self {
            index,
            source_end,
            bytes,
        }
    }

    pub const fn index(&self) -> u64 {
        self.index
    }

    pub const fn source_end(&self) -> u64 {
        self.source_end
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
    pub queue_wait_ns: u64,
    pub service_ns: u64,
    pub output_blocked_ns: u64,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PipelineReport {
    job_id: StreamJobId,
    accepted_items: u64,
    completed_items: u64,
    peak_in_flight_items: usize,
    peak_in_flight_bytes: usize,
    peak_reorder_items: usize,
    worker_count: usize,
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
    pub const fn worker_count(&self) -> usize {
        self.worker_count
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
    queue_wait: Duration,
    map_time: Duration,
    mapped_at: Instant,
    _item_permit: Option<OwnedSemaphorePermit>,
    _byte_permit: Option<OwnedSemaphorePermit>,
}

struct Work {
    partition: StreamPartition,
    queued_at: Instant,
    item_permit: Option<OwnedSemaphorePermit>,
    byte_permit: Option<OwnedSemaphorePermit>,
}

pub(crate) struct FixedPartitionMapPool<T> {
    work_sender: Option<std_mpsc::SyncSender<Work>>,
    result_receiver: mpsc::UnboundedReceiver<Result<Pending<T>, PipelineError>>,
    cancelled: Arc<AtomicBool>,
    workers: Vec<std::thread::JoinHandle<()>>,
}

impl<T: Send + 'static> FixedPartitionMapPool<T> {
    pub(crate) fn new<Map>(
        worker_count: usize,
        queue_capacity: usize,
        map: Map,
    ) -> Result<Self, PipelineError>
    where
        Map: Fn(StreamPartition) -> Result<T, PipelineError> + Send + Sync + 'static,
    {
        if worker_count == 0 || queue_capacity == 0 {
            return Err(PipelineError::InvalidLimits);
        }
        let map = Arc::new(map);
        let cancelled = Arc::new(AtomicBool::new(false));
        let (work_sender, work_receiver) = std_mpsc::sync_channel::<Work>(queue_capacity);
        let work_receiver = Arc::new(Mutex::new(work_receiver));
        let (result_sender, result_receiver) = mpsc::unbounded_channel();
        let mut workers = Vec::with_capacity(worker_count);
        for worker_index in 0..worker_count {
            let receiver = Arc::clone(&work_receiver);
            let results = result_sender.clone();
            let map = Arc::clone(&map);
            let cancelled = Arc::clone(&cancelled);
            let worker = std::thread::Builder::new()
                .name(format!("aster-stream-map-{worker_index}"))
                .spawn(move || {
                    loop {
                        if cancelled.load(Ordering::Acquire) {
                            break;
                        }
                        let work = match receiver.lock() {
                            Ok(receiver) => receiver.recv(),
                            Err(_) => {
                                _ = results.send(Err(PipelineError::WorkerPanicked));
                                break;
                            }
                        };
                        let Ok(work) = work else {
                            break;
                        };
                        if cancelled.load(Ordering::Acquire) {
                            break;
                        }
                        let started = Instant::now();
                        let queue_wait = started.saturating_duration_since(work.queued_at);
                        let index = work.partition.index;
                        let bytes = work.partition.len();
                        let mapped = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                            map(work.partition)
                        }));
                        let result = match mapped {
                            Ok(Ok(value)) => Ok(Pending {
                                mapped: MappedPartition {
                                    index,
                                    input_bytes: bytes,
                                    value,
                                },
                                queue_wait,
                                map_time: started.elapsed(),
                                mapped_at: Instant::now(),
                                _item_permit: work.item_permit,
                                _byte_permit: work.byte_permit,
                            }),
                            Ok(Err(error)) => Err(error),
                            Err(_) => Err(PipelineError::WorkerPanicked),
                        };
                        let terminal = result.is_err();
                        if results.send(result).is_err() || terminal {
                            break;
                        }
                    }
                })
                .map_err(|_| PipelineError::WorkerPanicked)?;
            workers.push(worker);
        }
        drop(result_sender);
        Ok(Self {
            work_sender: Some(work_sender),
            result_receiver,
            cancelled,
            workers,
        })
    }

    fn submit(
        &self,
        partition: StreamPartition,
        item_permit: OwnedSemaphorePermit,
        byte_permit: OwnedSemaphorePermit,
    ) -> Result<(), PipelineError> {
        self.submit_work(Work {
            partition,
            queued_at: Instant::now(),
            item_permit: Some(item_permit),
            byte_permit: Some(byte_permit),
        })
    }

    fn submit_work(&self, work: Work) -> Result<(), PipelineError> {
        self.work_sender
            .as_ref()
            .ok_or(PipelineError::WorkerPanicked)?
            .send(work)
            .map_err(|_| PipelineError::WorkerPanicked)
    }

    async fn recv(&mut self) -> Result<Pending<T>, PipelineError> {
        self.result_receiver
            .recv()
            .await
            .ok_or(PipelineError::WorkerPanicked)?
    }

    pub(crate) fn submit_unbudgeted(
        &self,
        partition: StreamPartition,
    ) -> Result<(), PipelineError> {
        self.submit_work(Work {
            partition,
            queued_at: Instant::now(),
            item_permit: None,
            byte_permit: None,
        })
    }

    pub(crate) fn try_recv_mapped(&mut self) -> Result<Option<MappedPartition<T>>, PipelineError> {
        match self.result_receiver.try_recv() {
            Ok(result) => result.map(|pending| Some(pending.mapped)),
            Err(mpsc::error::TryRecvError::Empty) => Ok(None),
            Err(mpsc::error::TryRecvError::Disconnected) => Err(PipelineError::WorkerPanicked),
        }
    }

    pub(crate) fn recv_mapped_blocking(&mut self) -> Result<MappedPartition<T>, PipelineError> {
        self.result_receiver
            .blocking_recv()
            .ok_or(PipelineError::WorkerPanicked)?
            .map(|pending| pending.mapped)
    }

    pub(crate) fn shutdown(mut self) -> Result<(), PipelineError> {
        self.cancelled.store(true, Ordering::Release);
        drop(self.work_sender.take());
        let mut panicked = false;
        for worker in self.workers.drain(..) {
            panicked |= worker.join().is_err();
        }
        if panicked {
            Err(PipelineError::WorkerPanicked)
        } else {
            Ok(())
        }
    }
}

async fn stop_workers<T: Send + 'static>(pool: FixedPartitionMapPool<T>) -> bool {
    tokio::task::spawn_blocking(move || pool.shutdown().is_err())
        .await
        .unwrap_or(true)
}

impl<T> Drop for FixedPartitionMapPool<T> {
    fn drop(&mut self) {
        self.cancelled.store(true, Ordering::Release);
        drop(self.work_sender.take());
        // Normal paths call shutdown. On cancellation, joining here guarantees
        // map workers never outlive the job whose plaintext they own.
        let mut panicked = false;
        for worker in self.workers.drain(..) {
            panicked |= worker.join().is_err();
        }
        let _ = panicked;
    }
}

fn add_observation(
    stages: &mut [StageObservation; PIPELINE_STAGE_COUNT],
    stage: PipelineStage,
    bytes: usize,
    queue_wait: Duration,
    service: Duration,
    output_blocked: Duration,
) {
    let observation = &mut stages[stage as usize];
    observation.items = observation.items.saturating_add(1);
    observation.bytes = observation.bytes.saturating_add(bytes as u64);
    observation.queue_wait_ns = observation
        .queue_wait_ns
        .saturating_add(queue_wait.as_nanos().min(u128::from(u64::MAX)) as u64);
    observation.service_ns = observation
        .service_ns
        .saturating_add(service.as_nanos().min(u128::from(u64::MAX)) as u64);
    observation.output_blocked_ns = observation
        .output_blocked_ns
        .saturating_add(output_blocked.as_nanos().min(u128::from(u64::MAX)) as u64);
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
    let mut map_pool = FixedPartitionMapPool::new(limits.workers, limits.max_in_flight_items, map)?;

    let outcome = async {
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
            let mut in_flight_items = limits.max_in_flight_items - item_budget.available_permits();
            while in_flight_items < limits.max_in_flight_items
                && in_flight_items < limits.max_reorder_items
            {
                if next_partition.is_none() && !source_done {
                    let next = if in_flight_items == 0 {
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
                        Err(error) => return Err(error),
                    }
                }
                let Some(next) = next_partition.as_ref() else {
                    break;
                };
                if next.len() > limits.max_in_flight_bytes {
                    return Err(PipelineError::PartitionTooLarge);
                }
                if next.len() > byte_budget.available_permits() {
                    break;
                }
                let partition = next_partition.take().expect("buffered partition");
                let index = partition.index;
                if partition.is_empty() {
                    return Err(PipelineError::EmptyPartition);
                }
                let expected = initial_index.checked_add(accepted_items).ok_or(
                    PipelineError::NonContiguousIndex {
                        expected: u64::MAX,
                        actual: index,
                    },
                )?;
                if index != expected {
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
                    Duration::ZERO,
                    admission_started.elapsed(),
                    Duration::ZERO,
                );
                accepted_items += 1;
                let current_items = limits.max_in_flight_items - item_budget.available_permits();
                let in_flight_bytes = limits.max_in_flight_bytes - byte_budget.available_permits();
                peak_items = peak_items.max(current_items);
                peak_bytes = peak_bytes.max(in_flight_bytes);
                map_pool.submit(partition, item_permit, byte_permit)?;
                in_flight_items = limits.max_in_flight_items - item_budget.available_permits();
            }

            let in_flight_items = limits.max_in_flight_items - item_budget.available_permits();
            if in_flight_items == 0 {
                if source_done && next_partition.is_none() && reorder.is_empty() {
                    break;
                }
                continue;
            }

            let pending = map_pool.recv().await?;
            let reorder_started = Instant::now();
            let index = pending.mapped.index;
            let bytes = pending.mapped.input_bytes;
            if reorder.insert(index, pending).is_some() {
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
                Duration::ZERO,
                reorder_started.elapsed(),
                Duration::ZERO,
            );

            while let Some(pending) = reorder.remove(&next_index) {
                let bytes = pending.mapped.input_bytes;
                add_observation(
                    &mut stages,
                    PipelineStage::Map,
                    bytes,
                    pending.queue_wait,
                    pending.map_time,
                    pending.mapped_at.elapsed(),
                );
                let sink_started = Instant::now();
                if let Err(error) = sink(pending.mapped).await {
                    return Err(PipelineError::SinkFailed(error.to_string()));
                }
                add_observation(
                    &mut stages,
                    PipelineStage::Sink,
                    bytes,
                    Duration::ZERO,
                    sink_started.elapsed(),
                    Duration::ZERO,
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
            worker_count: limits.workers,
            stages,
        })
    }
    .await;

    let worker_panicked = stop_workers(map_pool).await;
    if worker_panicked && outcome.is_ok() {
        Err(PipelineError::WorkerPanicked)
    } else {
        outcome
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::{
        collections::HashSet,
        sync::{
            Arc, Barrier, Condvar, Mutex,
            atomic::{AtomicUsize, Ordering},
        },
    };

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
    async fn pipeline_uses_one_fixed_worker_set_for_the_complete_job() {
        let threads = Arc::new(Mutex::new(HashSet::new()));
        let observed_threads = Arc::clone(&threads);
        let first_workers = Arc::new(Barrier::new(2));
        let worker_rendezvous = Arc::clone(&first_workers);
        let report = run_ordered_pipeline(
            StreamJobId::from_bytes([0x81; 16]),
            (0..64)
                .map(|index| StreamPartition::new(index, vec![0; 16]))
                .collect::<Vec<_>>(),
            PipelineLimits::new(2, 4, 64, 4).expect("limits"),
            move |partition| {
                observed_threads
                    .lock()
                    .expect("thread set")
                    .insert(std::thread::current().id());
                if partition.index() < 2 {
                    worker_rendezvous.wait();
                }
                Ok(partition.into_bytes())
            },
            |_| std::future::ready(Ok(())),
        )
        .await
        .expect("pipeline");

        assert_eq!(report.worker_count(), 2);
        assert_eq!(threads.lock().expect("thread set").len(), 2);
    }

    #[test]
    fn fixed_pool_admission_does_not_wait_for_an_active_map() {
        let map_started = Arc::new(std::sync::Barrier::new(2));
        let release_map = Arc::new(std::sync::Barrier::new(2));
        let started = Arc::clone(&map_started);
        let release = Arc::clone(&release_map);
        let mut pool = FixedPartitionMapPool::new(1, 1, move |partition| {
            if partition.index() == 0 {
                started.wait();
                release.wait();
            }
            Ok(partition.into_bytes())
        })
        .expect("pool");

        pool.submit_unbudgeted(StreamPartition::new(0, vec![0; 16]))
            .expect("first partition");
        map_started.wait();
        let submitted = Instant::now();
        pool.submit_unbudgeted(StreamPartition::new(1, vec![1; 16]))
            .expect("queued partition");
        assert!(submitted.elapsed() < Duration::from_millis(100));

        release_map.wait();
        assert_eq!(pool.recv_mapped_blocking().expect("first map").index(), 0);
        assert_eq!(pool.recv_mapped_blocking().expect("second map").index(), 1);
        pool.shutdown().expect("joined pool");
    }

    #[tokio::test]
    async fn pipeline_early_validation_failure_joins_active_workers() {
        let (started_tx, started_rx) = std::sync::mpsc::sync_channel(0);
        let active = Arc::new(AtomicUsize::new(0));
        let active_worker = Arc::clone(&active);
        let release = Arc::new((Mutex::new(false), Condvar::new()));
        let source_release = Arc::clone(&release);
        let worker_release = Arc::clone(&release);
        let mut index = 0_u64;
        let partitions = std::iter::from_fn(move || {
            let partition = match index {
                0 => StreamPartition::new(0, vec![0; 16]),
                1 => {
                    started_rx
                        .recv_timeout(std::time::Duration::from_secs(1))
                        .expect("first worker started");
                    let (released, condition) = &*source_release;
                    *released.lock().expect("release state") = true;
                    condition.notify_all();
                    StreamPartition::new(1, vec![0; 33])
                }
                _ => return None,
            };
            index += 1;
            Some(partition)
        });
        let result = run_ordered_pipeline(
            StreamJobId::from_bytes([0x82; 16]),
            partitions,
            PipelineLimits::new(2, 2, 32, 2).expect("limits"),
            move |partition| {
                active_worker.fetch_add(1, Ordering::SeqCst);
                started_tx.send(()).expect("signal worker start");
                let (released, condition) = &*worker_release;
                let mut released = released.lock().expect("release state");
                while !*released {
                    released = condition.wait(released).expect("release worker");
                }
                active_worker.fetch_sub(1, Ordering::SeqCst);
                Ok(partition.into_bytes())
            },
            |_| std::future::ready(Ok(())),
        )
        .await;

        assert!(matches!(result, Err(PipelineError::PartitionTooLarge)));
        assert_eq!(active.load(Ordering::SeqCst), 0, "worker still running");
    }

    #[tokio::test]
    async fn pipeline_reports_queue_service_and_output_blocking_separately() {
        let report = run_ordered_pipeline(
            StreamJobId::from_bytes([0x83; 16]),
            (0..8)
                .map(|index| StreamPartition::new(index, vec![0; 16]))
                .collect::<Vec<_>>(),
            PipelineLimits::new(2, 4, 64, 4).expect("limits"),
            |partition| {
                if partition.index() == 0 {
                    std::thread::sleep(std::time::Duration::from_millis(10));
                }
                Ok(partition.into_bytes())
            },
            |_| std::future::ready(Ok(())),
        )
        .await
        .expect("pipeline");

        let map = report.stage(PipelineStage::Map);
        assert_eq!(map.items, 8);
        assert!(map.queue_wait_ns > 0);
        assert!(map.service_ns > 0);
        assert!(map.output_blocked_ns > 0);
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
        let active = Arc::new(AtomicUsize::new(0));
        let map_active = Arc::clone(&active);
        let gate = Arc::new((Mutex::new((0_usize, false)), Condvar::new()));
        let map_gate = Arc::clone(&gate);
        let sink_gate = Arc::clone(&gate);
        let result = run_ordered_pipeline(
            StreamJobId::from_bytes([11; 16]),
            (0..4)
                .map(|index| StreamPartition::new(index, vec![0; 16]))
                .collect::<Vec<_>>(),
            PipelineLimits::new(4, 4, 64, 4).expect("limits"),
            move |partition| {
                map_active.fetch_add(1, Ordering::SeqCst);
                let (state, condition) = &*map_gate;
                let mut state = state.lock().expect("worker gate");
                if partition.index() == 0 {
                    while state.0 == 0 {
                        state = condition.wait(state).expect("wait for active worker");
                    }
                } else {
                    state.0 += 1;
                    condition.notify_all();
                    while !state.1 {
                        state = condition.wait(state).expect("wait for sink failure");
                    }
                }
                drop(state);
                map_active.fetch_sub(1, Ordering::SeqCst);
                Ok(partition.into_bytes())
            },
            move |_| {
                let (state, condition) = &*sink_gate;
                state.lock().expect("worker gate").1 = true;
                condition.notify_all();
                std::future::ready(Err(PipelineError::SinkFailed("cancel".into())))
            },
        )
        .await;
        assert!(matches!(result, Err(PipelineError::SinkFailed(_))));
        assert_eq!(active.load(Ordering::SeqCst), 0, "worker still running");
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
