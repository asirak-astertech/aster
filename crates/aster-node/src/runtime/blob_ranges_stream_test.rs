//! Controlled live-stream boundary fault, keyed by the test-owned Store allocation.
use super::*;
use std::sync::OnceLock;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) enum Boundary {
    Original,
    LostTerminal,
    BadAead,
    WrongAad,
    Revocation,
    AppendCapacity,
    PrefixConflict,
    UnavailableGap,
}

pub(super) struct Fault {
    pub fired: std::sync::atomic::AtomicBool,
    pub boundary: Boundary,
    pub before_append: bool,
    pub sender_paused: tokio::sync::Notify,
    pub receiver_paused: tokio::sync::Notify,
    pub release_sender: tokio::sync::Notify,
    pub release_receiver: tokio::sync::Notify,
}

fn registry() -> &'static StdMutex<BTreeMap<usize, Arc<Fault>>> {
    static REGISTRY: OnceLock<StdMutex<BTreeMap<usize, Arc<Fault>>>> = OnceLock::new();
    REGISTRY.get_or_init(StdMutex::default)
}

pub(super) fn install(sender: &Store, receiver: &Store, before_append: bool) -> Arc<Fault> {
    install_boundary(sender, receiver, before_append, Boundary::Original)
}

pub(super) fn install_boundary(
    sender: &Store,
    receiver: &Store,
    before_append: bool,
    boundary: Boundary,
) -> Arc<Fault> {
    let fault = Arc::new(Fault {
        fired: std::sync::atomic::AtomicBool::new(false),
        boundary,
        before_append,
        sender_paused: tokio::sync::Notify::new(),
        receiver_paused: tokio::sync::Notify::new(),
        release_sender: tokio::sync::Notify::new(),
        release_receiver: tokio::sync::Notify::new(),
    });
    let mut registry = registry().lock().unwrap();
    registry.insert(sender as *const Store as usize, fault.clone());
    registry.insert(receiver as *const Store as usize, fault.clone());
    fault
}

pub(super) fn remove(store: &Store) {
    registry()
        .lock()
        .unwrap()
        .remove(&(store as *const Store as usize));
}

pub(super) fn get(store: &Store) -> Option<Arc<Fault>> {
    registry()
        .lock()
        .unwrap()
        .get(&(store as *const Store as usize))
        .cloned()
}

fn second_data(plaintext: &[u8]) -> bool {
    plaintext.starts_with(b"ABRD\x01") && plaintext.get(37..39) == Some(&[0, 1])
}

pub(super) fn write_digest(store: &Store, plaintext: &[u8], mut digest: [u8; 32]) -> [u8; 32] {
    if second_data(plaintext)
        && let Some(fault) = get(store)
        && fault.boundary == Boundary::WrongAad
    {
        digest[0] ^= 1;
        fault.fired.store(true, Ordering::Release);
    }
    digest
}

pub(super) fn write_ciphertext(
    store: &Store,
    plaintext: &[u8],
    mut ciphertext: Vec<u8>,
) -> Vec<u8> {
    if second_data(plaintext)
        && let Some(fault) = get(store)
        && fault.boundary == Boundary::BadAead
    {
        *ciphertext.last_mut().unwrap() ^= 1;
        fault.fired.store(true, Ordering::Release);
    }
    ciphertext
}

pub(super) fn range_bytes(store: &Store, index: usize, bytes: Option<Vec<u8>>) -> Option<Vec<u8>> {
    if index == 1
        && let Some(fault) = get(store)
        && fault.boundary == Boundary::UnavailableGap
    {
        fault.fired.store(true, Ordering::Release);
        return None;
    }
    bytes
}

pub(super) fn append_boundary(
    store: &Store,
    index: usize,
    incoming: usize,
) -> Result<(), StoreError> {
    if index == 1
        && let Some(fault) = get(store)
        && fault.boundary == Boundary::AppendCapacity
    {
        fault.fired.store(true, Ordering::Release);
        return Err(StoreError::Blob(
            BlobStoreError::NetworkStagingByteLimitExceeded {
                current: MAX_BLOB_NETWORK_RANGE_BYTES as u64,
                incoming: incoming as u64,
                limit: MAX_BLOB_NETWORK_RANGE_BYTES as u64,
            },
        ));
    }
    Ok(())
}
