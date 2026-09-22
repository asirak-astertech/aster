//! Crash-safe client support for numbered Event publication.
//!
//! The journal is protocol state rather than a cache. It must be explicitly
//! initialized once and is then opened exclusively. Opening never creates or
//! repairs a missing or corrupt journal.

use std::fmt;
use std::path::{Path, PathBuf};

use connectrpc::client::{ClientTransport, UnaryResponse};
use redb::{Database, Durability, ReadableDatabase, ReadableTable, TableDefinition};
use serde::{Deserialize, Serialize};

use crate::proto::aster::application::v1alpha1 as api;

const JOURNAL_META: TableDefinition<&str, &[u8]> =
    TableDefinition::new("aster.event-publication-journal.meta.v1");
const JOURNAL_ENTRIES: TableDefinition<u64, &[u8]> =
    TableDefinition::new("aster.event-publication-journal.entries.v1");
const STATE_KEY: &str = "state";
const JOURNAL_VERSION: u32 = 1;
const CLAIM_NONCE_BYTES: usize = 32;

/// An error that prevents the SDK from safely changing publication state.
#[derive(Debug)]
pub enum NumberedEventSdkError {
    Journal(String),
    Protocol(String),
    Transport(connectrpc::ConnectError),
}

impl fmt::Display for NumberedEventSdkError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Journal(message) => write!(formatter, "publication journal: {message}"),
            Self::Protocol(message) => write!(formatter, "publication protocol: {message}"),
            Self::Transport(error) => write!(formatter, "publication transport: {error}"),
        }
    }
}

impl std::error::Error for NumberedEventSdkError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Transport(error) => Some(error),
            Self::Journal(_) | Self::Protocol(_) => None,
        }
    }
}

impl From<connectrpc::ConnectError> for NumberedEventSdkError {
    fn from(value: connectrpc::ConnectError) -> Self {
        Self::Transport(value)
    }
}

type Result<T> = std::result::Result<T, NumberedEventSdkError>;

#[derive(Clone, Debug, Serialize, Deserialize)]
struct JournalState {
    version: u32,
    client_id: Vec<u8>,
    session: u64,
    allocated_through: u64,
    snapshot_revision: u64,
    recovery_complete: bool,
    pending_claim: Option<PendingClaim>,
    next_sequence: Option<u64>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
struct PendingClaim {
    expected_session: u64,
    nonce: Vec<u8>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
struct JournalEntry {
    intent: api::PublishNumberedEventRequest,
    result: Option<api::CommittedPublicationResult>,
    abandoned: bool,
}

/// Exclusive, transactional publication state for one stable client ID.
pub struct PublicationJournal {
    database: Database,
    path: PathBuf,
}

impl PublicationJournal {
    /// Creates a new journal. Existing paths are refused instead of reused.
    pub fn initialize(path: impl AsRef<Path>, client_id: &[u8]) -> Result<()> {
        validate_client_id(client_id)?;
        let path = path.as_ref();
        let file = std::fs::OpenOptions::new()
            .read(true)
            .write(true)
            .create_new(true)
            .open(path)
            .map_err(|error| journal_error(path, "create", error))?;
        let database = redb::Builder::new()
            .create_file(file)
            .map_err(|error| journal_error(path, "initialize", error))?;
        let state = JournalState {
            version: JOURNAL_VERSION,
            client_id: client_id.to_vec(),
            session: 0,
            allocated_through: 0,
            snapshot_revision: 0,
            recovery_complete: false,
            pending_claim: None,
            next_sequence: Some(1),
        };
        let mut write = database
            .begin_write()
            .map_err(|error| journal_error(path, "begin initialization", error))?;
        write
            .set_durability(Durability::Immediate)
            .map_err(|error| journal_error(path, "set durability", error))?;
        {
            let mut meta = write
                .open_table(JOURNAL_META)
                .map_err(|error| journal_error(path, "create metadata", error))?;
            let encoded = encode_json(&state)?;
            meta.insert(STATE_KEY, encoded.as_slice())
                .map_err(|error| journal_error(path, "write metadata", error))?;
            write
                .open_table(JOURNAL_ENTRIES)
                .map_err(|error| journal_error(path, "create entries", error))?;
        }
        write
            .commit()
            .map_err(|error| journal_error(path, "commit initialization", error))
    }

    /// Opens an existing journal and acquires redb's exclusive writer lock.
    pub fn open(path: impl AsRef<Path>, client_id: &[u8]) -> Result<Self> {
        validate_client_id(client_id)?;
        let path = path.as_ref().to_path_buf();
        if !path.is_file() {
            return Err(NumberedEventSdkError::Journal(format!(
                "{} is missing; explicit initialization is required",
                path.display()
            )));
        }
        let database = Database::open(&path)
            .map_err(|error| journal_error(&path, "open exclusively", error))?;
        let journal = Self { database, path };
        let state = journal.read_state()?;
        if state.version != JOURNAL_VERSION {
            return Err(NumberedEventSdkError::Journal(format!(
                "unsupported journal version {}",
                state.version
            )));
        }
        if state.client_id != client_id {
            return Err(NumberedEventSdkError::Journal(
                "configured client_id does not match the durable journal".to_owned(),
            ));
        }
        journal.audit_entries(&state)?;
        journal.update_state(|state| {
            state.recovery_complete = false;
            Ok(())
        })?;
        Ok(journal)
    }

    pub fn path(&self) -> &Path {
        &self.path
    }

    fn read_state(&self) -> Result<JournalState> {
        let read = self
            .database
            .begin_read()
            .map_err(|error| journal_error(&self.path, "read metadata", error))?;
        let table = read
            .open_table(JOURNAL_META)
            .map_err(|error| journal_error(&self.path, "open metadata", error))?;
        let value = table
            .get(STATE_KEY)
            .map_err(|error| journal_error(&self.path, "get metadata", error))?
            .ok_or_else(|| NumberedEventSdkError::Journal("metadata is missing".to_owned()))?;
        decode_json(value.value(), "metadata")
    }

    fn update_state(&self, update: impl FnOnce(&mut JournalState) -> Result<()>) -> Result<()> {
        self.write(|state, _entries| update(state))
    }

    fn write(
        &self,
        update: impl FnOnce(&mut JournalState, &mut redb::Table<'_, u64, &[u8]>) -> Result<()>,
    ) -> Result<()> {
        let mut write = self
            .database
            .begin_write()
            .map_err(|error| journal_error(&self.path, "begin transaction", error))?;
        write
            .set_durability(Durability::Immediate)
            .map_err(|error| journal_error(&self.path, "set durability", error))?;
        {
            let mut meta = write
                .open_table(JOURNAL_META)
                .map_err(|error| journal_error(&self.path, "open metadata", error))?;
            let value = meta
                .get(STATE_KEY)
                .map_err(|error| journal_error(&self.path, "get metadata", error))?
                .ok_or_else(|| NumberedEventSdkError::Journal("metadata is missing".to_owned()))?;
            let mut state: JournalState = decode_json(value.value(), "metadata")?;
            drop(value);
            let mut entries = write
                .open_table(JOURNAL_ENTRIES)
                .map_err(|error| journal_error(&self.path, "open entries", error))?;
            update(&mut state, &mut entries)?;
            let encoded = encode_json(&state)?;
            meta.insert(STATE_KEY, encoded.as_slice())
                .map_err(|error| journal_error(&self.path, "write metadata", error))?;
        }
        write
            .commit()
            .map_err(|error| journal_error(&self.path, "commit transaction", error))
    }

    fn audit_entries(&self, state: &JournalState) -> Result<()> {
        if state
            .next_sequence
            .is_some_and(|next| next == 0 || next <= state.allocated_through)
        {
            return Err(NumberedEventSdkError::Journal(
                "sequence frontier is invalid".to_owned(),
            ));
        }
        if let Some(claim) = &state.pending_claim
            && (claim.nonce.len() != CLAIM_NONCE_BYTES || claim.expected_session != state.session)
        {
            return Err(NumberedEventSdkError::Journal(
                "pending session claim is invalid".to_owned(),
            ));
        }
        let read = self
            .database
            .begin_read()
            .map_err(|error| journal_error(&self.path, "audit", error))?;
        let table = read
            .open_table(JOURNAL_ENTRIES)
            .map_err(|error| journal_error(&self.path, "open entries", error))?;
        let iter = table
            .iter()
            .map_err(|error| journal_error(&self.path, "iterate entries", error))?;
        for row in iter {
            let (key, value) =
                row.map_err(|error| journal_error(&self.path, "read entry", error))?;
            let sequence = key.value();
            let entry: JournalEntry = decode_json(value.value(), "entry")?;
            if sequence == 0
                || state.next_sequence.is_some_and(|next| sequence >= next)
                || entry.intent.operation_sequence != sequence
                || entry.intent.client_id != state.client_id
                || entry
                    .result
                    .as_ref()
                    .is_some_and(|result| result.operation_sequence != sequence)
                || (entry.abandoned && entry.result.is_some())
            {
                return Err(NumberedEventSdkError::Journal(format!(
                    "entry {sequence} is inconsistent"
                )));
            }
        }
        Ok(())
    }

    fn entry(&self, sequence: u64) -> Result<Option<JournalEntry>> {
        let read = self
            .database
            .begin_read()
            .map_err(|error| journal_error(&self.path, "read entry", error))?;
        let table = read
            .open_table(JOURNAL_ENTRIES)
            .map_err(|error| journal_error(&self.path, "open entries", error))?;
        table
            .get(sequence)
            .map_err(|error| journal_error(&self.path, "get entry", error))?
            .map(|value| decode_json(value.value(), "entry"))
            .transpose()
    }
}

/// A generated Connect client paired with its durable numbered-operation journal.
pub struct NumberedEventSdk<T> {
    client: api::AsterApplicationServiceClient<T>,
    journal: PublicationJournal,
}

impl<T> NumberedEventSdk<T>
where
    T: ClientTransport,
    <T::ResponseBody as connectrpc::http_body::Body>::Error: fmt::Display,
{
    /// Opens durable state without contacting the agent. Call [`Self::recover`]
    /// before allocating, publishing, abandoning, or acknowledging work.
    pub fn open(
        client: api::AsterApplicationServiceClient<T>,
        journal_path: impl AsRef<Path>,
        client_id: &[u8],
    ) -> Result<Self> {
        Ok(Self {
            client,
            journal: PublicationJournal::open(journal_path, client_id)?,
        })
    }

    pub fn journal_path(&self) -> &Path {
        self.journal.path()
    }

    pub fn session(&self) -> Result<u64> {
        Ok(self.journal.read_state()?.session)
    }

    /// Claims or idempotently resumes this process session and persists the
    /// complete recovery snapshot before returning.
    pub async fn begin_recovery(&self) -> Result<()> {
        let mut state = self.journal.read_state()?;
        let claim = if let Some(claim) = state.pending_claim.clone() {
            claim
        } else {
            let mut nonce = vec![0; CLAIM_NONCE_BYTES];
            getrandom::fill(&mut nonce).map_err(|error| {
                NumberedEventSdkError::Journal(format!("generate claim nonce: {error}"))
            })?;
            let claim = PendingClaim {
                expected_session: state.session,
                nonce,
            };
            self.journal.update_state(|state| {
                state.pending_claim = Some(claim.clone());
                state.recovery_complete = false;
                Ok(())
            })?;
            claim
        };
        let response = self
            .client
            .begin_event_publication_session(api::BeginEventPublicationSessionRequest {
                client_id: state.client_id.clone(),
                expected_session: claim.expected_session,
                claim_nonce: claim.nonce.clone(),
                ..Default::default()
            })
            .await?
            .into_owned();
        if response.session == 0 || response.allocated_through < state.allocated_through {
            return Err(NumberedEventSdkError::Protocol(
                "recovery snapshot regressed a durable frontier".to_owned(),
            ));
        }
        self.journal.write(|journal_state, entries| {
            if journal_state.pending_claim.as_ref().is_none_or(|pending| {
                pending.expected_session != claim.expected_session || pending.nonce != claim.nonce
            }) {
                return Err(NumberedEventSdkError::Journal(
                    "session claim changed while an RPC was in flight".to_owned(),
                ));
            }
            for result in &response.outstanding {
                let sequence = result.operation_sequence;
                let value = entries
                    .get(sequence)
                    .map_err(|error| {
                        journal_error(self.journal.path(), "get recovered entry", error)
                    })?
                    .ok_or_else(|| {
                        NumberedEventSdkError::Protocol(format!(
                            "agent returned unknown journal sequence {sequence}"
                        ))
                    })?;
                let mut entry: JournalEntry = decode_json(value.value(), "entry")?;
                drop(value);
                entry.result = Some(result.clone());
                entry.abandoned = false;
                let encoded = encode_json(&entry)?;
                entries
                    .insert(sequence, encoded.as_slice())
                    .map_err(|error| {
                        journal_error(self.journal.path(), "store recovered result", error)
                    })?;
            }
            let mut retired = Vec::new();
            let iter = entries
                .range(1..=response.allocated_through)
                .map_err(|error| {
                    journal_error(self.journal.path(), "scan recovered entries", error)
                })?;
            for row in iter {
                let (key, value) = row.map_err(|error| {
                    journal_error(self.journal.path(), "read recovered entry", error)
                })?;
                let entry: JournalEntry = decode_json(value.value(), "entry")?;
                if entry.result.is_none()
                    && !response
                        .outstanding
                        .iter()
                        .any(|result| result.operation_sequence == key.value())
                {
                    retired.push(key.value());
                }
            }
            for sequence in retired {
                let value = entries
                    .get(sequence)
                    .map_err(|error| {
                        journal_error(self.journal.path(), "get retired entry", error)
                    })?
                    .ok_or_else(|| {
                        NumberedEventSdkError::Journal("entry disappeared".to_owned())
                    })?;
                let mut entry: JournalEntry = decode_json(value.value(), "entry")?;
                drop(value);
                entry.abandoned = true;
                let encoded = encode_json(&entry)?;
                entries
                    .insert(sequence, encoded.as_slice())
                    .map_err(|error| {
                        journal_error(self.journal.path(), "mark retired entry", error)
                    })?;
            }
            journal_state.session = response.session;
            journal_state.allocated_through = response.allocated_through;
            journal_state.snapshot_revision = response.snapshot_revision;
            journal_state.pending_claim = None;
            journal_state.recovery_complete = false;
            journal_state.next_sequence = match (
                journal_state.next_sequence,
                response.allocated_through.checked_add(1),
            ) {
                (Some(local), Some(agent)) => Some(local.max(agent)),
                (None, _) | (_, None) => None,
            };
            Ok(())
        })?;
        state = self.journal.read_state()?;
        if state.session != response.session {
            return Err(NumberedEventSdkError::Journal(
                "recovered session was not persisted".to_owned(),
            ));
        }
        Ok(())
    }

    /// Completes the saved snapshot. Repeating this after a lost response is
    /// safe because the same session and snapshot revision remain journaled.
    pub async fn complete_recovery(&self) -> Result<()> {
        let state = self.journal.read_state()?;
        if state.session == 0 || state.pending_claim.is_some() {
            return Err(NumberedEventSdkError::Protocol(
                "begin_recovery has not durably completed".to_owned(),
            ));
        }
        self.client
            .complete_event_publication_recovery(api::CompleteEventPublicationRecoveryRequest {
                client_id: state.client_id.clone(),
                session: state.session,
                snapshot_revision: state.snapshot_revision,
                ..Default::default()
            })
            .await?;
        self.journal.update_state(|current| {
            if current.session != state.session
                || current.snapshot_revision != state.snapshot_revision
            {
                return Err(NumberedEventSdkError::Journal(
                    "recovery state changed while completion was in flight".to_owned(),
                ));
            }
            current.recovery_complete = true;
            Ok(())
        })
    }

    pub async fn recover(&self) -> Result<()> {
        self.begin_recovery().await?;
        self.complete_recovery().await
    }

    /// Durably assigns the next positive sequence before any request can be sent.
    pub fn journal_publication(&self, mut intent: api::PublishNumberedEventRequest) -> Result<u64> {
        let mut assigned = 0;
        self.journal.write(|state, entries| {
            require_recovered(state)?;
            assigned = state.next_sequence.ok_or_else(|| {
                NumberedEventSdkError::Protocol("operation sequence exhausted".to_owned())
            })?;
            intent.client_id.clone_from(&state.client_id);
            intent.session = state.session;
            intent.operation_sequence = assigned;
            let entry = JournalEntry {
                intent: intent.clone(),
                result: None,
                abandoned: false,
            };
            let encoded = encode_json(&entry)?;
            entries
                .insert(assigned, encoded.as_slice())
                .map_err(|error| {
                    journal_error(self.journal.path(), "journal publication", error)
                })?;
            state.next_sequence = assigned.checked_add(1);
            Ok(())
        })?;
        Ok(assigned)
    }

    /// Sends only a previously journaled intent and persists its result before
    /// exposing it to the caller.
    pub async fn publish_journaled(
        &self,
        sequence: u64,
    ) -> Result<api::CommittedPublicationResult> {
        let state = self.journal.read_state()?;
        require_recovered(&state)?;
        let mut entry = self.journal.entry(sequence)?.ok_or_else(|| {
            NumberedEventSdkError::Journal(format!("sequence {sequence} is not journaled"))
        })?;
        if entry.abandoned {
            return Err(NumberedEventSdkError::Protocol(format!(
                "sequence {sequence} is permanently retired"
            )));
        }
        if let Some(result) = entry.result {
            return Ok(result);
        }
        if sequence != state.allocated_through + 1 {
            return Err(NumberedEventSdkError::Protocol(format!(
                "sequence {sequence} is not the next first admission"
            )));
        }
        entry.intent.client_id.clone_from(&state.client_id);
        entry.intent.session = state.session;
        let response = self
            .client
            .publish_numbered_event(entry.intent.clone())
            .await?
            .into_owned();
        let result = response.result.as_option().cloned().ok_or_else(|| {
            NumberedEventSdkError::Protocol(
                "publication response omitted its committed result".to_owned(),
            )
        })?;
        if result.operation_sequence != sequence {
            return Err(NumberedEventSdkError::Protocol(
                "publication response returned a different sequence".to_owned(),
            ));
        }
        self.journal.write(|current, entries| {
            require_recovered(current)?;
            if current.session != state.session || current.allocated_through + 1 != sequence {
                return Err(NumberedEventSdkError::Journal(
                    "publication frontier changed while an RPC was in flight".to_owned(),
                ));
            }
            let value = entries
                .get(sequence)
                .map_err(|error| journal_error(self.journal.path(), "get publication", error))?
                .ok_or_else(|| {
                    NumberedEventSdkError::Journal("publication disappeared".to_owned())
                })?;
            let mut saved: JournalEntry = decode_json(value.value(), "entry")?;
            drop(value);
            saved.result = Some(result.clone());
            let encoded = encode_json(&saved)?;
            entries
                .insert(sequence, encoded.as_slice())
                .map_err(|error| {
                    journal_error(self.journal.path(), "store publication result", error)
                })?;
            current.allocated_through = sequence;
            Ok(())
        })?;
        Ok(result)
    }

    pub async fn publish(
        &self,
        intent: api::PublishNumberedEventRequest,
    ) -> Result<(u64, api::CommittedPublicationResult)> {
        let sequence = self.journal_publication(intent)?;
        let result = self.publish_journaled(sequence).await?;
        Ok((sequence, result))
    }

    /// Permanently consumes the next journaled but unadmitted sequence.
    pub async fn abandon(&self, sequence: u64) -> Result<()> {
        let state = self.journal.read_state()?;
        require_recovered(&state)?;
        let entry = self.journal.entry(sequence)?.ok_or_else(|| {
            NumberedEventSdkError::Journal(format!("sequence {sequence} is not journaled"))
        })?;
        if entry.abandoned {
            return Ok(());
        }
        if entry.result.is_some() || sequence != state.allocated_through + 1 {
            return Err(NumberedEventSdkError::Protocol(
                "only the next unadmitted sequence may be abandoned".to_owned(),
            ));
        }
        self.client
            .abandon_event_publication(api::AbandonEventPublicationRequest {
                client_id: state.client_id.clone(),
                session: state.session,
                operation_sequence: sequence,
                ..Default::default()
            })
            .await?;
        self.journal.write(|current, entries| {
            require_recovered(current)?;
            if current.session != state.session || current.allocated_through + 1 != sequence {
                return Err(NumberedEventSdkError::Journal(
                    "abandonment frontier changed while an RPC was in flight".to_owned(),
                ));
            }
            let value = entries
                .get(sequence)
                .map_err(|error| journal_error(self.journal.path(), "get abandonment", error))?
                .ok_or_else(|| {
                    NumberedEventSdkError::Journal("publication disappeared".to_owned())
                })?;
            let mut saved: JournalEntry = decode_json(value.value(), "entry")?;
            drop(value);
            saved.abandoned = true;
            let encoded = encode_json(&saved)?;
            entries
                .insert(sequence, encoded.as_slice())
                .map_err(|error| journal_error(self.journal.path(), "store abandonment", error))?;
            current.allocated_through = sequence;
            Ok(())
        })
    }

    /// Acknowledges a committed result, then removes its journal row.
    pub async fn acknowledge(&self, sequence: u64) -> Result<()> {
        let state = self.journal.read_state()?;
        require_recovered(&state)?;
        let entry = self.journal.entry(sequence)?.ok_or_else(|| {
            NumberedEventSdkError::Journal(format!("sequence {sequence} is not journaled"))
        })?;
        if entry.result.is_none() || entry.abandoned {
            return Err(NumberedEventSdkError::Protocol(
                "only a durably saved committed result may be acknowledged".to_owned(),
            ));
        }
        self.client
            .acknowledge_event_publication_result(api::AcknowledgeEventPublicationResultRequest {
                client_id: state.client_id.clone(),
                session: state.session,
                operation_sequence: sequence,
                ..Default::default()
            })
            .await?;
        self.journal.write(|current, entries| {
            require_recovered(current)?;
            if current.session != state.session {
                return Err(NumberedEventSdkError::Journal(
                    "session changed while acknowledgement was in flight".to_owned(),
                ));
            }
            entries.remove(sequence).map_err(|error| {
                journal_error(self.journal.path(), "remove acknowledged result", error)
            })?;
            Ok(())
        })
    }
}

fn require_recovered(state: &JournalState) -> Result<()> {
    if state.recovery_complete {
        Ok(())
    } else {
        Err(NumberedEventSdkError::Protocol(
            "publication recovery is not complete".to_owned(),
        ))
    }
}

fn validate_client_id(client_id: &[u8]) -> Result<()> {
    if client_id.is_empty() || client_id.len() > 64 {
        return Err(NumberedEventSdkError::Journal(
            "client_id must contain 1 to 64 bytes".to_owned(),
        ));
    }
    Ok(())
}

fn encode_json(value: &impl Serialize) -> Result<Vec<u8>> {
    serde_json::to_vec(value)
        .map_err(|error| NumberedEventSdkError::Journal(format!("encode state: {error}")))
}

fn decode_json<T: for<'de> Deserialize<'de>>(bytes: &[u8], name: &str) -> Result<T> {
    serde_json::from_slice(bytes).map_err(|error| {
        NumberedEventSdkError::Journal(format!("decode {name}; journal is corrupt: {error}"))
    })
}

fn journal_error(path: &Path, operation: &str, error: impl fmt::Display) -> NumberedEventSdkError {
    NumberedEventSdkError::Journal(format!("{operation} {}: {error}", path.display()))
}

// Keep the concrete response type visible in rustdoc for SDK callers using
// generated transports, and make accidental response-shape drift a compile error.
#[allow(dead_code)]
fn _response_shape<T>(response: UnaryResponse<T>) -> UnaryResponse<T> {
    response
}

#[cfg(test)]
mod tests {
    use super::*;

    fn journal_path(name: &str) -> PathBuf {
        std::env::temp_dir().join(format!(
            "aster-numbered-journal-{name}-{}-{:?}.redb",
            std::process::id(),
            std::thread::current().id()
        ))
    }

    #[test]
    fn missing_wrong_identity_and_second_writer_fail_closed() {
        let path = journal_path("exclusive");
        let _ = std::fs::remove_file(&path);
        assert!(PublicationJournal::open(&path, b"client-a").is_err());
        PublicationJournal::initialize(&path, b"client-a").expect("initialize");
        assert!(PublicationJournal::open(&path, b"client-b").is_err());
        let first = PublicationJournal::open(&path, b"client-a").expect("first writer");
        assert!(PublicationJournal::open(&path, b"client-a").is_err());
        drop(first);
        std::fs::remove_file(path).expect("remove journal");
    }

    #[test]
    fn malformed_journal_does_not_get_recreated() {
        let path = journal_path("corrupt");
        let _ = std::fs::remove_file(&path);
        std::fs::write(&path, b"not a redb database").expect("write corrupt journal");
        assert!(PublicationJournal::open(&path, b"client-a").is_err());
        assert_eq!(
            std::fs::read(&path).expect("read corrupt journal"),
            b"not a redb database"
        );
        std::fs::remove_file(path).expect("remove journal");
    }
}
