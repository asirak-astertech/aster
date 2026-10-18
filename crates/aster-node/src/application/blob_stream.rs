//! Bounded application-owned Blob publication streams.

use tokio::sync::{mpsc, oneshot};
use zeroize::Zeroizing;

use aster_mesh::{NodeId, Priority, Scope, Topic};

use super::blob::{
    BlobId, BlobPublishOptions, BlobPublishRequest, BlobPublishResult, SelectedBlobCommand,
};
use super::{ApplicationError, SelectedApplicationCommand, actor_unavailable};

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct BlobPublishStreamRequest {
    pub publication: BlobPublishRequest,
    pub options: BlobPublishOptions,
    pub total_len: u64,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct BlobPublishProgress {
    pub accepted_offset: u64,
    pub durable_offset: u64,
}

pub struct SelectedBlobPublishStream {
    commands: mpsc::Sender<SelectedApplicationCommand>,
    token: [u8; 32],
    accepted_offset: u64,
    durable_offset: u64,
}

#[derive(Debug, Eq, PartialEq)]
pub struct BlobReadFrame {
    pub offset: u64,
    pub bytes: Zeroizing<Vec<u8>>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct BlobReadStreamMetadata {
    pub id: BlobId,
    pub publisher: NodeId,
    pub publisher_counter: u64,
    pub topic: Topic,
    pub scope: Scope,
    pub priority: Priority,
    pub ttl_ms: Option<u64>,
    pub total_len: u64,
    pub media_type: Option<String>,
    pub schema_id: Vec<u8>,
    pub acceptance_marker: u64,
}

pub struct SelectedBlobReadStream {
    commands: mpsc::Sender<SelectedApplicationCommand>,
    token: [u8; 32],
    metadata: BlobReadStreamMetadata,
    closed: bool,
}

impl SelectedBlobReadStream {
    pub(crate) fn new(
        commands: mpsc::Sender<SelectedApplicationCommand>,
        token: [u8; 32],
        metadata: BlobReadStreamMetadata,
    ) -> Self {
        Self {
            commands,
            token,
            metadata,
            closed: false,
        }
    }

    pub const fn metadata(&self) -> &BlobReadStreamMetadata {
        &self.metadata
    }

    pub async fn next(
        &mut self,
        max_bytes: usize,
    ) -> Result<Option<BlobReadFrame>, ApplicationError> {
        let (response, received) = oneshot::channel();
        self.commands
            .send(SelectedApplicationCommand::Blob(
                SelectedBlobCommand::NextReadStream {
                    token: self.token,
                    max_bytes,
                    response,
                },
            ))
            .await
            .map_err(|_| actor_unavailable("blob stream read"))?;
        let frame = received
            .await
            .map_err(|_| actor_unavailable("blob stream read"))??;
        if frame.is_none() {
            self.closed = true;
        }
        Ok(frame)
    }
}

impl Drop for SelectedBlobReadStream {
    fn drop(&mut self) {
        if !self.closed {
            _ = self.commands.try_send(SelectedApplicationCommand::Blob(
                SelectedBlobCommand::CloseReadStream { token: self.token },
            ));
        }
    }
}

impl SelectedBlobPublishStream {
    pub(crate) fn new(
        commands: mpsc::Sender<SelectedApplicationCommand>,
        token: [u8; 32],
        progress: BlobPublishProgress,
    ) -> Self {
        Self {
            commands,
            token,
            accepted_offset: progress.accepted_offset,
            durable_offset: progress.durable_offset,
        }
    }

    pub const fn durable_offset(&self) -> u64 {
        self.durable_offset
    }

    pub async fn write(
        &mut self,
        offset: u64,
        bytes: Zeroizing<Vec<u8>>,
    ) -> Result<BlobPublishProgress, ApplicationError> {
        let (response, received) = oneshot::channel();
        self.commands
            .send(SelectedApplicationCommand::Blob(
                SelectedBlobCommand::AppendPublishStream {
                    token: self.token,
                    offset,
                    bytes,
                    response,
                },
            ))
            .await
            .map_err(|_| actor_unavailable("blob stream write"))?;
        let progress = received
            .await
            .map_err(|_| actor_unavailable("blob stream write"))??;
        self.accepted_offset = progress.accepted_offset;
        self.durable_offset = progress.durable_offset;
        Ok(progress)
    }

    pub async fn finish(self) -> Result<BlobPublishResult, ApplicationError> {
        let (response, received) = oneshot::channel();
        self.commands
            .send(SelectedApplicationCommand::Blob(
                SelectedBlobCommand::FinishPublishStream {
                    token: self.token,
                    response,
                },
            ))
            .await
            .map_err(|_| actor_unavailable("blob stream finish"))?;
        received
            .await
            .map_err(|_| actor_unavailable("blob stream finish"))?
    }
}

pub(crate) struct OpenedBlobPublishStream {
    pub token: [u8; 32],
    pub progress: BlobPublishProgress,
}

pub(crate) struct OpenedBlobReadStream {
    pub token: [u8; 32],
    pub metadata: BlobReadStreamMetadata,
}
