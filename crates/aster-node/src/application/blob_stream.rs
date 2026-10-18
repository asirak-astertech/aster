//! Bounded application-owned Blob publication streams.

use tokio::sync::{mpsc, oneshot};
use zeroize::Zeroizing;

use super::blob::{BlobPublishOptions, BlobPublishRequest, BlobPublishResult, SelectedBlobCommand};
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
