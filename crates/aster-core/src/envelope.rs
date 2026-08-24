//! Store-independent authenticated-envelope boundary shared by core compositions.

use crate::blob::BlobRouteCommitment;
use crate::model::{CausalStamp, DataClass, ItemId, NodeId, Priority, Scope, Topic};
use std::error::Error;
use std::fmt::{self, Display, Formatter};

/// Stable transfer identifier, distinct from the semantic item identifier.
pub type EnvelopeId = [u8; 32];

/// Persisted revocation after control-plane signature verification.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Revocation {
    pub subject: NodeId,
    pub authority: NodeId,
    pub signer: NodeId,
    pub generation: u64,
    pub control_sequence: u64,
    pub previous_control: Option<EnvelopeId>,
    pub sealed_notice: Vec<u8>,
    pub observed_at_ms: Option<u64>,
}

/// Persisted scope key epoch (key bytes are held by the crypto provider).
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ScopeEpoch {
    pub authority: NodeId,
    pub signer: NodeId,
    pub scope: Scope,
    pub epoch: u64,
    pub control_sequence: u64,
    pub previous_control: Option<EnvelopeId>,
    pub sealed_notice: Vec<u8>,
}

/// Stable mission control-chain namespace paired with the delegated identity
/// authorized to append the reserved link.
///
/// `authority` remains stable across signer rotation. Chain heads must never be
/// keyed by `signer`, because doing so would create an independent history for
/// every delegated credential.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ControlPrincipal {
    pub authority: NodeId,
    pub signer: NodeId,
}

/// Authenticated routing and causality metadata protected inside an envelope.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct EnvelopeHeader {
    pub class: DataClass,
    pub topic: Topic,
    pub scope: Scope,
    pub priority: Priority,
    pub stamp: CausalStamp,
    pub event_sequence: Option<u64>,
    pub logical_key: Vec<u8>,
    pub blob_route: Option<BlobRouteCommitment>,
    pub ttl_ms: Option<u64>,
    pub content_len: u64,
    pub tombstone: bool,
    pub key_epoch: u64,
}

/// Input to source sealing. Routing fields must be protected by the provider's
/// mesh-membership layer and payload bytes by the scope end-to-end layer.
pub struct SealRequest<'a> {
    pub header: &'a EnvelopeHeader,
    pub payload: &'a [u8],
}

/// Provider output ready for durable storage and opaque transport.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SealedEnvelope {
    pub id: ItemId,
    pub bytes: Vec<u8>,
}

/// An envelope whose source authentication, membership metadata, algorithms,
/// downgrade protection, and freshness syntax have been checked by the provider.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct VerifiedEnvelope {
    pub id: ItemId,
    pub header: EnvelopeHeader,
}

/// Authenticated mesh control object.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum VerifiedControl {
    Revocation(Revocation),
    ScopeEpoch(ScopeEpoch),
}

/// Authenticated result of inspecting either stable envelope kind.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum VerifiedObject {
    Data(VerifiedEnvelope),
    Control(VerifiedControl),
}

/// Cryptographic integration error without exposing primitives in the node API.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct EnvelopeError(pub String);

impl Display for EnvelopeError {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
        formatter.write_str(&self.0)
    }
}

impl Error for EnvelopeError {}

/// Narrow integration boundary implemented by the selected vetted crypto stack.
pub trait EnvelopeSealer {
    fn seal(&mut self, request: SealRequest<'_>) -> Result<SealedEnvelope, EnvelopeError>;
    fn inspect(&mut self, sealed: &[u8]) -> Result<VerifiedEnvelope, EnvelopeError>;
    fn open_payload(
        &mut self,
        envelope: &VerifiedEnvelope,
        sealed: &[u8],
    ) -> Result<Vec<u8>, EnvelopeError>;
    /// Reauthenticates one exact compact batch representation through its exact
    /// proof and opens its payload. Providers without semantic-v2 batch support
    /// fail closed through the default implementation.
    fn open_compact_batch_payload_with_proof(
        &mut self,
        _compact: &[u8],
        _proof: &[u8],
    ) -> Result<(VerifiedEnvelope, Vec<u8>), EnvelopeError> {
        Err(EnvelopeError(
            "compact batch authentication is unsupported by this provider".into(),
        ))
    }
    /// Opens content when this node is authorized. `None` is reserved for a valid,
    /// source-authenticated route whose topic content key is not granted locally.
    fn open_payload_if_authorized(
        &mut self,
        envelope: &VerifiedEnvelope,
        sealed: &[u8],
    ) -> Result<Option<Vec<u8>>, EnvelopeError> {
        self.open_payload(envelope, sealed).map(Some)
    }
    fn inspect_control(&mut self, sealed: &[u8]) -> Result<VerifiedControl, EnvelopeError>;
    /// Applies provider-owned key state only after the corresponding control is durably active.
    fn activate_control(
        &mut self,
        _sealed: &[u8],
        _local_revoked: bool,
    ) -> Result<(), EnvelopeError> {
        Ok(())
    }
    /// Inspects either a data or control envelope without exposing format tags to callers.
    fn inspect_object(&mut self, sealed: &[u8]) -> Result<VerifiedObject, EnvelopeError> {
        match self.inspect(sealed) {
            Ok(data) => Ok(VerifiedObject::Data(data)),
            Err(data_error) => self
                .inspect_control(sealed)
                .map(VerifiedObject::Control)
                .map_err(|_| data_error),
        }
    }
    /// Creates recipient- and exchange-bound protected custody metadata.
    fn seal_forwarding(
        &mut self,
        _recipient: NodeId,
        _exchange_id: u64,
        _envelope_id: EnvelopeId,
        _custody_age_ms: u64,
    ) -> Result<Vec<u8>, EnvelopeError> {
        Err(EnvelopeError(
            "forwarding metadata is unsupported by this provider".into(),
        ))
    }
    /// Authenticates protected custody metadata against the live adjacency.
    fn inspect_forwarding(
        &mut self,
        _authenticated_sender: NodeId,
        _recipient: NodeId,
        _exchange_id: u64,
        _envelope_id: EnvelopeId,
        _forwarding: &[u8],
    ) -> Result<u64, EnvelopeError> {
        Err(EnvelopeError(
            "forwarding metadata is unsupported by this provider".into(),
        ))
    }
    /// Tests an authority-signed opaque route-grant commitment from a peer credential.
    fn peer_can_route(
        &self,
        _peer: NodeId,
        _peer_route_commitments: &[[u8; 32]],
        _scope: &Scope,
        _epoch: u64,
    ) -> bool {
        false
    }
    /// Stable chain namespace and delegated signing identity for an
    /// authority-capable provider.
    fn control_principal(&self) -> Option<ControlPrincipal> {
        None
    }
    /// Identity of the stable mission control-chain namespace.
    ///
    /// This compatibility accessor must never be used when the delegated
    /// signer is also needed for authorization or reservation binding.
    fn control_authority(&self) -> Option<NodeId> {
        self.control_principal()
            .map(|principal| principal.authority)
    }
    fn seal_revocation_control(
        &mut self,
        _subject: NodeId,
        _generation: u64,
        _sequence: u64,
        _previous: Option<EnvelopeId>,
    ) -> Result<Vec<u8>, EnvelopeError> {
        Err(EnvelopeError(
            "control publication is unsupported by this provider".into(),
        ))
    }
    fn seal_scope_epoch_control(
        &mut self,
        _scope: &Scope,
        _epoch: u64,
        _sequence: u64,
        _previous: Option<EnvelopeId>,
    ) -> Result<Vec<u8>, EnvelopeError> {
        Err(EnvelopeError(
            "control publication is unsupported by this provider".into(),
        ))
    }
    /// Rapidly and irreversibly erases provider-owned local key material.
    fn zeroize(&mut self) -> Result<(), EnvelopeError>;
}
