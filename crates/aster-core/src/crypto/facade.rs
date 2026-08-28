//! Small exact-magic dispatch facade for provision-time profile selection.

use super::{
    ClassicalEnvelopeSealer, ClassicalProvisioningBundle, ProvisioningBundle,
    ReferenceEnvelopeSealer, SecurityProfile, VerifiedSecurityProfile,
};
use crate::{
    envelope::{
        ControlPrincipal, EnvelopeError, EnvelopeId, EnvelopeSealer, SealRequest, SealedEnvelope,
        VerifiedControl, VerifiedEnvelope,
    },
    model::{NodeId, Scope},
    provisioning::{
        ProtectedProvisioningError, ProvisioningProtector, ProvisioningUnprotector,
        UnprotectedProvisioning, protect_provisioning_artifact, unprotect_provisioning_artifact,
    },
};
use std::fmt;

const HYBRID_BUNDLE_MAGIC: &[u8; 8] = b"ASTRPB03";
const CLASSICAL_BUNDLE_MAGIC: &[u8; 8] = b"ASTRPB04";

/// Provisioning bytes dispatched only by their exact canonical magic.
pub enum ProfileProvisioningBundle {
    Hybrid(ProvisioningBundle),
    Classical(ClassicalProvisioningBundle),
}

impl fmt::Debug for ProfileProvisioningBundle {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Hybrid(bundle) => formatter.debug_tuple("Hybrid").field(bundle).finish(),
            Self::Classical(bundle) => formatter.debug_tuple("Classical").field(bundle).finish(),
        }
    }
}

impl ProfileProvisioningBundle {
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, EnvelopeError> {
        match bytes.get(..8) {
            Some(magic) if magic == HYBRID_BUNDLE_MAGIC => {
                ProvisioningBundle::from_bytes(bytes).map(Self::Hybrid)
            }
            Some(magic) if magic == CLASSICAL_BUNDLE_MAGIC => {
                ClassicalProvisioningBundle::from_bytes(bytes).map(Self::Classical)
            }
            _ => Err(EnvelopeError(
                "unknown security-profile provisioning representation".into(),
            )),
        }
    }

    pub fn to_bytes(&self) -> Result<Vec<u8>, EnvelopeError> {
        match self {
            Self::Hybrid(bundle) => bundle.to_bytes(),
            Self::Classical(bundle) => bundle.to_bytes(),
        }
    }

    /// Protects either exact inner representation with the deployment-owned
    /// provisioning protector. Profile dispatch never occurs on unauthenticated
    /// outer bytes.
    pub fn to_protected_bytes<P>(
        &self,
        protector: &mut P,
    ) -> Result<Vec<u8>, ProtectedProvisioningError>
    where
        P: ProvisioningProtector + ?Sized,
    {
        let plaintext = UnprotectedProvisioning::new(
            self.to_bytes()
                .map_err(|_| ProtectedProvisioningError::InvalidBundle)?,
        )?;
        protect_provisioning_artifact(&plaintext, protector).map_err(Into::into)
    }

    /// Authenticates the outer provisioning artifact before exact-magic
    /// dispatch. Provider rejection never falls back to plaintext parsing.
    pub fn from_protected_bytes<P>(
        protected: &[u8],
        unprotector: &mut P,
    ) -> Result<Self, ProtectedProvisioningError>
    where
        P: ProvisioningUnprotector + ?Sized,
    {
        let plaintext = unprotect_provisioning_artifact(protected, unprotector)?;
        Self::from_bytes(plaintext.expose()).map_err(|_| ProtectedProvisioningError::InvalidBundle)
    }

    pub const fn profile(&self) -> SecurityProfile {
        match self {
            Self::Hybrid(_) => SecurityProfile::HYBRID_PQ_ASTER_RECORD_V1,
            Self::Classical(_) => SecurityProfile::CLASSICAL_P256_IROH_QUIC_V1,
        }
    }

    pub fn zeroize(&mut self) {
        match self {
            Self::Hybrid(bundle) => bundle.zeroize(),
            Self::Classical(bundle) => bundle.zeroize(),
        }
    }
}

impl From<ProvisioningBundle> for ProfileProvisioningBundle {
    fn from(bundle: ProvisioningBundle) -> Self {
        Self::Hybrid(bundle)
    }
}

impl From<ClassicalProvisioningBundle> for ProfileProvisioningBundle {
    fn from(bundle: ClassicalProvisioningBundle) -> Self {
        Self::Classical(bundle)
    }
}

/// One-time provisioning dispatch over the two deliberately separate sealers.
pub enum ProfileEnvelopeSealer {
    Hybrid(Box<ReferenceEnvelopeSealer>),
    Classical(Box<ClassicalEnvelopeSealer>),
}

impl fmt::Debug for ProfileEnvelopeSealer {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Hybrid(sealer) => formatter.debug_tuple("Hybrid").field(sealer).finish(),
            Self::Classical(sealer) => formatter.debug_tuple("Classical").field(sealer).finish(),
        }
    }
}

impl ProfileEnvelopeSealer {
    pub fn open(bundle: ProfileProvisioningBundle) -> Result<Self, EnvelopeError> {
        match bundle {
            ProfileProvisioningBundle::Hybrid(bundle) => ReferenceEnvelopeSealer::open(bundle)
                .map(Box::new)
                .map(Self::Hybrid),
            ProfileProvisioningBundle::Classical(bundle) => ClassicalEnvelopeSealer::open(bundle)
                .map(Box::new)
                .map(Self::Classical),
        }
    }

    pub fn identity(&self) -> NodeId {
        match self {
            Self::Hybrid(sealer) => sealer.identity(),
            Self::Classical(sealer) => sealer.identity(),
        }
    }

    pub fn mission_authority_id(&self) -> NodeId {
        match self {
            Self::Hybrid(sealer) => sealer.mission_authority_id(),
            Self::Classical(sealer) => sealer.mission_authority_id(),
        }
    }

    pub const fn profile(&self) -> SecurityProfile {
        match self {
            Self::Hybrid(_) => SecurityProfile::HYBRID_PQ_ASTER_RECORD_V1,
            Self::Classical(_) => SecurityProfile::CLASSICAL_P256_IROH_QUIC_V1,
        }
    }

    pub const fn verified_security_profile(&self) -> Option<VerifiedSecurityProfile> {
        match self {
            Self::Hybrid(_) => None,
            Self::Classical(sealer) => Some(sealer.verified_security_profile()),
        }
    }

    pub fn can_route_event(&self, scope: &Scope, epoch: u64) -> bool {
        match self {
            Self::Hybrid(sealer) => sealer.can_route_event(scope, epoch),
            Self::Classical(sealer) => sealer.can_route_event(scope, epoch),
        }
    }
}

impl EnvelopeSealer for ProfileEnvelopeSealer {
    fn seal(&mut self, request: SealRequest<'_>) -> Result<SealedEnvelope, EnvelopeError> {
        match self {
            Self::Hybrid(sealer) => sealer.seal(request),
            Self::Classical(sealer) => sealer.seal(request),
        }
    }

    fn inspect(&mut self, sealed: &[u8]) -> Result<VerifiedEnvelope, EnvelopeError> {
        match self {
            Self::Hybrid(sealer) => sealer.inspect(sealed),
            Self::Classical(sealer) => sealer.inspect(sealed),
        }
    }

    fn open_payload(
        &mut self,
        envelope: &VerifiedEnvelope,
        sealed: &[u8],
    ) -> Result<Vec<u8>, EnvelopeError> {
        match self {
            Self::Hybrid(sealer) => sealer.open_payload(envelope, sealed),
            Self::Classical(sealer) => sealer.open_payload(envelope, sealed),
        }
    }

    fn open_compact_batch_payload_with_proof(
        &mut self,
        compact: &[u8],
        proof: &[u8],
    ) -> Result<(VerifiedEnvelope, Vec<u8>), EnvelopeError> {
        match self {
            Self::Hybrid(sealer) => sealer.open_compact_batch_payload_with_proof(compact, proof),
            Self::Classical(_) => Err(EnvelopeError(
                "compact batch is unsupported by the classical profile".into(),
            )),
        }
    }

    fn open_payload_if_authorized(
        &mut self,
        envelope: &VerifiedEnvelope,
        sealed: &[u8],
    ) -> Result<Option<Vec<u8>>, EnvelopeError> {
        match self {
            Self::Hybrid(sealer) => sealer.open_payload_if_authorized(envelope, sealed),
            Self::Classical(sealer) => sealer.open_payload_if_authorized(envelope, sealed),
        }
    }

    fn inspect_control(&mut self, sealed: &[u8]) -> Result<VerifiedControl, EnvelopeError> {
        match self {
            Self::Hybrid(sealer) => sealer.inspect_control(sealed),
            Self::Classical(sealer) => sealer.inspect_control(sealed),
        }
    }

    fn activate_control(
        &mut self,
        sealed: &[u8],
        local_revoked: bool,
    ) -> Result<(), EnvelopeError> {
        match self {
            Self::Hybrid(sealer) => sealer.activate_control(sealed, local_revoked),
            Self::Classical(sealer) => sealer.activate_control(sealed, local_revoked),
        }
    }

    fn seal_forwarding(
        &mut self,
        recipient: NodeId,
        exchange_id: u64,
        envelope_id: EnvelopeId,
        custody_age_ms: u64,
    ) -> Result<Vec<u8>, EnvelopeError> {
        match self {
            Self::Hybrid(sealer) => {
                sealer.seal_forwarding(recipient, exchange_id, envelope_id, custody_age_ms)
            }
            Self::Classical(_) => Err(EnvelopeError(
                "forwarding metadata is unsupported by the classical profile".into(),
            )),
        }
    }

    fn inspect_forwarding(
        &mut self,
        authenticated_sender: NodeId,
        recipient: NodeId,
        exchange_id: u64,
        envelope_id: EnvelopeId,
        forwarding: &[u8],
    ) -> Result<u64, EnvelopeError> {
        match self {
            Self::Hybrid(sealer) => sealer.inspect_forwarding(
                authenticated_sender,
                recipient,
                exchange_id,
                envelope_id,
                forwarding,
            ),
            Self::Classical(_) => Err(EnvelopeError(
                "forwarding metadata is unsupported by the classical profile".into(),
            )),
        }
    }

    fn peer_can_route(
        &self,
        peer: NodeId,
        peer_route_commitments: &[[u8; 32]],
        scope: &Scope,
        epoch: u64,
    ) -> bool {
        match self {
            Self::Hybrid(sealer) => {
                sealer.peer_can_route(peer, peer_route_commitments, scope, epoch)
            }
            Self::Classical(sealer) => {
                sealer.peer_can_route(peer, peer_route_commitments, scope, epoch)
            }
        }
    }

    fn control_principal(&self) -> Option<ControlPrincipal> {
        match self {
            Self::Hybrid(sealer) => sealer.control_principal(),
            Self::Classical(sealer) => sealer.control_principal(),
        }
    }

    fn seal_revocation_control(
        &mut self,
        subject: NodeId,
        generation: u64,
        sequence: u64,
        previous: Option<EnvelopeId>,
    ) -> Result<Vec<u8>, EnvelopeError> {
        match self {
            Self::Hybrid(sealer) => {
                sealer.seal_revocation_control(subject, generation, sequence, previous)
            }
            Self::Classical(sealer) => {
                sealer.seal_revocation_control(subject, generation, sequence, previous)
            }
        }
    }

    fn seal_scope_epoch_control(
        &mut self,
        scope: &Scope,
        epoch: u64,
        sequence: u64,
        previous: Option<EnvelopeId>,
    ) -> Result<Vec<u8>, EnvelopeError> {
        match self {
            Self::Hybrid(sealer) => {
                sealer.seal_scope_epoch_control(scope, epoch, sequence, previous)
            }
            Self::Classical(sealer) => {
                sealer.seal_scope_epoch_control(scope, epoch, sequence, previous)
            }
        }
    }

    fn zeroize(&mut self) -> Result<(), EnvelopeError> {
        match self {
            Self::Hybrid(sealer) => sealer.zeroize(),
            Self::Classical(sealer) => sealer.zeroize(),
        }
    }
}
