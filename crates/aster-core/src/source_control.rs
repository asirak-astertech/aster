//! Source-authenticated control-envelope seam for selected store/runtime compositions.
//!
//! This module introduces no control format or chain state. It carries claims
//! authenticated by the existing [`EnvelopeSealer::inspect_control`] boundary
//! across durable storage, and separates that inspection capability from the
//! provider-mutation capability used only after a store commits a contiguous
//! control-chain prefix.

use crate::{
    crypto::{ReferenceEnvelopeSealer, ScopeRekeyPlan, ScopeRekeyRecipient},
    envelope::{ControlPrincipal, EnvelopeError, EnvelopeId, EnvelopeSealer, VerifiedControl},
    model::{NodeId, Scope},
};
use sha2::{Digest, Sha256};

/// Existing authenticated control-envelope kinds.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(u8)]
pub enum VerifiedControlKind {
    /// Authority-signed identity revocation.
    Revocation = 1,
    /// Authority-signed activation of one scope key epoch.
    ScopeEpoch = 2,
}

/// Stable mission control-chain namespace and authenticated delegated signer.
///
/// The private constructor prevents application code from manufacturing an
/// authority/signer pair that appears to have come from the provider.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct VerifiedControlPrincipal {
    authority: NodeId,
    signer: NodeId,
}

impl VerifiedControlPrincipal {
    fn from_provider(principal: ControlPrincipal) -> Self {
        Self {
            authority: principal.authority,
            signer: principal.signer,
        }
    }

    /// Stable mission authority namespace used for chain storage.
    pub const fn authority(&self) -> NodeId {
        self.authority
    }

    /// Delegated authority credential authorized to sign a reserved link.
    pub const fn signer(&self) -> NodeId {
        self.signer
    }
}

/// Opaque registry-authenticated plan for one recipient-filtered scope rekey.
///
/// The provider has authenticated the exact public registry, enforced its
/// generation floor, resolved every requested NodeID to an authority-issued
/// credential, and canonicalized recipient order. No fresh scope key, topic
/// key, encapsulation, nonce, or sealed control exists until the separate
/// sealing call.
pub struct RegistryAuthenticatedScopeRekeyPlan {
    plan: ScopeRekeyPlan,
    mission_authority_id: NodeId,
    signed_registry_sha256: [u8; 32],
    registry_generation: u64,
}

impl std::fmt::Debug for RegistryAuthenticatedScopeRekeyPlan {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("RegistryAuthenticatedScopeRekeyPlan")
            .field("plan", &self.plan)
            .field("mission_authority_id", &self.mission_authority_id)
            .field("signed_registry_sha256", &"[REDACTED]")
            .field("registry_generation", &self.registry_generation)
            .field("key_material", &"[NONE]")
            .finish()
    }
}

/// Opaque proof that one exact registry-authenticated rekey plan produced one
/// exact sealed control envelope.
///
/// The private constructor binds the sealed-byte SHA-256 identity to the exact
/// authenticated registry identity and generation, scope, epoch, and canonical
/// full recipient policies retained by the plan. The capability contains no
/// key material and deliberately redacts every binding from `Debug` output.
pub struct ScopeRekeyPublicationCapability {
    sealed_envelope_id: EnvelopeId,
    mission_authority_id: NodeId,
    signed_registry_sha256: [u8; 32],
    registry_generation: u64,
    scope: Scope,
    epoch: u64,
    recipients: Vec<ScopeRekeyRecipient>,
}

impl std::fmt::Debug for ScopeRekeyPublicationCapability {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("ScopeRekeyPublicationCapability")
            .field("binding", &"[REDACTED]")
            .finish()
    }
}

impl ScopeRekeyPublicationCapability {
    fn from_plan_and_sealed(plan: &RegistryAuthenticatedScopeRekeyPlan, sealed: &[u8]) -> Self {
        Self {
            sealed_envelope_id: Sha256::digest(sealed).into(),
            mission_authority_id: plan.mission_authority_id,
            signed_registry_sha256: plan.signed_registry_sha256,
            registry_generation: plan.registry_generation,
            scope: plan.plan.scope().clone(),
            epoch: plan.plan.epoch(),
            recipients: plan.plan.recipients().cloned().collect(),
        }
    }

    /// SHA-256 transfer identity of the exact sealed output from this plan.
    pub const fn sealed_envelope_id(&self) -> EnvelopeId {
        self.sealed_envelope_id
    }

    /// Cryptographic mission-authority domain that authenticated the plan.
    pub const fn mission_authority_id(&self) -> NodeId {
        self.mission_authority_id
    }

    /// SHA-256 identity of the exact provider-authenticated signed registry.
    pub const fn signed_registry_sha256(&self) -> [u8; 32] {
        self.signed_registry_sha256
    }

    /// Provider-authenticated registry generation bound to the sealed output.
    pub const fn registry_generation(&self) -> u64 {
        self.registry_generation
    }

    /// Scope bound to the sealed output.
    pub const fn scope(&self) -> &Scope {
        &self.scope
    }

    /// Nonzero scope epoch bound to the sealed output.
    pub const fn epoch(&self) -> u64 {
        self.epoch
    }

    /// Canonical full recipient policies bound to the sealed output.
    pub fn recipient_policies(
        &self,
    ) -> impl ExactSizeIterator<Item = (NodeId, bool, &[crate::model::Topic])> + '_ {
        self.recipients.iter().map(|recipient| {
            (
                recipient.node(),
                recipient.has_route_access(),
                recipient.readable_topics(),
            )
        })
    }
}

impl RegistryAuthenticatedScopeRekeyPlan {
    /// Provider-authenticated generation of the exact registry used to plan.
    pub const fn registry_generation(&self) -> u64 {
        self.registry_generation
    }

    /// Scope authenticated and canonicalized into this plan.
    pub fn scope(&self) -> &Scope {
        self.plan.scope()
    }

    /// Nonzero scope epoch authenticated and canonicalized into this plan.
    pub fn epoch(&self) -> u64 {
        self.plan.epoch()
    }

    /// Canonically ordered recipient identities, without credentials or key material.
    pub fn recipient_nodes(&self) -> impl ExactSizeIterator<Item = NodeId> + '_ {
        self.plan.recipients().map(ScopeRekeyRecipient::node)
    }
}

/// Source-authenticated metadata for one exact sealed control envelope.
///
/// Fields and constructors are private so callers cannot manufacture claims
/// from wire metadata. This capability is sufficient for durable chain
/// validation and forwarding. It does not permit provider key-state mutation;
/// that requires an [`ActivationReadyControlEnvelope`] minted only at the
/// explicit post-commit boundary.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct VerifiedControlEnvelope {
    control: VerifiedControl,
    envelope_id: EnvelopeId,
    mission_authority_id: NodeId,
    scope_rekey_recipient_nodes: Option<Vec<NodeId>>,
}

impl VerifiedControlEnvelope {
    fn from_verified(
        control: VerifiedControl,
        sealed: &[u8],
        mission_authority_id: NodeId,
        scope_rekey_recipient_nodes: Option<Vec<NodeId>>,
    ) -> Result<Self, EnvelopeError> {
        if sealed.is_empty() {
            return Err(EnvelopeError("control envelope is empty".into()));
        }
        let (authority, sequence, previous, authenticated_sealed) = match &control {
            VerifiedControl::Revocation(revocation) => (
                revocation.authority,
                revocation.control_sequence,
                revocation.previous_control,
                revocation.sealed_notice.as_slice(),
            ),
            VerifiedControl::ScopeEpoch(epoch) => (
                epoch.authority,
                epoch.control_sequence,
                epoch.previous_control,
                epoch.sealed_notice.as_slice(),
            ),
        };
        if authority != mission_authority_id {
            return Err(EnvelopeError(
                "control belongs to another mission authority".into(),
            ));
        }
        if authenticated_sealed != sealed {
            return Err(EnvelopeError(
                "authenticated control does not retain the exact sealed bytes".into(),
            ));
        }
        // Preserve the existing canonical chain syntax at this boundary. The
        // durable store remains authoritative for fork, rollback, revocation,
        // duplicate, and out-of-order decisions across multiple controls.
        if sequence == 0 || (sequence == 1) != previous.is_none() {
            return Err(EnvelopeError(
                "authenticated control has invalid chain linkage".into(),
            ));
        }
        match (&control, scope_rekey_recipient_nodes.as_deref()) {
            (VerifiedControl::Revocation(_), Some(_)) => {
                return Err(EnvelopeError(
                    "revocation control cannot carry scope rekey recipients".into(),
                ));
            }
            (VerifiedControl::ScopeEpoch(_), Some(recipients))
                if recipients.is_empty()
                    || recipients.windows(2).any(|pair| pair[0] >= pair[1]) =>
            {
                return Err(EnvelopeError(
                    "authenticated scope rekey recipients are not canonical".into(),
                ));
            }
            _ => {}
        }
        Ok(Self {
            control,
            envelope_id: Sha256::digest(sealed).into(),
            mission_authority_id,
            scope_rekey_recipient_nodes,
        })
    }

    /// SHA-256 transfer identity of the exact stable sealed bytes.
    pub const fn envelope_id(&self) -> EnvelopeId {
        self.envelope_id
    }

    /// Stable mission authority that authenticated this control and its signer.
    pub const fn mission_authority_id(&self) -> NodeId {
        self.mission_authority_id
    }

    /// Alias for [`Self::mission_authority_id`].
    pub const fn authority_id(&self) -> NodeId {
        self.mission_authority_id()
    }

    /// Delegated authority credential that signed this chain link.
    pub const fn signer(&self) -> NodeId {
        match &self.control {
            VerifiedControl::Revocation(revocation) => revocation.signer,
            VerifiedControl::ScopeEpoch(epoch) => epoch.signer,
        }
    }

    /// Nonzero position in the stable mission-authority control chain.
    pub const fn control_sequence(&self) -> u64 {
        match &self.control {
            VerifiedControl::Revocation(revocation) => revocation.control_sequence,
            VerifiedControl::ScopeEpoch(epoch) => epoch.control_sequence,
        }
    }

    /// Exact predecessor transfer identity, absent only for sequence one.
    pub const fn previous_control(&self) -> Option<EnvelopeId> {
        match &self.control {
            VerifiedControl::Revocation(revocation) => revocation.previous_control,
            VerifiedControl::ScopeEpoch(epoch) => epoch.previous_control,
        }
    }

    /// Authenticated control kind.
    pub const fn kind(&self) -> VerifiedControlKind {
        match &self.control {
            VerifiedControl::Revocation(_) => VerifiedControlKind::Revocation,
            VerifiedControl::ScopeEpoch(_) => VerifiedControlKind::ScopeEpoch,
        }
    }

    /// Revoked identity for a revocation control.
    pub const fn revocation_subject(&self) -> Option<NodeId> {
        match &self.control {
            VerifiedControl::Revocation(revocation) => Some(revocation.subject),
            VerifiedControl::ScopeEpoch(_) => None,
        }
    }

    /// Nonzero monotonic subject generation for a revocation control.
    pub const fn revocation_generation(&self) -> Option<u64> {
        match &self.control {
            VerifiedControl::Revocation(revocation) => Some(revocation.generation),
            VerifiedControl::ScopeEpoch(_) => None,
        }
    }

    /// Scope affected by a scope-epoch control.
    pub const fn scope(&self) -> Option<&Scope> {
        match &self.control {
            VerifiedControl::Revocation(_) => None,
            VerifiedControl::ScopeEpoch(epoch) => Some(&epoch.scope),
        }
    }

    /// Epoch activated by a scope-epoch control.
    pub const fn scope_epoch(&self) -> Option<u64> {
        match &self.control {
            VerifiedControl::Revocation(_) => None,
            VerifiedControl::ScopeEpoch(epoch) => Some(epoch.epoch),
        }
    }

    /// Canonically ordered authenticated recipients for an exact scope-rekey
    /// package/capsule control.
    ///
    /// This is `None` for revocations and legacy pre-provisioned scope-epoch
    /// controls. Only recipient NodeIDs cross this boundary; public
    /// credentials, package metadata, grants, and key material remain private.
    pub fn scope_rekey_recipient_nodes(&self) -> Option<&[NodeId]> {
        self.scope_rekey_recipient_nodes.as_deref()
    }

    /// Checks that bytes accompanying this capability are the exact bytes that
    /// were authenticated when it was created.
    pub fn verify_exact_sealed(&self, sealed: &[u8]) -> Result<(), EnvelopeError> {
        if sealed.is_empty() || <EnvelopeId>::from(Sha256::digest(sealed)) != self.envelope_id {
            return Err(EnvelopeError(
                "verified control capability does not match sealed bytes".into(),
            ));
        }
        let retained = match &self.control {
            VerifiedControl::Revocation(revocation) => revocation.sealed_notice.as_slice(),
            VerifiedControl::ScopeEpoch(epoch) => epoch.sealed_notice.as_slice(),
        };
        if retained != sealed {
            return Err(EnvelopeError(
                "verified control capability does not retain sealed bytes".into(),
            ));
        }
        Ok(())
    }
}

/// Exact control material freshly reauthenticated for provider mutation.
///
/// This type is deliberately non-`Clone` and has a private constructor. It is
/// minted by [`ReferenceEnvelopeSealer::prepare_committed_control_activation`]
/// only after fresh authentication of the exact persisted bytes and is consumed
/// by [`ReferenceEnvelopeSealer::activate_committed_control`]. It is not proof
/// of storage or commit ordering by itself: the caller must invoke the
/// preparation method only for the ordered `Applied` suffix returned by its
/// successful durable transaction, or for an audited ordered replay of
/// already-applied controls at restart.
#[derive(Debug, Eq, PartialEq)]
pub struct ActivationReadyControlEnvelope {
    verified: VerifiedControlEnvelope,
    sealed: Vec<u8>,
}

impl ActivationReadyControlEnvelope {
    fn new(verified: VerifiedControlEnvelope, sealed: &[u8]) -> Self {
        Self {
            verified,
            sealed: sealed.to_vec(),
        }
    }

    /// Exact transfer identity authorized for post-commit activation.
    pub const fn envelope_id(&self) -> EnvelopeId {
        self.verified.envelope_id()
    }

    /// Stable mission authority of the committed control.
    pub const fn mission_authority_id(&self) -> NodeId {
        self.verified.mission_authority_id()
    }

    /// Authenticated kind of the committed control.
    pub const fn kind(&self) -> VerifiedControlKind {
        self.verified.kind()
    }
}

impl ReferenceEnvelopeSealer {
    /// Stable control-chain namespace and delegated signing identity, when this
    /// provisioned node is authorized to publish controls.
    pub fn verified_control_principal(&self) -> Option<VerifiedControlPrincipal> {
        <Self as EnvelopeSealer>::control_principal(self)
            .map(VerifiedControlPrincipal::from_provider)
    }

    /// Authenticates the source, stable authority, exact bytes, chain claims,
    /// and effect metadata of one existing-format control envelope.
    ///
    /// All mission nodes with the existing control-route grant may inspect and
    /// durably relay these mission-control claims. This does not open any
    /// application content and does not mutate provider key state.
    pub fn verify_control(
        &mut self,
        sealed: &[u8],
    ) -> Result<VerifiedControlEnvelope, EnvelopeError> {
        let (verified, scope_rekey_recipient_nodes) =
            self.inspect_control_with_scope_rekey_recipient_nodes(sealed)?;
        VerifiedControlEnvelope::from_verified(
            verified,
            sealed,
            self.mission_authority_id(),
            scope_rekey_recipient_nodes,
        )
    }

    /// Creates an existing-format revocation at an already-reserved chain link.
    pub fn seal_chained_revocation_control(
        &mut self,
        subject: NodeId,
        generation: u64,
        sequence: u64,
        previous: Option<EnvelopeId>,
    ) -> Result<Vec<u8>, EnvelopeError> {
        <Self as EnvelopeSealer>::seal_revocation_control(
            self, subject, generation, sequence, previous,
        )
    }

    /// Authenticates one exact signed public registry and resolves a canonical
    /// rekey plan without generating fresh key material or consuming RNG.
    #[allow(clippy::too_many_arguments)]
    pub fn plan_scope_rekey_control_from_registry(
        &self,
        signed_public_registry: &[u8],
        minimum_registry_generation: u64,
        scope: Scope,
        epoch: u64,
        recipients: Vec<ScopeRekeyRecipient>,
    ) -> Result<RegistryAuthenticatedScopeRekeyPlan, EnvelopeError> {
        let (plan, registry_generation) = self.plan_scope_rekey_from_registry(
            signed_public_registry,
            minimum_registry_generation,
            scope,
            epoch,
            recipients,
        )?;
        Ok(RegistryAuthenticatedScopeRekeyPlan {
            plan,
            mission_authority_id: self.mission_authority_id(),
            signed_registry_sha256: Sha256::digest(signed_public_registry).into(),
            registry_generation,
        })
    }

    /// Randomizes and seals one previously registry-authenticated rekey plan at
    /// an already-reserved control-chain link.
    pub fn seal_chained_scope_rekey_control(
        &mut self,
        plan: &RegistryAuthenticatedScopeRekeyPlan,
        sequence: u64,
        previous: Option<EnvelopeId>,
    ) -> Result<Vec<u8>, EnvelopeError> {
        if plan.mission_authority_id != self.mission_authority_id() {
            return Err(EnvelopeError(
                "scope rekey plan belongs to another mission authority".into(),
            ));
        }
        self.seal_scope_rekey_chained(&plan.plan, sequence, previous)
    }

    /// Randomizes and seals one authenticated rekey plan while minting the
    /// capability required to commit that exact output as a local publication.
    pub fn seal_chained_scope_rekey_control_for_publication(
        &mut self,
        plan: &RegistryAuthenticatedScopeRekeyPlan,
        sequence: u64,
        previous: Option<EnvelopeId>,
    ) -> Result<(Vec<u8>, ScopeRekeyPublicationCapability), EnvelopeError> {
        let sealed = self.seal_chained_scope_rekey_control(plan, sequence, previous)?;
        let capability = ScopeRekeyPublicationCapability::from_plan_and_sealed(plan, &sealed);
        Ok((sealed, capability))
    }

    /// Verifies the existing authority-signed recipient registry, creates the
    /// existing recipient-filtered rekey control, and returns the authenticated
    /// registry generation used. Key material remains provider-owned.
    #[allow(clippy::too_many_arguments)]
    pub fn seal_chained_scope_rekey_control_from_registry(
        &mut self,
        signed_public_registry: &[u8],
        minimum_registry_generation: u64,
        scope: Scope,
        epoch: u64,
        recipients: Vec<ScopeRekeyRecipient>,
        sequence: u64,
        previous: Option<EnvelopeId>,
    ) -> Result<(Vec<u8>, u64), EnvelopeError> {
        let plan = self.plan_scope_rekey_control_from_registry(
            signed_public_registry,
            minimum_registry_generation,
            scope,
            epoch,
            recipients,
        )?;
        let sealed = self.seal_chained_scope_rekey_control(&plan, sequence, previous)?;
        Ok((sealed, plan.registry_generation()))
    }

    /// Freshly reauthenticates exact bytes at the post-commit boundary and
    /// mints a one-use provider mutation token.
    ///
    /// Call this only for controls in the ordered contiguous suffix returned by
    /// the successful commit, or during ordered restart replay after comparing
    /// every persisted claim with [`Self::verify_control`]. Pending, duplicate,
    /// rejected, or merely received controls must never cross this boundary.
    pub fn prepare_committed_control_activation(
        &mut self,
        committed: &VerifiedControlEnvelope,
        exact_persisted_sealed: &[u8],
    ) -> Result<ActivationReadyControlEnvelope, EnvelopeError> {
        committed.verify_exact_sealed(exact_persisted_sealed)?;
        if committed.mission_authority_id() != self.mission_authority_id() {
            return Err(EnvelopeError(
                "committed control belongs to another mission authority".into(),
            ));
        }
        let freshly_verified = self.verify_control(exact_persisted_sealed)?;
        if freshly_verified != *committed {
            return Err(EnvelopeError(
                "persisted control claims differ from fresh authentication".into(),
            ));
        }
        Ok(ActivationReadyControlEnvelope::new(
            freshly_verified,
            exact_persisted_sealed,
        ))
    }

    /// Applies provider-owned recipient-filtered key state for one durably
    /// committed control. The one-use token enforces fresh inspection/activation
    /// separation; the selected store/runtime remains responsible for commit
    /// ordering and must derive `local_revoked` from committed revocation state,
    /// never configuration or uncommitted input.
    ///
    /// Preparing and activating the same exact applied control again is
    /// intentionally supported so an audited restart can replay provider-owned
    /// recipient state deterministically.
    pub fn activate_committed_control(
        &mut self,
        ready: ActivationReadyControlEnvelope,
        local_revoked: bool,
    ) -> Result<(), EnvelopeError> {
        if ready.mission_authority_id() != self.mission_authority_id() {
            return Err(EnvelopeError(
                "activation-ready control belongs to another mission authority".into(),
            ));
        }
        ready.verified.verify_exact_sealed(&ready.sealed)?;
        <Self as EnvelopeSealer>::activate_control(self, &ready.sealed, local_revoked)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        EventContentVerification,
        crypto::{ProvisioningAccess, ReferenceProvisioner},
        engine::EnvelopeHeader,
        model::{CausalStamp, DataClass, Dot, Priority, Topic, VersionVector},
    };

    fn scope() -> Scope {
        Scope::new("test/source-control").expect("scope")
    }

    fn topic() -> Topic {
        Topic::new("control-test").expect("topic")
    }

    fn member_access() -> ProvisioningAccess {
        ProvisioningAccess::member(scope(), vec![1], vec![topic()]).expect("access")
    }

    fn relay_access() -> ProvisioningAccess {
        ProvisioningAccess::relay(scope(), vec![1]).expect("relay access")
    }

    struct Services {
        authority: ReferenceEnvelopeSealer,
        member: ReferenceEnvelopeSealer,
        relay: ReferenceEnvelopeSealer,
        excluded: ReferenceEnvelopeSealer,
        registry: Vec<u8>,
    }

    fn services(seed: [u8; 32]) -> Services {
        let mut provisioner = ReferenceProvisioner::from_seed(seed).expect("provisioner");
        let authority_bundle = provisioner
            .issue_control_authority(1, &[member_access()])
            .expect("authority bundle");
        let member_bundle = provisioner
            .issue_node(2, &[member_access()])
            .expect("member bundle");
        let relay_bundle = provisioner
            .issue_node(3, &[relay_access()])
            .expect("relay bundle");
        let excluded_bundle = provisioner
            .issue_node(4, &[member_access()])
            .expect("excluded bundle");
        let registry = provisioner
            .export_rekey_registry()
            .expect("public registry");
        let authority = ReferenceEnvelopeSealer::open(authority_bundle).expect("authority");
        let member = ReferenceEnvelopeSealer::open(member_bundle).expect("member");
        let relay = ReferenceEnvelopeSealer::open(relay_bundle).expect("relay");
        let excluded = ReferenceEnvelopeSealer::open(excluded_bundle).expect("excluded");
        Services {
            authority,
            member,
            relay,
            excluded,
            registry,
        }
    }

    #[test]
    fn verified_control_binds_exact_bytes_authority_chain_and_effect() {
        let Services {
            mut authority,
            mut member,
            ..
        } = services([0x31; 32]);
        let subject = member.identity();
        let principal = authority
            .verified_control_principal()
            .expect("control principal");
        assert_eq!(principal.authority(), authority.mission_authority_id());
        assert_eq!(principal.signer(), authority.identity());
        assert_eq!(member.verified_control_principal(), None);
        let sealed = authority
            .seal_chained_revocation_control(subject, 7, 1, None)
            .expect("seal revocation");
        let verified = member.verify_control(&sealed).expect("verify control");

        assert_eq!(verified.kind(), VerifiedControlKind::Revocation);
        assert_eq!(verified.authority_id(), authority.mission_authority_id());
        assert_eq!(verified.signer(), authority.identity());
        assert_eq!(verified.control_sequence(), 1);
        assert_eq!(verified.previous_control(), None);
        assert_eq!(verified.revocation_subject(), Some(subject));
        assert_eq!(verified.revocation_generation(), Some(7));
        assert_eq!(verified.scope(), None);
        assert_eq!(verified.scope_epoch(), None);
        assert_eq!(verified.scope_rekey_recipient_nodes(), None);
        assert_eq!(
            verified.envelope_id(),
            <[u8; 32]>::from(Sha256::digest(&sealed))
        );
        verified.verify_exact_sealed(&sealed).expect("exact bytes");
        assert!(verified.verify_exact_sealed(&[]).is_err());

        let mut tampered = sealed;
        tampered[0] ^= 1;
        assert!(verified.verify_exact_sealed(&tampered).is_err());
        assert!(member.verify_control(&tampered).is_err());
    }

    #[test]
    fn registry_plan_and_verified_rekey_expose_canonical_recipient_nodes_only() {
        let Services {
            mut authority,
            mut member,
            relay,
            excluded,
            registry,
        } = services([0x3a; 32]);
        let member_id = member.identity();
        let relay_id = relay.identity();
        let content_only_id = excluded.identity();
        let plan = authority
            .plan_scope_rekey_control_from_registry(
                &registry,
                4,
                scope(),
                2,
                vec![
                    ScopeRekeyRecipient::content_only(content_only_id, vec![topic()])
                        .expect("content-only recipient"),
                    ScopeRekeyRecipient::route_only(relay_id),
                    ScopeRekeyRecipient::member(member_id, vec![topic()])
                        .expect("member recipient"),
                ],
            )
            .expect("registry-authenticated plan");

        let mut expected = vec![member_id, relay_id, content_only_id];
        expected.sort_unstable();
        assert_eq!(plan.registry_generation(), 4);
        assert_eq!(plan.scope(), &scope());
        assert_eq!(plan.epoch(), 2);
        assert_eq!(plan.recipient_nodes().collect::<Vec<_>>(), expected);

        let (sealed, publication) = authority
            .seal_chained_scope_rekey_control_for_publication(&plan, 1, None)
            .expect("seal planned control");
        let verified = member.verify_control(&sealed).expect("verify rekey");
        assert_eq!(verified.kind(), VerifiedControlKind::ScopeEpoch);
        assert_eq!(publication.sealed_envelope_id(), verified.envelope_id());
        assert_eq!(
            publication.mission_authority_id(),
            verified.mission_authority_id()
        );
        assert_eq!(
            publication.signed_registry_sha256(),
            <[u8; 32]>::from(Sha256::digest(&registry))
        );
        assert_eq!(publication.registry_generation(), 4);
        assert_eq!(publication.scope(), &scope());
        assert_eq!(publication.epoch(), 2);
        assert_eq!(
            publication
                .recipient_policies()
                .map(|(node, _, _)| node)
                .collect::<Vec<_>>(),
            expected
        );
        assert_eq!(
            format!("{publication:?}"),
            "ScopeRekeyPublicationCapability { binding: \"[REDACTED]\" }"
        );
        assert_eq!(
            verified.scope_rekey_recipient_nodes(),
            Some(expected.as_slice())
        );

        let mut tampered = sealed;
        let tampered_index = tampered.len() / 2;
        tampered[tampered_index] ^= 1;
        assert!(member.verify_control(&tampered).is_err());
    }

    #[test]
    fn registry_plan_rejects_a_sealer_from_another_mission_before_publication() {
        let Services {
            authority: planner,
            member,
            registry,
            ..
        } = services([0x3b; 32]);
        let plan = planner
            .plan_scope_rekey_control_from_registry(
                &registry,
                0,
                scope(),
                2,
                vec![
                    ScopeRekeyRecipient::member(member.identity(), vec![topic()])
                        .expect("member recipient"),
                ],
            )
            .expect("registry-authenticated plan");
        let Services {
            authority: mut foreign_authority,
            ..
        } = services([0x3c; 32]);

        assert!(
            foreign_authority
                .seal_chained_scope_rekey_control_for_publication(&plan, 1, None)
                .is_err()
        );
    }

    #[test]
    fn verification_rejects_wrong_mission_and_exposes_links_for_store_policy() {
        let Services {
            mut authority,
            mut member,
            registry,
            ..
        } = services([0x32; 32]);
        let first = authority
            .seal_chained_revocation_control(member.identity(), 1, 1, None)
            .expect("first");
        let first_id = <[u8; 32]>::from(Sha256::digest(&first));
        let authority_id = authority.identity();
        let member_id = member.identity();
        let (second, registry_generation) = authority
            .seal_chained_scope_rekey_control_from_registry(
                &registry,
                0,
                scope(),
                2,
                vec![
                    ScopeRekeyRecipient::member(authority_id, vec![topic()])
                        .expect("authority recipient"),
                    ScopeRekeyRecipient::member(member_id, vec![topic()])
                        .expect("member recipient"),
                ],
                2,
                Some(first_id),
            )
            .expect("second");
        assert!(registry_generation >= 2);
        let verified_second = member.verify_control(&second).expect("verify second");
        assert_eq!(verified_second.kind(), VerifiedControlKind::ScopeEpoch);
        assert_eq!(verified_second.control_sequence(), 2);
        assert_eq!(verified_second.previous_control(), Some(first_id));
        assert_eq!(verified_second.scope(), Some(&scope()));
        assert_eq!(verified_second.scope_epoch(), Some(2));
        assert_eq!(verified_second.revocation_subject(), None);
        assert_eq!(verified_second.revocation_generation(), None);

        let Services {
            member: mut wrong_mission,
            ..
        } = services([0x33; 32]);
        assert!(wrong_mission.verify_control(&first).is_err());
        assert!(wrong_mission.verify_control(&second).is_err());
    }

    #[test]
    fn activation_requires_fresh_exact_post_commit_preparation_and_replays() {
        let Services {
            mut authority,
            mut member,
            mut relay,
            mut excluded,
            registry,
        } = services([0x34; 32]);
        let recipients = vec![
            ScopeRekeyRecipient::member(authority.identity(), vec![topic()])
                .expect("authority recipient"),
            ScopeRekeyRecipient::member(member.identity(), vec![topic()])
                .expect("member recipient"),
            ScopeRekeyRecipient::route_only(relay.identity()),
        ];
        let (sealed, _) = authority
            .seal_chained_scope_rekey_control_from_registry(
                &registry,
                0,
                scope(),
                2,
                recipients,
                1,
                None,
            )
            .expect("scope rekey control");
        let committed = member
            .verify_control(&sealed)
            .expect("inspect before commit");

        // In production the durable store transaction and its applied-prefix
        // outcome occur between these two calls.
        let authority_committed = authority
            .verify_control(&sealed)
            .expect("authority inspect");
        let authority_ready = authority
            .prepare_committed_control_activation(&authority_committed, &sealed)
            .expect("authority prepare after commit");
        authority
            .activate_committed_control(authority_ready, false)
            .expect("authority activate");
        let ready = member
            .prepare_committed_control_activation(&committed, &sealed)
            .expect("prepare after commit");
        assert_eq!(ready.envelope_id(), committed.envelope_id());
        assert_eq!(ready.kind(), VerifiedControlKind::ScopeEpoch);
        member
            .activate_committed_control(ready, false)
            .expect("activate committed control");
        let relay_committed = relay.verify_control(&sealed).expect("relay inspect");
        let relay_ready = relay
            .prepare_committed_control_activation(&relay_committed, &sealed)
            .expect("relay prepare after commit");
        relay
            .activate_committed_control(relay_ready, false)
            .expect("relay activate");
        let excluded_committed = excluded.verify_control(&sealed).expect("excluded inspect");
        let excluded_ready = excluded
            .prepare_committed_control_activation(&excluded_committed, &sealed)
            .expect("excluded prepare after commit");
        excluded
            .activate_committed_control(excluded_ready, false)
            .expect("excluded activate");

        let payload = b"fresh epoch content";
        let header = EnvelopeHeader {
            class: DataClass::Event,
            topic: topic(),
            scope: scope(),
            priority: Priority::Immediate,
            stamp: CausalStamp {
                dot: Dot {
                    publisher: authority.identity(),
                    counter: 1,
                },
                context: VersionVector::default(),
            },
            event_sequence: Some(1),
            logical_key: b"rekey-test".to_vec(),
            blob_route: None,
            ttl_ms: None,
            content_len: payload.len() as u64,
            tombstone: false,
            key_epoch: 2,
        };
        let event = authority
            .seal_event(&header, payload)
            .expect("seal fresh epoch Event");
        let member_route = member.verify_event(&event.bytes).expect("member route");
        assert!(matches!(
            member
                .verify_event_content(member_route, &event.bytes)
                .expect("member content"),
            EventContentVerification::ContentVerified { payload: opened, .. }
                if opened == payload
        ));
        let relay_route = relay.verify_event(&event.bytes).expect("relay route");
        assert!(matches!(
            relay
                .verify_event_content(relay_route, &event.bytes)
                .expect("relay content decision"),
            EventContentVerification::RouteOnly(_)
        ));
        assert!(excluded.verify_event(&event.bytes).is_err());

        // Restart replay follows the same exact-byte authentication boundary;
        // applying the existing provider state transition again is idempotent.
        let replayed = member.verify_control(&sealed).expect("restart inspection");
        let replay_ready = member
            .prepare_committed_control_activation(&replayed, &sealed)
            .expect("restart preparation");
        member
            .activate_committed_control(replay_ready, false)
            .expect("restart activation replay");

        let mut different = sealed;
        different.push(0);
        assert!(
            member
                .prepare_committed_control_activation(&committed, &different)
                .is_err()
        );
    }

    #[test]
    fn same_epoch_first_rekey_invalidates_only_the_superseded_event_route_lineage() {
        let Services {
            mut authority,
            mut member,
            registry,
            ..
        } = services([0x39; 32]);
        let old_payload = b"provisioning epoch-one Event";
        let old_header = EnvelopeHeader {
            class: DataClass::Event,
            topic: topic(),
            scope: scope(),
            priority: Priority::Immediate,
            stamp: CausalStamp {
                dot: Dot {
                    publisher: authority.identity(),
                    counter: 1,
                },
                context: VersionVector::default(),
            },
            event_sequence: Some(1),
            logical_key: b"same-epoch-old".to_vec(),
            blob_route: None,
            ttl_ms: None,
            content_len: old_payload.len() as u64,
            tombstone: false,
            key_epoch: 1,
        };
        let old = authority
            .seal_event(&old_header, old_payload)
            .expect("seal provisioning-key Event");
        let old_route = member
            .verify_event(&old.bytes)
            .expect("verify provisioning-key Event");
        let old_lineage = old_route.route_lineage();
        assert!(member.is_current_event_route_lineage(&scope(), 1, old_lineage));
        assert_eq!(
            format!("{old_lineage:?}"),
            "EventRouteLineage([PROVIDER-OWNED])"
        );

        let recipients = vec![
            ScopeRekeyRecipient::member(authority.identity(), vec![topic()])
                .expect("authority recipient"),
            ScopeRekeyRecipient::member(member.identity(), vec![topic()])
                .expect("member recipient"),
        ];
        let (sealed_control, _) = authority
            .seal_chained_scope_rekey_control_from_registry(
                &registry,
                0,
                scope(),
                1,
                recipients,
                1,
                None,
            )
            .expect("same-epoch first rekey");
        for service in [&mut authority, &mut member] {
            let committed = service
                .verify_control(&sealed_control)
                .expect("verify committed same-epoch control");
            let ready = service
                .prepare_committed_control_activation(&committed, &sealed_control)
                .expect("prepare committed same-epoch control");
            service
                .activate_committed_control(ready, false)
                .expect("activate committed same-epoch control");
        }

        assert!(member.can_route_event(&scope(), 1));
        assert!(!member.is_current_event_route_lineage(&scope(), 1, old_lineage));
        assert!(member.verify_event(&old.bytes).is_err());

        let new_payload = b"replacement epoch-one Event";
        let mut new_header = old_header;
        new_header.stamp.dot.counter = 2;
        new_header.event_sequence = Some(2);
        new_header.logical_key = b"same-epoch-new".to_vec();
        new_header.content_len = new_payload.len() as u64;
        let new = authority
            .seal_event(&new_header, new_payload)
            .expect("seal replacement-key Event");
        let new_route = member
            .verify_event(&new.bytes)
            .expect("verify replacement-key Event");
        let new_lineage = new_route.route_lineage();
        assert_ne!(new_lineage, old_lineage);
        assert!(member.is_current_event_route_lineage(&scope(), 1, new_lineage));
        assert!(!member.is_current_event_route_lineage(&scope(), 2, new_lineage));
    }

    #[test]
    fn chain_claims_distinguish_duplicate_out_of_order_fork_rollback_and_revoked_signer() {
        let Services {
            mut authority,
            mut member,
            ..
        } = services([0x35; 32]);
        let signer = authority.identity();
        let first = authority
            .seal_chained_revocation_control(signer, 1, 1, None)
            .expect("first revokes delegated signer");
        let first_verified = member.verify_control(&first).expect("verify first");
        let first_id = first_verified.envelope_id();

        let second = authority
            .seal_chained_revocation_control(member.identity(), 1, 2, Some(first_id))
            .expect("second");
        let second_verified = member.verify_control(&second).expect("verify second");
        let duplicate = member.verify_control(&second).expect("verify duplicate");
        assert_eq!(duplicate, second_verified);
        assert_eq!(second_verified.signer(), signer);
        assert_eq!(first_verified.revocation_subject(), Some(signer));

        // Both links authenticate cryptographically. The durable chain state
        // rejects this signer because the contiguous predecessor revoked it.
        assert_eq!(second_verified.control_sequence(), 2);
        assert_eq!(second_verified.previous_control(), Some(first_id));

        let fork = authority
            .seal_chained_revocation_control(member.identity(), 2, 2, Some(first_id))
            .expect("fork candidate");
        let fork_verified = member.verify_control(&fork).expect("verify fork candidate");
        assert_eq!(fork_verified.control_sequence(), 2);
        assert_eq!(fork_verified.previous_control(), Some(first_id));
        assert_ne!(fork_verified.envelope_id(), second_verified.envelope_id());

        let rollback = authority
            .seal_chained_revocation_control(member.identity(), 3, 1, None)
            .expect("rollback candidate");
        let rollback_verified = member
            .verify_control(&rollback)
            .expect("verify rollback candidate");
        assert_eq!(rollback_verified.control_sequence(), 1);
        assert_eq!(rollback_verified.previous_control(), None);
        assert_ne!(rollback_verified.envelope_id(), first_id);

        let third = authority
            .seal_chained_revocation_control(
                member.identity(),
                4,
                3,
                Some(second_verified.envelope_id()),
            )
            .expect("out-of-order candidate");
        let third_verified = member.verify_control(&third).expect("verify third");
        assert_eq!(third_verified.control_sequence(), 3);
        assert_eq!(
            third_verified.previous_control(),
            Some(second_verified.envelope_id())
        );

        // Canonical link syntax itself still fails closed before storage.
        assert!(
            authority
                .seal_chained_revocation_control(member.identity(), 5, 2, None)
                .is_err()
        );
        assert!(
            authority
                .seal_chained_revocation_control(member.identity(), 5, 1, Some(first_id))
                .is_err()
        );
        assert!(
            member
                .seal_chained_revocation_control(signer, 2, 2, Some(first_id))
                .is_err()
        );
    }
}
