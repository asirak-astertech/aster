use super::*;
use crate::crypto::{
    BatchCryptoProvider, BridgeCryptoProvider, ReferenceEnvelopeSealer, VerifiedBatchItem,
    VerifiedBatchProof, VerifiedBridgeSourceRoute, VerifiedBridgeWrapper,
};
use crate::engine::{EnvelopeError, EnvelopeSealer, stored_from_verified};
use crate::store::{
    BridgeAuthorizationCursor, BridgeControlOutcome, BridgeRouteOutcome, BridgeRouteReadiness,
    SqliteStore, StoreError, StoredBatchMaterial, StoredBridgeRoute, StoredBridgeSource,
    StoredItem, StoredItemRepresentation, StoredPendingBatchItem, StoredPendingBridgeBlobCarrier,
    StoredPendingBridgeWrapper, VerifiedBlobRouteMetadata,
    VerifiedBridgeAuthorization as StoreVerifiedBridgeAuthorization,
    VerifiedBridgeBlobCarrierCommit, VerifiedBridgeRoute as StoreVerifiedBridgeRoute,
    VerifiedBridgeSource as StoreVerifiedBridgeSource, VerifiedBridgeSourceMetadata,
    VerifiedPendingBridgeBlobCarrier, VerifiedPendingBridgeWrapper,
    VerifiedRejectedBridgeBlobCarrier, VerifiedUnresolvedBridgeSource,
};

const RESTART_PAGE: usize = 1_024;
const MAX_SEMANTIC_INVENTORY_OBJECTS: usize = 100_000;

/// Reference runtime composition which adds semantic-v2 bridge and batch
/// dependency handling around the stable singleton/Blob backend.
///
/// The wrapper is intentionally concrete: custom envelope providers continue
/// to use [`BlobRuntimeBackend`] until they implement the complete semantic-v2
/// provider contract rather than inheriting a permissive fallback.
pub struct ReferenceSemanticRuntimeBackend {
    inner: BlobRuntimeBackend<SqliteStore, ReferenceEnvelopeSealer>,
    batch_inventory_grants: BTreeMap<ObjectId, BatchInventoryGrant>,
    batch_served: BTreeMap<(NodeId, u64, ObjectId), ServedBatchObject>,
    bridge_inventory_grants: BTreeMap<ObjectId, BridgeInventoryGrant>,
    bridge_served: BTreeMap<(NodeId, u64, ObjectId), ServedBridgeObject>,
}

#[derive(Clone, Copy)]
enum BatchInventoryRole {
    Proof {
        proof_envelope_id: [u8; 32],
        anchor_item_id: ItemId,
    },
    Compact {
        item_id: ItemId,
        envelope_id: [u8; 32],
    },
    Singleton {
        item_id: ItemId,
        envelope_id: [u8; 32],
    },
    Blob {
        item_id: ItemId,
        route: AuthenticatedBlobRoute,
    },
}

#[derive(Clone)]
struct BatchInventoryGrant {
    peer: NodeId,
    peer_route_commitments: Vec<[u8; 32]>,
    filter: InterestFilter,
    effective_priority: Priority,
    role: BatchInventoryRole,
}

#[derive(Clone)]
struct ServedBatchObject {
    grant: BatchInventoryGrant,
    total_len: u64,
}

struct LiveBatchMaterial {
    material: StoredBatchMaterial,
    verified: VerifiedBatchItem,
    item: StoredItem,
}

struct BatchInventoryCandidate {
    material: StoredBatchMaterial,
    item: StoredItem,
    compact: StoredItemRepresentation,
}

enum ValidatedBatchGrant {
    Singleton(StoredItemRepresentation),
    Extended(Box<LiveBatchMaterial>),
}

#[derive(Clone)]
struct BridgeInventoryGrant {
    wrapper_envelope_id: [u8; 32],
    current_scope: crate::model::Scope,
    current_route_epoch: u64,
    peer: NodeId,
    filter: InterestFilter,
}

#[derive(Clone)]
struct ServedBridgeObject {
    grant: BridgeInventoryGrant,
    total_len: u64,
}

struct IncomingSemanticObject {
    authenticated_peer: NodeId,
    exchange_id: u64,
    semantic_version: u16,
    object_id: ObjectId,
    bytes: Vec<u8>,
    forwarding: Vec<u8>,
}

impl ReferenceSemanticRuntimeBackend {
    pub fn new(
        node: Node<SqliteStore, ReferenceEnvelopeSealer>,
        blobs: BlobTransferStore,
    ) -> Result<Self, BlobRuntimeError> {
        let mut backend = Self {
            inner: BlobRuntimeBackend::new(node, blobs),
            batch_inventory_grants: BTreeMap::new(),
            batch_served: BTreeMap::new(),
            bridge_inventory_grants: BTreeMap::new(),
            bridge_served: BTreeMap::new(),
        };
        let _ = backend.reauthenticate_batch_state()?;
        let _ = backend.reauthenticate_bridge_state()?;
        Ok(backend)
    }

    pub fn node(&self) -> &Node<SqliteStore, ReferenceEnvelopeSealer> {
        self.inner.node()
    }

    pub fn node_mut(&mut self) -> &mut Node<SqliteStore, ReferenceEnvelopeSealer> {
        self.inner.node_mut()
    }

    pub fn blobs(&self) -> &BlobTransferStore {
        self.inner.blobs()
    }

    pub fn blobs_mut(&mut self) -> &mut BlobTransferStore {
        self.inner.blobs_mut()
    }

    pub fn into_parts(
        self,
    ) -> (
        Node<SqliteStore, ReferenceEnvelopeSealer>,
        BlobTransferStore,
    ) {
        self.inner.into_parts()
    }

    /// Clears contact-scoped bridge authorization caches and reauthenticates
    /// every durable bridge object after a host-side administration mutation.
    /// Returned identities were promoted while rebuilding; callers that use a
    /// reducer-owned inventory should invalidate and reselect that view.
    pub fn refresh_local_bridge_state(&mut self) -> Result<Vec<ObjectId>, BlobRuntimeError> {
        self.clear_bridge_contact_state();
        self.reauthenticate_bridge_state()
    }

    fn clear_bridge_contact_state(&mut self) {
        self.batch_inventory_grants.clear();
        self.batch_served.clear();
        self.bridge_inventory_grants.clear();
        self.bridge_served.clear();
    }

    fn ensure_bridge_contact_authorized(
        &mut self,
        authenticated_peer: NodeId,
    ) -> Result<(), BlobRuntimeError> {
        if self
            .node_mut()
            .store_mut()
            .is_zeroized()
            .map_err(store_error)?
        {
            self.clear_bridge_contact_state();
            return Err(store_error(StoreError::Zeroized));
        }
        if self
            .node_mut()
            .store_mut()
            .is_revoked(&authenticated_peer)
            .map_err(store_error)?
        {
            self.clear_bridge_contact_state();
            return Err(BlobRuntimeError::Engine(EngineError::Revoked(
                authenticated_peer,
            )));
        }
        Ok(())
    }

    fn batch_proof_policy_is_live(
        &mut self,
        proof: &VerifiedBatchProof,
    ) -> Result<bool, BlobRuntimeError> {
        let preamble = &proof.manifest().preamble;
        if self
            .node_mut()
            .store_mut()
            .is_revoked(&preamble.publisher)
            .map_err(store_error)?
        {
            return Ok(false);
        }
        let scope = crate::model::Scope::new(preamble.scope.clone())
            .map_err(|error| store_error(StoreError::Invalid(error.to_string())))?;
        let current_epoch = self
            .node_mut()
            .store_mut()
            .scope_epoch(&scope)
            .map_err(store_error)?;
        Ok(preamble.key_epoch >= current_epoch)
    }

    fn batch_item_policy_is_live(
        &mut self,
        verified: &VerifiedBatchItem,
    ) -> Result<bool, BlobRuntimeError> {
        let envelope = verified.verified_envelope();
        if self
            .node_mut()
            .store_mut()
            .is_revoked(&envelope.header.stamp.dot.publisher)
            .map_err(store_error)?
        {
            return Ok(false);
        }
        let current_epoch = self
            .node_mut()
            .store_mut()
            .scope_epoch(&envelope.header.scope)
            .map_err(store_error)?;
        Ok(envelope.header.key_epoch >= current_epoch)
    }

    fn reauthenticate_batch_state(&mut self) -> Result<Vec<ObjectId>, BlobRuntimeError> {
        self.node_mut().store_mut().clear_verified_batch_proofs();
        let mut promoted = Vec::new();
        let mut after = None;
        loop {
            let page = self
                .node()
                .store()
                .stored_batch_proofs_after(after, RESTART_PAGE)
                .map_err(store_error)?;
            if page.is_empty() {
                break;
            }
            for stored in &page {
                let Ok(proof) = self
                    .node()
                    .envelopes()
                    .open_batch_proof(&stored.exact_bytes, wire::SEMANTIC_PROTOCOL_V2)
                else {
                    continue;
                };
                if proof.proof_envelope_id() != stored.proof_envelope_id
                    || !self.batch_proof_policy_is_live(&proof)?
                {
                    continue;
                }
                self.node_mut()
                    .store_mut()
                    .mark_verified_batch_proof(&proof, &stored.exact_bytes)
                    .map_err(store_error)?;
                promoted.extend(self.promote_pending_batch_items(&proof)?);
            }
            after = page.last().map(|value| value.inserted_order);
            if page.len() < RESTART_PAGE {
                break;
            }
        }
        let mut material_after = None;
        loop {
            let page = self
                .node()
                .store()
                .stored_batch_materials_after(material_after, RESTART_PAGE)
                .map_err(store_error)?;
            if page.is_empty() {
                break;
            }
            for material in &page {
                if let Some(live) = self.live_batch_material(material.item_id)? {
                    self.install_batch_manifest_if_authorized(
                        &live.verified,
                        &live.material.compact_bytes,
                    )?;
                }
            }
            material_after = page.last().map(|material| material.inserted_order);
            if page.len() < RESTART_PAGE {
                break;
            }
        }
        promoted.sort_unstable();
        promoted.dedup();
        Ok(promoted)
    }

    fn promote_pending_batch_items(
        &mut self,
        proof: &VerifiedBatchProof,
    ) -> Result<Vec<ObjectId>, BlobRuntimeError> {
        let proof_id = proof.proof_envelope_id();
        let mut promoted = Vec::new();
        let mut after = None;
        loop {
            let page = self
                .node()
                .store()
                .pending_batch_items_for_proof(&proof_id, after, RESTART_PAGE)
                .map_err(store_error)?;
            if page.is_empty() {
                break;
            }
            for pending in &page {
                match self.promote_one_pending_batch_item(pending, proof) {
                    Ok(_) => promoted.push(ObjectId::new(
                        ObjectKind::SourceEnvelope,
                        pending.envelope_id,
                    )),
                    Err(error) if semantic_terminal_commit_error(&error) => {
                        self.node_mut()
                            .store_mut()
                            .discard_rejected_pending_batch_item(
                                pending.envelope_id,
                                &pending.exact_bytes,
                            )
                            .map_err(store_error)?;
                    }
                    Err(error) => return Err(error),
                }
            }
            after = page.last().map(|value| value.inserted_order);
            if page.len() < RESTART_PAGE {
                break;
            }
        }
        Ok(promoted)
    }

    fn promote_one_pending_batch_item(
        &mut self,
        pending: &StoredPendingBatchItem,
        proof: &VerifiedBatchProof,
    ) -> Result<ItemId, BlobRuntimeError> {
        let opened = self
            .node()
            .envelopes()
            .open_compact_batch_item(&pending.exact_bytes, wire::SEMANTIC_PROTOCOL_V2)
            .map_err(envelope_error)?;
        if opened.envelope_id() != pending.envelope_id
            || opened.item_id() != pending.item_id
            || self.node().envelopes().pending_batch_proof_id(&opened) != proof.proof_envelope_id()
        {
            return Err(missing("pending compact batch identity changed"));
        }
        let verified = self
            .node()
            .envelopes()
            .verify_compact_batch_item(&opened, Some(proof), &pending.exact_bytes)
            .map_err(envelope_error)?;
        if !self.batch_item_policy_is_live(&verified)? {
            return Err(missing(
                "compact batch item is revoked or from a stale epoch",
            ));
        }
        let sample = self.node().custody_sample();
        let stored = stored_from_verified(
            verified.verified_envelope(),
            pending.exact_bytes.clone(),
            self.node().now_ms(),
            pending.cumulative_custody_age_ms,
            sample,
        );
        let item_id = stored.id;
        self.node_mut()
            .store_mut()
            .commit_verified_batch_item_at(&verified, stored, &pending.exact_bytes, sample)
            .map_err(store_error)?;
        self.install_batch_manifest_if_authorized(&verified, &pending.exact_bytes)?;
        Ok(item_id)
    }

    fn install_batch_manifest_if_authorized(
        &mut self,
        verified: &VerifiedBatchItem,
        exact_bytes: &[u8],
    ) -> Result<(), BlobRuntimeError> {
        let envelope = verified.verified_envelope();
        let Some(commitment) = envelope.header.blob_route else {
            return Ok(());
        };
        if !self.node().envelopes().has_content_grant(
            &envelope.header.scope,
            &envelope.header.topic,
            envelope.header.key_epoch,
        ) {
            return Ok(());
        }
        let manifest = self
            .node()
            .envelopes()
            .open_compact_batch_payload(verified, exact_bytes)
            .map_err(envelope_error)?;
        self.blobs_mut().install_authenticated_manifest(
            &manifest,
            &envelope.header.scope,
            &envelope.header.topic,
            envelope.header.key_epoch,
            AuthenticatedBlobRoute::new(EnvelopeId::from_bytes(verified.envelope_id()), commitment),
        )?;
        Ok(())
    }

    /// Reopens the exact proof and compact bytes before they authorize a
    /// route, inventory entry, or Blob carrier. Durable representation rows
    /// are indexes, not authentication capabilities.
    fn live_batch_material(
        &mut self,
        item_id: ItemId,
    ) -> Result<Option<LiveBatchMaterial>, BlobRuntimeError> {
        let Some(material) = self
            .node()
            .store()
            .stored_batch_material(&item_id)
            .map_err(store_error)?
        else {
            return Ok(None);
        };
        let proof = self
            .node()
            .envelopes()
            .open_batch_proof(&material.proof.exact_bytes, wire::SEMANTIC_PROTOCOL_V2)
            .map_err(envelope_error)?;
        if proof.proof_envelope_id() != material.proof.proof_envelope_id
            || !self.batch_proof_policy_is_live(&proof)?
        {
            return Ok(None);
        }
        let pending = self
            .node()
            .envelopes()
            .open_compact_batch_item(&material.compact_bytes, wire::SEMANTIC_PROTOCOL_V2)
            .map_err(envelope_error)?;
        if pending.item_id() != item_id
            || pending.envelope_id() != material.compact_envelope_id
            || self.node().envelopes().pending_batch_proof_id(&pending) != proof.proof_envelope_id()
        {
            return Err(store_error(StoreError::Corrupt(
                "batch representation index differs from authenticated bytes".into(),
            )));
        }
        let verified = self
            .node()
            .envelopes()
            .verify_compact_batch_item(&pending, Some(&proof), &material.compact_bytes)
            .map_err(envelope_error)?;
        if !self.batch_item_policy_is_live(&verified)? {
            return Ok(None);
        }
        let Some(item) = self
            .node_mut()
            .store_mut()
            .get(&item_id)
            .map_err(store_error)?
        else {
            return Err(store_error(StoreError::Corrupt(
                "accepted batch representation has no semantic item".into(),
            )));
        };
        if !stored_item_matches_batch_verification(&item, &verified) {
            return Err(store_error(StoreError::Corrupt(
                "accepted batch item differs from authenticated representation".into(),
            )));
        }
        Ok(Some(LiveBatchMaterial {
            material,
            verified,
            item,
        }))
    }

    fn live_batch_material_for_compact(
        &mut self,
        compact_envelope_id: [u8; 32],
    ) -> Result<Option<LiveBatchMaterial>, BlobRuntimeError> {
        let item_id = self
            .node()
            .store()
            .stored_batch_material_by_compact_envelope(&compact_envelope_id)
            .map_err(store_error)?
            .map(|material| material.item_id);
        match item_id {
            Some(item_id) => self.live_batch_material(item_id),
            None => Ok(None),
        }
    }

    fn reauthenticate_bridge_state(&mut self) -> Result<Vec<ObjectId>, BlobRuntimeError> {
        self.reauthenticate_bridge_authorizations()?;
        self.reauthenticate_pending_bridge_wrappers()?;
        self.reauthenticate_pending_bridge_sources()?;
        self.reauthenticate_committed_bridge_routes()?;
        self.promote_ready_bridge_routes()
    }

    fn reauthenticate_bridge_authorizations(&mut self) -> Result<(), BlobRuntimeError> {
        let mut after = None;
        loop {
            let page = self
                .node()
                .store()
                .stored_bridge_authorizations_after(after, RESTART_PAGE)
                .map_err(store_error)?;
            if page.is_empty() {
                return Ok(());
            }
            for stored in &page {
                let verified = match self
                    .node()
                    .envelopes()
                    .open_bridge_authorization(&stored.exact_bytes)
                {
                    Ok(verified) => verified,
                    Err(_) => continue,
                };
                let envelope = verified.envelope();
                let value = StoreVerifiedBridgeAuthorization::from_provider(
                    envelope.envelope_id,
                    envelope.authorization.clone(),
                    verified.control_signer(),
                    stored.exact_bytes.clone(),
                )
                .map_err(store_error)?;
                self.node_mut()
                    .store_mut()
                    .ingest_bridge_authorization(&value)
                    .map_err(store_error)?;
            }
            let last = page.last().expect("nonempty page");
            after = Some(BridgeAuthorizationCursor {
                authority_id: last.authorization.authority_id,
                sequence: last.authorization.control_sequence,
            });
            if page.len() < RESTART_PAGE {
                return Ok(());
            }
        }
    }

    fn reauthenticate_pending_bridge_wrappers(&mut self) -> Result<(), BlobRuntimeError> {
        let mut after = None;
        loop {
            let page = self
                .node()
                .store()
                .pending_bridge_wrappers_after(after, RESTART_PAGE)
                .map_err(store_error)?;
            if page.is_empty() {
                return Ok(());
            }
            for stored in &page {
                let wrapper = match self
                    .node()
                    .envelopes()
                    .open_bridge_wrapper_for_any_local_route(&stored.exact_wrapper_bytes)
                {
                    Ok(wrapper) => wrapper,
                    Err(_) => continue,
                };
                let verified = VerifiedPendingBridgeWrapper::from_provider(
                    wrapper.wrapper_envelope_id(),
                    wrapper.route().clone(),
                    stored.exact_wrapper_bytes.clone(),
                    stored.authenticated_forwarding_age_ms,
                )
                .map_err(store_error)?;
                let sample = self.node().custody_sample();
                self.node_mut()
                    .store_mut()
                    .stage_verified_pending_bridge_wrapper(&verified, sample)
                    .map_err(store_error)?;
            }
            after = page.last().map(|value| value.inserted_order);
            if page.len() < RESTART_PAGE {
                return Ok(());
            }
        }
    }

    fn reauthenticate_pending_bridge_sources(&mut self) -> Result<(), BlobRuntimeError> {
        let mut after = None;
        loop {
            let page = self
                .node()
                .store()
                .pending_bridge_sources_after(after, RESTART_PAGE)
                .map_err(store_error)?;
            if page.is_empty() {
                return Ok(());
            }
            for stored in &page {
                if let Some(verified) = self.verify_stored_bridge_source(stored)? {
                    self.node_mut()
                        .store_mut()
                        .stage_verified_bridge_source(&verified)
                        .map_err(store_error)?;
                }
            }
            after = page.last().map(|value| value.inserted_order);
            if page.len() < RESTART_PAGE {
                return Ok(());
            }
        }
    }

    fn reauthenticate_committed_bridge_routes(&mut self) -> Result<(), BlobRuntimeError> {
        let mut after = None;
        loop {
            let page = self
                .node()
                .store()
                .stored_bridge_routes_after(after, RESTART_PAGE)
                .map_err(store_error)?;
            if page.is_empty() {
                return Ok(());
            }
            for stored in &page {
                let verified = match self.verify_stored_bridge_route(stored) {
                    Ok(verified) => verified,
                    Err(BlobRuntimeError::Engine(EngineError::Envelope(_))) => continue,
                    Err(error) => return Err(error),
                };
                match self
                    .node()
                    .store()
                    .verified_bridge_route_readiness(&verified)
                    .map_err(store_error)?
                {
                    BridgeRouteReadiness::Eligible => {}
                    BridgeRouteReadiness::MissingDependency | BridgeRouteReadiness::Ineligible => {
                        continue;
                    }
                }
                let sample = self.node().custody_sample();
                match self
                    .node_mut()
                    .store_mut()
                    .promote_verified_bridge_route_at(&verified, sample)
                {
                    Ok(_) => {
                        self.install_bridged_manifest_if_authorized(stored.origin_envelope_id)?
                    }
                    Err(StoreError::BridgeRouteIneligible) => {}
                    Err(error) => return Err(store_error(error)),
                }
            }
            after = page.last().map(|value| value.inserted_order);
            if page.len() < RESTART_PAGE {
                return Ok(());
            }
        }
    }

    fn verify_stored_bridge_source(
        &mut self,
        stored: &StoredBridgeSource,
    ) -> Result<Option<StoreVerifiedBridgeSource>, BlobRuntimeError> {
        let wrappers =
            self.pending_and_committed_wrappers_for_source(&stored.origin_envelope_id)?;
        for exact_wrapper in wrappers {
            let wrapper = match self
                .node()
                .envelopes()
                .open_bridge_wrapper_for_any_local_route(&exact_wrapper)
            {
                Ok(value) => value,
                Err(_) => continue,
            };
            let source = match self
                .node()
                .envelopes()
                .verify_bridge_wrapper_source(&wrapper, &stored.exact_bytes)
            {
                Ok(value) => value,
                Err(_) => continue,
            };
            return self
                .store_verified_source(
                    &source,
                    stored.exact_bytes.clone(),
                    stored.authenticated_forwarding_age_ms,
                )
                .map(Some);
        }
        Ok(None)
    }

    fn verify_stored_bridge_route(
        &mut self,
        stored: &StoredBridgeRoute,
    ) -> Result<StoreVerifiedBridgeRoute, BlobRuntimeError> {
        let wrapper = self
            .node()
            .envelopes()
            .open_bridge_wrapper_for_any_local_route(&stored.exact_wrapper_bytes)
            .map_err(envelope_error)?;
        self.verify_wrapper_authorizations(&wrapper)?;
        let source = self
            .node()
            .envelopes()
            .verify_bridge_wrapper_source(&wrapper, &stored.exact_source_bytes)
            .map_err(envelope_error)?;
        let source = self.store_verified_source(
            &source,
            stored.exact_source_bytes.clone(),
            stored.authenticated_forwarding_age_ms,
        )?;
        StoreVerifiedBridgeRoute::from_provider(
            wrapper.wrapper_envelope_id(),
            wrapper.route().clone(),
            stored.exact_wrapper_bytes.clone(),
            stored.authenticated_forwarding_age_ms,
            source,
        )
        .map_err(store_error)
    }

    fn verify_wrapper_authorizations(
        &mut self,
        wrapper: &VerifiedBridgeWrapper,
    ) -> Result<(), BlobRuntimeError> {
        for (index, hop) in wrapper.route().hops.iter().enumerate() {
            let stored = self
                .node()
                .store()
                .stored_bridge_authorization(&hop.authorization_envelope_id)
                .map_err(store_error)?
                .ok_or_else(|| missing("bridge authorization dependency"))?;
            let verified = self
                .node()
                .envelopes()
                .open_bridge_authorization(&stored.exact_bytes)
                .map_err(envelope_error)?;
            self.node()
                .envelopes()
                .verify_bridge_hop(wrapper.route(), index, &verified)
                .map_err(envelope_error)?;
        }
        Ok(())
    }

    fn store_verified_source(
        &self,
        source: &VerifiedBridgeSourceRoute,
        exact_bytes: Vec<u8>,
        forwarding_age_ms: u64,
    ) -> Result<StoreVerifiedBridgeSource, BlobRuntimeError> {
        let header = source.header();
        let blob_route = header.blob_route.map(|value| VerifiedBlobRouteMetadata {
            blob_id: *value.blob_id().as_bytes(),
            chunk_count: value.chunk_count(),
            merkle_root: *value.root(),
        });
        StoreVerifiedBridgeSource::from_provider(
            source.origin_envelope_id(),
            VerifiedBridgeSourceMetadata {
                source_item_id: source.source_item_id(),
                class: header.class,
                topic: header.topic.clone(),
                priority: header.priority,
                stamp: header.stamp.clone(),
                event_sequence: header.event_sequence,
                logical_key: header.logical_key.clone(),
                ttl_ms: header.ttl_ms,
                blob_route,
                content_len: header.content_len,
                tombstone: header.tombstone,
                origin_scope: header.scope.clone(),
                origin_route_epoch: header.key_epoch,
            },
            exact_bytes,
            forwarding_age_ms,
        )
        .map_err(store_error)
    }

    fn pending_and_committed_wrappers_for_source(
        &self,
        origin_envelope_id: &[u8; 32],
    ) -> Result<Vec<Vec<u8>>, BlobRuntimeError> {
        let mut wrappers = Vec::new();
        let mut after = None;
        loop {
            let page = self
                .node()
                .store()
                .pending_bridge_wrappers_after(after, RESTART_PAGE)
                .map_err(store_error)?;
            for value in &page {
                if &value.route.origin_envelope_id == origin_envelope_id {
                    wrappers.push(value.exact_wrapper_bytes.clone());
                }
            }
            after = page.last().map(|value| value.inserted_order);
            if page.len() < RESTART_PAGE {
                break;
            }
        }
        let mut after = None;
        loop {
            let page = self
                .node()
                .store()
                .stored_bridge_routes_after(after, RESTART_PAGE)
                .map_err(store_error)?;
            for value in &page {
                if &value.origin_envelope_id == origin_envelope_id {
                    wrappers.push(value.exact_wrapper_bytes.clone());
                }
            }
            after = page.last().map(|value| value.inserted_order);
            if page.len() < RESTART_PAGE {
                break;
            }
        }
        Ok(wrappers)
    }

    fn promote_ready_bridge_routes(&mut self) -> Result<Vec<ObjectId>, BlobRuntimeError> {
        let mut promoted = Vec::new();
        let mut after = None;
        loop {
            let page = self
                .node()
                .store()
                .pending_bridge_wrappers_after(after, RESTART_PAGE)
                .map_err(store_error)?;
            if page.is_empty() {
                break;
            }
            for pending in &page {
                let missing = self
                    .node()
                    .store()
                    .missing_bridge_dependencies(&pending.wrapper_envelope_id, 9)
                    .map_err(store_error)?;
                if missing
                    .iter()
                    .any(|value| value.kind() == ObjectKind::BridgeAuthorization)
                {
                    continue;
                }
                if let Err(error) = self.resolve_unresolved_source_for_wrapper(pending) {
                    if matches!(error, BlobRuntimeError::Engine(EngineError::Envelope(_))) {
                        continue;
                    }
                    return Err(error);
                }
                if !self
                    .node()
                    .store()
                    .missing_bridge_dependencies(&pending.wrapper_envelope_id, 9)
                    .map_err(store_error)?
                    .is_empty()
                {
                    continue;
                }
                let source = self
                    .node()
                    .store()
                    .stored_pending_bridge_source(&pending.route.origin_envelope_id)
                    .map_err(store_error)?;
                let source = match source {
                    Some(value) => Some(value),
                    None => self
                        .node()
                        .store()
                        .stored_bridge_source(&pending.route.origin_envelope_id)
                        .map_err(store_error)?,
                };
                let Some(source) = source else {
                    continue;
                };
                let route = match self.verify_pending_bridge_route(pending, &source) {
                    Ok(route) => route,
                    Err(BlobRuntimeError::Engine(EngineError::Envelope(_))) => continue,
                    Err(error) => return Err(error),
                };
                match self
                    .node()
                    .store()
                    .verified_bridge_route_readiness(&route)
                    .map_err(store_error)?
                {
                    BridgeRouteReadiness::Eligible => {}
                    BridgeRouteReadiness::MissingDependency | BridgeRouteReadiness::Ineligible => {
                        continue;
                    }
                }
                let sample = self.node().custody_sample();
                let outcome = self
                    .node_mut()
                    .store_mut()
                    .promote_verified_bridge_route_at(&route, sample)
                    .map_err(store_error)?;
                self.install_bridged_manifest_if_authorized(pending.route.origin_envelope_id)?;
                if !matches!(outcome, BridgeRouteOutcome::Duplicate { .. }) {
                    promoted.push(ObjectId::new(
                        ObjectKind::BridgeRouteWrapper,
                        pending.wrapper_envelope_id,
                    ));
                    promoted.push(ObjectId::new(
                        ObjectKind::SourceEnvelope,
                        pending.route.origin_envelope_id,
                    ));
                }
            }
            after = page.last().map(|value| value.inserted_order);
            if page.len() < RESTART_PAGE {
                break;
            }
        }
        promoted.extend(self.promote_ready_bridge_blob_carriers()?);
        promoted.sort_unstable();
        promoted.dedup();
        Ok(promoted)
    }

    fn active_verified_bridge_source(
        &mut self,
        origin_envelope_id: [u8; 32],
    ) -> Result<Option<(VerifiedBridgeSourceRoute, StoredBridgeRoute)>, BlobRuntimeError> {
        let sample = self.node().custody_sample();
        let mut after = None;
        loop {
            let page = self
                .node()
                .store()
                .stored_bridge_routes_after(after, RESTART_PAGE)
                .map_err(store_error)?;
            if page.is_empty() {
                return Ok(None);
            }
            for route in &page {
                if route.origin_envelope_id != origin_envelope_id
                    || !route.active
                    || !self
                        .node()
                        .store()
                        .bridge_route_is_live_at(&route.wrapper_envelope_id, sample)
                        .map_err(store_error)?
                {
                    continue;
                }
                let wrapper = self
                    .node()
                    .envelopes()
                    .open_bridge_wrapper_for_any_local_route(&route.exact_wrapper_bytes)
                    .map_err(envelope_error)?;
                self.verify_wrapper_authorizations(&wrapper)?;
                let source = self
                    .node()
                    .envelopes()
                    .verify_bridge_wrapper_source(&wrapper, &route.exact_source_bytes)
                    .map_err(envelope_error)?;
                return Ok(Some((source, route.clone())));
            }
            after = page.last().map(|value| value.inserted_order);
            if page.len() < RESTART_PAGE {
                return Ok(None);
            }
        }
    }

    fn install_bridged_manifest_if_authorized(
        &mut self,
        origin_envelope_id: [u8; 32],
    ) -> Result<(), BlobRuntimeError> {
        let Some((source, route)) = self.active_verified_bridge_source(origin_envelope_id)? else {
            return Ok(());
        };
        let header = source.header();
        let Some(commitment) = header.blob_route else {
            return Ok(());
        };
        if !self.node().envelopes().has_content_grant(
            &header.scope,
            &header.topic,
            header.key_epoch,
        ) {
            return Ok(());
        }
        let scope = header.scope.clone();
        let topic = header.topic.clone();
        let epoch = header.key_epoch;
        let manifest = self
            .node()
            .envelopes()
            .open_bridged_payload(&source, &route.exact_source_bytes)
            .map_err(envelope_error)?;
        self.blobs_mut().install_authenticated_manifest(
            &manifest,
            &scope,
            &topic,
            epoch,
            AuthenticatedBlobRoute::new(EnvelopeId::from_bytes(origin_envelope_id), commitment),
        )?;
        Ok(())
    }

    fn resolve_unresolved_source_for_wrapper(
        &mut self,
        pending: &StoredPendingBridgeWrapper,
    ) -> Result<(), BlobRuntimeError> {
        if self
            .node()
            .store()
            .stored_pending_bridge_source(&pending.route.origin_envelope_id)
            .map_err(store_error)?
            .is_some()
            || self
                .node()
                .store()
                .stored_bridge_source(&pending.route.origin_envelope_id)
                .map_err(store_error)?
                .is_some()
        {
            return Ok(());
        }
        let unresolved = self
            .node()
            .store()
            .stored_unresolved_bridge_source(&pending.route.origin_envelope_id)
            .map_err(store_error)?;
        let (exact_source, forwarding_age) = if let Some(unresolved) = unresolved {
            (
                unresolved.exact_bytes,
                unresolved.authenticated_forwarding_age_ms,
            )
        } else {
            let sample = self.node().custody_sample();
            let Some(item) = self
                .node_mut()
                .store_mut()
                .get_by_envelope(&pending.route.origin_envelope_id)
                .map_err(store_error)?
            else {
                return Ok(());
            };
            let forwarding_age = conservative_item_custody_age(&item, sample);
            (item.sealed, forwarding_age)
        };
        let wrapper = self
            .node()
            .envelopes()
            .open_bridge_wrapper_for_any_local_route(&pending.exact_wrapper_bytes)
            .map_err(envelope_error)?;
        self.verify_wrapper_authorizations(&wrapper)?;
        let source = self
            .node()
            .envelopes()
            .verify_bridge_wrapper_source(&wrapper, &exact_source)
            .map_err(envelope_error)?;
        let source = self.store_verified_source(&source, exact_source, forwarding_age)?;
        self.node_mut()
            .store_mut()
            .stage_verified_bridge_source(&source)
            .map_err(store_error)?;
        Ok(())
    }

    fn verify_pending_bridge_route(
        &mut self,
        pending: &StoredPendingBridgeWrapper,
        stored_source: &StoredBridgeSource,
    ) -> Result<StoreVerifiedBridgeRoute, BlobRuntimeError> {
        let wrapper = self
            .node()
            .envelopes()
            .open_bridge_wrapper_for_any_local_route(&pending.exact_wrapper_bytes)
            .map_err(envelope_error)?;
        self.verify_wrapper_authorizations(&wrapper)?;
        let source = self
            .node()
            .envelopes()
            .verify_bridge_wrapper_source(&wrapper, &stored_source.exact_bytes)
            .map_err(envelope_error)?;
        let source = self.store_verified_source(
            &source,
            stored_source.exact_bytes.clone(),
            stored_source.authenticated_forwarding_age_ms,
        )?;
        StoreVerifiedBridgeRoute::from_provider(
            wrapper.wrapper_envelope_id(),
            wrapper.route().clone(),
            pending.exact_wrapper_bytes.clone(),
            pending.authenticated_forwarding_age_ms,
            source,
        )
        .map_err(store_error)
    }

    fn commit_bridge_authorization(
        &mut self,
        object_id: ObjectId,
        bytes: Vec<u8>,
        forwarding: Vec<u8>,
    ) -> Result<RuntimeCommit, BlobRuntimeError> {
        if !forwarding.is_empty() {
            return Err(missing(
                "bridge authorization forwarding metadata is forbidden",
            ));
        }
        let verified = self
            .node()
            .envelopes()
            .open_bridge_authorization(&bytes)
            .map_err(envelope_error)?;
        let envelope = verified.envelope();
        if object_id.digest() != &envelope.envelope_id {
            return Err(missing("bridge authorization identity mismatch"));
        }
        let stored = StoreVerifiedBridgeAuthorization::from_provider(
            envelope.envelope_id,
            envelope.authorization.clone(),
            verified.control_signer(),
            bytes,
        )
        .map_err(store_error)?;
        let outcome = self
            .node_mut()
            .store_mut()
            .ingest_bridge_authorization(&stored)
            .map_err(store_error)?;
        if let Some(rejected) = outcome.rejected_input() {
            if self
                .node_mut()
                .store_mut()
                .is_revoked(&envelope.authorization.authority_id)
                .map_err(store_error)?
            {
                return Err(store_error(StoreError::BridgeControlAuthorityRevoked(
                    envelope.authorization.authority_id,
                )));
            }
            if self
                .node_mut()
                .store_mut()
                .is_revoked(&rejected.signer)
                .map_err(store_error)?
            {
                return Err(store_error(StoreError::BridgeControlSignerRevoked(
                    rejected.signer,
                )));
            }
            return Err(store_error(StoreError::Invalid(
                "bridge control input was discarded with an invalid pending suffix".into(),
            )));
        }
        self.node_mut().finish_transfer(object_id)?;

        let mut promoted = Vec::new();
        let mut refresh_bridge_state = false;
        let disposition = match outcome {
            BridgeControlOutcome::Applied { activated, .. } => {
                refresh_bridge_state = true;
                promoted.extend(activated.into_iter().filter_map(|value| {
                    (value.envelope_id != *object_id.digest()).then_some(ObjectId::new(
                        ObjectKind::BridgeAuthorization,
                        value.envelope_id,
                    ))
                }));
                RuntimeCommit::Committed {
                    item_id: None,
                    promoted: Vec::new(),
                }
            }
            BridgeControlOutcome::Duplicate { .. } => {
                let stored = self
                    .node()
                    .store()
                    .stored_bridge_authorization(object_id.digest())
                    .map_err(store_error)?
                    .ok_or_else(|| missing("duplicate bridge authorization disappeared"))?;
                if stored.applied {
                    RuntimeCommit::Committed {
                        item_id: None,
                        promoted: Vec::new(),
                    }
                } else {
                    RuntimeCommit::Deferred {
                        dependencies: vec![
                            self.first_missing_bridge_control_dependency(
                                stored.authorization.previous_control_id,
                            )?
                            .ok_or_else(|| {
                                store_error(StoreError::Corrupt(
                                    "unapplied bridge control has no missing predecessor".into(),
                                ))
                            })?,
                        ],
                    }
                }
            }
            BridgeControlOutcome::Pending { .. } => RuntimeCommit::Deferred {
                dependencies: vec![
                    self.first_missing_bridge_control_dependency(
                        envelope.authorization.previous_control_id,
                    )?
                    .ok_or_else(|| {
                        store_error(StoreError::Corrupt(
                            "pending bridge control has no missing predecessor".into(),
                        ))
                    })?,
                ],
            },
            BridgeControlOutcome::Rejected { signer, .. } => {
                return Err(store_error(StoreError::BridgeControlSignerRevoked(signer)));
            }
        };
        match disposition {
            RuntimeCommit::Committed { item_id, .. } => {
                if refresh_bridge_state {
                    self.clear_bridge_contact_state();
                    promoted.extend(self.reauthenticate_bridge_state()?);
                } else {
                    promoted.extend(self.promote_ready_bridge_routes()?);
                }
                promoted.sort_unstable();
                promoted.dedup();
                Ok(RuntimeCommit::Committed { item_id, promoted })
            }
            RuntimeCommit::Deferred { dependencies } => {
                Ok(RuntimeCommit::Deferred { dependencies })
            }
            RuntimeCommit::Quarantined => unreachable!("bridge controls are never quarantined"),
        }
    }

    fn first_missing_bridge_control_dependency(
        &self,
        mut predecessor: Option<[u8; 32]>,
    ) -> Result<Option<ObjectId>, BlobRuntimeError> {
        let mut seen = BTreeSet::new();
        while let Some(envelope_id) = predecessor {
            if !seen.insert(envelope_id) || seen.len() > MAX_SEMANTIC_INVENTORY_OBJECTS {
                return Err(store_error(StoreError::Corrupt(
                    "bridge control predecessor chain is cyclic or unbounded".into(),
                )));
            }
            let Some(stored) = self
                .node()
                .store()
                .stored_bridge_authorization(&envelope_id)
                .map_err(store_error)?
            else {
                return Ok(Some(ObjectId::new(
                    ObjectKind::BridgeAuthorization,
                    envelope_id,
                )));
            };
            if stored.applied {
                return Ok(None);
            }
            predecessor = stored.authorization.previous_control_id;
        }
        Ok(None)
    }

    fn commit_bridge_wrapper(
        &mut self,
        authenticated_peer: NodeId,
        exchange_id: u64,
        object_id: ObjectId,
        bytes: Vec<u8>,
        forwarding: Vec<u8>,
    ) -> Result<RuntimeCommit, BlobRuntimeError> {
        let wrapper = self
            .node()
            .envelopes()
            .open_bridge_wrapper_for_any_local_route(&bytes)
            .map_err(envelope_error)?;
        if object_id.digest() != &wrapper.wrapper_envelope_id() {
            return Err(missing("bridge wrapper identity mismatch"));
        }
        let recipient = self.node().identity();
        let forwarding_age = self
            .node_mut()
            .envelopes_mut()
            .inspect_forwarding(
                authenticated_peer,
                recipient,
                exchange_id,
                wrapper.wrapper_envelope_id(),
                &forwarding,
            )
            .map_err(envelope_error)?;
        let verified = VerifiedPendingBridgeWrapper::from_provider(
            wrapper.wrapper_envelope_id(),
            wrapper.route().clone(),
            bytes,
            forwarding_age,
        )
        .map_err(store_error)?;
        let sample = self.node().custody_sample();
        self.node_mut()
            .store_mut()
            .defer_verified_pending_bridge_wrapper_transfer(&verified, sample)
            .map_err(store_error)?;
        let promoted = self.promote_ready_bridge_routes()?;
        if promoted.contains(&object_id) {
            let route = self
                .node()
                .store()
                .stored_bridge_route(object_id.digest())
                .map_err(store_error)?
                .ok_or_else(|| missing("promoted bridge route is missing"))?;
            return Ok(RuntimeCommit::Committed {
                item_id: Some(route.source_item_id),
                promoted: promoted
                    .into_iter()
                    .filter(|value| *value != object_id)
                    .collect(),
            });
        }
        if let Some(route) = self
            .node()
            .store()
            .stored_bridge_route(object_id.digest())
            .map_err(store_error)?
        {
            return Ok(RuntimeCommit::Committed {
                item_id: Some(route.source_item_id),
                promoted,
            });
        }
        let dependencies = self
            .node()
            .store()
            .missing_bridge_dependencies(object_id.digest(), 9)
            .map_err(store_error)?;
        if dependencies.is_empty() {
            return Err(missing(
                "bridge wrapper remained pending without a missing dependency",
            ));
        }
        Ok(RuntimeCommit::Deferred { dependencies })
    }

    fn commit_bridge_source(
        &mut self,
        authenticated_peer: NodeId,
        exchange_id: u64,
        object_id: ObjectId,
        bytes: Vec<u8>,
        forwarding: Vec<u8>,
    ) -> Result<RuntimeCommit, BlobRuntimeError> {
        let wrappers = self.pending_and_committed_wrappers_for_source(object_id.digest())?;
        let mut authenticated = None;
        for exact_wrapper in wrappers {
            let Ok(wrapper) = self
                .node()
                .envelopes()
                .open_bridge_wrapper_for_any_local_route(&exact_wrapper)
            else {
                continue;
            };
            let Ok(source) = self
                .node()
                .envelopes()
                .verify_bridge_wrapper_source(&wrapper, &bytes)
            else {
                continue;
            };
            authenticated = Some(source);
            break;
        }
        let source =
            authenticated.ok_or_else(|| missing("bridge source has no verified wrapper"))?;
        let recipient = self.node().identity();
        let forwarding_age = self
            .node_mut()
            .envelopes_mut()
            .inspect_forwarding(
                authenticated_peer,
                recipient,
                exchange_id,
                *object_id.digest(),
                &forwarding,
            )
            .map_err(envelope_error)?;
        let materialize_ordinary = self.node().envelopes().has_content_grant(
            &source.header().scope,
            &source.header().topic,
            source.header().key_epoch,
        );
        let item_id = source.source_item_id();
        let ordinary_bytes = materialize_ordinary.then(|| bytes.clone());
        let source = self.store_verified_source(&source, bytes, forwarding_age)?;
        let sample = self.node().custody_sample();
        if materialize_ordinary {
            let mut ordinary = self.inner.commit_authenticated_object_with_dependencies(
                authenticated_peer,
                exchange_id,
                wire::SEMANTIC_PROTOCOL_V2,
                object_id,
                ordinary_bytes.expect("ordinary bytes follow the authorization check"),
                forwarding,
            )?;
            let RuntimeCommit::Committed { promoted, .. } = &mut ordinary else {
                return Err(missing(
                    "provider-authorized bridge source did not commit as an ordinary origin view",
                ));
            };
            self.node_mut()
                .store_mut()
                .stage_verified_bridge_source_at(&source, sample)
                .map_err(store_error)?;
            promoted.extend(self.promote_ready_bridge_routes()?);
            promoted.sort_unstable();
            promoted.dedup();
            return Ok(ordinary);
        }
        self.node_mut()
            .store_mut()
            .defer_verified_bridge_source_transfer(&source, sample)
            .map_err(store_error)?;
        let promoted = self.promote_ready_bridge_routes()?;
        if !promoted.is_empty() {
            return Ok(RuntimeCommit::Committed {
                item_id: Some(item_id),
                promoted: promoted
                    .into_iter()
                    .filter(|value| *value != object_id)
                    .collect(),
            });
        }
        if self
            .node()
            .store()
            .stored_bridge_source(object_id.digest())
            .map_err(store_error)?
            .is_some()
        {
            return Ok(RuntimeCommit::Committed {
                item_id: Some(item_id),
                promoted: Vec::new(),
            });
        }
        let dependencies = self.bridge_dependencies_for_source(object_id.digest())?;
        if dependencies.is_empty() {
            return Err(missing(
                "bridge source remained pending without a missing dependency",
            ));
        }
        Ok(RuntimeCommit::Deferred { dependencies })
    }

    fn commit_source_or_quarantine(
        &mut self,
        incoming: IncomingSemanticObject,
        allow_bridge_quarantine: bool,
    ) -> Result<RuntimeCommit, BlobRuntimeError> {
        let IncomingSemanticObject {
            authenticated_peer,
            exchange_id,
            semantic_version,
            object_id,
            bytes,
            forwarding,
        } = incoming;
        let ordinary = self.node_mut().envelopes_mut().inspect_object(&bytes).ok();
        if let Some(ordinary) = ordinary {
            let control = matches!(ordinary, crate::engine::VerifiedObject::Control(_));
            let mut commit = self.inner.commit_authenticated_object_with_dependencies(
                authenticated_peer,
                exchange_id,
                semantic_version,
                object_id,
                bytes,
                forwarding,
            )?;
            if control && matches!(commit, RuntimeCommit::Committed { .. }) {
                self.clear_bridge_contact_state();
                let batch_promoted = self.reauthenticate_batch_state()?;
                let bridge_promoted = self.reauthenticate_bridge_state()?;
                if let RuntimeCommit::Committed { promoted, .. } = &mut commit {
                    promoted.extend(batch_promoted);
                    promoted.extend(bridge_promoted);
                    promoted.sort_unstable();
                    promoted.dedup();
                }
            } else if matches!(commit, RuntimeCommit::Committed { .. }) {
                let blob_promoted = self.promote_ready_bridge_blob_carriers()?;
                if let RuntimeCommit::Committed { promoted, .. } = &mut commit {
                    promoted.extend(blob_promoted);
                    promoted.sort_unstable();
                    promoted.dedup();
                }
            }
            return Ok(commit);
        }

        // Semantic version 1 has no bridge-source representation. Preserve
        // the ordinary backend's terminal validation behavior for malformed
        // kind-1 bytes instead of treating them as a deferred bridge source.
        if !allow_bridge_quarantine {
            return self.inner.commit_authenticated_object_with_dependencies(
                authenticated_peer,
                exchange_id,
                semantic_version,
                object_id,
                bytes,
                forwarding,
            );
        }

        let recipient = self.node().identity();
        let forwarding_age = self
            .node_mut()
            .envelopes_mut()
            .inspect_forwarding(
                authenticated_peer,
                recipient,
                exchange_id,
                *object_id.digest(),
                &forwarding,
            )
            .map_err(envelope_error)?;
        let unresolved = VerifiedUnresolvedBridgeSource::from_provider(
            *object_id.digest(),
            bytes,
            forwarding_age,
        )
        .map_err(store_error)?;
        let sample = self.node().custody_sample();
        self.node_mut()
            .store_mut()
            .defer_verified_unresolved_bridge_source_transfer(&unresolved, sample)
            .map_err(store_error)?;
        Ok(RuntimeCommit::Quarantined)
    }

    fn commit_batch_proof(
        &mut self,
        authenticated_peer: NodeId,
        exchange_id: u64,
        object_id: ObjectId,
        bytes: Vec<u8>,
        forwarding: Vec<u8>,
    ) -> Result<RuntimeCommit, BlobRuntimeError> {
        let exact_identity: [u8; 32] = Sha256::digest(&bytes).into();
        if exact_identity != *object_id.digest() {
            return Err(missing("batch proof transfer digest mismatch"));
        }
        let existing = self
            .node()
            .store()
            .stored_batch_proof(object_id.digest())
            .map_err(store_error)?;
        let proof = match self
            .node()
            .envelopes()
            .open_batch_proof(&bytes, wire::SEMANTIC_PROTOCOL_V2)
        {
            Ok(proof) => proof,
            Err(error) => {
                if existing.is_none() {
                    self.node_mut()
                        .store_mut()
                        .reject_batch_proof(*object_id.digest(), &bytes)
                        .map_err(store_error)?;
                }
                return Err(envelope_error(error));
            }
        };
        if proof.proof_envelope_id() != *object_id.digest() {
            return Err(missing("batch proof identity mismatch"));
        }
        if forwarding.is_empty() {
            if !existing
                .as_ref()
                .is_some_and(|stored| stored.exact_bytes == bytes)
            {
                return Err(missing(
                    "first-time batch proof omitted authenticated forwarding metadata",
                ));
            }
        } else {
            let recipient = self.node().identity();
            self.node_mut()
                .envelopes_mut()
                .inspect_forwarding(
                    authenticated_peer,
                    recipient,
                    exchange_id,
                    *object_id.digest(),
                    &forwarding,
                )
                .map_err(envelope_error)?;
        }
        if !self.batch_proof_policy_is_live(&proof)? {
            return Err(missing("batch proof is revoked or from a stale epoch"));
        }
        self.node_mut()
            .store_mut()
            .stage_verified_batch_proof(&proof, &bytes)
            .map_err(store_error)?;
        let mut promoted = self.promote_pending_batch_items(&proof)?;
        promoted.extend(self.promote_ready_bridge_blob_carriers()?);
        promoted.sort_unstable();
        promoted.dedup();
        self.node_mut().finish_transfer(object_id)?;
        Ok(RuntimeCommit::Committed {
            item_id: None,
            promoted,
        })
    }

    fn commit_compact_batch_item(
        &mut self,
        authenticated_peer: NodeId,
        exchange_id: u64,
        object_id: ObjectId,
        bytes: Vec<u8>,
        forwarding: Vec<u8>,
    ) -> Result<RuntimeCommit, BlobRuntimeError> {
        let pending = self
            .node()
            .envelopes()
            .open_compact_batch_item(&bytes, wire::SEMANTIC_PROTOCOL_V2)
            .map_err(envelope_error)?;
        if pending.envelope_id() != *object_id.digest() {
            return Err(missing("compact batch identity mismatch"));
        }
        let existing_pending = self
            .node()
            .store()
            .stored_pending_batch_item(object_id.digest())
            .map_err(store_error)?;
        let accepted_material = self
            .node()
            .store()
            .stored_batch_material(&pending.item_id())
            .map_err(store_error)?;
        let authenticated_age = if forwarding.is_empty() {
            if let Some(existing) = &existing_pending {
                if existing.exact_bytes != bytes {
                    return Err(missing("pending compact replay bytes changed"));
                }
                existing.authenticated_forwarding_age_ms
            } else if accepted_material.as_ref().is_some_and(|material| {
                material.compact_envelope_id == *object_id.digest()
                    && material.compact_bytes == bytes
            }) {
                self.node_mut().finish_transfer(object_id)?;
                return Ok(RuntimeCommit::Committed {
                    item_id: Some(pending.item_id()),
                    promoted: Vec::new(),
                });
            } else {
                return Err(missing(
                    "first-time compact batch item omitted authenticated forwarding metadata",
                ));
            }
        } else {
            let recipient = self.node().identity();
            self.node_mut()
                .envelopes_mut()
                .inspect_forwarding(
                    authenticated_peer,
                    recipient,
                    exchange_id,
                    *object_id.digest(),
                    &forwarding,
                )
                .map_err(envelope_error)?
        };
        let header = pending.header();
        if self
            .node_mut()
            .store_mut()
            .is_revoked(&header.stamp.dot.publisher)
            .map_err(store_error)?
        {
            return Err(BlobRuntimeError::Engine(EngineError::Revoked(
                header.stamp.dot.publisher,
            )));
        }
        let current_epoch = self
            .node_mut()
            .store_mut()
            .scope_epoch(&header.scope)
            .map_err(store_error)?;
        if header.key_epoch < current_epoch {
            return Err(BlobRuntimeError::Engine(EngineError::StaleKeyEpoch {
                current: current_epoch,
                received: header.key_epoch,
            }));
        }
        if !header.tombstone
            && header
                .ttl_ms
                .is_some_and(|ttl_ms| authenticated_age >= ttl_ms)
        {
            return Err(BlobRuntimeError::Engine(EngineError::Expired));
        }
        let sample = self.node().custody_sample();
        self.node_mut()
            .store_mut()
            .stage_pending_batch_item_at(&pending, &bytes, authenticated_age, sample)
            .map_err(store_error)?;

        let proof_id = self.node().envelopes().pending_batch_proof_id(&pending);
        let Some(stored_proof) = self
            .node()
            .store()
            .stored_batch_proof(&proof_id)
            .map_err(store_error)?
        else {
            self.node_mut().finish_transfer(object_id)?;
            return Ok(RuntimeCommit::Deferred {
                dependencies: vec![ObjectId::new(ObjectKind::SourceBatchProof, proof_id)],
            });
        };
        let proof = self
            .node()
            .envelopes()
            .open_batch_proof(&stored_proof.exact_bytes, wire::SEMANTIC_PROTOCOL_V2)
            .map_err(envelope_error)?;
        if proof.proof_envelope_id() != proof_id || !self.batch_proof_policy_is_live(&proof)? {
            return Err(missing("compact batch proof is not live"));
        }
        self.node_mut()
            .store_mut()
            .mark_verified_batch_proof(&proof, &stored_proof.exact_bytes)
            .map_err(store_error)?;
        let durable_pending = self
            .node()
            .store()
            .stored_pending_batch_item(object_id.digest())
            .map_err(store_error)?
            .ok_or_else(|| missing("staged compact batch item disappeared"))?;
        let item_id = self.promote_one_pending_batch_item(&durable_pending, &proof)?;
        let mut promoted = self.promote_ready_bridge_blob_carriers()?;
        promoted.sort_unstable();
        promoted.dedup();
        self.node_mut().finish_transfer(object_id)?;
        Ok(RuntimeCommit::Committed {
            item_id: Some(item_id),
            promoted,
        })
    }

    fn commit_bridge_blob_chunk(
        &mut self,
        object_id: ObjectId,
        bytes: Vec<u8>,
        forwarding: Vec<u8>,
    ) -> Result<Option<RuntimeCommit>, BlobRuntimeError> {
        if !forwarding.is_empty() {
            return Err(missing("Blob chunk forwarding metadata is forbidden"));
        }
        let inspected = inspect_blob_transfer_object(&bytes)?;
        if inspected.object_id() != object_id {
            return Err(missing("Blob carrier identity mismatch"));
        }
        let source_envelope = inspected.source_envelope().into_bytes();
        if let Some(live) = self.live_batch_material_for_compact(source_envelope)? {
            let commitment = live
                .verified
                .verified_envelope()
                .header
                .blob_route
                .ok_or_else(|| missing("batch carrier source is not a Blob manifest"))?;
            let route =
                AuthenticatedBlobRoute::new(EnvelopeId::from_bytes(source_envelope), commitment);
            crate::blob::authenticate_blob_transfer_object_for_route(object_id, &bytes, route)?;
            self.blobs_mut().commit_carrier(object_id, &bytes, route)?;
            self.node_mut().finish_transfer(object_id)?;
            return Ok(Some(RuntimeCommit::Committed {
                item_id: None,
                promoted: Vec::new(),
            }));
        }
        let Some((source, route)) = self.active_verified_bridge_source(source_envelope)? else {
            // A complete semantic-v2 carrier can arrive before either an
            // ordinary source manifest or the wrapper which identifies a
            // bridged source.  The carrier itself intentionally does not
            // disclose that distinction, so retain its exact bytes in the
            // private dependency partition until the source arrives.  If the
            // ordinary source is already authenticated, let the stable Blob
            // backend commit it directly.
            if let Some((verified, _sealed)) = self
                .node_mut()
                .inspect_stored_data_envelope(EnvelopeId::from_bytes(source_envelope))?
            {
                return if verified.header.blob_route.is_some() {
                    Ok(None)
                } else {
                    Err(missing("Blob carrier source is not a Blob manifest"))
                };
            }
            let pending =
                VerifiedPendingBridgeBlobCarrier::from_provider(object_id, source_envelope, bytes)
                    .map_err(store_error)?;
            self.node_mut()
                .store_mut()
                .defer_verified_pending_bridge_blob_carrier_transfer(&pending)
                .map_err(store_error)?;
            return Ok(Some(RuntimeCommit::Deferred {
                dependencies: vec![ObjectId::new(ObjectKind::SourceEnvelope, source_envelope)],
            }));
        };
        let commitment = source
            .header()
            .blob_route
            .ok_or_else(|| missing("bridged source is not a Blob manifest"))?;
        let authenticated_route =
            AuthenticatedBlobRoute::new(EnvelopeId::from_bytes(source_envelope), commitment);
        crate::blob::authenticate_blob_transfer_object_for_route(
            object_id,
            &bytes,
            authenticated_route,
        )?;
        let pending = VerifiedPendingBridgeBlobCarrier::from_provider(
            object_id,
            source_envelope,
            bytes.clone(),
        )
        .map_err(store_error)?;
        self.node_mut()
            .store_mut()
            .defer_verified_pending_bridge_blob_carrier_transfer(&pending)
            .map_err(store_error)?;
        self.blobs_mut()
            .commit_carrier(object_id, &bytes, authenticated_route)?;
        let committed =
            VerifiedBridgeBlobCarrierCommit::from_provider(object_id, source_envelope, bytes)
                .map_err(store_error)?;
        let sample = self.node().custody_sample();
        self.node_mut()
            .store_mut()
            .complete_verified_bridge_blob_carrier_commit(&committed, sample)
            .map_err(store_error)?;
        self.node_mut().finish_transfer(object_id)?;
        if self.node().envelopes().has_content_grant(
            &source.header().scope,
            &source.header().topic,
            source.header().key_epoch,
        ) {
            let scope = source.header().scope.clone();
            let topic = source.header().topic.clone();
            let epoch = source.header().key_epoch;
            let manifest = self
                .node()
                .envelopes()
                .open_bridged_payload(&source, &route.exact_source_bytes)
                .map_err(envelope_error)?;
            self.blobs_mut().install_authenticated_manifest(
                &manifest,
                &scope,
                &topic,
                epoch,
                authenticated_route,
            )?;
        }
        Ok(Some(RuntimeCommit::Committed {
            item_id: None,
            promoted: Vec::new(),
        }))
    }

    fn promote_ready_bridge_blob_carriers(&mut self) -> Result<Vec<ObjectId>, BlobRuntimeError> {
        let mut promoted = Vec::new();
        let mut after = None;
        loop {
            let page = self
                .node()
                .store()
                .pending_bridge_blob_carriers_after(after, RESTART_PAGE)
                .map_err(store_error)?;
            if page.is_empty() {
                break;
            }
            for pending in &page {
                if self.commit_pending_bridge_blob_carrier(pending)? {
                    promoted.push(pending.object_id);
                }
            }
            after = page.last().map(|value| value.inserted_order);
            if page.len() < RESTART_PAGE {
                break;
            }
        }
        Ok(promoted)
    }

    fn commit_pending_bridge_blob_carrier(
        &mut self,
        pending: &StoredPendingBridgeBlobCarrier,
    ) -> Result<bool, BlobRuntimeError> {
        if let Some(live) = self.live_batch_material_for_compact(pending.source_envelope_id)? {
            let Some(commitment) = live.verified.verified_envelope().header.blob_route else {
                self.discard_rejected_pending_bridge_blob_carrier(pending)?;
                return Ok(false);
            };
            let route = AuthenticatedBlobRoute::new(
                EnvelopeId::from_bytes(pending.source_envelope_id),
                commitment,
            );
            if crate::blob::authenticate_blob_transfer_object_for_route(
                pending.object_id,
                &pending.exact_bytes,
                route,
            )
            .is_err()
            {
                self.discard_rejected_pending_bridge_blob_carrier(pending)?;
                return Ok(false);
            }
            self.blobs_mut()
                .commit_carrier(pending.object_id, &pending.exact_bytes, route)?;
            self.discard_rejected_pending_bridge_blob_carrier(pending)?;
            self.node_mut().finish_transfer(pending.object_id)?;
            return Ok(true);
        }
        if let Some((source, _route)) =
            self.active_verified_bridge_source(pending.source_envelope_id)?
        {
            let Some(commitment) = source.header().blob_route else {
                self.discard_rejected_pending_bridge_blob_carrier(pending)?;
                return Ok(false);
            };
            let authenticated_route = AuthenticatedBlobRoute::new(
                EnvelopeId::from_bytes(pending.source_envelope_id),
                commitment,
            );
            if crate::blob::authenticate_blob_transfer_object_for_route(
                pending.object_id,
                &pending.exact_bytes,
                authenticated_route,
            )
            .is_err()
            {
                self.discard_rejected_pending_bridge_blob_carrier(pending)?;
                return Ok(false);
            }
            self.blobs_mut().commit_carrier(
                pending.object_id,
                &pending.exact_bytes,
                authenticated_route,
            )?;
            let committed = VerifiedBridgeBlobCarrierCommit::from_provider(
                pending.object_id,
                pending.source_envelope_id,
                pending.exact_bytes.clone(),
            )
            .map_err(store_error)?;
            let sample = self.node().custody_sample();
            self.node_mut()
                .store_mut()
                .complete_verified_bridge_blob_carrier_commit(&committed, sample)
                .map_err(store_error)?;
            self.node_mut().finish_transfer(pending.object_id)?;
            return Ok(true);
        }

        // Before its source arrives the same opaque carrier may prove to be an
        // ordinary within-scope Blob rather than a bridge carrier.  Authenticate
        // it against that source, commit it to the common Blob store, and then
        // retire only the temporary bridge-candidate row.
        let source_envelope = EnvelopeId::from_bytes(pending.source_envelope_id);
        let Some((verified, _sealed)) = self
            .node_mut()
            .inspect_stored_data_envelope(source_envelope)?
        else {
            return Ok(false);
        };
        let Some(commitment) = verified.header.blob_route else {
            self.discard_rejected_pending_bridge_blob_carrier(pending)?;
            return Ok(false);
        };
        let authenticated_route = AuthenticatedBlobRoute::new(source_envelope, commitment);
        if crate::blob::authenticate_blob_transfer_object_for_route(
            pending.object_id,
            &pending.exact_bytes,
            authenticated_route,
        )
        .is_err()
        {
            self.discard_rejected_pending_bridge_blob_carrier(pending)?;
            return Ok(false);
        }
        self.blobs_mut().commit_carrier(
            pending.object_id,
            &pending.exact_bytes,
            authenticated_route,
        )?;
        self.discard_rejected_pending_bridge_blob_carrier(pending)?;
        self.node_mut().finish_transfer(pending.object_id)?;
        Ok(true)
    }

    fn discard_rejected_pending_bridge_blob_carrier(
        &mut self,
        pending: &StoredPendingBridgeBlobCarrier,
    ) -> Result<(), BlobRuntimeError> {
        let rejected = VerifiedRejectedBridgeBlobCarrier::from_provider(
            pending.object_id,
            pending.source_envelope_id,
            pending.exact_bytes.clone(),
        )
        .map_err(store_error)?;
        self.node_mut()
            .store_mut()
            .discard_rejected_pending_bridge_blob_carrier(&rejected)
            .map_err(store_error)?;
        Ok(())
    }

    fn bridge_dependencies_for_source(
        &self,
        origin_envelope_id: &[u8; 32],
    ) -> Result<Vec<ObjectId>, BlobRuntimeError> {
        let mut dependencies = BTreeSet::new();
        let mut after = None;
        loop {
            let page = self
                .node()
                .store()
                .pending_bridge_wrappers_after(after, RESTART_PAGE)
                .map_err(store_error)?;
            for pending in &page {
                if &pending.route.origin_envelope_id == origin_envelope_id {
                    dependencies.extend(
                        self.node()
                            .store()
                            .missing_bridge_dependencies(&pending.wrapper_envelope_id, 9)
                            .map_err(store_error)?
                            .into_iter()
                            .filter(|value| value.digest() != origin_envelope_id),
                    );
                }
            }
            after = page.last().map(|value| value.inserted_order);
            if page.len() < RESTART_PAGE {
                break;
            }
        }
        Ok(dependencies.into_iter().collect())
    }

    fn source_has_bridge_reference(
        &self,
        origin_envelope_id: &[u8; 32],
    ) -> Result<bool, BlobRuntimeError> {
        Ok(!self
            .pending_and_committed_wrappers_for_source(origin_envelope_id)?
            .is_empty())
    }

    fn bridge_durable_dependencies(&self, limit: usize) -> Result<Vec<ObjectId>, BlobRuntimeError> {
        if limit == 0 {
            return Ok(Vec::new());
        }
        let mut dependencies = BTreeSet::new();
        let mut batch_after = None;
        while dependencies.len() < limit {
            let page = self
                .node()
                .store()
                .stored_pending_batch_items_after(batch_after, RESTART_PAGE)
                .map_err(store_error)?;
            if page.is_empty() {
                break;
            }
            for pending in &page {
                if self
                    .node()
                    .store()
                    .stored_batch_proof(&pending.proof_envelope_id)
                    .map_err(store_error)?
                    .is_none()
                    && !self
                        .node()
                        .store()
                        .is_batch_proof_rejected(&pending.proof_envelope_id)
                        .map_err(store_error)?
                {
                    dependencies.insert(ObjectId::new(
                        ObjectKind::SourceBatchProof,
                        pending.proof_envelope_id,
                    ));
                    if dependencies.len() == limit {
                        break;
                    }
                }
            }
            batch_after = page.last().map(|value| value.inserted_order);
            if page.len() < RESTART_PAGE {
                break;
            }
        }
        let mut after = None;
        while dependencies.len() < limit {
            let page = self
                .node()
                .store()
                .pending_bridge_wrappers_after(after, RESTART_PAGE)
                .map_err(store_error)?;
            if page.is_empty() {
                break;
            }
            for pending in &page {
                for dependency in self
                    .node()
                    .store()
                    .missing_bridge_dependencies(
                        &pending.wrapper_envelope_id,
                        limit.saturating_sub(dependencies.len()),
                    )
                    .map_err(store_error)?
                {
                    dependencies.insert(dependency);
                    if dependencies.len() == limit {
                        break;
                    }
                }
            }
            after = page.last().map(|value| value.inserted_order);
            if page.len() < RESTART_PAGE {
                break;
            }
        }
        let mut after = None;
        while dependencies.len() < limit {
            let page = self
                .node()
                .store()
                .pending_bridge_blob_carriers_after(after, RESTART_PAGE)
                .map_err(store_error)?;
            if page.is_empty() {
                break;
            }
            for pending in &page {
                dependencies.insert(ObjectId::new(
                    ObjectKind::SourceEnvelope,
                    pending.source_envelope_id,
                ));
                if dependencies.len() == limit {
                    break;
                }
            }
            after = page.last().map(|value| value.inserted_order);
            if page.len() < RESTART_PAGE {
                break;
            }
        }
        let mut cursor = None;
        while dependencies.len() < limit {
            let page = self
                .node()
                .store()
                .stored_bridge_authorizations_after(cursor, RESTART_PAGE)
                .map_err(store_error)?;
            if page.is_empty() {
                break;
            }
            for authorization in &page {
                if authorization.applied {
                    continue;
                }
                if let Some(previous) = authorization.authorization.previous_control_id
                    && self
                        .node()
                        .store()
                        .stored_bridge_authorization(&previous)
                        .map_err(store_error)?
                        .is_none()
                {
                    dependencies.insert(ObjectId::new(ObjectKind::BridgeAuthorization, previous));
                    if dependencies.len() == limit {
                        break;
                    }
                }
            }
            let last = page.last().expect("nonempty page");
            cursor = Some(BridgeAuthorizationCursor {
                authority_id: last.authorization.authority_id,
                sequence: last.authorization.control_sequence,
            });
            if page.len() < RESTART_PAGE {
                break;
            }
        }
        Ok(dependencies.into_iter().collect())
    }

    fn batch_item_is_eligible(
        &mut self,
        authenticated_peer: NodeId,
        peer_route_commitments: &[[u8; 32]],
        filter: &InterestFilter,
        purpose: InventoryPurpose,
        item: &StoredItem,
    ) -> Result<bool, BlobRuntimeError> {
        let minimum = Priority::from_wire(filter.min_priority)
            .ok_or_else(|| missing("interest priority is unknown"))?;
        let sample = self.node().custody_sample();
        let publisher_revoked = self
            .node_mut()
            .store_mut()
            .is_revoked(&item.publisher())
            .map_err(store_error)?;
        let current_epoch = self
            .node_mut()
            .store_mut()
            .scope_epoch(&item.scope)
            .map_err(store_error)?;
        if !filter
            .topics
            .iter()
            .any(|topic| topic == item.topic.as_str())
            || !filter
                .scopes
                .iter()
                .any(|scope| scope == item.scope.as_str())
            || item.priority < minimum
            || !item.is_forwardable_at(sample)
            || publisher_revoked
            || item.key_epoch < current_epoch
        {
            return Ok(false);
        }
        if purpose == InventoryPurpose::ServePeer
            && (!self.node().emission_policy().allows(item.priority)
                || !self.node().envelopes().peer_can_route(
                    authenticated_peer,
                    peer_route_commitments,
                    &item.scope,
                    item.key_epoch,
                ))
        {
            return Ok(false);
        }
        Ok(true)
    }

    fn batch_inventory_candidates(
        &mut self,
        authenticated_peer: NodeId,
        peer_route_commitments: &[[u8; 32]],
        filter: &InterestFilter,
        purpose: InventoryPurpose,
    ) -> Result<Vec<BatchInventoryCandidate>, BlobRuntimeError> {
        let mut candidates = Vec::new();
        let mut after = None;
        loop {
            let page = self
                .node()
                .store()
                .stored_batch_materials_after(after, RESTART_PAGE)
                .map_err(store_error)?;
            if page.is_empty() {
                break;
            }
            for material in &page {
                let Some(item) = self
                    .node()
                    .store()
                    .stored_item(&material.item_id)
                    .map_err(store_error)?
                else {
                    return Err(store_error(StoreError::Corrupt(
                        "batch material has no semantic item".into(),
                    )));
                };
                if !self.batch_item_is_eligible(
                    authenticated_peer,
                    peer_route_commitments,
                    filter,
                    purpose,
                    &item,
                )? {
                    continue;
                }
                let Some(compact) = self
                    .node()
                    .store()
                    .stored_item_representation(&material.item_id, wire::SEMANTIC_PROTOCOL_V2)
                    .map_err(store_error)?
                else {
                    continue;
                };
                if compact.envelope_id != material.compact_envelope_id
                    || compact.proof_envelope_id != Some(material.proof.proof_envelope_id)
                    || compact.exact_bytes != material.compact_bytes
                {
                    return Err(store_error(StoreError::Corrupt(
                        "selected compact representation differs from batch material".into(),
                    )));
                }
                candidates.push(BatchInventoryCandidate {
                    material: material.clone(),
                    item,
                    compact,
                });
                if candidates.len() > MAX_SEMANTIC_INVENTORY_OBJECTS {
                    return Err(missing("batch inventory exceeds bound"));
                }
            }
            after = page.last().map(|material| material.inserted_order);
            if page.len() < RESTART_PAGE {
                break;
            }
        }
        Ok(candidates)
    }

    fn add_batch_blob_inventory(
        &mut self,
        ids: &mut BTreeSet<ObjectId>,
        authenticated_peer: NodeId,
        peer_route_commitments: &[[u8; 32]],
        filter: &InterestFilter,
        item_id: ItemId,
        record_grant: bool,
    ) -> Result<(), BlobRuntimeError> {
        let Some(live) = self.live_batch_material(item_id)? else {
            return Ok(());
        };
        let envelope = live.verified.verified_envelope();
        let Some(commitment) = envelope.header.blob_route else {
            return Ok(());
        };
        let route = AuthenticatedBlobRoute::new(
            EnvelopeId::from_bytes(live.material.compact_envelope_id),
            commitment,
        );
        let remaining = MAX_SEMANTIC_INVENTORY_OBJECTS
            .saturating_sub(ids.len())
            .min(usize::try_from(self.blobs().config().max_chunks).unwrap_or(usize::MAX));
        for object_id in self.blobs_mut().object_ids_for_route(route, remaining)? {
            insert_semantic_inventory_id(ids, object_id)?;
            if record_grant {
                self.batch_inventory_grants.insert(
                    object_id,
                    BatchInventoryGrant {
                        peer: authenticated_peer,
                        peer_route_commitments: peer_route_commitments.to_vec(),
                        filter: filter.clone(),
                        effective_priority: live.item.priority,
                        role: BatchInventoryRole::Blob { item_id, route },
                    },
                );
            }
        }
        Ok(())
    }

    fn select_semantic_v1_inventory(
        &mut self,
        authenticated_peer: NodeId,
        peer_route_commitments: &[[u8; 32]],
        filter: &InterestFilter,
        purpose: InventoryPurpose,
        semantic_version: u16,
    ) -> Result<SparseInventory, BlobRuntimeError> {
        let ordinary = self
            .inner
            .select_authorized_inventory_for_semantic_version(
                authenticated_peer,
                peer_route_commitments,
                filter,
                purpose,
                semantic_version,
            )?;
        let mut ids = ordinary
            .ids_under(
                &crate::inventory::NibblePrefix::root(),
                MAX_SEMANTIC_INVENTORY_OBJECTS.saturating_add(1),
            )
            .into_iter()
            .collect::<BTreeSet<_>>();
        if ids.len() > MAX_SEMANTIC_INVENTORY_OBJECTS {
            return Err(missing("semantic-v1 inventory exceeds bound"));
        }
        if purpose == InventoryPurpose::ServePeer {
            self.batch_inventory_grants.clear();
        }
        let mut compact_sources = BTreeSet::new();
        let mut after = None;
        loop {
            let page = self
                .node()
                .store()
                .stored_batch_materials_after(after, RESTART_PAGE)
                .map_err(store_error)?;
            if page.is_empty() {
                break;
            }
            for material in &page {
                let compact = EnvelopeId::from_bytes(material.compact_envelope_id);
                compact_sources.insert(compact);
                ids.remove(&ObjectId::for_envelope(compact));
                if purpose == InventoryPurpose::ServePeer
                    && let Some(singleton) = material.singleton_envelope_id
                {
                    let object_id = ObjectId::new(ObjectKind::SourceEnvelope, singleton);
                    if ids.contains(&object_id) {
                        let item = self
                            .node()
                            .store()
                            .stored_item(&material.item_id)
                            .map_err(store_error)?
                            .ok_or_else(|| {
                                store_error(StoreError::Corrupt(
                                    "retained singleton has no semantic item".into(),
                                ))
                            })?;
                        self.batch_inventory_grants.insert(
                            object_id,
                            BatchInventoryGrant {
                                peer: authenticated_peer,
                                peer_route_commitments: peer_route_commitments.to_vec(),
                                filter: filter.clone(),
                                effective_priority: item.priority,
                                role: BatchInventoryRole::Singleton {
                                    item_id: material.item_id,
                                    envelope_id: singleton,
                                },
                            },
                        );
                    }
                }
            }
            after = page.last().map(|material| material.inserted_order);
            if page.len() < RESTART_PAGE {
                break;
            }
        }
        if purpose == InventoryPurpose::ServePeer {
            for object_id in self
                .inner
                .discard_serve_routes_for_sources(&compact_sources)
            {
                ids.remove(&object_id);
            }
        }
        Ok(SparseInventory::from_ids(ids))
    }

    fn select_semantic_v2_inventory(
        &mut self,
        authenticated_peer: NodeId,
        peer_route_commitments: &[[u8; 32]],
        filter: &InterestFilter,
        purpose: InventoryPurpose,
    ) -> Result<SparseInventory, BlobRuntimeError> {
        self.ensure_bridge_contact_authorized(authenticated_peer)?;
        let ordinary = self
            .inner
            .select_authorized_inventory_for_semantic_version(
                authenticated_peer,
                peer_route_commitments,
                filter,
                purpose,
                wire::SEMANTIC_PROTOCOL_V2,
            )?;
        let mut ids = ordinary
            .ids_under(
                &crate::inventory::NibblePrefix::root(),
                MAX_SEMANTIC_INVENTORY_OBJECTS.saturating_add(1),
            )
            .into_iter()
            .collect::<BTreeSet<_>>();
        if ids.len() > MAX_SEMANTIC_INVENTORY_OBJECTS {
            return Err(missing("composite semantic inventory exceeds bound"));
        }
        if purpose == InventoryPurpose::ServePeer {
            self.batch_inventory_grants.clear();
            self.bridge_inventory_grants.clear();
        }

        // The ordinary backend indexes the canonical source representation.
        // Replace both exact batch representations before hashing inventory so
        // semantic version 2 prefers compact bytes and never advertises the
        // retained singleton or its source-bound Blob carriers by accident.
        let mut all_materials = Vec::new();
        let mut material_after = None;
        loop {
            let page = self
                .node()
                .store()
                .stored_batch_materials_after(material_after, RESTART_PAGE)
                .map_err(store_error)?;
            if page.is_empty() {
                break;
            }
            all_materials.extend(page.iter().cloned());
            if all_materials.len() > MAX_SEMANTIC_INVENTORY_OBJECTS {
                return Err(missing("batch inventory exceeds bound"));
            }
            material_after = page.last().map(|material| material.inserted_order);
            if page.len() < RESTART_PAGE {
                break;
            }
        }
        let mut batch_sources = BTreeSet::new();
        for material in &all_materials {
            let compact = EnvelopeId::from_bytes(material.compact_envelope_id);
            batch_sources.insert(compact);
            ids.remove(&ObjectId::for_envelope(compact));
            if let Some(singleton_id) = material.singleton_envelope_id {
                let singleton = EnvelopeId::from_bytes(singleton_id);
                batch_sources.insert(singleton);
                ids.remove(&ObjectId::for_envelope(singleton));
                let limit = usize::try_from(self.blobs().config().max_chunks)
                    .unwrap_or(usize::MAX)
                    .min(MAX_SEMANTIC_INVENTORY_OBJECTS);
                for object_id in self.inner.blob_object_ids_for_source(singleton, limit)? {
                    ids.remove(&object_id);
                }
            }
        }
        if purpose == InventoryPurpose::ServePeer {
            for object_id in self.inner.discard_serve_routes_for_sources(&batch_sources) {
                ids.remove(&object_id);
            }
        }

        let candidates = self.batch_inventory_candidates(
            authenticated_peer,
            peer_route_commitments,
            filter,
            purpose,
        )?;
        if purpose == InventoryPurpose::ReceiveBaseline {
            for candidate in &candidates {
                insert_semantic_inventory_id(
                    &mut ids,
                    ObjectId::new(
                        ObjectKind::SourceBatchProof,
                        candidate.material.proof.proof_envelope_id,
                    ),
                )?;
                insert_semantic_inventory_id(
                    &mut ids,
                    ObjectId::new(ObjectKind::SourceEnvelope, candidate.compact.envelope_id),
                )?;
                self.add_batch_blob_inventory(
                    &mut ids,
                    authenticated_peer,
                    peer_route_commitments,
                    filter,
                    candidate.item.id,
                    false,
                )?;
            }
        } else {
            let mut proof_anchors = BTreeMap::<[u8; 32], (ItemId, Priority)>::new();
            for candidate in &candidates {
                proof_anchors
                    .entry(candidate.material.proof.proof_envelope_id)
                    .and_modify(|(_, priority)| {
                        *priority = (*priority).max(candidate.item.priority)
                    })
                    .or_insert((candidate.item.id, candidate.item.priority));
            }
            let proof_candidates = proof_anchors.keys().copied().collect::<Vec<_>>();
            for chunk in proof_candidates.chunks(RESTART_PAGE) {
                for proof_id in self
                    .node()
                    .store()
                    .filter_unacknowledged_batch_proofs(authenticated_peer, chunk, chunk.len())
                    .map_err(store_error)?
                {
                    let (anchor_item_id, priority) = proof_anchors[&proof_id];
                    let object_id = ObjectId::new(ObjectKind::SourceBatchProof, proof_id);
                    insert_semantic_inventory_id(&mut ids, object_id)?;
                    self.batch_inventory_grants.insert(
                        object_id,
                        BatchInventoryGrant {
                            peer: authenticated_peer,
                            peer_route_commitments: peer_route_commitments.to_vec(),
                            filter: filter.clone(),
                            effective_priority: priority,
                            role: BatchInventoryRole::Proof {
                                proof_envelope_id: proof_id,
                                anchor_item_id,
                            },
                        },
                    );
                }
            }

            let compact_candidates = candidates
                .iter()
                .map(|candidate| candidate.item.id)
                .collect::<Vec<_>>();
            let by_item = candidates
                .iter()
                .map(|candidate| (candidate.item.id, candidate))
                .collect::<BTreeMap<_, _>>();
            for chunk in compact_candidates.chunks(RESTART_PAGE) {
                for item_id in self
                    .node()
                    .store()
                    .filter_unacknowledged_batch_compacts(authenticated_peer, chunk, chunk.len())
                    .map_err(store_error)?
                {
                    let candidate = by_item[&item_id];
                    let object_id =
                        ObjectId::new(ObjectKind::SourceEnvelope, candidate.compact.envelope_id);
                    insert_semantic_inventory_id(&mut ids, object_id)?;
                    self.batch_inventory_grants.insert(
                        object_id,
                        BatchInventoryGrant {
                            peer: authenticated_peer,
                            peer_route_commitments: peer_route_commitments.to_vec(),
                            filter: filter.clone(),
                            effective_priority: candidate.item.priority,
                            role: BatchInventoryRole::Compact {
                                item_id,
                                envelope_id: candidate.compact.envelope_id,
                            },
                        },
                    );
                }
                for item_id in self
                    .node()
                    .store()
                    .filter_batch_blob_ready(authenticated_peer, chunk, chunk.len())
                    .map_err(store_error)?
                {
                    self.add_batch_blob_inventory(
                        &mut ids,
                        authenticated_peer,
                        peer_route_commitments,
                        filter,
                        item_id,
                        true,
                    )?;
                }
            }
        }
        let sample = self.node().custody_sample();
        let mut after = None;
        loop {
            let page = self
                .node()
                .store()
                .stored_bridge_routes_after(after, RESTART_PAGE)
                .map_err(store_error)?;
            if page.is_empty() {
                break;
            }
            for route in &page {
                if !route.active
                    || !self
                        .node()
                        .store()
                        .bridge_route_is_live_at(&route.wrapper_envelope_id, sample)
                        .map_err(store_error)?
                    || !bridge_route_matches_filter(route, filter)
                    || (purpose == InventoryPurpose::ServePeer
                        && (!self.node().emission_policy().allows(route.priority)
                            || !self.node().envelopes().peer_can_route(
                                authenticated_peer,
                                peer_route_commitments,
                                &route.current_scope,
                                route.current_route_epoch,
                            )
                            || bridge_forwarding_age(route, sample).is_none()))
                {
                    continue;
                }
                let wrapper = self
                    .node()
                    .envelopes()
                    .open_bridge_wrapper_for_any_local_route(&route.exact_wrapper_bytes)
                    .map_err(envelope_error)?;
                if purpose == InventoryPurpose::ServePeer
                    && !self.local_bridge_route_allows(&wrapper, route)?
                {
                    continue;
                }
                let grant = BridgeInventoryGrant {
                    wrapper_envelope_id: route.wrapper_envelope_id,
                    current_scope: route.current_scope.clone(),
                    current_route_epoch: route.current_route_epoch,
                    peer: authenticated_peer,
                    filter: filter.clone(),
                };
                let authorization_ids = self.bridge_authorization_chain_ids(&wrapper)?;
                let mut blob_ids = Vec::new();
                if let Some(source) = self
                    .node()
                    .store()
                    .stored_bridge_source(&route.origin_envelope_id)
                    .map_err(store_error)?
                    && let Some(blob) = source.metadata.blob_route
                {
                    let blob_route = authenticated_blob_route(route.origin_envelope_id, &blob);
                    let remaining = MAX_SEMANTIC_INVENTORY_OBJECTS
                        .saturating_sub(ids.len())
                        .min(
                            usize::try_from(self.blobs().config().max_chunks).unwrap_or(usize::MAX),
                        );
                    blob_ids = self
                        .blobs_mut()
                        .object_ids_for_route(blob_route, remaining)?;
                }
                let mut route_ids = Vec::new();
                if purpose == InventoryPurpose::ServePeer {
                    let wrapper_ids = self
                        .node()
                        .store()
                        .filter_unacknowledged_bridge_routes(
                            authenticated_peer,
                            &[route.wrapper_envelope_id],
                            1,
                        )
                        .map_err(store_error)?;
                    route_ids.extend(
                        wrapper_ids
                            .into_iter()
                            .map(|id| ObjectId::new(ObjectKind::BridgeRouteWrapper, id)),
                    );

                    let source_ids = self
                        .node()
                        .store()
                        .filter_unacknowledged_bridge_sources_for_path(
                            authenticated_peer,
                            route.wrapper_envelope_id,
                            &[route.origin_envelope_id],
                            1,
                        )
                        .map_err(store_error)?;
                    route_ids.extend(
                        source_ids
                            .into_iter()
                            .map(|id| ObjectId::new(ObjectKind::SourceEnvelope, id)),
                    );

                    for candidates in authorization_ids.chunks(RESTART_PAGE) {
                        let envelope_ids =
                            candidates.iter().map(|id| *id.digest()).collect::<Vec<_>>();
                        let selected = self
                            .node()
                            .store()
                            .filter_unacknowledged_bridge_authorizations(
                                authenticated_peer,
                                &envelope_ids,
                                candidates.len(),
                            )
                            .map_err(store_error)?;
                        route_ids.extend(
                            selected
                                .into_iter()
                                .map(|id| ObjectId::new(ObjectKind::BridgeAuthorization, id)),
                        );
                    }
                    for candidates in blob_ids.chunks(RESTART_PAGE) {
                        route_ids.extend(
                            self.node()
                                .store()
                                .filter_unacknowledged_bridge_blob_carriers(
                                    authenticated_peer,
                                    route.wrapper_envelope_id,
                                    route.origin_envelope_id,
                                    candidates,
                                    candidates.len(),
                                    sample,
                                )
                                .map_err(store_error)?,
                        );
                    }
                } else {
                    route_ids.push(ObjectId::new(
                        ObjectKind::BridgeRouteWrapper,
                        route.wrapper_envelope_id,
                    ));
                    route_ids.push(ObjectId::new(
                        ObjectKind::SourceEnvelope,
                        route.origin_envelope_id,
                    ));
                    route_ids.extend(authorization_ids);
                    route_ids.extend(blob_ids);
                }
                for object_id in route_ids {
                    if ids.len() == MAX_SEMANTIC_INVENTORY_OBJECTS && !ids.contains(&object_id) {
                        return Err(missing("composite semantic inventory exceeds bound"));
                    }
                    ids.insert(object_id);
                    if purpose == InventoryPurpose::ServePeer {
                        self.bridge_inventory_grants
                            .entry(object_id)
                            .or_insert_with(|| grant.clone());
                    }
                }
            }
            after = page.last().map(|value| value.inserted_order);
            if page.len() < RESTART_PAGE {
                break;
            }
        }
        Ok(SparseInventory::from_ids(ids))
    }

    fn validate_batch_grant(
        &mut self,
        authenticated_peer: NodeId,
        peer_route_commitments: &[[u8; 32]],
        grant: &BatchInventoryGrant,
    ) -> Result<ValidatedBatchGrant, BlobRuntimeError> {
        if grant.peer != authenticated_peer {
            return Err(missing("batch inventory peer binding mismatch"));
        }
        let item_id = match grant.role {
            BatchInventoryRole::Proof { anchor_item_id, .. }
            | BatchInventoryRole::Compact {
                item_id: anchor_item_id,
                ..
            }
            | BatchInventoryRole::Singleton {
                item_id: anchor_item_id,
                ..
            }
            | BatchInventoryRole::Blob {
                item_id: anchor_item_id,
                ..
            } => anchor_item_id,
        };
        if matches!(grant.role, BatchInventoryRole::Singleton { .. }) {
            let Some(item) = self
                .node()
                .store()
                .stored_item(&item_id)
                .map_err(store_error)?
            else {
                return Err(missing("retained singleton item disappeared"));
            };
            if !self.batch_item_is_eligible(
                authenticated_peer,
                peer_route_commitments,
                &grant.filter,
                InventoryPurpose::ServePeer,
                &item,
            )? {
                return Err(missing("retained singleton grant is no longer live"));
            }
            let Some(representation) = self
                .node()
                .store()
                .stored_item_representation(&item_id, wire::SEMANTIC_PROTOCOL_V1)
                .map_err(store_error)?
            else {
                return Err(missing("retained singleton representation disappeared"));
            };
            let BatchInventoryRole::Singleton { envelope_id, .. } = grant.role else {
                unreachable!();
            };
            if representation.envelope_id != envelope_id
                || representation.proof_envelope_id.is_some()
            {
                return Err(missing("retained singleton representation changed"));
            }
            return Ok(ValidatedBatchGrant::Singleton(representation));
        }

        let Some(live) = self.live_batch_material(item_id)? else {
            return Err(missing("batch material is no longer live"));
        };
        if !self.batch_item_is_eligible(
            authenticated_peer,
            peer_route_commitments,
            &grant.filter,
            InventoryPurpose::ServePeer,
            &live.item,
        )? {
            return Err(missing("batch inventory grant is no longer live"));
        }
        match grant.role {
            BatchInventoryRole::Proof {
                proof_envelope_id, ..
            } if live.material.proof.proof_envelope_id == proof_envelope_id => {}
            BatchInventoryRole::Compact { envelope_id, .. }
                if live.material.compact_envelope_id == envelope_id => {}
            BatchInventoryRole::Blob { route, .. } => {
                let envelope = live.verified.verified_envelope();
                if envelope.header.blob_route != Some(route.commitment())
                    || route.source_envelope()
                        != EnvelopeId::from_bytes(live.material.compact_envelope_id)
                {
                    return Err(missing("batch Blob route changed after inventory"));
                }
            }
            _ => return Err(missing("batch representation changed after inventory")),
        }
        Ok(ValidatedBatchGrant::Extended(Box::new(live)))
    }

    fn serve_batch_want(
        &mut self,
        authenticated_peer: NodeId,
        peer_route_commitments: &[[u8; 32]],
        exchange_id: u64,
        semantic_version: u16,
        want: &WantItem,
    ) -> Result<Vec<Data>, BlobRuntimeError> {
        self.ensure_bridge_contact_authorized(authenticated_peer)?;
        let grant = self
            .batch_inventory_grants
            .get(&want.object_id)
            .cloned()
            .ok_or_else(|| missing("batch object was not in served inventory"))?;

        if let BatchInventoryRole::Singleton {
            item_id: _,
            envelope_id,
        } = grant.role
        {
            if semantic_version != wire::SEMANTIC_PROTOCOL_V1 {
                return Err(missing("batch singleton grant used on the wrong version"));
            }
            let ValidatedBatchGrant::Singleton(representation) =
                self.validate_batch_grant(authenticated_peer, peer_route_commitments, &grant)?
            else {
                return Err(missing("singleton validation returned compact material"));
            };
            let data = self.inner.data_for_want_for_semantic_version(
                authenticated_peer,
                peer_route_commitments,
                exchange_id,
                semantic_version,
                want,
            )?;
            if !data.is_empty() {
                if representation.envelope_id != envelope_id {
                    return Err(missing("served singleton identity changed"));
                }
                self.remember_batch_serve(
                    authenticated_peer,
                    exchange_id,
                    want.object_id,
                    grant,
                    representation.exact_bytes.len() as u64,
                );
            }
            return Ok(data);
        }

        if semantic_version < wire::SEMANTIC_PROTOCOL_V2 {
            return Err(missing("semantic-v2 batch object reached version 1"));
        }
        let ValidatedBatchGrant::Extended(live) =
            self.validate_batch_grant(authenticated_peer, peer_route_commitments, &grant)?
        else {
            return Err(missing("compact validation returned a singleton"));
        };
        let sample = self.node().custody_sample();
        let (total_len, forwarding) = match grant.role {
            BatchInventoryRole::Proof { .. } => {
                if !want.need_forwarding {
                    return Err(missing("batch proof omitted forwarding metadata"));
                }
                let forwarding = self
                    .node_mut()
                    .envelopes_mut()
                    .seal_forwarding(authenticated_peer, exchange_id, *want.object_id.digest(), 0)
                    .map_err(envelope_error)?;
                (live.material.proof.exact_bytes.len() as u64, forwarding)
            }
            BatchInventoryRole::Compact { .. } => {
                if !want.need_forwarding {
                    return Err(missing("compact batch item omitted forwarding metadata"));
                }
                let age = conservative_item_custody_age(&live.item, sample);
                if age == u64::MAX && !live.item.tombstone {
                    return Err(missing("compact batch custody continuity is unavailable"));
                }
                let forwarding = self
                    .node_mut()
                    .envelopes_mut()
                    .seal_forwarding(
                        authenticated_peer,
                        exchange_id,
                        *want.object_id.digest(),
                        age,
                    )
                    .map_err(envelope_error)?;
                (live.material.compact_bytes.len() as u64, forwarding)
            }
            BatchInventoryRole::Blob { route, .. } => {
                if want.need_forwarding {
                    return Err(missing("batch Blob requested forwarding metadata"));
                }
                let (total_len, _) =
                    self.blobs_mut()
                        .read_object_range(route, want.object_id, 0, 1)?;
                (total_len, Vec::new())
            }
            BatchInventoryRole::Singleton { .. } => unreachable!(),
        };
        if want.total_len.is_some_and(|expected| expected != total_len) {
            return Err(missing("wanted batch object length changed"));
        }
        let requested = if want.missing.is_empty() {
            if want.total_len.is_some() {
                Vec::new()
            } else {
                vec![ByteRange {
                    start: 0,
                    end: total_len,
                }]
            }
        } else {
            want.missing.clone()
        };
        let mut data = Vec::new();
        for requested_range in requested {
            if requested_range.start >= requested_range.end || requested_range.end > total_len {
                return Err(missing("batch WANT range is invalid"));
            }
            let mut offset = requested_range.start;
            while offset < requested_range.end && data.len() < MAX_DATA_MESSAGES_PER_WANT {
                let budget = usize::try_from(requested_range.end - offset)
                    .unwrap_or(usize::MAX)
                    .min(MAX_DATA_PAYLOAD_BYTES);
                let range = crate::store::ChunkRange {
                    start: offset,
                    end: offset.saturating_add(budget as u64),
                };
                let payload = match grant.role {
                    BatchInventoryRole::Proof {
                        proof_envelope_id, ..
                    } => self
                        .node()
                        .store()
                        .read_batch_proof_range(&proof_envelope_id, range, budget)
                        .map_err(store_error)?,
                    BatchInventoryRole::Compact { item_id, .. } => self
                        .node()
                        .store()
                        .read_batch_compact_range(&item_id, range, budget, sample)
                        .map_err(store_error)?,
                    BatchInventoryRole::Blob { route, .. } => {
                        self.blobs_mut()
                            .read_object_range(route, want.object_id, offset, budget)?
                            .1
                    }
                    BatchInventoryRole::Singleton { .. } => unreachable!(),
                };
                if payload.is_empty() {
                    break;
                }
                let payload_len = payload.len() as u64;
                data.push(Data {
                    exchange_id,
                    object_id: want.object_id,
                    total_len,
                    offset,
                    payload,
                    forwarding: if data.is_empty() {
                        forwarding.clone()
                    } else {
                        Vec::new()
                    },
                });
                offset = offset.saturating_add(payload_len);
            }
            if data.len() == MAX_DATA_MESSAGES_PER_WANT {
                break;
            }
        }
        if data.is_empty() && !forwarding.is_empty() {
            data.push(Data {
                exchange_id,
                object_id: want.object_id,
                total_len,
                offset: 0,
                payload: Vec::new(),
                forwarding,
            });
        }
        if !data.is_empty() {
            let now_ms = self.node().now_ms();
            match grant.role {
                BatchInventoryRole::Proof { .. } => self
                    .node_mut()
                    .store_mut()
                    .record_batch_proof_attempts(
                        authenticated_peer,
                        std::slice::from_ref(&live.material.proof),
                        now_ms,
                    )
                    .map_err(store_error)?,
                BatchInventoryRole::Compact { item_id, .. } => {
                    let representation = self
                        .node()
                        .store()
                        .stored_item_representation(&item_id, wire::SEMANTIC_PROTOCOL_V2)
                        .map_err(store_error)?
                        .ok_or_else(|| missing("served compact representation disappeared"))?;
                    self.node_mut()
                        .store_mut()
                        .record_batch_compact_attempts(
                            authenticated_peer,
                            &[representation],
                            now_ms,
                        )
                        .map_err(store_error)?;
                }
                BatchInventoryRole::Blob { .. } => {}
                BatchInventoryRole::Singleton { .. } => unreachable!(),
            }
            self.remember_batch_serve(
                authenticated_peer,
                exchange_id,
                want.object_id,
                grant,
                total_len,
            );
        }
        Ok(data)
    }

    fn remember_batch_serve(
        &mut self,
        authenticated_peer: NodeId,
        exchange_id: u64,
        object_id: ObjectId,
        grant: BatchInventoryGrant,
        total_len: u64,
    ) {
        let key = (authenticated_peer, exchange_id, object_id);
        if self.batch_served.len() >= MAX_SEMANTIC_INVENTORY_OBJECTS
            && !self.batch_served.contains_key(&key)
        {
            self.batch_served.pop_first();
        }
        self.batch_served
            .insert(key, ServedBatchObject { grant, total_len });
    }

    fn acknowledge_batch_receipt(
        &mut self,
        authenticated_peer: NodeId,
        semantic_version: u16,
        receipt: &wire::Receipt,
    ) -> Result<(), BlobRuntimeError> {
        self.ensure_bridge_contact_authorized(authenticated_peer)?;
        let key = (authenticated_peer, receipt.exchange_id, receipt.object_id);
        let served = self
            .batch_served
            .remove(&key)
            .ok_or_else(|| missing("batch receipt has no served object"))?;
        if served.total_len != receipt.total_len || served.grant.peer != authenticated_peer {
            return Err(missing("batch receipt does not match the served object"));
        }
        if matches!(served.grant.role, BatchInventoryRole::Singleton { .. }) {
            if semantic_version != wire::SEMANTIC_PROTOCOL_V1 {
                return Err(missing("singleton receipt used on the wrong version"));
            }
        } else if semantic_version < wire::SEMANTIC_PROTOCOL_V2 {
            return Err(missing("semantic-v2 batch receipt reached version 1"));
        }
        let route_commitments = served.grant.peer_route_commitments.clone();
        let validated =
            self.validate_batch_grant(authenticated_peer, &route_commitments, &served.grant)?;
        if matches!(served.grant.role, BatchInventoryRole::Singleton { .. })
            != matches!(validated, ValidatedBatchGrant::Singleton(_))
        {
            return Err(missing("batch receipt representation class changed"));
        }
        let now_ms = self.node().now_ms();
        match served.grant.role {
            BatchInventoryRole::Proof {
                proof_envelope_id, ..
            } => self
                .node_mut()
                .store_mut()
                .acknowledge_batch_proof_peer(authenticated_peer, &[proof_envelope_id], now_ms)
                .map_err(store_error)?,
            BatchInventoryRole::Compact { item_id, .. } => self
                .node_mut()
                .store_mut()
                .acknowledge_batch_compact_peer(authenticated_peer, &[item_id], now_ms)
                .map_err(store_error)?,
            BatchInventoryRole::Singleton { item_id, .. } => {
                self.node_mut()
                    .acknowledge_peer(authenticated_peer, &[item_id])?;
            }
            BatchInventoryRole::Blob { .. } => {}
        }
        Ok(())
    }

    fn serve_bridge_want(
        &mut self,
        authenticated_peer: NodeId,
        peer_route_commitments: &[[u8; 32]],
        exchange_id: u64,
        want: &WantItem,
    ) -> Result<Vec<Data>, BlobRuntimeError> {
        self.ensure_bridge_contact_authorized(authenticated_peer)?;
        let grant = self
            .bridge_inventory_grants
            .get(&want.object_id)
            .cloned()
            .ok_or_else(|| missing("bridge object was not in served inventory"))?;
        if grant.peer != authenticated_peer {
            return Err(missing("bridge inventory peer binding mismatch"));
        }
        let sample = self.node().custody_sample();
        let route = self
            .node()
            .store()
            .stored_bridge_route(&grant.wrapper_envelope_id)
            .map_err(store_error)?
            .ok_or_else(|| missing("bridge served route is missing"))?;
        let wrapper = self
            .node()
            .envelopes()
            .open_bridge_wrapper_for_any_local_route(&route.exact_wrapper_bytes)
            .map_err(envelope_error)?;
        if !route.active
            || route.current_scope != grant.current_scope
            || route.current_route_epoch != grant.current_route_epoch
            || !bridge_route_matches_filter(&route, &grant.filter)
            || !self.node().emission_policy().allows(route.priority)
            || !self.node().envelopes().peer_can_route(
                authenticated_peer,
                peer_route_commitments,
                &route.current_scope,
                route.current_route_epoch,
            )
            || !self
                .node()
                .store()
                .bridge_route_is_live_at(&route.wrapper_envelope_id, sample)
                .map_err(store_error)?
            || !self.local_bridge_route_allows(&wrapper, &route)?
        {
            return Err(missing("bridge route is no longer authorized to serve"));
        }
        let forwarding_age = bridge_forwarding_age(&route, sample)
            .ok_or_else(|| missing("bridge custody continuity is unavailable"))?;
        let (total_len, read_kind) = self.bridge_object_length_and_kind(&route, want.object_id)?;
        if want.total_len.is_some_and(|expected| expected != total_len) {
            return Err(missing("wanted bridge object length changed"));
        }
        let forwarding = match read_kind {
            BridgeReadKind::Authorization => {
                if want.need_forwarding {
                    return Err(missing(
                        "bridge authorization requested forwarding metadata",
                    ));
                }
                Vec::new()
            }
            BridgeReadKind::Wrapper | BridgeReadKind::Source => {
                if !want.need_forwarding {
                    return Err(missing(
                        "bridge object omitted required forwarding metadata",
                    ));
                }
                self.node_mut()
                    .envelopes_mut()
                    .seal_forwarding(
                        authenticated_peer,
                        exchange_id,
                        *want.object_id.digest(),
                        forwarding_age,
                    )
                    .map_err(envelope_error)?
            }
            BridgeReadKind::Blob(_) => {
                if want.need_forwarding {
                    return Err(missing("Blob carrier requested forwarding metadata"));
                }
                Vec::new()
            }
        };
        let requested = if want.missing.is_empty() {
            if want.total_len.is_some() {
                Vec::new()
            } else {
                vec![ByteRange {
                    start: 0,
                    end: total_len,
                }]
            }
        } else {
            want.missing.clone()
        };
        let mut data = Vec::new();
        for requested_range in requested {
            if requested_range.start >= requested_range.end || requested_range.end > total_len {
                return Err(missing("bridge WANT range is invalid"));
            }
            let mut offset = requested_range.start;
            while offset < requested_range.end && data.len() < MAX_DATA_MESSAGES_PER_WANT {
                let budget = usize::try_from(requested_range.end - offset)
                    .unwrap_or(usize::MAX)
                    .min(MAX_DATA_PAYLOAD_BYTES);
                let payload = self.read_bridge_range(
                    &route,
                    want.object_id,
                    &read_kind,
                    offset,
                    budget,
                    sample,
                )?;
                if payload.is_empty() {
                    break;
                }
                let payload_len = u64::try_from(payload.len())
                    .map_err(|_| missing("bridge DATA length overflow"))?;
                data.push(Data {
                    exchange_id,
                    object_id: want.object_id,
                    total_len,
                    offset,
                    payload,
                    forwarding: if data.is_empty() {
                        forwarding.clone()
                    } else {
                        Vec::new()
                    },
                });
                offset = offset.saturating_add(payload_len);
            }
            if data.len() == MAX_DATA_MESSAGES_PER_WANT {
                break;
            }
        }
        if data.is_empty() && !forwarding.is_empty() {
            data.push(Data {
                exchange_id,
                object_id: want.object_id,
                total_len,
                offset: 0,
                payload: Vec::new(),
                forwarding,
            });
        }
        if !data.is_empty() {
            let served_key = (authenticated_peer, exchange_id, want.object_id);
            if self.bridge_served.len() >= MAX_SEMANTIC_INVENTORY_OBJECTS
                && !self.bridge_served.contains_key(&served_key)
            {
                self.bridge_served.pop_first();
            }
            self.bridge_served
                .insert(served_key, ServedBridgeObject { grant, total_len });
        }
        Ok(data)
    }

    fn bridge_object_length_and_kind(
        &mut self,
        route: &StoredBridgeRoute,
        object_id: ObjectId,
    ) -> Result<(u64, BridgeReadKind), BlobRuntimeError> {
        match object_id.kind() {
            ObjectKind::BridgeRouteWrapper if object_id.digest() == &route.wrapper_envelope_id => {
                Ok((
                    route.exact_wrapper_bytes.len() as u64,
                    BridgeReadKind::Wrapper,
                ))
            }
            ObjectKind::SourceEnvelope if object_id.digest() == &route.origin_envelope_id => Ok((
                route.exact_source_bytes.len() as u64,
                BridgeReadKind::Source,
            )),
            ObjectKind::BridgeAuthorization => {
                let wrapper = self
                    .node()
                    .envelopes()
                    .open_bridge_wrapper_for_any_local_route(&route.exact_wrapper_bytes)
                    .map_err(envelope_error)?;
                if !self
                    .bridge_authorization_chain_ids(&wrapper)?
                    .iter()
                    .any(|value| value == &object_id)
                {
                    return Err(missing("authorization is not a route dependency"));
                }
                let authorization = self
                    .node()
                    .store()
                    .stored_bridge_authorization(object_id.digest())
                    .map_err(store_error)?
                    .ok_or_else(|| missing("bridge authorization is missing"))?;
                Ok((
                    authorization.exact_bytes.len() as u64,
                    BridgeReadKind::Authorization,
                ))
            }
            ObjectKind::BlobChunk => {
                let source = self
                    .node()
                    .store()
                    .stored_bridge_source(&route.origin_envelope_id)
                    .map_err(store_error)?
                    .ok_or_else(|| missing("bridge Blob source is missing"))?;
                let blob = source
                    .metadata
                    .blob_route
                    .ok_or_else(|| missing("bridge source is not a Blob"))?;
                let blob_route = authenticated_blob_route(route.origin_envelope_id, &blob);
                let (total_len, _) = self
                    .blobs_mut()
                    .read_object_range(blob_route, object_id, 0, 1)?;
                Ok((total_len, BridgeReadKind::Blob(blob_route)))
            }
            _ => Err(missing(
                "object does not belong to the selected bridge route",
            )),
        }
    }

    fn bridge_authorization_chain_ids(
        &self,
        wrapper: &VerifiedBridgeWrapper,
    ) -> Result<Vec<ObjectId>, BlobRuntimeError> {
        let mut ordered = Vec::new();
        let mut seen = BTreeSet::new();
        for hop in &wrapper.route().hops {
            let mut next = Some(hop.authorization_envelope_id);
            while let Some(envelope_id) = next {
                if !seen.insert(envelope_id) {
                    break;
                }
                if seen.len() > MAX_SEMANTIC_INVENTORY_OBJECTS {
                    return Err(store_error(StoreError::Corrupt(
                        "bridge authorization predecessor chain exceeds bound".into(),
                    )));
                }
                let stored = self
                    .node()
                    .store()
                    .stored_bridge_authorization(&envelope_id)
                    .map_err(store_error)?
                    .ok_or_else(|| missing("bridge authorization predecessor is missing"))?;
                if !stored.applied {
                    return Err(missing("bridge authorization predecessor is not applied"));
                }
                let verified = self
                    .node()
                    .envelopes()
                    .open_bridge_authorization(&stored.exact_bytes)
                    .map_err(envelope_error)?;
                if verified.envelope().envelope_id != envelope_id
                    || verified.envelope().authorization != stored.authorization
                {
                    return Err(store_error(StoreError::Corrupt(
                        "stored bridge authorization normalization mismatch".into(),
                    )));
                }
                ordered.push(ObjectId::new(ObjectKind::BridgeAuthorization, envelope_id));
                next = stored.authorization.previous_control_id;
            }
        }
        ordered.reverse();
        ordered.dedup();
        Ok(ordered)
    }

    fn local_bridge_route_allows(
        &mut self,
        wrapper: &VerifiedBridgeWrapper,
        route: &StoredBridgeRoute,
    ) -> Result<bool, BlobRuntimeError> {
        let terminal = wrapper
            .route()
            .hops
            .last()
            .ok_or_else(|| missing("bridge route has no authorized hop"))?;
        if terminal.to_scope != route.current_scope
            || terminal.to_route_epoch != route.current_route_epoch
        {
            return Err(missing("bridge route endpoint differs from its wrapper"));
        }
        let local_identity = self.node().identity();
        for hop in wrapper
            .route()
            .hops
            .iter()
            .filter(|hop| hop.bridge_node_id == local_identity)
        {
            if !self
                .node_mut()
                .store_mut()
                .bridge_allows(&hop.from_scope, &hop.to_scope, &route.topic, route.priority)
                .map_err(store_error)?
            {
                return Ok(false);
            }
        }
        Ok(true)
    }

    fn read_bridge_range(
        &mut self,
        route: &StoredBridgeRoute,
        object_id: ObjectId,
        kind: &BridgeReadKind,
        offset: u64,
        max_bytes: usize,
        sample: Option<crate::store::CustodySample>,
    ) -> Result<Vec<u8>, BlobRuntimeError> {
        let range = crate::store::ChunkRange {
            start: offset,
            end: offset.saturating_add(max_bytes as u64),
        };
        match kind {
            BridgeReadKind::Authorization => self
                .node()
                .store()
                .read_bridge_authorization_range(object_id.digest(), range, max_bytes)
                .map_err(store_error),
            BridgeReadKind::Wrapper => self
                .node()
                .store()
                .read_bridge_wrapper_range(&route.wrapper_envelope_id, range, max_bytes, sample)
                .map_err(store_error),
            BridgeReadKind::Source => self
                .node()
                .store()
                .read_bridge_source_range(&route.origin_envelope_id, range, max_bytes, sample)
                .map_err(store_error),
            BridgeReadKind::Blob(blob_route) => self
                .blobs_mut()
                .read_object_range(*blob_route, object_id, offset, max_bytes)
                .map(|(_, bytes)| bytes)
                .map_err(Into::into),
        }
    }

    fn acknowledge_bridge_receipt(
        &mut self,
        authenticated_peer: NodeId,
        receipt: &wire::Receipt,
    ) -> Result<(), BlobRuntimeError> {
        self.ensure_bridge_contact_authorized(authenticated_peer)?;
        let key = (authenticated_peer, receipt.exchange_id, receipt.object_id);
        let Some(served) = self.bridge_served.remove(&key) else {
            return self.inner.acknowledge_receipt(
                authenticated_peer,
                wire::SEMANTIC_PROTOCOL_V2,
                receipt,
            );
        };
        if served.total_len != receipt.total_len || served.grant.peer != authenticated_peer {
            return Err(missing("bridge receipt does not match the served object"));
        }
        let sample = self.node().custody_sample();
        let route = self
            .node()
            .store()
            .stored_bridge_route(&served.grant.wrapper_envelope_id)
            .map_err(store_error)?
            .ok_or_else(|| missing("bridge receipt route is missing"))?;
        if !route.active
            || route.current_scope != served.grant.current_scope
            || route.current_route_epoch != served.grant.current_route_epoch
            || !bridge_route_matches_filter(&route, &served.grant.filter)
            || !self.node().emission_policy().allows(route.priority)
            || !self
                .node()
                .store()
                .bridge_route_is_live_at(&route.wrapper_envelope_id, sample)
                .map_err(store_error)?
        {
            return Err(missing("bridge receipt route is no longer live"));
        }
        let now_ms = self.node().now_ms();
        match receipt.object_id.kind() {
            ObjectKind::BridgeRouteWrapper => self
                .node_mut()
                .store_mut()
                .acknowledge_bridge_route_peer(
                    authenticated_peer,
                    &[route.wrapper_envelope_id],
                    now_ms,
                    sample,
                )
                .map_err(store_error)?,
            ObjectKind::SourceEnvelope => self
                .node_mut()
                .store_mut()
                .acknowledge_bridge_source_path_peer(
                    authenticated_peer,
                    route.wrapper_envelope_id,
                    &[route.origin_envelope_id],
                    now_ms,
                    sample,
                )
                .map_err(store_error)?,
            ObjectKind::BridgeAuthorization => self
                .node_mut()
                .store_mut()
                .acknowledge_bridge_authorization_peer(
                    authenticated_peer,
                    &[*receipt.object_id.digest()],
                    now_ms,
                )
                .map_err(store_error)?,
            ObjectKind::BlobChunk => {
                self.node_mut()
                    .store_mut()
                    .acknowledge_bridge_blob_carrier_peer(
                        authenticated_peer,
                        route.wrapper_envelope_id,
                        route.origin_envelope_id,
                        &[receipt.object_id],
                        now_ms,
                        sample,
                    )
                    .map_err(store_error)?;
            }
            ObjectKind::SourceBatchProof => {
                return Err(missing("batch receipt reached bridge acknowledgement"));
            }
        }
        Ok(())
    }
}

#[derive(Clone, Copy)]
enum BridgeReadKind {
    Authorization,
    Wrapper,
    Source,
    Blob(AuthenticatedBlobRoute),
}

impl RuntimeBackend for ReferenceSemanticRuntimeBackend {
    type Error = BlobRuntimeError;

    fn authorize_adjacency(&mut self, authenticated_peer: NodeId) -> Result<(), Self::Error> {
        self.inner.authorize_adjacency(authenticated_peer)
    }

    fn durable_progress(
        &mut self,
        limit: usize,
    ) -> Result<Vec<RuntimeTransferProgress>, Self::Error> {
        self.inner.durable_progress(limit)
    }

    fn durable_progress_for_semantic_version(
        &mut self,
        limit: usize,
        semantic_version: u16,
    ) -> Result<Vec<RuntimeTransferProgress>, Self::Error> {
        let progress = self
            .inner
            .durable_progress_for_semantic_version(limit, semantic_version)?;
        Ok(progress
            .into_iter()
            .filter(|entry| semantic_restart_progress_allowed(entry, semantic_version))
            .collect())
    }

    fn durable_dependencies(&mut self, limit: usize) -> Result<Vec<ObjectId>, Self::Error> {
        self.bridge_durable_dependencies(limit)
    }

    fn durable_dependencies_for_semantic_version(
        &mut self,
        limit: usize,
        semantic_version: u16,
    ) -> Result<Vec<ObjectId>, Self::Error> {
        if semantic_version < wire::SEMANTIC_PROTOCOL_V2 {
            return Ok(Vec::new());
        }
        self.bridge_durable_dependencies(limit)
    }

    fn durably_disposed_object_len(
        &mut self,
        object_id: ObjectId,
        semantic_version: u16,
    ) -> Result<Option<u64>, Self::Error> {
        self.node()
            .store()
            .durably_disposed_semantic_object_len(object_id, semantic_version)
            .map_err(store_error)
    }

    fn select_authorized_inventory(
        &mut self,
        authenticated_peer: NodeId,
        peer_route_commitments: &[[u8; 32]],
        filter: &InterestFilter,
        purpose: InventoryPurpose,
    ) -> Result<SparseInventory, Self::Error> {
        self.inner.select_authorized_inventory(
            authenticated_peer,
            peer_route_commitments,
            filter,
            purpose,
        )
    }

    fn select_authorized_inventory_for_semantic_version(
        &mut self,
        authenticated_peer: NodeId,
        peer_route_commitments: &[[u8; 32]],
        filter: &InterestFilter,
        purpose: InventoryPurpose,
        semantic_version: u16,
    ) -> Result<SparseInventory, Self::Error> {
        if semantic_version < wire::SEMANTIC_PROTOCOL_V2 {
            self.bridge_inventory_grants.clear();
            self.bridge_served.clear();
            self.batch_inventory_grants.clear();
            self.batch_served.clear();
            return self.select_semantic_v1_inventory(
                authenticated_peer,
                peer_route_commitments,
                filter,
                purpose,
                semantic_version,
            );
        }
        self.select_semantic_v2_inventory(
            authenticated_peer,
            peer_route_commitments,
            filter,
            purpose,
        )
    }

    fn store_object_chunk(
        &mut self,
        object_id: ObjectId,
        total_len: u64,
        offset: u64,
        bytes: &[u8],
    ) -> Result<(), Self::Error> {
        self.inner
            .store_object_chunk(object_id, total_len, offset, bytes)
    }

    fn store_object_chunk_for_semantic_version(
        &mut self,
        object_id: ObjectId,
        total_len: u64,
        offset: u64,
        bytes: &[u8],
        semantic_version: u16,
    ) -> Result<(), Self::Error> {
        self.inner.store_object_chunk_for_semantic_version(
            object_id,
            total_len,
            offset,
            bytes,
            semantic_version,
        )
    }

    fn complete_object_bytes(
        &mut self,
        object_id: ObjectId,
        total_len: u64,
    ) -> Result<Vec<u8>, Self::Error> {
        self.inner.complete_object_bytes(object_id, total_len)
    }

    fn abort_object(&mut self, object_id: ObjectId) -> Result<(), Self::Error> {
        self.inner.abort_object(object_id)
    }

    fn commit_authenticated_object(
        &mut self,
        authenticated_peer: NodeId,
        exchange_id: u64,
        object_id: ObjectId,
        bytes: Vec<u8>,
        forwarding: Vec<u8>,
    ) -> Result<Option<ItemId>, Self::Error> {
        self.inner.commit_authenticated_object(
            authenticated_peer,
            exchange_id,
            object_id,
            bytes,
            forwarding,
        )
    }

    fn commit_authenticated_object_with_dependencies(
        &mut self,
        authenticated_peer: NodeId,
        exchange_id: u64,
        semantic_version: u16,
        object_id: ObjectId,
        bytes: Vec<u8>,
        forwarding: Vec<u8>,
    ) -> Result<RuntimeCommit, Self::Error> {
        if semantic_version >= wire::SEMANTIC_PROTOCOL_V2 {
            self.ensure_bridge_contact_authorized(authenticated_peer)?;
        }
        if semantic_version < wire::SEMANTIC_PROTOCOL_V2
            && matches!(
                object_id.kind(),
                ObjectKind::SourceBatchProof
                    | ObjectKind::BridgeAuthorization
                    | ObjectKind::BridgeRouteWrapper
            )
        {
            return Err(missing("semantic-v2 object reached a version-1 backend"));
        }
        match object_id.kind() {
            ObjectKind::BridgeAuthorization => {
                self.commit_bridge_authorization(object_id, bytes, forwarding)
            }
            ObjectKind::BridgeRouteWrapper => self.commit_bridge_wrapper(
                authenticated_peer,
                exchange_id,
                object_id,
                bytes,
                forwarding,
            ),
            ObjectKind::SourceEnvelope if semantic_version >= wire::SEMANTIC_PROTOCOL_V2 => {
                if bytes.starts_with(b"ASTRENV3") {
                    self.commit_compact_batch_item(
                        authenticated_peer,
                        exchange_id,
                        object_id,
                        bytes,
                        forwarding,
                    )
                } else if self.source_has_bridge_reference(object_id.digest())? {
                    self.commit_bridge_source(
                        authenticated_peer,
                        exchange_id,
                        object_id,
                        bytes,
                        forwarding,
                    )
                } else {
                    self.commit_source_or_quarantine(
                        IncomingSemanticObject {
                            authenticated_peer,
                            exchange_id,
                            semantic_version,
                            object_id,
                            bytes,
                            forwarding,
                        },
                        true,
                    )
                }
            }
            ObjectKind::SourceBatchProof => self.commit_batch_proof(
                authenticated_peer,
                exchange_id,
                object_id,
                bytes,
                forwarding,
            ),
            ObjectKind::BlobChunk if semantic_version >= wire::SEMANTIC_PROTOCOL_V2 => {
                if let Some(commit) =
                    self.commit_bridge_blob_chunk(object_id, bytes.clone(), forwarding.clone())?
                {
                    Ok(commit)
                } else {
                    self.inner.commit_authenticated_object_with_dependencies(
                        authenticated_peer,
                        exchange_id,
                        semantic_version,
                        object_id,
                        bytes,
                        forwarding,
                    )
                }
            }
            ObjectKind::SourceEnvelope => self.commit_source_or_quarantine(
                IncomingSemanticObject {
                    authenticated_peer,
                    exchange_id,
                    semantic_version,
                    object_id,
                    bytes,
                    forwarding,
                },
                false,
            ),
            ObjectKind::BlobChunk => self.inner.commit_authenticated_object_with_dependencies(
                authenticated_peer,
                exchange_id,
                semantic_version,
                object_id,
                bytes,
                forwarding,
            ),
        }
    }

    fn is_terminal_commit_error(&self, error: &Self::Error) -> bool {
        semantic_terminal_commit_error(error)
    }

    fn object_priority(&mut self, object_id: ObjectId) -> Result<Priority, Self::Error> {
        if let Some(grant) = self.batch_inventory_grants.get(&object_id) {
            return Ok(grant.effective_priority);
        }
        match object_id.kind() {
            ObjectKind::BridgeAuthorization => Ok(Priority::Flash),
            ObjectKind::BridgeRouteWrapper => {
                if let Some(route) = self
                    .node()
                    .store()
                    .stored_bridge_route(object_id.digest())
                    .map_err(store_error)?
                {
                    return Ok(route.priority);
                }
                if let Some(pending) = self
                    .node()
                    .store()
                    .stored_pending_bridge_wrapper(object_id.digest())
                    .map_err(store_error)?
                    && let Some(source) = self
                        .node()
                        .store()
                        .stored_pending_bridge_source(&pending.route.origin_envelope_id)
                        .map_err(store_error)?
                {
                    return Ok(source.metadata.priority);
                }
                Ok(Priority::Routine)
            }
            ObjectKind::SourceEnvelope => {
                if let Some(item) = self
                    .node_mut()
                    .store_mut()
                    .get_by_envelope(object_id.digest())
                    .map_err(store_error)?
                    && item.sealed.starts_with(b"ASTRENV3")
                {
                    return Ok(item.priority);
                }
                let source = match self
                    .node()
                    .store()
                    .stored_bridge_source(object_id.digest())
                    .map_err(store_error)?
                {
                    Some(source) => Some(source),
                    None => self
                        .node()
                        .store()
                        .stored_pending_bridge_source(object_id.digest())
                        .map_err(store_error)?,
                };
                if let Some(source) = source {
                    return Ok(source.metadata.priority);
                }
                self.inner.object_priority(object_id)
            }
            ObjectKind::BlobChunk => {
                if let Some(grant) = self.bridge_inventory_grants.get(&object_id).cloned() {
                    let sample = self.node().custody_sample();
                    let route = self
                        .node()
                        .store()
                        .stored_bridge_route(&grant.wrapper_envelope_id)
                        .map_err(store_error)?
                        .ok_or_else(|| missing("bridge Blob priority route is missing"))?;
                    if route.active
                        && route.current_scope == grant.current_scope
                        && route.current_route_epoch == grant.current_route_epoch
                        && self
                            .node()
                            .store()
                            .bridge_route_is_live_at(&route.wrapper_envelope_id, sample)
                            .map_err(store_error)?
                    {
                        return Ok(route.priority);
                    }
                    return Err(missing("bridge Blob priority route is no longer live"));
                }
                self.inner.object_priority(object_id)
            }
            ObjectKind::SourceBatchProof => {
                if let Some(proof) = self
                    .node()
                    .store()
                    .stored_batch_proof(object_id.digest())
                    .map_err(store_error)?
                {
                    return Ok(proof.effective_priority);
                }
                let sample = self.node().custody_sample();
                let mut after = None;
                let mut effective = Priority::Routine;
                loop {
                    let page = self
                        .node()
                        .store()
                        .pending_batch_items_for_proof(object_id.digest(), after, RESTART_PAGE)
                        .map_err(store_error)?;
                    if page.is_empty() {
                        break;
                    }
                    for pending in &page {
                        if pending.ttl_ms.is_none()
                            || pending.effective_custody_age_ms(sample).is_some_and(|age| {
                                pending.ttl_ms.is_some_and(|ttl_ms| age < ttl_ms)
                            })
                        {
                            effective = effective.max(pending.priority);
                        }
                    }
                    after = page.last().map(|value| value.inserted_order);
                    if page.len() < RESTART_PAGE {
                        break;
                    }
                }
                Ok(effective)
            }
        }
    }

    fn data_for_want(
        &mut self,
        authenticated_peer: NodeId,
        peer_route_commitments: &[[u8; 32]],
        exchange_id: u64,
        want: &WantItem,
    ) -> Result<Vec<Data>, Self::Error> {
        self.inner.data_for_want(
            authenticated_peer,
            peer_route_commitments,
            exchange_id,
            want,
        )
    }

    fn data_for_want_for_semantic_version(
        &mut self,
        authenticated_peer: NodeId,
        peer_route_commitments: &[[u8; 32]],
        exchange_id: u64,
        semantic_version: u16,
        want: &WantItem,
    ) -> Result<Vec<Data>, Self::Error> {
        if self.batch_inventory_grants.contains_key(&want.object_id) {
            return self.serve_batch_want(
                authenticated_peer,
                peer_route_commitments,
                exchange_id,
                semantic_version,
                want,
            );
        }
        if semantic_version < wire::SEMANTIC_PROTOCOL_V2 {
            return self.inner.data_for_want_for_semantic_version(
                authenticated_peer,
                peer_route_commitments,
                exchange_id,
                semantic_version,
                want,
            );
        }
        if self.bridge_inventory_grants.contains_key(&want.object_id) {
            return self.serve_bridge_want(
                authenticated_peer,
                peer_route_commitments,
                exchange_id,
                want,
            );
        }
        self.inner.data_for_want_for_semantic_version(
            authenticated_peer,
            peer_route_commitments,
            exchange_id,
            semantic_version,
            want,
        )
    }

    fn acknowledge_receipt(
        &mut self,
        authenticated_peer: NodeId,
        semantic_version: u16,
        receipt: &wire::Receipt,
    ) -> Result<(), Self::Error> {
        if !receipt.complete {
            return self
                .inner
                .acknowledge_receipt(authenticated_peer, semantic_version, receipt);
        }
        if self.batch_served.contains_key(&(
            authenticated_peer,
            receipt.exchange_id,
            receipt.object_id,
        )) {
            return self.acknowledge_batch_receipt(authenticated_peer, semantic_version, receipt);
        }
        if semantic_version < wire::SEMANTIC_PROTOCOL_V2 {
            return self
                .inner
                .acknowledge_receipt(authenticated_peer, semantic_version, receipt);
        }
        self.acknowledge_bridge_receipt(authenticated_peer, receipt)
    }
}

fn store_error(error: StoreError) -> BlobRuntimeError {
    BlobRuntimeError::Engine(EngineError::Store(error))
}

fn envelope_error(error: EnvelopeError) -> BlobRuntimeError {
    BlobRuntimeError::Engine(EngineError::Envelope(error))
}

fn missing(message: &'static str) -> BlobRuntimeError {
    BlobRuntimeError::Invalid(message)
}

fn semantic_terminal_commit_error(error: &BlobRuntimeError) -> bool {
    match error {
        BlobRuntimeError::Invalid(_) => true,
        BlobRuntimeError::Engine(EngineError::Store(error)) => match error {
            StoreError::Sqlite(_)
            | StoreError::CounterChanged
            | StoreError::NotFound(_)
            | StoreError::QuotaExceeded
            | StoreError::BridgeDependencyMissing
            | StoreError::BridgeObjectReferenced => false,
            StoreError::Invalid(_)
            | StoreError::Corrupt(_)
            | StoreError::Equivocation { .. }
            | StoreError::EventEquivocation { .. }
            | StoreError::Zeroized
            | StoreError::ControlFork
            | StoreError::ControlRollback
            | StoreError::ControlSignerRevoked(_)
            | StoreError::ControlAuthorityRevoked(_)
            | StoreError::BridgeControlFork
            | StoreError::BridgeControlRollback
            | StoreError::BridgeControlSignerRevoked(_)
            | StoreError::BridgeControlAuthorityRevoked(_)
            | StoreError::LegacyControlMigrationRequired
            | StoreError::BridgeRouteIneligible => true,
        },
        BlobRuntimeError::Engine(_) => true,
        BlobRuntimeError::Blob(BlobError::Io(_))
        | BlobRuntimeError::Blob(BlobError::Store(_))
        | BlobRuntimeError::Blob(BlobError::MissingChunk) => false,
        BlobRuntimeError::Blob(_) => true,
    }
}

fn semantic_restart_progress_allowed(
    entry: &RuntimeTransferProgress,
    semantic_version: u16,
) -> bool {
    if !matches!(
        semantic_version,
        wire::SEMANTIC_PROTOCOL_V1 | wire::SEMANTIC_PROTOCOL_V2
    ) {
        return false;
    }
    if !entry
        .object_id
        .kind()
        .is_allowed_in_semantic_version(semantic_version)
    {
        return false;
    }
    let Some(origin_semantic_version) = entry.origin_semantic_version else {
        return false;
    };
    if !matches!(
        origin_semantic_version,
        wire::SEMANTIC_PROTOCOL_V1 | wire::SEMANTIC_PROTOCOL_V2
    ) {
        return false;
    }
    // SourceEnvelope kind 1 has a version-2-only compact shape, so a
    // version-1 contact may hydrate only an exact partial proved to have
    // started under version 1. BlobChunk kind 2 is byte-for-byte stable across
    // both registries and is safely resumable under either supported version.
    match entry.object_id.kind() {
        ObjectKind::SourceEnvelope => {
            semantic_version >= wire::SEMANTIC_PROTOCOL_V2
                || origin_semantic_version == wire::SEMANTIC_PROTOCOL_V1
        }
        ObjectKind::BlobChunk => true,
        ObjectKind::SourceBatchProof
        | ObjectKind::BridgeAuthorization
        | ObjectKind::BridgeRouteWrapper => {
            semantic_version == wire::SEMANTIC_PROTOCOL_V2
                && origin_semantic_version == wire::SEMANTIC_PROTOCOL_V2
        }
    }
}

fn insert_semantic_inventory_id(
    ids: &mut BTreeSet<ObjectId>,
    object_id: ObjectId,
) -> Result<(), BlobRuntimeError> {
    if ids.len() == MAX_SEMANTIC_INVENTORY_OBJECTS && !ids.contains(&object_id) {
        return Err(missing("composite semantic inventory exceeds bound"));
    }
    ids.insert(object_id);
    Ok(())
}

fn bridge_route_matches_filter(route: &StoredBridgeRoute, filter: &InterestFilter) -> bool {
    filter
        .topics
        .binary_search_by(|value| value.as_str().cmp(route.topic.as_str()))
        .is_ok()
        && filter
            .scopes
            .binary_search_by(|value| value.as_str().cmp(route.current_scope.as_str()))
            .is_ok()
        && route.priority as u8 >= filter.min_priority
}

fn stored_item_matches_batch_verification(item: &StoredItem, verified: &VerifiedBatchItem) -> bool {
    let envelope = verified.verified_envelope();
    item.id == envelope.id
        && item.class == envelope.header.class
        && item.topic == envelope.header.topic
        && item.scope == envelope.header.scope
        && item.priority == envelope.header.priority
        && item.stamp == envelope.header.stamp
        && item.event_sequence == envelope.header.event_sequence
        && item.logical_key == envelope.header.logical_key
        && item.ttl_ms == envelope.header.ttl_ms
        && item.content_len == envelope.header.content_len
        && item.tombstone == envelope.header.tombstone
        && item.key_epoch == envelope.header.key_epoch
}

fn bridge_forwarding_age(
    route: &StoredBridgeRoute,
    sample: Option<crate::store::CustodySample>,
) -> Option<u64> {
    if route.age_continuity_unknown || !route.custody_elapsed_available {
        return None;
    }
    let sample = sample?;
    let clock_id = route.custody_clock_id?;
    let tick_ms = route.custody_tick_ms?;
    if sample.clock_id != clock_id || sample.tick_ms < tick_ms {
        return None;
    }
    Some(
        route
            .cumulative_custody_age_ms
            .max(route.authenticated_forwarding_age_ms)
            .saturating_add(sample.tick_ms - tick_ms),
    )
}

fn conservative_item_custody_age(
    item: &crate::store::StoredItem,
    sample: Option<crate::store::CustodySample>,
) -> u64 {
    if item.tombstone || item.ttl_ms.is_none() {
        if item.custody_elapsed_available
            && let (Some(clock_id), Some(tick), Some(sample)) =
                (item.custody_clock_id, item.custody_tick_ms, sample)
            && clock_id == sample.clock_id
            && sample.tick_ms >= tick
        {
            return item
                .custody_age_ms
                .saturating_add(sample.tick_ms.saturating_sub(tick));
        }
        return item.custody_age_ms;
    }
    if !item.custody_elapsed_available {
        return u64::MAX;
    }
    let (Some(clock_id), Some(tick), Some(sample)) =
        (item.custody_clock_id, item.custody_tick_ms, sample)
    else {
        return u64::MAX;
    };
    if clock_id != sample.clock_id || sample.tick_ms < tick {
        return u64::MAX;
    }
    item.custody_age_ms
        .saturating_add(sample.tick_ms.saturating_sub(tick))
}

fn authenticated_blob_route(
    origin_envelope_id: [u8; 32],
    metadata: &VerifiedBlobRouteMetadata,
) -> AuthenticatedBlobRoute {
    AuthenticatedBlobRoute::new(
        EnvelopeId::from_bytes(origin_envelope_id),
        crate::blob::BlobRouteCommitment::from_authenticated_header(
            crate::blob::BlobId::from_bytes(metadata.blob_id),
            metadata.chunk_count,
            metadata.merkle_root,
        ),
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::blob::BlobStoreConfig;
    use crate::crypto::{
        ProvisioningAccess, ProvisioningBundle, ReferenceProvisioner, open_reference_node,
    };
    use crate::engine::{BatchPublishItem, NodeConfig, PublishRequest};
    use crate::model::{DataClass, Scope, Topic};
    use crate::store::BatchStoragePolicy;
    use std::fs;
    use std::time::{SystemTime, UNIX_EPOCH};

    #[test]
    fn semantic_commit_failure_classification_retires_poison_but_keeps_retryable_state() {
        assert!(semantic_terminal_commit_error(&store_error(
            StoreError::Corrupt("normalization mismatch".into())
        )));
        assert!(semantic_terminal_commit_error(&store_error(
            StoreError::BridgeControlFork
        )));
        assert!(semantic_terminal_commit_error(&BlobRuntimeError::Blob(
            BlobError::AuthenticationFailed
        )));

        assert!(!semantic_terminal_commit_error(&store_error(
            StoreError::QuotaExceeded
        )));
        assert!(!semantic_terminal_commit_error(&store_error(
            StoreError::BridgeDependencyMissing
        )));
        assert!(!semantic_terminal_commit_error(&BlobRuntimeError::Blob(
            BlobError::MissingChunk
        )));
    }

    #[test]
    fn finite_ttl_ordinary_custody_fails_closed_without_continuity() {
        let item = crate::store::StoredItem {
            id: [1; 32],
            envelope_id: [2; 32],
            class: crate::model::DataClass::State,
            topic: crate::model::Topic::new("mission").unwrap(),
            scope: crate::model::Scope::new("team").unwrap(),
            priority: Priority::Routine,
            stamp: crate::model::CausalStamp {
                dot: crate::model::Dot {
                    publisher: [3; 32],
                    counter: 1,
                },
                context: crate::model::VersionVector::default(),
            },
            event_sequence: None,
            logical_key: b"key".to_vec(),
            ttl_ms: Some(10),
            observed_at_ms: None,
            sealed: vec![4],
            content_len: 1,
            tombstone: false,
            key_epoch: 1,
            custody_age_ms: 4,
            custody_clock_id: None,
            custody_tick_ms: None,
            custody_elapsed_available: false,
            status: crate::store::VersionStatus::Current,
            inserted_order: 1,
        };
        assert_eq!(conservative_item_custody_age(&item, None), u64::MAX);
    }

    #[test]
    fn restart_progress_never_downgrades_an_ambiguous_source_partial() {
        let source = |origin_semantic_version| RuntimeTransferProgress {
            object_id: ObjectId::new(ObjectKind::SourceEnvelope, [0x31; 32]),
            origin_semantic_version,
            total_len: 9,
            received: vec![ByteRange { start: 0, end: 4 }],
        };
        let blob = RuntimeTransferProgress {
            object_id: ObjectId::new(ObjectKind::BlobChunk, [0x32; 32]),
            origin_semantic_version: Some(wire::SEMANTIC_PROTOCOL_V2),
            total_len: 9,
            received: vec![ByteRange { start: 0, end: 4 }],
        };
        let proof = RuntimeTransferProgress {
            object_id: ObjectId::new(ObjectKind::SourceBatchProof, [0x33; 32]),
            origin_semantic_version: Some(wire::SEMANTIC_PROTOCOL_V2),
            total_len: 9,
            received: vec![ByteRange { start: 0, end: 4 }],
        };

        assert!(semantic_restart_progress_allowed(
            &source(Some(wire::SEMANTIC_PROTOCOL_V1)),
            wire::SEMANTIC_PROTOCOL_V1
        ));
        assert!(!semantic_restart_progress_allowed(
            &source(Some(wire::SEMANTIC_PROTOCOL_V2)),
            wire::SEMANTIC_PROTOCOL_V1
        ));
        assert!(!semantic_restart_progress_allowed(
            &source(None),
            wire::SEMANTIC_PROTOCOL_V1
        ));
        assert!(semantic_restart_progress_allowed(
            &source(Some(wire::SEMANTIC_PROTOCOL_V1)),
            wire::SEMANTIC_PROTOCOL_V2
        ));
        assert!(semantic_restart_progress_allowed(
            &source(Some(wire::SEMANTIC_PROTOCOL_V2)),
            wire::SEMANTIC_PROTOCOL_V2
        ));
        assert!(!semantic_restart_progress_allowed(
            &source(None),
            wire::SEMANTIC_PROTOCOL_V2
        ));
        assert!(semantic_restart_progress_allowed(
            &blob,
            wire::SEMANTIC_PROTOCOL_V1
        ));
        assert!(!semantic_restart_progress_allowed(
            &proof,
            wire::SEMANTIC_PROTOCOL_V1
        ));
    }

    #[test]
    fn disposed_lookup_persists_private_compact_and_quarantine_across_restart() {
        let root = std::env::temp_dir().join(format!(
            "aster-batch-compact-first-{}-{}",
            std::process::id(),
            SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        fs::create_dir_all(&root).unwrap();
        let topic = Topic::new("batch.compact-first").unwrap();
        let scope = Scope::new("mission/compact-first").unwrap();
        let access =
            ProvisioningAccess::member(scope.clone(), vec![0], vec![topic.clone()]).unwrap();
        let mut provisioner = ReferenceProvisioner::from_seed([0xc4; 32]).unwrap();
        let source_bundle = provisioner
            .issue_node(1, std::slice::from_ref(&access))
            .unwrap();
        let receiver_bundle = provisioner.issue_node(2, &[access]).unwrap();
        let receiver_bundle_bytes = receiver_bundle.to_bytes().unwrap();
        let mut source = open_reference_node(
            root.join("source.sqlite"),
            source_bundle,
            NodeConfig::default(),
        )
        .unwrap();
        let receipt = source
            .publish_reference_batch(
                [b"alpha".as_slice(), b"bravo".as_slice()]
                    .into_iter()
                    .map(|key| BatchPublishItem {
                        request: PublishRequest {
                            class: DataClass::State,
                            topic: topic.clone(),
                            scope: scope.clone(),
                            priority: Priority::Priority,
                            ttl_ms: None,
                            logical_key: key.to_vec(),
                            payload: key.to_vec(),
                            tombstone: false,
                        },
                        blob_route: None,
                    })
                    .collect(),
                BatchStoragePolicy::BatchOnly,
            )
            .unwrap();
        let material = source
            .store_mut()
            .stored_batch_material(&receipt.items[0].id)
            .unwrap()
            .unwrap();
        let source_id = source.identity();
        let receiver = open_reference_node(
            root.join("receiver.sqlite"),
            receiver_bundle,
            NodeConfig::default(),
        )
        .unwrap();
        let receiver_id = receiver.identity();
        let blobs = BlobTransferStore::open_with_config(
            root.join("receiver-blobs"),
            BlobStoreConfig::default(),
        )
        .unwrap();
        let mut backend = ReferenceSemanticRuntimeBackend::new(receiver, blobs).unwrap();
        backend.authorize_adjacency(source_id).unwrap();

        let compact_id = ObjectId::new(ObjectKind::SourceEnvelope, material.compact_envelope_id);
        let compact_forwarding = source
            .envelopes_mut()
            .seal_forwarding(receiver_id, 41, material.compact_envelope_id, 0)
            .unwrap();
        let v1_error = backend
            .commit_authenticated_object_with_dependencies(
                source_id,
                40,
                wire::SEMANTIC_PROTOCOL_V1,
                compact_id,
                material.compact_bytes.clone(),
                Vec::new(),
            )
            .unwrap_err();
        assert!(backend.is_terminal_commit_error(&v1_error));
        backend
            .store_object_chunk_for_semantic_version(
                compact_id,
                material.compact_bytes.len() as u64,
                0,
                &material.compact_bytes,
                wire::SEMANTIC_PROTOCOL_V2,
            )
            .unwrap();
        let compact_bytes = backend
            .complete_object_bytes(compact_id, material.compact_bytes.len() as u64)
            .unwrap();
        let deferred = backend
            .commit_authenticated_object_with_dependencies(
                source_id,
                41,
                wire::SEMANTIC_PROTOCOL_V2,
                compact_id,
                compact_bytes,
                compact_forwarding,
            )
            .unwrap();
        assert_eq!(
            deferred,
            RuntimeCommit::Deferred {
                dependencies: vec![ObjectId::new(
                    ObjectKind::SourceBatchProof,
                    material.proof.proof_envelope_id,
                )],
            }
        );
        assert_eq!(
            backend
                .durably_disposed_object_len(compact_id, wire::SEMANTIC_PROTOCOL_V2)
                .unwrap(),
            Some(material.compact_bytes.len() as u64)
        );
        assert_eq!(
            backend
                .durably_disposed_object_len(compact_id, wire::SEMANTIC_PROTOCOL_V1)
                .unwrap(),
            None
        );
        assert!(
            backend
                .node_mut()
                .store_mut()
                .get(&receipt.items[0].id)
                .unwrap()
                .is_none()
        );

        let quarantined_bytes = b"private-unresolved-source-carrier".to_vec();
        let quarantined_id = ObjectId::new(
            ObjectKind::SourceEnvelope,
            Sha256::digest(&quarantined_bytes).into(),
        );
        let quarantined_forwarding = source
            .envelopes_mut()
            .seal_forwarding(receiver_id, 42, *quarantined_id.digest(), 0)
            .unwrap();
        backend
            .store_object_chunk_for_semantic_version(
                quarantined_id,
                quarantined_bytes.len() as u64,
                0,
                &quarantined_bytes,
                wire::SEMANTIC_PROTOCOL_V2,
            )
            .unwrap();
        let completed_quarantine = backend
            .complete_object_bytes(quarantined_id, quarantined_bytes.len() as u64)
            .unwrap();
        assert_eq!(
            backend
                .commit_authenticated_object_with_dependencies(
                    source_id,
                    42,
                    wire::SEMANTIC_PROTOCOL_V2,
                    quarantined_id,
                    completed_quarantine,
                    quarantined_forwarding,
                )
                .unwrap(),
            RuntimeCommit::Quarantined
        );
        assert_eq!(
            backend
                .durably_disposed_object_len(quarantined_id, wire::SEMANTIC_PROTOCOL_V2)
                .unwrap(),
            Some(quarantined_bytes.len() as u64)
        );
        drop(backend);

        let receiver = open_reference_node(
            root.join("receiver.sqlite"),
            ProvisioningBundle::from_bytes(&receiver_bundle_bytes).unwrap(),
            NodeConfig::default(),
        )
        .unwrap();
        let blobs = BlobTransferStore::open_with_config(
            root.join("receiver-blobs"),
            BlobStoreConfig::default(),
        )
        .unwrap();
        let mut backend = ReferenceSemanticRuntimeBackend::new(receiver, blobs).unwrap();
        backend.authorize_adjacency(source_id).unwrap();
        assert_eq!(
            backend
                .durably_disposed_object_len(compact_id, wire::SEMANTIC_PROTOCOL_V2)
                .unwrap(),
            Some(material.compact_bytes.len() as u64)
        );
        assert_eq!(
            backend
                .durably_disposed_object_len(quarantined_id, wire::SEMANTIC_PROTOCOL_V2)
                .unwrap(),
            Some(quarantined_bytes.len() as u64)
        );
        assert_eq!(
            backend
                .durably_disposed_object_len(quarantined_id, wire::SEMANTIC_PROTOCOL_V1)
                .unwrap(),
            None
        );
        assert!(
            backend
                .node()
                .store()
                .stored_pending_batch_item(compact_id.digest())
                .unwrap()
                .is_some()
        );

        let proof_id = ObjectId::new(
            ObjectKind::SourceBatchProof,
            material.proof.proof_envelope_id,
        );
        let proof_forwarding = source
            .envelopes_mut()
            .seal_forwarding(receiver_id, 43, material.proof.proof_envelope_id, 0)
            .unwrap();
        backend
            .store_object_chunk_for_semantic_version(
                proof_id,
                material.proof.exact_bytes.len() as u64,
                0,
                &material.proof.exact_bytes,
                wire::SEMANTIC_PROTOCOL_V2,
            )
            .unwrap();
        let proof_bytes = backend
            .complete_object_bytes(proof_id, material.proof.exact_bytes.len() as u64)
            .unwrap();
        let committed = backend
            .commit_authenticated_object_with_dependencies(
                source_id,
                43,
                wire::SEMANTIC_PROTOCOL_V2,
                proof_id,
                proof_bytes,
                proof_forwarding,
            )
            .unwrap();
        let RuntimeCommit::Committed { promoted, .. } = committed else {
            panic!("proof did not promote its durable compact dependency");
        };
        assert!(promoted.contains(&compact_id));
        assert!(
            backend
                .node_mut()
                .store_mut()
                .get(&receipt.items[0].id)
                .unwrap()
                .is_some()
        );
        assert!(
            backend
                .node()
                .store()
                .stored_pending_batch_item(compact_id.digest())
                .unwrap()
                .is_none()
        );
        assert_eq!(
            backend
                .durably_disposed_object_len(compact_id, wire::SEMANTIC_PROTOCOL_V2)
                .unwrap(),
            None
        );
        assert_eq!(
            backend
                .durably_disposed_object_len(quarantined_id, wire::SEMANTIC_PROTOCOL_V2)
                .unwrap(),
            Some(quarantined_bytes.len() as u64)
        );

        drop(backend);
        drop(source);
        fs::remove_dir_all(root).unwrap();
    }
}
