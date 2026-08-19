//! Canonical semantic-v2 bridge authorization and route-wrapper data model.
//!
//! This module contains no keys and performs no signing or encryption. It defines the
//! byte-exact, bounded values which the cryptographic provider authenticates and which
//! the durable engine may activate only after provider verification.

use crate::model::{NodeId, Priority, Scope, Topic};
use sha2::{Digest, Sha256};
use std::collections::{BTreeMap, BTreeSet};
use std::fmt;

pub(crate) const AUTHORIZATION_MAGIC: &[u8; 8] = b"ASTRBA01";
pub(crate) const WRAPPER_MAGIC: &[u8; 8] = b"ASTRBW01";
pub(crate) const AUTHORIZATION_FORMAT: u16 = 1;
pub(crate) const WRAPPER_FORMAT: u16 = 1;
pub(crate) const SEMANTIC_PROTOCOL: u16 = 2;
pub(crate) const COMPLETE_SUITE: u16 = 0x0001;
pub(crate) const AUTHORIZATION_KIND: u8 = 4;
pub(crate) const MAX_TOPICS: usize = 128;
pub(crate) const MAX_HOPS: usize = 8;
pub(crate) const MAX_AUTHORIZATION_TOTAL_BYTES: usize = 65_536;
pub(crate) const MAX_WRAPPER_PROTECTED_BYTES: usize = 524_288;
pub(crate) const BRIDGE_PUBLIC_HEADER_BYTES: usize = 34;
pub(crate) const MAX_WRAPPER_TOTAL_BYTES: usize =
    BRIDGE_PUBLIC_HEADER_BYTES + MAX_WRAPPER_PROTECTED_BYTES;
pub(crate) const MAX_SOURCE_DESCRIPTOR_BYTES: usize = 262_128;
pub(crate) const HYBRID_SIGNATURE_BYTES: usize = 2 + 64 + 4 + 3_309;
const GCM_TAG_BYTES: usize = 16;
const MAX_AUTHORIZATION_PLAINTEXT_BYTES: usize =
    MAX_AUTHORIZATION_TOTAL_BYTES - BRIDGE_PUBLIC_HEADER_BYTES - GCM_TAG_BYTES;
const MAX_AUTHORIZATION_PROTECTED_BYTES: usize =
    MAX_AUTHORIZATION_TOTAL_BYTES - BRIDGE_PUBLIC_HEADER_BYTES;
const MAX_WRAPPER_PLAINTEXT_BYTES: usize = MAX_WRAPPER_PROTECTED_BYTES - GCM_TAG_BYTES;
const MAX_CREDENTIAL_BYTES: usize = 16 * 1024;
const AUTHORIZATION_KEY_DOMAIN: &[u8] = b"aster/bridge-authorization-key/v1";
const AUTHORIZATION_CONTROL_DOMAIN: &[u8] = b"aster/bridge-authorization-control/v1";
const HOP_SIGNATURE_DOMAIN: &[u8] = b"aster/bridge-hop-signature/v1";
const HOP_ID_DOMAIN: &[u8] = b"aster/bridge-hop-id/v1";
const ROUTE_ID_DOMAIN: &[u8] = b"aster/bridge-route-id/v1";

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) enum BridgeCodecError {
    Invalid(&'static str),
    Truncated,
    TrailingBytes,
    SizeLimit,
}

impl fmt::Display for BridgeCodecError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Invalid(field) => write!(formatter, "invalid bridge {field}"),
            Self::Truncated => formatter.write_str("truncated bridge object"),
            Self::TrailingBytes => formatter.write_str("trailing bridge bytes"),
            Self::SizeLimit => formatter.write_str("bridge object exceeds a declared bound"),
        }
    }
}

impl std::error::Error for BridgeCodecError {}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct EnabledAuthorization {
    pub(crate) source_route_epoch: u64,
    pub(crate) target_route_epoch: u64,
    pub(crate) source_route_commitment: [u8; 32],
    pub(crate) target_route_commitment: [u8; 32],
    pub(crate) allowed_priority_mask: u8,
    pub(crate) max_total_hops: u8,
    pub(crate) topics: Vec<Topic>,
    pub(crate) bridge_credential: Vec<u8>,
    pub(crate) authority_credential_signature: Vec<u8>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct BridgeAuthorization {
    pub(crate) mission_id: [u8; 32],
    pub(crate) authority_id: NodeId,
    pub(crate) control_sequence: u64,
    pub(crate) previous_control_id: Option<[u8; 32]>,
    pub(crate) authorization_key: [u8; 32],
    pub(crate) generation: u64,
    pub(crate) bridge_node_id: NodeId,
    pub(crate) source_scope: Scope,
    pub(crate) target_scope: Scope,
    pub(crate) enabled: Option<EnabledAuthorization>,
    pub(crate) authority_control_signature: Vec<u8>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct BridgeNarrowing {
    /// Empty means the complete authority topic set, never topics outside it.
    pub(crate) topics: BTreeSet<Topic>,
    pub(crate) allowed_priority_mask: u8,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct BridgeHop {
    pub(crate) authorization_envelope_id: [u8; 32],
    pub(crate) bridge_node_id: NodeId,
    pub(crate) from_scope: Scope,
    pub(crate) from_route_epoch: u64,
    pub(crate) to_scope: Scope,
    pub(crate) to_route_epoch: u64,
    pub(crate) cumulative_custody_age_ms: u64,
    pub(crate) age_continuity_unknown: bool,
    pub(crate) previous_hop_digest: [u8; 32],
    pub(crate) bridge_hybrid_signature: Vec<u8>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct BridgeRoute {
    pub(crate) mission_id: [u8; 32],
    pub(crate) origin_envelope_id: [u8; 32],
    pub(crate) source_item_id: [u8; 32],
    pub(crate) origin_scope: Scope,
    pub(crate) origin_route_epoch: u64,
    pub(crate) current_scope: Scope,
    pub(crate) current_route_epoch: u64,
    pub(crate) source_route_descriptor: Vec<u8>,
    pub(crate) hops: Vec<BridgeHop>,
    pub(crate) bridge_route_id: [u8; 32],
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct AuthorizationEnvelope {
    pub(crate) envelope_id: [u8; 32],
    pub(crate) authorization: BridgeAuthorization,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum BridgeOuterKind {
    Authorization,
    Wrapper,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct BridgePublicHeader {
    pub(crate) kind: BridgeOuterKind,
    pub(crate) selector: [u8; 16],
    pub(crate) protected_length: usize,
}

impl BridgePublicHeader {
    pub(crate) fn total_length(self) -> Result<usize, BridgeCodecError> {
        BRIDGE_PUBLIC_HEADER_BYTES
            .checked_add(self.protected_length)
            .ok_or(BridgeCodecError::SizeLimit)
    }
}

pub(crate) fn hash_domain(domain: &[u8], input: &[u8]) -> [u8; 32] {
    let mut digest = Sha256::new();
    digest.update((domain.len() as u64).to_be_bytes());
    digest.update(domain);
    digest.update((input.len() as u64).to_be_bytes());
    digest.update(input);
    digest.finalize().into()
}

pub(crate) fn bridge_authorization_key(
    mission_id: &[u8; 32],
    bridge_node_id: &NodeId,
    source_scope: &Scope,
    target_scope: &Scope,
) -> Result<[u8; 32], BridgeCodecError> {
    let mut input = Vec::new();
    input.extend_from_slice(mission_id);
    input.extend_from_slice(bridge_node_id);
    push_text(&mut input, source_scope.as_str())?;
    push_text(&mut input, target_scope.as_str())?;
    Ok(hash_domain(AUTHORIZATION_KEY_DOMAIN, &input))
}

fn validate_hybrid_signature(bytes: &[u8]) -> Result<(), BridgeCodecError> {
    if bytes.len() != HYBRID_SIGNATURE_BYTES
        || bytes[..2] != 64u16.to_be_bytes()
        || bytes[66..70] != 3_309u32.to_be_bytes()
    {
        return Err(BridgeCodecError::Invalid("hybrid signature encoding"));
    }
    Ok(())
}

fn validate_priority_mask(mask: u8) -> Result<(), BridgeCodecError> {
    if mask == 0 || mask & !0x0f != 0 {
        return Err(BridgeCodecError::Invalid("priority mask"));
    }
    Ok(())
}

fn validate_topics(topics: &[Topic]) -> Result<(), BridgeCodecError> {
    if topics.is_empty()
        || topics.len() > MAX_TOPICS
        || topics.windows(2).any(|pair| pair[0] >= pair[1])
    {
        return Err(BridgeCodecError::Invalid("topic set"));
    }
    Ok(())
}

impl BridgeAuthorization {
    pub(crate) fn validate(&self) -> Result<(), BridgeCodecError> {
        if self.control_sequence == 0
            || (self.control_sequence == 1) != self.previous_control_id.is_none()
            || self.generation == 0
            || self.source_scope == self.target_scope
            || self.authorization_key
                != bridge_authorization_key(
                    &self.mission_id,
                    &self.bridge_node_id,
                    &self.source_scope,
                    &self.target_scope,
                )?
        {
            return Err(BridgeCodecError::Invalid("authorization identity"));
        }
        validate_hybrid_signature(&self.authority_control_signature)?;
        if let Some(enabled) = &self.enabled {
            if enabled.source_route_epoch == 0
                || enabled.target_route_epoch == 0
                || enabled.max_total_hops == 0
                || usize::from(enabled.max_total_hops) > MAX_HOPS
                || enabled.bridge_credential.is_empty()
                || enabled.bridge_credential.len() > MAX_CREDENTIAL_BYTES
            {
                return Err(BridgeCodecError::Invalid("enabled authorization"));
            }
            validate_priority_mask(enabled.allowed_priority_mask)?;
            validate_topics(&enabled.topics)?;
            validate_hybrid_signature(&enabled.authority_credential_signature)?;
        }
        if self.encode()?.len() > MAX_AUTHORIZATION_PLAINTEXT_BYTES {
            return Err(BridgeCodecError::SizeLimit);
        }
        Ok(())
    }

    pub(crate) fn control_signature_digest(&self) -> Result<[u8; 32], BridgeCodecError> {
        let bytes = self.encode_inner(false)?;
        Ok(hash_input(AUTHORIZATION_CONTROL_DOMAIN, &bytes))
    }

    pub(crate) fn encode(&self) -> Result<Vec<u8>, BridgeCodecError> {
        let bytes = self.encode_inner(true)?;
        if bytes.len() > MAX_AUTHORIZATION_PLAINTEXT_BYTES {
            return Err(BridgeCodecError::SizeLimit);
        }
        Ok(bytes)
    }

    fn encode_inner(&self, signature: bool) -> Result<Vec<u8>, BridgeCodecError> {
        let mut out = Vec::new();
        out.push(AUTHORIZATION_KIND);
        out.extend_from_slice(&self.mission_id);
        out.extend_from_slice(&self.authority_id);
        out.extend_from_slice(&self.control_sequence.to_be_bytes());
        push_optional_id(&mut out, self.previous_control_id);
        out.extend_from_slice(&self.authorization_key);
        out.extend_from_slice(&self.generation.to_be_bytes());
        out.push(u8::from(self.enabled.is_some()));
        out.extend_from_slice(&self.bridge_node_id);
        push_text(&mut out, self.source_scope.as_str())?;
        push_text(&mut out, self.target_scope.as_str())?;
        if let Some(enabled) = &self.enabled {
            out.extend_from_slice(&enabled.source_route_epoch.to_be_bytes());
            out.extend_from_slice(&enabled.target_route_epoch.to_be_bytes());
            out.extend_from_slice(&enabled.source_route_commitment);
            out.extend_from_slice(&enabled.target_route_commitment);
            out.push(enabled.allowed_priority_mask);
            out.push(enabled.max_total_hops);
            out.extend_from_slice(
                &u16::try_from(enabled.topics.len())
                    .map_err(|_| BridgeCodecError::SizeLimit)?
                    .to_be_bytes(),
            );
            for topic in &enabled.topics {
                push_text(&mut out, topic.as_str())?;
            }
            push_u32_bytes(&mut out, &enabled.bridge_credential)?;
            out.extend_from_slice(&enabled.authority_credential_signature);
        }
        if signature {
            out.extend_from_slice(&self.authority_control_signature);
        }
        Ok(out)
    }

    pub(crate) fn decode(bytes: &[u8]) -> Result<Self, BridgeCodecError> {
        if bytes.len() > MAX_AUTHORIZATION_PLAINTEXT_BYTES {
            return Err(BridgeCodecError::SizeLimit);
        }
        let mut reader = Reader::new(bytes);
        if reader.u8()? != AUTHORIZATION_KIND {
            return Err(BridgeCodecError::Invalid("authorization kind"));
        }
        let mission_id = reader.array()?;
        let authority_id = reader.array()?;
        let control_sequence = reader.u64()?;
        let previous_control_id = reader.optional_id()?;
        let authorization_key = reader.array()?;
        let generation = reader.u64()?;
        let enabled_flag = reader.boolean()?;
        let bridge_node_id = reader.array()?;
        let source_scope =
            Scope::new(reader.text()?).map_err(|_| BridgeCodecError::Invalid("source scope"))?;
        let target_scope =
            Scope::new(reader.text()?).map_err(|_| BridgeCodecError::Invalid("target scope"))?;
        let enabled = if enabled_flag {
            let source_route_epoch = reader.u64()?;
            let target_route_epoch = reader.u64()?;
            let source_route_commitment = reader.array()?;
            let target_route_commitment = reader.array()?;
            let allowed_priority_mask = reader.u8()?;
            let max_total_hops = reader.u8()?;
            let count = usize::from(reader.u16()?);
            if count == 0 || count > MAX_TOPICS {
                return Err(BridgeCodecError::Invalid("topic count"));
            }
            let mut topics = Vec::with_capacity(count);
            for _ in 0..count {
                topics.push(
                    Topic::new(reader.text()?).map_err(|_| BridgeCodecError::Invalid("topic"))?,
                );
            }
            let bridge_credential = reader.u32_bytes(MAX_CREDENTIAL_BYTES)?.to_vec();
            let authority_credential_signature = reader.take(HYBRID_SIGNATURE_BYTES)?.to_vec();
            Some(EnabledAuthorization {
                source_route_epoch,
                target_route_epoch,
                source_route_commitment,
                target_route_commitment,
                allowed_priority_mask,
                max_total_hops,
                topics,
                bridge_credential,
                authority_credential_signature,
            })
        } else {
            None
        };
        let authority_control_signature = reader.take(HYBRID_SIGNATURE_BYTES)?.to_vec();
        reader.finish()?;
        let value = Self {
            mission_id,
            authority_id,
            control_sequence,
            previous_control_id,
            authorization_key,
            generation,
            bridge_node_id,
            source_scope,
            target_scope,
            enabled,
            authority_control_signature,
        };
        value.validate()?;
        Ok(value)
    }
}

impl BridgeNarrowing {
    pub(crate) fn validate_subset(
        &self,
        authorization: &EnabledAuthorization,
    ) -> Result<(), BridgeCodecError> {
        validate_priority_mask(self.allowed_priority_mask)?;
        if self.allowed_priority_mask & !authorization.allowed_priority_mask != 0 {
            return Err(BridgeCodecError::Invalid("local priority widening"));
        }
        let allowed = authorization.topics.iter().collect::<BTreeSet<_>>();
        if self.topics.iter().any(|topic| !allowed.contains(topic)) {
            return Err(BridgeCodecError::Invalid("local topic widening"));
        }
        Ok(())
    }
}

pub(crate) fn priority_allowed(mask: u8, priority: Priority) -> bool {
    mask & (1 << priority as u8) != 0
}

fn hash_input(domain: &[u8], exact: &[u8]) -> [u8; 32] {
    let mut input = Vec::new();
    input.extend_from_slice(&AUTHORIZATION_FORMAT.to_be_bytes());
    input.extend_from_slice(&SEMANTIC_PROTOCOL.to_be_bytes());
    input.extend_from_slice(&COMPLETE_SUITE.to_be_bytes());
    input.extend_from_slice(exact);
    hash_domain(domain, &input)
}

impl BridgeHop {
    fn validate(&self) -> Result<(), BridgeCodecError> {
        if self.from_scope == self.to_scope
            || self.from_route_epoch == 0
            || self.to_route_epoch == 0
        {
            return Err(BridgeCodecError::Invalid("bridge hop edge"));
        }
        validate_hybrid_signature(&self.bridge_hybrid_signature)
    }

    fn encode_with_index(&self, index: u8, out: &mut Vec<u8>) -> Result<(), BridgeCodecError> {
        self.validate()?;
        out.push(index);
        out.extend_from_slice(&self.authorization_envelope_id);
        out.extend_from_slice(&self.bridge_node_id);
        push_text(out, self.from_scope.as_str())?;
        out.extend_from_slice(&self.from_route_epoch.to_be_bytes());
        push_text(out, self.to_scope.as_str())?;
        out.extend_from_slice(&self.to_route_epoch.to_be_bytes());
        out.extend_from_slice(&self.cumulative_custody_age_ms.to_be_bytes());
        out.push(u8::from(self.age_continuity_unknown));
        out.extend_from_slice(&self.previous_hop_digest);
        out.extend_from_slice(&self.bridge_hybrid_signature);
        Ok(())
    }

    fn decode_with_index(
        reader: &mut Reader<'_>,
        expected_index: u8,
    ) -> Result<Self, BridgeCodecError> {
        if reader.u8()? != expected_index {
            return Err(BridgeCodecError::Invalid("hop index"));
        }
        let value = Self {
            authorization_envelope_id: reader.array()?,
            bridge_node_id: reader.array()?,
            from_scope: Scope::new(reader.text()?)
                .map_err(|_| BridgeCodecError::Invalid("hop source scope"))?,
            from_route_epoch: reader.u64()?,
            to_scope: Scope::new(reader.text()?)
                .map_err(|_| BridgeCodecError::Invalid("hop target scope"))?,
            to_route_epoch: reader.u64()?,
            cumulative_custody_age_ms: reader.u64()?,
            age_continuity_unknown: reader.boolean()?,
            previous_hop_digest: reader.array()?,
            bridge_hybrid_signature: reader.take(HYBRID_SIGNATURE_BYTES)?.to_vec(),
        };
        value.validate()?;
        Ok(value)
    }

    pub(crate) fn digest(&self, index: u8) -> Result<[u8; 32], BridgeCodecError> {
        let mut exact = Vec::new();
        self.encode_with_index(index, &mut exact)?;
        Ok(hash_domain(HOP_ID_DOMAIN, &exact))
    }
}

impl BridgeRoute {
    fn prefix_without_route_id(&self) -> Result<Vec<u8>, BridgeCodecError> {
        if self.source_route_descriptor.is_empty()
            || self.source_route_descriptor.len() > MAX_SOURCE_DESCRIPTOR_BYTES
            || self.hops.is_empty()
            || self.hops.len() > MAX_HOPS
            || self.origin_route_epoch == 0
            || self.current_route_epoch == 0
        {
            return Err(BridgeCodecError::Invalid("route bounds"));
        }
        let mut out = Vec::new();
        out.extend_from_slice(&WRAPPER_FORMAT.to_be_bytes());
        out.extend_from_slice(&self.mission_id);
        out.extend_from_slice(&self.origin_envelope_id);
        out.extend_from_slice(&self.source_item_id);
        push_text(&mut out, self.origin_scope.as_str())?;
        out.extend_from_slice(&self.origin_route_epoch.to_be_bytes());
        push_text(&mut out, self.current_scope.as_str())?;
        out.extend_from_slice(&self.current_route_epoch.to_be_bytes());
        push_u32_bytes(&mut out, &self.source_route_descriptor)?;
        out.extend_from_slice(&Sha256::digest(&self.source_route_descriptor));
        out.push(u8::try_from(self.hops.len()).map_err(|_| BridgeCodecError::SizeLimit)?);
        for (offset, hop) in self.hops.iter().enumerate() {
            hop.encode_with_index(
                u8::try_from(offset + 1).map_err(|_| BridgeCodecError::SizeLimit)?,
                &mut out,
            )?;
        }
        Ok(out)
    }

    pub(crate) fn compute_route_id(&self) -> Result<[u8; 32], BridgeCodecError> {
        Ok(hash_domain(
            ROUTE_ID_DOMAIN,
            &self.prefix_without_route_id()?,
        ))
    }

    pub(crate) fn encode(&self) -> Result<Vec<u8>, BridgeCodecError> {
        self.validate_structure()?;
        let mut out = self.prefix_without_route_id()?;
        out.extend_from_slice(&self.bridge_route_id);
        if out.len() > MAX_WRAPPER_PLAINTEXT_BYTES {
            return Err(BridgeCodecError::SizeLimit);
        }
        Ok(out)
    }

    pub(crate) fn decode(bytes: &[u8]) -> Result<Self, BridgeCodecError> {
        if bytes.len() > MAX_WRAPPER_PLAINTEXT_BYTES {
            return Err(BridgeCodecError::SizeLimit);
        }
        let mut reader = Reader::new(bytes);
        if reader.u16()? != WRAPPER_FORMAT {
            return Err(BridgeCodecError::Invalid("route format"));
        }
        let mission_id = reader.array()?;
        let origin_envelope_id = reader.array()?;
        let source_item_id = reader.array()?;
        let origin_scope =
            Scope::new(reader.text()?).map_err(|_| BridgeCodecError::Invalid("origin scope"))?;
        let origin_route_epoch = reader.u64()?;
        let current_scope =
            Scope::new(reader.text()?).map_err(|_| BridgeCodecError::Invalid("current scope"))?;
        let current_route_epoch = reader.u64()?;
        let source_route_descriptor = reader.u32_bytes(MAX_SOURCE_DESCRIPTOR_BYTES)?.to_vec();
        let descriptor_hash: [u8; 32] = reader.array()?;
        let expected_descriptor_hash: [u8; 32] = Sha256::digest(&source_route_descriptor).into();
        if descriptor_hash != expected_descriptor_hash {
            return Err(BridgeCodecError::Invalid("source descriptor digest"));
        }
        let hop_count = usize::from(reader.u8()?);
        if hop_count == 0 || hop_count > MAX_HOPS {
            return Err(BridgeCodecError::Invalid("hop count"));
        }
        let mut hops = Vec::with_capacity(hop_count);
        for offset in 0..hop_count {
            hops.push(BridgeHop::decode_with_index(
                &mut reader,
                u8::try_from(offset + 1).map_err(|_| BridgeCodecError::SizeLimit)?,
            )?);
        }
        let bridge_route_id = reader.array()?;
        reader.finish()?;
        let value = Self {
            mission_id,
            origin_envelope_id,
            source_item_id,
            origin_scope,
            origin_route_epoch,
            current_scope,
            current_route_epoch,
            source_route_descriptor,
            hops,
            bridge_route_id,
        };
        value.validate_structure()?;
        Ok(value)
    }

    pub(crate) fn validate_structure(&self) -> Result<(), BridgeCodecError> {
        if self.bridge_route_id != self.compute_route_id()? {
            return Err(BridgeCodecError::Invalid("route identifier"));
        }
        let mut scopes = BTreeSet::new();
        scopes.insert(self.origin_scope.clone());
        let mut expected_scope = &self.origin_scope;
        let mut expected_epoch = self.origin_route_epoch;
        let mut expected_previous = [0u8; 32];
        let mut prior_age = 0u64;
        let mut prior_unknown = false;
        for (offset, hop) in self.hops.iter().enumerate() {
            let index = u8::try_from(offset + 1).map_err(|_| BridgeCodecError::SizeLimit)?;
            hop.validate()?;
            if &hop.from_scope != expected_scope
                || hop.from_route_epoch != expected_epoch
                || hop.previous_hop_digest != expected_previous
                || hop.cumulative_custody_age_ms < prior_age
                || (prior_unknown && !hop.age_continuity_unknown)
                || !scopes.insert(hop.to_scope.clone())
            {
                return Err(BridgeCodecError::Invalid("hop continuity"));
            }
            expected_previous = hop.digest(index)?;
            expected_scope = &hop.to_scope;
            expected_epoch = hop.to_route_epoch;
            prior_age = hop.cumulative_custody_age_ms;
            prior_unknown = hop.age_continuity_unknown;
        }
        if expected_scope != &self.current_scope || expected_epoch != self.current_route_epoch {
            return Err(BridgeCodecError::Invalid("current route endpoint"));
        }
        if self.prefix_without_route_id()?.len().saturating_add(32) > MAX_WRAPPER_PLAINTEXT_BYTES {
            return Err(BridgeCodecError::SizeLimit);
        }
        Ok(())
    }

    /// Verifies the complete authority-controlled path without relying on any
    /// bridge node's private local narrowing configuration.
    pub(crate) fn validate_authority_path(
        &self,
        topic: &Topic,
        priority: Priority,
        authorizations: &BTreeMap<[u8; 32], AuthorizationEnvelope>,
        active_authorization_ids: &BTreeMap<[u8; 32], [u8; 32]>,
    ) -> Result<(), BridgeCodecError> {
        self.validate_structure()?;
        for hop in &self.hops {
            let record = authorizations
                .get(&hop.authorization_envelope_id)
                .ok_or(BridgeCodecError::Invalid("missing authorization"))?;
            if record.envelope_id != hop.authorization_envelope_id {
                return Err(BridgeCodecError::Invalid("authorization identifier"));
            }
            let authorization = &record.authorization;
            authorization.validate()?;
            if active_authorization_ids.get(&authorization.authorization_key)
                != Some(&record.envelope_id)
            {
                return Err(BridgeCodecError::Invalid("superseded authorization"));
            }
            let enabled = authorization
                .enabled
                .as_ref()
                .ok_or(BridgeCodecError::Invalid("disabled authorization"))?;
            if authorization.mission_id != self.mission_id
                || authorization.bridge_node_id != hop.bridge_node_id
                || authorization.source_scope != hop.from_scope
                || authorization.target_scope != hop.to_scope
                || enabled.source_route_epoch != hop.from_route_epoch
                || enabled.target_route_epoch != hop.to_route_epoch
                || usize::from(enabled.max_total_hops) < self.hops.len()
                || enabled.topics.binary_search(topic).is_err()
                || !priority_allowed(enabled.allowed_priority_mask, priority)
            {
                return Err(BridgeCodecError::Invalid("authorization policy"));
            }
        }
        Ok(())
    }

    /// Applies this node's narrowing rule to one newly appended hop after the
    /// authority path itself has validated. It can never authorize a prior hop
    /// or widen the exact authority object referenced by `hop_index`.
    pub(crate) fn validate_local_new_hop(
        &self,
        hop_index: usize,
        topic: &Topic,
        priority: Priority,
        authorizations: &BTreeMap<[u8; 32], AuthorizationEnvelope>,
        active_authorization_ids: &BTreeMap<[u8; 32], [u8; 32]>,
        local: &BridgeNarrowing,
    ) -> Result<(), BridgeCodecError> {
        self.validate_authority_path(topic, priority, authorizations, active_authorization_ids)?;
        let hop = self
            .hops
            .get(hop_index)
            .ok_or(BridgeCodecError::Invalid("hop index"))?;
        let enabled = authorizations
            .get(&hop.authorization_envelope_id)
            .and_then(|record| record.authorization.enabled.as_ref())
            .ok_or(BridgeCodecError::Invalid("missing authorization"))?;
        local.validate_subset(enabled)?;
        if (!local.topics.is_empty() && !local.topics.contains(topic))
            || !priority_allowed(local.allowed_priority_mask, priority)
        {
            return Err(BridgeCodecError::Invalid("local bridge policy"));
        }
        Ok(())
    }

    pub(crate) fn hop_signature_digest(&self, index: usize) -> Result<[u8; 32], BridgeCodecError> {
        let hop = self
            .hops
            .get(index)
            .ok_or(BridgeCodecError::Invalid("hop index"))?;
        let hop_index = u8::try_from(index + 1).map_err(|_| BridgeCodecError::SizeLimit)?;
        let mut input = Vec::new();
        input.extend_from_slice(&WRAPPER_FORMAT.to_be_bytes());
        input.extend_from_slice(&SEMANTIC_PROTOCOL.to_be_bytes());
        input.extend_from_slice(&COMPLETE_SUITE.to_be_bytes());
        input.extend_from_slice(&self.mission_id);
        input.extend_from_slice(&self.origin_envelope_id);
        input.extend_from_slice(&self.source_item_id);
        input.extend_from_slice(&Sha256::digest(&self.source_route_descriptor));
        input.push(hop_index);
        input.extend_from_slice(&hop.authorization_envelope_id);
        input.extend_from_slice(&hop.bridge_node_id);
        push_text(&mut input, hop.from_scope.as_str())?;
        input.extend_from_slice(&hop.from_route_epoch.to_be_bytes());
        push_text(&mut input, hop.to_scope.as_str())?;
        input.extend_from_slice(&hop.to_route_epoch.to_be_bytes());
        input.extend_from_slice(&hop.cumulative_custody_age_ms.to_be_bytes());
        input.push(u8::from(hop.age_continuity_unknown));
        input.extend_from_slice(&hop.previous_hop_digest);
        Ok(hash_domain(HOP_SIGNATURE_DOMAIN, &input))
    }
}

pub(crate) fn encode_public_header(
    magic: &[u8; 8],
    selector: [u8; 16],
    protected_length: usize,
) -> Result<[u8; BRIDGE_PUBLIC_HEADER_BYTES], BridgeCodecError> {
    let maximum = if magic == AUTHORIZATION_MAGIC {
        MAX_AUTHORIZATION_PROTECTED_BYTES
    } else if magic == WRAPPER_MAGIC {
        MAX_WRAPPER_PROTECTED_BYTES
    } else {
        return Err(BridgeCodecError::Invalid("public header magic"));
    };
    if protected_length < 16 || protected_length > maximum {
        return Err(BridgeCodecError::Invalid("public header"));
    }
    let mut out = [0u8; BRIDGE_PUBLIC_HEADER_BYTES];
    out[..8].copy_from_slice(magic);
    out[8..10].copy_from_slice(&1u16.to_be_bytes());
    out[10..12].copy_from_slice(&SEMANTIC_PROTOCOL.to_be_bytes());
    out[12..14].copy_from_slice(&COMPLETE_SUITE.to_be_bytes());
    out[14..30].copy_from_slice(&selector);
    out[30..34].copy_from_slice(
        &u32::try_from(protected_length)
            .map_err(|_| BridgeCodecError::SizeLimit)?
            .to_be_bytes(),
    );
    Ok(out)
}

pub(crate) fn decode_public_header(bytes: &[u8]) -> Result<BridgePublicHeader, BridgeCodecError> {
    if bytes.len() != BRIDGE_PUBLIC_HEADER_BYTES {
        return Err(BridgeCodecError::Invalid("public header length"));
    }
    let kind = if &bytes[..8] == AUTHORIZATION_MAGIC {
        BridgeOuterKind::Authorization
    } else if &bytes[..8] == WRAPPER_MAGIC {
        BridgeOuterKind::Wrapper
    } else {
        return Err(BridgeCodecError::Invalid("public header magic"));
    };
    if u16::from_be_bytes(
        bytes[8..10]
            .try_into()
            .map_err(|_| BridgeCodecError::Truncated)?,
    ) != 1
        || u16::from_be_bytes(
            bytes[10..12]
                .try_into()
                .map_err(|_| BridgeCodecError::Truncated)?,
        ) != SEMANTIC_PROTOCOL
        || u16::from_be_bytes(
            bytes[12..14]
                .try_into()
                .map_err(|_| BridgeCodecError::Truncated)?,
        ) != COMPLETE_SUITE
    {
        return Err(BridgeCodecError::Invalid("public header profile"));
    }
    let selector = bytes[14..30]
        .try_into()
        .map_err(|_| BridgeCodecError::Truncated)?;
    let protected_length = usize::try_from(u32::from_be_bytes(
        bytes[30..34]
            .try_into()
            .map_err(|_| BridgeCodecError::Truncated)?,
    ))
    .map_err(|_| BridgeCodecError::SizeLimit)?;
    let expected = match kind {
        BridgeOuterKind::Authorization => AUTHORIZATION_MAGIC,
        BridgeOuterKind::Wrapper => WRAPPER_MAGIC,
    };
    let canonical = encode_public_header(expected, selector, protected_length)?;
    if bytes != canonical {
        return Err(BridgeCodecError::Invalid("public header encoding"));
    }
    Ok(BridgePublicHeader {
        kind,
        selector,
        protected_length,
    })
}

pub(crate) fn exact_object_id(stable_bytes: &[u8]) -> [u8; 32] {
    Sha256::digest(stable_bytes).into()
}

/// Validates one independently contiguous semantic-v2 bridge-control chain and returns
/// the latest exact envelope identity for each authorization key.
#[cfg(test)]
pub(crate) fn validate_authorization_chain(
    records: &[AuthorizationEnvelope],
) -> Result<BTreeMap<[u8; 32], [u8; 32]>, BridgeCodecError> {
    let first = records
        .first()
        .ok_or(BridgeCodecError::Invalid("empty authorization chain"))?;
    let mission = first.authorization.mission_id;
    let authority = first.authorization.authority_id;
    let mut previous = None;
    let mut expected_sequence = 1u64;
    let mut generations = BTreeMap::<[u8; 32], u64>::new();
    let mut active = BTreeMap::new();
    for record in records {
        let authorization = &record.authorization;
        authorization.validate()?;
        if authorization.mission_id != mission
            || authorization.authority_id != authority
            || authorization.control_sequence != expected_sequence
            || authorization.previous_control_id != previous
        {
            return Err(BridgeCodecError::Invalid("authorization chain"));
        }
        if generations
            .get(&authorization.authorization_key)
            .is_some_and(|prior| *prior >= authorization.generation)
        {
            return Err(BridgeCodecError::Invalid(
                "authorization generation rollback",
            ));
        }
        generations.insert(authorization.authorization_key, authorization.generation);
        active.insert(authorization.authorization_key, record.envelope_id);
        previous = Some(record.envelope_id);
        expected_sequence = expected_sequence
            .checked_add(1)
            .ok_or(BridgeCodecError::Invalid("authorization sequence overflow"))?;
    }
    Ok(active)
}

fn push_optional_id(out: &mut Vec<u8>, value: Option<[u8; 32]>) {
    match value {
        Some(value) => {
            out.push(1);
            out.extend_from_slice(&value);
        }
        None => out.push(0),
    }
}

fn push_text(out: &mut Vec<u8>, value: &str) -> Result<(), BridgeCodecError> {
    let len = u16::try_from(value.len()).map_err(|_| BridgeCodecError::SizeLimit)?;
    out.extend_from_slice(&len.to_be_bytes());
    out.extend_from_slice(value.as_bytes());
    Ok(())
}

fn push_u32_bytes(out: &mut Vec<u8>, value: &[u8]) -> Result<(), BridgeCodecError> {
    let len = u32::try_from(value.len()).map_err(|_| BridgeCodecError::SizeLimit)?;
    out.extend_from_slice(&len.to_be_bytes());
    out.extend_from_slice(value);
    Ok(())
}

struct Reader<'a> {
    bytes: &'a [u8],
    offset: usize,
}

impl<'a> Reader<'a> {
    fn new(bytes: &'a [u8]) -> Self {
        Self { bytes, offset: 0 }
    }

    fn take(&mut self, len: usize) -> Result<&'a [u8], BridgeCodecError> {
        let end = self
            .offset
            .checked_add(len)
            .ok_or(BridgeCodecError::SizeLimit)?;
        let value = self
            .bytes
            .get(self.offset..end)
            .ok_or(BridgeCodecError::Truncated)?;
        self.offset = end;
        Ok(value)
    }

    fn array<const N: usize>(&mut self) -> Result<[u8; N], BridgeCodecError> {
        self.take(N)?
            .try_into()
            .map_err(|_| BridgeCodecError::Truncated)
    }

    fn u8(&mut self) -> Result<u8, BridgeCodecError> {
        Ok(self.take(1)?[0])
    }

    fn u16(&mut self) -> Result<u16, BridgeCodecError> {
        Ok(u16::from_be_bytes(self.array()?))
    }

    fn u32(&mut self) -> Result<u32, BridgeCodecError> {
        Ok(u32::from_be_bytes(self.array()?))
    }

    fn u64(&mut self) -> Result<u64, BridgeCodecError> {
        Ok(u64::from_be_bytes(self.array()?))
    }

    fn boolean(&mut self) -> Result<bool, BridgeCodecError> {
        match self.u8()? {
            0 => Ok(false),
            1 => Ok(true),
            _ => Err(BridgeCodecError::Invalid("boolean")),
        }
    }

    fn optional_id(&mut self) -> Result<Option<[u8; 32]>, BridgeCodecError> {
        match self.u8()? {
            0 => Ok(None),
            1 => self.array().map(Some),
            _ => Err(BridgeCodecError::Invalid("optional identifier")),
        }
    }

    fn text(&mut self) -> Result<String, BridgeCodecError> {
        let len = usize::from(self.u16()?);
        let bytes = self.take(len)?;
        std::str::from_utf8(bytes)
            .map(str::to_owned)
            .map_err(|_| BridgeCodecError::Invalid("UTF-8"))
    }

    fn u32_bytes(&mut self, maximum: usize) -> Result<&'a [u8], BridgeCodecError> {
        let len = usize::try_from(self.u32()?).map_err(|_| BridgeCodecError::SizeLimit)?;
        if len > maximum {
            return Err(BridgeCodecError::SizeLimit);
        }
        self.take(len)
    }

    fn finish(self) -> Result<(), BridgeCodecError> {
        if self.offset == self.bytes.len() {
            Ok(())
        } else {
            Err(BridgeCodecError::TrailingBytes)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn signature(seed: u8) -> Vec<u8> {
        let mut value = vec![seed; HYBRID_SIGNATURE_BYTES];
        value[..2].copy_from_slice(&64u16.to_be_bytes());
        value[66..70].copy_from_slice(&3_309u32.to_be_bytes());
        value
    }

    fn scope(value: &str) -> Scope {
        Scope::new(value).unwrap()
    }

    fn topic(value: &str) -> Topic {
        Topic::new(value).unwrap()
    }

    fn authorization(
        sequence: u64,
        previous: Option<[u8; 32]>,
        generation: u64,
        enabled: bool,
    ) -> BridgeAuthorization {
        let mission_id = [1; 32];
        let bridge_node_id = [3; 32];
        let source_scope = scope("mission/alpha");
        let target_scope = scope("mission/bravo");
        BridgeAuthorization {
            mission_id,
            authority_id: [2; 32],
            control_sequence: sequence,
            previous_control_id: previous,
            authorization_key: bridge_authorization_key(
                &mission_id,
                &bridge_node_id,
                &source_scope,
                &target_scope,
            )
            .unwrap(),
            generation,
            bridge_node_id,
            source_scope,
            target_scope,
            enabled: enabled.then(|| EnabledAuthorization {
                source_route_epoch: 7,
                target_route_epoch: 9,
                source_route_commitment: [4; 32],
                target_route_commitment: [5; 32],
                allowed_priority_mask: 0b1110,
                max_total_hops: 4,
                topics: vec![topic("orders"), topic("position")],
                bridge_credential: vec![6; 128],
                authority_credential_signature: signature(7),
            }),
            authority_control_signature: signature(8),
        }
    }

    fn one_hop_route() -> BridgeRoute {
        let hop = BridgeHop {
            authorization_envelope_id: [0x21; 32],
            bridge_node_id: [3; 32],
            from_scope: scope("mission/alpha"),
            from_route_epoch: 7,
            to_scope: scope("mission/bravo"),
            to_route_epoch: 9,
            cumulative_custody_age_ms: 500,
            age_continuity_unknown: false,
            previous_hop_digest: [0; 32],
            bridge_hybrid_signature: signature(9),
        };
        let mut route = BridgeRoute {
            mission_id: [1; 32],
            origin_envelope_id: [0x31; 32],
            source_item_id: [0x32; 32],
            origin_scope: scope("mission/alpha"),
            origin_route_epoch: 7,
            current_scope: scope("mission/bravo"),
            current_route_epoch: 9,
            source_route_descriptor: b"exact verified format-2 route plaintext".to_vec(),
            hops: vec![hop],
            bridge_route_id: [0; 32],
        };
        route.bridge_route_id = route.compute_route_id().unwrap();
        route
    }

    #[test]
    fn authorization_round_trip_is_exact_and_fail_closed() {
        let value = authorization(1, None, 1, true);
        value.validate().unwrap();
        let encoded = value.encode().unwrap();
        assert_eq!(BridgeAuthorization::decode(&encoded).unwrap(), value);
        assert_eq!(
            BridgeAuthorization::decode(&encoded)
                .unwrap()
                .encode()
                .unwrap(),
            encoded
        );
        assert_eq!(value.control_signature_digest().unwrap().len(), 32);

        let mut trailing = encoded.clone();
        trailing.push(0);
        assert_eq!(
            BridgeAuthorization::decode(&trailing),
            Err(BridgeCodecError::TrailingBytes)
        );
        assert_eq!(
            BridgeAuthorization::decode(&encoded[..encoded.len() - 1]),
            Err(BridgeCodecError::Truncated)
        );
        let mut wrong_key = value.clone();
        wrong_key.authorization_key[0] ^= 1;
        assert!(wrong_key.validate().is_err());
        let mut bad_topics = value.clone();
        bad_topics.enabled.as_mut().unwrap().topics.reverse();
        assert!(bad_topics.validate().is_err());
    }

    #[test]
    fn disabled_record_has_no_conditional_policy_and_chain_rejects_rollback() {
        let first = AuthorizationEnvelope {
            envelope_id: [0x11; 32],
            authorization: authorization(1, None, 1, true),
        };
        let second = AuthorizationEnvelope {
            envelope_id: [0x12; 32],
            authorization: authorization(2, Some(first.envelope_id), 2, false),
        };
        let active = validate_authorization_chain(&[first.clone(), second.clone()]).unwrap();
        assert_eq!(
            active.get(&first.authorization.authorization_key),
            Some(&second.envelope_id)
        );
        let encoded = second.authorization.encode().unwrap();
        assert_eq!(
            BridgeAuthorization::decode(&encoded).unwrap(),
            second.authorization
        );

        let mut rollback = second;
        rollback.authorization.generation = 1;
        assert!(validate_authorization_chain(&[first.clone(), rollback]).is_err());
        let mut fork = first.clone();
        fork.authorization.control_sequence = 2;
        fork.authorization.previous_control_id = Some([0xff; 32]);
        assert!(validate_authorization_chain(&[first, fork]).is_err());
    }

    #[test]
    fn local_rules_can_only_narrow_the_authority_filter() {
        let authorization = authorization(1, None, 1, true);
        let enabled = authorization.enabled.as_ref().unwrap();
        BridgeNarrowing {
            topics: BTreeSet::from([topic("orders")]),
            allowed_priority_mask: 0b1100,
        }
        .validate_subset(enabled)
        .unwrap();
        assert!(
            BridgeNarrowing {
                topics: BTreeSet::from([topic("outside")]),
                allowed_priority_mask: 0b1100,
            }
            .validate_subset(enabled)
            .is_err()
        );
        assert!(
            BridgeNarrowing {
                topics: BTreeSet::new(),
                allowed_priority_mask: 0b1111,
            }
            .validate_subset(enabled)
            .is_err()
        );
    }

    #[test]
    fn route_round_trip_binds_descriptor_path_and_exact_route_id() {
        let route = one_hop_route();
        route.validate_structure().unwrap();
        let encoded = route.encode().unwrap();
        assert_eq!(BridgeRoute::decode(&encoded).unwrap(), route);
        assert_eq!(route.hop_signature_digest(0).unwrap().len(), 32);

        let mut tampered = route.clone();
        tampered.source_route_descriptor[0] ^= 1;
        assert!(tampered.validate_structure().is_err());
        let mut wrong_previous = route.clone();
        wrong_previous.hops[0].previous_hop_digest[0] = 1;
        wrong_previous.bridge_route_id = wrong_previous.compute_route_id().unwrap();
        assert!(wrong_previous.validate_structure().is_err());
    }

    #[test]
    fn authorization_path_checks_active_policy_and_local_subset() {
        let route = one_hop_route();
        let auth = authorization(1, None, 1, true);
        let record = AuthorizationEnvelope {
            envelope_id: route.hops[0].authorization_envelope_id,
            authorization: auth.clone(),
        };
        let records = BTreeMap::from([(record.envelope_id, record.clone())]);
        let active = BTreeMap::from([(auth.authorization_key, record.envelope_id)]);
        let local = BridgeNarrowing {
            topics: BTreeSet::from([topic("orders")]),
            allowed_priority_mask: 0b1100,
        };
        route
            .validate_authority_path(&topic("orders"), Priority::Immediate, &records, &active)
            .unwrap();
        route
            .validate_local_new_hop(
                0,
                &topic("orders"),
                Priority::Immediate,
                &records,
                &active,
                &local,
            )
            .unwrap();
        assert!(
            route
                .validate_local_new_hop(
                    0,
                    &topic("position"),
                    Priority::Immediate,
                    &records,
                    &active,
                    &local,
                )
                .is_err()
        );
        assert!(
            route
                .validate_local_new_hop(
                    0,
                    &topic("orders"),
                    Priority::Routine,
                    &records,
                    &active,
                    &local,
                )
                .is_err()
        );
        let superseded = BTreeMap::from([(auth.authorization_key, [0xee; 32])]);
        assert!(
            route
                .validate_local_new_hop(
                    0,
                    &topic("orders"),
                    Priority::Immediate,
                    &records,
                    &superseded,
                    &local,
                )
                .is_err()
        );
    }

    #[test]
    fn loops_ninth_hop_age_regression_and_unknown_reset_are_rejected() {
        let mut route = one_hop_route();
        let prior = route.hops[0].digest(1).unwrap();
        route.hops.push(BridgeHop {
            authorization_envelope_id: [0x22; 32],
            bridge_node_id: [4; 32],
            from_scope: scope("mission/bravo"),
            from_route_epoch: 9,
            to_scope: scope("mission/alpha"),
            to_route_epoch: 7,
            cumulative_custody_age_ms: 600,
            age_continuity_unknown: false,
            previous_hop_digest: prior,
            bridge_hybrid_signature: signature(10),
        });
        route.current_scope = scope("mission/alpha");
        route.current_route_epoch = 7;
        route.bridge_route_id = route.compute_route_id().unwrap();
        assert!(route.validate_structure().is_err());

        let mut too_many = one_hop_route();
        while too_many.hops.len() <= MAX_HOPS {
            too_many.hops.push(too_many.hops[0].clone());
        }
        assert!(too_many.validate_structure().is_err());

        let mut unknown_reset = one_hop_route();
        unknown_reset.hops[0].age_continuity_unknown = true;
        let prior = unknown_reset.hops[0].digest(1).unwrap();
        unknown_reset.hops.push(BridgeHop {
            authorization_envelope_id: [0x23; 32],
            bridge_node_id: [4; 32],
            from_scope: scope("mission/bravo"),
            from_route_epoch: 9,
            to_scope: scope("mission/charlie"),
            to_route_epoch: 10,
            cumulative_custody_age_ms: 400,
            age_continuity_unknown: false,
            previous_hop_digest: prior,
            bridge_hybrid_signature: signature(11),
        });
        unknown_reset.current_scope = scope("mission/charlie");
        unknown_reset.current_route_epoch = 10;
        unknown_reset.bridge_route_id = unknown_reset.compute_route_id().unwrap();
        assert!(unknown_reset.validate_structure().is_err());
    }

    #[test]
    fn public_headers_are_exact_and_enforce_type_specific_caps() {
        let header = encode_public_header(WRAPPER_MAGIC, [9; 16], 16).unwrap();
        assert_eq!(header.len(), BRIDGE_PUBLIC_HEADER_BYTES);
        assert_eq!(&header[..8], WRAPPER_MAGIC);
        assert_eq!(&header[10..12], &SEMANTIC_PROTOCOL.to_be_bytes());
        assert_eq!(
            decode_public_header(&header).unwrap(),
            BridgePublicHeader {
                kind: BridgeOuterKind::Wrapper,
                selector: [9; 16],
                protected_length: 16,
            }
        );
        assert_eq!(
            decode_public_header(&header)
                .unwrap()
                .total_length()
                .unwrap(),
            50
        );
        let authorization_max = encode_public_header(
            AUTHORIZATION_MAGIC,
            [8; 16],
            MAX_AUTHORIZATION_PROTECTED_BYTES,
        )
        .unwrap();
        assert_eq!(
            decode_public_header(&authorization_max)
                .unwrap()
                .total_length()
                .unwrap(),
            MAX_AUTHORIZATION_TOTAL_BYTES
        );
        let wrapper_max =
            encode_public_header(WRAPPER_MAGIC, [7; 16], MAX_WRAPPER_PROTECTED_BYTES).unwrap();
        assert_eq!(
            decode_public_header(&wrapper_max)
                .unwrap()
                .total_length()
                .unwrap(),
            MAX_WRAPPER_TOTAL_BYTES
        );
        assert!(encode_public_header(AUTHORIZATION_MAGIC, [0; 16], 65_537).is_err());
        assert!(encode_public_header(WRAPPER_MAGIC, [0; 16], 524_289).is_err());
        assert!(encode_public_header(b"NOTMAGIC", [0; 16], 16).is_err());
        let mut wrong_semantic = header;
        wrong_semantic[11] ^= 1;
        assert!(decode_public_header(&wrong_semantic).is_err());
        assert!(decode_public_header(&header[..header.len() - 1]).is_err());
        assert_ne!(exact_object_id(&header), exact_object_id(&[0; 34]));
    }
}
