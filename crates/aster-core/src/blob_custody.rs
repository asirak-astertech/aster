//! Canonical semantic-v8 Blob custody claims and verified claim capability.

use crate::{BlobId, ContentVerifiedBlobEnvelope, CustodySample, Priority};
use core::error::Error;
use core::fmt::{self, Display, Formatter};
use sha2::{Digest, Sha256};

/// Exact byte length of one canonical semantic-v8 Blob custody claim.
pub const BLOB_CUSTODY_CLAIM_V1_BYTES: usize = 208;

const MAGIC: &[u8; 8] = b"ASTRBL08";
const FORMAT_VERSION: u16 = 1;
const SEMANTIC_VERSION: u16 = 8;
const PROFILE_ID: u16 = 3;
const BLOB_LANE_ID: u16 = 4;
const V8_LANE_RECORD_DOMAIN: &[u8] = b"ASTER/v8-lane-record/v1\0";
const CONTACT_ID_DOMAIN: &[u8] = b"ASTER/v8-blob-custody-contact/v1\0";

/// Sanitized semantic-v8 Blob custody claim failure.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum BlobCustodyError {
    /// The fixed-width encoding or one of its closed values is invalid.
    InvalidClaim,
    /// Checked cumulative-age arithmetic overflowed.
    AgeOverflow,
    /// A decoded claim does not match fresh authenticated context.
    ContextMismatch,
}

impl Display for BlobCustodyError {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::InvalidClaim => "invalid Blob custody claim",
            Self::AgeOverflow => "Blob custody age overflow",
            Self::ContextMismatch => "Blob custody claim context mismatch",
        })
    }
}

impl Error for BlobCustodyError {}

/// Receiver of one semantic-v8 Blob source transfer.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
#[repr(u8)]
pub enum BlobCustodyDirectionV1 {
    /// The authenticated session initiator receives the source.
    ToSessionInitiator = 1,
    /// The authenticated session responder receives the source.
    ToSessionResponder = 2,
}

impl BlobCustodyDirectionV1 {
    const fn from_wire(value: u8) -> Result<Self, BlobCustodyError> {
        match value {
            1 => Ok(Self::ToSessionInitiator),
            2 => Ok(Self::ToSessionResponder),
            _ => Err(BlobCustodyError::InvalidClaim),
        }
    }
}

/// Opaque proof that one peer record was authenticated and replay-checked in
/// the semantic-v8 `BlobRangesStreamV1` custody lane domain.
///
/// Construction is core-private. Public callers can receive this value only
/// from `ReferenceAuthenticatedSession::open_blob_custody_frame` after an
/// authenticated profile-3 Blob-lane record open succeeds.
#[derive(Debug, Eq, PartialEq)]
pub struct AuthenticatedBlobCustodyContactV1 {
    semantic_version: u16,
    profile_id: u16,
    session_transcript: [u8; 32],
    transfer_profile_digest: [u8; 32],
    direction: BlobCustodyDirectionV1,
    record_sequence: u64,
    claim_digest: [u8; 32],
    contact_identity: [u8; 32],
}

/// Opaque one-use outbound context from an authenticated semantic-v8,
/// profile-3 Blob session.
///
/// Construction is core-private and the type is deliberately non-`Clone`.
/// Store authorization consumes it so raw session, exchange, direction, and
/// finalization fields cannot independently mint a finite custody claim.
#[derive(Debug, Eq, PartialEq)]
pub struct AuthenticatedBlobCustodySendContextV1 {
    semantic_version: u16,
    profile_id: u16,
    session_transcript: [u8; 32],
    exchange_id: u64,
    direction: BlobCustodyDirectionV1,
    finalization_charge_ms: u64,
}

impl AuthenticatedBlobCustodySendContextV1 {
    pub(crate) const fn from_authenticated_session(
        session_transcript: [u8; 32],
        exchange_id: u64,
        direction: BlobCustodyDirectionV1,
        finalization_charge_ms: u64,
    ) -> Self {
        Self {
            semantic_version: SEMANTIC_VERSION,
            profile_id: PROFILE_ID,
            session_transcript,
            exchange_id,
            direction,
            finalization_charge_ms,
        }
    }

    /// Returns the authenticated semantic version.
    pub const fn semantic_version(&self) -> u16 {
        self.semantic_version
    }

    /// Returns the authenticated Blob transfer profile identifier.
    pub const fn profile_id(&self) -> u16 {
        self.profile_id
    }

    /// Returns the completed authenticated-session transcript identity.
    pub const fn session_transcript(&self) -> [u8; 32] {
        self.session_transcript
    }

    /// Returns the exact exchange bound to this source emission.
    pub const fn exchange_id(&self) -> u64 {
        self.exchange_id
    }

    /// Returns the authenticated outbound receiver direction.
    pub const fn direction(&self) -> BlobCustodyDirectionV1 {
        self.direction
    }

    /// Returns the conservative age contribution authenticated for finalization.
    pub const fn finalization_charge_ms(&self) -> u64 {
        self.finalization_charge_ms
    }
}

/// Opened complete Blob source frame and its optional exact finite authority.
///
/// This name is public because the node mission boundary must carry the exact
/// core-opened result without reconstructing or exposing either component.
/// The authority remains non-`Clone` inside this return shape and can therefore
/// still be consumed exactly once by the receiving Store transaction.
pub type OpenedBlobSourceFrameV1 = (
    Vec<u8>,
    Option<(BlobCustodyClaimV1, AuthenticatedBlobCustodyContactV1)>,
);

impl AuthenticatedBlobCustodyContactV1 {
    pub(crate) fn from_opened_record(
        session_transcript: [u8; 32],
        transfer_profile_digest: [u8; 32],
        direction: BlobCustodyDirectionV1,
        record_sequence: u64,
        claim_digest: [u8; 32],
    ) -> Self {
        let mut hasher = Sha256::new();
        hasher.update(CONTACT_ID_DOMAIN);
        hasher.update(SEMANTIC_VERSION.to_be_bytes());
        hasher.update(PROFILE_ID.to_be_bytes());
        hasher.update(session_transcript);
        hasher.update(transfer_profile_digest);
        hasher.update([direction as u8]);
        hasher.update(record_sequence.to_be_bytes());
        hasher.update(claim_digest);
        Self {
            semantic_version: SEMANTIC_VERSION,
            profile_id: PROFILE_ID,
            session_transcript,
            transfer_profile_digest,
            direction,
            record_sequence,
            claim_digest,
            contact_identity: hasher.finalize().into(),
        }
    }

    /// Returns the authenticated session's selected semantic version.
    pub const fn semantic_version(&self) -> u16 {
        self.semantic_version
    }

    /// Returns the selected Blob-lane transfer profile identifier.
    pub const fn profile_id(&self) -> u16 {
        self.profile_id
    }

    /// Returns the completed authenticated-session transcript identity.
    pub const fn session_transcript(&self) -> [u8; 32] {
        self.session_transcript
    }

    /// Returns the authenticated transfer-profile negotiation digest.
    pub const fn transfer_profile_digest(&self) -> [u8; 32] {
        self.transfer_profile_digest
    }

    /// Returns the receiver direction authenticated by the opened record.
    pub const fn direction(&self) -> BlobCustodyDirectionV1 {
        self.direction
    }

    /// Returns the replay-checked record sequence for this contact.
    pub const fn record_sequence(&self) -> u64 {
        self.record_sequence
    }

    /// Digest of the exact canonical claim plaintext opened by this contact.
    pub const fn claim_digest(&self) -> [u8; 32] {
        self.claim_digest
    }

    /// Returns a non-secret identity of this exact authenticated contact.
    pub const fn contact_identity(&self) -> [u8; 32] {
        self.contact_identity
    }
}

pub(crate) fn blob_custody_lane_record_context(
    transfer_profile_digest: [u8; 32],
    direction: BlobCustodyDirectionV1,
) -> Vec<u8> {
    let mut context = Vec::with_capacity(V8_LANE_RECORD_DOMAIN.len() + 2 + 32 + 2 + 2 + 1);
    context.extend_from_slice(V8_LANE_RECORD_DOMAIN);
    context.extend_from_slice(&SEMANTIC_VERSION.to_be_bytes());
    context.extend_from_slice(&transfer_profile_digest);
    context.extend_from_slice(&BLOB_LANE_ID.to_be_bytes());
    context.extend_from_slice(&PROFILE_ID.to_be_bytes());
    context.push(direction as u8);
    context
}

/// Typed identity of exact stable source-sealed Blob bytes.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct BlobCustodyTransferId([u8; 32]);

impl BlobCustodyTransferId {
    /// Wraps the SHA-256 identity of exact stable source-sealed Blob bytes.
    pub const fn from_exact_hash(bytes: [u8; 32]) -> Self {
        Self(bytes)
    }

    /// Borrows the exact transfer digest.
    pub const fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }
}

/// Canonically decoded but not yet context-verified Blob custody claim.
///
/// Decoding establishes only fixed grammar and arithmetic validity. Callers
/// must not use this value as admission authority.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct BlobCustodyClaimV1 {
    session_transcript: [u8; 32],
    exchange_id: u64,
    direction: BlobCustodyDirectionV1,
    source_transfer_id: BlobCustodyTransferId,
    source_len: u64,
    publication_id: [u8; 32],
    blob_id: BlobId,
    priority: Priority,
    ttl_ms: u64,
    prior_cumulative_age_ms: u64,
    sender_sample: CustodySample,
    hop_delta_ms: u64,
    forwarding_age_ms: u64,
}

impl BlobCustodyClaimV1 {
    /// Creates an outbound claim only from a content-authenticated exact source.
    #[allow(clippy::too_many_arguments)]
    pub fn from_authenticated_source(
        session_transcript: [u8; 32],
        exchange_id: u64,
        direction: BlobCustodyDirectionV1,
        source_transfer_id: BlobCustodyTransferId,
        source: &ContentVerifiedBlobEnvelope,
        exact_source_bytes: &[u8],
        prior_cumulative_age_ms: u64,
        sender_sample: CustodySample,
        hop_delta_ms: u64,
    ) -> Result<Self, BlobCustodyError> {
        source
            .verify_exact_sealed(exact_source_bytes)
            .map_err(|_| BlobCustodyError::ContextMismatch)?;
        if source_transfer_id.as_bytes() != &source.envelope_id() {
            return Err(BlobCustodyError::ContextMismatch);
        }
        let source_len =
            u64::try_from(exact_source_bytes.len()).map_err(|_| BlobCustodyError::InvalidClaim)?;
        let ttl_ms = source.ttl_ms().ok_or(BlobCustodyError::InvalidClaim)?;
        if source_len == 0 || ttl_ms == 0 {
            return Err(BlobCustodyError::InvalidClaim);
        }
        let forwarding_age_ms = prior_cumulative_age_ms
            .checked_add(hop_delta_ms)
            .ok_or(BlobCustodyError::AgeOverflow)?;
        Ok(Self {
            session_transcript,
            exchange_id,
            direction,
            source_transfer_id,
            source_len,
            publication_id: source.item_id(),
            blob_id: source.blob_id(),
            priority: source.priority(),
            ttl_ms,
            prior_cumulative_age_ms,
            sender_sample,
            hop_delta_ms,
            forwarding_age_ms,
        })
    }

    /// Verifies every frame claim field against fresh authenticated context.
    ///
    /// This is the only public path that returns a verified Blob custody
    /// capability. The decoded claim itself remains untrusted.
    #[allow(clippy::too_many_arguments)]
    pub fn verify_authenticated_source(
        &self,
        authenticated_contact: AuthenticatedBlobCustodyContactV1,
        exchange_id: u64,
        source_transfer_id: BlobCustodyTransferId,
        source: &ContentVerifiedBlobEnvelope,
        exact_source_bytes: &[u8],
        prior_cumulative_age_ms: u64,
        sender_sample: CustodySample,
        hop_delta_ms: u64,
    ) -> Result<VerifiedBlobCustodyClaimV1, BlobCustodyError> {
        let expected = Self::from_authenticated_source(
            authenticated_contact.session_transcript,
            exchange_id,
            authenticated_contact.direction,
            source_transfer_id,
            source,
            exact_source_bytes,
            prior_cumulative_age_ms,
            sender_sample,
            hop_delta_ms,
        )?;
        if self.digest() != authenticated_contact.claim_digest || *self != expected {
            return Err(BlobCustodyError::ContextMismatch);
        }
        Ok(VerifiedBlobCustodyClaimV1::from_verified(
            *self,
            authenticated_contact,
        ))
    }

    /// Decodes the one exact fixed-width canonical representation.
    pub fn decode(encoded: &[u8]) -> Result<Self, BlobCustodyError> {
        if encoded.len() != BLOB_CUSTODY_CLAIM_V1_BYTES {
            return Err(BlobCustodyError::InvalidClaim);
        }
        let mut reader = ClaimReader::new(encoded);
        if reader.take::<8>()? != *MAGIC
            || reader.u16()? != FORMAT_VERSION
            || reader.u16()? != SEMANTIC_VERSION
            || reader.u16()? != PROFILE_ID
        {
            return Err(BlobCustodyError::InvalidClaim);
        }
        let session_transcript = reader.take::<32>()?;
        let exchange_id = reader.u64()?;
        let direction = BlobCustodyDirectionV1::from_wire(reader.u8()?)?;
        let source_transfer_id = BlobCustodyTransferId::from_exact_hash(reader.take::<32>()?);
        let source_len = reader.u64()?;
        let publication_id = reader.take::<32>()?;
        let blob_id = BlobId::from_bytes(reader.take::<32>()?);
        let priority = Priority::from_wire(reader.u8()?).ok_or(BlobCustodyError::InvalidClaim)?;
        let ttl_ms = reader.u64()?;
        let prior_cumulative_age_ms = reader.u64()?;
        let sender_sample = CustodySample {
            clock_id: reader.take::<16>()?,
            tick_ms: reader.u64()?,
        };
        let hop_delta_ms = reader.u64()?;
        reader.finish()?;
        if source_len == 0 || ttl_ms == 0 {
            return Err(BlobCustodyError::InvalidClaim);
        }
        let forwarding_age_ms = prior_cumulative_age_ms
            .checked_add(hop_delta_ms)
            .ok_or(BlobCustodyError::AgeOverflow)?;
        Ok(Self {
            session_transcript,
            exchange_id,
            direction,
            source_transfer_id,
            source_len,
            publication_id,
            blob_id,
            priority,
            ttl_ms,
            prior_cumulative_age_ms,
            sender_sample,
            hop_delta_ms,
            forwarding_age_ms,
        })
    }

    /// Returns the exact 208-byte canonical representation.
    pub fn encode(&self) -> [u8; BLOB_CUSTODY_CLAIM_V1_BYTES] {
        let mut output = [0u8; BLOB_CUSTODY_CLAIM_V1_BYTES];
        let mut offset = 0usize;
        macro_rules! append {
            ($bytes:expr) => {{
                let bytes = $bytes;
                let end = offset + bytes.len();
                output[offset..end].copy_from_slice(bytes);
                offset = end;
            }};
        }
        append!(MAGIC);
        append!(&FORMAT_VERSION.to_be_bytes());
        append!(&SEMANTIC_VERSION.to_be_bytes());
        append!(&PROFILE_ID.to_be_bytes());
        append!(&self.session_transcript);
        append!(&self.exchange_id.to_be_bytes());
        append!(&[self.direction as u8]);
        append!(self.source_transfer_id.as_bytes());
        append!(&self.source_len.to_be_bytes());
        append!(&self.publication_id);
        append!(self.blob_id.as_bytes());
        append!(&[self.priority as u8]);
        append!(&self.ttl_ms.to_be_bytes());
        append!(&self.prior_cumulative_age_ms.to_be_bytes());
        append!(&self.sender_sample.clock_id);
        append!(&self.sender_sample.tick_ms.to_be_bytes());
        append!(&self.hop_delta_ms.to_be_bytes());
        debug_assert_eq!(offset, BLOB_CUSTODY_CLAIM_V1_BYTES);
        output
    }

    /// SHA-256 of all 208 canonical bytes.
    pub fn digest(&self) -> [u8; 32] {
        Sha256::digest(self.encode()).into()
    }

    pub const fn session_transcript(&self) -> [u8; 32] {
        self.session_transcript
    }

    pub const fn exchange_id(&self) -> u64 {
        self.exchange_id
    }

    pub const fn direction(&self) -> BlobCustodyDirectionV1 {
        self.direction
    }

    pub const fn source_transfer_id(&self) -> BlobCustodyTransferId {
        self.source_transfer_id
    }

    pub const fn source_len(&self) -> u64 {
        self.source_len
    }

    pub const fn publication_id(&self) -> [u8; 32] {
        self.publication_id
    }

    pub const fn blob_id(&self) -> BlobId {
        self.blob_id
    }

    pub const fn priority(&self) -> Priority {
        self.priority
    }

    pub const fn ttl_ms(&self) -> u64 {
        self.ttl_ms
    }

    pub const fn prior_cumulative_age_ms(&self) -> u64 {
        self.prior_cumulative_age_ms
    }

    pub const fn sender_sample(&self) -> CustodySample {
        self.sender_sample
    }

    pub const fn hop_delta_ms(&self) -> u64 {
        self.hop_delta_ms
    }

    pub const fn forwarding_age_ms(&self) -> u64 {
        self.forwarding_age_ms
    }
}

/// Exact-context-verified Blob custody admission capability.
///
/// Fields and construction are private. `aster-redb-store` can consume this
/// core type without depending on `aster-node`, while raw frame claims cannot
/// construct it.
///
/// Caller-selected claim context plus a content-verified source is not enough
/// to mint admission authority; an opaque capability from a replay-checked
/// semantic-v8 Blob-custody record open is also required:
///
/// ```compile_fail
/// use aster_mesh::{
///     BlobCustodyClaimV1, BlobCustodyDirectionV1, BlobCustodyTransferId,
///     ContentVerifiedBlobEnvelope, CustodySample, VerifiedBlobCustodyClaimV1,
/// };
///
/// fn forge_from_public_values(
///     claim: &BlobCustodyClaimV1,
///     source: &ContentVerifiedBlobEnvelope,
///     exact_source_bytes: &[u8],
/// ) -> VerifiedBlobCustodyClaimV1 {
///     claim.verify_authenticated_source(
///         [0x11; 32],
///         7,
///         BlobCustodyDirectionV1::ToSessionResponder,
///         BlobCustodyTransferId::from_exact_hash(source.envelope_id()),
///         source,
///         exact_source_bytes,
///         0,
///         CustodySample { clock_id: [0x22; 16], tick_ms: 9 },
///         1,
///     ).unwrap()
/// }
/// ```
///
/// Nor can a caller manufacture the required contact capability:
///
/// ```compile_fail
/// use aster_mesh::{AuthenticatedBlobCustodyContactV1, BlobCustodyDirectionV1};
///
/// let forged = AuthenticatedBlobCustodyContactV1 {
///     semantic_version: 8,
///     profile_id: 3,
///     session_transcript: [0x11; 32],
///     transfer_profile_digest: [0x22; 32],
///     direction: BlobCustodyDirectionV1::ToSessionResponder,
///     record_sequence: 0,
///     claim_digest: [0x44; 32],
///     contact_identity: [0x33; 32],
/// };
/// ```
///
/// The exact-open authority is linear rather than cloneable:
///
/// ```compile_fail
/// use aster_mesh::AuthenticatedBlobCustodyContactV1;
///
/// fn duplicate(
///     contact: AuthenticatedBlobCustodyContactV1,
/// ) -> (AuthenticatedBlobCustodyContactV1, AuthenticatedBlobCustodyContactV1) {
///     (contact, contact)
/// }
/// ```
#[derive(Debug, Eq, PartialEq)]
pub struct VerifiedBlobCustodyClaimV1 {
    claim: BlobCustodyClaimV1,
    digest: [u8; 32],
    authenticated_contact: AuthenticatedBlobCustodyContactV1,
}

impl VerifiedBlobCustodyClaimV1 {
    fn from_verified(
        claim: BlobCustodyClaimV1,
        authenticated_contact: AuthenticatedBlobCustodyContactV1,
    ) -> Self {
        let digest = claim.digest();
        Self {
            claim,
            digest,
            authenticated_contact,
        }
    }

    /// Digest of the exact raw claim that was verified.
    pub const fn digest(&self) -> [u8; 32] {
        self.digest
    }

    pub const fn source_transfer_id(&self) -> BlobCustodyTransferId {
        self.claim.source_transfer_id
    }

    pub const fn source_len(&self) -> u64 {
        self.claim.source_len
    }

    pub const fn publication_id(&self) -> [u8; 32] {
        self.claim.publication_id
    }

    pub const fn blob_id(&self) -> BlobId {
        self.claim.blob_id
    }

    pub const fn priority(&self) -> Priority {
        self.claim.priority
    }

    pub const fn ttl_ms(&self) -> u64 {
        self.claim.ttl_ms
    }

    pub const fn forwarding_age_ms(&self) -> u64 {
        self.claim.forwarding_age_ms
    }

    /// Non-secret identity of the exact authenticated, replay-checked contact
    /// record that authorized verification.
    pub const fn contact_identity(&self) -> [u8; 32] {
        self.authenticated_contact.contact_identity
    }
}

struct ClaimReader<'a> {
    bytes: &'a [u8],
    offset: usize,
}

impl<'a> ClaimReader<'a> {
    const fn new(bytes: &'a [u8]) -> Self {
        Self { bytes, offset: 0 }
    }

    fn take<const N: usize>(&mut self) -> Result<[u8; N], BlobCustodyError> {
        let end = self
            .offset
            .checked_add(N)
            .ok_or(BlobCustodyError::InvalidClaim)?;
        let value = self
            .bytes
            .get(self.offset..end)
            .ok_or(BlobCustodyError::InvalidClaim)?
            .try_into()
            .map_err(|_| BlobCustodyError::InvalidClaim)?;
        self.offset = end;
        Ok(value)
    }

    fn u8(&mut self) -> Result<u8, BlobCustodyError> {
        Ok(self.take::<1>()?[0])
    }

    fn u16(&mut self) -> Result<u16, BlobCustodyError> {
        Ok(u16::from_be_bytes(self.take::<2>()?))
    }

    fn u64(&mut self) -> Result<u64, BlobCustodyError> {
        Ok(u64::from_be_bytes(self.take::<8>()?))
    }

    fn finish(self) -> Result<(), BlobCustodyError> {
        if self.offset == self.bytes.len() {
            Ok(())
        } else {
            Err(BlobCustodyError::InvalidClaim)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const MINIMUM_HEX: &str = "41535452424c30380001000800031111111111111111111111111111111111111111111111111111111111111111000000000000000001222222222222222222222222222222222222222222222222222222222222222200000000000000013333333333333333333333333333333333333333333333333333333333333333444444444444444444444444444444444444444444444444444444444444444400000000000000000100000000000000005555555555555555555555555555555500000000000000000000000000000000";
    const MAXIMUM_HEX: &str = "41535452424c3038000100080003ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff02eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeffffffffffffffffddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddcccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc03ffffffffffffffffffffffffffffffffbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbffffffffffffffff0000000000000000";

    fn literal_hex<const N: usize>(encoded: &str) -> [u8; N] {
        assert_eq!(encoded.len(), N * 2, "literal vector width");
        let mut output = [0u8; N];
        for (index, byte) in output.iter_mut().enumerate() {
            *byte = u8::from_str_radix(&encoded[index * 2..index * 2 + 2], 16)
                .expect("literal hexadecimal byte");
        }
        output
    }

    #[test]
    fn canonical_minimum_and_maximum_claim_vectors_are_stable() {
        // Mutation caught: changing any field offset, width, byte order, fixed
        // domain/version/profile value, or digest coverage breaks a literal.
        let minimum = literal_hex::<208>(MINIMUM_HEX);
        let claim = BlobCustodyClaimV1::decode(&minimum).expect("minimum canonical claim");
        assert_eq!(claim.encode(), minimum);
        assert_eq!(claim.session_transcript(), [0x11; 32]);
        assert_eq!(claim.exchange_id(), 0);
        assert_eq!(
            claim.direction(),
            BlobCustodyDirectionV1::ToSessionInitiator
        );
        assert_eq!(claim.source_transfer_id().as_bytes(), &[0x22; 32]);
        assert_eq!(claim.source_len(), 1);
        assert_eq!(claim.publication_id(), [0x33; 32]);
        assert_eq!(claim.blob_id().as_bytes(), &[0x44; 32]);
        assert_eq!(claim.priority(), crate::Priority::Routine);
        assert_eq!(claim.ttl_ms(), 1);
        assert_eq!(claim.prior_cumulative_age_ms(), 0);
        assert_eq!(claim.sender_sample().clock_id, [0x55; 16]);
        assert_eq!(claim.sender_sample().tick_ms, 0);
        assert_eq!(claim.hop_delta_ms(), 0);
        assert_eq!(claim.forwarding_age_ms(), 0);
        assert_eq!(
            claim.digest(),
            literal_hex::<32>("97db5c5cadc102f7f58ceeea9a0bbbc6bf18429016bb0033582eea682cbcfe95")
        );

        let maximum = literal_hex::<208>(MAXIMUM_HEX);
        let claim = BlobCustodyClaimV1::decode(&maximum).expect("maximum canonical claim");
        assert_eq!(claim.encode(), maximum);
        assert_eq!(claim.exchange_id(), u64::MAX);
        assert_eq!(
            claim.direction(),
            BlobCustodyDirectionV1::ToSessionResponder
        );
        assert_eq!(claim.source_len(), u64::MAX);
        assert_eq!(claim.priority(), crate::Priority::Flash);
        assert_eq!(claim.ttl_ms(), u64::MAX);
        assert_eq!(claim.prior_cumulative_age_ms(), u64::MAX);
        assert_eq!(claim.sender_sample().tick_ms, u64::MAX);
        assert_eq!(claim.hop_delta_ms(), 0);
        assert_eq!(claim.forwarding_age_ms(), u64::MAX);
        assert_eq!(
            claim.digest(),
            literal_hex::<32>("aa7dbfa6fc8c912af579a4d979c8091c5b25750a2cacf23dcd93a5f9c299a09b")
        );
    }

    #[test]
    fn malformed_noncanonical_and_overflow_claims_fail_closed() {
        // Mutation caught: accepting a short/surplus/duplicated field, an
        // unknown fixed integer or enum, a zero finite bound, or wrapped age.
        let canonical = literal_hex::<208>(MINIMUM_HEX);
        assert!(BlobCustodyClaimV1::decode(&canonical[..207]).is_err());
        let mut surplus = canonical.to_vec();
        surplus.push(0);
        assert!(BlobCustodyClaimV1::decode(&surplus).is_err());
        let mut duplicate = canonical.to_vec();
        duplicate.extend_from_slice(&canonical);
        assert!(BlobCustodyClaimV1::decode(&duplicate).is_err());

        for (offset, replacement) in [
            (0usize, 0x40),
            (9, 2),
            (11, 7),
            (13, 2),
            (54, 0),
            (54, 3),
            (159, 4),
        ] {
            let mut malformed = canonical;
            malformed[offset] = replacement;
            assert!(BlobCustodyClaimV1::decode(&malformed).is_err());
        }

        let mut zero_source_len = canonical;
        zero_source_len[87..95].fill(0);
        assert!(BlobCustodyClaimV1::decode(&zero_source_len).is_err());

        let mut zero_ttl = canonical;
        zero_ttl[160..168].fill(0);
        assert!(BlobCustodyClaimV1::decode(&zero_ttl).is_err());

        let mut overflow = canonical;
        overflow[168..176].copy_from_slice(&u64::MAX.to_be_bytes());
        overflow[200..208].copy_from_slice(&1u64.to_be_bytes());
        assert_eq!(
            BlobCustodyClaimV1::decode(&overflow),
            Err(BlobCustodyError::AgeOverflow)
        );

        let mut shifted_short_integer = canonical.to_vec();
        shifted_short_integer.remove(46);
        shifted_short_integer.push(0);
        assert!(BlobCustodyClaimV1::decode(&shifted_short_integer).is_err());
    }
}
