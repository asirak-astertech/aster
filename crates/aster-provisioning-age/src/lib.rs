//! Experimental age X25519 protection for local Aster provisioning artifacts.
//!
//! This crate is an opt-in implementation of Aster's replaceable local
//! provisioning-protection boundary. It deliberately does not change the mesh
//! protocol or wire format. The supported profile is narrow: binary age v1
//! files, parsed X25519 keys, bounded in-memory input and output, and no armor,
//! passphrases, SSH keys, plugins, filesystem access, or CLI invocation.
//!
//! This provider is not post-quantum, FIPS validated, persistent key custody,
//! recovery, rollback protection, or secure deletion.

#![forbid(unsafe_code)]

use std::error::Error;
use std::fmt;
use std::io::{self, Read, Write};
use std::iter;
use std::panic::{self, AssertUnwindSafe};

use age::secrecy::ExposeSecret;
use age_core::format::{FileKey, Stanza};
use aster_mesh::{
    MAX_PROTECTED_PROVISIONING_BYTES, MAX_UNPROTECTED_PROVISIONING_BYTES,
    ProvisioningProtectionError, ProvisioningProtector, ProvisioningUnprotector,
    UnprotectedProvisioning,
};
use zeroize::{Zeroize, Zeroizing};

const AGE_V1_MAGIC: &[u8] = b"age-encryption.org/v1\n";
const AGE_HEADER_MAC_PREFIX: &[u8] = b"--- ";
const AGE_ENCODED_MAC_BYTES: usize = 43;

/// Maximum number of X25519 recipients accepted for one protected artifact.
pub const MAX_AGE_RECIPIENTS: usize = 16;

/// Maximum number of X25519 identities tried while opening one artifact.
pub const MAX_AGE_IDENTITIES: usize = 16;

/// Maximum age-v1 header size admitted before invoking the upstream parser.
///
/// This is a work-admission bound, not a second age format parser. The upstream
/// parser remains authoritative after this allocation-free preflight succeeds.
pub const MAX_AGE_HEADER_BYTES: usize = 64 * 1024;

/// Maximum number of newline-terminated age-v1 header lines admitted.
///
/// The count includes the version and MAC lines. This ceiling is deliberately
/// larger than the provider's sixteen X25519 stanzas plus one extension stanza,
/// while bounding repeated parser work on malicious incomplete headers.
pub const MAX_AGE_HEADER_LINES: usize = 256;

/// The exact upstream X25519 identity type admitted by this provider.
pub use age::x25519::Identity as AgeIdentity;

/// The exact upstream X25519 recipient type admitted by this provider.
pub use age::x25519::Recipient as AgeRecipient;

/// A secret string suitable for parsing an [`AgeIdentity`].
pub use age::secrecy::SecretString;

/// Sanitized provider-configuration failure.
///
/// Variants carry no parser strings or key material so the error is safe to
/// cross logging and language boundaries.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[non_exhaustive]
pub enum AgeProviderConfigError {
    /// At least one recipient is required.
    NoRecipients,
    /// The recipient count exceeds [`MAX_AGE_RECIPIENTS`].
    TooManyRecipients,
    /// The supplied recipient string is not an age X25519 recipient.
    InvalidRecipient,
    /// The same recipient was supplied more than once.
    DuplicateRecipient,
    /// At least one identity is required.
    NoIdentities,
    /// The identity count exceeds [`MAX_AGE_IDENTITIES`].
    TooManyIdentities,
    /// The supplied secret string is not an age X25519 identity.
    InvalidIdentity,
    /// Two supplied identities resolve to the same recipient.
    DuplicateIdentity,
}

impl fmt::Display for AgeProviderConfigError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        let message = match self {
            Self::NoRecipients => "an age recipient is required",
            Self::TooManyRecipients => "too many age recipients",
            Self::InvalidRecipient => "invalid age recipient configuration",
            Self::DuplicateRecipient => "duplicate age recipient configuration",
            Self::NoIdentities => "an age identity is required",
            Self::TooManyIdentities => "too many age identities",
            Self::InvalidIdentity => "invalid age identity configuration",
            Self::DuplicateIdentity => "duplicate age identity configuration",
        };
        formatter.write_str(message)
    }
}

impl Error for AgeProviderConfigError {}

/// X25519 public-recipient capability for creating protected artifacts.
///
/// The provider owns public material only. It intentionally does not implement
/// [`ProvisioningUnprotector`].
pub struct AgeX25519Protector {
    primary: AgeRecipient,
    additional: Vec<AgeRecipient>,
}

impl AgeX25519Protector {
    /// Creates a protector for one to sixteen parsed X25519 recipients.
    pub fn new(
        recipients: impl IntoIterator<Item = AgeRecipient>,
    ) -> Result<Self, AgeProviderConfigError> {
        let mut recipients = recipients.into_iter();
        let primary = recipients
            .next()
            .ok_or(AgeProviderConfigError::NoRecipients)?;
        let mut additional = Vec::with_capacity(MAX_AGE_RECIPIENTS - 1);

        for recipient in recipients {
            if additional.len() == MAX_AGE_RECIPIENTS - 1 {
                return Err(AgeProviderConfigError::TooManyRecipients);
            }
            if recipient == primary || additional.contains(&recipient) {
                return Err(AgeProviderConfigError::DuplicateRecipient);
            }
            additional.push(recipient);
        }

        Ok(Self {
            primary,
            additional,
        })
    }

    /// Parses one public X25519 recipient and creates a protector for it.
    pub fn parse(recipient: &str) -> Result<Self, AgeProviderConfigError> {
        let recipient = recipient
            .parse::<AgeRecipient>()
            .map_err(|_| AgeProviderConfigError::InvalidRecipient)?;
        Self::new(iter::once(recipient))
    }

    /// Returns the configured recipient count without exposing identities.
    pub fn recipient_count(&self) -> usize {
        1 + self.additional.len()
    }

    fn recipients(&self) -> impl Iterator<Item = &dyn age::Recipient> {
        iter::once(&self.primary as &dyn age::Recipient).chain(
            self.additional
                .iter()
                .map(|recipient| recipient as &dyn age::Recipient),
        )
    }

    fn protect_inner(
        &self,
        plaintext: &UnprotectedProvisioning,
    ) -> Result<Vec<u8>, ProvisioningProtectionError> {
        if plaintext.is_empty() {
            return Err(ProvisioningProtectionError::Rejected);
        }
        if plaintext.len() > MAX_UNPROTECTED_PROVISIONING_BYTES {
            return Err(ProvisioningProtectionError::TooLarge);
        }

        let encryptor = age::Encryptor::with_recipients(self.recipients())
            .map_err(|_| ProvisioningProtectionError::Unavailable)?;
        let capacity = plaintext
            .len()
            .saturating_add(4096)
            .min(MAX_PROTECTED_PROVISIONING_BYTES);
        let output = BoundedVecWriter::new(MAX_PROTECTED_PROVISIONING_BYTES, capacity);
        let mut writer = encryptor.wrap_output(output).map_err(map_output_error)?;
        writer
            .write_all(plaintext.expose())
            .map_err(map_output_error)?;
        let output = writer.finish().map_err(map_output_error)?;
        let protected = output.into_inner();

        if protected.is_empty() {
            return Err(ProvisioningProtectionError::Unavailable);
        }
        Ok(protected)
    }
}

impl fmt::Debug for AgeX25519Protector {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("AgeX25519Protector")
            .field("recipient_count", &self.recipient_count())
            .finish_non_exhaustive()
    }
}

impl ProvisioningProtector for AgeX25519Protector {
    fn protect(
        &mut self,
        plaintext: &UnprotectedProvisioning,
    ) -> Result<Vec<u8>, ProvisioningProtectionError> {
        match panic::catch_unwind(AssertUnwindSafe(|| self.protect_inner(plaintext))) {
            Ok(result) => result,
            Err(_) => Err(ProvisioningProtectionError::Unavailable),
        }
    }
}

/// X25519 secret-identity capability for opening protected artifacts.
///
/// The provider accepts secret material explicitly and performs no filesystem
/// or environment loading. It intentionally does not implement
/// [`ProvisioningProtector`].
pub struct AgeX25519Unprotector {
    primary: AgeIdentity,
    additional: Vec<AgeIdentity>,
}

impl AgeX25519Unprotector {
    /// Creates an unprotector for one to sixteen parsed X25519 identities.
    pub fn new(
        identities: impl IntoIterator<Item = AgeIdentity>,
    ) -> Result<Self, AgeProviderConfigError> {
        let mut identities = identities.into_iter();
        let primary = identities
            .next()
            .ok_or(AgeProviderConfigError::NoIdentities)?;
        let primary_recipient = primary.to_public();
        let mut additional = Vec::with_capacity(MAX_AGE_IDENTITIES - 1);

        for identity in identities {
            if additional.len() == MAX_AGE_IDENTITIES - 1 {
                return Err(AgeProviderConfigError::TooManyIdentities);
            }
            let recipient = identity.to_public();
            if recipient == primary_recipient
                || additional
                    .iter()
                    .any(|existing: &AgeIdentity| existing.to_public() == recipient)
            {
                return Err(AgeProviderConfigError::DuplicateIdentity);
            }
            additional.push(identity);
        }

        Ok(Self {
            primary,
            additional,
        })
    }

    /// Parses one secret X25519 identity and creates an unprotector for it.
    pub fn parse(identity: &SecretString) -> Result<Self, AgeProviderConfigError> {
        let identity = identity
            .expose_secret()
            .parse::<AgeIdentity>()
            .map_err(|_| AgeProviderConfigError::InvalidIdentity)?;
        Self::new(iter::once(identity))
    }

    /// Returns the public recipient corresponding to the primary identity.
    pub fn recipient(&self) -> AgeRecipient {
        self.primary.to_public()
    }

    /// Returns the configured identity count without exposing key material.
    pub fn identity_count(&self) -> usize {
        1 + self.additional.len()
    }

    fn unprotect_inner(
        &self,
        protected: &[u8],
        max_plaintext_len: usize,
    ) -> Result<UnprotectedProvisioning, ProvisioningProtectionError> {
        if protected.is_empty() {
            return Err(ProvisioningProtectionError::Rejected);
        }
        if protected.len() > MAX_PROTECTED_PROVISIONING_BYTES {
            return Err(ProvisioningProtectionError::TooLarge);
        }
        preflight_age_header(protected)?;

        let decryptor = age::Decryptor::new_buffered(protected)
            .map_err(|_| ProvisioningProtectionError::Rejected)?;
        let profiled_identities = iter::once(&self.primary)
            .chain(self.additional.iter())
            .map(ProfiledIdentity)
            .collect::<Vec<_>>();
        let reader = decryptor
            .decrypt(
                profiled_identities
                    .iter()
                    .map(|identity| identity as &dyn age::Identity),
            )
            .map_err(|_| ProvisioningProtectionError::Rejected)?;
        let accepted_len = max_plaintext_len.min(MAX_UNPROTECTED_PROVISIONING_BYTES);
        let read_len = accepted_len.saturating_add(1);
        let capacity = accepted_len.min(protected.len());
        let mut plaintext = Zeroizing::new(Vec::with_capacity(capacity));
        reader
            .take(read_len as u64)
            .read_to_end(&mut plaintext)
            .map_err(|_| ProvisioningProtectionError::Rejected)?;

        if plaintext.len() > accepted_len {
            return Err(ProvisioningProtectionError::TooLarge);
        }
        let plaintext = std::mem::take(&mut *plaintext);
        UnprotectedProvisioning::new(plaintext)
    }
}

fn preflight_age_header(protected: &[u8]) -> Result<(), ProvisioningProtectionError> {
    if !protected.starts_with(AGE_V1_MAGIC) {
        return Err(ProvisioningProtectionError::Rejected);
    }

    let mut line_start = 0;
    let mut line_count = 0usize;
    for (offset, byte) in protected.iter().enumerate() {
        if offset >= MAX_AGE_HEADER_BYTES {
            return Err(ProvisioningProtectionError::Rejected);
        }
        if *byte != b'\n' {
            continue;
        }

        line_count = line_count.saturating_add(1);
        if line_count > MAX_AGE_HEADER_LINES {
            return Err(ProvisioningProtectionError::Rejected);
        }
        let line = &protected[line_start..offset];
        if line.len() == AGE_HEADER_MAC_PREFIX.len() + AGE_ENCODED_MAC_BYTES
            && line.starts_with(AGE_HEADER_MAC_PREFIX)
        {
            return Ok(());
        }
        line_start = offset.saturating_add(1);
    }

    Err(ProvisioningProtectionError::Rejected)
}

struct ProfiledIdentity<'a>(&'a AgeIdentity);

impl age::Identity for ProfiledIdentity<'_> {
    fn unwrap_stanza(&self, stanza: &Stanza) -> Option<Result<FileKey, age::DecryptError>> {
        age::Identity::unwrap_stanza(self.0, stanza)
    }

    fn unwrap_stanzas(&self, stanzas: &[Stanza]) -> Option<Result<FileKey, age::DecryptError>> {
        let x25519_count = stanzas
            .iter()
            .filter(|stanza| stanza.tag == "X25519")
            .count();
        let extension_count = stanzas.len().saturating_sub(x25519_count);
        if x25519_count == 0
            || x25519_count > MAX_AGE_RECIPIENTS
            || extension_count > 1
            || stanzas.iter().any(|stanza| stanza.tag == "scrypt")
        {
            return Some(Err(age::DecryptError::InvalidHeader));
        }
        age::Identity::unwrap_stanzas(self.0, stanzas)
    }
}

impl fmt::Debug for AgeX25519Unprotector {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("AgeX25519Unprotector")
            .field("identity_count", &self.identity_count())
            .field("identities", &"[REDACTED]")
            .finish()
    }
}

impl ProvisioningUnprotector for AgeX25519Unprotector {
    fn unprotect(
        &mut self,
        protected: &[u8],
        max_plaintext_len: usize,
    ) -> Result<UnprotectedProvisioning, ProvisioningProtectionError> {
        match panic::catch_unwind(AssertUnwindSafe(|| {
            self.unprotect_inner(protected, max_plaintext_len)
        })) {
            Ok(result) => result,
            Err(_) => Err(ProvisioningProtectionError::Rejected),
        }
    }
}

#[derive(Debug)]
struct OutputLimitExceeded;

impl fmt::Display for OutputLimitExceeded {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("bounded output limit exceeded")
    }
}

impl Error for OutputLimitExceeded {}

fn map_output_error(error: io::Error) -> ProvisioningProtectionError {
    if error
        .get_ref()
        .and_then(|source| source.downcast_ref::<OutputLimitExceeded>())
        .is_some()
    {
        ProvisioningProtectionError::TooLarge
    } else {
        ProvisioningProtectionError::Unavailable
    }
}

struct BoundedVecWriter {
    bytes: Vec<u8>,
    limit: usize,
}

impl BoundedVecWriter {
    fn new(limit: usize, capacity: usize) -> Self {
        Self {
            bytes: Vec::with_capacity(capacity.min(limit)),
            limit,
        }
    }

    fn into_inner(mut self) -> Vec<u8> {
        std::mem::take(&mut self.bytes)
    }
}

impl Write for BoundedVecWriter {
    fn write(&mut self, input: &[u8]) -> io::Result<usize> {
        let Some(next_len) = self.bytes.len().checked_add(input.len()) else {
            return Err(io::Error::other(OutputLimitExceeded));
        };
        if next_len > self.limit {
            return Err(io::Error::other(OutputLimitExceeded));
        }
        self.bytes.extend_from_slice(input);
        Ok(input.len())
    }

    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

impl Drop for BoundedVecWriter {
    fn drop(&mut self) {
        self.bytes.zeroize();
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn bounded_writer_rejects_a_write_atomically() {
        let mut writer = BoundedVecWriter::new(4, 4);
        writer.write_all(b"abc").unwrap();
        let error = writer.write_all(b"de").unwrap_err();

        assert!(
            error
                .get_ref()
                .is_some_and(|source| { source.downcast_ref::<OutputLimitExceeded>().is_some() })
        );
        assert_eq!(writer.bytes, b"abc");
    }

    #[test]
    fn header_preflight_bounds_bytes_and_lines_before_age_parsing() {
        let mut too_many_lines = AGE_V1_MAGIC.to_vec();
        for _ in 0..MAX_AGE_HEADER_LINES {
            too_many_lines.extend_from_slice(b"-> X\n\n");
        }
        too_many_lines.extend_from_slice(b"--- AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA\n");
        assert!(too_many_lines.len() < MAX_PROTECTED_PROVISIONING_BYTES);
        assert_eq!(
            preflight_age_header(&too_many_lines),
            Err(ProvisioningProtectionError::Rejected)
        );

        let mut deceptive_footer = AGE_V1_MAGIC.to_vec();
        deceptive_footer.extend_from_slice(b"-> X\n\n--- short\n");
        for _ in 0..MAX_AGE_HEADER_LINES {
            deceptive_footer.extend_from_slice(b"-> X\n\n");
        }
        deceptive_footer.extend_from_slice(b"--- AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA\n");
        assert!(deceptive_footer.len() < MAX_PROTECTED_PROVISIONING_BYTES);
        assert_eq!(
            preflight_age_header(&deceptive_footer),
            Err(ProvisioningProtectionError::Rejected)
        );

        let mut oversized_header = AGE_V1_MAGIC.to_vec();
        oversized_header.resize(MAX_AGE_HEADER_BYTES, b'A');
        oversized_header.extend_from_slice(b"\n--- AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA\n");
        assert!(oversized_header.len() < MAX_PROTECTED_PROVISIONING_BYTES);
        assert_eq!(
            preflight_age_header(&oversized_header),
            Err(ProvisioningProtectionError::Rejected)
        );
    }
}
