//! Replaceable protection boundary for local provisioning artifacts.
//!
//! The mesh protocol does not define an at-rest provisioning format. The
//! canonical `ASTRPB03` bytes are an unprotected inner representation; an
//! operational deployment supplies separate [`ProvisioningProtector`] and
//! [`ProvisioningUnprotector`] implementations which own the outer artifact
//! format and its key custody.

use std::error::Error;
use std::fmt;
use zeroize::Zeroize;

const UNPROTECTED_PROVISIONING_MAGIC: &[u8; 8] = b"ASTRPB03";

/// Exact maximum length of a canonical `ASTRPB03` plaintext bundle.
///
/// This follows from the fixed v3 key/signature sizes, the 256 route-grant and
/// 256 content-grant limits, and 128-byte scope/topic names.
pub const MAX_UNPROTECTED_PROVISIONING_BYTES: usize = 125_877;

/// Maximum accepted size of one provider-owned protected artifact.
///
/// Outer formats may carry recipient and recovery metadata, but node opening
/// remains a bounded operation. Providers needing more than one MiB must first
/// justify and revise this public contract.
pub const MAX_PROTECTED_PROVISIONING_BYTES: usize = 1024 * 1024;

/// Sanitized failure from a local provisioning-protection provider.
///
/// Variants intentionally carry no provider strings, paths, recipient names,
/// key identifiers, or plaintext details because this error may cross logging
/// and language-binding boundaries.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[non_exhaustive]
pub enum ProvisioningProtectionError {
    /// The configured provider, credential, hardware, or key store is not
    /// currently available.
    Unavailable,
    /// The artifact was malformed, unauthenticated, or not addressed to an
    /// available recipient.
    Rejected,
    /// A protected artifact or recovered plaintext exceeded its public bound.
    TooLarge,
}

impl fmt::Display for ProvisioningProtectionError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Unavailable => formatter.write_str("provisioning protection is unavailable"),
            Self::Rejected => formatter.write_str("protected provisioning artifact was rejected"),
            Self::TooLarge => formatter.write_str("provisioning artifact exceeds its size limit"),
        }
    }
}

impl Error for ProvisioningProtectionError {}

/// Typed, sanitized failure while importing or exporting a protected bundle.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[non_exhaustive]
pub enum ProtectedProvisioningError {
    /// The provider failed with a safe public category.
    Protection(ProvisioningProtectionError),
    /// The canonical inner bundle was invalid or already zeroized.
    InvalidBundle,
}

impl fmt::Display for ProtectedProvisioningError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Protection(error) => fmt::Display::fmt(error, formatter),
            Self::InvalidBundle => formatter.write_str("provisioning bundle is invalid"),
        }
    }
}

impl Error for ProtectedProvisioningError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        match self {
            Self::Protection(error) => Some(error),
            Self::InvalidBundle => None,
        }
    }
}

impl From<ProvisioningProtectionError> for ProtectedProvisioningError {
    fn from(error: ProvisioningProtectionError) -> Self {
        Self::Protection(error)
    }
}

/// Owned plaintext provisioning bytes which are erased on zeroize and drop.
///
/// This type deliberately does not implement `Clone`, `Deref`, `Display`,
/// serialization, or equality. Calling [`Self::expose`] is an explicit secret
/// access operation intended for protection providers and bounded ingestion.
pub struct UnprotectedProvisioning {
    bytes: Vec<u8>,
}

impl UnprotectedProvisioning {
    /// Takes ownership of a nonempty, bounded plaintext bundle buffer.
    ///
    /// Rejected input is erased before the error is returned.
    pub fn new(mut bytes: Vec<u8>) -> Result<Self, ProvisioningProtectionError> {
        if bytes.is_empty() {
            bytes.zeroize();
            return Err(ProvisioningProtectionError::Rejected);
        }
        if bytes.len() > MAX_UNPROTECTED_PROVISIONING_BYTES {
            bytes.zeroize();
            return Err(ProvisioningProtectionError::TooLarge);
        }
        Ok(Self { bytes })
    }

    /// Explicitly exposes the plaintext for immediate protection or ingestion.
    pub fn expose(&self) -> &[u8] {
        &self.bytes
    }

    /// Returns the bounded plaintext length without exposing its contents.
    pub fn len(&self) -> usize {
        self.bytes.len()
    }

    /// Reports whether explicit zeroization has emptied the owned buffer.
    pub fn is_empty(&self) -> bool {
        self.bytes.is_empty()
    }

    /// Reports whether explicit zeroization has emptied the owned buffer.
    pub fn is_zeroized(&self) -> bool {
        self.is_empty()
    }

    /// Erases and empties the owned plaintext buffer immediately.
    pub fn zeroize(&mut self) {
        self.bytes.zeroize();
    }
}

impl fmt::Debug for UnprotectedProvisioning {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("UnprotectedProvisioning([REDACTED])")
    }
}

impl Drop for UnprotectedProvisioning {
    fn drop(&mut self) {
        self.zeroize();
    }
}

/// Provider-owned outer protection for newly issued local provisioning artifacts.
///
/// Issuing authorities normally hold only recipient public material. Keeping
/// this capability separate from [`ProvisioningUnprotector`] avoids requiring
/// one object to hold both recipient and identity/private-key capabilities.
pub trait ProvisioningProtector {
    /// Protects one canonical plaintext bundle for local storage or transfer.
    fn protect(
        &mut self,
        plaintext: &UnprotectedProvisioning,
    ) -> Result<Vec<u8>, ProvisioningProtectionError>;
}

/// Provider-owned opening of an existing local provisioning artifact.
///
/// Implementations may use an admitted file-envelope library, a platform key
/// store, hardware-backed keys, or a deployment service. They must authenticate
/// before releasing plaintext, honor `max_plaintext_len` while reading, return
/// only sanitized errors, and never fall back to interpreting `protected` as
/// plaintext. This boundary does not define a mesh wire format.
pub trait ProvisioningUnprotector {
    /// Authenticates and opens one protected artifact into an owned secret.
    fn unprotect(
        &mut self,
        protected: &[u8],
        max_plaintext_len: usize,
    ) -> Result<UnprotectedProvisioning, ProvisioningProtectionError>;
}

/// Invokes one protection provider and validates its bounded outer artifact.
pub fn protect_provisioning_artifact<P>(
    plaintext: &UnprotectedProvisioning,
    protector: &mut P,
) -> Result<Vec<u8>, ProvisioningProtectionError>
where
    P: ProvisioningProtector + ?Sized,
{
    let mut protected = protector.protect(plaintext)?;
    if let Err(error) = validate_protected_artifact(&protected) {
        protected.zeroize();
        return Err(error);
    }
    Ok(protected)
}

/// Validates and opens one provider-owned artifact at most once.
///
/// Empty, oversized, and raw `ASTRPB03` inputs are rejected before provider
/// invocation. A nonempty bounded outer artifact invokes the provider exactly
/// once, then independently rechecks the recovered plaintext bound.
pub fn unprotect_provisioning_artifact<P>(
    protected: &[u8],
    unprotector: &mut P,
) -> Result<UnprotectedProvisioning, ProvisioningProtectionError>
where
    P: ProvisioningUnprotector + ?Sized,
{
    validate_protected_artifact(protected)?;
    let mut plaintext = unprotector.unprotect(protected, MAX_UNPROTECTED_PROVISIONING_BYTES)?;
    if plaintext.is_empty() {
        plaintext.zeroize();
        return Err(ProvisioningProtectionError::Rejected);
    }
    if plaintext.len() > MAX_UNPROTECTED_PROVISIONING_BYTES {
        plaintext.zeroize();
        return Err(ProvisioningProtectionError::TooLarge);
    }
    Ok(plaintext)
}

pub(crate) fn validate_protected_artifact(
    protected: &[u8],
) -> Result<(), ProvisioningProtectionError> {
    if protected.is_empty() || protected.starts_with(UNPROTECTED_PROVISIONING_MAGIC) {
        return Err(ProvisioningProtectionError::Rejected);
    }
    if protected.len() > MAX_PROTECTED_PROVISIONING_BYTES {
        return Err(ProvisioningProtectionError::TooLarge);
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    struct OutputProtector(Option<Vec<u8>>);

    impl ProvisioningProtector for OutputProtector {
        fn protect(
            &mut self,
            _plaintext: &UnprotectedProvisioning,
        ) -> Result<Vec<u8>, ProvisioningProtectionError> {
            self.0
                .take()
                .ok_or(ProvisioningProtectionError::Unavailable)
        }
    }

    struct EchoUnprotector {
        calls: usize,
    }

    impl ProvisioningUnprotector for EchoUnprotector {
        fn unprotect(
            &mut self,
            protected: &[u8],
            _max_plaintext_len: usize,
        ) -> Result<UnprotectedProvisioning, ProvisioningProtectionError> {
            self.calls += 1;
            UnprotectedProvisioning::new(protected.to_vec())
        }
    }

    #[test]
    fn unprotected_provisioning_is_redacted_and_explicitly_erased() {
        let canary = b"provisioning-secret-canary".to_vec();
        let mut plaintext = UnprotectedProvisioning::new(canary.clone()).unwrap();

        let debug = format!("{plaintext:?}");
        assert_eq!(debug, "UnprotectedProvisioning([REDACTED])");
        assert!(
            !debug
                .as_bytes()
                .windows(canary.len())
                .any(|part| part == canary)
        );
        assert_eq!(plaintext.expose(), canary);

        plaintext.zeroize();
        assert!(plaintext.is_zeroized());
        assert!(plaintext.expose().is_empty());
    }

    #[test]
    fn provisioning_artifact_bounds_fail_closed() {
        assert!(UnprotectedProvisioning::new(vec![0; MAX_UNPROTECTED_PROVISIONING_BYTES]).is_ok());
        assert_eq!(
            UnprotectedProvisioning::new(Vec::new()).unwrap_err(),
            ProvisioningProtectionError::Rejected
        );
        assert_eq!(
            UnprotectedProvisioning::new(vec![0; MAX_UNPROTECTED_PROVISIONING_BYTES + 1])
                .unwrap_err(),
            ProvisioningProtectionError::TooLarge
        );
        assert_eq!(
            validate_protected_artifact(&[]).unwrap_err(),
            ProvisioningProtectionError::Rejected
        );
        assert_eq!(
            validate_protected_artifact(b"ASTRPB03raw-bundle").unwrap_err(),
            ProvisioningProtectionError::Rejected
        );
        assert!(validate_protected_artifact(&vec![0; MAX_PROTECTED_PROVISIONING_BYTES]).is_ok());
        assert_eq!(
            validate_protected_artifact(&vec![0; MAX_PROTECTED_PROVISIONING_BYTES + 1])
                .unwrap_err(),
            ProvisioningProtectionError::TooLarge
        );
    }

    #[test]
    fn empty_oversized_and_echo_protection_are_rejected() {
        let plaintext = UnprotectedProvisioning::new(b"ASTRPB03inner-secret".to_vec()).unwrap();

        let mut empty = OutputProtector(Some(Vec::new()));
        assert_eq!(
            protect_provisioning_artifact(&plaintext, &mut empty).unwrap_err(),
            ProvisioningProtectionError::Rejected
        );

        let mut oversized = OutputProtector(Some(vec![0; MAX_PROTECTED_PROVISIONING_BYTES + 1]));
        assert_eq!(
            protect_provisioning_artifact(&plaintext, &mut oversized).unwrap_err(),
            ProvisioningProtectionError::TooLarge
        );

        let mut echo = OutputProtector(Some(plaintext.expose().to_vec()));
        assert_eq!(
            protect_provisioning_artifact(&plaintext, &mut echo).unwrap_err(),
            ProvisioningProtectionError::Rejected
        );

        let mut echo_opener = EchoUnprotector { calls: 0 };
        assert_eq!(
            unprotect_provisioning_artifact(plaintext.expose(), &mut echo_opener).unwrap_err(),
            ProvisioningProtectionError::Rejected
        );
        assert_eq!(echo_opener.calls, 0);
    }
}
