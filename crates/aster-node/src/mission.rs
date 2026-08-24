//! Mission-authenticated session boundary above the Iroh carrier.
//!
//! An Iroh endpoint identity authenticates the carrier connection. It does not
//! establish Aster mission membership. This module binds an observed carrier
//! peer to a separately provisioned, expected mission [`NodeId`] and delegates
//! the complete hybrid four-flight handshake and ordered application-frame
//! protection to `aster-core`.
//!
//! The handshake state types intentionally expose no application-frame API.
//! Only [`MissionSession`], produced after the fourth flight and an exact peer
//! identity check, can seal or open application bytes.

use aster_iroh::{CarrierError, Connection, EndpointId, SecretKey};
use aster_mesh::{
    MAX_UNPROTECTED_PROVISIONING_BYTES, NodeId, ProvisioningBundle, ProvisioningProtectionError,
    ReferenceAuthenticatedSession, ReferenceEnvelopeSealer, ReferenceSessionAwaitingFinished,
    ReferenceSessionInitiator, ReferenceSessionResponder, ReferenceSessionResponderPending,
    UnprotectedProvisioning, engine::EnvelopeError,
};
use std::{
    error::Error,
    fmt,
    fs::File,
    io,
    path::{Path, PathBuf},
    sync::{Arc, Mutex},
};
#[cfg(unix)]
use std::{
    ffi::OsString,
    fs::OpenOptions,
    io::{Read, Seek, SeekFrom, Write},
    os::unix::{ffi::OsStringExt as _, fs::MetadataExt as _},
};
use zeroize::Zeroize as _;

const SOFTWARE_ERASURE_DESCRIPTOR_MAGIC: &[u8; 8] = b"ASTRZE01";
/// Maximum canonical descriptor bytes, aligned with the terminal redb record bound.
pub const MAX_SOFTWARE_ERASURE_DESCRIPTOR_BYTES: usize = 8 * 1024;
const SOFTWARE_ERASURE_DESCRIPTOR_HEADER_BYTES: usize = 37;
const MAX_SOFTWARE_ERASURE_PATH_BYTES: usize =
    MAX_SOFTWARE_ERASURE_DESCRIPTOR_BYTES - SOFTWARE_ERASURE_DESCRIPTOR_HEADER_BYTES;
const ERASE_BUFFER_BYTES: usize = 8 * 1024;

/// Kind of local plaintext secret named by a software-erasure descriptor.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(u8)]
pub enum SoftwareSecretArtifact {
    /// Authority-issued hybrid mission provisioning bundle.
    MissionBundle = 1,
    /// Persisted Iroh carrier signing key.
    CarrierIdentity = 2,
}

impl SoftwareSecretArtifact {
    const fn from_byte(byte: u8) -> Option<Self> {
        match byte {
            1 => Some(Self::MissionBundle),
            2 => Some(Self::CarrierIdentity),
            _ => None,
        }
    }
}

/// Durable, non-secret identity of one exact local secret artifact.
///
/// The descriptor is safe to persist in the terminal zeroization record. It
/// deliberately contains no credential bytes. A pending crash recovery may
/// reopen only a regular, owner-only, uniquely linked pathname whose device
/// and inode still match this descriptor. Missing or replaced paths remain
/// indeterminate and are never inferred to have been erased. This API does not
/// unlink secret pathnames: the zero-length tombstone is retained so a
/// pathname race cannot delete replacement data. Any later operator cleanup is
/// outside the software-erasure proof.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SoftwareErasureTarget {
    artifact: SoftwareSecretArtifact,
    path: PathBuf,
    device: u64,
    inode: u64,
    original_len: u64,
}

impl SoftwareErasureTarget {
    /// Artifact class bound into this descriptor.
    pub const fn artifact(&self) -> SoftwareSecretArtifact {
        self.artifact
    }

    /// Absolute pathname observed when the exact retained inode was opened.
    pub fn path(&self) -> &Path {
        &self.path
    }

    /// Unix device number of the exact retained inode.
    pub const fn device(&self) -> u64 {
        self.device
    }

    /// Unix inode number of the exact retained inode.
    pub const fn inode(&self) -> u64 {
        self.inode
    }

    /// Secret artifact length captured before the terminal marker.
    pub const fn original_len(&self) -> u64 {
        self.original_len
    }

    /// Encodes the bounded descriptor without credential bytes.
    #[cfg(unix)]
    pub fn to_bytes(&self) -> Vec<u8> {
        use std::os::unix::ffi::OsStrExt as _;

        let path = self.path.as_os_str().as_bytes();
        debug_assert!(path.len() <= MAX_SOFTWARE_ERASURE_PATH_BYTES);
        let path_len = u32::try_from(path.len()).expect("bounded erasure path fits in u32");
        let mut encoded = Vec::with_capacity(SOFTWARE_ERASURE_DESCRIPTOR_HEADER_BYTES + path.len());
        encoded.extend_from_slice(SOFTWARE_ERASURE_DESCRIPTOR_MAGIC);
        encoded.push(self.artifact as u8);
        encoded.extend_from_slice(&self.device.to_be_bytes());
        encoded.extend_from_slice(&self.inode.to_be_bytes());
        encoded.extend_from_slice(&self.original_len.to_be_bytes());
        encoded.extend_from_slice(&path_len.to_be_bytes());
        encoded.extend_from_slice(path);
        encoded
    }

    /// Decodes one canonical bounded descriptor without opening its pathname.
    #[cfg(unix)]
    pub fn from_bytes(encoded: &[u8]) -> Result<Self, SoftwareErasureError> {
        const HEADER: usize = SOFTWARE_ERASURE_DESCRIPTOR_HEADER_BYTES;
        if encoded.len() < HEADER || &encoded[..8] != SOFTWARE_ERASURE_DESCRIPTOR_MAGIC {
            return Err(SoftwareErasureError::InvalidDescriptor);
        }
        let artifact = SoftwareSecretArtifact::from_byte(encoded[8])
            .ok_or(SoftwareErasureError::InvalidDescriptor)?;
        let device = u64::from_be_bytes(
            encoded[9..17]
                .try_into()
                .map_err(|_| SoftwareErasureError::InvalidDescriptor)?,
        );
        let inode = u64::from_be_bytes(
            encoded[17..25]
                .try_into()
                .map_err(|_| SoftwareErasureError::InvalidDescriptor)?,
        );
        let original_len = u64::from_be_bytes(
            encoded[25..33]
                .try_into()
                .map_err(|_| SoftwareErasureError::InvalidDescriptor)?,
        );
        let valid_length = match artifact {
            SoftwareSecretArtifact::MissionBundle => {
                original_len != 0
                    && original_len
                        <= u64::try_from(MAX_UNPROTECTED_PROVISIONING_BYTES)
                            .expect("provisioning bound fits u64")
            }
            SoftwareSecretArtifact::CarrierIdentity => original_len == 32,
        };
        if !valid_length {
            return Err(SoftwareErasureError::InvalidDescriptor);
        }
        let path_len = u32::from_be_bytes(
            encoded[33..37]
                .try_into()
                .map_err(|_| SoftwareErasureError::InvalidDescriptor)?,
        ) as usize;
        if path_len == 0
            || path_len > MAX_SOFTWARE_ERASURE_PATH_BYTES
            || encoded.len() != HEADER + path_len
        {
            return Err(SoftwareErasureError::InvalidDescriptor);
        }
        let path = PathBuf::from(OsString::from_vec(encoded[HEADER..].to_vec()));
        if !path.is_absolute() {
            return Err(SoftwareErasureError::InvalidDescriptor);
        }
        Ok(Self {
            artifact,
            path,
            device,
            inode,
            original_len,
        })
    }

    /// Reopens an unflagged pending artifact after a crash.
    ///
    /// A missing pathname, a replacement inode, a symlink, a hard link, unsafe
    /// ownership or permissions, or another live advisory lock is terminally
    /// indeterminate. This method never parses or copies credential bytes.
    #[cfg(unix)]
    pub fn resume_pending(&self) -> Result<ResumedSoftwareErasure, SoftwareErasureError> {
        let mut artifact = RetainedSecretArtifact::open_existing(&self.path, self.artifact)
            .map_err(|error| SoftwareErasureError::indeterminate(self.path.clone(), error))?;
        if artifact.target.artifact != self.artifact
            || artifact.target.path != self.path
            || artifact.target.device != self.device
            || artifact.target.inode != self.inode
            || artifact.target.original_len > self.original_len
        {
            return Err(SoftwareErasureError::Indeterminate(self.path.clone()));
        }
        // A crash may occur after truncation but before the runtime records the
        // per-artifact destroyed phase. Retain the original bound while
        // accepting any same-inode prefix length, including zero, then repeat
        // the idempotent FD destruction before advancing the durable phase.
        artifact.target = self.clone();
        Ok(ResumedSoftwareErasure { artifact })
    }
}

/// Receipt for destruction of secret contents through an exact retained FD.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SoftwareErasureReceipt {
    target: SoftwareErasureTarget,
    bytes_overwritten: u64,
    already_destroyed: bool,
}

impl SoftwareErasureReceipt {
    /// Durable descriptor whose per-artifact destroyed flag may now be set.
    pub fn target(&self) -> &SoftwareErasureTarget {
        &self.target
    }

    /// Bytes overwritten before the exact inode was truncated and synchronized.
    pub const fn bytes_overwritten(&self) -> u64 {
        self.bytes_overwritten
    }

    /// Whether this retained handle had already completed destruction.
    pub const fn already_destroyed(&self) -> bool {
        self.already_destroyed
    }

    /// The receipt proves only bounded local software erasure.
    pub const fn bounded_software_erasure(&self) -> bool {
        true
    }

    /// Software erasure does not prove physical flash, snapshot, swap, or backup sanitization.
    pub const fn physical_media_sanitized(&self) -> bool {
        false
    }
}

/// Prepared mission-bundle destruction token acquired before terminal commit.
pub struct PreparedMissionErasure {
    encoded: Arc<Mutex<UnprotectedProvisioning>>,
    artifact: Arc<Mutex<RetainedSecretArtifact>>,
    target: SoftwareErasureTarget,
    mission_authority: NodeId,
}

impl PreparedMissionErasure {
    /// Descriptor to persist before invoking the irreversible operation.
    pub const fn target(&self) -> &SoftwareErasureTarget {
        &self.target
    }

    /// Stable authority identity cached from the validated source bundle.
    pub const fn mission_authority_id(&self) -> NodeId {
        self.mission_authority
    }

    /// Invalidates all wrapper clones and destroys the exact retained inode's contents.
    ///
    /// Callers must first zeroize and drop sessions, sealers, and provisioning
    /// objects already derived from the shared wrapper.
    pub fn destroy_contents(&mut self) -> Result<SoftwareErasureReceipt, SoftwareErasureError> {
        self.encoded
            .lock()
            .map_err(|_| SoftwareErasureError::StatePoisoned)?
            .zeroize();
        self.artifact
            .lock()
            .map_err(|_| SoftwareErasureError::StatePoisoned)?
            .destroy_contents()
    }
}

/// Prepared Iroh identity destruction token acquired before terminal commit.
pub struct PreparedIdentityErasure {
    secret: Arc<Mutex<Option<SecretKey>>>,
    artifact: Arc<Mutex<RetainedSecretArtifact>>,
    target: SoftwareErasureTarget,
}

impl PreparedIdentityErasure {
    pub(crate) fn new(
        secret: Arc<Mutex<Option<SecretKey>>>,
        artifact: Arc<Mutex<RetainedSecretArtifact>>,
    ) -> Result<Self, SoftwareErasureError> {
        let target = artifact
            .lock()
            .map_err(|_| SoftwareErasureError::StatePoisoned)?
            .preflight()?;
        Ok(Self {
            secret,
            artifact,
            target,
        })
    }

    /// Descriptor to persist before invoking the irreversible operation.
    pub const fn target(&self) -> &SoftwareErasureTarget {
        &self.target
    }

    /// Invalidates all wrapper clones and destroys the exact retained inode's contents.
    ///
    /// Callers must first close and drop every endpoint that received an
    /// independent provider copy from [`crate::NodeIdentity::secret`].
    pub fn destroy_contents(&mut self) -> Result<SoftwareErasureReceipt, SoftwareErasureError> {
        self.secret
            .lock()
            .map_err(|_| SoftwareErasureError::StatePoisoned)?
            .take();
        self.artifact
            .lock()
            .map_err(|_| SoftwareErasureError::StatePoisoned)?
            .destroy_contents()
    }
}

/// Crash-recovered exact-FD destruction token for an unflagged artifact.
pub struct ResumedSoftwareErasure {
    artifact: RetainedSecretArtifact,
}

impl ResumedSoftwareErasure {
    /// Destroys the pending artifact contents without parsing credential bytes.
    pub fn destroy_contents(&mut self) -> Result<SoftwareErasureReceipt, SoftwareErasureError> {
        self.artifact.destroy_contents()
    }
}

/// Fail-closed local software-erasure error.
#[derive(Debug)]
pub enum SoftwareErasureError {
    /// Filesystem operation failed.
    Io(io::Error),
    /// The artifact is not a regular file.
    NotRegular(PathBuf),
    /// The pathname no longer names the exact retained inode.
    Changed(PathBuf),
    /// Group or world permission bits are present.
    UnsafePermissions(PathBuf),
    /// The file owner is not the effective process owner.
    WrongOwner {
        path: PathBuf,
        owner: u32,
        effective: u32,
    },
    /// More than one hard link names the artifact.
    SharedLinks { path: PathBuf, links: u64 },
    /// Another live open-file description holds the exclusive advisory lock.
    InUse(PathBuf),
    /// The wrapper was constructed from memory and has no retained file.
    NoPersistedArtifact,
    /// A pending crash recovery cannot prove that the original inode remains.
    Indeterminate(PathBuf),
    /// Descriptor bytes are noncanonical or out of bounds.
    InvalidDescriptor,
    /// Shared secret state was poisoned by a panic.
    StatePoisoned,
    /// Secret content destruction has already invalidated the live capability.
    SecretDestroyed,
    /// This platform cannot enforce the Unix retained-inode contract.
    PlatformUnavailable,
}

impl SoftwareErasureError {
    fn indeterminate(path: PathBuf, _cause: Self) -> Self {
        Self::Indeterminate(path)
    }
}

impl fmt::Display for SoftwareErasureError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Io(error) => write!(formatter, "secret artifact I/O: {error}"),
            Self::NotRegular(path) => write!(
                formatter,
                "secret artifact is not a regular file: {}",
                path.display()
            ),
            Self::Changed(path) => write!(
                formatter,
                "secret artifact pathname or inode changed: {}",
                path.display()
            ),
            Self::UnsafePermissions(path) => write!(
                formatter,
                "secret artifact is accessible beyond its owner: {}",
                path.display()
            ),
            Self::WrongOwner {
                path,
                owner,
                effective,
            } => write!(
                formatter,
                "secret artifact {} is owned by uid {owner}, effective uid is {effective}",
                path.display()
            ),
            Self::SharedLinks { path, links } => write!(
                formatter,
                "secret artifact {} has {links} hard links; exactly one is required",
                path.display()
            ),
            Self::InUse(path) => write!(
                formatter,
                "secret artifact is already held by another live loader: {}",
                path.display()
            ),
            Self::NoPersistedArtifact => {
                formatter.write_str("in-memory secret has no retained artifact")
            }
            Self::Indeterminate(path) => write!(
                formatter,
                "pending secret erasure is indeterminate; original inode cannot be proven at {}",
                path.display()
            ),
            Self::InvalidDescriptor => {
                formatter.write_str("invalid software-erasure target descriptor")
            }
            Self::StatePoisoned => formatter.write_str("shared secret state is poisoned"),
            Self::SecretDestroyed => formatter.write_str("secret key material has been destroyed"),
            Self::PlatformUnavailable => formatter
                .write_str("retained-inode software erasure is unavailable on this platform"),
        }
    }
}

impl Error for SoftwareErasureError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        match self {
            Self::Io(error) => Some(error),
            _ => None,
        }
    }
}

impl From<io::Error> for SoftwareErasureError {
    fn from(error: io::Error) -> Self {
        Self::Io(error)
    }
}

pub(crate) struct RetainedSecretArtifact {
    pub(crate) file: File,
    target: SoftwareErasureTarget,
    destroyed: bool,
}

impl RetainedSecretArtifact {
    #[cfg(unix)]
    pub(crate) fn open_existing(
        path: &Path,
        artifact: SoftwareSecretArtifact,
    ) -> Result<Self, SoftwareErasureError> {
        let path = absolute_artifact_path(path)?;
        let path_metadata = std::fs::symlink_metadata(&path)?;
        if !path_metadata.file_type().is_file() {
            return Err(SoftwareErasureError::NotRegular(path));
        }
        let mut options = OpenOptions::new();
        options.read(true).write(true);
        use std::os::unix::fs::OpenOptionsExt as _;
        options.custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK);
        let file = options.open(&path)?;
        Self::from_open_file(file, path, artifact, Some(path_metadata))
    }

    #[cfg(unix)]
    pub(crate) fn from_open_file(
        file: File,
        path: PathBuf,
        artifact: SoftwareSecretArtifact,
        path_metadata: Option<std::fs::Metadata>,
    ) -> Result<Self, SoftwareErasureError> {
        let path = absolute_artifact_path(&path)?;
        let metadata = file.metadata()?;
        validate_artifact_metadata(&path, &metadata)?;
        if let Some(path_metadata) = path_metadata
            && (path_metadata.dev() != metadata.dev() || path_metadata.ino() != metadata.ino())
        {
            return Err(SoftwareErasureError::Changed(path));
        }
        acquire_artifact_lock(&file, &path)?;
        use std::os::unix::ffi::OsStrExt as _;
        let path_bytes = path.as_os_str().as_bytes();
        if path_bytes.is_empty() || path_bytes.len() > MAX_SOFTWARE_ERASURE_PATH_BYTES {
            return Err(SoftwareErasureError::InvalidDescriptor);
        }
        Ok(Self {
            file,
            target: SoftwareErasureTarget {
                artifact,
                path,
                device: metadata.dev(),
                inode: metadata.ino(),
                original_len: metadata.len(),
            },
            destroyed: false,
        })
    }

    #[cfg(unix)]
    fn preflight(&self) -> Result<SoftwareErasureTarget, SoftwareErasureError> {
        let metadata = self.file.metadata()?;
        validate_artifact_metadata(&self.target.path, &metadata)?;
        if metadata.dev() != self.target.device
            || metadata.ino() != self.target.inode
            || metadata.len() != self.target.original_len
        {
            return Err(SoftwareErasureError::Changed(self.target.path.clone()));
        }
        let path_metadata = std::fs::symlink_metadata(&self.target.path)?;
        validate_artifact_metadata(&self.target.path, &path_metadata)?;
        if path_metadata.dev() != self.target.device || path_metadata.ino() != self.target.inode {
            return Err(SoftwareErasureError::Changed(self.target.path.clone()));
        }
        Ok(self.target.clone())
    }

    #[cfg(not(unix))]
    fn preflight(&self) -> Result<SoftwareErasureTarget, SoftwareErasureError> {
        Err(SoftwareErasureError::PlatformUnavailable)
    }

    #[cfg(unix)]
    fn destroy_contents(&mut self) -> Result<SoftwareErasureReceipt, SoftwareErasureError> {
        if self.destroyed {
            return Ok(SoftwareErasureReceipt {
                target: self.target.clone(),
                bytes_overwritten: 0,
                already_destroyed: true,
            });
        }
        let metadata = self.file.metadata()?;
        if !metadata.is_file()
            || metadata.dev() != self.target.device
            || metadata.ino() != self.target.inode
        {
            return Err(SoftwareErasureError::Changed(self.target.path.clone()));
        }
        let bytes_to_overwrite = metadata.len().min(self.target.original_len);
        self.file.seek(SeekFrom::Start(0))?;
        let zeros = [0u8; ERASE_BUFFER_BYTES];
        let mut remaining = bytes_to_overwrite;
        while remaining != 0 {
            let count = usize::try_from(remaining.min(ERASE_BUFFER_BYTES as u64))
                .expect("erasure chunk fits usize");
            self.file.write_all(&zeros[..count])?;
            remaining -= count as u64;
        }
        self.file.sync_all()?;
        self.file.set_len(0)?;
        self.file.sync_all()?;
        self.destroyed = true;
        Ok(SoftwareErasureReceipt {
            target: self.target.clone(),
            bytes_overwritten: bytes_to_overwrite,
            already_destroyed: false,
        })
    }

    #[cfg(not(unix))]
    fn destroy_contents(&mut self) -> Result<SoftwareErasureReceipt, SoftwareErasureError> {
        Err(SoftwareErasureError::PlatformUnavailable)
    }
}

#[cfg(unix)]
pub(crate) fn acquire_artifact_lock(file: &File, path: &Path) -> Result<(), SoftwareErasureError> {
    use rustix::fs::{FlockOperation, flock};

    match flock(file, FlockOperation::NonBlockingLockExclusive) {
        Ok(()) => Ok(()),
        Err(error) if error == rustix::io::Errno::WOULDBLOCK => {
            Err(SoftwareErasureError::InUse(path.to_path_buf()))
        }
        Err(error) => Err(io::Error::from(error).into()),
    }
}

#[cfg(not(unix))]
pub(crate) fn acquire_artifact_lock(
    _file: &File,
    _path: &Path,
) -> Result<(), SoftwareErasureError> {
    Err(SoftwareErasureError::PlatformUnavailable)
}

#[cfg(unix)]
fn validate_artifact_metadata(
    path: &Path,
    metadata: &std::fs::Metadata,
) -> Result<(), SoftwareErasureError> {
    use std::os::unix::fs::PermissionsExt as _;

    if !metadata.is_file() {
        return Err(SoftwareErasureError::NotRegular(path.to_path_buf()));
    }
    if metadata.permissions().mode() & 0o077 != 0 {
        return Err(SoftwareErasureError::UnsafePermissions(path.to_path_buf()));
    }
    let effective = rustix::process::geteuid().as_raw();
    if metadata.uid() != effective {
        return Err(SoftwareErasureError::WrongOwner {
            path: path.to_path_buf(),
            owner: metadata.uid(),
            effective,
        });
    }
    if metadata.nlink() != 1 {
        return Err(SoftwareErasureError::SharedLinks {
            path: path.to_path_buf(),
            links: metadata.nlink(),
        });
    }
    Ok(())
}

#[cfg(unix)]
fn absolute_artifact_path(path: &Path) -> io::Result<PathBuf> {
    if path.is_absolute() {
        Ok(path.to_path_buf())
    } else {
        Ok(std::env::current_dir()?.join(path))
    }
}

/// Parsed mission credentials retained as zeroizing plaintext reference bytes.
///
/// This is intentionally named `UnprotectedReferenceMission` because it is not
/// an operational at-rest protection mechanism. Runtime callers must not
/// confuse owner-only file permissions with an admitted
/// `ProvisioningUnprotector`. The selected runtime requires this bounded
/// reference seam today and receipts that limitation explicitly.
#[derive(Clone)]
pub struct UnprotectedReferenceMission {
    encoded: Arc<Mutex<UnprotectedProvisioning>>,
    identity: NodeId,
    mission_authority: NodeId,
    artifact: Option<Arc<Mutex<RetainedSecretArtifact>>>,
}

impl UnprotectedReferenceMission {
    /// Validates and owns canonical unprotected reference bundle bytes.
    pub fn from_bytes(bytes: Vec<u8>) -> Result<Self, MissionProvisioningError> {
        let encoded = UnprotectedProvisioning::new(bytes)?;
        let bundle = ProvisioningBundle::from_bytes(encoded.expose())?;
        let sealer = ReferenceEnvelopeSealer::open(bundle)?;
        let identity = sealer.identity();
        let mission_authority = sealer.mission_authority_id();
        Ok(Self {
            encoded: Arc::new(Mutex::new(encoded)),
            identity,
            mission_authority,
            artifact: None,
        })
    }

    /// Loads one bounded regular owner-only unprotected reference bundle.
    ///
    /// The already-open file is inspected before reading so a missing, loose,
    /// oversized, or non-regular artifact fails before node state or sockets
    /// are created.
    pub fn load(path: impl AsRef<Path>) -> Result<Self, MissionProvisioningError> {
        load_owner_only_bundle(path.as_ref())
    }

    /// Persists newly issued demo/test credentials with owner-only permissions.
    pub fn persist(
        path: impl AsRef<Path>,
        bytes: Vec<u8>,
    ) -> Result<Self, MissionProvisioningError> {
        persist_owner_only_bundle(path.as_ref(), bytes)
    }

    /// Authority-authenticated Aster mission identity in this bundle.
    pub const fn identity(&self) -> NodeId {
        self.identity
    }

    /// Stable authority identity authenticated by this validated mission bundle.
    pub const fn mission_authority_id(&self) -> NodeId {
        self.mission_authority
    }

    /// Side-effect-free validation and retention before terminal zeroization commit.
    pub fn prepare_software_erasure(
        &self,
    ) -> Result<PreparedMissionErasure, MissionProvisioningError> {
        let artifact = self
            .artifact
            .as_ref()
            .ok_or(SoftwareErasureError::NoPersistedArtifact)?;
        let target = artifact
            .lock()
            .map_err(|_| SoftwareErasureError::StatePoisoned)?
            .preflight()?;
        Ok(PreparedMissionErasure {
            encoded: Arc::clone(&self.encoded),
            artifact: Arc::clone(artifact),
            target,
            mission_authority: self.mission_authority,
        })
    }

    pub(crate) fn fresh_bundle(&self) -> Result<ProvisioningBundle, MissionSessionError> {
        let encoded = self.encoded.lock().map_err(|_| {
            MissionSessionError::Authentication(EnvelopeError(
                "mission provisioning state is poisoned".into(),
            ))
        })?;
        if encoded.is_zeroized() {
            return Err(MissionSessionError::Authentication(EnvelopeError(
                "mission provisioning has been zeroized".into(),
            )));
        }
        ProvisioningBundle::from_bytes(encoded.expose()).map_err(Into::into)
    }
}

#[cfg(unix)]
fn load_owner_only_bundle(
    path: &Path,
) -> Result<UnprotectedReferenceMission, MissionProvisioningError> {
    let path_metadata = std::fs::symlink_metadata(path)?;
    if !path_metadata.file_type().is_file() {
        return Err(MissionProvisioningError::NotRegular(path.to_path_buf()));
    }
    let retained =
        RetainedSecretArtifact::open_existing(path, SoftwareSecretArtifact::MissionBundle)
            .map_err(MissionProvisioningError::from_artifact)?;
    let metadata = retained.file.metadata()?;
    let maximum =
        u64::try_from(MAX_UNPROTECTED_PROVISIONING_BYTES).expect("provisioning bound fits in u64");
    if metadata.len() > maximum {
        return Err(MissionProvisioningError::TooLarge {
            path: path.to_path_buf(),
            actual: metadata.len(),
            maximum,
        });
    }
    let capacity = usize::try_from(metadata.len()).unwrap_or(0);
    let mut bytes = Vec::with_capacity(capacity);
    let reader = &retained.file;
    if let Err(error) = reader
        .take(maximum.saturating_add(1))
        .read_to_end(&mut bytes)
    {
        bytes.zeroize();
        return Err(error.into());
    }
    if u64::try_from(bytes.len()).expect("vector length fits in u64") > maximum {
        bytes.zeroize();
        return Err(MissionProvisioningError::TooLarge {
            path: path.to_path_buf(),
            actual: maximum.saturating_add(1),
            maximum,
        });
    }
    let mut mission = UnprotectedReferenceMission::from_bytes(bytes)?;
    mission.artifact = Some(Arc::new(Mutex::new(retained)));
    Ok(mission)
}

#[cfg(not(unix))]
fn load_owner_only_bundle(
    path: &Path,
) -> Result<UnprotectedReferenceMission, MissionProvisioningError> {
    Err(MissionProvisioningError::OwnerOnlyPermissionsUnavailable(
        path.to_path_buf(),
    ))
}

#[cfg(unix)]
fn persist_owner_only_bundle(
    path: &Path,
    bytes: Vec<u8>,
) -> Result<UnprotectedReferenceMission, MissionProvisioningError> {
    let mut credentials = UnprotectedReferenceMission::from_bytes(bytes)?;
    let mut options = OpenOptions::new();
    options.read(true).write(true).create_new(true);
    use std::os::unix::fs::OpenOptionsExt as _;
    options.mode(0o600);
    let mut file = options.open(path)?;
    acquire_artifact_lock(&file, path)?;
    let encoded = credentials
        .encoded
        .lock()
        .map_err(|_| SoftwareErasureError::StatePoisoned)?;
    file.write_all(encoded.expose())?;
    file.sync_all()?;
    drop(encoded);
    sync_parent_directory(path)?;
    let path = absolute_artifact_path(path)?;
    let path_metadata = std::fs::symlink_metadata(&path)?;
    let retained = RetainedSecretArtifact::from_open_file(
        file,
        path,
        SoftwareSecretArtifact::MissionBundle,
        Some(path_metadata),
    )
    .map_err(MissionProvisioningError::from_artifact)?;
    credentials.artifact = Some(Arc::new(Mutex::new(retained)));
    Ok(credentials)
}

#[cfg(unix)]
fn sync_parent_directory(path: &Path) -> io::Result<()> {
    let parent = path
        .parent()
        .filter(|parent| !parent.as_os_str().is_empty())
        .unwrap_or_else(|| Path::new("."));
    File::open(parent)?.sync_all()
}

#[cfg(not(unix))]
fn persist_owner_only_bundle(
    path: &Path,
    mut bytes: Vec<u8>,
) -> Result<UnprotectedReferenceMission, MissionProvisioningError> {
    bytes.zeroize();
    Err(MissionProvisioningError::OwnerOnlyPermissionsUnavailable(
        path.to_path_buf(),
    ))
}

impl fmt::Debug for UnprotectedReferenceMission {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        let encoded_len = self.encoded.lock().map_or(0, |encoded| encoded.len());
        formatter
            .debug_struct("UnprotectedReferenceMission")
            .field("identity", &self.identity)
            .field("mission_authority", &self.mission_authority)
            .field("encoded_len", &encoded_len)
            .field("persisted", &self.artifact.is_some())
            .field("provisioning", &"[UNPROTECTED REFERENCE BYTES REDACTED]")
            .finish()
    }
}

/// Fail-closed reference provisioning artifact error.
#[derive(Debug)]
pub enum MissionProvisioningError {
    /// Filesystem operation failed.
    Io(io::Error),
    /// The supplied artifact is not a regular file.
    NotRegular(PathBuf),
    /// The path changed between validation and opening.
    Changed(PathBuf),
    /// The supplied artifact is readable beyond its owner.
    UnsafePermissions(PathBuf),
    /// This platform cannot enforce the reference bundle's owner-only contract.
    OwnerOnlyPermissionsUnavailable(PathBuf),
    /// The artifact exceeds the aster-core reference bound.
    TooLarge {
        path: PathBuf,
        actual: u64,
        maximum: u64,
    },
    /// The zeroizing plaintext wrapper rejected the artifact.
    Protection(ProvisioningProtectionError),
    /// `aster-core` rejected the bundle or could not open its identity.
    Invalid(EnvelopeError),
    /// The retained local artifact failed the software-erasure safety contract.
    Artifact(SoftwareErasureError),
}

impl fmt::Display for MissionProvisioningError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Io(error) => write!(formatter, "mission provisioning I/O: {error}"),
            Self::NotRegular(path) => write!(
                formatter,
                "unprotected reference mission bundle is not a regular file: {}",
                path.display()
            ),
            Self::Changed(path) => write!(
                formatter,
                "unprotected reference mission bundle changed while opening: {}",
                path.display()
            ),
            Self::UnsafePermissions(path) => write!(
                formatter,
                "unprotected reference mission bundle is accessible beyond its owner: {}",
                path.display()
            ),
            Self::OwnerOnlyPermissionsUnavailable(path) => write!(
                formatter,
                "owner-only permissions cannot be verified for unprotected reference mission bundle on this platform: {}",
                path.display()
            ),
            Self::TooLarge {
                path,
                actual,
                maximum,
            } => write!(
                formatter,
                "unprotected reference mission bundle {} is {actual} bytes; maximum is {maximum}",
                path.display()
            ),
            Self::Protection(error) => write!(formatter, "mission provisioning: {error}"),
            Self::Invalid(error) => write!(formatter, "invalid reference mission bundle: {error}"),
            Self::Artifact(error) => write!(formatter, "mission provisioning artifact: {error}"),
        }
    }
}

impl Error for MissionProvisioningError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        match self {
            Self::Io(error) => Some(error),
            Self::Protection(error) => Some(error),
            Self::Invalid(error) => Some(error),
            Self::Artifact(error) => Some(error),
            Self::NotRegular(_)
            | Self::Changed(_)
            | Self::UnsafePermissions(_)
            | Self::OwnerOnlyPermissionsUnavailable(_)
            | Self::TooLarge { .. } => None,
        }
    }
}

impl From<io::Error> for MissionProvisioningError {
    fn from(error: io::Error) -> Self {
        Self::Io(error)
    }
}

impl From<ProvisioningProtectionError> for MissionProvisioningError {
    fn from(error: ProvisioningProtectionError) -> Self {
        Self::Protection(error)
    }
}

impl From<EnvelopeError> for MissionProvisioningError {
    fn from(error: EnvelopeError) -> Self {
        Self::Invalid(error)
    }
}

impl From<SoftwareErasureError> for MissionProvisioningError {
    fn from(error: SoftwareErasureError) -> Self {
        Self::Artifact(error)
    }
}

impl MissionProvisioningError {
    fn from_artifact(error: SoftwareErasureError) -> Self {
        match error {
            SoftwareErasureError::NotRegular(path) => Self::NotRegular(path),
            SoftwareErasureError::Changed(path) => Self::Changed(path),
            SoftwareErasureError::UnsafePermissions(path) => Self::UnsafePermissions(path),
            other => Self::Artifact(other),
        }
    }
}

/// Exact carrier-to-mission identity binding configured for one peer.
///
/// `carrier_id` is the Iroh identity authenticated by QUIC. `mission_id` is the
/// authority-provisioned Aster identity authenticated by the hybrid mission
/// handshake. They are deliberately different fields and different types.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct MissionPeerBinding {
    carrier_id: EndpointId,
    mission_id: NodeId,
}

impl MissionPeerBinding {
    /// Creates an exact expected binding for one peer.
    pub const fn new(carrier_id: EndpointId, mission_id: NodeId) -> Self {
        Self {
            carrier_id,
            mission_id,
        }
    }

    /// Iroh endpoint identity expected on the carrier connection.
    pub const fn carrier_id(&self) -> EndpointId {
        self.carrier_id
    }

    /// Aster mission identity expected inside the authenticated handshake.
    pub const fn mission_id(&self) -> NodeId {
        self.mission_id
    }

    fn verify_observed_carrier(self, observed: EndpointId) -> Result<Self, MissionSessionError> {
        if observed != self.carrier_id {
            return Err(MissionSessionError::CarrierIdentityMismatch {
                expected: self.carrier_id,
                observed,
            });
        }
        Ok(self)
    }
}

/// Fail-closed error from carrier binding, mission authentication, or protected frames.
#[derive(Debug)]
pub enum MissionSessionError {
    /// The bounded Iroh carrier failed while exchanging an opaque flight.
    Carrier(CarrierError),
    /// The connection's authenticated Iroh identity did not match configuration.
    CarrierIdentityMismatch {
        expected: EndpointId,
        observed: EndpointId,
    },
    /// The hybrid-authenticated Aster identity did not match configuration.
    MissionIdentityMismatch {
        expected: NodeId,
        authenticated: NodeId,
    },
    /// `aster-core` rejected a handshake flight or protected application frame.
    Authentication(EnvelopeError),
}

impl fmt::Display for MissionSessionError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Carrier(error) => write!(formatter, "mission carrier: {error}"),
            Self::CarrierIdentityMismatch { expected, observed } => write!(
                formatter,
                "carrier identity mismatch: expected {expected}, observed {observed}"
            ),
            Self::MissionIdentityMismatch {
                expected,
                authenticated,
            } => {
                formatter.write_str("mission identity mismatch: expected ")?;
                write_node_id(formatter, expected)?;
                formatter.write_str(", authenticated ")?;
                write_node_id(formatter, authenticated)
            }
            Self::Authentication(error) => write!(formatter, "mission authentication: {error}"),
        }
    }
}

impl Error for MissionSessionError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        match self {
            Self::Carrier(error) => Some(error),
            Self::Authentication(error) => Some(error),
            Self::CarrierIdentityMismatch { .. } | Self::MissionIdentityMismatch { .. } => None,
        }
    }
}

impl From<EnvelopeError> for MissionSessionError {
    fn from(error: EnvelopeError) -> Self {
        Self::Authentication(error)
    }
}

impl From<CarrierError> for MissionSessionError {
    fn from(error: CarrierError) -> Self {
        Self::Carrier(error)
    }
}

fn write_node_id(formatter: &mut fmt::Formatter<'_>, identity: &NodeId) -> fmt::Result {
    for byte in identity {
        write!(formatter, "{byte:02x}")?;
    }
    Ok(())
}

/// One opaque flight of the `aster-core` four-flight mission handshake.
///
/// The adapter adds no competing framing or cryptographic semantics. The
/// current typestate determines which flight is expected.
pub struct MissionHandshakeFlight(Vec<u8>);

impl MissionHandshakeFlight {
    fn new(bytes: Vec<u8>) -> Self {
        Self(bytes)
    }

    /// Borrows the opaque bytes for a bounded carrier exchange.
    pub fn as_bytes(&self) -> &[u8] {
        &self.0
    }

    /// Consumes the flight for an API that owns its outbound buffer.
    pub fn into_bytes(self) -> Vec<u8> {
        self.0
    }

    /// Reports the exact encoded size for carrier-bound checks and metrics.
    pub fn len(&self) -> usize {
        self.0.len()
    }

    /// Reports whether the underlying implementation produced no bytes.
    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }
}

impl fmt::Debug for MissionHandshakeFlight {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("MissionHandshakeFlight")
            .field("encoded_len", &self.0.len())
            .field("contents", &"[OPAQUE]")
            .finish()
    }
}

/// Wire accounting released only after all four mission flights authenticate.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct MissionHandshakeReceipt {
    /// Exactly four authenticated handshake flights.
    pub(crate) frames: usize,
    /// Encoded bytes across those four flights.
    pub(crate) bytes: usize,
}

impl MissionHandshakeReceipt {
    fn from_flights(lengths: [usize; 4]) -> Self {
        Self {
            frames: lengths.len(),
            bytes: lengths.into_iter().sum(),
        }
    }
}

/// Initiator waiting for the responder's second handshake flight.
pub struct MissionSessionInitiator {
    inner: ReferenceSessionInitiator,
    peer: MissionPeerBinding,
}

impl MissionSessionInitiator {
    /// Starts the hybrid handshake after checking the carrier identity.
    ///
    /// `observed_carrier` must come from the authenticated Iroh connection,
    /// normally `aster_iroh::Connection::remote_id()`.
    pub fn start(
        bundle: ProvisioningBundle,
        peer: MissionPeerBinding,
        observed_carrier: EndpointId,
    ) -> Result<(Self, MissionHandshakeFlight), MissionSessionError> {
        let peer = peer.verify_observed_carrier(observed_carrier)?;
        let (inner, flight) = ReferenceSessionInitiator::start(bundle)?;
        Ok((Self { inner, peer }, MissionHandshakeFlight::new(flight)))
    }

    /// Authenticates the responder's second flight and creates the third.
    pub fn receive_server(
        self,
        flight: &[u8],
    ) -> Result<(MissionSessionAwaitingFinished, MissionHandshakeFlight), MissionSessionError> {
        let (inner, response) = self.inner.receive_server(flight)?;
        Ok((
            MissionSessionAwaitingFinished {
                inner,
                peer: self.peer,
            },
            MissionHandshakeFlight::new(response),
        ))
    }
}

/// Runs the initiator side of the four-flight mission handshake over one
/// authenticated Iroh connection.
///
/// The carrier performs two independently bounded request/response exchanges:
/// flights one/two and flights three/four. Any failure closes the connection;
/// only a fully authenticated, exactly peer-bound session is returned.
pub async fn initiate_over_iroh(
    connection: &Connection,
    bundle: ProvisioningBundle,
    peer: MissionPeerBinding,
) -> Result<MissionSession, MissionSessionError> {
    initiate_over_iroh_metered(connection, bundle, peer)
        .await
        .map(|(session, _receipt)| session)
}

/// Runs the initiator handshake and receipts its flights only on full success.
pub(crate) async fn initiate_over_iroh_metered(
    connection: &Connection,
    bundle: ProvisioningBundle,
    peer: MissionPeerBinding,
) -> Result<(MissionSession, MissionHandshakeReceipt), MissionSessionError> {
    let result = async {
        let (initiator, first) =
            MissionSessionInitiator::start(bundle, peer, connection.remote_id())?;
        let second = connection.request(first.as_bytes()).await?;
        let (pending, third) = initiator.receive_server(&second)?;
        let fourth = connection.request(third.as_bytes()).await?;
        let receipt = MissionHandshakeReceipt::from_flights([
            first.len(),
            second.len(),
            third.len(),
            fourth.len(),
        ]);
        Ok((pending.receive_finished(&fourth)?, receipt))
    }
    .await;
    if result.is_err() {
        connection.close();
    }
    result
}

/// Initiator waiting for fourth-flight key confirmation.
///
/// This type has no application-frame methods. It becomes usable only after
/// both key confirmation and the exact expected mission-identity check succeed.
pub struct MissionSessionAwaitingFinished {
    inner: ReferenceSessionAwaitingFinished,
    peer: MissionPeerBinding,
}

impl MissionSessionAwaitingFinished {
    /// Authenticates the fourth flight and checks the expected mission peer.
    pub fn receive_finished(self, flight: &[u8]) -> Result<MissionSession, MissionSessionError> {
        MissionSession::bind(self.inner.receive_finished(flight)?, self.peer)
    }
}

/// Responder waiting for the initiator's first handshake flight.
pub struct MissionSessionResponder {
    inner: ReferenceSessionResponder,
    peer: MissionPeerBinding,
}

impl MissionSessionResponder {
    /// Opens the responder after checking the carrier identity.
    ///
    /// `observed_carrier` must come from the authenticated Iroh connection,
    /// normally `aster_iroh::Connection::remote_id()`.
    pub fn open(
        bundle: ProvisioningBundle,
        peer: MissionPeerBinding,
        observed_carrier: EndpointId,
    ) -> Result<Self, MissionSessionError> {
        let peer = peer.verify_observed_carrier(observed_carrier)?;
        Ok(Self {
            inner: ReferenceSessionResponder::open(bundle)?,
            peer,
        })
    }

    /// Authenticates the initiator's first flight and creates the second.
    pub fn receive_client(
        self,
        flight: &[u8],
    ) -> Result<(MissionSessionResponderPending, MissionHandshakeFlight), MissionSessionError> {
        let (inner, response) = self.inner.receive_client(flight)?;
        Ok((
            MissionSessionResponderPending {
                inner,
                peer: self.peer,
            },
            MissionHandshakeFlight::new(response),
        ))
    }
}

/// Responder waiting for the initiator's third handshake flight.
///
/// This type has no application-frame methods. The expected mission identity
/// is checked before the fourth flight is returned to the carrier.
pub struct MissionSessionResponderPending {
    inner: ReferenceSessionResponderPending,
    peer: MissionPeerBinding,
}

impl MissionSessionResponderPending {
    /// Authenticates the third flight, checks the expected mission peer, and
    /// returns the completed responder session plus fourth flight.
    pub fn receive_client_auth(
        self,
        flight: &[u8],
    ) -> Result<(MissionSession, MissionHandshakeFlight), MissionSessionError> {
        let (inner, response) = self.inner.receive_client_auth(flight)?;
        let session = MissionSession::bind(inner, self.peer)?;
        Ok((session, MissionHandshakeFlight::new(response)))
    }
}

/// Runs the responder side of the four-flight mission handshake over one
/// authenticated Iroh connection.
///
/// The carrier accepts two independently bounded request/response exchanges:
/// flights one/two and flights three/four. A handshake or binding error is
/// retained as a mission error rather than being relabeled as a transport
/// failure. Any failure closes the connection.
pub async fn respond_over_iroh(
    connection: &Connection,
    bundle: ProvisioningBundle,
    peer: MissionPeerBinding,
) -> Result<MissionSession, MissionSessionError> {
    respond_over_iroh_metered(connection, bundle, peer)
        .await
        .map(|(session, _receipt)| session)
}

/// Runs the responder handshake and receipts its flights only on full success.
pub(crate) async fn respond_over_iroh_metered(
    connection: &Connection,
    bundle: ProvisioningBundle,
    peer: MissionPeerBinding,
) -> Result<(MissionSession, MissionHandshakeReceipt), MissionSessionError> {
    let result = respond_over_iroh_inner(connection, bundle, peer).await;
    if result.is_err() {
        connection.close();
    }
    result
}

async fn respond_over_iroh_inner(
    connection: &Connection,
    bundle: ProvisioningBundle,
    peer: MissionPeerBinding,
) -> Result<(MissionSession, MissionHandshakeReceipt), MissionSessionError> {
    let responder = MissionSessionResponder::open(bundle, peer, connection.remote_id())?;
    let mut first_transition = None;
    let mut first_lengths = None;
    let first_exchange = connection
        .respond_once(|first| match responder.receive_client(first) {
            Ok((pending, second)) => {
                first_lengths = Some((first.len(), second.len()));
                first_transition = Some(Ok(pending));
                Ok((second.into_bytes(), false))
            }
            Err(error) => {
                first_transition = Some(Err(error));
                Err(CarrierError::Transport(
                    "mission handshake rejected before flight two".into(),
                ))
            }
        })
        .await;
    let pending = match (first_exchange, first_transition) {
        (_, Some(Err(error))) => return Err(error),
        (Err(error), _) => return Err(error.into()),
        (Ok(false), Some(Ok(pending))) => pending,
        (Ok(true), Some(Ok(_))) => {
            return Err(CarrierError::Transport(
                "mission carrier reported early handshake completion".into(),
            )
            .into());
        }
        (Ok(_), None) => {
            return Err(CarrierError::Transport(
                "mission carrier skipped the first handshake transition".into(),
            )
            .into());
        }
    };

    let mut second_transition = None;
    let mut second_lengths = None;
    let second_exchange = connection
        .respond_once(|third| match pending.receive_client_auth(third) {
            Ok((session, fourth)) => {
                second_lengths = Some((third.len(), fourth.len()));
                second_transition = Some(Ok(session));
                Ok((fourth.into_bytes(), true))
            }
            Err(error) => {
                second_transition = Some(Err(error));
                Err(CarrierError::Transport(
                    "mission handshake rejected before flight four".into(),
                ))
            }
        })
        .await;
    match (second_exchange, second_transition) {
        (_, Some(Err(error))) => Err(error),
        (Err(error), _) => Err(error.into()),
        (Ok(true), Some(Ok(session))) => {
            let (first, second) = first_lengths.ok_or_else(|| {
                CarrierError::Transport("mission carrier omitted first-flight accounting".into())
            })?;
            let (third, fourth) = second_lengths.ok_or_else(|| {
                CarrierError::Transport("mission carrier omitted second-flight accounting".into())
            })?;
            Ok((
                session,
                MissionHandshakeReceipt::from_flights([first, second, third, fourth]),
            ))
        }
        (Ok(false), Some(Ok(_))) => Err(CarrierError::Transport(
            "mission carrier did not report completed handshake".into(),
        )
        .into()),
        (Ok(_), None) => Err(CarrierError::Transport(
            "mission carrier skipped the second handshake transition".into(),
        )
        .into()),
    }
}

/// Hybrid-authenticated, peer-bound mission session for application frames.
pub struct MissionSession {
    inner: ReferenceAuthenticatedSession,
    peer: MissionPeerBinding,
}

impl MissionSession {
    fn bind(
        mut inner: ReferenceAuthenticatedSession,
        peer: MissionPeerBinding,
    ) -> Result<Self, MissionSessionError> {
        let authenticated = inner.peer_identity();
        if authenticated != peer.mission_id {
            inner.zeroize();
            return Err(MissionSessionError::MissionIdentityMismatch {
                expected: peer.mission_id,
                authenticated,
            });
        }
        Ok(Self { inner, peer })
    }

    /// Exact carrier-to-mission peer binding authenticated for this session.
    pub const fn peer(&self) -> MissionPeerBinding {
        self.peer
    }

    /// Authenticated semantic protocol version selected by `aster-core`.
    pub fn semantic_version(&self) -> u16 {
        self.inner.semantic_version()
    }

    /// Authority-signed route-grant commitments authenticated in the peer's
    /// mission credential by the completed handshake.
    ///
    /// The values remain opaque and are only valid as provider authorization
    /// input; they are never learned from application frames.
    pub fn peer_route_grant_commitments(&self) -> &[[u8; 32]] {
        self.inner.peer_route_grant_commitments()
    }

    /// Encrypts, authenticates, and sequences one application frame.
    pub fn seal_application_frame(
        &mut self,
        plaintext: &[u8],
    ) -> Result<Vec<u8>, MissionSessionError> {
        self.inner.seal_frame(plaintext).map_err(Into::into)
    }

    /// Authenticates, decrypts, and replay-checks one application frame.
    pub fn open_application_frame(&mut self, frame: &[u8]) -> Result<Vec<u8>, MissionSessionError> {
        self.inner.open_frame(frame).map_err(Into::into)
    }

    /// Rapidly erases the directional traffic keys.
    pub fn zeroize(&mut self) {
        self.inner.zeroize();
    }
}

impl fmt::Debug for MissionSession {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("MissionSession")
            .field("peer", &self.peer)
            .field("semantic_version", &self.inner.semantic_version())
            .field("key_material", &"[REDACTED]")
            .finish()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::frame::Frame;
    use aster_iroh::{Endpoint, EndpointConfig, ExpectedPeer, SecretKey};
    use aster_mesh::{
        ProvisioningAccess, ReferenceEnvelopeSealer, ReferenceProvisioner, Scope, Topic,
    };
    use std::{collections::BTreeSet, net::SocketAddr};

    struct IssuedNode {
        bundle: Vec<u8>,
        identity: NodeId,
        carrier: EndpointId,
    }

    impl IssuedNode {
        fn bundle(&self) -> ProvisioningBundle {
            ProvisioningBundle::from_bytes(&self.bundle).expect("parse issued bundle")
        }
    }

    fn access() -> ProvisioningAccess {
        ProvisioningAccess::member(
            Scope::new("test/mission").expect("scope"),
            vec![1],
            vec![Topic::new("mesh").expect("topic")],
        )
        .expect("access")
    }

    fn issue(provisioner: &mut ReferenceProvisioner, serial: u64) -> IssuedNode {
        let bundle = provisioner
            .issue_node(serial, &[access()])
            .expect("issue node");
        let encoded = bundle.to_bytes().expect("encode bundle");
        let identity = ReferenceEnvelopeSealer::open(
            ProvisioningBundle::from_bytes(&encoded).expect("identity bundle"),
        )
        .expect("open identity service")
        .identity();
        IssuedNode {
            bundle: encoded,
            identity,
            carrier: SecretKey::generate().public(),
        }
    }

    fn binding(peer: &IssuedNode) -> MissionPeerBinding {
        MissionPeerBinding::new(peer.carrier, peer.identity)
    }

    fn establish(
        initiator: &IssuedNode,
        responder: &IssuedNode,
    ) -> Result<(MissionSession, MissionSession), MissionSessionError> {
        let (initiator_state, first) = MissionSessionInitiator::start(
            initiator.bundle(),
            binding(responder),
            responder.carrier,
        )?;
        let responder_state = MissionSessionResponder::open(
            responder.bundle(),
            binding(initiator),
            initiator.carrier,
        )?;
        let (responder_pending, second) = responder_state.receive_client(first.as_bytes())?;
        let (initiator_pending, third) = initiator_state.receive_server(second.as_bytes())?;
        let (responder_session, fourth) =
            responder_pending.receive_client_auth(third.as_bytes())?;
        let initiator_session = initiator_pending.receive_finished(fourth.as_bytes())?;
        Ok((initiator_session, responder_session))
    }

    fn loopback(endpoint: &Endpoint) -> SocketAddr {
        endpoint
            .bound_sockets()
            .into_iter()
            .find(SocketAddr::is_ipv4)
            .expect("IPv4 loopback binding")
    }

    #[tokio::test]
    async fn real_iroh_connection_rejects_plaintext_and_replayed_post_handshake_frames() {
        let server = Endpoint::bind(
            SecretKey::generate(),
            EndpointConfig::direct("127.0.0.1:0".parse().expect("server address")),
        )
        .await
        .expect("server endpoint");
        let client = Endpoint::bind(
            SecretKey::generate(),
            EndpointConfig::direct("127.0.0.1:0".parse().expect("client address")),
        )
        .await
        .expect("client endpoint");

        let mut provisioner = ReferenceProvisioner::from_seed([0x40; 32]).expect("provisioner");
        let mut initiator = issue(&mut provisioner, 1);
        let mut responder = issue(&mut provisioner, 2);
        initiator.carrier = client.id();
        responder.carrier = server.id();

        let initiator_binding = binding(&initiator);
        let responder_binding = binding(&responder);
        let responder_bundle = responder.bundle();
        let allowed = BTreeSet::from([client.id()]);
        let server_task = tokio::spawn({
            let server = server.clone();
            async move {
                let connection = server.accept(&allowed).await.expect("accept carrier");
                let mut mission =
                    respond_over_iroh(&connection, responder_bundle, initiator_binding)
                        .await
                        .expect("responder mission handshake");
                assert_eq!(mission.peer(), initiator_binding);
                assert!(
                    !connection
                        .respond_once(|protected_ping| {
                            let ping = mission
                                .open_application_frame(protected_ping)
                                .map_err(|error| CarrierError::Transport(error.to_string()))?;
                            if ping != b"ping" {
                                return Err(CarrierError::Transport(
                                    "unexpected protected application request".into(),
                                ));
                            }
                            let protected_pong = mission
                                .seal_application_frame(b"pong")
                                .map_err(|error| CarrierError::Transport(error.to_string()))?;
                            Ok((protected_pong, false))
                        })
                        .await
                        .expect("protected response")
                );
                let plaintext_error = connection
                    .respond_once(|plaintext_mechanics| {
                        assert!(matches!(
                            mission.open_application_frame(plaintext_mechanics),
                            Err(MissionSessionError::Authentication(_))
                        ));
                        Err(CarrierError::Transport(
                            "plaintext mechanics frame rejected".into(),
                        ))
                    })
                    .await
                    .expect_err("plaintext must not receive a response");
                assert!(matches!(plaintext_error, CarrierError::Transport(_)));
                let replay_error = connection
                    .respond_once(|replayed_ping| {
                        assert!(matches!(
                            mission.open_application_frame(replayed_ping),
                            Err(MissionSessionError::Authentication(_))
                        ));
                        Err(CarrierError::Transport(
                            "replayed mission frame rejected".into(),
                        ))
                    })
                    .await
                    .expect_err("replay must not receive a response");
                assert!(matches!(replay_error, CarrierError::Transport(_)));
                connection.close();
            }
        });

        let connection = client
            .connect(ExpectedPeer {
                id: server.id(),
                address: loopback(&server),
            })
            .await
            .expect("connect carrier");
        let mut mission = initiate_over_iroh(&connection, initiator.bundle(), responder_binding)
            .await
            .expect("initiator mission handshake");
        assert_eq!(mission.peer(), responder_binding);
        let protected_ping = mission
            .seal_application_frame(b"ping")
            .expect("protect ping");
        let protected_pong = connection
            .request(&protected_ping)
            .await
            .expect("exchange protected ping");
        assert_eq!(
            mission
                .open_application_frame(&protected_pong)
                .expect("authenticate pong"),
            b"pong"
        );
        let plaintext_finish = Frame::Finish.encode().expect("encode plaintext mechanics");
        if let Ok(response) = connection.request(&plaintext_finish).await {
            assert!(
                mission.open_application_frame(&response).is_err(),
                "plaintext mechanics unexpectedly received an authenticated response"
            );
        }
        if let Ok(response) = connection.request(&protected_ping).await {
            assert!(
                mission.open_application_frame(&response).is_err(),
                "replayed application frame unexpectedly received an authenticated response"
            );
        }

        server_task.await.expect("server task");
        client.close().await;
        server.close().await;
    }

    #[test]
    fn four_flights_gate_bidirectional_replay_protected_application_frames() {
        let mut provisioner = ReferenceProvisioner::from_seed([0x41; 32]).expect("provisioner");
        let initiator = issue(&mut provisioner, 1);
        let responder = issue(&mut provisioner, 2);
        let (mut initiator_session, mut responder_session) =
            establish(&initiator, &responder).expect("establish session");

        assert_eq!(initiator_session.peer(), binding(&responder));
        assert_eq!(responder_session.peer(), binding(&initiator));
        assert_eq!(
            initiator_session.semantic_version(),
            responder_session.semantic_version()
        );

        let frame = initiator_session
            .seal_application_frame(b"ping")
            .expect("seal ping");
        assert_eq!(
            responder_session
                .open_application_frame(&frame)
                .expect("open ping"),
            b"ping"
        );
        assert!(matches!(
            responder_session.open_application_frame(&frame),
            Err(MissionSessionError::Authentication(_))
        ));

        let reverse = responder_session
            .seal_application_frame(b"pong")
            .expect("seal pong");
        let mut tampered = reverse.clone();
        let last = tampered.last_mut().expect("protected frame is nonempty");
        *last ^= 1;
        assert!(matches!(
            initiator_session.open_application_frame(&tampered),
            Err(MissionSessionError::Authentication(_))
        ));
        assert_eq!(
            initiator_session
                .open_application_frame(&reverse)
                .expect("valid frame remains acceptable after tamper"),
            b"pong"
        );
    }

    #[test]
    fn carrier_and_mission_identities_are_independent_exact_checks() {
        let mut provisioner = ReferenceProvisioner::from_seed([0x42; 32]).expect("provisioner");
        let initiator = issue(&mut provisioner, 1);
        let responder = issue(&mut provisioner, 2);
        let other = issue(&mut provisioner, 3);

        let wrong_carrier =
            MissionSessionInitiator::start(initiator.bundle(), binding(&responder), other.carrier);
        assert!(matches!(
            wrong_carrier,
            Err(MissionSessionError::CarrierIdentityMismatch { .. })
        ));

        let wrong_mission_binding = MissionPeerBinding::new(responder.carrier, other.identity);
        let (initiator_state, first) = MissionSessionInitiator::start(
            initiator.bundle(),
            wrong_mission_binding,
            responder.carrier,
        )
        .expect("carrier identity is independently correct");
        let responder_state = MissionSessionResponder::open(
            responder.bundle(),
            binding(&initiator),
            initiator.carrier,
        )
        .expect("responder open");
        let (responder_pending, second) = responder_state
            .receive_client(first.as_bytes())
            .expect("first flight");
        let (initiator_pending, third) = initiator_state
            .receive_server(second.as_bytes())
            .expect("second flight");
        let (_responder_session, fourth) = responder_pending
            .receive_client_auth(third.as_bytes())
            .expect("third flight");
        assert!(matches!(
            initiator_pending.receive_finished(fourth.as_bytes()),
            Err(MissionSessionError::MissionIdentityMismatch {
                expected,
                authenticated,
            }) if expected == other.identity && authenticated == responder.identity
        ));

        let (initiator_state, first) = MissionSessionInitiator::start(
            initiator.bundle(),
            binding(&responder),
            responder.carrier,
        )
        .expect("initiator start");
        let responder_state = MissionSessionResponder::open(
            responder.bundle(),
            MissionPeerBinding::new(initiator.carrier, other.identity),
            initiator.carrier,
        )
        .expect("carrier identity is independently correct");
        let (responder_pending, second) = responder_state
            .receive_client(first.as_bytes())
            .expect("first flight");
        let (_initiator_pending, third) = initiator_state
            .receive_server(second.as_bytes())
            .expect("second flight");
        assert!(matches!(
            responder_pending.receive_client_auth(third.as_bytes()),
            Err(MissionSessionError::MissionIdentityMismatch {
                expected,
                authenticated,
            }) if expected == other.identity && authenticated == initiator.identity
        ));
    }

    #[test]
    fn different_mission_and_handshake_tamper_fail_closed() {
        let mut mission_a = ReferenceProvisioner::from_seed([0x43; 32]).expect("mission A");
        let mut mission_b = ReferenceProvisioner::from_seed([0x44; 32]).expect("mission B");
        let initiator = issue(&mut mission_a, 1);
        let responder = issue(&mut mission_b, 1);

        let (initiator_state, first) = MissionSessionInitiator::start(
            initiator.bundle(),
            binding(&responder),
            responder.carrier,
        )
        .expect("initiator start");
        let responder_state = MissionSessionResponder::open(
            responder.bundle(),
            binding(&initiator),
            initiator.carrier,
        )
        .expect("responder open");
        assert!(matches!(
            responder_state.receive_client(first.as_bytes()),
            Err(MissionSessionError::Authentication(_))
        ));
        drop(initiator_state);

        let mut same_mission = ReferenceProvisioner::from_seed([0x45; 32]).expect("mission");
        let initiator = issue(&mut same_mission, 1);
        let responder = issue(&mut same_mission, 2);
        let (_initiator_state, first) = MissionSessionInitiator::start(
            initiator.bundle(),
            binding(&responder),
            responder.carrier,
        )
        .expect("initiator start");
        let responder_state = MissionSessionResponder::open(
            responder.bundle(),
            binding(&initiator),
            initiator.carrier,
        )
        .expect("responder open");
        let mut damaged = first.into_bytes();
        *damaged.last_mut().expect("flight is nonempty") ^= 1;
        assert!(matches!(
            responder_state.receive_client(&damaged),
            Err(MissionSessionError::Authentication(_))
        ));
    }

    #[cfg(unix)]
    #[test]
    fn unprotected_reference_bundle_loader_is_bounded_regular_and_owner_only() {
        let root =
            std::env::temp_dir().join(format!("aster-mission-provisioning-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&root);
        std::fs::create_dir_all(&root).expect("create root");

        assert!(matches!(
            UnprotectedReferenceMission::load(root.join("missing.bundle")),
            Err(MissionProvisioningError::Io(error))
                if error.kind() == io::ErrorKind::NotFound
        ));
        assert!(matches!(
            UnprotectedReferenceMission::load(&root),
            Err(MissionProvisioningError::NotRegular(path)) if path == root
        ));

        let oversized = root.join("oversized.bundle");
        std::fs::write(
            &oversized,
            vec![0x55; MAX_UNPROTECTED_PROVISIONING_BYTES + 1],
        )
        .expect("write oversized");
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt as _;
            std::fs::set_permissions(&oversized, std::fs::Permissions::from_mode(0o600))
                .expect("chmod oversized");
        }
        assert!(matches!(
            UnprotectedReferenceMission::load(&oversized),
            Err(MissionProvisioningError::TooLarge { .. })
        ));

        let mut provisioner = ReferenceProvisioner::from_seed([0x46; 32]).expect("provisioner");
        let issued = issue(&mut provisioner, 1);
        let persisted = root.join("valid.bundle");
        let expected = UnprotectedReferenceMission::persist(&persisted, issued.bundle)
            .expect("persist owner-only bundle");
        let expected_identity = expected.identity();
        assert!(matches!(
            UnprotectedReferenceMission::load(&persisted),
            Err(MissionProvisioningError::Artifact(
                SoftwareErasureError::InUse(_)
            ))
        ));
        drop(expected);
        let loaded = UnprotectedReferenceMission::load(&persisted)
            .expect("load owner-only bundle after prior holder drops");
        assert_eq!(loaded.identity(), expected_identity);
        drop(loaded);

        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt as _;
            use std::os::unix::fs::symlink;
            let symlink_path = root.join("symlink.bundle");
            symlink(&persisted, &symlink_path).expect("create bundle symlink");
            assert!(matches!(
                UnprotectedReferenceMission::load(&symlink_path),
                Err(MissionProvisioningError::NotRegular(path)) if path == symlink_path
            ));
            std::fs::set_permissions(&persisted, std::fs::Permissions::from_mode(0o644))
                .expect("loosen permissions");
            assert!(matches!(
                UnprotectedReferenceMission::load(&persisted),
                Err(MissionProvisioningError::UnsafePermissions(path)) if path == persisted
            ));
        }

        std::fs::remove_dir_all(root).expect("cleanup");
    }

    #[cfg(unix)]
    #[test]
    fn mission_erasure_is_inode_bound_idempotent_and_invalidates_clones() {
        let root =
            std::env::temp_dir().join(format!("aster-mission-erasure-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&root);
        std::fs::create_dir_all(&root).expect("create root");
        let mut provisioner = ReferenceProvisioner::from_seed([0x47; 32]).expect("provisioner");
        let issued = issue(&mut provisioner, 7);
        let path = root.join("mission.bundle");
        let mission =
            UnprotectedReferenceMission::persist(&path, issued.bundle).expect("persist mission");
        let clone = mission.clone();
        let moved = root.join("mission.original");
        let replacement = b"operator replacement must survive";
        let mut prepared = mission
            .prepare_software_erasure()
            .expect("prepare mission erasure");
        let target = prepared.target().clone();
        let encoded = target.to_bytes();
        assert!(encoded.len() <= MAX_SOFTWARE_ERASURE_DESCRIPTOR_BYTES);
        assert_eq!(
            SoftwareErasureTarget::from_bytes(&encoded).expect("decode descriptor"),
            target
        );

        std::fs::rename(&path, &moved).expect("move exact original inode");
        std::fs::write(&path, replacement).expect("write replacement");
        let first = prepared.destroy_contents().expect("destroy exact inode");
        assert!(first.bounded_software_erasure());
        assert!(!first.physical_media_sanitized());
        assert_eq!(first.bytes_overwritten(), target.original_len());
        assert!(!first.already_destroyed());
        assert!(
            prepared
                .destroy_contents()
                .expect("repeat destruction")
                .already_destroyed()
        );
        assert_eq!(std::fs::metadata(&moved).expect("moved inode").len(), 0);
        assert_eq!(std::fs::read(&path).expect("replacement"), replacement);
        assert!(clone.fresh_bundle().is_err());

        drop(prepared);
        drop(clone);
        drop(mission);
        std::fs::remove_dir_all(root).expect("cleanup");
    }

    #[cfg(unix)]
    #[test]
    fn pending_erasure_resumes_same_zero_length_inode_without_parsing_credentials() {
        let root =
            std::env::temp_dir().join(format!("aster-mission-resume-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&root);
        std::fs::create_dir_all(&root).expect("create root");
        let mut provisioner = ReferenceProvisioner::from_seed([0x48; 32]).expect("provisioner");
        let path = root.join("mission.bundle");
        let mission =
            UnprotectedReferenceMission::persist(&path, issue(&mut provisioner, 8).bundle)
                .expect("persist mission");
        let mut prepared = mission.prepare_software_erasure().expect("prepare");
        let target = prepared.target().clone();
        let mut truncated_descriptor = target.to_bytes();
        truncated_descriptor.pop();
        assert!(matches!(
            SoftwareErasureTarget::from_bytes(&truncated_descriptor),
            Err(SoftwareErasureError::InvalidDescriptor)
        ));
        prepared
            .destroy_contents()
            .expect("simulate destroy before phase flag");
        drop(prepared);
        drop(mission);

        let mut resumed = target
            .resume_pending()
            .expect("same zero-length inode resumes");
        let receipt = resumed
            .destroy_contents()
            .expect("repeat exact destruction");
        assert_eq!(receipt.bytes_overwritten(), 0);
        drop(resumed);
        assert_eq!(
            std::fs::metadata(&path).expect("retained tombstone").len(),
            0
        );
        std::fs::remove_file(&path).expect("simulate external pathname removal");
        assert!(matches!(
            target.resume_pending(),
            Err(SoftwareErasureError::Indeterminate(_))
        ));
        std::fs::remove_dir_all(root).expect("cleanup");
    }

    #[cfg(unix)]
    #[test]
    fn mission_preflight_rejects_hardlinks_permissions_and_path_replacement() {
        use std::os::unix::fs::PermissionsExt as _;

        let root =
            std::env::temp_dir().join(format!("aster-mission-preflight-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&root);
        std::fs::create_dir_all(&root).expect("create root");
        let mut provisioner = ReferenceProvisioner::from_seed([0x49; 32]).expect("provisioner");
        let path = root.join("mission.bundle");
        let mission =
            UnprotectedReferenceMission::persist(&path, issue(&mut provisioner, 9).bundle)
                .expect("persist mission");

        let hardlink = root.join("mission.hardlink");
        std::fs::hard_link(&path, &hardlink).expect("hardlink");
        assert!(matches!(
            mission.prepare_software_erasure(),
            Err(MissionProvisioningError::Artifact(
                SoftwareErasureError::SharedLinks { links: 2, .. }
            ))
        ));
        std::fs::remove_file(hardlink).expect("remove hardlink");

        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o640))
            .expect("loose permissions");
        assert!(matches!(
            mission.prepare_software_erasure(),
            Err(MissionProvisioningError::Artifact(
                SoftwareErasureError::UnsafePermissions(_)
            ))
        ));
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600))
            .expect("restore permissions");

        let prepared = mission
            .prepare_software_erasure()
            .expect("safe preflight before replacement");
        let target = prepared.target().clone();
        drop(prepared);
        let original = root.join("mission.original");
        std::fs::rename(&path, &original).expect("replace path");
        std::fs::write(&path, b"replacement").expect("replacement");
        assert!(mission.prepare_software_erasure().is_err());
        assert!(matches!(
            target.resume_pending(),
            Err(SoftwareErasureError::Indeterminate(_))
        ));
        assert_eq!(
            std::fs::read(&path).expect("replacement retained"),
            b"replacement"
        );

        drop(mission);
        std::fs::remove_dir_all(root).expect("cleanup");
    }

    #[cfg(unix)]
    #[test]
    fn basename_provisioning_path_syncs_the_current_directory() {
        sync_parent_directory(Path::new("mission.bundle"))
            .expect("basename path must resolve its parent to the current directory");
        let absolute = absolute_artifact_path(Path::new("mission.bundle"))
            .expect("basename path becomes durable absolute descriptor path");
        assert!(absolute.is_absolute());
        assert!(absolute.ends_with("mission.bundle"));
    }

    #[cfg(not(unix))]
    #[test]
    fn unprotected_reference_bundle_files_fail_closed_without_owner_only_permissions() {
        let path = PathBuf::from("mission.bundle");
        assert!(matches!(
            UnprotectedReferenceMission::load(&path),
            Err(MissionProvisioningError::OwnerOnlyPermissionsUnavailable(error_path))
                if error_path == path
        ));
        assert!(matches!(
            UnprotectedReferenceMission::persist(&path, Vec::new()),
            Err(MissionProvisioningError::OwnerOnlyPermissionsUnavailable(error_path))
                if error_path == path
        ));
    }
}
