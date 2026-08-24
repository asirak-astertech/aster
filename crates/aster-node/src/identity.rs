use std::{
    error::Error,
    fmt,
    fs::{self, File, OpenOptions},
    io::{self, Read, Write},
    path::{Path, PathBuf},
    sync::{Arc, Mutex},
};

use aster_iroh::{EndpointId, SecretKey};
use zeroize::Zeroizing;

use crate::mission::{
    PreparedIdentityErasure, RetainedSecretArtifact, SoftwareErasureError, SoftwareSecretArtifact,
    acquire_artifact_lock,
};

const KEY_FILE: &str = "identity.key";

/// Persisted random Iroh endpoint identity for one node root.
#[derive(Clone)]
pub struct NodeIdentity {
    secret: Arc<Mutex<Option<SecretKey>>>,
    artifact: Arc<Mutex<RetainedSecretArtifact>>,
    id: EndpointId,
    path: PathBuf,
}

impl NodeIdentity {
    /// Loads an existing identity without creating either state or key material.
    pub fn load_existing(state: impl AsRef<Path>) -> Result<Self, IdentityError> {
        let path = state.as_ref().join(KEY_FILE);
        let (secret, artifact) = load_secret(&path)?;
        Ok(Self::new(secret, artifact, path))
    }

    /// Loads an exact 32-byte secret or creates one with owner-only access.
    pub fn load_or_create(state: impl AsRef<Path>) -> Result<Self, IdentityError> {
        #[cfg(not(unix))]
        {
            let _ = state;
            Err(SoftwareErasureError::PlatformUnavailable.into())
        }
        #[cfg(unix)]
        {
            let state = state.as_ref();
            fs::create_dir_all(state)?;
            let path = state.join(KEY_FILE);
            match load_secret(&path) {
                Ok((secret, artifact)) => Ok(Self::new(secret, artifact, path)),
                Err(IdentityError::Io(error)) if error.kind() == io::ErrorKind::NotFound => {
                    let secret = SecretKey::generate();
                    match create_secret(&path, &secret) {
                        Ok(artifact) => {
                            File::open(state)?.sync_all()?;
                            Ok(Self::new(secret, artifact, path))
                        }
                        Err(IdentityError::Io(error))
                            if error.kind() == io::ErrorKind::AlreadyExists =>
                        {
                            let (secret, artifact) = load_secret(&path)?;
                            Ok(Self::new(secret, artifact, path))
                        }
                        Err(error) => Err(error),
                    }
                }
                Err(error) => Err(error),
            }
        }
    }

    fn new(secret: SecretKey, artifact: RetainedSecretArtifact, path: PathBuf) -> Self {
        let id = secret.public();
        Self {
            secret: Arc::new(Mutex::new(Some(secret))),
            artifact: Arc::new(Mutex::new(artifact)),
            id,
            path,
        }
    }

    /// Returns the endpoint identity.
    pub fn id(&self) -> EndpointId {
        self.id
    }

    /// Returns a zeroize-on-drop provider copy for binding the carrier.
    ///
    /// Wrapper clones share the live capability and all fail after content
    /// destruction. An already-returned provider copy is independent, so the
    /// runtime must close and drop every endpoint before destroying this
    /// retained artifact.
    pub fn secret(&self) -> Result<SecretKey, IdentityError> {
        self.secret
            .lock()
            .map_err(|_| IdentityError::Artifact(SoftwareErasureError::StatePoisoned))?
            .clone()
            .ok_or(IdentityError::Artifact(
                SoftwareErasureError::SecretDestroyed,
            ))
    }

    /// Returns the durable key path for operator receipts.
    pub fn path(&self) -> &Path {
        &self.path
    }

    /// Side-effect-free validation and retention before terminal zeroization commit.
    pub fn prepare_software_erasure(&self) -> Result<PreparedIdentityErasure, IdentityError> {
        PreparedIdentityErasure::new(Arc::clone(&self.secret), Arc::clone(&self.artifact))
            .map_err(Into::into)
    }
}

#[cfg(unix)]
fn load_secret(path: &Path) -> Result<(SecretKey, RetainedSecretArtifact), IdentityError> {
    let artifact =
        RetainedSecretArtifact::open_existing(path, SoftwareSecretArtifact::CarrierIdentity)
            .map_err(IdentityError::from_artifact)?;
    let secret = read_secret(&artifact.file, path)?;
    Ok((secret, artifact))
}

#[cfg(not(unix))]
fn load_secret(_path: &Path) -> Result<(SecretKey, RetainedSecretArtifact), IdentityError> {
    Err(SoftwareErasureError::PlatformUnavailable.into())
}

fn read_secret(file: &File, path: &Path) -> Result<SecretKey, IdentityError> {
    let actual = usize::try_from(file.metadata()?.len()).unwrap_or(usize::MAX);
    if actual != 32 {
        return Err(IdentityError::InvalidLength {
            path: path.to_path_buf(),
            actual,
        });
    }
    let mut exact = Zeroizing::new([0u8; 32]);
    let mut reader = file;
    reader.read_exact(&mut *exact)?;
    Ok(SecretKey::from_bytes(&exact))
}

#[cfg(unix)]
fn create_secret(path: &Path, secret: &SecretKey) -> Result<RetainedSecretArtifact, IdentityError> {
    let mut options = OpenOptions::new();
    options.read(true).write(true).create_new(true);
    use std::os::unix::fs::OpenOptionsExt as _;
    options.mode(0o600);
    let mut file = options.open(path)?;
    acquire_artifact_lock(&file, path).map_err(IdentityError::from_artifact)?;
    let bytes = Zeroizing::new(secret.to_bytes());
    file.write_all(&bytes[..])?;
    file.sync_all().map_err(IdentityError::from)?;
    let path_metadata = fs::symlink_metadata(path)?;
    RetainedSecretArtifact::from_open_file(
        file,
        path.to_path_buf(),
        SoftwareSecretArtifact::CarrierIdentity,
        Some(path_metadata),
    )
    .map_err(IdentityError::from_artifact)
}

#[cfg(not(unix))]
fn create_secret(
    _path: &Path,
    _secret: &SecretKey,
) -> Result<RetainedSecretArtifact, IdentityError> {
    Err(SoftwareErasureError::PlatformUnavailable.into())
}

/// Durable identity loading or creation failure.
#[derive(Debug)]
pub enum IdentityError {
    /// Filesystem operation failed.
    Io(io::Error),
    /// Existing key had unsafe group or world permissions.
    UnsafePermissions(PathBuf),
    /// Existing key was not exactly 32 bytes.
    InvalidLength { path: PathBuf, actual: usize },
    /// Retained artifact safety or software erasure failed closed.
    Artifact(SoftwareErasureError),
}

impl fmt::Display for IdentityError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Io(error) => write!(formatter, "identity I/O: {error}"),
            Self::UnsafePermissions(path) => {
                write!(
                    formatter,
                    "identity key is accessible beyond its owner: {}",
                    path.display()
                )
            }
            Self::InvalidLength { path, actual } => write!(
                formatter,
                "identity key {} is {actual} bytes; expected 32",
                path.display()
            ),
            Self::Artifact(error) => write!(formatter, "identity artifact: {error}"),
        }
    }
}

impl Error for IdentityError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        match self {
            Self::Io(error) => Some(error),
            Self::Artifact(error) => Some(error),
            Self::UnsafePermissions(_) | Self::InvalidLength { .. } => None,
        }
    }
}

impl From<io::Error> for IdentityError {
    fn from(value: io::Error) -> Self {
        Self::Io(value)
    }
}

impl From<SoftwareErasureError> for IdentityError {
    fn from(value: SoftwareErasureError) -> Self {
        Self::Artifact(value)
    }
}

impl IdentityError {
    fn from_artifact(error: SoftwareErasureError) -> Self {
        match error {
            SoftwareErasureError::Io(error) => Self::Io(error),
            SoftwareErasureError::UnsafePermissions(path) => Self::UnsafePermissions(path),
            other => Self::Artifact(other),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::mission::SoftwareErasureTarget;

    fn root(name: &str) -> PathBuf {
        let path =
            std::env::temp_dir().join(format!("aster-identity-{}-{name}", std::process::id()));
        let _ = fs::remove_dir_all(&path);
        path
    }

    #[test]
    fn identity_is_randomly_created_and_stable_across_restart() {
        let root = root("stable");
        let first = NodeIdentity::load_or_create(&root).expect("first");
        let first_id = first.id();
        let key_path = first.path().to_path_buf();
        drop(first);
        let second = NodeIdentity::load_or_create(&root).expect("second");
        assert_eq!(first_id, second.id());
        assert_eq!(fs::read(key_path).expect("key").len(), 32);
        drop(second);
        fs::remove_dir_all(root).expect("cleanup");
    }

    #[cfg(unix)]
    #[test]
    fn identity_rejects_live_sharing_symlinks_hardlinks_and_loose_permissions() {
        use std::os::unix::fs::{PermissionsExt as _, symlink};

        let root = root("safety");
        let identity = NodeIdentity::load_or_create(&root).expect("create identity");
        let concurrent_root = root.clone();
        let concurrent = std::thread::spawn(move || NodeIdentity::load_or_create(concurrent_root));
        assert!(matches!(
            concurrent.join().expect("concurrent loader thread"),
            Err(IdentityError::Artifact(SoftwareErasureError::InUse(_)))
        ));

        let key = identity.path().to_path_buf();
        let linked_root = root.with_extension("hardlink");
        fs::create_dir_all(&linked_root).expect("hardlink root");
        fs::hard_link(&key, linked_root.join(KEY_FILE)).expect("hard link");
        assert!(matches!(
            identity.prepare_software_erasure(),
            Err(IdentityError::Artifact(SoftwareErasureError::SharedLinks {
                links: 2,
                ..
            }))
        ));
        fs::remove_file(linked_root.join(KEY_FILE)).expect("remove hard link");

        let symlink_root = root.with_extension("symlink");
        fs::create_dir_all(&symlink_root).expect("symlink root");
        symlink(&key, symlink_root.join(KEY_FILE)).expect("key symlink");
        assert!(matches!(
            NodeIdentity::load_or_create(&symlink_root),
            Err(IdentityError::Artifact(SoftwareErasureError::NotRegular(_)))
        ));

        fs::set_permissions(&key, fs::Permissions::from_mode(0o644)).expect("loose mode");
        assert!(matches!(
            identity.prepare_software_erasure(),
            Err(IdentityError::UnsafePermissions(_))
                | Err(IdentityError::Artifact(
                    SoftwareErasureError::UnsafePermissions(_)
                ))
        ));
        fs::set_permissions(&key, fs::Permissions::from_mode(0o600)).expect("restore mode");

        drop(identity);
        fs::remove_dir_all(root).expect("cleanup root");
        fs::remove_dir_all(linked_root).expect("cleanup hardlink root");
        fs::remove_dir_all(symlink_root).expect("cleanup symlink root");
    }

    #[cfg(unix)]
    #[test]
    fn identity_destruction_invalidates_clones_and_retains_replacement() {
        let root = root("replace");
        let identity = NodeIdentity::load_or_create(&root).expect("create identity");
        let clone = identity.clone();
        let original = identity.path().to_path_buf();
        let moved = root.join("identity.original");
        let replacement = [0xA5; 32];
        let mut prepared = identity
            .prepare_software_erasure()
            .expect("prepare identity erasure");
        let target = prepared.target().clone();
        assert_eq!(
            SoftwareErasureTarget::from_bytes(&target.to_bytes()).expect("decode target"),
            target
        );

        fs::rename(&original, &moved).expect("move original inode");
        fs::write(&original, replacement).expect("write replacement");
        let first = prepared.destroy_contents().expect("destroy exact inode");
        assert_eq!(first.bytes_overwritten(), 32);
        assert!(!first.already_destroyed());
        let second = prepared.destroy_contents().expect("idempotent destroy");
        assert!(second.already_destroyed());
        assert_eq!(fs::metadata(&moved).expect("moved metadata").len(), 0);
        assert_eq!(
            fs::read(&original).expect("replacement retained"),
            replacement
        );
        assert!(matches!(
            clone.secret(),
            Err(IdentityError::Artifact(
                SoftwareErasureError::SecretDestroyed
            ))
        ));

        drop(prepared);
        drop(clone);
        drop(identity);
        fs::remove_dir_all(root).expect("cleanup");
    }

    #[cfg(not(unix))]
    #[test]
    fn unavailable_platform_does_not_create_identity_state() {
        let root = root("unsupported");
        assert!(matches!(
            NodeIdentity::load_or_create(&root),
            Err(IdentityError::Artifact(
                SoftwareErasureError::PlatformUnavailable
            ))
        ));
        assert!(!root.exists());
    }
}
