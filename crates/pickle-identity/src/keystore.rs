//! On-disk storage for an [`Identity`](crate::Identity).
//!
//! The file holds an unencrypted Ed25519 secret key, so it is written `0600`
//! and refuses to load if the permissions have been widened. It is exactly as
//! sensitive as an SSH host key and should be backed up like one — losing it
//! means losing every permission every server granted to that key.
//!
//! # Why this one is not encrypted
//!
//! This is the *server's* store, and a server boots unattended: there is nobody
//! at the console to type a passphrase when systemd restarts it at four in the
//! morning. The only ways to encrypt it and still start automatically are to put
//! the passphrase in an environment variable, a unit file, or a second file
//! beside the key — and all three live inside the same trust boundary as the key
//! itself. Anyone who can read `identity.json` can read the unit file that
//! unlocks it, or `/proc/<pid>/environ`, or the sibling file. That is not
//! encryption; it is obfuscation that reports itself as encryption, which is
//! worse than being plainly unencrypted, because an operator would relax the
//! protections that actually work in exchange for it.
//!
//! The protections that actually work for a server are: the data directory is
//! `0600`/`0700` and owned by the service user; and, where an operator wants
//! more, the platform's own facilities — full-disk encryption, `systemd`
//! credentials, a KMS — which sit outside this crate and outside the process.
//! Nothing is gained by pretending here.
//!
//! The client's store is a different problem and gets a different answer: a
//! human is present to type a passphrase, and the threat — a stolen laptop, a
//! synced folder, a backup — is one that encryption at rest genuinely addresses.
//! See [`crate::Vault`], which is encrypted, optionally, at the user's choice.

use crate::Identity;
use data_encoding::BASE64;
use serde::{Deserialize, Serialize};
use std::fs;
use std::io::Write;
use std::path::{Path, PathBuf};
use zeroize::{Zeroize, ZeroizeOnDrop, Zeroizing};

const KEYSTORE_VERSION: u32 = 1;

#[derive(Debug, thiserror::Error)]
pub enum KeystoreError {
    #[error("reading keystore {path}: {source}")]
    Io {
        path: PathBuf,
        #[source]
        source: std::io::Error,
    },
    #[error("keystore {0} is not valid JSON")]
    Malformed(PathBuf),
    #[error("keystore {path} has version {found}, but this build understands {expected}")]
    UnsupportedVersion {
        path: PathBuf,
        found: u32,
        expected: u32,
    },
    #[error("keystore {0} does not contain a valid Ed25519 secret key")]
    BadKey(PathBuf),
    #[error(
        "keystore {path} is readable by other users (mode {mode:o}); \
         run `chmod 600 {}` before using it", path.display()
    )]
    PermissionsTooOpen { path: PathBuf, mode: u32 },
}

/// What [`Keystore::load`] hands back: the key plus the cosmetic profile
/// attached to it.
pub struct LoadedIdentity {
    pub identity: Identity,
    pub nickname: String,
}

/// The file's shape.
///
/// `ZeroizeOnDrop` because `secret_key` is the whole identity in printable form.
/// A `String` that long-lived would otherwise be handed back to the allocator
/// with the key still legible in it.
#[derive(Serialize, Deserialize, Zeroize, ZeroizeOnDrop)]
struct StoredIdentity {
    version: u32,
    /// Base64 of the 32-byte Ed25519 secret scalar seed.
    secret_key: String,
    /// Proof-of-work witness. See [`crate::security_level`].
    counter: u64,
    nickname: String,
}

pub struct Keystore;

impl Keystore {
    /// Load an identity, or generate and persist a new one if the file is absent.
    ///
    /// A fresh identity starts at security level 0. Callers that care should
    /// mine it up and call [`Keystore::save`] again.
    pub fn load_or_create(
        path: &Path,
        default_nickname: &str,
    ) -> Result<LoadedIdentity, KeystoreError> {
        match Self::load(path) {
            Ok(loaded) => Ok(loaded),
            Err(KeystoreError::Io { source, .. })
                if source.kind() == std::io::ErrorKind::NotFound =>
            {
                let identity = Identity::generate();
                Self::save(path, &identity, default_nickname)?;
                Ok(LoadedIdentity {
                    identity,
                    nickname: default_nickname.to_string(),
                })
            }
            Err(other) => Err(other),
        }
    }

    pub fn load(path: &Path) -> Result<LoadedIdentity, KeystoreError> {
        // Zeroizing: the raw text is the secret key in base64.
        let raw = Zeroizing::new(
            fs::read_to_string(path).map_err(|source| KeystoreError::Io {
                path: path.to_path_buf(),
                source,
            })?,
        );

        // Only meaningful once the file exists — hence after the read.
        check_permissions(path)?;

        let stored: StoredIdentity =
            serde_json::from_str(&raw).map_err(|_| KeystoreError::Malformed(path.to_path_buf()))?;

        if stored.version != KEYSTORE_VERSION {
            return Err(KeystoreError::UnsupportedVersion {
                path: path.to_path_buf(),
                found: stored.version,
                expected: KEYSTORE_VERSION,
            });
        }

        let secret = Zeroizing::new(
            BASE64
                .decode(stored.secret_key.as_bytes())
                .ok()
                .and_then(|b| <[u8; 32]>::try_from(b.as_slice()).ok())
                .ok_or_else(|| KeystoreError::BadKey(path.to_path_buf()))?,
        );

        Ok(LoadedIdentity {
            identity: Identity::from_secret_bytes(&secret, stored.counter),
            // Cloned rather than moved: `StoredIdentity` wipes itself on drop,
            // and a type with a `Drop` cannot be taken apart field by field.
            nickname: stored.nickname.clone(),
        })
    }

    /// Persist an identity, replacing any existing file.
    ///
    /// Writes to a sibling temp file and renames, so an interrupted save can
    /// never truncate an existing key into oblivion.
    pub fn save(path: &Path, identity: &Identity, nickname: &str) -> Result<(), KeystoreError> {
        let io_err = |source| KeystoreError::Io {
            path: path.to_path_buf(),
            source,
        };

        if let Some(parent) = path.parent() {
            if !parent.as_os_str().is_empty() {
                fs::create_dir_all(parent).map_err(io_err)?;
            }
        }

        let stored = StoredIdentity {
            version: KEYSTORE_VERSION,
            secret_key: BASE64.encode(identity.secret_bytes().as_slice()),
            counter: identity.counter(),
            nickname: nickname.to_string(),
        };
        // Zeroizing: this is the same key material again, in a third
        // representation. `stored` wipes itself; the rendered JSON has to be
        // told to.
        let json = Zeroizing::new(
            serde_json::to_string_pretty(&stored).expect("StoredIdentity is always serializable"),
        );

        let tmp = path.with_extension("tmp");
        let mut file = create_private(&tmp).map_err(io_err)?;
        file.write_all(json.as_bytes()).map_err(io_err)?;
        file.write_all(b"\n").map_err(io_err)?;
        file.sync_all().map_err(io_err)?;
        drop(file);

        fs::rename(&tmp, path).map_err(io_err)?;
        Ok(())
    }
}

/// Shared with [`crate::vault`], which stores the same kind of secret material
/// and must protect it identically.
#[cfg(unix)]
pub(crate) fn create_private(path: &Path) -> std::io::Result<fs::File> {
    use std::os::unix::fs::OpenOptionsExt;
    fs::OpenOptions::new()
        .write(true)
        .create(true)
        .truncate(true)
        .mode(0o600)
        .open(path)
}

#[cfg(not(unix))]
pub(crate) fn create_private(path: &Path) -> std::io::Result<fs::File> {
    // Windows inherits the parent directory's ACL, which for a per-user app
    // data directory is already user-only.
    fs::File::create(path)
}

#[cfg(unix)]
pub(crate) fn check_permissions(path: &Path) -> Result<(), KeystoreError> {
    use std::os::unix::fs::PermissionsExt;
    let mode = fs::metadata(path)
        .map_err(|source| KeystoreError::Io {
            path: path.to_path_buf(),
            source,
        })?
        .permissions()
        .mode()
        & 0o777;

    if mode & 0o077 != 0 {
        return Err(KeystoreError::PermissionsTooOpen {
            path: path.to_path_buf(),
            mode,
        });
    }
    Ok(())
}

#[cfg(not(unix))]
pub(crate) fn check_permissions(_path: &Path) -> Result<(), KeystoreError> {
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn save_then_load_preserves_the_key_and_counter() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("identity.json");

        let mut original = Identity::generate();
        original.mine(8, &mut |_| true);

        Keystore::save(&path, &original, "andy").unwrap();
        let loaded = Keystore::load(&path).unwrap();

        assert_eq!(loaded.identity.fingerprint(), original.fingerprint());
        assert_eq!(loaded.identity.counter(), original.counter());
        assert_eq!(loaded.identity.security_level(), original.security_level());
        assert_eq!(loaded.nickname, "andy");
    }

    #[test]
    fn load_or_create_generates_once_then_reuses() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("identity.json");

        let first = Keystore::load_or_create(&path, "andy").unwrap();
        let second = Keystore::load_or_create(&path, "someone-else").unwrap();

        assert_eq!(first.identity.fingerprint(), second.identity.fingerprint());
        assert_eq!(second.nickname, "andy", "existing profile must win");
    }

    #[test]
    fn load_or_create_builds_missing_parent_directories() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("nested/deeper/identity.json");
        assert!(Keystore::load_or_create(&path, "andy").is_ok());
        assert!(path.exists());
    }

    #[cfg(unix)]
    #[test]
    fn saved_keystore_is_not_readable_by_others() {
        use std::os::unix::fs::PermissionsExt;
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("identity.json");
        Keystore::save(&path, &Identity::generate(), "andy").unwrap();

        let mode = fs::metadata(&path).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode, 0o600, "secret key must be user-only");
    }

    #[cfg(unix)]
    #[test]
    fn loading_a_world_readable_keystore_is_refused() {
        use std::os::unix::fs::PermissionsExt;
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("identity.json");
        Keystore::save(&path, &Identity::generate(), "andy").unwrap();
        fs::set_permissions(&path, fs::Permissions::from_mode(0o644)).unwrap();

        assert!(matches!(
            Keystore::load(&path),
            Err(KeystoreError::PermissionsTooOpen { .. })
        ));
    }

    #[test]
    fn a_corrupt_keystore_reports_rather_than_silently_regenerating() {
        // Silently making a new identity here would strand the user's
        // permissions on every server they use.
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("identity.json");
        fs::write(&path, "{not json").unwrap();
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            fs::set_permissions(&path, fs::Permissions::from_mode(0o600)).unwrap();
        }
        assert!(matches!(
            Keystore::load_or_create(&path, "andy"),
            Err(KeystoreError::Malformed(_))
        ));
    }

    #[test]
    fn a_future_version_is_refused() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("identity.json");
        Keystore::save(&path, &Identity::generate(), "andy").unwrap();
        let bumped = fs::read_to_string(&path)
            .unwrap()
            .replace("\"version\": 1", "\"version\": 99");
        fs::write(&path, bumped).unwrap();

        assert!(matches!(
            Keystore::load(&path),
            Err(KeystoreError::UnsupportedVersion { found: 99, .. })
        ));
    }
}
