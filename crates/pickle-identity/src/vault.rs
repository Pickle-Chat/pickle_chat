//! A collection of identities, one of them active.
//!
//! [`Keystore`](crate::Keystore) holds exactly one key and is what a *server*
//! wants: a server is one identity by nature, and nothing about it should have
//! to know that clients can carry several. This module sits alongside it rather
//! than replacing it, so the server's key handling is untouched by any of this.
//!
//! The file holds unencrypted Ed25519 secret keys, so it is written `0600` and
//! refuses to load if the permissions have been widened — the same protection,
//! by the same helpers, as the single-key store.
//!
//! Identities are keyed by fingerprint. That is a natural name rather than an
//! invented one: it is derived from the public key, so it cannot drift out of
//! step with the identity it labels, and it is already what the user compares
//! out of band.

use crate::keystore::{check_permissions, create_private};
use crate::{Identity, Keystore, KeystoreError};
use data_encoding::BASE64;
use serde::{Deserialize, Serialize};
use std::fs;
use std::io::Write;
use std::path::{Path, PathBuf};

const VAULT_VERSION: u32 = 2;

/// Suffix given to a v1 keystore once it has been folded into a vault.
///
/// The old file is renamed, never deleted: it holds the only copy of a key, and
/// a rename is recoverable by anyone who needs it while a delete is not.
const MIGRATED_SUFFIX: &str = "v1.bak";

#[derive(Debug, thiserror::Error)]
pub enum VaultError {
    #[error("reading vault {path}: {source}")]
    Io {
        path: PathBuf,
        #[source]
        source: std::io::Error,
    },
    #[error("vault {0} is not valid JSON")]
    Malformed(PathBuf),
    #[error("vault {path} has version {found}, but this build understands {expected}")]
    UnsupportedVersion {
        path: PathBuf,
        found: u32,
        expected: u32,
    },
    #[error("vault {0} contains an entry that is not a valid Ed25519 secret key")]
    BadKey(PathBuf),
    #[error(
        "vault {path} is readable by other users (mode {mode:o}); \
         run `chmod 600 {}` before using it", path.display()
    )]
    PermissionsTooOpen { path: PathBuf, mode: u32 },
    #[error("no identity with fingerprint {0}")]
    NotFound(String),
    #[error("this is the only identity you have; add another before removing it")]
    WouldEmpty,
    #[error("migrating {from}: {source}")]
    Migration {
        from: PathBuf,
        #[source]
        source: Box<KeystoreError>,
    },
}

/// One identity and the profile attached to it.
pub struct VaultEntry {
    pub identity: Identity,
    /// Shown to other users on a server.
    pub nickname: String,
    /// Private note, so several identities with similar nicknames can still be
    /// told apart in the picker. Never leaves this machine.
    pub label: String,
}

#[derive(Serialize, Deserialize)]
struct StoredEntry {
    /// Base64 of the 32-byte Ed25519 secret scalar seed.
    secret_key: String,
    /// Proof-of-work witness. See [`crate::security_level`].
    counter: u64,
    nickname: String,
    #[serde(default)]
    label: String,
}

#[derive(Serialize, Deserialize)]
struct StoredVault {
    version: u32,
    /// Fingerprint of the active identity.
    active: String,
    identities: Vec<StoredEntry>,
}

pub struct Vault {
    path: PathBuf,
    entries: Vec<VaultEntry>,
    active: String,
}

impl Vault {
    /// Open the vault, migrating a v1 keystore or creating a first identity as
    /// needed.
    ///
    /// `legacy` is the single-key file to fold in if the vault does not exist
    /// yet. Passing a path that is absent is fine and simply means a fresh
    /// start.
    pub fn open(path: &Path, legacy: &Path, default_nickname: &str) -> Result<Self, VaultError> {
        match fs::read_to_string(path) {
            Ok(raw) => {
                // Only meaningful once the file exists — hence after the read.
                check_permissions(path).map_err(|e| permissions_error(path, e))?;
                Self::parse(path, &raw)
            }
            Err(source) if source.kind() == std::io::ErrorKind::NotFound => {
                Self::create(path, legacy, default_nickname)
            }
            Err(source) => Err(VaultError::Io {
                path: path.to_path_buf(),
                source,
            }),
        }
    }

    /// Build a vault where none exists: from the v1 keystore if there is one,
    /// otherwise from a freshly generated identity.
    fn create(path: &Path, legacy: &Path, default_nickname: &str) -> Result<Self, VaultError> {
        let (identity, nickname, migrated) = match Keystore::load(legacy) {
            Ok(loaded) => (loaded.identity, loaded.nickname, true),
            // No v1 file: an ordinary first run.
            Err(KeystoreError::Io { source, .. })
                if source.kind() == std::io::ErrorKind::NotFound =>
            {
                (Identity::generate(), default_nickname.to_string(), false)
            }
            // A v1 file that exists but will not load is not something to paper
            // over by generating a new key — that would strand every permission
            // the old one was granted.
            Err(other) => {
                return Err(VaultError::Migration {
                    from: legacy.to_path_buf(),
                    source: Box::new(other),
                })
            }
        };

        let active = identity.fingerprint().to_string();
        let vault = Self {
            path: path.to_path_buf(),
            entries: vec![VaultEntry {
                identity,
                nickname,
                label: String::new(),
            }],
            active,
        };
        vault.save()?;

        // Only once the new file is safely on disk.
        if migrated {
            let backup = legacy.with_extension(MIGRATED_SUFFIX);
            fs::rename(legacy, &backup).map_err(|source| VaultError::Io {
                path: backup,
                source,
            })?;
        }

        Ok(vault)
    }

    fn parse(path: &Path, raw: &str) -> Result<Self, VaultError> {
        let stored: StoredVault =
            serde_json::from_str(raw).map_err(|_| VaultError::Malformed(path.to_path_buf()))?;

        if stored.version != VAULT_VERSION {
            return Err(VaultError::UnsupportedVersion {
                path: path.to_path_buf(),
                found: stored.version,
                expected: VAULT_VERSION,
            });
        }

        let mut entries = Vec::with_capacity(stored.identities.len());
        for entry in stored.identities {
            let secret = BASE64
                .decode(entry.secret_key.as_bytes())
                .ok()
                .and_then(|b| <[u8; 32]>::try_from(b.as_slice()).ok())
                .ok_or_else(|| VaultError::BadKey(path.to_path_buf()))?;

            entries.push(VaultEntry {
                identity: Identity::from_secret_bytes(&secret, entry.counter),
                nickname: entry.nickname,
                label: entry.label,
            });
        }

        if entries.is_empty() {
            return Err(VaultError::Malformed(path.to_path_buf()));
        }

        // A dangling pointer would leave the app with no identity to sign with,
        // so fall back to the first rather than failing to start.
        let active = if entries
            .iter()
            .any(|e| e.identity.fingerprint().to_string() == stored.active)
        {
            stored.active
        } else {
            entries[0].identity.fingerprint().to_string()
        };

        Ok(Self {
            path: path.to_path_buf(),
            entries,
            active,
        })
    }

    pub fn active(&self) -> &VaultEntry {
        self.entries
            .iter()
            .find(|e| e.identity.fingerprint().to_string() == self.active)
            .expect("the active fingerprint is checked to exist whenever it is set")
    }

    pub fn active_mut(&mut self) -> &mut VaultEntry {
        let active = self.active.clone();
        self.entries
            .iter_mut()
            .find(|e| e.identity.fingerprint().to_string() == active)
            .expect("the active fingerprint is checked to exist whenever it is set")
    }

    pub fn active_fingerprint(&self) -> &str {
        &self.active
    }

    pub fn list(&self) -> &[VaultEntry] {
        &self.entries
    }

    pub fn get(&self, fingerprint: &str) -> Option<&VaultEntry> {
        self.entries
            .iter()
            .find(|e| e.identity.fingerprint().to_string() == fingerprint)
    }

    /// Add an identity and return its fingerprint.
    ///
    /// An identity already present is not duplicated; its fingerprint is
    /// returned so the caller can select it instead.
    pub fn add(&mut self, identity: Identity, nickname: &str, label: &str) -> String {
        let fingerprint = identity.fingerprint().to_string();
        if self.get(&fingerprint).is_none() {
            self.entries.push(VaultEntry {
                identity,
                nickname: nickname.to_string(),
                label: label.to_string(),
            });
        }
        fingerprint
    }

    /// Record improved proof of work against an identity.
    ///
    /// Mining is minutes of CPU, so it runs on a copy of the key rather than
    /// under the vault's lock; this is how the result comes back. The keypair is
    /// untouched — only the witness improves — so the fingerprint is unchanged
    /// and every permission the identity holds survives.
    pub fn set_counter(&mut self, fingerprint: &str, counter: u64) -> Result<(), VaultError> {
        let entry = self
            .entries
            .iter_mut()
            .find(|e| e.identity.fingerprint().to_string() == fingerprint)
            .ok_or_else(|| VaultError::NotFound(fingerprint.to_string()))?;

        entry.identity = Identity::from_secret_bytes(&entry.identity.secret_bytes(), counter);
        Ok(())
    }

    pub fn set_nickname(&mut self, fingerprint: &str, nickname: &str) -> Result<(), VaultError> {
        self.entry_mut(fingerprint)?.nickname = nickname.to_string();
        Ok(())
    }

    pub fn set_label(&mut self, fingerprint: &str, label: &str) -> Result<(), VaultError> {
        self.entry_mut(fingerprint)?.label = label.to_string();
        Ok(())
    }

    fn entry_mut(&mut self, fingerprint: &str) -> Result<&mut VaultEntry, VaultError> {
        self.entries
            .iter_mut()
            .find(|e| e.identity.fingerprint().to_string() == fingerprint)
            .ok_or_else(|| VaultError::NotFound(fingerprint.to_string()))
    }

    pub fn set_active(&mut self, fingerprint: &str) -> Result<(), VaultError> {
        if self.get(fingerprint).is_none() {
            return Err(VaultError::NotFound(fingerprint.to_string()));
        }
        self.active = fingerprint.to_string();
        Ok(())
    }

    /// Remove an identity.
    ///
    /// Removing the last one is refused: the application has no meaningful state
    /// without an identity to sign with. Removing the active one moves the
    /// selection to whatever remains, rather than leaving it dangling.
    pub fn remove(&mut self, fingerprint: &str) -> Result<(), VaultError> {
        if self.get(fingerprint).is_none() {
            return Err(VaultError::NotFound(fingerprint.to_string()));
        }
        if self.entries.len() == 1 {
            return Err(VaultError::WouldEmpty);
        }

        self.entries
            .retain(|e| e.identity.fingerprint().to_string() != fingerprint);

        if self.active == fingerprint {
            self.active = self.entries[0].identity.fingerprint().to_string();
        }
        Ok(())
    }

    /// Persist the vault.
    ///
    /// Writes to a sibling temp file and renames, so an interrupted save can
    /// never truncate a file full of keys into oblivion.
    pub fn save(&self) -> Result<(), VaultError> {
        let io_err = |source| VaultError::Io {
            path: self.path.clone(),
            source,
        };

        if let Some(parent) = self.path.parent() {
            if !parent.as_os_str().is_empty() {
                fs::create_dir_all(parent).map_err(io_err)?;
            }
        }

        let stored = StoredVault {
            version: VAULT_VERSION,
            active: self.active.clone(),
            identities: self
                .entries
                .iter()
                .map(|entry| StoredEntry {
                    secret_key: BASE64.encode(&entry.identity.secret_bytes()),
                    counter: entry.identity.counter(),
                    nickname: entry.nickname.clone(),
                    label: entry.label.clone(),
                })
                .collect(),
        };
        let json =
            serde_json::to_string_pretty(&stored).expect("StoredVault is always serializable");

        let tmp = self.path.with_extension("tmp");
        let mut file = create_private(&tmp).map_err(io_err)?;
        file.write_all(json.as_bytes()).map_err(io_err)?;
        file.write_all(b"\n").map_err(io_err)?;
        file.sync_all().map_err(io_err)?;
        drop(file);

        fs::rename(&tmp, &self.path).map_err(io_err)?;
        Ok(())
    }
}

/// Translate the keystore's permission complaint into the vault's own, so the
/// message names the file the user is actually looking at.
fn permissions_error(path: &Path, error: KeystoreError) -> VaultError {
    match error {
        KeystoreError::PermissionsTooOpen { mode, .. } => VaultError::PermissionsTooOpen {
            path: path.to_path_buf(),
            mode,
        },
        KeystoreError::Io { source, .. } => VaultError::Io {
            path: path.to_path_buf(),
            source,
        },
        other => VaultError::Migration {
            from: path.to_path_buf(),
            source: Box::new(other),
        },
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    struct Paths {
        _dir: tempfile::TempDir,
        vault: PathBuf,
        legacy: PathBuf,
    }

    fn paths() -> Paths {
        let dir = tempfile::tempdir().unwrap();
        Paths {
            vault: dir.path().join("identities.json"),
            legacy: dir.path().join("identity.json"),
            _dir: dir,
        }
    }

    #[test]
    fn a_first_run_creates_one_identity_and_selects_it() {
        let p = paths();
        let vault = Vault::open(&p.vault, &p.legacy, "andy").unwrap();

        assert_eq!(vault.list().len(), 1);
        assert_eq!(vault.active().nickname, "andy");
        assert_eq!(
            vault.active_fingerprint(),
            vault.list()[0].identity.fingerprint().to_string()
        );
    }

    #[test]
    fn migration_preserves_the_key_counter_and_level() {
        // The whole point of the migration: the user must come out the other
        // side as the same person to every server they have ever used.
        let p = paths();

        let mut original = Identity::generate();
        original.mine(8, &mut |_| true);
        Keystore::save(&p.legacy, &original, "andy").unwrap();

        let vault = Vault::open(&p.vault, &p.legacy, "ignored").unwrap();
        let migrated = &vault.active().identity;

        assert_eq!(migrated.fingerprint(), original.fingerprint());
        assert_eq!(migrated.counter(), original.counter());
        assert_eq!(migrated.security_level(), original.security_level());
        assert_eq!(vault.active().nickname, "andy", "the profile comes across");
    }

    #[test]
    fn migration_keeps_the_old_file_as_a_backup() {
        // It holds the only copy of a key; deleting it is not recoverable.
        let p = paths();
        Keystore::save(&p.legacy, &Identity::generate(), "andy").unwrap();

        Vault::open(&p.vault, &p.legacy, "ignored").unwrap();

        assert!(!p.legacy.exists(), "the v1 file is moved aside");
        assert!(
            p.legacy.with_extension(MIGRATED_SUFFIX).exists(),
            "and kept as a backup"
        );
    }

    #[test]
    fn migration_happens_once_and_is_not_repeated() {
        let p = paths();
        Keystore::save(&p.legacy, &Identity::generate(), "andy").unwrap();

        let first = Vault::open(&p.vault, &p.legacy, "ignored").unwrap();
        let fingerprint = first.active_fingerprint().to_string();

        let second = Vault::open(&p.vault, &p.legacy, "ignored").unwrap();
        assert_eq!(second.active_fingerprint(), fingerprint);
        assert_eq!(second.list().len(), 1);
    }

    #[test]
    fn an_unreadable_v1_file_is_reported_rather_than_replaced() {
        // Generating a fresh key here would silently strand every permission
        // the old one held.
        let p = paths();
        fs::write(&p.legacy, "{not json").unwrap();
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            fs::set_permissions(&p.legacy, fs::Permissions::from_mode(0o600)).unwrap();
        }

        assert!(matches!(
            Vault::open(&p.vault, &p.legacy, "andy"),
            Err(VaultError::Migration { .. })
        ));
        assert!(
            !p.vault.exists(),
            "nothing is written on a failed migration"
        );
    }

    #[test]
    fn save_then_open_round_trips_every_identity() {
        let p = paths();
        let mut vault = Vault::open(&p.vault, &p.legacy, "andy").unwrap();
        let second = vault.add(Identity::generate(), "alter-ego", "work");
        vault.set_active(&second).unwrap();
        vault.save().unwrap();

        let reopened = Vault::open(&p.vault, &p.legacy, "ignored").unwrap();
        assert_eq!(reopened.list().len(), 2);
        assert_eq!(reopened.active_fingerprint(), second);
        assert_eq!(reopened.active().nickname, "alter-ego");
        assert_eq!(reopened.active().label, "work");
    }

    #[test]
    fn adding_an_identity_twice_does_not_duplicate_it() {
        let p = paths();
        let mut vault = Vault::open(&p.vault, &p.legacy, "andy").unwrap();

        let identity = Identity::generate();
        let bytes = identity.secret_bytes();
        let first = vault.add(identity, "one", "");
        let again = vault.add(Identity::from_secret_bytes(&bytes, 0), "two", "");

        assert_eq!(first, again);
        assert_eq!(vault.list().len(), 2, "the original plus one, not two");
    }

    #[test]
    fn removing_the_active_identity_selects_another() {
        let p = paths();
        let mut vault = Vault::open(&p.vault, &p.legacy, "andy").unwrap();
        let second = vault.add(Identity::generate(), "other", "");
        vault.set_active(&second).unwrap();

        vault.remove(&second).unwrap();

        assert_eq!(vault.list().len(), 1);
        assert_eq!(
            vault.active_fingerprint(),
            vault.list()[0].identity.fingerprint().to_string(),
            "the selection must never dangle",
        );
    }

    #[test]
    fn recording_a_mined_counter_keeps_the_fingerprint() {
        // The guarantee that makes mining safe: raising your level must never
        // cost you the permissions servers granted the key.
        let p = paths();
        let mut vault = Vault::open(&p.vault, &p.legacy, "andy").unwrap();
        let fingerprint = vault.active_fingerprint().to_string();

        // Mine on a copy, exactly as the application does.
        let mut copy = Identity::from_secret_bytes(&vault.active().identity.secret_bytes(), 0);
        copy.mine(8, &mut |_| true);

        vault.set_counter(&fingerprint, copy.counter()).unwrap();

        assert_eq!(vault.active_fingerprint(), fingerprint);
        assert_eq!(vault.active().identity.counter(), copy.counter());
        assert_eq!(
            vault.active().identity.security_level(),
            copy.security_level()
        );
    }

    #[test]
    fn removing_the_last_identity_is_refused() {
        let p = paths();
        let mut vault = Vault::open(&p.vault, &p.legacy, "andy").unwrap();
        let only = vault.active_fingerprint().to_string();

        assert!(matches!(vault.remove(&only), Err(VaultError::WouldEmpty)));
    }

    #[test]
    fn removing_or_selecting_an_unknown_identity_is_an_error() {
        let p = paths();
        let mut vault = Vault::open(&p.vault, &p.legacy, "andy").unwrap();

        assert!(matches!(
            vault.set_active("nope"),
            Err(VaultError::NotFound(_))
        ));
        assert!(matches!(vault.remove("nope"), Err(VaultError::NotFound(_))));
    }

    #[test]
    fn a_dangling_active_pointer_falls_back_rather_than_failing_to_start() {
        let p = paths();
        let vault = Vault::open(&p.vault, &p.legacy, "andy").unwrap();
        vault.save().unwrap();

        let broken = fs::read_to_string(&p.vault)
            .unwrap()
            .replace(vault.active_fingerprint(), "not-a-fingerprint");
        fs::write(&p.vault, broken).unwrap();

        let reopened = Vault::open(&p.vault, &p.legacy, "andy").unwrap();
        assert_eq!(
            reopened.active_fingerprint(),
            reopened.list()[0].identity.fingerprint().to_string()
        );
    }

    #[cfg(unix)]
    #[test]
    fn the_vault_is_not_readable_by_others() {
        use std::os::unix::fs::PermissionsExt;
        let p = paths();
        Vault::open(&p.vault, &p.legacy, "andy").unwrap();

        let mode = fs::metadata(&p.vault).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode, 0o600, "the vault is full of secret keys");
    }

    #[cfg(unix)]
    #[test]
    fn opening_a_world_readable_vault_is_refused() {
        use std::os::unix::fs::PermissionsExt;
        let p = paths();
        Vault::open(&p.vault, &p.legacy, "andy").unwrap();
        fs::set_permissions(&p.vault, fs::Permissions::from_mode(0o644)).unwrap();

        assert!(matches!(
            Vault::open(&p.vault, &p.legacy, "andy"),
            Err(VaultError::PermissionsTooOpen { .. })
        ));
    }

    #[test]
    fn a_future_version_is_refused() {
        let p = paths();
        Vault::open(&p.vault, &p.legacy, "andy").unwrap();

        let bumped = fs::read_to_string(&p.vault)
            .unwrap()
            .replace("\"version\": 2", "\"version\": 99");
        fs::write(&p.vault, bumped).unwrap();

        assert!(matches!(
            Vault::open(&p.vault, &p.legacy, "andy"),
            Err(VaultError::UnsupportedVersion { found: 99, .. })
        ));
    }
}
