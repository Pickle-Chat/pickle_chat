//! A collection of identities, one of them active.
//!
//! [`Keystore`](crate::Keystore) holds exactly one key and is what a *server*
//! wants: a server is one identity by nature, and nothing about it should have
//! to know that clients can carry several. This module sits alongside it rather
//! than replacing it, so the server's key handling is untouched by any of this.
//!
//! The file holds Ed25519 secret keys, so it is written `0600` and refuses to
//! load if the permissions have been widened — the same protection, by the same
//! helpers, as the single-key store.
//!
//! It can additionally be **encrypted with a passphrase**, which is off unless
//! the user turns it on. That default is not laziness. Encryption is the only
//! thing here that can lock a user out of their own identity forever: a
//! forgotten passphrase is unrecoverable by construction, and losing the key
//! costs every permission every server ever granted them. Demanding one from a
//! user who never chose to set it — on an upgrade, say — would be a far worse
//! outcome than the plaintext file they already had. So a vault written before
//! this existed keeps opening exactly as it did, and turning encryption on is an
//! act the user has to perform.
//!
//! When it *is* on, the file is a sealed envelope (see [`crate::sealed`]) whose
//! plaintext is byte-for-byte the document an unencrypted vault stores. There is
//! one description of what an identity is, and encryption wraps it.
//!
//! Identities are keyed by fingerprint. That is a natural name rather than an
//! invented one: it is derived from the public key, so it cannot drift out of
//! step with the identity it labels, and it is already what the user compares
//! out of band.

use crate::keystore::{check_permissions, create_private};
use crate::sealed::{SealError, SealedVault, VaultKey, SEALED_VERSION};
use crate::{Identity, Keystore, KeystoreError};
use data_encoding::BASE64;
use serde::{Deserialize, Serialize};
use std::fs;
use std::io::Write;
use std::path::{Path, PathBuf};
use zeroize::{Zeroize, ZeroizeOnDrop, Zeroizing};

const VAULT_VERSION: u32 = 2;

/// Suffix given to a v1 keystore once it has been folded into a vault.
///
/// The old file is renamed, never deleted: it holds the only copy of a key, and
/// a rename is recoverable by anyone who needs it while a delete is not.
const MIGRATED_SUFFIX: &str = "v1.bak";

/// Extension of the file a re-encryption is staged in before it replaces the
/// real one. Distinct from `save`'s `.tmp` so the two can never collide.
const STAGING_SUFFIX: &str = "rekey";

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
    #[error(
        "vault {path} has version {found}, but this build understands {expected} \
         (unencrypted) and 3 (passphrase-encrypted)"
    )]
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
    #[error("vault {0} is encrypted; a passphrase is needed to open it")]
    PassphraseRequired(PathBuf),
    #[error("could not open vault {path}: {source}")]
    Locked {
        path: PathBuf,
        #[source]
        source: SealError,
    },
    /// A newly written file did not read back as the vault that produced it, so
    /// it was thrown away and the original left alone. Should be unreachable;
    /// it exists so that if it ever is reached, nobody loses a key over it.
    #[error(
        "the re-encrypted vault did not read back correctly, so {0} was left unchanged; \
         your identities are safe and nothing was written"
    )]
    VerificationFailed(PathBuf),
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

/// One entry as it appears in the file.
///
/// `ZeroizeOnDrop` because `secret_key` is a whole identity in printable form.
/// This struct exists on both the read and the write path, so without it every
/// load and every save would leave a legible key in freed heap.
#[derive(Serialize, Deserialize, Zeroize, ZeroizeOnDrop)]
struct StoredEntry {
    /// Base64 of the 32-byte Ed25519 secret scalar seed.
    secret_key: String,
    /// Proof-of-work witness. See [`crate::security_level`].
    counter: u64,
    nickname: String,
    #[serde(default)]
    label: String,
}

#[derive(Serialize, Deserialize, Zeroize, ZeroizeOnDrop)]
struct StoredVault {
    version: u32,
    /// Fingerprint of the active identity.
    active: String,
    identities: Vec<StoredEntry>,
}

/// Just enough of any vault file to tell which kind it is.
///
/// Read before anything else, because the answer decides whether the rest of the
/// document is readable at all.
#[derive(Deserialize)]
struct VersionProbe {
    version: u32,
}

/// How the file on disk is protected.
enum Protection {
    /// Plaintext JSON, as every vault was before encryption existed.
    None,
    /// A sealed envelope, and the key it was opened with — kept so that saving
    /// does not have to ask the user for the passphrase again, or re-run the
    /// KDF, every time a nickname changes.
    Passphrase(Box<VaultKey>),
}

pub struct Vault {
    path: PathBuf,
    entries: Vec<VaultEntry>,
    active: String,
    protection: Protection,
}

impl Vault {
    /// Open an unencrypted vault, migrating a v1 keystore or creating a first
    /// identity as needed.
    ///
    /// `legacy` is the single-key file to fold in if the vault does not exist
    /// yet. Passing a path that is absent is fine and simply means a fresh
    /// start.
    ///
    /// Fails with [`VaultError::PassphraseRequired`] if the vault turns out to
    /// be encrypted. Callers that can ask a user for one should check
    /// [`Vault::needs_passphrase`] first and use
    /// [`Vault::open_with_passphrase`].
    pub fn open(path: &Path, legacy: &Path, default_nickname: &str) -> Result<Self, VaultError> {
        Self::open_with_passphrase(path, legacy, default_nickname, None)
    }

    /// Open a vault that may be encrypted.
    ///
    /// `passphrase` is ignored if the file is not encrypted, so a caller that
    /// has one cached does not have to ask which kind of vault it is holding
    /// first. It is *not* silently applied to an unencrypted vault either —
    /// turning encryption on is [`Vault::set_passphrase`], and it is never
    /// something that happens as a side effect of opening a file.
    pub fn open_with_passphrase(
        path: &Path,
        legacy: &Path,
        default_nickname: &str,
        passphrase: Option<&str>,
    ) -> Result<Self, VaultError> {
        match fs::read_to_string(path) {
            // Zeroizing: for an unencrypted vault this text is every secret key
            // the user owns.
            Ok(raw) => {
                // Only meaningful once the file exists — hence after the read.
                check_permissions(path).map_err(|e| permissions_error(path, e))?;
                Self::parse(path, &Zeroizing::new(raw), passphrase)
            }
            Err(source) if source.kind() == std::io::ErrorKind::NotFound => {
                Self::create(path, legacy, default_nickname, passphrase)
            }
            Err(source) => Err(VaultError::Io {
                path: path.to_path_buf(),
                source,
            }),
        }
    }

    /// Whether the vault at `path` will ask for a passphrase.
    ///
    /// Answered without decrypting anything, so a caller can decide whether to
    /// put a prompt on screen before it has anything to unlock. A vault that
    /// does not exist yet answers `false`: one is about to be created, and a new
    /// vault is created unencrypted unless the caller says otherwise.
    pub fn needs_passphrase(path: &Path) -> Result<bool, VaultError> {
        // Zeroizing even here: an unencrypted vault's text is every key the user
        // owns, and this reads the whole file to find one number.
        let raw = match fs::read_to_string(path) {
            Ok(raw) => Zeroizing::new(raw),
            Err(source) if source.kind() == std::io::ErrorKind::NotFound => return Ok(false),
            Err(source) => {
                return Err(VaultError::Io {
                    path: path.to_path_buf(),
                    source,
                })
            }
        };

        let probe: VersionProbe =
            serde_json::from_str(&raw).map_err(|_| VaultError::Malformed(path.to_path_buf()))?;
        Ok(probe.version == SEALED_VERSION)
    }

    /// Whether this vault is encrypted at rest.
    pub fn is_encrypted(&self) -> bool {
        matches!(self.protection, Protection::Passphrase(_))
    }

    /// Build a vault where none exists: from the v1 keystore if there is one,
    /// otherwise from a freshly generated identity.
    fn create(
        path: &Path,
        legacy: &Path,
        default_nickname: &str,
        passphrase: Option<&str>,
    ) -> Result<Self, VaultError> {
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

        let protection =
            match passphrase {
                Some(passphrase) => Protection::Passphrase(Box::new(
                    VaultKey::fresh(passphrase).map_err(|source| VaultError::Locked {
                        path: path.to_path_buf(),
                        source,
                    })?,
                )),
                None => Protection::None,
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
            protection,
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

    fn parse(path: &Path, raw: &str, passphrase: Option<&str>) -> Result<Self, VaultError> {
        let malformed = || VaultError::Malformed(path.to_path_buf());

        // The version is read on its own first, because it decides whether the
        // rest of the document is a vault or a ciphertext.
        let probe: VersionProbe = serde_json::from_str(raw).map_err(|_| malformed())?;
        let (stored, protection) = match probe.version {
            VAULT_VERSION => (
                serde_json::from_str::<StoredVault>(raw).map_err(|_| malformed())?,
                Protection::None,
            ),
            SEALED_VERSION => Self::unseal(path, raw, passphrase)?,
            found => {
                return Err(VaultError::UnsupportedVersion {
                    path: path.to_path_buf(),
                    found,
                    expected: VAULT_VERSION,
                })
            }
        };

        let mut entries = Vec::with_capacity(stored.identities.len());
        // By reference, not by value: `StoredEntry` wipes itself on drop, and a
        // type with a `Drop` cannot be taken apart field by field.
        for entry in &stored.identities {
            let secret = Zeroizing::new(
                BASE64
                    .decode(entry.secret_key.as_bytes())
                    .ok()
                    .and_then(|b| <[u8; 32]>::try_from(b.as_slice()).ok())
                    .ok_or_else(|| VaultError::BadKey(path.to_path_buf()))?,
            );

            entries.push(VaultEntry {
                identity: Identity::from_secret_bytes(&secret, entry.counter),
                nickname: entry.nickname.clone(),
                label: entry.label.clone(),
            });
        }

        if entries.is_empty() {
            return Err(malformed());
        }

        // A dangling pointer would leave the app with no identity to sign with,
        // so fall back to the first rather than failing to start.
        let active = if entries
            .iter()
            .any(|e| e.identity.fingerprint().to_string() == stored.active)
        {
            stored.active.clone()
        } else {
            entries[0].identity.fingerprint().to_string()
        };

        Ok(Self {
            path: path.to_path_buf(),
            entries,
            active,
            protection,
        })
    }

    /// Decrypt a sealed vault file into the same document a plaintext one holds.
    fn unseal(
        path: &Path,
        raw: &str,
        passphrase: Option<&str>,
    ) -> Result<(StoredVault, Protection), VaultError> {
        let locked = |source| VaultError::Locked {
            path: path.to_path_buf(),
            source,
        };

        let sealed: SealedVault =
            serde_json::from_str(raw).map_err(|_| VaultError::Malformed(path.to_path_buf()))?;
        let passphrase =
            passphrase.ok_or_else(|| VaultError::PassphraseRequired(path.to_path_buf()))?;

        let key = VaultKey::derive(passphrase, &sealed.kdf).map_err(locked)?;
        let plaintext = key.open(&sealed).map_err(locked)?;

        // Anything that fails from here on is a damaged file rather than a wrong
        // passphrase: the tag already proved these bytes are the ones we wrote.
        let stored: StoredVault = serde_json::from_slice(&plaintext)
            .map_err(|_| VaultError::Malformed(path.to_path_buf()))?;
        if stored.version != VAULT_VERSION {
            return Err(VaultError::UnsupportedVersion {
                path: path.to_path_buf(),
                found: stored.version,
                expected: VAULT_VERSION,
            });
        }

        Ok((stored, Protection::Passphrase(Box::new(key))))
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

    /// Persist the vault, in whichever form it is currently protected by.
    ///
    /// Writes to a sibling temp file and renames, so an interrupted save can
    /// never truncate a file full of keys into oblivion.
    pub fn save(&self) -> Result<(), VaultError> {
        let tmp = self.path.with_extension("tmp");
        let bytes = self.encode(&self.protection)?;
        self.write_private(&tmp, &bytes)?;
        fs::rename(&tmp, &self.path).map_err(|source| VaultError::Io {
            path: self.path.clone(),
            source,
        })
    }

    /// Turn on passphrase encryption, or change the passphrase already in use.
    ///
    /// No current passphrase is asked for, because holding an unlocked `Vault`
    /// already required one: this is a re-encryption of keys the caller can
    /// plainly see, not an authentication step.
    ///
    /// # What this cannot do
    ///
    /// There is no recovery. Forgetting the passphrase destroys every identity
    /// in the vault as surely as deleting the file, and no amount of care here
    /// can change that — it is the point of the feature. Callers must say so
    /// before they call this.
    pub fn set_passphrase(&mut self, passphrase: &str) -> Result<(), VaultError> {
        let key = VaultKey::fresh(passphrase).map_err(|source| VaultError::Locked {
            path: self.path.clone(),
            source,
        })?;
        self.rewrite_verified(Protection::Passphrase(Box::new(key)), Some(passphrase))
    }

    /// Go back to an unencrypted vault.
    pub fn remove_passphrase(&mut self) -> Result<(), VaultError> {
        self.rewrite_verified(Protection::None, None)
    }

    /// Replace the file with one written under a different protection, but only
    /// after proving the new file gives the keys back.
    ///
    /// This is the one operation that could destroy a user's only copy of an
    /// identity: everything else either adds a key or rewrites the file in a
    /// form we have just read. The v1 migration's answer — keep the old file as
    /// a backup — is no good here, because a plaintext backup of a vault the
    /// user just asked to encrypt would hand an attacker exactly what the
    /// encryption was for. So instead of a backup, the new file is written
    /// alongside the old, read back *from disk* with the passphrase the user
    /// will actually type next time, and compared key for key. Only if it comes
    /// back identical does it replace the original; otherwise it is removed and
    /// nothing has changed.
    fn rewrite_verified(
        &mut self,
        protection: Protection,
        passphrase: Option<&str>,
    ) -> Result<(), VaultError> {
        let staging = self.path.with_extension(STAGING_SUFFIX);
        let bytes = self.encode(&protection)?;
        self.write_private(&staging, &bytes)?;

        let verified = Self::open_with_passphrase(
            &staging,
            // Unreachable: `staging` was just written, so the missing-file path
            // that consults `legacy` cannot be taken.
            Path::new(""),
            "",
            passphrase,
        )
        .and_then(|reopened| {
            if reopened.holds_the_same_identities_as(self) {
                Ok(())
            } else {
                Err(VaultError::VerificationFailed(self.path.clone()))
            }
        });

        if let Err(error) = verified {
            // The original is untouched; drop the candidate rather than leave a
            // half-trusted file with keys in it lying about.
            let _ = fs::remove_file(&staging);
            return Err(error);
        }

        fs::rename(&staging, &self.path).map_err(|source| VaultError::Io {
            path: self.path.clone(),
            source,
        })?;
        self.protection = protection;
        Ok(())
    }

    /// Whether `other` round-tripped to exactly this vault — every key, witness,
    /// name and the selection.
    fn holds_the_same_identities_as(&self, other: &Self) -> bool {
        self.active == other.active
            && self.entries.len() == other.entries.len()
            && self.entries.iter().zip(&other.entries).all(|(a, b)| {
                a.identity.secret_bytes() == b.identity.secret_bytes()
                    && a.identity.counter() == b.identity.counter()
                    && a.nickname == b.nickname
                    && a.label == b.label
            })
    }

    /// The exact bytes of the file, encrypted or not.
    fn encode(&self, protection: &Protection) -> Result<Zeroizing<Vec<u8>>, VaultError> {
        let stored = StoredVault {
            version: VAULT_VERSION,
            active: self.active.clone(),
            identities: self
                .entries
                .iter()
                .map(|entry| StoredEntry {
                    secret_key: BASE64.encode(entry.identity.secret_bytes().as_slice()),
                    counter: entry.identity.counter(),
                    nickname: entry.nickname.clone(),
                    label: entry.label.clone(),
                })
                .collect(),
        };
        // Zeroizing: `stored` wipes itself, but the rendered JSON is the same
        // keys again in a second buffer and has to be told to.
        let body = Zeroizing::new(
            serde_json::to_vec_pretty(&stored).expect("StoredVault is always serializable"),
        );

        let mut out = match protection {
            Protection::None => body,
            Protection::Passphrase(key) => {
                let sealed = key.seal(&body).map_err(|source| VaultError::Locked {
                    path: self.path.clone(),
                    source,
                })?;
                // The envelope holds no plaintext secret, but it costs nothing
                // to treat every buffer on this path the same way.
                Zeroizing::new(
                    serde_json::to_vec_pretty(&sealed).expect("SealedVault is always serializable"),
                )
            }
        };
        out.push(b'\n');
        Ok(out)
    }

    /// Write bytes to a user-only file, durably.
    ///
    /// `sync_all` before the caller renames: without it a crash can leave the
    /// rename visible while the contents are not, which for this file means an
    /// empty vault where the identities used to be.
    fn write_private(&self, path: &Path, bytes: &[u8]) -> Result<(), VaultError> {
        let io_err = |source| VaultError::Io {
            path: path.to_path_buf(),
            source,
        };

        if let Some(parent) = path.parent() {
            if !parent.as_os_str().is_empty() {
                fs::create_dir_all(parent).map_err(io_err)?;
            }
        }

        let mut file = create_private(path).map_err(io_err)?;
        file.write_all(bytes).map_err(io_err)?;
        file.sync_all().map_err(io_err)?;
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

    // --- passphrase encryption ---------------------------------------------

    const PASSPHRASE: &str = "correct horse battery staple";

    /// A vault with two identities, one of them mined, so that a round trip has
    /// something to get wrong.
    fn populated(p: &Paths) -> Vault {
        let mut vault = Vault::open(&p.vault, &p.legacy, "andy").unwrap();
        let first = vault.active_fingerprint().to_string();

        let mut mined = Identity::generate();
        mined.mine(8, &mut |_| true);
        let second = vault.add(mined, "alter-ego", "work");

        vault.set_active(&second).unwrap();
        vault.set_active(&first).unwrap();
        vault.save().unwrap();
        vault
    }

    /// Everything about a vault that must survive a round trip, in a form two
    /// vaults can be compared on.
    fn snapshot(vault: &Vault) -> Vec<(String, [u8; 32], u64, String, String)> {
        vault
            .list()
            .iter()
            .map(|e| {
                (
                    e.identity.fingerprint().to_string(),
                    *e.identity.secret_bytes(),
                    e.identity.counter(),
                    e.nickname.clone(),
                    e.label.clone(),
                )
            })
            .collect()
    }

    #[test]
    fn encrypting_and_reopening_preserves_every_identity_exactly() {
        // The whole bargain: a passphrase must cost the user nothing but the
        // typing. Every key, witness, nickname and label comes back.
        let p = paths();
        let mut vault = populated(&p);
        let before = snapshot(&vault);
        let active = vault.active_fingerprint().to_string();

        vault.set_passphrase(PASSPHRASE).unwrap();

        let reopened =
            Vault::open_with_passphrase(&p.vault, &p.legacy, "ignored", Some(PASSPHRASE)).unwrap();
        assert_eq!(snapshot(&reopened), before);
        assert_eq!(reopened.active_fingerprint(), active);
        assert!(reopened.is_encrypted());
    }

    #[test]
    fn an_encrypted_vault_holds_no_key_material_in_the_clear() {
        let p = paths();
        let mut vault = populated(&p);
        let secret = BASE64.encode(vault.active().identity.secret_bytes().as_slice());
        vault.set_passphrase(PASSPHRASE).unwrap();

        let raw = fs::read_to_string(&p.vault).unwrap();
        assert!(!raw.contains(&secret), "the secret key must not be legible");
        assert!(
            !raw.contains("alter-ego"),
            "nor the profile attached to it: nicknames say who the user is",
        );
        assert!(
            !raw.contains(vault.active_fingerprint()),
            "nor the fingerprint, which names the key on every server it uses",
        );
    }

    #[test]
    fn an_encrypted_vault_will_not_open_without_a_passphrase() {
        let p = paths();
        let mut vault = populated(&p);
        vault.set_passphrase(PASSPHRASE).unwrap();

        assert!(matches!(
            Vault::open(&p.vault, &p.legacy, "andy"),
            Err(VaultError::PassphraseRequired(_))
        ));
    }

    #[test]
    fn the_wrong_passphrase_fails_rather_than_producing_a_key() {
        // The failure that matters most: a near miss must be an error, never a
        // vault full of keys that are subtly not the user's.
        let p = paths();
        let mut vault = populated(&p);
        vault.set_passphrase(PASSPHRASE).unwrap();

        let result = Vault::open_with_passphrase(&p.vault, &p.legacy, "andy", Some("hunter2"));
        assert!(matches!(
            result,
            Err(VaultError::Locked {
                source: SealError::Unauthentic,
                ..
            })
        ));
    }

    #[test]
    fn a_wrong_passphrase_does_not_replace_the_vault() {
        // A failed unlock must leave the file alone. Rewriting it here would
        // destroy the identities the user was one typo away from reaching.
        let p = paths();
        let mut vault = populated(&p);
        vault.set_passphrase(PASSPHRASE).unwrap();
        let before = fs::read(&p.vault).unwrap();

        let _ = Vault::open_with_passphrase(&p.vault, &p.legacy, "andy", Some("hunter2"));
        let _ = Vault::open(&p.vault, &p.legacy, "andy");

        assert_eq!(fs::read(&p.vault).unwrap(), before);
        let recovered =
            Vault::open_with_passphrase(&p.vault, &p.legacy, "andy", Some(PASSPHRASE)).unwrap();
        assert_eq!(snapshot(&recovered), snapshot(&vault));
    }

    #[test]
    fn an_existing_unencrypted_vault_keeps_opening_untouched() {
        // Nobody who never asked for a passphrase may be made to type one.
        let p = paths();
        let vault = populated(&p);
        let before = snapshot(&vault);
        drop(vault);

        let reopened = Vault::open(&p.vault, &p.legacy, "ignored").unwrap();
        assert!(!reopened.is_encrypted());
        assert_eq!(snapshot(&reopened), before);
        assert!(!Vault::needs_passphrase(&p.vault).unwrap());
    }

    #[test]
    fn a_passphrase_offered_to_an_unencrypted_vault_does_not_encrypt_it() {
        // Opening a file is never the moment encryption gets turned on; a caller
        // holding a cached passphrase must not silently convert the vault.
        let p = paths();
        populated(&p);

        let vault =
            Vault::open_with_passphrase(&p.vault, &p.legacy, "ignored", Some(PASSPHRASE)).unwrap();
        assert!(!vault.is_encrypted());
        vault.save().unwrap();
        assert!(Vault::open(&p.vault, &p.legacy, "ignored").is_ok());
    }

    #[test]
    fn needs_passphrase_answers_before_anything_is_decrypted() {
        let p = paths();
        assert!(
            !Vault::needs_passphrase(&p.vault).unwrap(),
            "a vault that does not exist yet is about to be created unencrypted",
        );

        let mut vault = populated(&p);
        assert!(!Vault::needs_passphrase(&p.vault).unwrap());

        vault.set_passphrase(PASSPHRASE).unwrap();
        assert!(Vault::needs_passphrase(&p.vault).unwrap());
    }

    #[test]
    fn ordinary_saves_keep_the_vault_encrypted() {
        // Encryption is a property of the vault, not of the one call that
        // enabled it: a nickname edit must not quietly write plaintext back.
        let p = paths();
        let mut vault = populated(&p);
        vault.set_passphrase(PASSPHRASE).unwrap();

        let active = vault.active_fingerprint().to_string();
        vault.set_nickname(&active, "renamed").unwrap();
        vault.save().unwrap();

        assert!(Vault::needs_passphrase(&p.vault).unwrap());
        let reopened =
            Vault::open_with_passphrase(&p.vault, &p.legacy, "ignored", Some(PASSPHRASE)).unwrap();
        assert_eq!(reopened.active().nickname, "renamed");
    }

    #[test]
    fn changing_the_passphrase_retires_the_old_one() {
        let p = paths();
        let mut vault = populated(&p);
        let before = snapshot(&vault);

        vault.set_passphrase(PASSPHRASE).unwrap();
        vault.set_passphrase("something else entirely").unwrap();

        assert!(matches!(
            Vault::open_with_passphrase(&p.vault, &p.legacy, "andy", Some(PASSPHRASE)),
            Err(VaultError::Locked { .. })
        ));
        let reopened = Vault::open_with_passphrase(
            &p.vault,
            &p.legacy,
            "ignored",
            Some("something else entirely"),
        )
        .unwrap();
        assert_eq!(snapshot(&reopened), before);
    }

    #[test]
    fn removing_the_passphrase_returns_an_ordinary_vault() {
        let p = paths();
        let mut vault = populated(&p);
        let before = snapshot(&vault);

        vault.set_passphrase(PASSPHRASE).unwrap();
        vault.remove_passphrase().unwrap();

        assert!(!vault.is_encrypted());
        let reopened = Vault::open(&p.vault, &p.legacy, "ignored").unwrap();
        assert_eq!(snapshot(&reopened), before);
    }

    #[test]
    fn re_encrypting_leaves_no_staging_file_behind() {
        // The staging file holds every key in the vault. Whatever happens, it
        // must not survive the operation that created it.
        let p = paths();
        let mut vault = populated(&p);
        vault.set_passphrase(PASSPHRASE).unwrap();
        vault.remove_passphrase().unwrap();

        assert!(!p.vault.with_extension(STAGING_SUFFIX).exists());
    }

    #[test]
    fn a_first_run_can_start_out_encrypted() {
        let p = paths();
        let vault =
            Vault::open_with_passphrase(&p.vault, &p.legacy, "andy", Some(PASSPHRASE)).unwrap();

        assert!(vault.is_encrypted());
        assert_eq!(vault.active().nickname, "andy");
        assert!(Vault::needs_passphrase(&p.vault).unwrap());
    }

    #[test]
    fn migrating_a_v1_keystore_into_an_encrypted_vault_preserves_the_key() {
        let p = paths();
        let mut original = Identity::generate();
        original.mine(8, &mut |_| true);
        Keystore::save(&p.legacy, &original, "andy").unwrap();

        let vault =
            Vault::open_with_passphrase(&p.vault, &p.legacy, "ignored", Some(PASSPHRASE)).unwrap();

        assert!(vault.is_encrypted());
        assert_eq!(
            vault.active().identity.fingerprint(),
            original.fingerprint()
        );
        assert_eq!(vault.active().identity.counter(), original.counter());
        assert_eq!(vault.active().nickname, "andy");
        assert!(
            p.legacy.with_extension(MIGRATED_SUFFIX).exists(),
            "the v1 file is still kept, not deleted",
        );
    }

    #[test]
    fn a_truncated_encrypted_vault_is_reported_rather_than_regenerated() {
        // Silently generating a fresh identity over a damaged file is the worst
        // thing this code could do: the user would appear to be a stranger on
        // every server they have ever used, with no sign anything went wrong.
        let p = paths();
        let mut vault = populated(&p);
        vault.set_passphrase(PASSPHRASE).unwrap();

        let whole = fs::read_to_string(&p.vault).unwrap();
        fs::write(&p.vault, &whole[..whole.len() / 2]).unwrap();

        assert!(matches!(
            Vault::open_with_passphrase(&p.vault, &p.legacy, "andy", Some(PASSPHRASE)),
            Err(VaultError::Malformed(_))
        ));
    }

    #[test]
    fn a_corrupted_ciphertext_is_reported_rather_than_regenerated() {
        let p = paths();
        let mut vault = populated(&p);
        vault.set_passphrase(PASSPHRASE).unwrap();

        // A single flipped character in the body, leaving the JSON intact — the
        // kind of damage a failing disk produces rather than an editor.
        let raw = fs::read_to_string(&p.vault).unwrap();
        let sealed: serde_json::Value = serde_json::from_str(&raw).unwrap();
        let mut ciphertext = sealed["ciphertext"].as_str().unwrap().to_string();
        let flipped = if ciphertext.starts_with('A') {
            'B'
        } else {
            'A'
        };
        ciphertext.replace_range(0..1, &flipped.to_string());
        fs::write(
            &p.vault,
            raw.replace(sealed["ciphertext"].as_str().unwrap(), &ciphertext),
        )
        .unwrap();

        assert!(matches!(
            Vault::open_with_passphrase(&p.vault, &p.legacy, "andy", Some(PASSPHRASE)),
            Err(VaultError::Locked { .. })
        ));
    }

    #[cfg(unix)]
    #[test]
    fn an_encrypted_vault_is_still_not_readable_by_others() {
        // Belt and braces. The passphrase is the user's protection against a
        // stolen disk; the mode is their protection against the other accounts
        // on the machine they are using right now.
        use std::os::unix::fs::PermissionsExt;
        let p = paths();
        let mut vault = populated(&p);
        vault.set_passphrase(PASSPHRASE).unwrap();

        let mode = fs::metadata(&p.vault).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode, 0o600);
    }

    #[cfg(unix)]
    #[test]
    fn opening_a_world_readable_encrypted_vault_is_still_refused() {
        use std::os::unix::fs::PermissionsExt;
        let p = paths();
        let mut vault = populated(&p);
        vault.set_passphrase(PASSPHRASE).unwrap();
        fs::set_permissions(&p.vault, fs::Permissions::from_mode(0o644)).unwrap();

        assert!(matches!(
            Vault::open_with_passphrase(&p.vault, &p.legacy, "andy", Some(PASSPHRASE)),
            Err(VaultError::PermissionsTooOpen { .. })
        ));
    }
}
