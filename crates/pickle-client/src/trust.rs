//! Trust on first use for server identities.
//!
//! Pickle has no certificate authority, so the first connection to an address
//! cannot be verified against anything — the client records the identity it
//! saw and treats a later change as suspicious. This is exactly SSH's
//! `known_hosts` model, and it fails the same way: it cannot detect an attacker
//! present from the very first connection. Users who need certainty should
//! compare the fingerprint out of band, which is why the server prints it at
//! startup.
//!
//! Entries are keyed by address, since that is what the user typed. The pinned
//! value is the server's Ed25519 identity rather than its TLS certificate, so
//! rotating the certificate does not trip the alarm.

use pickle_identity::Fingerprint;
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

#[derive(Debug, thiserror::Error)]
pub enum TrustError {
    #[error("reading {path}: {source}")]
    Io {
        path: PathBuf,
        #[source]
        source: std::io::Error,
    },
    #[error("{0} is not valid JSON")]
    Malformed(PathBuf),
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TrustedServer {
    pub fingerprint: Fingerprint,
    /// Last name the server advertised. Cosmetic; a rename is not suspicious.
    pub name: String,
    pub first_seen_unix_ms: u64,
    pub last_seen_unix_ms: u64,
}

/// What the client should do about the identity it just saw.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TrustDecision {
    /// Never seen this address before. Show the fingerprint and let the user
    /// decide.
    FirstContact { fingerprint: Fingerprint },
    /// Matches what was pinned.
    Recognised,
    /// Pinned identity does not match. Either the operator moved the server and
    /// lost the key, someone else now answers on this address, or a machine in
    /// the middle is impersonating it. Never resolve this silently.
    Changed {
        expected: Fingerprint,
        actual: Fingerprint,
    },
}

#[derive(Debug, Default, Serialize, Deserialize)]
struct StoreFile {
    #[serde(default)]
    servers: BTreeMap<String, TrustedServer>,
}

/// The on-disk set of pinned servers.
pub struct TrustStore {
    path: PathBuf,
    file: StoreFile,
}

impl TrustStore {
    /// Load the store, treating a missing file as empty.
    pub fn open(path: &Path) -> Result<Self, TrustError> {
        let file = match std::fs::read_to_string(path) {
            Ok(raw) => {
                serde_json::from_str(&raw).map_err(|_| TrustError::Malformed(path.to_path_buf()))?
            }
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => StoreFile::default(),
            Err(source) => {
                return Err(TrustError::Io {
                    path: path.to_path_buf(),
                    source,
                })
            }
        };

        Ok(Self {
            path: path.to_path_buf(),
            file,
        })
    }

    /// An in-memory store that never touches disk. For tests and ephemeral
    /// sessions.
    pub fn ephemeral() -> Self {
        Self {
            path: PathBuf::new(),
            file: StoreFile::default(),
        }
    }

    pub fn get(&self, address: &str) -> Option<&TrustedServer> {
        self.file.servers.get(address)
    }

    pub fn iter(&self) -> impl Iterator<Item = (&String, &TrustedServer)> {
        self.file.servers.iter()
    }

    /// Compare an observed identity against what is pinned for `address`.
    ///
    /// Read-only: nothing is recorded until [`TrustStore::trust`] is called,
    /// so the caller can put a change in front of the user first.
    pub fn check(&self, address: &str, fingerprint: Fingerprint) -> TrustDecision {
        match self.file.servers.get(address) {
            None => TrustDecision::FirstContact { fingerprint },
            Some(known) if known.fingerprint == fingerprint => TrustDecision::Recognised,
            Some(known) => TrustDecision::Changed {
                expected: known.fingerprint,
                actual: fingerprint,
            },
        }
    }

    /// Pin an identity for `address`, replacing any previous entry.
    ///
    /// Calling this after [`TrustDecision::Changed`] is how a user accepts a
    /// server's new key — it must be a deliberate act, never automatic.
    pub fn trust(&mut self, address: &str, fingerprint: Fingerprint, name: &str) {
        let now = now_unix_ms();
        let entry = self
            .file
            .servers
            .entry(address.to_string())
            .or_insert_with(|| TrustedServer {
                fingerprint,
                name: name.to_string(),
                first_seen_unix_ms: now,
                last_seen_unix_ms: now,
            });

        // Preserve first_seen across a re-pin; it is useful context when
        // showing the user that a long-trusted server changed keys.
        entry.fingerprint = fingerprint;
        entry.name = name.to_string();
        entry.last_seen_unix_ms = now;
    }

    pub fn forget(&mut self, address: &str) -> bool {
        self.file.servers.remove(address).is_some()
    }

    pub fn save(&self) -> Result<(), TrustError> {
        if self.path.as_os_str().is_empty() {
            return Ok(()); // ephemeral
        }

        let io_err = |source| TrustError::Io {
            path: self.path.clone(),
            source,
        };

        if let Some(parent) = self.path.parent() {
            if !parent.as_os_str().is_empty() {
                std::fs::create_dir_all(parent).map_err(io_err)?;
            }
        }

        let json =
            serde_json::to_string_pretty(&self.file).expect("StoreFile is always serializable");
        std::fs::write(&self.path, json).map_err(io_err)
    }
}

fn now_unix_ms() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_millis() as u64)
        .unwrap_or(0)
}

#[cfg(test)]
mod tests {
    use super::*;
    use pickle_identity::Identity;

    fn fingerprint() -> Fingerprint {
        Identity::generate().fingerprint()
    }

    #[test]
    fn an_unknown_address_is_first_contact() {
        let store = TrustStore::ephemeral();
        let fp = fingerprint();
        assert_eq!(
            store.check("1.2.3.4:42071", fp),
            TrustDecision::FirstContact { fingerprint: fp }
        );
    }

    #[test]
    fn a_pinned_identity_is_recognised() {
        let mut store = TrustStore::ephemeral();
        let fp = fingerprint();
        store.trust("1.2.3.4:42071", fp, "Andy's Server");
        assert_eq!(store.check("1.2.3.4:42071", fp), TrustDecision::Recognised);
    }

    #[test]
    fn a_different_identity_on_a_known_address_is_flagged() {
        let mut store = TrustStore::ephemeral();
        let original = fingerprint();
        let impostor = fingerprint();
        store.trust("1.2.3.4:42071", original, "Andy's Server");

        assert_eq!(
            store.check("1.2.3.4:42071", impostor),
            TrustDecision::Changed {
                expected: original,
                actual: impostor,
            }
        );
    }

    #[test]
    fn checking_does_not_pin() {
        // The user must get a chance to refuse before anything is recorded.
        let store = TrustStore::ephemeral();
        let fp = fingerprint();
        store.check("1.2.3.4:42071", fp);
        assert!(store.get("1.2.3.4:42071").is_none());
    }

    #[test]
    fn a_server_rename_is_not_treated_as_a_change() {
        let mut store = TrustStore::ephemeral();
        let fp = fingerprint();
        store.trust("1.2.3.4:42071", fp, "Old Name");
        store.trust("1.2.3.4:42071", fp, "New Name");

        assert_eq!(store.check("1.2.3.4:42071", fp), TrustDecision::Recognised);
        assert_eq!(store.get("1.2.3.4:42071").unwrap().name, "New Name");
    }

    #[test]
    fn re_pinning_keeps_the_original_first_seen() {
        let mut store = TrustStore::ephemeral();
        let fp = fingerprint();
        store.trust("1.2.3.4:42071", fp, "Server");
        let first_seen = store.get("1.2.3.4:42071").unwrap().first_seen_unix_ms;

        store.trust("1.2.3.4:42071", fingerprint(), "Server");
        assert_eq!(
            store.get("1.2.3.4:42071").unwrap().first_seen_unix_ms,
            first_seen,
            "how long a server was trusted is context the user needs"
        );
    }

    #[test]
    fn addresses_are_pinned_independently() {
        let mut store = TrustStore::ephemeral();
        let a = fingerprint();
        let b = fingerprint();
        store.trust("1.2.3.4:42071", a, "A");
        store.trust("5.6.7.8:42071", b, "B");

        assert_eq!(store.check("1.2.3.4:42071", a), TrustDecision::Recognised);
        assert_eq!(store.check("5.6.7.8:42071", b), TrustDecision::Recognised);
        assert!(matches!(
            store.check("5.6.7.8:42071", a),
            TrustDecision::Changed { .. }
        ));
    }

    #[test]
    fn forgetting_an_address_returns_it_to_first_contact() {
        let mut store = TrustStore::ephemeral();
        let fp = fingerprint();
        store.trust("1.2.3.4:42071", fp, "Server");

        assert!(store.forget("1.2.3.4:42071"));
        assert!(!store.forget("1.2.3.4:42071"));
        assert!(matches!(
            store.check("1.2.3.4:42071", fp),
            TrustDecision::FirstContact { .. }
        ));
    }

    #[test]
    fn the_store_survives_a_save_and_reload() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("known_servers.json");
        let fp = fingerprint();

        let mut store = TrustStore::open(&path).unwrap();
        store.trust("1.2.3.4:42071", fp, "Andy's Server");
        store.save().unwrap();

        let reloaded = TrustStore::open(&path).unwrap();
        assert_eq!(
            reloaded.check("1.2.3.4:42071", fp),
            TrustDecision::Recognised
        );
        assert_eq!(reloaded.get("1.2.3.4:42071").unwrap().name, "Andy's Server");
    }

    #[test]
    fn a_missing_store_file_starts_empty() {
        let dir = tempfile::tempdir().unwrap();
        let store = TrustStore::open(&dir.path().join("does-not-exist.json")).unwrap();
        assert_eq!(store.iter().count(), 0);
    }

    #[test]
    fn a_corrupt_store_is_reported_rather_than_discarded() {
        // Quietly starting fresh would silently drop every pin the user has.
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("known_servers.json");
        std::fs::write(&path, "{ not json").unwrap();
        assert!(matches!(
            TrustStore::open(&path),
            Err(TrustError::Malformed(_))
        ));
    }
}
