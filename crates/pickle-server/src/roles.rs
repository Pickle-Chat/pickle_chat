//! Who holds which role.
//!
//! Keyed by fingerprint rather than nickname or client id: a fingerprint
//! outlives a connection and survives a rename, so a role granted today still
//! means something tomorrow. Client ids are assigned per connection and
//! nicknames are unverified — granting either a permission would be granting it
//! to whoever turns up wearing the name.
//!
//! Stored as JSON beside the server's identity, in the same shape the client
//! uses for its own state, and written atomically so an interrupted save cannot
//! truncate the file that decides who can moderate.
//!
//! The operator is deliberately **not** in here. Ownership comes from the
//! config, so a malformed or emptied role file cannot lock someone out of their
//! own server.

use pickle_identity::Fingerprint;
use pickle_proto::{Capability, Permissions, Role};
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use std::fs;
use std::io::Write;
use std::path::{Path, PathBuf};

const ROLES_VERSION: u32 = 1;

#[derive(Debug, thiserror::Error)]
pub enum RoleError {
    #[error("reading roles {path}: {source}")]
    Io {
        path: PathBuf,
        #[source]
        source: std::io::Error,
    },
    #[error("roles file {0} is not valid JSON")]
    Malformed(PathBuf),
    #[error("roles file {path} has version {found}, but this build understands {expected}")]
    UnsupportedVersion {
        path: PathBuf,
        found: u32,
        expected: u32,
    },
    #[error("no role named {0}")]
    NoSuchRole(String),
}

#[derive(Debug, Serialize, Deserialize)]
struct StoredRoles {
    version: u32,
    /// Defined roles, by name.
    roles: Vec<Role>,
    /// Fingerprint to role name.
    assignments: BTreeMap<String, String>,
}

impl Default for StoredRoles {
    fn default() -> Self {
        Self {
            version: ROLES_VERSION,
            roles: default_roles(),
            assignments: BTreeMap::new(),
        }
    }
}

/// A starting ladder, so a fresh server has something to grant.
///
/// Ranks are spaced rather than consecutive, leaving room to insert a role
/// between two existing ones without renumbering everyone already assigned.
fn default_roles() -> Vec<Role> {
    vec![
        Role {
            name: "admin".into(),
            rank: 100,
            capabilities: Capability::ALL.to_vec(),
        },
        Role {
            name: "moderator".into(),
            rank: 50,
            capabilities: vec![
                Capability::KickUsers,
                Capability::BanUsers,
                Capability::MuteUsers,
                Capability::MoveUsers,
            ],
        },
    ]
}

#[derive(Debug)]
pub struct Roles {
    path: PathBuf,
    roles: Vec<Role>,
    assignments: BTreeMap<String, String>,
}

impl Roles {
    /// Read the store, creating a default ladder if the file is absent.
    pub fn open(path: &Path) -> Result<Self, RoleError> {
        let stored = match fs::read_to_string(path) {
            Ok(raw) => serde_json::from_str::<StoredRoles>(&raw)
                .map_err(|_| RoleError::Malformed(path.to_path_buf()))?,
            Err(source) if source.kind() == std::io::ErrorKind::NotFound => StoredRoles::default(),
            Err(source) => {
                return Err(RoleError::Io {
                    path: path.to_path_buf(),
                    source,
                })
            }
        };

        if stored.version != ROLES_VERSION {
            return Err(RoleError::UnsupportedVersion {
                path: path.to_path_buf(),
                found: stored.version,
                expected: ROLES_VERSION,
            });
        }

        Ok(Self {
            path: path.to_path_buf(),
            roles: stored.roles,
            assignments: stored.assignments,
        })
    }

    pub fn list(&self) -> &[Role] {
        &self.roles
    }

    pub fn role(&self, name: &str) -> Option<&Role> {
        self.roles.iter().find(|role| role.name == name)
    }

    /// What this fingerprint may do.
    ///
    /// `owner` is decided by the caller from the config, not from this store —
    /// that separation is what keeps a broken file from costing the operator
    /// their server.
    pub fn permissions(&self, fingerprint: Fingerprint, owner: bool) -> Permissions {
        let assigned = self
            .assignments
            .get(&fingerprint.to_string())
            .and_then(|name| self.role(name));

        match assigned {
            Some(role) => Permissions {
                role: Some(role.name.clone()),
                rank: role.rank,
                capabilities: role.capabilities.clone(),
                owner,
            },
            // An assignment naming a role that no longer exists resolves to no
            // capabilities rather than to an error: deleting a role should
            // demote its holders, not lock the server's admission path.
            None => Permissions {
                role: None,
                rank: 0,
                capabilities: Vec::new(),
                owner,
            },
        }
    }

    /// Grant a role, or revoke with `None`.
    pub fn assign(
        &mut self,
        fingerprint: Fingerprint,
        role: Option<&str>,
    ) -> Result<(), RoleError> {
        match role {
            Some(name) => {
                if self.role(name).is_none() {
                    return Err(RoleError::NoSuchRole(name.to_string()));
                }
                self.assignments
                    .insert(fingerprint.to_string(), name.to_string());
            }
            None => {
                self.assignments.remove(&fingerprint.to_string());
            }
        }
        Ok(())
    }

    pub fn assignments(&self) -> impl Iterator<Item = (&String, &String)> {
        self.assignments.iter()
    }

    /// Persist, via a temp file and rename so an interrupted save cannot leave
    /// a truncated file deciding who may moderate.
    pub fn save(&self) -> Result<(), RoleError> {
        let stored = StoredRoles {
            version: ROLES_VERSION,
            roles: self.roles.clone(),
            assignments: self.assignments.clone(),
        };
        write_atomically(&self.path, &stored).map_err(|source| RoleError::Io {
            path: self.path.clone(),
            source,
        })
    }
}

/// Write JSON to a sibling temp file and rename over the target.
///
/// Shared with the ban store, which has the same durability requirement for the
/// same reason.
pub(crate) fn write_atomically<T: Serialize>(path: &Path, value: &T) -> std::io::Result<()> {
    if let Some(parent) = path.parent() {
        if !parent.as_os_str().is_empty() {
            fs::create_dir_all(parent)?;
        }
    }

    let json = serde_json::to_string_pretty(value).expect("the stores are always serializable");

    let tmp = path.with_extension("tmp");
    let mut file = fs::File::create(&tmp)?;
    file.write_all(json.as_bytes())?;
    file.write_all(b"\n")?;
    file.sync_all()?;
    drop(file);

    fs::rename(&tmp, path)
}

#[cfg(test)]
mod tests {
    use super::*;
    use pickle_identity::Identity;

    fn fingerprint() -> Fingerprint {
        Identity::generate().fingerprint()
    }

    #[test]
    fn a_fresh_store_offers_a_ladder_to_grant_from() {
        let dir = tempfile::tempdir().unwrap();
        let roles = Roles::open(&dir.path().join("roles.json")).unwrap();

        assert!(roles.role("admin").is_some());
        assert!(roles.role("moderator").is_some());
        assert!(
            roles.role("admin").unwrap().rank > roles.role("moderator").unwrap().rank,
            "an admin has to outrank a moderator or neither can act on the other",
        );
    }

    #[test]
    fn an_unassigned_fingerprint_may_do_nothing() {
        let dir = tempfile::tempdir().unwrap();
        let roles = Roles::open(&dir.path().join("roles.json")).unwrap();

        let permissions = roles.permissions(fingerprint(), false);
        assert_eq!(permissions.role, None);
        assert!(!permissions.allows(Capability::KickUsers));
    }

    #[test]
    fn the_owner_passes_every_check_without_a_role() {
        // The whole point of keeping ownership in the config: an empty or
        // broken role file must not cost the operator their server.
        let dir = tempfile::tempdir().unwrap();
        let roles = Roles::open(&dir.path().join("roles.json")).unwrap();

        let owner = roles.permissions(fingerprint(), true);
        assert_eq!(owner.role, None, "ownership is not a role");
        for capability in Capability::ALL {
            assert!(owner.allows(capability), "{capability:?}");
        }
    }

    #[test]
    fn assigning_and_revoking_round_trips_through_the_file() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("roles.json");
        let who = fingerprint();

        let mut roles = Roles::open(&path).unwrap();
        roles.assign(who, Some("moderator")).unwrap();
        roles.save().unwrap();

        let reopened = Roles::open(&path).unwrap();
        let permissions = reopened.permissions(who, false);
        assert_eq!(permissions.role.as_deref(), Some("moderator"));
        assert!(permissions.allows(Capability::KickUsers));
        assert!(
            !permissions.allows(Capability::ManageServer),
            "a moderator is not an admin",
        );

        let mut roles = Roles::open(&path).unwrap();
        roles.assign(who, None).unwrap();
        roles.save().unwrap();
        assert_eq!(
            Roles::open(&path).unwrap().permissions(who, false).role,
            None
        );
    }

    #[test]
    fn assigning_a_role_that_does_not_exist_is_refused() {
        let dir = tempfile::tempdir().unwrap();
        let mut roles = Roles::open(&dir.path().join("roles.json")).unwrap();
        assert!(matches!(
            roles.assign(fingerprint(), Some("wizard")),
            Err(RoleError::NoSuchRole(_)),
        ));
    }

    #[test]
    fn an_assignment_to_a_deleted_role_demotes_rather_than_failing() {
        // Removing a role from the file by hand should cost its holders their
        // powers, not break the admission path for everyone.
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("roles.json");
        let who = fingerprint();

        let mut roles = Roles::open(&path).unwrap();
        roles.assign(who, Some("moderator")).unwrap();
        roles.save().unwrap();

        let raw = fs::read_to_string(&path).unwrap();
        let mut stored: serde_json::Value = serde_json::from_str(&raw).unwrap();
        stored["roles"] = serde_json::json!([]);
        fs::write(&path, stored.to_string()).unwrap();

        let permissions = Roles::open(&path).unwrap().permissions(who, false);
        assert_eq!(permissions.role, None);
        assert!(!permissions.allows(Capability::KickUsers));
    }

    #[test]
    fn a_future_version_is_refused_rather_than_silently_emptied() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("roles.json");
        Roles::open(&path).unwrap().save().unwrap();

        let bumped = fs::read_to_string(&path)
            .unwrap()
            .replace("\"version\": 1", "\"version\": 99");
        fs::write(&path, bumped).unwrap();

        assert!(matches!(
            Roles::open(&path),
            Err(RoleError::UnsupportedVersion { found: 99, .. }),
        ));
    }
}
