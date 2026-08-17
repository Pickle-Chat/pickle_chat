//! Saved servers.
//!
//! Deliberately separate from the trust store in `known_servers.json`, which
//! records which identity a server proved at first contact. The two answer
//! different questions and must not be conflated: removing a bookmark is
//! housekeeping, while forgetting a pin discards a security decision and opens
//! the next connection to a stranger. Keeping them apart means neither action
//! can quietly perform the other.
//!
//! An entry may carry a server password, so the file is written `0600` and its
//! permissions are checked on load, exactly as the keystore is.

use serde::{Deserialize, Serialize};
use std::fs;
use std::io::Write;
use std::path::{Path, PathBuf};

const BOOKMARKS_VERSION: u32 = 1;

#[derive(Debug, thiserror::Error)]
pub enum BookmarkError {
    #[error("reading bookmarks {path}: {source}")]
    Io {
        path: PathBuf,
        #[source]
        source: std::io::Error,
    },
    #[error("bookmarks file {0} is not valid JSON")]
    Malformed(PathBuf),
    #[error("bookmarks file {path} has version {found}, but this build understands {expected}")]
    UnsupportedVersion {
        path: PathBuf,
        found: u32,
        expected: u32,
    },
    #[error(
        "bookmarks file {path} is readable by other users (mode {mode:o}); \
         it may contain server passwords, so run `chmod 600 {}` before using it", path.display()
    )]
    PermissionsTooOpen { path: PathBuf, mode: u32 },
    #[error("no bookmark with id {0}")]
    NotFound(u64),
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Bookmark {
    /// Assigned by the store, never reused within a file.
    pub id: u64,
    pub label: String,
    pub address: String,
    /// Only if the user asked us to remember it.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub password: Option<String>,
    /// Fingerprint of the identity to connect with, when the user wants a
    /// particular one for this server.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub identity: Option<String>,
}

/// What the frontend sends to create or update one. The id is the store's to
/// assign, so it is absent here.
#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct BookmarkInput {
    pub label: String,
    pub address: String,
    #[serde(default)]
    pub password: Option<String>,
    #[serde(default)]
    pub identity: Option<String>,
}

#[derive(Debug, Default, Serialize, Deserialize)]
struct StoredBookmarks {
    version: u32,
    /// Persisted rather than derived from the entries: deriving it as one past
    /// the highest in use would hand a deleted entry's id to the next bookmark
    /// added, and a reference held elsewhere would then quietly point at a
    /// different server.
    #[serde(default)]
    next_id: u64,
    entries: Vec<Bookmark>,
}

#[derive(Debug, Default)]
pub struct Bookmarks {
    path: PathBuf,
    next_id: u64,
    entries: Vec<Bookmark>,
}

impl Bookmarks {
    /// Read the store, treating an absent file as an empty one.
    pub fn open(path: &Path) -> Result<Self, BookmarkError> {
        let raw = match fs::read_to_string(path) {
            Ok(raw) => raw,
            Err(source) if source.kind() == std::io::ErrorKind::NotFound => {
                return Ok(Self {
                    path: path.to_path_buf(),
                    next_id: 1,
                    entries: Vec::new(),
                })
            }
            Err(source) => {
                return Err(BookmarkError::Io {
                    path: path.to_path_buf(),
                    source,
                })
            }
        };

        // Only meaningful once the file exists — hence after the read.
        check_permissions(path)?;

        let stored: StoredBookmarks =
            serde_json::from_str(&raw).map_err(|_| BookmarkError::Malformed(path.to_path_buf()))?;

        if stored.version != BOOKMARKS_VERSION {
            return Err(BookmarkError::UnsupportedVersion {
                path: path.to_path_buf(),
                found: stored.version,
                expected: BOOKMARKS_VERSION,
            });
        }

        // Never below what the entries already use, so a hand-edited or
        // truncated counter cannot cause a collision.
        let highest = stored.entries.iter().map(|b| b.id).max().unwrap_or(0);
        let next_id = stored.next_id.max(highest + 1);

        Ok(Self {
            path: path.to_path_buf(),
            next_id,
            entries: stored.entries,
        })
    }

    pub fn list(&self) -> &[Bookmark] {
        &self.entries
    }

    pub fn add(&mut self, input: BookmarkInput) -> &Bookmark {
        let id = self.next_id;
        self.next_id += 1;
        self.entries.push(Bookmark {
            id,
            label: input.label,
            address: input.address,
            password: input.password.filter(|p| !p.is_empty()),
            identity: input.identity,
        });
        self.entries.last().expect("just pushed")
    }

    pub fn update(&mut self, id: u64, input: BookmarkInput) -> Result<&Bookmark, BookmarkError> {
        let entry = self
            .entries
            .iter_mut()
            .find(|b| b.id == id)
            .ok_or(BookmarkError::NotFound(id))?;

        entry.label = input.label;
        entry.address = input.address;
        entry.password = input.password.filter(|p| !p.is_empty());
        entry.identity = input.identity;
        Ok(entry)
    }

    /// Remove a bookmark. Note this touches no trust state whatsoever.
    pub fn remove(&mut self, id: u64) -> bool {
        let before = self.entries.len();
        self.entries.retain(|b| b.id != id);
        self.entries.len() != before
    }

    /// Persist, writing to a sibling temp file and renaming so an interrupted
    /// save cannot truncate the file.
    pub fn save(&self) -> Result<(), BookmarkError> {
        let io_err = |source| BookmarkError::Io {
            path: self.path.clone(),
            source,
        };

        if let Some(parent) = self.path.parent() {
            if !parent.as_os_str().is_empty() {
                fs::create_dir_all(parent).map_err(io_err)?;
            }
        }

        let stored = StoredBookmarks {
            version: BOOKMARKS_VERSION,
            next_id: self.next_id,
            entries: self.entries.clone(),
        };
        let json =
            serde_json::to_string_pretty(&stored).expect("StoredBookmarks is always serializable");

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

#[cfg(unix)]
fn create_private(path: &Path) -> std::io::Result<fs::File> {
    use std::os::unix::fs::OpenOptionsExt;
    fs::OpenOptions::new()
        .write(true)
        .create(true)
        .truncate(true)
        .mode(0o600)
        .open(path)
}

#[cfg(not(unix))]
fn create_private(path: &Path) -> std::io::Result<fs::File> {
    // Windows inherits the parent directory's ACL, which for a per-user app
    // data directory is already user-only.
    fs::File::create(path)
}

#[cfg(unix)]
fn check_permissions(path: &Path) -> Result<(), BookmarkError> {
    use std::os::unix::fs::PermissionsExt;
    let mode = fs::metadata(path)
        .map_err(|source| BookmarkError::Io {
            path: path.to_path_buf(),
            source,
        })?
        .permissions()
        .mode()
        & 0o777;

    if mode & 0o077 != 0 {
        return Err(BookmarkError::PermissionsTooOpen {
            path: path.to_path_buf(),
            mode,
        });
    }
    Ok(())
}

#[cfg(not(unix))]
fn check_permissions(_path: &Path) -> Result<(), BookmarkError> {
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn input(label: &str, address: &str) -> BookmarkInput {
        BookmarkInput {
            label: label.into(),
            address: address.into(),
            password: None,
            identity: None,
        }
    }

    #[test]
    fn save_then_open_round_trips() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("bookmarks.json");

        let mut store = Bookmarks::open(&path).unwrap();
        store.add(input("Friends", "example.com:42071"));
        store.add(BookmarkInput {
            password: Some("hunter2".into()),
            identity: Some("abc123".into()),
            ..input("Work", "10.0.0.5")
        });
        store.save().unwrap();

        let reopened = Bookmarks::open(&path).unwrap();
        assert_eq!(reopened.list().len(), 2);
        assert_eq!(reopened.list()[0].label, "Friends");
        assert_eq!(reopened.list()[1].password.as_deref(), Some("hunter2"));
        assert_eq!(reopened.list()[1].identity.as_deref(), Some("abc123"));
    }

    #[test]
    fn a_missing_file_opens_as_an_empty_store() {
        let dir = tempfile::tempdir().unwrap();
        let store = Bookmarks::open(&dir.path().join("bookmarks.json")).unwrap();
        assert!(store.list().is_empty());
    }

    #[test]
    fn ids_are_not_reused_after_a_removal() {
        // A stale reference must fail to resolve rather than address whichever
        // server happened to take the freed id.
        let dir = tempfile::tempdir().unwrap();
        let mut store = Bookmarks::open(&dir.path().join("bookmarks.json")).unwrap();

        let first = store.add(input("One", "a")).id;
        let second = store.add(input("Two", "b")).id;
        assert!(store.remove(second));

        let third = store.add(input("Three", "c")).id;
        assert_ne!(third, second);
        assert_ne!(third, first);
    }

    #[test]
    fn ids_are_not_reused_across_a_reopen() {
        // The counter has to survive on disk; deriving it from the entries on
        // load would reuse the id of whichever bookmark was deleted last.
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("bookmarks.json");

        let mut store = Bookmarks::open(&path).unwrap();
        store.add(input("One", "a"));
        let second = store.add(input("Two", "b")).id;
        store.remove(second);
        store.save().unwrap();

        let mut reopened = Bookmarks::open(&path).unwrap();
        assert_ne!(reopened.add(input("Three", "c")).id, second);
    }

    #[test]
    fn a_counter_behind_the_entries_is_corrected_on_load() {
        // Guards against a hand-edited file handing out a colliding id.
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("bookmarks.json");
        fs::write(
            &path,
            r#"{"version":1,"nextId":1,"entries":[{"id":7,"label":"One","address":"a"}]}"#,
        )
        .unwrap();
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            fs::set_permissions(&path, fs::Permissions::from_mode(0o600)).unwrap();
        }

        let mut store = Bookmarks::open(&path).unwrap();
        assert_eq!(store.add(input("Two", "b")).id, 8);
    }

    #[test]
    fn removing_an_absent_bookmark_reports_it() {
        let dir = tempfile::tempdir().unwrap();
        let mut store = Bookmarks::open(&dir.path().join("bookmarks.json")).unwrap();
        assert!(!store.remove(99));
    }

    #[test]
    fn updating_an_absent_bookmark_is_an_error() {
        let dir = tempfile::tempdir().unwrap();
        let mut store = Bookmarks::open(&dir.path().join("bookmarks.json")).unwrap();
        assert!(matches!(
            store.update(99, input("x", "y")),
            Err(BookmarkError::NotFound(99))
        ));
    }

    #[test]
    fn an_empty_password_is_stored_as_absent() {
        // Otherwise the connect form would send "" and look like a remembered
        // password that happens to be blank.
        let dir = tempfile::tempdir().unwrap();
        let mut store = Bookmarks::open(&dir.path().join("bookmarks.json")).unwrap();
        let added = store.add(BookmarkInput {
            password: Some(String::new()),
            ..input("One", "a")
        });
        assert_eq!(added.password, None);
    }

    #[cfg(unix)]
    #[test]
    fn saved_bookmarks_are_not_readable_by_others() {
        use std::os::unix::fs::PermissionsExt;
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("bookmarks.json");

        let mut store = Bookmarks::open(&path).unwrap();
        store.add(input("One", "a"));
        store.save().unwrap();

        let mode = fs::metadata(&path).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode, 0o600, "bookmarks may hold server passwords");
    }

    #[cfg(unix)]
    #[test]
    fn opening_a_world_readable_file_is_refused() {
        use std::os::unix::fs::PermissionsExt;
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("bookmarks.json");

        let mut store = Bookmarks::open(&path).unwrap();
        store.add(input("One", "a"));
        store.save().unwrap();
        fs::set_permissions(&path, fs::Permissions::from_mode(0o644)).unwrap();

        assert!(matches!(
            Bookmarks::open(&path),
            Err(BookmarkError::PermissionsTooOpen { .. })
        ));
    }

    #[test]
    fn a_future_version_is_refused_rather_than_silently_emptied() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("bookmarks.json");

        let mut store = Bookmarks::open(&path).unwrap();
        store.add(input("One", "a"));
        store.save().unwrap();

        let bumped = fs::read_to_string(&path)
            .unwrap()
            .replace("\"version\": 1", "\"version\": 99");
        fs::write(&path, bumped).unwrap();

        assert!(matches!(
            Bookmarks::open(&path),
            Err(BookmarkError::UnsupportedVersion { found: 99, .. })
        ));
    }
}
