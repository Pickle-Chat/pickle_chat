//! Persisted user preferences.
//!
//! Unlike the keystore, nothing here is irreplaceable — these are choices the
//! user can make again. So a malformed file is not fatal: it is moved aside and
//! defaults take over, which keeps the app usable while still leaving the old
//! contents on disk for anyone who wants to look. Missing fields fill in from
//! defaults too, so a file written by an older or newer build still loads.

use pickle_audio::GateMode;
use serde::{Deserialize, Serialize};
use std::fs;
use std::io::Write;
use std::path::{Path, PathBuf};
use tracing::warn;

#[derive(Debug, thiserror::Error)]
pub enum SettingsError {
    #[error("writing settings {path}: {source}")]
    Io {
        path: PathBuf,
        #[source]
        source: std::io::Error,
    },
}

/// How the microphone is gated.
///
/// Mirrors [`GateMode`] rather than serialising it directly: the audio crate
/// describes the signal path and has no business carrying a storage format.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(rename_all = "camelCase")]
pub enum StoredGateMode {
    #[default]
    VoiceActivity,
    PushToTalk,
    Continuous,
}

impl From<StoredGateMode> for GateMode {
    fn from(mode: StoredGateMode) -> Self {
        match mode {
            StoredGateMode::VoiceActivity => GateMode::VoiceActivity,
            StoredGateMode::PushToTalk => GateMode::PushToTalk,
            StoredGateMode::Continuous => GateMode::Continuous,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", default)]
pub struct AudioSettings {
    /// Device name, or `None` for the system default.
    pub input_device: Option<String>,
    pub output_device: Option<String>,
    pub bitrate: u32,
    pub gate_mode: StoredGateMode,
}

impl Default for AudioSettings {
    fn default() -> Self {
        Self {
            input_device: None,
            output_device: None,
            bitrate: pickle_audio::DEFAULT_BITRATE,
            gate_mode: StoredGateMode::default(),
        }
    }
}

impl AudioSettings {
    /// Whether moving to `next` requires the engine to be rebuilt.
    ///
    /// Gate mode is excluded deliberately: the engine can change it in place,
    /// and rebuilding for it would drop audio for no reason.
    pub fn needs_restart(&self, next: &Self) -> bool {
        self.input_device != next.input_device
            || self.output_device != next.output_device
            || self.bitrate != next.bitrate
    }
}

/// Accelerators for the actions that are worth a key.
///
/// `None` means unbound. Stored as strings in Tauri's accelerator syntax so the
/// same value can be handed to the global shortcut registrar and shown back to
/// the user without translation.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", default)]
pub struct Keybinds {
    pub push_to_talk: Option<String>,
    pub toggle_mute: Option<String>,
    pub toggle_deafen: Option<String>,
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", default)]
pub struct Settings {
    pub audio: AudioSettings,
    pub keybinds: Keybinds,
}

impl Settings {
    /// Read settings, falling back to defaults when the file is absent or
    /// unreadable.
    ///
    /// A malformed file is renamed to `.bad` rather than being overwritten in
    /// place, so the next save cannot silently destroy something the user spent
    /// time on.
    pub fn load(path: &Path) -> Self {
        let raw = match fs::read_to_string(path) {
            Ok(raw) => raw,
            Err(source) => {
                if source.kind() != std::io::ErrorKind::NotFound {
                    warn!(path = %path.display(), error = %source, "could not read settings; using defaults");
                }
                return Self::default();
            }
        };

        match serde_json::from_str(&raw) {
            Ok(settings) => settings,
            Err(error) => {
                let aside = path.with_extension("json.bad");
                warn!(
                    path = %path.display(),
                    error = %error,
                    moved_to = %aside.display(),
                    "settings file is not valid JSON; keeping it aside and using defaults",
                );
                let _ = fs::rename(path, &aside);
                Self::default()
            }
        }
    }

    /// Write settings, replacing any existing file.
    ///
    /// Writes to a sibling temp file and renames, matching the keystore, so an
    /// interrupted save cannot leave a truncated file behind.
    pub fn save(&self, path: &Path) -> Result<(), SettingsError> {
        let io_err = |source| SettingsError::Io {
            path: path.to_path_buf(),
            source,
        };

        if let Some(parent) = path.parent() {
            if !parent.as_os_str().is_empty() {
                fs::create_dir_all(parent).map_err(io_err)?;
            }
        }

        let json = serde_json::to_string_pretty(self).expect("Settings is always serializable");

        let tmp = path.with_extension("tmp");
        let mut file = fs::File::create(&tmp).map_err(io_err)?;
        file.write_all(json.as_bytes()).map_err(io_err)?;
        file.write_all(b"\n").map_err(io_err)?;
        file.sync_all().map_err(io_err)?;
        drop(file);

        fs::rename(&tmp, path).map_err(io_err)?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn temp(name: &str) -> (tempfile::TempDir, PathBuf) {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join(name);
        (dir, path)
    }

    #[test]
    fn save_then_load_round_trips() {
        let (_dir, path) = temp("settings.json");

        let settings = Settings {
            audio: AudioSettings {
                input_device: Some("Yeti".into()),
                output_device: Some("Headphones".into()),
                bitrate: 24_000,
                gate_mode: StoredGateMode::PushToTalk,
            },
            keybinds: Keybinds {
                push_to_talk: Some("F13".into()),
                ..Keybinds::default()
            },
        };

        settings.save(&path).unwrap();
        assert_eq!(Settings::load(&path), settings);
    }

    #[test]
    fn a_missing_file_yields_defaults_without_complaint() {
        let (_dir, path) = temp("settings.json");
        assert_eq!(Settings::load(&path), Settings::default());
        assert!(!path.exists(), "loading must not create the file");
    }

    #[test]
    fn missing_fields_fill_in_from_defaults() {
        // What a file written by an older build looks like.
        let (_dir, path) = temp("settings.json");
        fs::write(&path, r#"{"audio":{"inputDevice":"Yeti"}}"#).unwrap();

        let loaded = Settings::load(&path);
        assert_eq!(loaded.audio.input_device.as_deref(), Some("Yeti"));
        assert_eq!(loaded.audio.bitrate, pickle_audio::DEFAULT_BITRATE);
        assert_eq!(loaded.audio.gate_mode, StoredGateMode::VoiceActivity);
        assert_eq!(loaded.keybinds, Keybinds::default());
    }

    #[test]
    fn unknown_fields_are_tolerated() {
        // A file written by a newer build must not lock the user out.
        let (_dir, path) = temp("settings.json");
        fs::write(&path, r#"{"audio":{"bitrate":16000},"somethingNew":true}"#).unwrap();
        assert_eq!(Settings::load(&path).audio.bitrate, 16_000);
    }

    #[test]
    fn a_malformed_file_is_kept_aside_rather_than_lost() {
        let (_dir, path) = temp("settings.json");
        fs::write(&path, "{not json").unwrap();

        assert_eq!(Settings::load(&path), Settings::default());

        let aside = path.with_extension("json.bad");
        assert!(aside.exists(), "the original must be preserved");
        assert_eq!(fs::read_to_string(&aside).unwrap(), "{not json");
    }

    #[test]
    fn save_builds_missing_parent_directories() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("nested/deeper/settings.json");
        Settings::default().save(&path).unwrap();
        assert!(path.exists());
    }

    #[test]
    fn only_device_and_bitrate_changes_need_a_restart() {
        let base = AudioSettings::default();

        // Gate mode is switchable in place on a running engine.
        let gate_only = AudioSettings {
            gate_mode: StoredGateMode::PushToTalk,
            ..base.clone()
        };
        assert!(!base.needs_restart(&gate_only));

        let device = AudioSettings {
            input_device: Some("Yeti".into()),
            ..base.clone()
        };
        assert!(base.needs_restart(&device));

        let bitrate = AudioSettings {
            bitrate: 16_000,
            ..base.clone()
        };
        assert!(base.needs_restart(&bitrate));
    }
}
