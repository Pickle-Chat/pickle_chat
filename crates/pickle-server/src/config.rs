//! Server configuration, read from a TOML file next to the server's data.
//!
//! Everything has a working default, so a first run needs no configuration at
//! all: the server writes a starter file, generates its identity and
//! certificate, and listens.

use pickle_proto::ChannelKind;
use serde::{Deserialize, Serialize};
use std::net::SocketAddr;
use std::path::{Path, PathBuf};

/// UDP port for QUIC. Not a registered assignment — just a memorable default
/// that avoids the usual suspects.
pub const DEFAULT_PORT: u16 = 42071;

#[derive(Debug, thiserror::Error)]
pub enum ConfigError {
    #[error("reading {path}: {source}")]
    Io {
        path: PathBuf,
        #[source]
        source: std::io::Error,
    },
    #[error("{path} is not valid TOML: {source}")]
    Parse {
        path: PathBuf,
        #[source]
        source: toml::de::Error,
    },
    #[error("configuration is invalid: {0}")]
    Invalid(String),
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ServerConfig {
    /// Address to listen on. `[::]` accepts both IPv6 and, on most systems,
    /// IPv4-mapped connections.
    #[serde(default = "default_bind")]
    pub bind: SocketAddr,

    /// Shown to clients before they authenticate, and covered by the server's
    /// signature in `ServerHello`.
    #[serde(default = "default_name")]
    pub name: String,

    /// Minimum identity proof-of-work level. Raising this makes throwaway
    /// identities expensive; see `pickle_identity::security_level`.
    ///
    /// 8 is a fraction of a second — enough to stop accidental churn, not
    /// enough to deter anyone determined. Try 20+ for a public server.
    #[serde(default = "default_min_security_level")]
    pub min_security_level: u32,

    /// Optional shared secret gating the whole server. Orthogonal to identity:
    /// it controls who may connect, while identity controls who they are.
    #[serde(default)]
    pub password: Option<String>,

    /// Fingerprint of the server operator, who passes every permission check.
    ///
    /// Deliberately here rather than in the role store: a malformed or emptied
    /// `roles.json` must not be able to lock someone out of their own server.
    /// It is also not a race — unlike claiming ownership on first connection,
    /// nobody can take it by reaching the port before you do.
    ///
    /// Accepts the hyphenated form the client shows in its titlebar.
    #[serde(default)]
    pub owner: Option<String>,

    #[serde(default = "default_max_users")]
    pub max_users: u32,

    #[serde(default = "default_channels")]
    pub channels: Vec<ChannelConfig>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ChannelConfig {
    pub name: String,
    #[serde(default)]
    pub topic: String,
    #[serde(default = "default_channel_kind")]
    pub kind: ChannelKind,
    /// Nests this channel under another by name, giving a channel tree.
    #[serde(default)]
    pub parent: Option<String>,
    #[serde(default)]
    pub max_users: Option<u16>,
    #[serde(default)]
    pub order: i32,
}

fn default_bind() -> SocketAddr {
    SocketAddr::from(([0, 0, 0, 0], DEFAULT_PORT))
}
fn default_name() -> String {
    "Pickle Server".to_string()
}
fn default_min_security_level() -> u32 {
    8
}
fn default_max_users() -> u32 {
    64
}
fn default_channel_kind() -> ChannelKind {
    ChannelKind::VoiceAndText
}
fn default_channels() -> Vec<ChannelConfig> {
    vec![
        ChannelConfig {
            name: "Lobby".into(),
            topic: "Say hello".into(),
            kind: ChannelKind::VoiceAndText,
            parent: None,
            max_users: None,
            order: 0,
        },
        ChannelConfig {
            name: "AFK".into(),
            topic: String::new(),
            kind: ChannelKind::Voice,
            parent: None,
            max_users: None,
            order: 100,
        },
    ]
}

impl Default for ServerConfig {
    fn default() -> Self {
        Self {
            bind: default_bind(),
            name: default_name(),
            min_security_level: default_min_security_level(),
            password: None,
            owner: None,
            max_users: default_max_users(),
            channels: default_channels(),
        }
    }
}

impl ServerConfig {
    pub fn load(path: &Path) -> Result<Self, ConfigError> {
        let raw = std::fs::read_to_string(path).map_err(|source| ConfigError::Io {
            path: path.to_path_buf(),
            source,
        })?;
        let config: Self = toml::from_str(&raw).map_err(|source| ConfigError::Parse {
            path: path.to_path_buf(),
            source,
        })?;
        config.validate()?;
        Ok(config)
    }

    /// Load, or write out the defaults and use those.
    pub fn load_or_create(path: &Path) -> Result<Self, ConfigError> {
        match Self::load(path) {
            Err(ConfigError::Io { source, .. })
                if source.kind() == std::io::ErrorKind::NotFound =>
            {
                let config = Self::default();
                config.save(path)?;
                Ok(config)
            }
            other => other,
        }
    }

    pub fn save(&self, path: &Path) -> Result<(), ConfigError> {
        let io_err = |source| ConfigError::Io {
            path: path.to_path_buf(),
            source,
        };
        if let Some(parent) = path.parent() {
            if !parent.as_os_str().is_empty() {
                std::fs::create_dir_all(parent).map_err(io_err)?;
            }
        }
        let toml = toml::to_string_pretty(self).expect("ServerConfig is always serializable");
        std::fs::write(path, toml).map_err(io_err)
    }

    pub fn validate(&self) -> Result<(), ConfigError> {
        if self.channels.is_empty() {
            return Err(ConfigError::Invalid(
                "at least one channel is required — clients need somewhere to land".into(),
            ));
        }

        let mut seen = std::collections::HashSet::new();
        for channel in &self.channels {
            if channel.name.trim().is_empty() {
                return Err(ConfigError::Invalid("channel names cannot be empty".into()));
            }
            if !seen.insert(channel.name.as_str()) {
                return Err(ConfigError::Invalid(format!(
                    "duplicate channel name {:?}; names are how parents are referenced",
                    channel.name
                )));
            }
        }

        for channel in &self.channels {
            if let Some(parent) = &channel.parent {
                if !seen.contains(parent.as_str()) {
                    return Err(ConfigError::Invalid(format!(
                        "channel {:?} names a parent {:?} that does not exist",
                        channel.name, parent
                    )));
                }
                if parent == &channel.name {
                    return Err(ConfigError::Invalid(format!(
                        "channel {:?} is its own parent",
                        channel.name
                    )));
                }
            }
        }

        // A landing channel must accept voice or text, or a client that joins
        // it can do nothing at all.
        if !self.channels.iter().any(|c| c.parent.is_none()) {
            return Err(ConfigError::Invalid(
                "at least one channel must be top-level".into(),
            ));
        }

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn defaults_are_valid() {
        ServerConfig::default().validate().unwrap();
    }

    #[test]
    fn a_minimal_config_file_parses() {
        let config: ServerConfig = toml::from_str(r#"name = "Andy's Server""#).unwrap();
        assert_eq!(config.name, "Andy's Server");
        assert_eq!(config.bind.port(), DEFAULT_PORT);
        assert!(!config.channels.is_empty(), "defaults must fill in");
    }

    #[test]
    fn channel_kinds_use_readable_names_in_toml() {
        let config: ServerConfig = toml::from_str(
            r#"
            [[channels]]
            name = "General"
            kind = "voice_and_text"

            [[channels]]
            name = "Notes"
            kind = "text"
            "#,
        )
        .unwrap();
        assert_eq!(config.channels[0].kind, ChannelKind::VoiceAndText);
        assert_eq!(config.channels[1].kind, ChannelKind::Text);
    }

    #[test]
    fn a_typo_in_a_field_name_is_reported_rather_than_ignored() {
        // Silently dropping `min_security_leval` would leave the operator
        // believing they had raised the bar.
        assert!(toml::from_str::<ServerConfig>("min_security_leval = 20").is_err());
    }

    #[test]
    fn duplicate_channel_names_are_refused() {
        let config: ServerConfig = toml::from_str(
            r#"
            [[channels]]
            name = "General"
            [[channels]]
            name = "General"
            "#,
        )
        .unwrap();
        assert!(config.validate().is_err());
    }

    #[test]
    fn a_dangling_parent_is_refused() {
        let config: ServerConfig = toml::from_str(
            r#"
            [[channels]]
            name = "General"
            parent = "Nowhere"
            "#,
        )
        .unwrap();
        assert!(config.validate().is_err());
    }

    #[test]
    fn an_empty_channel_list_is_refused() {
        let config: ServerConfig = toml::from_str("channels = []").unwrap();
        assert!(config.validate().is_err());
    }

    #[test]
    fn save_then_load_roundtrips() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("server.toml");

        let original = ServerConfig {
            name: "Roundtrip".into(),
            min_security_level: 22,
            password: Some("hunter2".into()),
            ..ServerConfig::default()
        };
        original.save(&path).unwrap();

        let loaded = ServerConfig::load(&path).unwrap();
        assert_eq!(loaded.name, "Roundtrip");
        assert_eq!(loaded.min_security_level, 22);
        assert_eq!(loaded.password.as_deref(), Some("hunter2"));
        assert_eq!(loaded.channels.len(), original.channels.len());
    }

    #[test]
    fn load_or_create_writes_a_starter_file() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("nested/server.toml");
        let config = ServerConfig::load_or_create(&path).unwrap();
        assert!(path.exists());
        assert_eq!(config.name, default_name());
        // Second call must read the file rather than overwrite it.
        assert!(ServerConfig::load_or_create(&path).is_ok());
    }
}
