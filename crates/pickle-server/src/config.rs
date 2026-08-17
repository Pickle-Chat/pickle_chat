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
    #[error("{key}={value:?} is not valid: {detail}")]
    Env {
        key: String,
        value: String,
        detail: String,
    },
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

    /// Where durable state lives.
    ///
    /// Unset means a SQLite file in the data directory, which is what a
    /// self-hosted server wants by default. Set it to a `postgres://` URL to
    /// use Postgres instead.
    #[serde(default)]
    pub database_url: Option<String>,

    /// Whether the server keeps chat history at all.
    ///
    /// Reported to clients through `ServerLimits`, so one that keeps nothing
    /// can say so rather than answering every history request with silence.
    #[serde(default = "default_history_enabled")]
    pub history_enabled: bool,

    /// Discard messages older than this many days. Unset keeps them forever.
    ///
    /// Unlimited by default: a self-hosted operator should decide what their
    /// own disk keeps, and quietly discarding what people assume is kept is the
    /// worse surprise.
    #[serde(default)]
    pub history_retention_days: Option<u32>,

    /// Keep at most this many messages in each channel. Unset is unlimited.
    ///
    /// Per channel rather than server-wide, so a busy channel cannot evict a
    /// quiet one's entire history.
    #[serde(default)]
    pub history_max_messages_per_channel: Option<u32>,

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
fn default_history_enabled() -> bool {
    true
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
            database_url: None,
            history_enabled: default_history_enabled(),
            history_retention_days: None,
            history_max_messages_per_channel: None,
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

    /// Load, or write out the defaults and use those, then apply the
    /// environment.
    ///
    /// The environment is applied *after* any save, deliberately. Writing it
    /// into the file would bake a one-off `PICKLE_NAME` from a single container
    /// run into the server's permanent configuration, where it would keep
    /// applying long after the variable was gone.
    pub fn load_or_create(path: &Path) -> Result<Self, ConfigError> {
        let mut config = match Self::load(path) {
            Err(ConfigError::Io { source, .. })
                if source.kind() == std::io::ErrorKind::NotFound =>
            {
                let config = Self::default();
                config.save(path)?;
                config
            }
            other => other?,
        };

        config.apply_env_from(|key| std::env::var(key).ok())?;
        config.validate()?;
        Ok(config)
    }

    /// Overlay `PICKLE_*` variables onto the configuration.
    ///
    /// Takes a lookup rather than reading the process environment directly, so
    /// the precedence rules can be tested without mutating global state that
    /// every other test in the binary shares.
    ///
    /// An unparseable value is an error rather than a fallback: a mistyped
    /// `PICKLE_BIND` in a compose file should stop the server, not leave it
    /// quietly listening somewhere nobody expects. An *empty* value is treated
    /// as absent, because an unset `${VAR}` in a compose file expands to one and
    /// almost never means "set this to nothing".
    pub fn apply_env_from(
        &mut self,
        get: impl Fn(&str) -> Option<String>,
    ) -> Result<(), ConfigError> {
        let read = |name: &str| -> Option<(String, String)> {
            let key = format!("PICKLE_{name}");
            get(&key)
                .map(|value| value.trim().to_string())
                .filter(|value| !value.is_empty())
                .map(|value| (key, value))
        };

        let invalid =
            |key: String, value: String, detail: &dyn std::fmt::Display| ConfigError::Env {
                key,
                value,
                detail: detail.to_string(),
            };

        if let Some((key, value)) = read("BIND") {
            self.bind = value.parse().map_err(|e| invalid(key, value.clone(), &e))?;
        }

        if let Some((_, value)) = read("NAME") {
            self.name = value;
        }

        if let Some((key, value)) = read("MIN_SECURITY_LEVEL") {
            self.min_security_level = value.parse().map_err(|e| invalid(key, value.clone(), &e))?;
        }

        if let Some((_, value)) = read("PASSWORD") {
            self.password = Some(value);
        }

        if let Some((key, value)) = read("OWNER") {
            // Checked here even though a bad owner in the *file* only warns.
            // A file may be hand-edited and refusing to start would be a poor
            // trade, but an environment variable is set deliberately by whoever
            // deployed this, and a typo silently leaving the server with no
            // owner is worse than a loud failure.
            pickle_identity::Fingerprint::parse(&value)
                .map_err(|e| invalid(key, value.clone(), &e))?;
            self.owner = Some(value);
        }

        if let Some((_, value)) = read("DATABASE_URL") {
            self.database_url = Some(value);
        }

        Ok(())
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

    /// A lookup over a fixed set of pairs, standing in for the process
    /// environment so these tests do not race each other through it.
    fn env<'a>(pairs: &'a [(&'a str, &'a str)]) -> impl Fn(&str) -> Option<String> + 'a {
        move |key| {
            pairs
                .iter()
                .find(|(k, _)| *k == key)
                .map(|(_, v)| v.to_string())
        }
    }

    #[test]
    fn the_environment_overrides_the_file() {
        let mut config = ServerConfig {
            name: "From File".into(),
            ..ServerConfig::default()
        };

        config
            .apply_env_from(env(&[
                ("PICKLE_NAME", "From Env"),
                ("PICKLE_BIND", "127.0.0.1:9999"),
                ("PICKLE_DATABASE_URL", "postgres://db/pickle"),
                ("PICKLE_MIN_SECURITY_LEVEL", "20"),
            ]))
            .unwrap();

        assert_eq!(config.name, "From Env");
        assert_eq!(config.bind.to_string(), "127.0.0.1:9999");
        assert_eq!(config.database_url.as_deref(), Some("postgres://db/pickle"));
        assert_eq!(config.min_security_level, 20);
    }

    #[test]
    fn the_file_wins_where_no_variable_is_set() {
        let mut config = ServerConfig {
            name: "From File".into(),
            min_security_level: 12,
            ..ServerConfig::default()
        };

        config.apply_env_from(env(&[])).unwrap();

        assert_eq!(config.name, "From File");
        assert_eq!(config.min_security_level, 12);
        assert_eq!(config.database_url, None);
    }

    #[test]
    fn an_unparseable_value_stops_the_server_rather_than_falling_back() {
        // A mistyped bind address in a compose file must not leave the server
        // quietly listening somewhere nobody expects.
        let mut config = ServerConfig::default();
        let original = config.bind;

        let error = config
            .apply_env_from(env(&[("PICKLE_BIND", "not-an-address")]))
            .expect_err("a bad address must be refused");

        assert!(matches!(error, ConfigError::Env { .. }));
        assert!(
            error.to_string().contains("PICKLE_BIND"),
            "the message must name the variable: {error}",
        );
        assert_eq!(config.bind, original, "and must not half-apply");
    }

    #[test]
    fn an_empty_value_is_treated_as_absent() {
        // An unset ${VAR} in a compose file expands to an empty string, which
        // almost never means "set this to nothing".
        let mut config = ServerConfig {
            name: "From File".into(),
            ..ServerConfig::default()
        };

        config
            .apply_env_from(env(&[("PICKLE_NAME", ""), ("PICKLE_PASSWORD", "   ")]))
            .unwrap();

        assert_eq!(config.name, "From File");
        assert_eq!(config.password, None);
    }

    #[test]
    fn a_malformed_owner_fingerprint_is_refused() {
        let mut config = ServerConfig::default();
        let error = config
            .apply_env_from(env(&[("PICKLE_OWNER", "not-a-fingerprint")]))
            .expect_err("a typo here would silently leave the server ownerless");
        assert!(matches!(error, ConfigError::Env { .. }));
    }

    #[test]
    fn load_or_create_does_not_write_the_environment_into_the_file() {
        // Otherwise a one-off variable from a single container run would be
        // baked in permanently, still applying long after it was gone.
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("config.toml");

        ServerConfig::load_or_create(&path).unwrap();
        let written: ServerConfig =
            toml::from_str(&std::fs::read_to_string(&path).unwrap()).unwrap();

        assert_eq!(
            written.name,
            ServerConfig::default().name,
            "the saved file holds defaults, not whatever the environment said",
        );
    }
}
