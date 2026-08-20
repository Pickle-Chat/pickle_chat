//! Durable server state.
//!
//! SQLite by default and Postgres when the configured URL says so, through
//! sqlx's `Any` driver — one code path, the backend chosen at runtime from the
//! URL scheme.
//!
//! # Two backends, and what that costs
//!
//! `sqlx::query!` verifies SQL against *one* database at compile time, so
//! supporting two rules it out. Every query here uses the runtime API instead,
//! which means correctness rests on the tests below rather than on the
//! compiler. The schema in `migrations/` stays inside the portable subset for
//! the same reason.
//!
//! # Where this sits
//!
//! Deliberately outside [`Shared`](crate::state::Shared), which stays entirely
//! synchronous. The store is async and is never called while a state lock is
//! held, so the property the voice relay depends on — never awaiting inside a
//! lock — is untouched by adding a database.

use pickle_identity::Fingerprint;
use pickle_proto::{
    BanEntry, Channel, ChannelId, ChannelKind, ChatMessage, MessageId, Overwrite, OverwriteTarget,
    Permissions, Role, RoleId,
};
use sqlx::any::{AnyPoolOptions, AnyRow};
use sqlx::{AnyPool, Row};
use std::path::Path;

#[derive(Debug, thiserror::Error)]
pub enum StoreError {
    #[error("opening the database: {0}")]
    Connect(#[source] sqlx::Error),
    #[error("preparing the database schema: {0}")]
    Migrate(#[source] sqlx::migrate::MigrateError),
    #[error("database query failed: {0}")]
    Query(#[from] sqlx::Error),
}

/// How many messages one history request may return, however many it asks for.
///
/// A client naming a huge limit would otherwise turn one frame into an
/// unbounded read and an unbounded response.
pub const MAX_HISTORY_LIMIT: u16 = 200;

#[derive(Clone)]
pub struct Store {
    pool: AnyPool,
}

impl Store {
    /// Open the database named by `url` and bring the schema up to date.
    ///
    /// A URL without a scheme is treated as a SQLite path, so an operator can
    /// write `history.db` and get what they expect.
    pub async fn open(url: &str) -> Result<Self, StoreError> {
        // Registers the sqlite and postgres drivers with the `Any` driver.
        // Without this every connection fails at runtime with an unhelpful
        // "no driver found", so it happens here rather than being left to the
        // caller to remember.
        sqlx::any::install_default_drivers();

        let pool = AnyPoolOptions::new()
            .max_connections(8)
            .connect(url)
            .await
            .map_err(StoreError::Connect)?;

        sqlx::migrate!("./migrations")
            .run(&pool)
            .await
            .map_err(StoreError::Migrate)?;

        Ok(Self { pool })
    }

    /// Build a SQLite URL for a file in the server's data directory.
    ///
    /// `?mode=rwc` creates the file if it is missing, which is the behaviour an
    /// operator expects from a fresh data directory.
    pub fn sqlite_url(data_dir: &Path, filename: &str) -> String {
        format!("sqlite://{}?mode=rwc", data_dir.join(filename).display())
    }

    /// The highest message id ever stored, if any.
    ///
    /// The server assigns message ids from an in-memory counter that starts at
    /// 1 on every boot. Once messages are durable that counter has to resume
    /// past what is already on disk, or the first restart silently reuses ids
    /// and collides with stored rows.
    pub async fn highest_message_id(&self) -> Result<Option<MessageId>, StoreError> {
        let row = sqlx::query("SELECT MAX(id) AS highest FROM messages")
            .fetch_one(&self.pool)
            .await?;

        // MAX over an empty table is NULL rather than no row.
        Ok(row.try_get::<i64, _>("highest").ok().map(|id| id as u64))
    }

    /// Store a message.
    ///
    /// Called before the message is broadcast, so a failure here is reported to
    /// the sender rather than leaving everyone looking at something that will
    /// not survive a restart.
    pub async fn insert_message(&self, message: &ChatMessage) -> Result<(), StoreError> {
        sqlx::query(
            "INSERT INTO messages (
                 id, channel, author_fingerprint, author_nickname,
                 sent_at_unix_ms, edited_at_unix_ms, content, reply_to
             ) VALUES ($1, $2, $3, $4, $5, $6, $7, $8)",
        )
        .bind(message.id as i64)
        .bind(message.channel as i64)
        .bind(message.author_fingerprint.to_string())
        .bind(message.author_nickname.clone())
        .bind(message.sent_at_unix_ms as i64)
        .bind(message.edited_at_unix_ms.map(|at| at as i64))
        .bind(message.content.clone())
        .bind(message.reply_to.map(|id| id as i64))
        .execute(&self.pool)
        .await?;

        Ok(())
    }

    /// A page of history, newest first, ending before `before` when given.
    ///
    /// Returns one more row than asked for internally, to answer "is there
    /// anything older" without a second count query.
    pub async fn history(
        &self,
        channel: ChannelId,
        before: Option<MessageId>,
        limit: u16,
    ) -> Result<History, StoreError> {
        let limit = limit.clamp(1, MAX_HISTORY_LIMIT);
        // One extra row is the cheapest way to know whether the beginning has
        // been reached.
        let probe = limit as i64 + 1;

        let rows: Vec<AnyRow> = match before {
            Some(before) => {
                sqlx::query(
                    "SELECT id, channel, author_fingerprint, author_nickname,
                            sent_at_unix_ms, edited_at_unix_ms, content, reply_to
                     FROM messages
                     WHERE channel = $1 AND id < $2
                     ORDER BY id DESC
                     LIMIT $3",
                )
                .bind(channel as i64)
                .bind(before as i64)
                .bind(probe)
                .fetch_all(&self.pool)
                .await?
            }
            None => {
                sqlx::query(
                    "SELECT id, channel, author_fingerprint, author_nickname,
                            sent_at_unix_ms, edited_at_unix_ms, content, reply_to
                     FROM messages
                     WHERE channel = $1
                     ORDER BY id DESC
                     LIMIT $2",
                )
                .bind(channel as i64)
                .bind(probe)
                .fetch_all(&self.pool)
                .await?
            }
        };

        let reached_start = rows.len() <= limit as usize;
        let mut messages: Vec<ChatMessage> = rows
            .iter()
            .take(limit as usize)
            .map(row_to_message)
            .collect::<Result<_, _>>()?;

        // Queried newest first for the LIMIT, handed back oldest first because
        // that is the order it will be rendered in.
        messages.reverse();

        Ok(History {
            messages,
            reached_start,
        })
    }

    // ---- Permissions ------------------------------------------------------
    //
    // Loaded once at startup into the in-memory engine and written through by
    // the admin handlers. Everything stays in the portable subset; every
    // query is covered by a round-trip test below, standing in for the
    // compile-time checking two backends rule out.

    /// Every role, ordered by position ascending (@everyone first).
    pub async fn load_roles(&self) -> Result<Vec<Role>, StoreError> {
        let rows = sqlx::query(
            "SELECT id, name, position, color, permissions FROM roles ORDER BY position ASC",
        )
        .fetch_all(&self.pool)
        .await?;
        rows.iter()
            .map(row_to_role)
            .collect::<Result<_, _>>()
            .map_err(StoreError::from)
    }

    pub async fn insert_role(&self, role: &Role) -> Result<(), StoreError> {
        sqlx::query(
            "INSERT INTO roles (id, name, position, color, permissions)
             VALUES ($1, $2, $3, $4, $5)",
        )
        .bind(role.id as i64)
        .bind(role.name.clone())
        .bind(role.position as i64)
        .bind(role.color.map(|c| c as i64))
        .bind(role.permissions.0 as i64)
        .execute(&self.pool)
        .await?;
        Ok(())
    }

    pub async fn update_role(&self, role: &Role) -> Result<(), StoreError> {
        sqlx::query("UPDATE roles SET name = $2, color = $3, permissions = $4 WHERE id = $1")
            .bind(role.id as i64)
            .bind(role.name.clone())
            .bind(role.color.map(|c| c as i64))
            .bind(role.permissions.0 as i64)
            .execute(&self.pool)
            .await?;
        Ok(())
    }

    /// Remove a role and everything that references it: grants and
    /// role-targeted overwrites. Deleting a role demotes its holders.
    pub async fn delete_role(&self, role: RoleId) -> Result<(), StoreError> {
        let mut tx = self.pool.begin().await?;
        sqlx::query("DELETE FROM role_members WHERE role_id = $1")
            .bind(role as i64)
            .execute(&mut *tx)
            .await?;
        sqlx::query("DELETE FROM channel_overwrites WHERE target_kind = 0 AND target = $1")
            .bind(role.to_string())
            .execute(&mut *tx)
            .await?;
        sqlx::query("DELETE FROM roles WHERE id = $1")
            .bind(role as i64)
            .execute(&mut *tx)
            .await?;
        tx.commit().await?;
        Ok(())
    }

    /// Write a full ordering in one transaction, so a crash mid-reorder can
    /// never leave two roles at one position.
    pub async fn set_role_positions(&self, positions: &[(RoleId, u32)]) -> Result<(), StoreError> {
        let mut tx = self.pool.begin().await?;
        for (role, position) in positions {
            sqlx::query("UPDATE roles SET position = $2 WHERE id = $1")
                .bind(*role as i64)
                .bind(*position as i64)
                .execute(&mut *tx)
                .await?;
        }
        tx.commit().await?;
        Ok(())
    }

    /// Replace a member's grants wholesale — the wire command's semantics.
    pub async fn replace_member_roles(
        &self,
        fingerprint: Fingerprint,
        roles: &[RoleId],
    ) -> Result<(), StoreError> {
        let mut tx = self.pool.begin().await?;
        sqlx::query("DELETE FROM role_members WHERE fingerprint = $1")
            .bind(fingerprint.to_string())
            .execute(&mut *tx)
            .await?;
        for role in roles {
            sqlx::query("INSERT INTO role_members (fingerprint, role_id) VALUES ($1, $2)")
                .bind(fingerprint.to_string())
                .bind(*role as i64)
                .execute(&mut *tx)
                .await?;
        }
        tx.commit().await?;
        Ok(())
    }

    pub async fn upsert_overwrite(
        &self,
        channel: ChannelId,
        overwrite: &Overwrite,
    ) -> Result<(), StoreError> {
        let (kind, target) = overwrite_key(&overwrite.target);
        sqlx::query(
            "INSERT INTO channel_overwrites (channel, target_kind, target, allow, deny)
             VALUES ($1, $2, $3, $4, $5)
             ON CONFLICT (channel, target_kind, target) DO UPDATE SET allow = $4, deny = $5",
        )
        .bind(channel as i64)
        .bind(kind)
        .bind(target)
        .bind(overwrite.allow.0 as i64)
        .bind(overwrite.deny.0 as i64)
        .execute(&self.pool)
        .await?;
        Ok(())
    }

    pub async fn delete_overwrite(
        &self,
        channel: ChannelId,
        target: &OverwriteTarget,
    ) -> Result<(), StoreError> {
        let (kind, key) = overwrite_key(target);
        sqlx::query(
            "DELETE FROM channel_overwrites
             WHERE channel = $1 AND target_kind = $2 AND target = $3",
        )
        .bind(channel as i64)
        .bind(kind)
        .bind(key)
        .execute(&self.pool)
        .await?;
        Ok(())
    }

    /// Every member's explicit role grants.
    pub async fn load_role_members(&self) -> Result<Vec<(Fingerprint, RoleId)>, StoreError> {
        let rows = sqlx::query("SELECT fingerprint, role_id FROM role_members")
            .fetch_all(&self.pool)
            .await?;
        let mut grants = Vec::with_capacity(rows.len());
        for row in &rows {
            let raw: String = row.try_get("fingerprint")?;
            // A row this code did not write (hand-edited, or a future bug) is
            // skipped rather than fatal: an unreadable grant must not stop the
            // server, and dropping it merely demotes its holder.
            let Ok(fingerprint) = Fingerprint::parse(&raw) else {
                tracing::warn!(fingerprint = raw, "skipping an unreadable role grant");
                continue;
            };
            let role: i64 = row.try_get("role_id")?;
            grants.push((fingerprint, role as RoleId));
        }
        Ok(grants)
    }

    pub async fn insert_role_member(
        &self,
        fingerprint: Fingerprint,
        role: RoleId,
    ) -> Result<(), StoreError> {
        sqlx::query(
            "INSERT INTO role_members (fingerprint, role_id) VALUES ($1, $2)
             ON CONFLICT (fingerprint, role_id) DO NOTHING",
        )
        .bind(fingerprint.to_string())
        .bind(role as i64)
        .execute(&self.pool)
        .await?;
        Ok(())
    }

    /// Every channel's overwrites, tagged with their channel id.
    pub async fn load_overwrites(&self) -> Result<Vec<(ChannelId, Overwrite)>, StoreError> {
        let rows =
            sqlx::query("SELECT channel, target_kind, target, allow, deny FROM channel_overwrites")
                .fetch_all(&self.pool)
                .await?;
        let mut overwrites = Vec::with_capacity(rows.len());
        for row in &rows {
            let channel: i64 = row.try_get("channel")?;
            let kind: i64 = row.try_get("target_kind")?;
            let raw: String = row.try_get("target")?;
            let target = match kind {
                0 => raw.parse::<RoleId>().ok().map(OverwriteTarget::Role),
                1 => Fingerprint::parse(&raw).ok().map(OverwriteTarget::Member),
                _ => None,
            };
            let Some(target) = target else {
                tracing::warn!(target = raw, kind, "skipping an unreadable overwrite");
                continue;
            };
            let allow: i64 = row.try_get("allow")?;
            let deny: i64 = row.try_get("deny")?;
            overwrites.push((
                channel as ChannelId,
                Overwrite {
                    target,
                    allow: Permissions(allow as u64),
                    deny: Permissions(deny as u64),
                },
            ));
        }
        Ok(overwrites)
    }

    /// Every channel, in display order. Overwrites are loaded separately and
    /// joined in memory by the caller.
    pub async fn load_channels(&self) -> Result<Vec<Channel>, StoreError> {
        let rows = sqlx::query(
            "SELECT id, parent, name, topic, kind, max_users, sort_order
             FROM channels ORDER BY sort_order ASC, id ASC",
        )
        .fetch_all(&self.pool)
        .await?;
        rows.iter()
            .map(row_to_channel)
            .collect::<Result<_, _>>()
            .map_err(StoreError::from)
    }

    pub async fn insert_channel(&self, channel: &Channel) -> Result<(), StoreError> {
        sqlx::query(
            "INSERT INTO channels (id, parent, name, topic, kind, max_users, sort_order)
             VALUES ($1, $2, $3, $4, $5, $6, $7)",
        )
        .bind(channel.id as i64)
        .bind(channel.parent.map(|p| p as i64))
        .bind(channel.name.clone())
        .bind(channel.topic.clone())
        .bind(kind_str(channel.kind))
        .bind(channel.max_users.map(|m| m as i64))
        .bind(channel.order as i64)
        .execute(&self.pool)
        .await?;
        Ok(())
    }

    /// Record a ban, replacing any existing one for the fingerprint — a
    /// re-ban updates the reason and clock rather than failing.
    pub async fn insert_ban(&self, ban: &BanEntry) -> Result<(), StoreError> {
        sqlx::query(
            "INSERT INTO bans (fingerprint, reason, until_unix_ms, issued_by, issued_at_unix_ms)
             VALUES ($1, $2, $3, $4, $5)
             ON CONFLICT (fingerprint) DO UPDATE SET
                 reason = $2, until_unix_ms = $3, issued_by = $4, issued_at_unix_ms = $5",
        )
        .bind(ban.fingerprint.to_string())
        .bind(ban.reason.clone())
        .bind(ban.until_unix_ms.map(|u| u as i64))
        .bind(ban.issued_by.to_string())
        .bind(ban.issued_at_unix_ms as i64)
        .execute(&self.pool)
        .await?;
        Ok(())
    }

    pub async fn delete_ban(&self, fingerprint: Fingerprint) -> Result<(), StoreError> {
        sqlx::query("DELETE FROM bans WHERE fingerprint = $1")
            .bind(fingerprint.to_string())
            .execute(&self.pool)
            .await?;
        Ok(())
    }

    /// Every ban on record, expired ones included — visible history until
    /// someone unbans, exactly as the schema comment promises.
    pub async fn list_bans(&self) -> Result<Vec<BanEntry>, StoreError> {
        let rows = sqlx::query(
            "SELECT fingerprint, reason, until_unix_ms, issued_by, issued_at_unix_ms
             FROM bans ORDER BY issued_at_unix_ms DESC",
        )
        .fetch_all(&self.pool)
        .await?;
        rows.iter()
            .map(row_to_ban)
            .collect::<Result<_, _>>()
            .map_err(StoreError::from)
    }

    /// The active ban for a fingerprint, if any. Expiry is compared here, on
    /// read, so a lapsed ban needs nothing running to stop applying.
    pub async fn active_ban(
        &self,
        fingerprint: Fingerprint,
        now_unix_ms: u64,
    ) -> Result<Option<BanEntry>, StoreError> {
        let row = sqlx::query(
            "SELECT fingerprint, reason, until_unix_ms, issued_by, issued_at_unix_ms
             FROM bans WHERE fingerprint = $1",
        )
        .bind(fingerprint.to_string())
        .fetch_optional(&self.pool)
        .await?;
        let Some(row) = row else { return Ok(None) };
        let ban = row_to_ban(&row)?;
        match ban.until_unix_ms {
            Some(until) if until <= now_unix_ms => Ok(None),
            _ => Ok(Some(ban)),
        }
    }

    /// Delete messages older than `cutoff`, returning how many went.
    pub async fn prune_before(&self, cutoff_unix_ms: u64) -> Result<u64, StoreError> {
        let result = sqlx::query("DELETE FROM messages WHERE sent_at_unix_ms < $1")
            .bind(cutoff_unix_ms as i64)
            .execute(&self.pool)
            .await?;
        Ok(result.rows_affected())
    }

    /// Keep only the newest `keep` messages in each channel.
    ///
    /// Expressed per channel rather than as one global cap so a busy channel
    /// cannot evict a quiet one's entire history.
    pub async fn prune_to_limit(&self, keep: u32) -> Result<u64, StoreError> {
        let channels: Vec<i64> = sqlx::query("SELECT DISTINCT channel FROM messages")
            .fetch_all(&self.pool)
            .await?
            .iter()
            .map(|row| row.get::<i64, _>("channel"))
            .collect();

        let mut removed = 0;
        for channel in channels {
            // A correlated subquery would be neater, but the portable subset
            // across both backends is narrower than either alone; two plain
            // statements are less clever and work everywhere.
            let cutoff: Option<i64> = sqlx::query(
                "SELECT id FROM messages
                 WHERE channel = $1
                 ORDER BY id DESC
                 LIMIT 1 OFFSET $2",
            )
            .bind(channel)
            .bind(keep as i64)
            .fetch_optional(&self.pool)
            .await?
            .map(|row| row.get::<i64, _>("id"));

            // No row at that offset means the channel is already under the cap.
            let Some(cutoff) = cutoff else { continue };

            let result = sqlx::query("DELETE FROM messages WHERE channel = $1 AND id <= $2")
                .bind(channel)
                .bind(cutoff)
                .execute(&self.pool)
                .await?;
            removed += result.rows_affected();
        }

        Ok(removed)
    }

    pub async fn message_count(&self) -> Result<u64, StoreError> {
        let row = sqlx::query("SELECT COUNT(*) AS total FROM messages")
            .fetch_one(&self.pool)
            .await?;
        Ok(row.get::<i64, _>("total") as u64)
    }
}

/// A page of history and whether anything older remains.
#[derive(Debug)]
pub struct History {
    /// Oldest first.
    pub messages: Vec<ChatMessage>,
    pub reached_start: bool,
}

/// The storage key for an overwrite target: (kind column, target column).
fn overwrite_key(target: &OverwriteTarget) -> (i64, String) {
    match target {
        OverwriteTarget::Role(id) => (0, id.to_string()),
        OverwriteTarget::Member(fingerprint) => (1, fingerprint.to_string()),
    }
}

fn row_to_role(row: &AnyRow) -> Result<Role, sqlx::Error> {
    let id: i64 = row.try_get("id")?;
    let position: i64 = row.try_get("position")?;
    let color: Option<i64> = row.try_get("color")?;
    let permissions: i64 = row.try_get("permissions")?;
    Ok(Role {
        id: id as RoleId,
        name: row.try_get("name")?,
        color: color.map(|c| c as u32),
        position: position as u32,
        permissions: Permissions(permissions as u64),
    })
}

fn row_to_channel(row: &AnyRow) -> Result<Channel, sqlx::Error> {
    let id: i64 = row.try_get("id")?;
    let parent: Option<i64> = row.try_get("parent")?;
    let kind: String = row.try_get("kind")?;
    let max_users: Option<i64> = row.try_get("max_users")?;
    let order: i64 = row.try_get("sort_order")?;
    Ok(Channel {
        id: id as ChannelId,
        parent: parent.map(|p| p as ChannelId),
        name: row.try_get("name")?,
        topic: row.try_get("topic")?,
        kind: kind_from_str(&kind),
        max_users: max_users.map(|m| m as u16),
        order: order as i32,
        // Joined in memory by the caller from load_overwrites.
        overwrites: Vec::new(),
    })
}

fn row_to_ban(row: &AnyRow) -> Result<BanEntry, sqlx::Error> {
    let raw: String = row.try_get("fingerprint")?;
    let issued_by_raw: String = row.try_get("issued_by")?;
    let until: Option<i64> = row.try_get("until_unix_ms")?;
    let issued_at: i64 = row.try_get("issued_at_unix_ms")?;
    let parse =
        |value: &str| Fingerprint::parse(value).map_err(|e| sqlx::Error::Decode(Box::new(e)));
    Ok(BanEntry {
        fingerprint: parse(&raw)?,
        reason: row.try_get("reason")?,
        until_unix_ms: until.map(|u| u as u64),
        issued_by: parse(&issued_by_raw)?,
        issued_at_unix_ms: issued_at as u64,
    })
}

/// The kind column's spellings are the config file's, so a row is readable by
/// anyone who has seen a server.toml.
fn kind_str(kind: ChannelKind) -> &'static str {
    match kind {
        ChannelKind::Voice => "voice",
        ChannelKind::Text => "text",
        ChannelKind::VoiceAndText => "voice_and_text",
    }
}

fn kind_from_str(raw: &str) -> ChannelKind {
    match raw {
        "voice" => ChannelKind::Voice,
        "text" => ChannelKind::Text,
        // The unknown case reads as the most permissive kind rather than
        // refusing to boot over one bad row.
        _ => ChannelKind::VoiceAndText,
    }
}

fn row_to_message(row: &AnyRow) -> Result<ChatMessage, sqlx::Error> {
    let fingerprint: String = row.try_get("author_fingerprint")?;

    Ok(ChatMessage {
        id: row.try_get::<i64, _>("id")? as u64,
        channel: row.try_get::<i64, _>("channel")? as u32,
        // The connection that sent this is long gone by the time history is
        // read, and a client id would mean someone else by now.
        author: None,
        author_fingerprint: pickle_identity::Fingerprint::parse(&fingerprint).map_err(|_| {
            sqlx::Error::Decode(format!("stored fingerprint {fingerprint} is unreadable").into())
        })?,
        author_nickname: row.try_get("author_nickname")?,
        sent_at_unix_ms: row.try_get::<i64, _>("sent_at_unix_ms")? as u64,
        edited_at_unix_ms: row
            .try_get::<Option<i64>, _>("edited_at_unix_ms")?
            .map(|at| at as u64),
        content: row.try_get("content")?,
        reply_to: row
            .try_get::<Option<i64>, _>("reply_to")?
            .map(|id| id as u64),
        attachments: Vec::new(),
        reactions: Vec::new(),
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use pickle_identity::Identity;

    /// A store on a fresh temporary database.
    ///
    /// Returns the directory too: dropping it deletes the file, so it has to
    /// outlive the store.
    async fn store() -> (tempfile::TempDir, Store) {
        let dir = tempfile::tempdir().unwrap();
        let store = Store::open(&Store::sqlite_url(dir.path(), "test.db"))
            .await
            .unwrap();
        (dir, store)
    }

    fn message(id: MessageId, channel: ChannelId, content: &str) -> ChatMessage {
        ChatMessage {
            id,
            channel,
            author: Some(1),
            author_fingerprint: Identity::generate().fingerprint(),
            author_nickname: "alice".into(),
            sent_at_unix_ms: 1_000 + id,
            edited_at_unix_ms: None,
            content: content.into(),
            reply_to: None,
            attachments: Vec::new(),
            reactions: Vec::new(),
        }
    }

    #[tokio::test]
    async fn a_message_survives_being_written_and_read_back() {
        let (_dir, store) = store().await;
        let original = message(1, 7, "hello");
        store.insert_message(&original).await.unwrap();

        let history = store.history(7, None, 10).await.unwrap();
        assert_eq!(history.messages.len(), 1);

        let read = &history.messages[0];
        assert_eq!(read.id, original.id);
        assert_eq!(read.content, "hello");
        assert_eq!(read.author_fingerprint, original.author_fingerprint);
        assert_eq!(read.author_nickname, "alice");
        assert_eq!(
            read.author, None,
            "the sending connection is gone; a client id would name someone else",
        );
    }

    #[tokio::test]
    async fn the_id_counter_resumes_past_what_is_already_stored() {
        // Without this the first restart reuses ids and collides with stored
        // rows — the bug persistence would otherwise introduce.
        let dir = tempfile::tempdir().unwrap();
        let url = Store::sqlite_url(dir.path(), "test.db");

        let store = Store::open(&url).await.unwrap();
        assert_eq!(store.highest_message_id().await.unwrap(), None);
        store.insert_message(&message(1, 1, "a")).await.unwrap();
        store.insert_message(&message(42, 1, "b")).await.unwrap();
        drop(store);

        // Reopening is what a server restart does.
        let reopened = Store::open(&url).await.unwrap();
        assert_eq!(reopened.highest_message_id().await.unwrap(), Some(42));
    }

    #[tokio::test]
    async fn history_is_returned_oldest_first() {
        let (_dir, store) = store().await;
        for id in 1..=3 {
            store
                .insert_message(&message(id, 1, &format!("m{id}")))
                .await
                .unwrap();
        }

        let history = store.history(1, None, 10).await.unwrap();
        let contents: Vec<&str> = history
            .messages
            .iter()
            .map(|m| m.content.as_str())
            .collect();
        assert_eq!(contents, vec!["m1", "m2", "m3"], "rendering order");
    }

    #[tokio::test]
    async fn paging_backwards_reports_the_start_only_at_the_start() {
        let (_dir, store) = store().await;
        for id in 1..=5 {
            store
                .insert_message(&message(id, 1, &format!("m{id}")))
                .await
                .unwrap();
        }

        let newest = store.history(1, None, 2).await.unwrap();
        assert_eq!(
            newest.messages.iter().map(|m| m.id).collect::<Vec<_>>(),
            vec![4, 5],
        );
        assert!(!newest.reached_start, "three older messages remain");

        let older = store.history(1, Some(4), 2).await.unwrap();
        assert_eq!(
            older.messages.iter().map(|m| m.id).collect::<Vec<_>>(),
            vec![2, 3]
        );
        assert!(!older.reached_start);

        let oldest = store.history(1, Some(2), 2).await.unwrap();
        assert_eq!(
            oldest.messages.iter().map(|m| m.id).collect::<Vec<_>>(),
            vec![1]
        );
        assert!(oldest.reached_start, "nothing older than the first message");
    }

    #[tokio::test]
    async fn history_does_not_leak_between_channels() {
        let (_dir, store) = store().await;
        store
            .insert_message(&message(1, 1, "in one"))
            .await
            .unwrap();
        store
            .insert_message(&message(2, 2, "in two"))
            .await
            .unwrap();

        let one = store.history(1, None, 10).await.unwrap();
        assert_eq!(one.messages.len(), 1);
        assert_eq!(one.messages[0].content, "in one");
    }

    #[tokio::test]
    async fn an_outsized_limit_is_capped() {
        let (_dir, store) = store().await;
        for id in 1..=10 {
            store.insert_message(&message(id, 1, "m")).await.unwrap();
        }

        // Asking for more than the cap must not turn one frame into an
        // unbounded read.
        let history = store.history(1, None, u16::MAX).await.unwrap();
        assert!(history.messages.len() <= MAX_HISTORY_LIMIT as usize);
    }

    #[tokio::test]
    async fn pruning_by_age_keeps_what_is_recent() {
        let (_dir, store) = store().await;
        // `message` sets sent_at to 1000 + id.
        for id in 1..=5 {
            store.insert_message(&message(id, 1, "m")).await.unwrap();
        }

        let removed = store.prune_before(1_003).await.unwrap();
        assert_eq!(removed, 2, "ids 1 and 2 sit before the cutoff");
        assert_eq!(store.message_count().await.unwrap(), 3);
    }

    #[tokio::test]
    async fn pruning_to_a_limit_is_per_channel() {
        // A busy channel must not be able to evict a quiet one's history.
        let (_dir, store) = store().await;
        for id in 1..=5 {
            store.insert_message(&message(id, 1, "busy")).await.unwrap();
        }
        store
            .insert_message(&message(100, 2, "quiet"))
            .await
            .unwrap();

        store.prune_to_limit(2).await.unwrap();

        assert_eq!(store.history(1, None, 10).await.unwrap().messages.len(), 2);
        assert_eq!(
            store.history(2, None, 10).await.unwrap().messages.len(),
            1,
            "the quiet channel was under the cap and keeps everything",
        );
    }

    #[tokio::test]
    async fn pruning_a_channel_already_under_the_limit_removes_nothing() {
        let (_dir, store) = store().await;
        store.insert_message(&message(1, 1, "m")).await.unwrap();

        assert_eq!(store.prune_to_limit(10).await.unwrap(), 0);
        assert_eq!(store.message_count().await.unwrap(), 1);
    }

    #[tokio::test]
    async fn migrations_are_idempotent_across_reopens() {
        // Every server start runs them, so a second run has to be a no-op
        // rather than an error.
        let dir = tempfile::tempdir().unwrap();
        let url = Store::sqlite_url(dir.path(), "test.db");
        Store::open(&url).await.unwrap();
        Store::open(&url).await.unwrap();
    }

    // ---- permission storage round-trips ------------------------------------
    //
    // The runtime query API has no compile-time checking with two backends,
    // so each query's test is its compiler.

    #[tokio::test]
    async fn roles_round_trip_in_position_order() {
        let (_dir, store) = store().await;
        let admin = Role {
            id: 2,
            name: "admin".into(),
            color: Some(0xff8800),
            position: 2,
            permissions: Permissions::ADMINISTRATOR,
        };
        let everyone = Role {
            id: 0,
            name: "everyone".into(),
            color: None,
            position: 0,
            permissions: Permissions::DEFAULT_EVERYONE,
        };
        store.insert_role(&admin).await.unwrap();
        store.insert_role(&everyone).await.unwrap();

        let loaded = store.load_roles().await.unwrap();
        assert_eq!(
            loaded,
            vec![everyone, admin],
            "ordered by position, not insertion"
        );
    }

    #[tokio::test]
    async fn a_high_bit_mask_survives_the_signed_column() {
        // Bit 62 is the highest a mask may ever use; the cast through BIGINT
        // must bring it back intact.
        let (_dir, store) = store().await;
        let role = Role {
            id: 1,
            name: "future".into(),
            color: None,
            position: 1,
            permissions: Permissions(1 << 62),
        };
        store.insert_role(&role).await.unwrap();
        assert_eq!(
            store.load_roles().await.unwrap()[0].permissions,
            Permissions(1 << 62)
        );
    }

    #[tokio::test]
    async fn channels_round_trip_with_their_config_shapes() {
        let (_dir, store) = store().await;
        let channel = Channel {
            id: 3,
            parent: Some(1),
            name: "General".into(),
            topic: "Hang out".into(),
            kind: ChannelKind::VoiceAndText,
            max_users: Some(8),
            order: 2,
            overwrites: Vec::new(),
        };
        store.insert_channel(&channel).await.unwrap();
        assert_eq!(store.load_channels().await.unwrap(), vec![channel]);
    }

    #[tokio::test]
    async fn overwrites_round_trip_for_both_target_kinds() {
        let (_dir, store) = store().await;
        let member = Identity::generate().fingerprint();
        sqlx::query(
            "INSERT INTO channel_overwrites (channel, target_kind, target, allow, deny)
             VALUES ($1, $2, $3, $4, $5)",
        )
        .bind(7i64)
        .bind(0i64)
        .bind("2")
        .bind(Permissions::SEND_MESSAGES.0 as i64)
        .bind(0i64)
        .execute(&store.pool)
        .await
        .unwrap();
        sqlx::query(
            "INSERT INTO channel_overwrites (channel, target_kind, target, allow, deny)
             VALUES ($1, $2, $3, $4, $5)",
        )
        .bind(7i64)
        .bind(1i64)
        .bind(member.to_string())
        .bind(0i64)
        .bind(Permissions::VIEW_CHANNEL.0 as i64)
        .execute(&store.pool)
        .await
        .unwrap();

        let loaded = store.load_overwrites().await.unwrap();
        assert_eq!(loaded.len(), 2);
        assert!(loaded.iter().any(|(c, o)| *c == 7
            && o.target == OverwriteTarget::Role(2)
            && o.allow == Permissions::SEND_MESSAGES));
        assert!(loaded.iter().any(|(c, o)| *c == 7
            && o.target == OverwriteTarget::Member(member)
            && o.deny == Permissions::VIEW_CHANNEL));
    }

    #[tokio::test]
    async fn role_grants_round_trip_and_unreadable_rows_demote() {
        let (_dir, store) = store().await;
        let member = Identity::generate().fingerprint();
        for (fp, role) in [
            (member.to_string(), 2i64),
            ("not-a-fingerprint".into(), 1i64),
        ] {
            sqlx::query("INSERT INTO role_members (fingerprint, role_id) VALUES ($1, $2)")
                .bind(fp)
                .bind(role)
                .execute(&store.pool)
                .await
                .unwrap();
        }
        let grants = store.load_role_members().await.unwrap();
        assert_eq!(
            grants,
            vec![(member, 2)],
            "the unreadable row is skipped, not fatal"
        );
    }

    #[tokio::test]
    async fn role_updates_reorders_and_deletion_cascade() {
        let (_dir, store) = store().await;
        let member = Identity::generate().fingerprint();
        for role in [
            Role {
                id: 0,
                name: "everyone".into(),
                color: None,
                position: 0,
                permissions: Permissions::DEFAULT_EVERYONE,
            },
            Role {
                id: 1,
                name: "helper".into(),
                color: None,
                position: 1,
                permissions: Permissions::NONE,
            },
        ] {
            store.insert_role(&role).await.unwrap();
        }
        store.insert_role_member(member, 1).await.unwrap();
        store
            .upsert_overwrite(
                7,
                &Overwrite {
                    target: OverwriteTarget::Role(1),
                    allow: Permissions::SEND_MESSAGES,
                    deny: Permissions::NONE,
                },
            )
            .await
            .unwrap();

        // Update sticks.
        let renamed = Role {
            id: 1,
            name: "mod".into(),
            color: Some(7),
            position: 1,
            permissions: Permissions::KICK_MEMBERS,
        };
        store.update_role(&renamed).await.unwrap();
        assert_eq!(store.load_roles().await.unwrap()[1], renamed);

        // Reorder is transactional and total.
        store.set_role_positions(&[(0, 0), (1, 5)]).await.unwrap();
        assert_eq!(store.load_roles().await.unwrap()[1].position, 5);

        // Deleting cascades to grants and role-targeted overwrites.
        store.delete_role(1).await.unwrap();
        assert!(store.load_role_members().await.unwrap().is_empty());
        assert!(store.load_overwrites().await.unwrap().is_empty());
        assert_eq!(store.load_roles().await.unwrap().len(), 1);
    }

    #[tokio::test]
    async fn member_roles_replace_wholesale_and_overwrites_upsert() {
        let (_dir, store) = store().await;
        let member = Identity::generate().fingerprint();
        for id in [1u32, 2, 3] {
            store
                .insert_role(&Role {
                    id,
                    name: format!("r{id}"),
                    color: None,
                    position: id,
                    permissions: Permissions::NONE,
                })
                .await
                .unwrap();
        }
        store.replace_member_roles(member, &[1, 2]).await.unwrap();
        store.replace_member_roles(member, &[3]).await.unwrap();
        let grants = store.load_role_members().await.unwrap();
        assert_eq!(grants, vec![(member, 3)], "replacement, not accumulation");

        let target = OverwriteTarget::Member(member);
        store
            .upsert_overwrite(
                4,
                &Overwrite {
                    target,
                    allow: Permissions::CONNECT,
                    deny: Permissions::NONE,
                },
            )
            .await
            .unwrap();
        store
            .upsert_overwrite(
                4,
                &Overwrite {
                    target,
                    allow: Permissions::NONE,
                    deny: Permissions::CONNECT,
                },
            )
            .await
            .unwrap();
        let loaded = store.load_overwrites().await.unwrap();
        assert_eq!(loaded.len(), 1, "same key upserts");
        assert_eq!(loaded[0].1.deny, Permissions::CONNECT);

        store.delete_overwrite(4, &target).await.unwrap();
        assert!(store.load_overwrites().await.unwrap().is_empty());
        // Deleting again is a quiet no-op.
        store.delete_overwrite(4, &target).await.unwrap();
    }

    #[tokio::test]
    async fn bans_upsert_delete_and_list_through_the_store_api() {
        let (_dir, store) = store().await;
        let target = Identity::generate().fingerprint();
        let issuer = Identity::generate().fingerprint();
        let ban = |reason: &str| BanEntry {
            fingerprint: target,
            reason: reason.into(),
            until_unix_ms: None,
            issued_by: issuer,
            issued_at_unix_ms: 42,
        };

        store.insert_ban(&ban("first")).await.unwrap();
        store.insert_ban(&ban("re-banned")).await.unwrap();
        let listed = store.list_bans().await.unwrap();
        assert_eq!(listed.len(), 1, "a re-ban replaces, never duplicates");
        assert_eq!(listed[0].reason, "re-banned");
        assert!(store.active_ban(target, 0).await.unwrap().is_some());

        store.delete_ban(target).await.unwrap();
        assert!(store.list_bans().await.unwrap().is_empty());
        assert!(store.active_ban(target, 0).await.unwrap().is_none());
    }

    #[tokio::test]
    async fn a_ban_applies_until_it_expires_and_permanent_ones_never_do() {
        let (_dir, store) = store().await;
        let banned = Identity::generate().fingerprint();
        let issuer = Identity::generate().fingerprint();
        let forever = Identity::generate().fingerprint();
        for (fp, until) in [(banned, Some(1_000i64)), (forever, None)] {
            sqlx::query(
                "INSERT INTO bans (fingerprint, reason, until_unix_ms, issued_by, issued_at_unix_ms)
                 VALUES ($1, $2, $3, $4, $5)",
            )
            .bind(fp.to_string())
            .bind("spam")
            .bind(until)
            .bind(issuer.to_string())
            .bind(500i64)
            .execute(&store.pool)
            .await
            .unwrap();
        }

        // Before expiry: both apply. After: only the permanent one.
        assert!(store.active_ban(banned, 999).await.unwrap().is_some());
        assert!(store.active_ban(banned, 1_000).await.unwrap().is_none());
        assert!(store.active_ban(forever, u64::MAX).await.unwrap().is_some());
        assert!(
            store.active_ban(issuer, 0).await.unwrap().is_none(),
            "unbanned is unbanned"
        );
    }
}
