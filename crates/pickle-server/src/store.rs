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

use pickle_proto::{ChannelId, ChatMessage, MessageId};
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
}
