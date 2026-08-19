//! Authoritative server state: who is connected, where they are, and how
//! messages reach them.
//!
//! Guarded by a single `RwLock`. Fan-out and voice relay only take the read
//! lock and never block inside it — sends are `try_send` into a bounded queue,
//! or into quinn's datagram queue, both of which return immediately. A slow
//! client therefore cannot stall the relay for everyone else.
//!
//! A client whose queue fills has stopped reading, and is disconnected rather
//! than allowed to grow the server's memory without limit. That reaping happens
//! after the lock is released, since removing needs the write lock.

use crate::config::ServerConfig;
use crate::roles::{RoleError, Roles};
use crate::store::Store;
use parking_lot::RwLock;
use pickle_identity::{Fingerprint, Identity, PublicIdentity};
use pickle_proto::voice::VoiceUpstream;
use pickle_proto::{
    AuthFailure, Channel, ChannelId, ChatMessage, ClientId, DisconnectReason, ErrorCode,
    Permissions, Role, ServerControl, ServerLimits, UserInfo, VoiceState,
};
use std::collections::{BTreeMap, HashMap};
use std::time::{SystemTime, UNIX_EPOCH};
use tokio::sync::mpsc;
use tracing::warn;

/// Control frames queued for one client.
///
/// Bounded. An unbounded queue lets a client that simply stops reading commit
/// the server to unlimited memory: the writer task stalls on QUIC flow control
/// while the queue keeps growing, and one `FetchHistory` frame of a few dozen
/// bytes can queue a page of up to `MAX_HISTORY_LIMIT` messages behind it. The
/// rate limiter caps how many requests arrive, not how many bytes they commit.
pub type ControlSender = mpsc::Sender<ServerControl>;
pub type ControlReceiver = mpsc::Receiver<ServerControl>;

/// How many control frames may be queued for one client before it is dropped.
///
/// Deep enough that a burst of state changes during a busy moment is absorbed,
/// shallow enough that a client which has stopped reading is noticed quickly.
/// Byte accounting would bound this more tightly than a message count — the
/// largest single frame is a history page — but a count already replaces an
/// unbounded ceiling with a finite one.
pub const CONTROL_QUEUE_DEPTH: usize = 64;

/// The transport a client's voice datagrams go out over.
///
/// A trait rather than a bare `quinn::Connection` so state can be tested
/// without standing up a network stack.
pub trait DatagramSink: Send + Sync + 'static {
    /// Best-effort. Voice is lossy by design, so a failure here is not an error
    /// worth propagating — the frame is simply dropped.
    fn send_datagram(&self, payload: bytes::Bytes);
}

impl DatagramSink for quinn::Connection {
    fn send_datagram(&self, payload: bytes::Bytes) {
        let _ = quinn::Connection::send_datagram(self, payload);
    }
}

struct ConnectedClient {
    info: UserInfo,
    control: ControlSender,
    datagrams: Box<dyn DatagramSink>,
}

/// Queue a frame, naming the client if its queue is full.
///
/// `try_send` rather than an await: every caller holds the state read lock, and
/// blocking there would stall the voice relay for everyone on one slow client —
/// the exact thing the lock discipline in this module exists to prevent.
fn try_queue(entry: &ConnectedClient, message: ServerControl) -> Option<ClientId> {
    match entry.control.try_send(message) {
        Ok(()) => None,
        // Already gone; the session is tearing down and will be reaped there.
        Err(mpsc::error::TrySendError::Closed(_)) => None,
        Err(mpsc::error::TrySendError::Full(_)) => Some(entry.info.client_id),
    }
}

struct Inner {
    next_client_id: ClientId,
    clients: HashMap<ClientId, ConnectedClient>,
    channels: BTreeMap<ChannelId, Channel>,
    /// Monotonic; assigned when a message is accepted.
    next_message_id: u64,
}

pub struct Shared {
    pub config: ServerConfig,
    pub identity: Identity,
    pub cert_hash: [u8; 32],
    pub limits: ServerLimits,
    /// Where admitted clients are placed, if anywhere: the lowest-ordered
    /// top-level channel that carries no voice. Connecting to a server must
    /// never drop someone into a room where they can be heard, so a server
    /// whose channels all carry voice places new arrivals in no channel at
    /// all rather than in the least bad one.
    pub default_channel: Option<ChannelId>,
    /// Who holds which role. Behind its own lock rather than inside `Inner`, so
    /// resolving permissions on every administrative command does not contend
    /// with the client and channel maps that voice relay reads.
    roles: RwLock<Roles>,
    /// Parsed once from the config. `None` when unset or unparseable — an
    /// operator who mistypes their fingerprint gets a server with no owner,
    /// which is recoverable, rather than one that refuses to start.
    owner: Option<Fingerprint>,
    /// The durable store, attached after construction so `Shared::new` stays
    /// synchronous and usable in tests that need no database.
    store: RwLock<Option<Store>>,
    inner: RwLock<Inner>,
}

impl Shared {
    pub fn new(
        config: ServerConfig,
        identity: Identity,
        cert_hash: [u8; 32],
        roles: Roles,
    ) -> Self {
        let channels = build_channels(&config);
        let default_channel = channels
            .values()
            .filter(|c| c.parent.is_none() && !c.kind.has_voice())
            .min_by_key(|c| (c.order, c.id))
            .map(|c| c.id);

        let limits = ServerLimits {
            max_users: config.max_users,
            ..ServerLimits::default()
        };

        let owner = config.owner.as_deref().and_then(|raw| {
            Fingerprint::parse(raw)
                .inspect_err(|_| {
                    warn!(
                        fingerprint = raw,
                        "owner fingerprint is not readable; nobody owns this server"
                    )
                })
                .ok()
        });

        Self {
            config,
            identity,
            cert_hash,
            limits,
            default_channel,
            roles: RwLock::new(roles),
            owner,
            store: RwLock::new(None),
            inner: RwLock::new(Inner {
                next_client_id: 1,
                clients: HashMap::new(),
                channels,
                next_message_id: 1,
            }),
        }
    }

    /// What this fingerprint may do here.
    ///
    /// The single place ownership and roles are combined, so no caller can
    /// accidentally consult one without the other.
    pub fn permissions(&self, fingerprint: Fingerprint) -> Permissions {
        let owner = self.owner == Some(fingerprint);
        self.roles.read().permissions(fingerprint, owner)
    }

    /// Grant or revoke a role, persisting the result.
    ///
    /// The capability and rank checks belong to the caller; this is the store.
    pub fn assign_role(
        &self,
        fingerprint: Fingerprint,
        role: Option<&str>,
    ) -> Result<(), RoleError> {
        let mut roles = self.roles.write();
        roles.assign(fingerprint, role)?;
        roles.save()
    }

    pub fn roles(&self) -> Vec<Role> {
        self.roles.read().list().to_vec()
    }

    pub fn channels(&self) -> Vec<Channel> {
        self.inner.read().channels.values().cloned().collect()
    }

    pub fn users(&self) -> Vec<UserInfo> {
        self.inner
            .read()
            .clients
            .values()
            .map(|c| c.info.clone())
            .collect()
    }

    pub fn user_count(&self) -> usize {
        self.inner.read().clients.len()
    }

    pub fn user(&self, client: ClientId) -> Option<UserInfo> {
        self.inner
            .read()
            .clients
            .get(&client)
            .map(|c| c.info.clone())
    }

    /// Admit an authenticated client and place it in the default channel.
    ///
    /// The caller must have verified the signature already; this checks only
    /// capacity and the identity's proof-of-work level.
    pub fn admit(
        &self,
        identity: PublicIdentity,
        nickname: String,
        control: ControlSender,
        datagrams: Box<dyn DatagramSink>,
    ) -> Result<UserInfo, AuthFailure> {
        let level = identity.security_level();
        if level < self.config.min_security_level {
            return Err(AuthFailure::SecurityLevelTooLow {
                required: self.config.min_security_level,
                provided: level,
            });
        }

        let nickname = sanitize_nickname(&nickname, self.limits.max_nickname_len as usize)
            .ok_or_else(|| AuthFailure::NicknameRejected {
                reason: "nickname must contain at least one printable character".into(),
            })?;

        // Resolved before taking the client lock, since it takes the role lock
        // and holding both at once invites an ordering bug later.
        let permissions = self.permissions(identity.fingerprint());

        let mut inner = self.inner.write();
        if inner.clients.len() >= self.config.max_users as usize {
            return Err(AuthFailure::ServerFull);
        }

        let client_id = inner.next_client_id;
        inner.next_client_id = inner.next_client_id.wrapping_add(1).max(1);

        let info = UserInfo {
            client_id,
            identity,
            nickname,
            channel: self.default_channel,
            voice: VoiceState::default(),
            connected_at_unix_ms: now_unix_ms(),
            permissions,
        };

        inner.clients.insert(
            client_id,
            ConnectedClient {
                info: info.clone(),
                control,
                datagrams,
            },
        );

        Ok(info)
    }

    pub fn remove(&self, client: ClientId) -> Option<UserInfo> {
        self.inner.write().clients.remove(&client).map(|c| c.info)
    }

    /// Move a client into `channel`, returning the channel it left.
    pub fn join_channel(
        &self,
        client: ClientId,
        channel: ChannelId,
    ) -> Result<Option<ChannelId>, ErrorCode> {
        let mut inner = self.inner.write();

        let max_users = inner
            .channels
            .get(&channel)
            .ok_or(ErrorCode::NoSuchChannel)?
            .max_users;
        if let Some(max) = max_users {
            let occupants = inner
                .clients
                .values()
                .filter(|c| c.info.channel == Some(channel) && c.info.client_id != client)
                .count();
            if occupants >= max as usize {
                return Err(ErrorCode::ChannelFull);
            }
        }

        let entry = inner
            .clients
            .get_mut(&client)
            .ok_or(ErrorCode::NotAuthenticated)?;
        let previous = entry.info.channel;
        entry.info.channel = Some(channel);
        Ok(previous)
    }

    pub fn leave_channel(&self, client: ClientId) -> Option<ChannelId> {
        let mut inner = self.inner.write();
        let entry = inner.clients.get_mut(&client)?;
        entry.info.channel.take()
    }

    pub fn channel(&self, channel: ChannelId) -> Option<Channel> {
        self.inner.read().channels.get(&channel).cloned()
    }

    pub fn set_voice_state(
        &self,
        client: ClientId,
        self_muted: bool,
        self_deafened: bool,
    ) -> Option<UserInfo> {
        let mut inner = self.inner.write();
        let entry = inner.clients.get_mut(&client)?;
        entry.info.voice.self_muted = self_muted;
        // Deafening implies muting: a client that cannot hear the channel
        // should not be transmitting into it either.
        entry.info.voice.self_deafened = self_deafened;
        if self_deafened {
            entry.info.voice.self_muted = true;
        }
        Some(entry.info.clone())
    }

    pub fn set_nickname(&self, client: ClientId, nickname: &str) -> Option<UserInfo> {
        let cleaned = sanitize_nickname(nickname, self.limits.max_nickname_len as usize)?;
        let mut inner = self.inner.write();
        let entry = inner.clients.get_mut(&client)?;
        entry.info.nickname = cleaned;
        Some(entry.info.clone())
    }

    pub fn next_message_id(&self) -> u64 {
        let mut inner = self.inner.write();
        let id = inner.next_message_id;
        inner.next_message_id += 1;
        id
    }

    /// Continue numbering after the highest id already on disk.
    ///
    /// The counter starts at 1 on every boot, which was harmless while nothing
    /// was stored. Against a database it would hand out ids that collide with
    /// existing rows on the first restart, so startup seeds it from what the
    /// store already holds.
    pub fn resume_message_ids_after(&self, highest: u64) {
        let mut inner = self.inner.write();
        inner.next_message_id = inner.next_message_id.max(highest + 1);
    }

    /// Attach the durable store.
    ///
    /// Held here for reach, but deliberately never used *inside* a state lock:
    /// the store is async, and awaiting while holding this lock would stall the
    /// voice relay for everyone.
    pub fn attach_store(&self, store: Store) {
        *self.store.write() = Some(store);
    }

    pub fn store(&self) -> Option<Store> {
        self.store.read().clone()
    }

    /// Whether this server keeps history, as reported to clients.
    pub fn history_enabled(&self) -> bool {
        self.config.history_enabled && self.store().is_some()
    }

    /// Queue a control frame for one client.
    pub fn send(&self, client: ClientId, message: ServerControl) {
        let overflowed = {
            let inner = self.inner.read();
            match inner.clients.get(&client) {
                Some(entry) => try_queue(entry, message),
                None => None,
            }
        };
        self.drop_overflowed(overflowed.into_iter());
    }

    /// Queue a control frame for everyone, optionally skipping one client.
    pub fn broadcast(&self, message: ServerControl, except: Option<ClientId>) {
        let overflowed: Vec<ClientId> = {
            let inner = self.inner.read();
            inner
                .clients
                .iter()
                .filter(|(id, _)| Some(**id) != except)
                .filter_map(|(_, entry)| try_queue(entry, message.clone()))
                .collect()
        };
        self.drop_overflowed(overflowed.into_iter());
    }

    /// Queue a control frame for everyone currently in `channel`.
    pub fn broadcast_to_channel(
        &self,
        channel: ChannelId,
        message: ServerControl,
        except: Option<ClientId>,
    ) {
        let overflowed: Vec<ClientId> = {
            let inner = self.inner.read();
            inner
                .clients
                .iter()
                .filter(|(id, entry)| Some(**id) != except && entry.info.channel == Some(channel))
                .filter_map(|(_, entry)| try_queue(entry, message.clone()))
                .collect()
        };
        self.drop_overflowed(overflowed.into_iter());
    }

    /// Disconnect clients whose queue filled up.
    ///
    /// Their control stream has gaps by definition, so continuing would leave
    /// them acting on a view of the server that no longer matches it. Dropping
    /// the entry drops its sender, which ends the session's writer task and
    /// tears the connection down through the ordinary path.
    ///
    /// Called only after the state lock is released: removing needs the write
    /// lock, and taking it while the read guard is alive would deadlock.
    fn drop_overflowed(&self, ids: impl Iterator<Item = ClientId>) {
        for id in ids {
            if self.remove(id).is_some() {
                warn!(
                    client_id = id,
                    "dropping a client that stopped reading its control stream"
                );
                // Best effort, and deliberately not recursive: anyone who
                // overflows on *this* frame is caught by the next one instead
                // of nesting a disconnect inside a disconnect.
                let inner = self.inner.read();
                for entry in inner.clients.values() {
                    let _ = entry.control.try_send(ServerControl::UserLeft {
                        client: id,
                        reason: DisconnectReason::Kicked,
                    });
                }
            }
        }
    }

    /// Forward one voice frame to the rest of the sender's channel.
    ///
    /// The server relays rather than mixes. Mixing would cost CPU proportional
    /// to the number of listeners and would flatten every stream into one,
    /// which costs per-speaker volume control and positional audio later on.
    /// Relaying keeps the server cheap and the client in charge.
    pub fn relay_voice(&self, from: ClientId, packet: VoiceUpstream) {
        let inner = self.inner.read();

        let Some(sender) = inner.clients.get(&from) else {
            return;
        };

        // Mute is enforced here, not just in the sender's UI. Otherwise a
        // modified client could show itself as muted while still transmitting.
        if sender.info.voice.self_muted || sender.info.voice.server_muted {
            return;
        }

        let Some(channel) = sender.info.channel else {
            return;
        };
        // Routing uses the server's view of the sender's channel, never a
        // channel id supplied by the client.
        if !inner
            .channels
            .get(&channel)
            .map(|c| c.kind.has_voice())
            .unwrap_or(false)
        {
            return;
        }

        let datagram = packet.into_downstream(from).encode();
        for (id, entry) in inner.clients.iter() {
            if *id == from || entry.info.channel != Some(channel) || entry.info.voice.self_deafened
            {
                continue;
            }
            // Cloning `Bytes` bumps a refcount; the audio is not copied.
            entry.datagrams.send_datagram(datagram.clone());
        }
    }

    /// Build a chat message with server-assigned id and timestamp.
    pub fn build_message(
        &self,
        author: &UserInfo,
        channel: ChannelId,
        content: String,
        reply_to: Option<u64>,
    ) -> ChatMessage {
        ChatMessage {
            id: self.next_message_id(),
            channel,
            author: Some(author.client_id),
            author_fingerprint: author.identity.fingerprint(),
            author_nickname: author.nickname.clone(),
            sent_at_unix_ms: now_unix_ms(),
            edited_at_unix_ms: None,
            content,
            reply_to,
            attachments: Vec::new(),
            reactions: Vec::new(),
        }
    }

    pub fn disconnect_all(&self, reason: DisconnectReason) {
        let inner = self.inner.read();
        for (id, entry) in inner.clients.iter() {
            // `try_send`, not `send`: the queue is bounded now, so `send` is a
            // future and discarding it would deliver nothing at all. Shutdown
            // is also the one moment a full queue does not matter — the
            // connection is closing regardless.
            let _ = entry.control.try_send(ServerControl::UserLeft {
                client: *id,
                reason,
            });
        }
    }

    /// Whether this fingerprint is already connected. Pickle allows it — the
    /// same person may legitimately be on a phone and a desktop.
    pub fn sessions_for(&self, fingerprint: Fingerprint) -> usize {
        self.inner
            .read()
            .clients
            .values()
            .filter(|c| c.info.identity.fingerprint() == fingerprint)
            .count()
    }
}

fn build_channels(config: &ServerConfig) -> BTreeMap<ChannelId, Channel> {
    let ids: HashMap<&str, ChannelId> = config
        .channels
        .iter()
        .enumerate()
        .map(|(i, c)| (c.name.as_str(), i as ChannelId + 1))
        .collect();

    config
        .channels
        .iter()
        .enumerate()
        .map(|(i, c)| {
            let id = i as ChannelId + 1;
            let channel = Channel {
                id,
                parent: c.parent.as_deref().and_then(|p| ids.get(p).copied()),
                name: c.name.clone(),
                topic: c.topic.clone(),
                kind: c.kind,
                max_users: c.max_users,
                password_protected: false,
                order: c.order,
            };
            (id, channel)
        })
        .collect()
}

/// Trim, collapse control characters, and enforce a length cap.
///
/// Returns `None` when nothing printable survives — an all-whitespace or
/// all-control nickname would render as an invisible user.
fn sanitize_nickname(raw: &str, max_len: usize) -> Option<String> {
    let cleaned: String = raw
        .chars()
        .filter(|c| !c.is_control())
        .collect::<String>()
        .trim()
        .chars()
        .take(max_len)
        .collect();

    if cleaned.is_empty() {
        None
    } else {
        Some(cleaned)
    }
}

fn now_unix_ms() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_millis() as u64)
        .unwrap_or(0)
}

#[cfg(test)]
mod tests {
    use super::*;
    use bytes::Bytes;
    use parking_lot::Mutex;
    use pickle_proto::ChannelKind;
    use std::sync::Arc;

    /// Records what would have gone out on the wire.
    #[derive(Clone, Default)]
    struct RecordingSink(Arc<Mutex<Vec<Bytes>>>);

    impl DatagramSink for RecordingSink {
        fn send_datagram(&self, payload: Bytes) {
            self.0.lock().push(payload);
        }
    }

    /// A role store backed by a path that does not exist, so it starts from the
    /// default ladder and never writes. Tests that need persistence open their
    /// own store against a `tempdir`.
    fn test_roles() -> Roles {
        Roles::open(std::path::Path::new("/nonexistent/pickle-test/roles.json")).unwrap()
    }

    fn test_config() -> ServerConfig {
        ServerConfig {
            min_security_level: 0,
            ..ServerConfig::default()
        }
    }

    struct TestClient {
        info: UserInfo,
        control: ControlReceiver,
        sink: RecordingSink,
    }

    fn join(shared: &Shared, nickname: &str) -> TestClient {
        let (tx, control) = mpsc::channel(CONTROL_QUEUE_DEPTH);
        let sink = RecordingSink::default();
        let info = shared
            .admit(
                Identity::generate().public(),
                nickname.into(),
                tx,
                Box::new(sink.clone()),
            )
            .expect("admission should succeed");
        TestClient {
            info,
            control,
            sink,
        }
    }

    fn shared() -> Shared {
        Shared::new(test_config(), Identity::generate(), [0u8; 32], test_roles())
    }

    fn voice_frame(seq: u32) -> VoiceUpstream {
        VoiceUpstream {
            seq,
            flags: 0,
            payload: Bytes::from_static(&[1, 2, 3]),
        }
    }

    /// Join and then move into "General" (channel 3), the default config's
    /// voice channel. The relay tests need occupants somewhere audible, and
    /// admission deliberately lands nobody there.
    fn join_voice(shared: &Shared, nickname: &str) -> TestClient {
        let client = join(shared, nickname);
        shared.join_channel(client.info.client_id, 3).unwrap();
        client
    }

    #[test]
    fn admitted_clients_land_in_the_default_channel() {
        let shared = shared();
        let alice = join(&shared, "alice");
        assert_eq!(alice.info.channel, shared.default_channel);
        assert_eq!(shared.user_count(), 1);
    }

    #[test]
    fn admission_never_places_anyone_where_they_can_be_heard() {
        let shared = shared();
        let alice = join(&shared, "alice");
        let landed = shared
            .channel(alice.info.channel.expect("the default config has a lobby"))
            .unwrap();
        assert!(
            !landed.kind.has_voice(),
            "connecting must not walk anyone into a live microphone"
        );
    }

    #[test]
    fn a_server_with_only_voice_channels_places_arrivals_nowhere() {
        // Every channel carries voice, so there is nowhere safe to land — and
        // "nowhere" is the right answer, not the least bad voice room.
        let mut config = test_config();
        for channel in &mut config.channels {
            channel.kind = ChannelKind::VoiceAndText;
        }
        let shared = Shared::new(config, Identity::generate(), [0u8; 32], test_roles());
        assert_eq!(shared.default_channel, None);

        let alice = join(&shared, "alice");
        assert_eq!(alice.info.channel, None);

        // Being nowhere is not being voiceless-forever: an explicit join works.
        shared.join_channel(alice.info.client_id, 2).unwrap();
    }

    #[test]
    fn client_ids_are_unique() {
        let shared = shared();
        let a = join(&shared, "alice");
        let b = join(&shared, "bob");
        assert_ne!(a.info.client_id, b.info.client_id);
    }

    #[test]
    fn an_identity_below_the_minimum_level_is_refused() {
        let mut config = test_config();
        config.min_security_level = 200; // unreachable
        let shared = Shared::new(config, Identity::generate(), [0u8; 32], test_roles());

        let (tx, _rx) = mpsc::channel(CONTROL_QUEUE_DEPTH);
        let result = shared.admit(
            Identity::generate().public(),
            "alice".into(),
            tx,
            Box::new(RecordingSink::default()),
        );
        assert!(matches!(
            result,
            Err(AuthFailure::SecurityLevelTooLow { required: 200, .. })
        ));
    }

    #[test]
    fn the_server_stops_admitting_at_capacity() {
        let mut config = test_config();
        config.max_users = 1;
        let shared = Shared::new(config, Identity::generate(), [0u8; 32], test_roles());

        join(&shared, "alice");
        let (tx, _rx) = mpsc::channel(CONTROL_QUEUE_DEPTH);
        assert!(matches!(
            shared.admit(
                Identity::generate().public(),
                "bob".into(),
                tx,
                Box::new(RecordingSink::default())
            ),
            Err(AuthFailure::ServerFull)
        ));
    }

    #[test]
    fn nicknames_are_stripped_of_control_characters() {
        let shared = shared();
        let (tx, _rx) = mpsc::channel(CONTROL_QUEUE_DEPTH);
        let info = shared
            .admit(
                Identity::generate().public(),
                "  al\u{7}ice\n  ".into(),
                tx,
                Box::new(RecordingSink::default()),
            )
            .unwrap();
        assert_eq!(info.nickname, "alice");
    }

    #[test]
    fn a_blank_nickname_is_refused() {
        let shared = shared();
        let (tx, _rx) = mpsc::channel(CONTROL_QUEUE_DEPTH);
        assert!(matches!(
            shared.admit(
                Identity::generate().public(),
                "   \n\t ".into(),
                tx,
                Box::new(RecordingSink::default())
            ),
            Err(AuthFailure::NicknameRejected { .. })
        ));
    }

    #[test]
    fn voice_reaches_others_in_the_same_channel() {
        let shared = shared();
        let alice = join_voice(&shared, "alice");
        let bob = join_voice(&shared, "bob");

        shared.relay_voice(alice.info.client_id, voice_frame(1));

        assert_eq!(bob.sink.0.lock().len(), 1);
        assert!(
            alice.sink.0.lock().is_empty(),
            "sender must not hear itself"
        );
    }

    #[test]
    fn voice_does_not_cross_channels() {
        let shared = shared();
        // Alice speaks from "General"; bob sits in "AFK" (channel 4).
        let alice = join_voice(&shared, "alice");
        let bob = join(&shared, "bob");
        shared.join_channel(bob.info.client_id, 4).unwrap();

        shared.relay_voice(alice.info.client_id, voice_frame(1));
        assert!(bob.sink.0.lock().is_empty());
    }

    #[test]
    fn a_muted_client_cannot_transmit() {
        // Enforced server-side, so a patched client gains nothing by lying.
        let shared = shared();
        let alice = join_voice(&shared, "alice");
        let bob = join_voice(&shared, "bob");

        shared.set_voice_state(alice.info.client_id, true, false);
        shared.relay_voice(alice.info.client_id, voice_frame(1));

        assert!(bob.sink.0.lock().is_empty());
    }

    #[test]
    fn a_deafened_client_receives_nothing() {
        let shared = shared();
        let alice = join_voice(&shared, "alice");
        let bob = join_voice(&shared, "bob");

        shared.set_voice_state(bob.info.client_id, false, true);
        shared.relay_voice(alice.info.client_id, voice_frame(1));

        assert!(bob.sink.0.lock().is_empty());
    }

    #[test]
    fn deafening_also_mutes() {
        let shared = shared();
        let alice = join(&shared, "alice");
        let updated = shared
            .set_voice_state(alice.info.client_id, false, true)
            .unwrap();
        assert!(updated.voice.self_muted, "deafened implies muted");
    }

    #[test]
    fn voice_is_dropped_in_a_text_only_channel() {
        // Admission lands both in the text-only Lobby, which is exactly the
        // situation this guards: a client transmitting from a text channel —
        // deliberately or through a bug — must reach nobody.
        let shared = shared();
        let alice = join(&shared, "alice");
        let bob = join(&shared, "bob");
        shared.relay_voice(alice.info.client_id, voice_frame(1));

        assert!(bob.sink.0.lock().is_empty());
    }

    #[test]
    fn leaving_a_channel_stops_voice_reaching_anyone() {
        let shared = shared();
        let alice = join_voice(&shared, "alice");
        let bob = join_voice(&shared, "bob");

        let from = shared.leave_channel(alice.info.client_id);
        assert_eq!(from, Some(3), "leaving reports where the user was");

        shared.relay_voice(alice.info.client_id, voice_frame(1));
        assert!(
            bob.sink.0.lock().is_empty(),
            "a client in no channel must reach nobody"
        );
    }

    #[test]
    fn voice_from_an_unknown_client_is_ignored() {
        let shared = shared();
        let bob = join(&shared, "bob");
        shared.relay_voice(9999, voice_frame(1));
        assert!(bob.sink.0.lock().is_empty());
    }

    #[test]
    fn the_relayed_frame_is_attributed_to_its_sender() {
        use pickle_proto::voice::VoiceDownstream;
        let shared = shared();
        let alice = join_voice(&shared, "alice");
        let bob = join_voice(&shared, "bob");

        shared.relay_voice(alice.info.client_id, voice_frame(77));

        let sent = bob.sink.0.lock()[0].clone();
        let decoded = VoiceDownstream::decode(sent).unwrap();
        assert_eq!(decoded.sender, alice.info.client_id);
        assert_eq!(decoded.seq, 77);
    }

    #[test]
    fn broadcast_can_skip_the_originator() {
        let shared = shared();
        let alice = join(&shared, "alice");
        let mut bob = join(&shared, "bob");

        shared.broadcast(ServerControl::Pong { nonce: 5 }, Some(alice.info.client_id));

        assert!(bob.control.try_recv().is_ok());
        let mut alice = alice;
        assert!(alice.control.try_recv().is_err());
    }

    #[test]
    fn channel_broadcast_respects_membership() {
        let shared = shared();
        let alice = join(&shared, "alice");
        let mut bob = join(&shared, "bob");
        shared.join_channel(bob.info.client_id, 2).unwrap();

        shared.broadcast_to_channel(
            shared.default_channel.unwrap(),
            ServerControl::Pong { nonce: 1 },
            None,
        );

        let mut alice = alice;
        assert!(alice.control.try_recv().is_ok());
        assert!(bob.control.try_recv().is_err());
    }

    #[test]
    fn joining_reports_the_previous_channel() {
        let shared = shared();
        let alice = join(&shared, "alice");
        let previous = shared.join_channel(alice.info.client_id, 2).unwrap();
        assert_eq!(previous, shared.default_channel);
    }

    #[test]
    fn joining_a_missing_channel_fails() {
        let shared = shared();
        let alice = join(&shared, "alice");
        assert_eq!(
            shared.join_channel(alice.info.client_id, 999),
            Err(ErrorCode::NoSuchChannel)
        );
    }

    #[test]
    fn a_full_channel_refuses_new_arrivals() {
        let mut config = test_config();
        config.channels[1].max_users = Some(1);
        let shared = Shared::new(config, Identity::generate(), [0u8; 32], test_roles());

        let alice = join(&shared, "alice");
        let bob = join(&shared, "bob");
        shared.join_channel(alice.info.client_id, 2).unwrap();

        assert_eq!(
            shared.join_channel(bob.info.client_id, 2),
            Err(ErrorCode::ChannelFull)
        );
    }

    #[test]
    fn rejoining_a_full_channel_you_are_already_in_is_allowed() {
        // The occupant count must exclude the joiner, or a re-join would fail.
        let mut config = test_config();
        config.channels[1].max_users = Some(1);
        let shared = Shared::new(config, Identity::generate(), [0u8; 32], test_roles());

        let alice = join(&shared, "alice");
        shared.join_channel(alice.info.client_id, 2).unwrap();
        assert!(shared.join_channel(alice.info.client_id, 2).is_ok());
    }

    #[test]
    fn removing_a_client_frees_its_slot() {
        let shared = shared();
        let alice = join(&shared, "alice");
        assert!(shared.remove(alice.info.client_id).is_some());
        assert_eq!(shared.user_count(), 0);
        assert!(shared.remove(alice.info.client_id).is_none());
    }

    #[test]
    fn channels_are_built_with_parents_resolved() {
        let mut config = test_config();
        config.channels.push(crate::config::ChannelConfig {
            name: "Sub".into(),
            topic: String::new(),
            kind: ChannelKind::Voice,
            parent: Some("Lobby".into()),
            max_users: None,
            order: 0,
        });
        let shared = Shared::new(config, Identity::generate(), [0u8; 32], test_roles());

        let channels = shared.channels();
        let lobby = channels.iter().find(|c| c.name == "Lobby").unwrap();
        let sub = channels.iter().find(|c| c.name == "Sub").unwrap();
        assert_eq!(sub.parent, Some(lobby.id));
        assert_eq!(lobby.parent, None);
    }

    #[test]
    fn the_default_channel_is_the_lowest_ordered_voiceless_one() {
        let shared = shared();
        let lobby = shared.channel(shared.default_channel.unwrap()).unwrap();
        assert_eq!(lobby.name, "Lobby");
        assert!(!lobby.kind.has_voice());
    }

    #[test]
    fn message_ids_increase() {
        let shared = shared();
        let alice = join(&shared, "alice");
        let first = shared.build_message(&alice.info, 1, "hi".into(), None);
        let second = shared.build_message(&alice.info, 1, "again".into(), None);
        assert!(second.id > first.id);
        assert_eq!(first.author_fingerprint, alice.info.identity.fingerprint());
    }

    #[test]
    fn the_same_identity_may_hold_several_sessions() {
        let shared = shared();
        let identity = Identity::generate().public();
        for _ in 0..2 {
            let (tx, _rx) = mpsc::channel(CONTROL_QUEUE_DEPTH);
            shared
                .admit(
                    identity,
                    "andy".into(),
                    tx,
                    Box::new(RecordingSink::default()),
                )
                .unwrap();
        }
        assert_eq!(shared.sessions_for(identity.fingerprint()), 2);
    }
}
