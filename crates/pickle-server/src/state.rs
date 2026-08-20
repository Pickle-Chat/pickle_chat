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
use crate::store::Store;
use parking_lot::RwLock;
use pickle_identity::{Fingerprint, Identity, PublicIdentity};
use pickle_proto::voice::VoiceUpstream;
use pickle_proto::{
    resolve, AuthFailure, Channel, ChannelId, ChatMessage, ClientId, DisconnectReason, ErrorCode,
    Overwrite, Permissions, Role, RoleId, ServerControl, ServerLimits, UserInfo, VoiceState,
};
use std::collections::{BTreeMap, HashMap};
use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};
use tokio::sync::mpsc;
use tracing::{info, warn};

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

    /// Authoritatively close the transport. A kick must not depend on the
    /// kicked client cooperating with a FIN. Default no-op so test sinks and
    /// any transport without a close need nothing.
    fn close(&self, _code: u32, _reason: &[u8]) {}
}

impl DatagramSink for quinn::Connection {
    fn send_datagram(&self, payload: bytes::Bytes) {
        let _ = quinn::Connection::send_datagram(self, payload);
    }

    fn close(&self, code: u32, reason: &[u8]) {
        quinn::Connection::close(self, code.into(), reason);
    }
}

pub struct ConnectedClient {
    info: UserInfo,
    control: ControlSender,
    datagrams: Box<dyn DatagramSink>,
}

impl ConnectedClient {
    /// Close the underlying transport with an application code and reason.
    /// Only meaningful on an entry already removed from the roster.
    pub fn close_transport(&self, code: u32, reason: &[u8]) {
        self.datagrams.close(code, reason);
    }
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

/// The permission inputs, as one immutable snapshot.
///
/// Readers clone the `Arc` under a brief lock and resolve lock-free on the
/// snapshot; writers (the admin handlers, from PR 4 on) build a new state and
/// swap the `Arc` — after the database write, never before, so what clients
/// are told always survives a restart. The perms lock is never held across an
/// await and never while `inner` is being acquired.
pub struct PermState {
    /// Every role, @everyone included, ordered by position.
    pub roles: Vec<Role>,
    /// Explicit grants by fingerprint; @everyone is implicit.
    pub members: HashMap<Fingerprint, Vec<RoleId>>,
}

impl PermState {
    /// The ladder a fresh server starts with. Also what the seeder writes.
    pub fn defaults() -> Self {
        Self {
            roles: default_roles(),
            members: HashMap::new(),
        }
    }
}

/// The default ladder: @everyone with today's open behavior, a moderator
/// rung, an admin rung. Mirrors the deleted roles.json ladder in spirit —
/// admin over moderator — with positions dense because reordering now
/// renumbers server-side.
pub fn default_roles() -> Vec<Role> {
    vec![
        Role {
            id: pickle_proto::EVERYONE_ROLE_ID,
            name: "everyone".into(),
            color: None,
            position: 0,
            permissions: Permissions::DEFAULT_EVERYONE,
        },
        Role {
            id: 1,
            name: "moderator".into(),
            color: None,
            position: 1,
            permissions: Permissions::KICK_MEMBERS
                .union(Permissions::BAN_MEMBERS)
                .union(Permissions::MUTE_MEMBERS)
                .union(Permissions::MOVE_MEMBERS)
                .union(Permissions::MANAGE_MESSAGES),
        },
        Role {
            id: 2,
            name: "admin".into(),
            color: None,
            position: 2,
            permissions: Permissions::ADMINISTRATOR,
        },
    ]
}

pub struct Shared {
    pub config: ServerConfig,
    pub identity: Identity,
    pub cert_hash: [u8; 32],
    pub limits: ServerLimits,
    /// The permission inputs. Behind its own lock rather than inside `Inner`
    /// so resolution never contends with the client and channel maps the
    /// voice relay reads; behind an `Arc` so readers snapshot and get out.
    perms: RwLock<Arc<PermState>>,
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
    /// `channels` and `perms` come from the database (seeded from the config
    /// on first boot) — loaded by the caller, because construction stays
    /// synchronous and usable in tests that need no database.
    pub fn new(
        config: ServerConfig,
        identity: Identity,
        cert_hash: [u8; 32],
        channels: Vec<Channel>,
        perms: PermState,
    ) -> Self {
        let channels: BTreeMap<ChannelId, Channel> =
            channels.into_iter().map(|c| (c.id, c)).collect();

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

        // Whether a server has an owner is the one thing an operator cannot
        // work out from the outside. A `PICKLE_OWNER` that never reached the
        // process and one that arrived correctly both start silently, and the
        // existing warning above only fires on a value that is present but
        // malformed. So say which it is, every time, and name the fingerprint
        // so it can be checked against the one the client shows.
        let grants = perms.members.len();
        match &owner {
            Some(fingerprint) => info!(%fingerprint, grants, "owner configured"),
            // Not fatal — roles can carry every permission — but ownership is
            // deliberately config-only precisely so a damaged or emptied role
            // table cannot lock an operator out, and a server relying only on
            // grants has given up that safeguard.
            None if grants > 0 => warn!(
                grants,
                "no owner configured; administration depends entirely on role grants"
            ),
            None => warn!(
                "no owner and no role grants: nobody can administer this server. \
                 Set PICKLE_OWNER to the fingerprint your client shows."
            ),
        }

        Self {
            config,
            identity,
            cert_hash,
            limits,
            perms: RwLock::new(Arc::new(perms)),
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

    /// The current permission inputs, as a lock-free snapshot.
    ///
    /// Lock order everywhere: this snapshot is taken **before** `inner` is
    /// acquired, never while holding it, so the two locks can never deadlock
    /// and resolution never extends `inner`'s critical sections.
    pub fn perm_state(&self) -> Arc<PermState> {
        self.perms.read().clone()
    }

    pub fn is_owner(&self, fingerprint: Fingerprint) -> bool {
        self.owner == Some(fingerprint)
    }

    /// The explicit role grants for a fingerprint. @everyone is implicit.
    pub fn member_roles(&self, fingerprint: Fingerprint) -> Vec<RoleId> {
        self.perms
            .read()
            .members
            .get(&fingerprint)
            .cloned()
            .unwrap_or_default()
    }

    /// What `client` may do in `channel` right now. The everyday enforcement
    /// entry point for the handlers that run outside the state locks.
    pub fn can(&self, client: ClientId, channel: ChannelId, bits: Permissions) -> bool {
        let snapshot = self.perm_state();
        let inner = self.inner.read();
        let Some(entry) = inner.clients.get(&client) else {
            return false;
        };
        let Some(target) = inner.channels.get(&channel) else {
            return false;
        };
        resolve(
            &snapshot.roles,
            &entry.info.roles,
            entry.info.fingerprint(),
            entry.info.owner,
            Some(&target.overwrites),
        )
        .contains(bits)
    }

    /// The channels this member may view — what AuthOk sends, and the shape
    /// the visibility resync keeps true afterwards.
    pub fn visible_channels(&self, member: &UserInfo) -> Vec<Channel> {
        let snapshot = self.perm_state();
        self.inner
            .read()
            .channels
            .values()
            .filter(|c| {
                resolve(
                    &snapshot.roles,
                    &member.roles,
                    member.fingerprint(),
                    member.owner,
                    Some(&c.overwrites),
                )
                .contains(Permissions::VIEW_CHANNEL)
            })
            .cloned()
            .collect()
    }

    /// The channel this member should read first: the lowest-ordered
    /// top-level text channel they can view. A suggestion, not a placement.
    pub fn default_channel_for(&self, member: &UserInfo) -> Option<ChannelId> {
        self.visible_channels(member)
            .into_iter()
            .filter(|c| c.parent.is_none() && c.kind.has_text())
            .min_by_key(|c| (c.order, c.id))
            .map(|c| c.id)
    }

    /// Every role, ordered by position — what AuthOk sends.
    pub fn roles_snapshot(&self) -> Vec<Role> {
        self.perms.read().roles.clone()
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

        // Read before taking the client lock — the perms lock is always
        // acquired first or not at all, never while `inner` is held.
        let fingerprint = identity.fingerprint();
        let roles = self.member_roles(fingerprint);
        let owner = self.is_owner(fingerprint);

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
            channel: None,
            voice: VoiceState::default(),
            connected_at_unix_ms: now_unix_ms(),
            roles,
            owner,
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
        // Snapshot before `inner`, as everywhere: the perms lock is never
        // acquired while `inner` is held, so the two can never deadlock.
        let snapshot = self.perm_state();
        let mut inner = self.inner.write();

        let target = inner
            .channels
            .get(&channel)
            .ok_or(ErrorCode::NoSuchChannel)?;
        let me = inner
            .clients
            .get(&client)
            .ok_or(ErrorCode::NotAuthenticated)?;
        let bits = resolve(
            &snapshot.roles,
            &me.info.roles,
            me.info.fingerprint(),
            me.info.owner,
            Some(&target.overwrites),
        );
        // A channel you may not view answers exactly as one that does not
        // exist: NotPermitted here would confirm there is something to see.
        if !bits.contains(Permissions::VIEW_CHANNEL) {
            return Err(ErrorCode::NoSuchChannel);
        }
        // Being "in" a channel means being in its voice room. A text channel
        // has no room to stand in — everyone can already read and write it —
        // so joining one is refused rather than recorded as meaningless state.
        if !target.kind.has_voice() {
            return Err(ErrorCode::NotPermitted);
        }
        if !bits.contains(Permissions::CONNECT) {
            return Err(ErrorCode::NotPermitted);
        }
        let max_users = target.max_users;
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
    /// Queue a frame for every client holding `VIEW_CHANNEL` on `channel`.
    ///
    /// The channel-scoped fan-out. With @everyone's default bits every client
    /// passes, so a fresh server behaves exactly like the open-text model
    /// this replaces — openness becomes the default rather than the rule.
    pub fn broadcast_filtered(
        &self,
        message: ServerControl,
        channel: ChannelId,
        except: Option<ClientId>,
    ) {
        let snapshot = self.perm_state();
        let overflowed: Vec<ClientId> = {
            let inner = self.inner.read();
            let Some(target) = inner.channels.get(&channel) else {
                return;
            };
            inner
                .clients
                .iter()
                .filter(|(id, _)| Some(**id) != except)
                .filter(|(_, entry)| {
                    resolve(
                        &snapshot.roles,
                        &entry.info.roles,
                        entry.info.fingerprint(),
                        entry.info.owner,
                        Some(&target.overwrites),
                    )
                    .contains(Permissions::VIEW_CHANNEL)
                })
                .filter_map(|(_, entry)| try_queue(entry, message.clone()))
                .collect()
        };
        self.drop_overflowed(overflowed.into_iter());
    }

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
        // Snapshot before `inner`, as everywhere. Per voice frame this is one
        // uncontended read-lock clone of an Arc — nanoseconds against a 20 ms
        // frame budget.
        let snapshot = self.perm_state();
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
        let Some(room) = inner.channels.get(&channel) else {
            return;
        };
        if !room.kind.has_voice() {
            return;
        }
        // SPEAK is enforced at the relay, not at the door: entering without
        // it is allowed (listen-only), and revoking it mid-hold takes effect
        // on the next frame.
        if !resolve(
            &snapshot.roles,
            &sender.info.roles,
            sender.info.fingerprint(),
            sender.info.owner,
            Some(&room.overwrites),
        )
        .contains(Permissions::SPEAK)
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
    /// What `client` may do server-wide (no channel context).
    pub fn can_globally(&self, client: ClientId, bits: Permissions) -> bool {
        let snapshot = self.perm_state();
        let inner = self.inner.read();
        let Some(entry) = inner.clients.get(&client) else {
            return false;
        };
        resolve(
            &snapshot.roles,
            &entry.info.roles,
            entry.info.fingerprint(),
            entry.info.owner,
            None,
        )
        .contains(bits)
    }

    /// May the online actor act on this fingerprint — kick, ban, mute, move?
    ///
    /// Works for offline targets too: their grants come from the engine, and
    /// the owner fingerprint is config, not presence. Rank alone; the bit is
    /// the caller's check.
    pub fn actor_outranks(&self, actor: ClientId, target: Fingerprint) -> bool {
        let snapshot = self.perm_state();
        let target_roles = snapshot.members.get(&target).cloned().unwrap_or_default();
        let target_owner = self.is_owner(target);
        let inner = self.inner.read();
        let Some(entry) = inner.clients.get(&actor) else {
            return false;
        };
        pickle_proto::can_act_on(
            &snapshot.roles,
            &entry.info.roles,
            entry.info.owner,
            &target_roles,
            target_owner,
        )
    }

    /// The fingerprint behind a live client id, if it is still connected.
    pub fn fingerprint_of(&self, client: ClientId) -> Option<Fingerprint> {
        self.inner
            .read()
            .clients
            .get(&client)
            .map(|c| c.info.fingerprint())
    }

    /// Swap the permission inputs for a new snapshot. Writers call this
    /// after the database write succeeds — stored before announced — and
    /// then broadcast whatever the mutation implies.
    pub fn swap_perm_state(&self, next: PermState) {
        *self.perms.write() = Arc::new(next);
    }

    /// Each connected client's currently-visible channel set. Captured before
    /// a permission mutation; diffed after, to drive the resync events.
    pub fn visible_ids_by_client(&self) -> Vec<(ClientId, std::collections::HashSet<ChannelId>)> {
        let snapshot = self.perm_state();
        let inner = self.inner.read();
        inner
            .clients
            .values()
            .map(|entry| {
                let visible = inner
                    .channels
                    .values()
                    .filter(|c| {
                        resolve(
                            &snapshot.roles,
                            &entry.info.roles,
                            entry.info.fingerprint(),
                            entry.info.owner,
                            Some(&c.overwrites),
                        )
                        .contains(Permissions::VIEW_CHANNEL)
                    })
                    .map(|c| c.id)
                    .collect();
                (entry.info.client_id, visible)
            })
            .collect()
    }

    /// After a permission mutation: tell each client exactly what its channel
    /// list gained, lost, or kept-but-changed, so the list every client holds
    /// is always precisely the channels it may view. `touched` names channels
    /// whose contents changed (an overwrite edit) so still-viewers get the
    /// updated object; role-level mutations pass none and only gains and
    /// losses flow.
    pub fn resync_visibility(
        &self,
        before: &[(ClientId, std::collections::HashSet<ChannelId>)],
        touched: &[ChannelId],
    ) {
        let after = self.visible_ids_by_client();
        let after_map: HashMap<ClientId, &std::collections::HashSet<ChannelId>> =
            after.iter().map(|(id, set)| (*id, set)).collect();
        let channels: HashMap<ChannelId, Channel> = {
            let inner = self.inner.read();
            inner.channels.clone().into_iter().collect()
        };

        for (client, was) in before {
            let Some(now) = after_map.get(client) else {
                continue;
            };
            for gained in now.iter().filter(|id| !was.contains(id)) {
                if let Some(channel) = channels.get(gained) {
                    self.send(*client, ServerControl::ChannelCreated(channel.clone()));
                }
            }
            for lost in was.iter().filter(|id| !now.contains(id)) {
                self.send(*client, ServerControl::ChannelRemoved(*lost));
            }
            for id in touched {
                if was.contains(id) && now.contains(id) {
                    if let Some(channel) = channels.get(id) {
                        self.send(*client, ServerControl::ChannelUpdated(channel.clone()));
                    }
                }
            }
        }
    }

    /// Update the cached role list on every live session of a fingerprint,
    /// returning the refreshed infos for broadcasting. Role changes must land
    /// on live sessions — the whole reason resolution reads inputs, not
    /// admission snapshots.
    pub fn update_live_member_roles(
        &self,
        fingerprint: Fingerprint,
        roles: &[RoleId],
    ) -> Vec<UserInfo> {
        let mut inner = self.inner.write();
        inner
            .clients
            .values_mut()
            .filter(|entry| entry.info.fingerprint() == fingerprint)
            .map(|entry| {
                entry.info.roles = roles.to_vec();
                entry.info.clone()
            })
            .collect()
    }

    /// Strip a deleted role from every live session holding it.
    pub fn strip_live_role(&self, role: RoleId) -> Vec<UserInfo> {
        let mut inner = self.inner.write();
        inner
            .clients
            .values_mut()
            .filter(|entry| entry.info.roles.contains(&role))
            .map(|entry| {
                entry.info.roles.retain(|r| *r != role);
                entry.info.clone()
            })
            .collect()
    }

    /// Replace or insert one overwrite on a channel, in memory. The store
    /// write happened first; this is the announce half.
    pub fn set_channel_overwrite(&self, channel: ChannelId, overwrite: Overwrite) -> bool {
        let mut inner = self.inner.write();
        let Some(target) = inner.channels.get_mut(&channel) else {
            return false;
        };
        target.overwrites.retain(|o| o.target != overwrite.target);
        target.overwrites.push(overwrite);
        true
    }

    pub fn remove_channel_overwrite(
        &self,
        channel: ChannelId,
        target: &pickle_proto::OverwriteTarget,
    ) -> bool {
        let mut inner = self.inner.write();
        let Some(entry) = inner.channels.get_mut(&channel) else {
            return false;
        };
        entry.overwrites.retain(|o| o.target != *target);
        true
    }

    /// Strip every overwrite naming a deleted role, returning the channels
    /// touched so the resync can update still-viewers.
    pub fn strip_role_overwrites(&self, role: RoleId) -> Vec<ChannelId> {
        let mut inner = self.inner.write();
        let target = pickle_proto::OverwriteTarget::Role(role);
        inner
            .channels
            .values_mut()
            .filter(|c| c.overwrites.iter().any(|o| o.target == target))
            .map(|c| {
                c.overwrites.retain(|o| o.target != target);
                c.id
            })
            .collect()
    }

    /// The next channel id: ids are never reused, so overwrites and history
    /// can never silently re-target a successor.
    pub fn next_channel_id(&self) -> ChannelId {
        self.inner
            .read()
            .channels
            .keys()
            .max()
            .copied()
            .unwrap_or(0)
            + 1
    }

    /// Would setting `child`'s parent to `parent` close a loop?
    pub fn parent_would_cycle(&self, child: ChannelId, parent: Option<ChannelId>) -> bool {
        let inner = self.inner.read();
        let mut cursor = parent;
        while let Some(id) = cursor {
            if id == child {
                return true;
            }
            cursor = inner.channels.get(&id).and_then(|c| c.parent);
        }
        false
    }

    pub fn insert_channel_mem(&self, channel: Channel) {
        self.inner.write().channels.insert(channel.id, channel);
    }

    /// Replace a channel's fields, preserving its overwrites — they have
    /// their own commands and their own storage row.
    pub fn update_channel_mem(&self, channel: Channel) -> bool {
        let mut inner = self.inner.write();
        let Some(existing) = inner.channels.get_mut(&channel.id) else {
            return false;
        };
        let overwrites = std::mem::take(&mut existing.overwrites);
        *existing = channel;
        existing.overwrites = overwrites;
        true
    }

    /// Remove a channel, evicting its voice occupants to nowhere. Returns the
    /// evicted, already updated, for the UserMoved broadcasts.
    pub fn remove_channel_mem(&self, channel: ChannelId) -> Vec<UserInfo> {
        let mut inner = self.inner.write();
        if inner.channels.remove(&channel).is_none() {
            return Vec::new();
        }
        inner
            .clients
            .values_mut()
            .filter(|entry| entry.info.channel == Some(channel))
            .map(|entry| {
                entry.info.channel = None;
                entry.info.clone()
            })
            .collect()
    }

    /// Remove a client by authority — a kick or a ban, not a quit.
    ///
    /// The victim is told first (a client that drains its queue learns *why*
    /// before the door shuts), then removed, then everyone else is told with
    /// the real reason. The returned entry carries the transport so the
    /// caller can close it after letting the frame flush — the 50 ms grace is
    /// the caller's, since this function must not sleep under any lock.
    pub fn eject(&self, victim: ClientId, reason: DisconnectReason) -> Option<ConnectedClient> {
        let entry = {
            let mut inner = self.inner.write();
            let entry = inner.clients.get(&victim)?;
            let _ = try_queue(
                entry,
                ServerControl::UserLeft {
                    client: victim,
                    reason,
                },
            );
            inner.clients.remove(&victim)
        };
        self.broadcast(
            ServerControl::UserLeft {
                client: victim,
                reason,
            },
            None,
        );
        entry
    }

    /// Set the server-side mute flag the relay has enforced all along.
    /// Returns the updated info for broadcasting, `None` if the client is gone.
    pub fn set_server_muted(&self, client: ClientId, muted: bool) -> Option<UserInfo> {
        let mut inner = self.inner.write();
        let entry = inner.clients.get_mut(&client)?;
        entry.info.voice.server_muted = muted;
        Some(entry.info.clone())
    }

    /// Move a member by authority. The target's own CONNECT is deliberately
    /// not consulted — the mover's is, by the caller — but the room's
    /// existence, kind, and capacity still apply: movers do not bypass walls.
    pub fn force_move(
        &self,
        client: ClientId,
        to: Option<ChannelId>,
    ) -> Result<Option<ChannelId>, ErrorCode> {
        let mut inner = self.inner.write();
        if let Some(channel) = to {
            let target = inner
                .channels
                .get(&channel)
                .ok_or(ErrorCode::NoSuchChannel)?;
            if !target.kind.has_voice() {
                return Err(ErrorCode::NotPermitted);
            }
            if let Some(max) = target.max_users {
                let occupants = inner
                    .clients
                    .values()
                    .filter(|c| c.info.channel == Some(channel) && c.info.client_id != client)
                    .count();
                if occupants >= max as usize {
                    return Err(ErrorCode::ChannelFull);
                }
            }
        }
        let entry = inner
            .clients
            .get_mut(&client)
            .ok_or(ErrorCode::NotAuthenticated)?;
        let previous = entry.info.channel;
        entry.info.channel = to;
        Ok(previous)
    }

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

/// Channels as the config file describes them — the first-boot seed, and what
/// tests build their maps from. After the seed, the database owns channels
/// and their ids; the config is a template.
pub fn build_channels(config: &ServerConfig) -> Vec<Channel> {
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
        .map(|(i, c)| Channel {
            id: i as ChannelId + 1,
            parent: c.parent.as_deref().and_then(|p| ids.get(p).copied()),
            name: c.name.clone(),
            topic: c.topic.clone(),
            kind: c.kind,
            max_users: c.max_users,
            order: c.order,
            overwrites: Vec::new(),
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

pub fn now_unix_ms() -> u64 {
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

    /// Build a Shared exactly as the server does, minus the database: the
    /// config's channels and the default role ladder.
    fn shared_from(config: ServerConfig) -> Shared {
        let channels = build_channels(&config);
        Shared::new(
            config,
            Identity::generate(),
            [0u8; 32],
            channels,
            PermState::defaults(),
        )
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
        shared_from(test_config())
    }

    #[test]
    fn a_configured_owner_passes_every_check_and_nobody_else_does() {
        // The behaviour PICKLE_OWNER exists for, asserted end to end from the
        // config rather than from the role store: an operator who sets it has
        // no way to confirm it took effect beyond a startup log, so the
        // resolution from string to capability is worth pinning down.
        let operator = Identity::generate();
        let bystander = Identity::generate();

        let config = ServerConfig {
            owner: Some(operator.fingerprint().to_string()),
            ..test_config()
        };
        let shared = shared_from(config);

        let snapshot = shared.perm_state();
        let owner = resolve(
            &snapshot.roles,
            &[],
            operator.fingerprint(),
            shared.is_owner(operator.fingerprint()),
            None,
        );
        assert_eq!(owner, Permissions::ALL, "the owner passes every check");

        let other = resolve(
            &snapshot.roles,
            &[],
            bystander.fingerprint(),
            shared.is_owner(bystander.fingerprint()),
            None,
        );
        assert!(
            !other.contains(Permissions::KICK_MEMBERS),
            "an unrelated identity must not inherit the owner's permissions"
        );
    }

    #[test]
    fn a_malformed_owner_leaves_the_server_ownerless_rather_than_refusing_to_start() {
        // Only reachable from a hand-edited config file; the environment path
        // refuses a bad value outright. Starting ownerless is recoverable,
        // where refusing to boot over a typo is not.
        let config = ServerConfig {
            owner: Some("not-a-fingerprint".into()),
            ..test_config()
        };
        let shared = shared_from(config);

        assert!(
            !shared.is_owner(Identity::generate().fingerprint()),
            "a server with an unreadable owner must grant nobody ownership"
        );
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
    fn admission_places_nobody_anywhere() {
        // Presence means standing in a voice room, and connecting must never
        // do that. Text needs no presence at all.
        let shared = shared();
        let alice = join(&shared, "alice");
        assert_eq!(alice.info.channel, None);
        assert_eq!(shared.user_count(), 1);

        // Nowhere is not stuck: an explicit join into a voice room works.
        shared.join_channel(alice.info.client_id, 3).unwrap();
    }

    #[test]
    fn joining_a_text_channel_is_refused() {
        // Being "in" a channel is being in its voice room. A text channel has
        // no room to stand in — everyone already reads and writes it — so the
        // server refuses to record the meaningless state.
        let shared = shared();
        let alice = join(&shared, "alice");
        assert_eq!(
            shared.join_channel(alice.info.client_id, 1),
            Err(ErrorCode::NotPermitted)
        );
    }

    #[test]
    fn a_message_reaches_clients_in_other_channels_and_in_none() {
        // The openness rule itself: text delivery ignores presence entirely.
        let shared = shared();
        let alice = join(&shared, "alice");
        let mut in_voice = join_voice(&shared, "bob");
        let mut nowhere = join(&shared, "carol");

        let message = shared.build_message(&alice.info, 1, "hi".into(), None);
        shared.broadcast(
            ServerControl::MessagePosted {
                message: Box::new(message),
                nonce: None,
            },
            Some(alice.info.client_id),
        );

        assert!(in_voice.control.try_recv().is_ok());
        assert!(nowhere.control.try_recv().is_ok());
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
        let shared = shared_from(config);

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
        let shared = shared_from(config);

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
    fn ejecting_tells_the_victim_then_everyone_with_the_real_reason() {
        let shared = shared();
        let mut alice = join(&shared, "alice");
        let mut bob = join(&shared, "bob");

        let entry = shared.eject(alice.info.client_id, DisconnectReason::Kicked);
        assert!(
            entry.is_some(),
            "the entry comes back for the transport close"
        );
        assert_eq!(shared.user_count(), 1);

        // Both the victim and the bystander hear UserLeft { Kicked }.
        for (who, control) in [("alice", &mut alice.control), ("bob", &mut bob.control)] {
            let frame = control
                .try_recv()
                .unwrap_or_else(|_| panic!("{who} heard nothing"));
            assert!(
                matches!(
                    frame,
                    ServerControl::UserLeft {
                        reason: DisconnectReason::Kicked,
                        ..
                    }
                ),
                "{who} must hear the real reason"
            );
        }

        // Ejecting a ghost is a quiet no-op.
        assert!(shared
            .eject(alice.info.client_id, DisconnectReason::Kicked)
            .is_none());
    }

    #[test]
    fn a_server_mute_silences_the_relay_until_lifted() {
        let shared = shared();
        let alice = join_voice(&shared, "alice");
        let bob = join_voice(&shared, "bob");

        shared.set_server_muted(alice.info.client_id, true).unwrap();
        shared.relay_voice(alice.info.client_id, voice_frame(1));
        assert!(
            bob.sink.0.lock().is_empty(),
            "muted by authority, not by choice"
        );

        shared
            .set_server_muted(alice.info.client_id, false)
            .unwrap();
        shared.relay_voice(alice.info.client_id, voice_frame(2));
        assert_eq!(bob.sink.0.lock().len(), 1, "and the lift is immediate");
    }

    #[test]
    fn force_move_bypasses_the_targets_permissions_but_not_the_walls() {
        let shared = shared();
        let alice = join(&shared, "alice");

        // Into a voice room: fine, and reports where they were.
        assert_eq!(shared.force_move(alice.info.client_id, Some(3)), Ok(None));
        // Into a text channel: still refused — there is no room to stand in.
        assert_eq!(
            shared.force_move(alice.info.client_id, Some(1)),
            Err(ErrorCode::NotPermitted)
        );
        // Out of voice entirely.
        assert_eq!(shared.force_move(alice.info.client_id, None), Ok(Some(3)));
    }

    #[test]
    fn hierarchy_helpers_answer_from_grants_and_config() {
        let operator = Identity::generate();
        let config = ServerConfig {
            owner: Some(operator.fingerprint().to_string()),
            ..test_config()
        };
        let shared = shared_from(config);
        let alice = join(&shared, "alice");

        // A roleless actor outranks nobody — not even another roleless member.
        let bob = join(&shared, "bob");
        assert!(!shared.actor_outranks(alice.info.client_id, bob.info.fingerprint()));
        // And nobody outranks the owner, online or not.
        assert!(!shared.actor_outranks(alice.info.client_id, operator.fingerprint()));
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
    fn joining_reports_the_previous_channel() {
        let shared = shared();
        let alice = join_voice(&shared, "alice");
        let previous = shared.join_channel(alice.info.client_id, 4).unwrap();
        assert_eq!(previous, Some(3));
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
        config.channels[2].max_users = Some(1);
        let shared = shared_from(config);

        let alice = join(&shared, "alice");
        let bob = join(&shared, "bob");
        shared.join_channel(alice.info.client_id, 3).unwrap();

        assert_eq!(
            shared.join_channel(bob.info.client_id, 3),
            Err(ErrorCode::ChannelFull)
        );
    }

    #[test]
    fn rejoining_a_full_channel_you_are_already_in_is_allowed() {
        // The occupant count must exclude the joiner, or a re-join would fail.
        let mut config = test_config();
        config.channels[2].max_users = Some(1);
        let shared = shared_from(config);

        let alice = join(&shared, "alice");
        shared.join_channel(alice.info.client_id, 3).unwrap();
        assert!(shared.join_channel(alice.info.client_id, 3).is_ok());
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
        let shared = shared_from(config);

        let channels = shared.channels();
        let lobby = channels.iter().find(|c| c.name == "Lobby").unwrap();
        let sub = channels.iter().find(|c| c.name == "Sub").unwrap();
        assert_eq!(sub.parent, Some(lobby.id));
        assert_eq!(lobby.parent, None);
    }

    #[test]
    fn the_suggested_channel_is_the_lowest_ordered_text_one() {
        let shared = shared();
        let probe = join(&shared, "probe");
        let lobby = shared
            .channel(shared.default_channel_for(&probe.info).unwrap())
            .unwrap();
        assert_eq!(lobby.name, "Lobby");
        assert!(lobby.kind.has_text());
    }

    #[test]
    fn a_server_with_no_text_anywhere_suggests_nothing() {
        let mut config = test_config();
        for channel in &mut config.channels {
            channel.kind = ChannelKind::Voice;
        }
        let shared = shared_from(config);
        let probe = join(&shared, "probe");
        assert_eq!(shared.default_channel_for(&probe.info), None);
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
