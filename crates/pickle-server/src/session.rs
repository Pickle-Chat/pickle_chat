//! One connected client, from TLS handshake to disconnect.
//!
//! The server opens the control stream and speaks first. That ordering matters:
//! QUIC only surfaces a peer-opened stream once data arrives on it, so if the
//! client opened the stream and then waited for `ServerHello`, both sides would
//! sit blocked forever.
//!
//! After authentication a session runs three concurrent parts — a control
//! reader, a control writer draining the outbound queue, and a datagram reader
//! feeding the voice relay. The first to finish tears down the other two.

use crate::state::Shared;
use pickle_identity::PublicIdentity;
use pickle_proto::codec::{self, CodecError};
use pickle_proto::voice::VoiceUpstream;
use pickle_proto::{
    AuthFailure, AuthOk, ClientAuth, ClientControl, ClientId, DisconnectReason, ErrorCode,
    ServerControl, ServerHello, ServerLimits, UserInfo, PROTOCOL_VERSION,
};
use rand::RngCore;
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::mpsc;
use tracing::{debug, info, warn};

/// How long a client has to complete authentication before being dropped.
/// Bounds the resources an unauthenticated peer can hold.
const HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(10);

/// Control frames a client may send per second before being throttled. Voice
/// datagrams are not counted — they are rate-limited by their own 20 ms cadence.
const CONTROL_RATE_LIMIT: u32 = 30;

/// QUIC application close codes.
const CLOSE_OK: u32 = 0;
const CLOSE_AUTH_FAILED: u32 = 1;
const CLOSE_PROTOCOL_ERROR: u32 = 2;

/// Handle an inbound connection to completion. Never returns an error: a single
/// bad client should not disturb the server.
pub async fn serve(shared: Arc<Shared>, incoming: quinn::Incoming) {
    let connection = match incoming.await {
        Ok(connection) => connection,
        Err(e) => {
            debug!(error = %e, "connection failed before it was established");
            return;
        }
    };

    let peer = connection.remote_address();
    match handshake(&shared, &connection).await {
        Ok(Some(session)) => {
            let client_id = session.info.client_id;
            let nickname = session.info.nickname.clone();
            info!(
                %peer,
                client_id,
                nickname = %nickname,
                fingerprint = %session.info.identity.fingerprint().short(),
                level = session.info.identity.security_level(),
                "client authenticated"
            );

            if let Err(e) = run_session(&shared, &connection, session).await {
                debug!(%peer, client_id, error = %e, "session ended");
            }

            // Always announce the departure, however the session ended.
            if shared.remove(client_id).is_some() {
                shared.broadcast(
                    ServerControl::UserLeft {
                        client: client_id,
                        reason: DisconnectReason::Quit,
                    },
                    Some(client_id),
                );
            }
            info!(%peer, client_id, nickname = %nickname, "client disconnected");
            connection.close(CLOSE_OK.into(), b"bye");
        }
        Ok(None) => {
            // Authentication was refused; the client has been told why.
            connection.close(CLOSE_AUTH_FAILED.into(), b"authentication failed");
        }
        Err(e) => {
            debug!(%peer, error = %e, "handshake failed");
            connection.close(CLOSE_PROTOCOL_ERROR.into(), b"protocol error");
        }
    }
}

/// State handed from the handshake to the running session.
struct Session {
    info: UserInfo,
    send: quinn::SendStream,
    recv: quinn::RecvStream,
    control_rx: crate::state::ControlReceiver,
}

/// Returns `Ok(None)` when the client was cleanly refused, `Err` on a protocol
/// or transport fault.
async fn handshake(
    shared: &Arc<Shared>,
    connection: &quinn::Connection,
) -> Result<Option<Session>, CodecError> {
    let (mut send, mut recv) = connection
        .open_bi()
        .await
        .map_err(|e| CodecError::Io(std::io::Error::other(e)))?;

    let mut nonce = [0u8; 32];
    rand::thread_rng().fill_bytes(&mut nonce);

    let hello = ServerHello {
        protocol_version: PROTOCOL_VERSION,
        server_name: shared.config.name.clone(),
        server_identity: shared.identity.public(),
        nonce,
        min_security_level: shared.config.min_security_level,
        requires_password: shared.config.password.is_some(),
        signature: shared
            .identity
            .sign_server_hello(&nonce, &shared.cert_hash, &shared.config.name)
            .into(),
    };
    codec::write_frame(&mut send, &ServerControl::Hello(Box::new(hello))).await?;

    let first = tokio::time::timeout(
        HANDSHAKE_TIMEOUT,
        codec::read_frame::<_, ClientControl>(&mut recv),
    )
    .await
    .map_err(|_| {
        CodecError::Io(std::io::Error::new(
            std::io::ErrorKind::TimedOut,
            "client did not authenticate in time",
        ))
    })??;

    let ClientControl::Auth(auth) = first else {
        // Anything before Auth is a protocol violation, not a refusal.
        return Err(CodecError::Io(std::io::Error::other(
            "first control frame was not Auth",
        )));
    };

    if let Err(failure) = verify_auth(shared, &auth, &nonce) {
        warn!(reason = ?failure, "rejecting client");
        codec::write_frame(&mut send, &ServerControl::AuthFailed(failure)).await?;
        // Give the frame a chance to reach the client before the close.
        let _ = send.finish();
        tokio::time::sleep(Duration::from_millis(50)).await;
        return Ok(None);
    }

    let (control_tx, control_rx) = mpsc::channel(crate::state::CONTROL_QUEUE_DEPTH);
    let info = match shared.admit(
        auth.identity,
        auth.nickname.clone(),
        control_tx,
        Box::new(connection.clone()),
    ) {
        Ok(info) => info,
        Err(failure) => {
            codec::write_frame(&mut send, &ServerControl::AuthFailed(failure)).await?;
            let _ = send.finish();
            tokio::time::sleep(Duration::from_millis(50)).await;
            return Ok(None);
        }
    };

    // From here the client occupies a slot in shared state, so every failure
    // path has to give it back. `?` alone would not: the caller only cleans up
    // after a session that *started*, so a client that authenticates and then
    // vanishes before `AuthOk` is written would stay in the roster forever,
    // counting against `max_users` and appearing as a phantom to everyone who
    // connects afterwards. Repeating that a few dozen times would wedge the
    // server at capacity until it was restarted.
    let admitted = Admitted {
        shared: Arc::clone(shared),
        client_id: info.client_id,
    };

    let ok = AuthOk {
        client_id: info.client_id,
        channels: shared.channels(),
        // Snapshot taken after admission, so the client sees itself in the list
        // and does not need a special case for its own arrival.
        users: shared.users(),
        default_channel: shared.default_channel,
        // Reported per connection rather than from the static config, so a
        // server whose store failed to open says so instead of promising
        // history it cannot serve.
        limits: ServerLimits {
            history_enabled: shared.history_enabled(),
            ..shared.limits.clone()
        },
    };
    codec::write_frame(&mut send, &ServerControl::AuthOk(Box::new(ok))).await?;

    shared.broadcast(
        ServerControl::UserJoined(Box::new(info.clone())),
        Some(info.client_id),
    );

    // Handed over to a running session, which owns the cleanup from here.
    admitted.disarm();

    Ok(Some(Session {
        info,
        send,
        recv,
        control_rx,
    }))
}

/// Removes an admitted client on drop, unless the session actually started.
///
/// A guard rather than a `remove` on each error path, because the failure being
/// guarded against is precisely *forgetting* one — and `?` makes every fallible
/// call between admission and handover an exit.
struct Admitted {
    shared: Arc<Shared>,
    client_id: ClientId,
}

impl Admitted {
    /// The session took ownership; stop guarding.
    fn disarm(self) {
        std::mem::forget(self);
    }
}

impl Drop for Admitted {
    fn drop(&mut self) {
        if self.shared.remove(self.client_id).is_some() {
            debug!(
                client_id = self.client_id,
                "released a slot for a client that never finished connecting"
            );
        }
    }
}

/// Check protocol version, password, and signature. Order matters only in that
/// the cheapest checks come first.
fn verify_auth(
    shared: &Arc<Shared>,
    auth: &ClientAuth,
    nonce: &[u8; 32],
) -> Result<(), AuthFailure> {
    if auth.protocol_version != PROTOCOL_VERSION {
        return Err(AuthFailure::ProtocolMismatch {
            server_version: PROTOCOL_VERSION,
        });
    }

    if let Some(expected) = &shared.config.password {
        match &auth.password {
            None => return Err(AuthFailure::PasswordRequired),
            Some(supplied) if !constant_time_eq(expected.as_bytes(), supplied.as_bytes()) => {
                return Err(AuthFailure::BadPassword)
            }
            Some(_) => {}
        }
    }

    // Proves the client holds the private key *and* is talking to this server:
    // the signature covers our certificate hash, so it cannot be replayed
    // against a different server by a relay in the middle.
    verify_signature(&auth.identity, nonce, &shared.cert_hash, &auth.signature.0)?;

    Ok(())
}

fn verify_signature(
    identity: &PublicIdentity,
    nonce: &[u8; 32],
    cert_hash: &[u8; 32],
    signature: &[u8; 64],
) -> Result<(), AuthFailure> {
    identity
        .verify_auth(nonce, cert_hash, signature)
        .map_err(|_| AuthFailure::BadSignature)
}

/// Compare without an early exit, so timing does not leak the password prefix.
fn constant_time_eq(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }
    let mut diff = 0u8;
    for (x, y) in a.iter().zip(b.iter()) {
        diff |= x ^ y;
    }
    diff == 0
}

async fn run_session(
    shared: &Arc<Shared>,
    connection: &quinn::Connection,
    session: Session,
) -> Result<(), CodecError> {
    let Session {
        info,
        mut send,
        mut recv,
        mut control_rx,
    } = session;
    let client_id = info.client_id;

    // Drains the outbound queue. Owning `send` keeps writes to the control
    // stream in one place, so frames can never interleave.
    let writer = tokio::spawn(async move {
        while let Some(message) = control_rx.recv().await {
            if codec::write_frame(&mut send, &message).await.is_err() {
                break;
            }
        }
        let _ = send.finish();
    });

    // Voice. Kept off the control task so a burst of audio cannot delay
    // chat, and vice versa.
    let datagrams = tokio::spawn({
        let shared = Arc::clone(shared);
        let connection = connection.clone();
        async move {
            while let Ok(datagram) = connection.read_datagram().await {
                match VoiceUpstream::decode(datagram) {
                    Ok(packet) => shared.relay_voice(client_id, packet),
                    // A malformed datagram is dropped rather than fatal; UDP
                    // payloads can be corrupted or come from an older client.
                    Err(e) => debug!(client_id, error = %e, "discarding voice datagram"),
                }
            }
        }
    });

    let result = control_loop(shared, &mut recv, client_id).await;

    writer.abort();
    datagrams.abort();
    result
}

async fn control_loop(
    shared: &Arc<Shared>,
    recv: &mut quinn::RecvStream,
    client_id: ClientId,
) -> Result<(), CodecError> {
    let mut limiter = RateLimiter::new(CONTROL_RATE_LIMIT);

    loop {
        let message: ClientControl = match codec::read_frame(recv).await {
            Ok(message) => message,
            Err(e) if e.is_clean_close() => return Ok(()),
            Err(e) => return Err(e),
        };

        if !limiter.allow() {
            shared.send(
                client_id,
                ServerControl::Error {
                    code: ErrorCode::RateLimited,
                    detail: "too many control messages".into(),
                },
            );
            continue;
        }

        handle_control(shared, client_id, message).await;
    }
}

async fn handle_control(shared: &Arc<Shared>, client_id: ClientId, message: ClientControl) {
    match message {
        // A second Auth on an authenticated stream is meaningless.
        ClientControl::Auth(_) => shared.send(
            client_id,
            ServerControl::Error {
                code: ErrorCode::Malformed,
                detail: "already authenticated".into(),
            },
        ),

        ClientControl::Ping { nonce } => shared.send(client_id, ServerControl::Pong { nonce }),

        ClientControl::JoinChannel { channel, .. } => {
            match shared.join_channel(client_id, channel) {
                Ok(from) => shared.broadcast(
                    ServerControl::UserMoved {
                        client: client_id,
                        from,
                        to: Some(channel),
                    },
                    None,
                ),
                Err(code) => shared.send(
                    client_id,
                    ServerControl::Error {
                        code,
                        detail: if code == ErrorCode::NotPermitted {
                            format!(
                                "channel {channel} carries no voice; text channels \
                                 are open to everyone without joining"
                            )
                        } else {
                            format!("could not join channel {channel}")
                        },
                    },
                ),
            }
        }

        ClientControl::LeaveChannel => {
            let from = shared.leave_channel(client_id);
            shared.broadcast(
                ServerControl::UserMoved {
                    client: client_id,
                    from,
                    to: None,
                },
                None,
            );
        }

        ClientControl::SetVoiceState {
            self_muted,
            self_deafened,
        } => {
            if let Some(info) = shared.set_voice_state(client_id, self_muted, self_deafened) {
                shared.broadcast(ServerControl::UserUpdated(Box::new(info)), None);
            }
        }

        ClientControl::SetNickname(nickname) => match shared.set_nickname(client_id, &nickname) {
            Some(info) => shared.broadcast(ServerControl::UserUpdated(Box::new(info)), None),
            None => shared.send(
                client_id,
                ServerControl::Error {
                    code: ErrorCode::Malformed,
                    detail: "nickname must contain a printable character".into(),
                },
            ),
        },

        ClientControl::SendMessage {
            channel,
            content,
            reply_to,
            nonce,
        } => send_message(shared, client_id, channel, content, reply_to, nonce).await,

        ClientControl::Typing { channel } => {
            shared.broadcast(
                ServerControl::Typing {
                    client: client_id,
                    channel,
                },
                Some(client_id),
            );
        }

        ClientControl::FetchHistory {
            channel,
            before,
            limit,
        } => fetch_history(shared, client_id, channel, before, limit).await,

        ClientControl::EditMessage { .. }
        | ClientControl::DeleteMessage { .. }
        | ClientControl::React { .. } => shared.send(
            client_id,
            ServerControl::Error {
                code: ErrorCode::NotPermitted,
                detail: "message editing, deletion and reactions need the message store, which is not implemented yet".into(),
            },
        ),
    }
}

/// Answer a request for past messages.
///
/// A server with history switched off, or with no store, answers with an empty
/// page marked as the start rather than staying silent — a client waiting on a
/// reply that never comes is worse than one told there is nothing.
async fn fetch_history(
    shared: &Arc<Shared>,
    client_id: ClientId,
    channel: pickle_proto::ChannelId,
    before: Option<pickle_proto::MessageId>,
    limit: u16,
) {
    let empty = |shared: &Arc<Shared>| {
        shared.send(
            client_id,
            ServerControl::History {
                channel,
                messages: Vec::new(),
                reached_start: true,
            },
        );
    };

    if !shared.history_enabled() {
        empty(shared);
        return;
    }

    // Reading another channel's history is reading a room you may not be in, so
    // the channel has to exist and carry text at all.
    match shared.channel(channel) {
        Some(c) if c.kind.has_text() => {}
        _ => {
            empty(shared);
            return;
        }
    }

    let Some(store) = shared.store() else {
        empty(shared);
        return;
    };

    match store.history(channel, before, limit).await {
        Ok(page) => shared.send(
            client_id,
            ServerControl::History {
                channel,
                messages: page.messages,
                reached_start: page.reached_start,
            },
        ),
        Err(error) => {
            warn!(%error, channel, "could not read history");
            shared.send(
                client_id,
                ServerControl::Error {
                    code: ErrorCode::Internal,
                    detail: "the server could not read history".into(),
                },
            );
        }
    }
}

async fn send_message(
    shared: &Arc<Shared>,
    client_id: ClientId,
    channel: pickle_proto::ChannelId,
    content: String,
    reply_to: Option<u64>,
    nonce: u64,
) {
    let Some(author) = shared.user(client_id) else {
        return;
    };

    if content.trim().is_empty() {
        return;
    }

    if content.len() > shared.limits.max_message_len as usize {
        shared.send(
            client_id,
            ServerControl::Error {
                code: ErrorCode::MessageTooLong,
                detail: format!(
                    "messages are limited to {} bytes",
                    shared.limits.max_message_len
                ),
            },
        );
        return;
    }

    match shared.channel(channel) {
        None => {
            shared.send(
                client_id,
                ServerControl::Error {
                    code: ErrorCode::NoSuchChannel,
                    detail: format!("no channel {channel}"),
                },
            );
            return;
        }
        Some(c) if !c.kind.has_text() => {
            shared.send(
                client_id,
                ServerControl::Error {
                    code: ErrorCode::NotPermitted,
                    detail: format!("channel {:?} does not carry text", c.name),
                },
            );
            return;
        }
        Some(_) => {}
    }

    let message = shared.build_message(&author, channel, content, reply_to);

    // Stored before anyone is told about it. The other order is faster, but it
    // means a message everyone saw can vanish on restart — history that
    // disagrees with what people remember reading is the worse failure, and a
    // write error has to reach the sender rather than being swallowed.
    if let Some(store) = shared.store() {
        if let Err(error) = store.insert_message(&message).await {
            warn!(%error, "could not store a message");
            shared.send(
                client_id,
                ServerControl::Error {
                    code: ErrorCode::Internal,
                    detail: "the server could not save that message, so it was not sent".into(),
                },
            );
            return;
        }
    }

    // The author gets the nonce back so an optimistic local echo can be
    // reconciled with the server's authoritative copy.
    shared.send(
        client_id,
        ServerControl::MessagePosted {
            message: Box::new(message.clone()),
            nonce: Some(nonce),
        },
    );
    // To everyone, not to the channel's occupants: text is readable without
    // joining, and occupancy means voice presence. The channel id on the
    // message is how clients file it, not who may see it.
    shared.broadcast(
        ServerControl::MessagePosted {
            message: Box::new(message),
            nonce: None,
        },
        Some(client_id),
    );
}

/// Token bucket refilled continuously, allowing short bursts without
/// permitting a sustained flood.
struct RateLimiter {
    capacity: f64,
    tokens: f64,
    per_second: f64,
    last: std::time::Instant,
}

impl RateLimiter {
    fn new(per_second: u32) -> Self {
        Self {
            capacity: per_second as f64,
            tokens: per_second as f64,
            per_second: per_second as f64,
            last: std::time::Instant::now(),
        }
    }

    fn allow(&mut self) -> bool {
        let now = std::time::Instant::now();
        let elapsed = now.duration_since(self.last).as_secs_f64();
        self.last = now;
        self.tokens = (self.tokens + elapsed * self.per_second).min(self.capacity);

        if self.tokens >= 1.0 {
            self.tokens -= 1.0;
            true
        } else {
            false
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn constant_time_eq_matches_ordinary_equality() {
        assert!(constant_time_eq(b"hunter2", b"hunter2"));
        assert!(!constant_time_eq(b"hunter2", b"hunter3"));
        assert!(!constant_time_eq(b"hunter2", b"hunter22"));
        assert!(constant_time_eq(b"", b""));
    }

    #[test]
    fn the_rate_limiter_allows_a_burst_then_throttles() {
        let mut limiter = RateLimiter::new(5);
        for _ in 0..5 {
            assert!(limiter.allow());
        }
        assert!(!limiter.allow(), "burst capacity should be exhausted");
    }

    #[test]
    fn the_rate_limiter_refills_over_time() {
        let mut limiter = RateLimiter::new(100);
        while limiter.allow() {}
        std::thread::sleep(Duration::from_millis(50));
        assert!(limiter.allow(), "tokens should accrue while idle");
    }
}
