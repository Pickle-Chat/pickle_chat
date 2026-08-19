//! End-to-end tests over a real QUIC connection.
//!
//! These stand up an actual server on a loopback port and drive real clients
//! through it. Unit tests cover the pieces; these cover the thing that matters
//! — that a client can find a server, prove who it is, and be heard.

use pickle_client::{ClientEvent, ConnectError, ConnectOptions, TrustPolicy, TrustStore};
use pickle_identity::Identity;
use pickle_server::{Server, ServerConfig};
use std::net::SocketAddr;
use std::time::Duration;
use tokio::sync::mpsc;
use tokio::sync::oneshot;

/// Generous enough for a loaded CI machine, short enough that a hang fails
/// rather than stalling the suite.
const TIMEOUT: Duration = Duration::from_secs(10);

struct TestServer {
    address: SocketAddr,
    fingerprint: pickle_identity::Fingerprint,
    shutdown: Option<oneshot::Sender<()>>,
    _data_dir: tempfile::TempDir,
}

impl TestServer {
    async fn start(configure: impl FnOnce(&mut ServerConfig)) -> Self {
        let data_dir = tempfile::tempdir().unwrap();

        let mut config = ServerConfig {
            // Port 0 lets the OS pick, so tests never collide.
            bind: "127.0.0.1:0".parse().unwrap(),
            min_security_level: 0,
            name: "Test Server".into(),
            ..ServerConfig::default()
        };
        configure(&mut config);

        let server = Server::bind(config, data_dir.path()).await.unwrap();
        let address = server.local_addr().unwrap();
        let fingerprint = server.fingerprint();

        let (shutdown, rx) = oneshot::channel();
        tokio::spawn(async move {
            server
                .run_until(async {
                    let _ = rx.await;
                })
                .await;
        });

        Self {
            address,
            fingerprint,
            shutdown: Some(shutdown),
            _data_dir: data_dir,
        }
    }

    async fn default() -> Self {
        Self::start(|_| {}).await
    }
}

impl Drop for TestServer {
    fn drop(&mut self) {
        if let Some(shutdown) = self.shutdown.take() {
            let _ = shutdown.send(());
        }
    }
}

async fn connect_client(
    server: &TestServer,
    nickname: &str,
) -> Result<(pickle_client::Client, mpsc::UnboundedReceiver<ClientEvent>), ConnectError> {
    let identity = Identity::generate();
    let mut trust = TrustStore::ephemeral();
    let options = ConnectOptions::new(server.address, nickname);
    pickle_client::connect(options, &identity, &mut trust).await
}

/// Wait for the first event matching `predicate`, ignoring anything else.
///
/// A disconnect while waiting fails immediately rather than timing out, so the
/// reported failure names the real cause.
async fn expect_event<T>(
    events: &mut mpsc::UnboundedReceiver<ClientEvent>,
    what: &str,
    mut predicate: impl FnMut(&ClientEvent) -> Option<T>,
) -> T {
    let deadline = tokio::time::Instant::now() + TIMEOUT;
    loop {
        let event = tokio::time::timeout_at(deadline, events.recv())
            .await
            .unwrap_or_else(|_| panic!("timed out waiting for {what}"))
            .unwrap_or_else(|| panic!("event stream closed while waiting for {what}"));

        if let Some(value) = predicate(&event) {
            return value;
        }
        if let ClientEvent::Disconnected { reason } = &event {
            panic!("disconnected while waiting for {what}: {reason}");
        }
    }
}

/// Walk a client into "General" (channel 2), the default configuration's voice
/// channel, and wait for the server to confirm the move. Admission lands
/// everyone in the text-only lobby — connecting must never put someone in a
/// room where they can be heard — so a test that wants audio flowing has to
/// take that walk first, exactly as a person would.
async fn join_general(
    client: &pickle_client::Client,
    events: &mut mpsc::UnboundedReceiver<ClientEvent>,
) {
    assert!(client.join_channel(2));
    let id = client.client_id();
    expect_event(
        events,
        "the move into the voice channel",
        |event| match event {
            ClientEvent::UserMoved {
                client,
                to: Some(2),
                ..
            } if *client == id => Some(()),
            _ => None,
        },
    )
    .await;
}

#[tokio::test]
async fn a_client_can_connect_and_authenticate() {
    let server = TestServer::default().await;
    let (client, _events) = connect_client(&server, "alice").await.unwrap();

    let session = client.session();
    assert_eq!(session.server_name, "Test Server");
    assert_eq!(session.server_identity.fingerprint(), server.fingerprint);
    assert!(session.client_id > 0);
    assert!(!session.channels.is_empty());

    // The client sees itself in the initial roster, so no special case is
    // needed for its own arrival.
    assert!(session.users.iter().any(|u| u.nickname == "alice"));
}

#[tokio::test]
async fn a_client_lands_in_the_default_channel() {
    let server = TestServer::default().await;
    let (client, _events) = connect_client(&server, "alice").await.unwrap();

    let session = client.session();
    let me = session
        .users
        .iter()
        .find(|u| u.client_id == session.client_id)
        .unwrap();
    assert_eq!(me.channel, session.default_channel);

    // The landing channel is not merely *a* channel: it must carry no voice.
    let landed = session
        .channels
        .iter()
        .find(|c| Some(c.id) == me.channel)
        .expect("the default config gives arrivals somewhere to land");
    assert!(
        !landed.kind.has_voice(),
        "connecting must not walk anyone into a live microphone"
    );
}

#[tokio::test]
async fn the_server_identity_is_pinned_on_first_contact() {
    let server = TestServer::default().await;
    let identity = Identity::generate();
    let mut trust = TrustStore::ephemeral();

    pickle_client::connect(
        ConnectOptions::new(server.address, "alice"),
        &identity,
        &mut trust,
    )
    .await
    .unwrap();

    let pinned = trust.get(&server.address.to_string()).unwrap();
    assert_eq!(pinned.fingerprint, server.fingerprint);
    assert_eq!(pinned.name, "Test Server");
}

#[tokio::test]
async fn a_strict_client_refuses_an_unpinned_server() {
    let server = TestServer::default().await;
    let identity = Identity::generate();
    let mut trust = TrustStore::ephemeral();

    let result = pickle_client::connect(
        ConnectOptions::new(server.address, "alice").with_trust(TrustPolicy::Strict),
        &identity,
        &mut trust,
    )
    .await;

    assert!(matches!(result, Err(ConnectError::NotTrusted { .. })));
}

#[tokio::test]
async fn a_strict_client_accepts_a_server_it_has_already_pinned() {
    let server = TestServer::default().await;
    let identity = Identity::generate();
    let mut trust = TrustStore::ephemeral();
    trust.trust(
        &server.address.to_string(),
        server.fingerprint,
        "Test Server",
    );

    let result = pickle_client::connect(
        ConnectOptions::new(server.address, "alice").with_trust(TrustPolicy::Strict),
        &identity,
        &mut trust,
    )
    .await;

    assert!(result.is_ok(), "{:?}", result.err());
}

#[tokio::test]
async fn a_client_is_refused_when_its_identity_level_is_too_low() {
    // Level 64 is unreachable, so every freshly generated identity is below it.
    let server = TestServer::start(|config| config.min_security_level = 64).await;

    match connect_client(&server, "alice").await {
        Err(ConnectError::Rejected(reason)) => {
            let text = reason.to_string();
            assert!(
                text.contains("64"),
                "the error should say what is required: {text}"
            );
        }
        other => panic!(
            "expected a rejection, got {other:?}",
            other = other.map(|_| "success")
        ),
    }
}

#[tokio::test]
async fn a_password_protected_server_refuses_the_wrong_password() {
    let server = TestServer::start(|config| config.password = Some("hunter2".into())).await;
    let identity = Identity::generate();
    let mut trust = TrustStore::ephemeral();

    let wrong = pickle_client::connect(
        ConnectOptions::new(server.address, "alice").with_password("wrong"),
        &identity,
        &mut trust,
    )
    .await;
    assert!(matches!(wrong, Err(ConnectError::Rejected(_))));

    let missing = pickle_client::connect(
        ConnectOptions::new(server.address, "alice"),
        &identity,
        &mut trust,
    )
    .await;
    assert!(matches!(missing, Err(ConnectError::Rejected(_))));

    let right = pickle_client::connect(
        ConnectOptions::new(server.address, "alice").with_password("hunter2"),
        &identity,
        &mut trust,
    )
    .await;
    assert!(right.is_ok(), "{:?}", right.err());
}

#[tokio::test]
async fn clients_see_each_other_arrive_and_leave() {
    let server = TestServer::default().await;
    let (_alice, mut alice_events) = connect_client(&server, "alice").await.unwrap();
    let (bob, _bob_events) = connect_client(&server, "bob").await.unwrap();
    let bob_id = bob.client_id();

    let joined = expect_event(&mut alice_events, "bob to join", |event| match event {
        ClientEvent::UserJoined(info) => Some(info.clone()),
        _ => None,
    })
    .await;
    assert_eq!(joined.nickname, "bob");
    assert_eq!(joined.client_id, bob_id);

    drop(bob);

    let left = expect_event(&mut alice_events, "bob to leave", |event| match event {
        ClientEvent::UserLeft { client, .. } => Some(*client),
        _ => None,
    })
    .await;
    assert_eq!(left, bob_id);
}

#[tokio::test]
async fn voice_reaches_another_client_in_the_same_channel() {
    // The core of the whole application: audio in one end, audio out the other.
    let server = TestServer::default().await;
    let (alice, mut alice_events) = connect_client(&server, "alice").await.unwrap();
    let (bob, mut bob_events) = connect_client(&server, "bob").await.unwrap();
    let alice_id = alice.client_id();
    // Both walk from the text-only lobby into General; nothing is audible
    // where admission put them.
    join_general(&alice, &mut alice_events).await;
    join_general(&bob, &mut bob_events).await;

    let payload = bytes::Bytes::from_static(&[0xaa, 0xbb, 0xcc, 0xdd]);

    // Datagrams are unreliable by design, so resend until one lands rather
    // than asserting on a single packet.
    let received = tokio::time::timeout(TIMEOUT, async {
        loop {
            alice.send_voice(42, pickle_proto::voice::FLAG_BURST_START, payload.clone());
            tokio::select! {
                Some(event) = bob_events.recv() => {
                    if let ClientEvent::Voice(packet) = event {
                        return packet;
                    }
                }
                _ = tokio::time::sleep(Duration::from_millis(20)) => {}
            }
        }
    })
    .await
    .expect("bob should hear alice");

    assert_eq!(
        received.sender, alice_id,
        "the server stamps the true sender"
    );
    assert_eq!(received.seq, 42);
    assert_eq!(received.payload, payload);
    assert!(received.starts_burst());
}

#[tokio::test]
async fn voice_does_not_reach_a_client_in_another_channel() {
    let server = TestServer::default().await;
    let (alice, mut alice_events) = connect_client(&server, "alice").await.unwrap();
    let (bob, mut bob_events) = connect_client(&server, "bob").await.unwrap();

    // Alice speaks from "General"; bob sits in "AFK" (channel 3).
    join_general(&alice, &mut alice_events).await;
    assert!(bob.join_channel(3));
    expect_event(&mut bob_events, "bob's channel move", |event| match event {
        ClientEvent::UserMoved { to: Some(3), .. } => Some(()),
        _ => None,
    })
    .await;

    for seq in 0..10 {
        alice.send_voice(seq, 0, bytes::Bytes::from_static(&[1, 2, 3]));
    }
    tokio::time::sleep(Duration::from_millis(300)).await;

    while let Ok(event) = bob_events.try_recv() {
        assert!(
            !matches!(event, ClientEvent::Voice(_)),
            "voice must not cross channel boundaries"
        );
    }
}

#[tokio::test]
async fn a_muted_client_is_silenced_by_the_server() {
    let server = TestServer::default().await;
    let (alice, mut alice_events) = connect_client(&server, "alice").await.unwrap();
    let (bob, mut bob_events) = connect_client(&server, "bob").await.unwrap();
    join_general(&alice, &mut alice_events).await;
    join_general(&bob, &mut bob_events).await;

    assert!(alice.set_voice_state(true, false));
    expect_event(
        &mut alice_events,
        "the mute to take effect",
        |event| match event {
            ClientEvent::UserUpdated(info) if info.voice.self_muted => Some(()),
            _ => None,
        },
    )
    .await;

    for seq in 0..10 {
        alice.send_voice(seq, 0, bytes::Bytes::from_static(&[1, 2, 3]));
    }
    tokio::time::sleep(Duration::from_millis(300)).await;

    while let Ok(event) = bob_events.try_recv() {
        assert!(
            !matches!(event, ClientEvent::Voice(_)),
            "the server must enforce mute, not just the sender's UI"
        );
    }
}

#[tokio::test]
async fn a_text_message_reaches_the_channel() {
    let server = TestServer::default().await;
    let (alice, mut alice_events) = connect_client(&server, "alice").await.unwrap();
    let (_bob, mut bob_events) = connect_client(&server, "bob").await.unwrap();

    let channel = alice
        .session()
        .default_channel
        .expect("the default config lands clients in the lobby");
    assert!(alice.send_message(channel, "hello **world**", 12345));

    let received = expect_event(&mut bob_events, "the message", |event| match event {
        ClientEvent::MessagePosted { message, .. } => Some(message.clone()),
        _ => None,
    })
    .await;
    assert_eq!(received.content, "hello **world**");
    assert_eq!(received.author_nickname, "alice");

    // The author's own echo carries the nonce back for reconciling an
    // optimistic local render.
    let echo = expect_event(&mut alice_events, "the echo", |event| match event {
        ClientEvent::MessagePosted {
            nonce: Some(n),
            message,
        } => Some((*n, message.clone())),
        _ => None,
    })
    .await;
    assert_eq!(echo.0, 12345);
    assert_eq!(echo.1.id, received.id, "both sides see the same message id");
}

#[tokio::test]
async fn a_ping_is_answered() {
    let server = TestServer::default().await;
    let (client, mut events) = connect_client(&server, "alice").await.unwrap();

    assert!(client.send_control(pickle_proto::ClientControl::Ping { nonce: 777 }));

    let nonce = expect_event(&mut events, "a pong", |event| match event {
        ClientEvent::Pong { nonce } => Some(*nonce),
        _ => None,
    })
    .await;
    assert_eq!(nonce, 777);
}

#[tokio::test]
async fn the_server_reports_a_full_house() {
    let server = TestServer::start(|config| config.max_users = 1).await;
    let _first = connect_client(&server, "alice").await.unwrap();

    match connect_client(&server, "bob").await {
        Err(ConnectError::Rejected(reason)) => {
            assert!(reason.to_string().contains("full"), "{reason}");
        }
        _ => panic!("the second client should have been refused"),
    }
}

#[tokio::test]
async fn datagrams_are_available_on_the_connection() {
    // If the transport config ever stops enabling datagrams, voice silently
    // stops working; catch that here rather than in the field.
    let server = TestServer::default().await;
    let (client, _events) = connect_client(&server, "alice").await.unwrap();

    let max = client
        .max_voice_payload()
        .expect("datagrams must be enabled");
    assert!(
        max >= 1000,
        "a datagram should carry a full Opus frame, got {max}"
    );
}

#[tokio::test]
async fn connecting_to_a_dead_address_fails_promptly() {
    let identity = Identity::generate();
    let mut trust = TrustStore::ephemeral();
    // Reserved for documentation; nothing answers there.
    let address: SocketAddr = "192.0.2.1:42071".parse().unwrap();

    let result = tokio::time::timeout(
        Duration::from_secs(15),
        pickle_client::connect(
            ConnectOptions::new(address, "alice").with_trust(TrustPolicy::Insecure),
            &identity,
            &mut trust,
        ),
    )
    .await
    .expect("a mistyped address must not leave the user waiting on the idle timeout");

    match result {
        Err(ConnectError::Unreachable { .. }) => {}
        Err(other) => panic!("expected an unreachable error, got: {other}"),
        Ok(_) => panic!("nothing should be listening at 192.0.2.1"),
    }
}

/// One identity, two servers, at the same time.
///
/// This is the foundation the desktop client's connection tabs rest on. Nothing
/// in the protocol forbids it — `Client` holds no global state — but "nothing
/// forbids it" is not the same as having seen it work, and the failure mode if
/// it did not would be an app that silently drops the first connection when the
/// second opens.
#[tokio::test]
async fn one_identity_can_hold_two_connections_at_once() {
    let first = TestServer::start(|config| config.name = "First".into()).await;
    let second = TestServer::start(|config| config.name = "Second".into()).await;

    // The same key on both, which is what connecting to two servers as yourself
    // actually means.
    let identity = Identity::generate();
    let mut trust = TrustStore::ephemeral();

    let (client_a, mut events_a) = pickle_client::connect(
        ConnectOptions::new(first.address, "alice"),
        &identity,
        &mut trust,
    )
    .await
    .unwrap();
    let (client_b, _events_b) = pickle_client::connect(
        ConnectOptions::new(second.address, "alice"),
        &identity,
        &mut trust,
    )
    .await
    .unwrap();

    assert_eq!(client_a.session().server_name, "First");
    assert_eq!(client_b.session().server_name, "Second");

    // Distinct servers, so distinct identities — a client that had silently
    // reconnected to the same one would pass every check above.
    assert_ne!(
        client_a.session().server_identity.fingerprint(),
        client_b.session().server_identity.fingerprint(),
    );

    // The first connection is still live, not merely still in scope: opening
    // the second must not have torn it down. A third client joining the first
    // server proves it, since a dead connection would never hear about them.
    let (other, _events) = connect_client(&first, "bob").await.unwrap();
    expect_event(
        &mut events_a,
        "bob joining the first server",
        |event| match event {
            ClientEvent::UserJoined(user) if user.nickname == "bob" => Some(()),
            _ => None,
        },
    )
    .await;
    drop(other);
}

/// Client ids are assigned per server, so the same number means different
/// people on different connections.
///
/// The desktop client keys its own session registry separately for exactly this
/// reason, and the voice mixer is kept to one server at a time because it keys
/// speakers this way.
#[tokio::test]
async fn client_ids_are_only_meaningful_within_one_server() {
    let first = TestServer::default().await;
    let second = TestServer::default().await;

    let (a, _ea) = connect_client(&first, "alice").await.unwrap();
    let (b, _eb) = connect_client(&second, "bob").await.unwrap();

    assert_eq!(
        a.session().client_id,
        b.session().client_id,
        "two fresh servers both start numbering from the same place, which is \
         precisely why a client id cannot be used to tell connections apart",
    );
}

/// The point of persistence: someone who was not there can read what was said.
///
/// Covers the whole path — persist on send, survive the sender leaving, and
/// come back through `FetchHistory` to a connection that did not exist at the
/// time.
#[tokio::test]
async fn a_later_client_can_read_what_it_missed() {
    let server = TestServer::default().await;

    let (early, mut early_events) = connect_client(&server, "alice").await.unwrap();
    let channel = early
        .session()
        .default_channel
        .expect("the default config lands clients in the lobby");
    early.send_message(channel, "said while you were away", 1);

    // Wait for the server's echo before leaving. Sending is fire-and-forget, so
    // disconnecting straight away races the frame reaching the server at all —
    // and the echo is only sent after the message has been stored.
    expect_event(&mut early_events, "the message to be accepted", |event| {
        matches!(event, ClientEvent::MessagePosted { .. }).then_some(())
    })
    .await;

    // The sender leaves entirely, so nothing about this can be served from a
    // live connection's memory.
    early.disconnect();
    drop(early);

    let (late, mut late_events) = connect_client(&server, "bob").await.unwrap();
    late.fetch_history(channel, None, 50);

    let messages = expect_event(&mut late_events, "history", |event| match event {
        ClientEvent::History { messages, .. } => Some(messages.clone()),
        _ => None,
    })
    .await;

    assert_eq!(messages.len(), 1, "the message outlived its sender");
    assert_eq!(messages[0].content, "said while you were away");
    assert_eq!(
        messages[0].author_nickname, "alice",
        "the name it was sent under, not whoever holds it now",
    );
}

/// History is per channel, and asking about a channel you are not in does not
/// hand back another room's conversation.
#[tokio::test]
async fn history_is_scoped_to_the_channel_asked_about() {
    let server = TestServer::default().await;
    let (client, mut events) = connect_client(&server, "alice").await.unwrap();

    let session = client.session();
    let default_channel = session
        .default_channel
        .expect("the default config lands clients in the lobby");
    let other = session
        .channels
        .iter()
        .find(|c| c.id != default_channel)
        .map(|c| c.id)
        .expect("the default config defines more than one channel");

    client.send_message(default_channel, "in the lobby", 1);

    client.fetch_history(other, None, 50);

    let messages = expect_event(
        &mut events,
        "history for the other channel",
        |event| match event {
            ClientEvent::History {
                channel, messages, ..
            } if *channel == other => Some(messages.clone()),
            _ => None,
        },
    )
    .await;

    assert!(messages.is_empty(), "nothing was said in that channel");
}

/// Pinning must key on the address the user typed, not on what it resolved to.
///
/// Keying on the resolved address keys on a value an attacker can influence:
/// change what the name resolves to and the new address is simply unknown, so
/// trust-on-first-use pins the impostor without a word. This drives the same
/// name at two different `SocketAddr`s and requires the identity to carry.
#[tokio::test]
async fn a_pin_follows_the_typed_address_not_the_resolved_one() {
    let first = TestServer::default().await;
    let second = TestServer::default().await;
    assert_ne!(
        first.fingerprint, second.fingerprint,
        "two servers, two identities — the whole point of the test",
    );

    let identity = Identity::generate();
    let mut trust = TrustStore::ephemeral();

    // The user types one name. It resolves to the first server today.
    pickle_client::connect(
        ConnectOptions::new(first.address, "alice").with_server_key("chat.example.com:42071"),
        &identity,
        &mut trust,
    )
    .await
    .unwrap();

    // Tomorrow the same name resolves elsewhere. Under the old behaviour this
    // was an unknown key and would have been pinned silently.
    let result = pickle_client::connect(
        ConnectOptions::new(second.address, "alice").with_server_key("chat.example.com:42071"),
        &identity,
        &mut trust,
    )
    .await;

    match result {
        Err(ConnectError::IdentityChanged {
            expected, actual, ..
        }) => {
            assert_eq!(expected, first.fingerprint);
            assert_eq!(actual, second.fingerprint);
        }
        other => panic!(
            "a substituted address must be refused, got {:?}",
            other.map(|_| "a silently accepted connection"),
        ),
    }
}

/// A pin recorded under the old resolved-address scheme is adopted, not
/// re-pinned.
///
/// Migrating by treating it as first contact would throw away the decision
/// being migrated — the user would silently re-trust whatever answered.
#[tokio::test]
async fn a_pin_from_the_old_scheme_is_carried_over() {
    let server = TestServer::default().await;
    let identity = Identity::generate();
    let mut trust = TrustStore::ephemeral();

    // What an older build wrote: keyed by the resolved address.
    trust.trust(
        &server.address.to_string(),
        server.fingerprint,
        "Test Server",
    );

    pickle_client::connect(
        ConnectOptions::new(server.address, "alice")
            .with_server_key("chat.example.com:42071")
            .with_trust(TrustPolicy::Strict),
        &identity,
        &mut trust,
    )
    .await
    .expect("the existing pin should be honoured, not treated as a new server");

    assert!(
        trust.get("chat.example.com:42071").is_some(),
        "re-keyed under what the user typed",
    );
    assert!(
        trust.get(&server.address.to_string()).is_none(),
        "and the old entry retired rather than left to rot",
    );
}

/// A legacy entry for a *different* identity is not adopted.
///
/// An address can legitimately be reused by another server, so that case has to
/// fall through to the ordinary rules rather than inheriting someone else's pin.
#[tokio::test]
async fn a_legacy_pin_for_another_identity_is_not_inherited() {
    let server = TestServer::default().await;
    let identity = Identity::generate();
    let mut trust = TrustStore::ephemeral();

    // Some unrelated server was once pinned at this address.
    let stranger = Identity::generate().fingerprint();
    trust.trust(&server.address.to_string(), stranger, "Someone Else");

    let result = pickle_client::connect(
        ConnectOptions::new(server.address, "alice")
            .with_server_key("chat.example.com:42071")
            .with_trust(TrustPolicy::Strict),
        &identity,
        &mut trust,
    )
    .await;

    assert!(
        matches!(result, Err(ConnectError::NotTrusted { .. })),
        "a stranger's pin must not be inherited",
    );
}
