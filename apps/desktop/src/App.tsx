import { useEffect, useMemo, useReducer, useRef, useState } from "react";
import {
  api,
  type Bookmark,
  type Channel,
  type Connection,
  type Identity,
  type Message,
  type SessionId,
  type Settings,
  type User,
} from "./api";
import { EMPTY, reduce, type ConnectionState } from "./connections";
import { LevelMeter } from "./LevelMeter";
import { SettingsDialog } from "./settings/SettingsDialog";
import { usePushToTalk } from "./usePushToTalk";

export function App() {
  const [identity, setIdentity] = useState<Identity | null>(null);
  const [connections, dispatch] = useReducer(reduce, EMPTY);
  const [voiceSession, setVoiceSession] = useState<SessionId | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [settingsOpen, setSettingsOpen] = useState(false);
  const [settings, setSettings] = useState<Settings | null>(null);
  const [restoring, setRestoring] = useState(false);

  useEffect(() => {
    api.identityInfo().then(setIdentity).catch((e) => setError(String(e)));
    api.settings().then(setSettings).catch((e) => setError(String(e)));
  }, []);

  // The focus-scoped half of push-to-talk. The global grab lives in Rust; this
  // covers the platforms that refuse it, and costs nothing where it succeeds.
  usePushToTalk(
    settings?.keybinds.pushToTalk ?? null,
    settings?.audio.gateMode === "pushToTalk",
  );

  // Server events drive the whole UI. Voice never arrives here — it is mixed
  // on the Rust side and goes straight to the speakers. Each event names its
  // connection, so it lands in the right tab.
  useEffect(() => {
    const unlisten = api.onServerEvent((session, event) =>
      dispatch({ type: "event", session, event }),
    );
    return () => {
      unlisten.then((fn) => fn());
    };
  }, []);

  // Reopen what was connected last time.
  //
  // Driven from here rather than at startup in Rust so each attempt becomes its
  // own tab: a server that is down, has changed identity, or now refuses the
  // key shows that in its own tab instead of blocking the others or failing
  // quietly.
  useEffect(() => {
    if (settings === null || settings.connections.length === 0) return;

    let cancelled = false;
    setRestoring(true);

    (async () => {
      const saved = await api.bookmarks().catch(() => [] as Bookmark[]);

      for (const previous of settings.connections) {
        if (cancelled) return;
        // A bookmark for the same address supplies a remembered password; a
        // server that needs one we do not have simply fails into its own tab.
        const bookmark = saved.find((b) => b.address === previous.address);
        try {
          const connection = await api.connect({
            address: previous.address,
            password: bookmark?.password,
            identity: previous.identity,
          });
          if (!cancelled) dispatch({ type: "opened", connection });
        } catch (e) {
          if (!cancelled) {
            setError(`Could not reconnect to ${previous.address}: ${e}`);
          }
        }
      }

      if (!cancelled) setRestoring(false);
    })();

    return () => {
      cancelled = true;
    };
    // Runs once, on the first settings load. Restoring again whenever settings
    // change would reconnect every time a device or keybind was edited.
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [settings !== null]);

  const active = connections.active === null ? null : connections.byId[connections.active] ?? null;

  const onConnected = (connection: Connection) => {
    dispatch({ type: "opened", connection });
    setError(null);
    refreshVoice();
  };

  const refreshVoice = () => {
    api
      .sessions()
      .then((list) => setVoiceSession(list.voice))
      .catch(() => {});
  };

  useEffect(refreshVoice, []);

  const onDisconnect = async (session: SessionId) => {
    await api.disconnect(session).catch((e) => setError(String(e)));
    dispatch({ type: "closed", session });
    refreshVoice();
  };

  return (
    <div className="app">
      <header className="titlebar">
        <span className="brand">Pickle</span>
        {identity && <IdentityBadge identity={identity} onChange={setIdentity} />}
        <button className="icon" onClick={() => setSettingsOpen(true)} aria-label="Settings">
          ⚙
        </button>
      </header>

      <ConnectionTabs
        connections={connections.order.map((id) => connections.byId[id])}
        active={connections.active}
        voice={voiceSession}
        restoring={restoring}
        onSelect={(session) => dispatch({ type: "focused", session })}
        onClose={onDisconnect}
      />

      {settingsOpen && (
        <SettingsDialog
          connected={connections.order.length > 0}
          onSettingsChange={setSettings}
          onIdentityChanged={() => {
            api.identityInfo().then(setIdentity).catch((e) => setError(String(e)));
          }}
          onClose={() => setSettingsOpen(false)}
        />
      )}

      {error && (
        <div className="banner error" role="alert">
          {error}
          <button onClick={() => setError(null)} aria-label="Dismiss">
            ×
          </button>
        </div>
      )}

      {active ? (
        <ConnectionView
          connection={active}
          hasVoice={voiceSession === active.session}
          onError={setError}
          onSelectChannel={(channel) => {
            dispatch({ type: "channelSelected", session: active.session, channel });
            api.joinChannel(active.session, channel).catch((e) => setError(String(e)));
          }}
          onLeaveChannel={() => {
            // The view empties with the membership: staying parked on a room
            // you just left would show a conversation that has stopped
            // arriving, silently going stale.
            dispatch({ type: "channelSelected", session: active.session, channel: null });
            api.leaveChannel(active.session).catch((e) => setError(String(e)));
          }}
          onTakeVoice={() => {
            api
              .setVoiceSession(active.session)
              .then(refreshVoice)
              .catch((e) => setError(String(e)));
          }}
          onDisconnect={() => onDisconnect(active.session)}
        />
      ) : (
        <ConnectForm onConnected={onConnected} onError={setError} />
      )}
    </div>
  );
}

/// One tab per connection, plus a `+` for opening another.
function ConnectionTabs({
  connections,
  active,
  voice,
  restoring,
  onSelect,
  onClose,
}: {
  connections: ConnectionState[];
  active: SessionId | null;
  voice: SessionId | null;
  restoring: boolean;
  onSelect: (session: SessionId | null) => void;
  onClose: (session: SessionId) => void;
}) {
  return (
    <nav className="tabs" role="tablist" aria-label="Connections">
      {connections.map((connection) => (
        <div
          key={connection.session}
          className={
            active === connection.session ? "tab active" : connection.disconnected ? "tab dead" : "tab"
          }
        >
          <button role="tab" aria-selected={active === connection.session} onClick={() => onSelect(connection.session)}>
            {/* Marks where the microphone is, which is not necessarily the tab
                being looked at. */}
            {voice === connection.session && (
              <span className="tab-voice" title="Voice is on this server" aria-label="Voice is on this server">
                🔊
              </span>
            )}
            {connection.info.serverName}
            {connection.unread > 0 && active !== connection.session && (
              <span className="tab-unread" aria-label={`${connection.unread} unread`}>
                {connection.unread}
              </span>
            )}
          </button>
          <button
            className="tab-close"
            onClick={() => onClose(connection.session)}
            aria-label={`Disconnect from ${connection.info.serverName}`}
            title="Disconnect"
          >
            ×
          </button>
        </div>
      ))}

      <button
        className={active === null ? "tab add active" : "tab add"}
        onClick={() => onSelect(null)}
        aria-label="Connect to another server"
      >
        +
      </button>

      {restoring && <span className="muted tab-note">Reconnecting…</span>}
    </nav>
  );
}

/// Everything for one connection.
function ConnectionView({
  connection,
  hasVoice,
  onError,
  onSelectChannel,
  onLeaveChannel,
  onTakeVoice,
  onDisconnect,
}: {
  connection: ConnectionState;
  hasVoice: boolean;
  onError: (error: string) => void;
  onSelectChannel: (channel: number) => void;
  onLeaveChannel: () => void;
  onTakeVoice: () => void;
  onDisconnect: () => void;
}) {
  if (connection.disconnected) {
    return (
      <div className="connect">
        <h1>{connection.info.serverName}</h1>
        <p className="banner error" role="alert">
          Disconnected: {connection.disconnected}
        </p>
        <p className="muted">
          The tab stays open so you can read why. Close it when you are done.
        </p>
        <button onClick={onDisconnect}>Close</button>
      </div>
    );
  }

  const channel =
    connection.info.channels.find((c) => c.id === connection.activeChannel) ?? null;

  return (
    <main className="layout">
      <ChannelList
        session={connection.session}
        channels={connection.info.channels}
        users={connection.users}
        activeChannel={connection.activeChannel}
        selfId={connection.info.clientId}
        hasVoice={hasVoice}
        onJoin={onSelectChannel}
        onLeave={onLeaveChannel}
      />
      <ChatPane
        channel={channel}
        messages={connection.messages.filter((m) => m.channel === connection.activeChannel)}
        onSend={(content) => {
          if (connection.activeChannel !== null) {
            api
              .sendMessage(connection.session, connection.activeChannel, content)
              .catch((e) => onError(String(e)));
          }
        }}
      />
      <VoiceControls
        hasVoice={hasVoice}
        serverName={connection.info.serverName}
        onTakeVoice={onTakeVoice}
        onError={onError}
        onDisconnect={onDisconnect}
      />
    </main>
  );
}

function IdentityBadge({
  identity,
  onChange,
}: {
  identity: Identity;
  onChange: (identity: Identity) => void;
}) {
  const [editing, setEditing] = useState(false);
  const [draft, setDraft] = useState(identity.nickname);
  const [mining, setMining] = useState<number | null>(null);

  useEffect(() => {
    const unlisten = api.onMiningProgress((progress) => {
      setMining(progress.done ? null : progress.bestLevel);
      if (progress.done) {
        api.identityInfo().then(onChange);
      }
    });
    return () => {
      unlisten.then((fn) => fn());
    };
  }, [onChange]);

  const save = () => {
    api.setNickname(draft).then(onChange).catch(() => setDraft(identity.nickname));
    setEditing(false);
  };

  return (
    <div className="identity">
      {editing ? (
        <input
          autoFocus
          value={draft}
          onChange={(e) => setDraft(e.target.value)}
          onBlur={save}
          onKeyDown={(e) => e.key === "Enter" && save()}
        />
      ) : (
        <button className="linklike" onClick={() => setEditing(true)}>
          {identity.nickname}
        </button>
      )}
      {/* The fingerprint, not the nickname, is what actually identifies you. */}
      <code className="fingerprint" title={identity.fingerprint}>
        {identity.short}
      </code>
      <span className="level" title="Identity security level — proof of work over your public key">
        L{identity.securityLevel}
      </span>
      {mining !== null ? (
        <span className="muted">mining… L{mining}</span>
      ) : (
        <button className="linklike" onClick={() => api.mineIdentity(identity.securityLevel + 4)}>
          raise
        </button>
      )}
    </div>
  );
}

function ConnectForm({
  onConnected,
  onError,
}: {
  onConnected: (connection: Connection) => void;
  onError: (error: string) => void;
}) {
  const [address, setAddress] = useState("127.0.0.1:42071");
  const [password, setPassword] = useState("");
  const [identity, setIdentity] = useState<string | undefined>(undefined);
  const [busy, setBusy] = useState(false);
  const [known, setKnown] = useState<{ address: string; name: string; fingerprint: string }[]>([]);
  const [bookmarks, setBookmarks] = useState<Bookmark[]>([]);

  useEffect(() => {
    api.knownServers().then(setKnown).catch(() => setKnown([]));
    api.bookmarks().then(setBookmarks).catch(() => setBookmarks([]));
  }, []);

  const submit = async (e: React.FormEvent) => {
    e.preventDefault();
    setBusy(true);
    try {
      onConnected(await api.connect({ address, password, identity }));
      // Cleared so the form is ready for the next server rather than still
      // holding the last one's password.
      setPassword("");
    } catch (err) {
      onError(String(err));
    } finally {
      setBusy(false);
    }
  };

  return (
    <div className="connect">
      <form onSubmit={submit}>
        <h1>Connect to a server</h1>
        <label>
          Address
          <input
            value={address}
            onChange={(e) => setAddress(e.target.value)}
            placeholder="hostname or IP, port optional"
          />
        </label>
        <label>
          Password <span className="muted">(only if the server has one)</span>
          <input type="password" value={password} onChange={(e) => setPassword(e.target.value)} />
        </label>
        <button type="submit" disabled={busy}>
          {busy ? "Connecting…" : "Connect"}
        </button>
      </form>

      {bookmarks.length > 0 && (
        <section className="known">
          <h2>Saved servers</h2>
          <ul>
            {bookmarks.map((bookmark) => (
              <li key={bookmark.id}>
                <button
                  className="linklike"
                  onClick={() => {
                    setAddress(bookmark.address);
                    // A saved password is the reason to save one at all; leave
                    // any typed password alone when the bookmark has none.
                    if (bookmark.password !== undefined) setPassword(bookmark.password);
                    // A bookmark may pin which identity to use for this server.
                    setIdentity(bookmark.identity);
                  }}
                >
                  {bookmark.label}
                </button>
                <span className="muted">{bookmark.address}</span>
              </li>
            ))}
          </ul>
        </section>
      )}

      {known.length > 0 && (
        <section className="known">
          <h2>Servers you have used</h2>
          <ul>
            {known.map((server) => (
              <li key={server.address}>
                <button className="linklike" onClick={() => setAddress(server.address)}>
                  {server.name}
                </button>
                <code className="fingerprint">{server.fingerprint}</code>
                <span className="muted">{server.address}</span>
              </li>
            ))}
          </ul>
        </section>
      )}
    </div>
  );
}

function ChannelList({
  session,
  channels,
  users,
  activeChannel,
  selfId,
  hasVoice,
  onJoin,
  onLeave,
}: {
  session: SessionId;
  channels: Channel[];
  users: User[];
  activeChannel: number | null;
  selfId: number;
  /// Whether this connection is the one carrying voice.
  hasVoice: boolean;
  onJoin: (id: number) => void;
  onLeave: () => void;
}) {
  const [speaking, setSpeaking] = useState<number[]>([]);

  // Polled rather than pushed: speaking state changes every frame, and an
  // event per change would flood the bridge for something purely cosmetic.
  //
  // The interval matches the level meter's. This drives the user's own
  // indicator as well as everyone else's, and a slower tick made keying push to
  // talk feel like it had not registered.
  //
  // Only for the connection holding voice. Speaker ids are assigned per server,
  // so applying another server's list here would light up whoever happens to
  // share a number with someone talking elsewhere.
  useEffect(() => {
    if (!hasVoice) {
      setSpeaking([]);
      return;
    }
    const timer = setInterval(() => {
      api
        .speaking()
        .then((audible) => setSpeaking(audible.session === session ? audible.clients : []))
        .catch(() => {});
    }, 100);
    return () => clearInterval(timer);
  }, [hasVoice, session]);

  const sorted = useMemo(
    () => [...channels].sort((a, b) => a.order - b.order || a.name.localeCompare(b.name)),
    [channels],
  );

  return (
    <nav className="channels">
      {sorted.map((channel) => (
        <div key={channel.id} className={channel.parent ? "channel nested" : "channel"}>
          <div className="channel-row">
            <button
              className={channel.id === activeChannel ? "channel-name active" : "channel-name"}
              onClick={() => onJoin(channel.id)}
              title={channel.topic}
            >
              <span className="glyph">{channel.hasVoice ? "🔊" : "#"}</span>
              {channel.name}
            </button>
            {/* On the channel you are standing in, not the one you are
                viewing: leaving is about presence — stepping out of a voice
                room, or unsubscribing from a room's live messages. */}
            {users.some((u) => u.clientId === selfId && u.channel === channel.id) && (
              <button
                className="leave"
                onClick={onLeave}
                title={
                  channel.hasVoice
                    ? "Leave — you will no longer be heard here"
                    : "Leave — new messages here will no longer reach you"
                }
                aria-label={`Leave ${channel.name}`}
              >
                leave
              </button>
            )}
          </div>
          <ul className="occupants">
            {users
              .filter((user) => user.channel === channel.id)
              .map((user) => {
                // Voice presence is meaningless where nothing can be heard: in
                // a text-only channel the engine may still be transmitting to a
                // server that discards it, and a talk-dot there would show
                // someone "speaking" whom nobody can hear.
                const voiced = channel.hasVoice;
                // `speaking` includes us when we are transmitting, so this one
                // check covers everyone the channel can currently hear.
                const talking = voiced && speaking.includes(user.clientId);
                const silenced = user.selfDeafened || user.selfMuted;

                return (
                  <li key={user.clientId} className={talking ? "speaking" : undefined}>
                    {/* Always rendered in a voice channel, so names do not
                        shift sideways as people start and stop talking. */}
                    {voiced && (
                      <span
                        className={talking ? "talk-dot on" : "talk-dot"}
                        aria-hidden="true"
                      />
                    )}
                    <span className="occupant-name">{user.nickname}</span>
                    {user.clientId === selfId && <span className="muted">(you)</span>}
                    {voiced && silenced && (
                      <span
                        title={user.selfDeafened ? "Deafened" : "Muted"}
                        aria-label={user.selfDeafened ? "Deafened" : "Muted"}
                      >
                        {user.selfDeafened ? "🔇" : "🎙️̸"}
                      </span>
                    )}
                    {/* Announced only for the person themselves; narrating every
                        speaker in a busy channel would be unusable. */}
                    {user.clientId === selfId && voiced && (
                      <span className="visually-hidden" role="status" aria-live="polite">
                        {talking ? "Transmitting" : "Not transmitting"}
                      </span>
                    )}
                  </li>
                );
              })}
          </ul>
        </div>
      ))}
      {/* A server whose channels all carry voice gives new arrivals nowhere to
          land, so people can now exist in no channel at all. Render them, or
          they would simply be invisible — including yourself, right after
          connecting. */}
      {users.some((user) => user.channel === null) && (
        <div className="channel">
          <span className="channel-name unjoined">Not in a channel</span>
          <ul className="occupants">
            {users
              .filter((user) => user.channel === null)
              .map((user) => (
                <li key={user.clientId}>
                  <span className="occupant-name">{user.nickname}</span>
                  {user.clientId === selfId && <span className="muted">(you)</span>}
                </li>
              ))}
          </ul>
        </div>
      )}
    </nav>
  );
}

function ChatPane({
  channel,
  messages,
  onSend,
}: {
  channel: Channel | null;
  messages: Message[];
  onSend: (content: string) => void;
}) {
  const [draft, setDraft] = useState("");
  const bottom = useRef<HTMLDivElement>(null);

  useEffect(() => {
    bottom.current?.scrollIntoView({ behavior: "smooth" });
  }, [messages.length]);

  if (!channel) {
    return <section className="chat empty">Pick a channel.</section>;
  }

  return (
    <section className="chat">
      <header>
        <strong>{channel.name}</strong>
        {channel.topic && <span className="muted"> — {channel.topic}</span>}
      </header>

      <div className="messages">
        {messages.length === 0 && <p className="muted">No messages yet.</p>}
        {messages.map((message) => (
          <article key={message.id}>
            <span className="author" title={message.authorFingerprint}>
              {message.authorNickname}
            </span>
            <time>{new Date(message.sentAtUnixMs).toLocaleTimeString()}</time>
            <p>{message.content}</p>
          </article>
        ))}
        <div ref={bottom} />
      </div>

      <form
        className="composer"
        onSubmit={(e) => {
          e.preventDefault();
          if (draft.trim()) {
            onSend(draft);
            setDraft("");
          }
        }}
      >
        <input
          value={draft}
          onChange={(e) => setDraft(e.target.value)}
          placeholder={channel.hasText ? `Message ${channel.name}` : "This channel is voice only"}
          disabled={!channel.hasText}
        />
        <button type="submit" disabled={!channel.hasText}>
          Send
        </button>
      </form>
    </section>
  );
}

function VoiceControls({
  hasVoice,
  serverName,
  onTakeVoice,
  onError,
  onDisconnect,
}: {
  hasVoice: boolean;
  serverName: string;
  onTakeVoice: () => void;
  onError: (error: string) => void;
  onDisconnect: () => void;
}) {
  const [{ muted, deafened }, setVoice] = useState({ muted: false, deafened: false });

  // The Rust side is the authority: it is what a global shortcut talks to, and
  // it applies the rule that deafening implies muting. Following its answer
  // rather than predicting one keeps the buttons right however the change was
  // made.
  useEffect(() => {
    api.voiceState().then(setVoice).catch(() => {});
    const unlisten = api.onVoiceState(setVoice);
    return () => {
      unlisten.then((fn) => fn());
    };
  }, []);

  const toggleMute = () => {
    api.setMuted(!muted).then(setVoice).catch((e) => onError(String(e)));
  };

  const toggleDeafen = () => {
    api.setDeafened(!deafened).then(setVoice).catch((e) => onError(String(e)));
  };

  return (
    <aside className="voice">
      {hasVoice ? (
        <>
          {/* No status text here: the channel list carries it against your own
              name, alongside everyone else's. */}
          <LevelMeter showStatus={false} />
          <button className={muted ? "toggled" : undefined} onClick={toggleMute}>
            {muted ? "Unmute" : "Mute"}
          </button>
          <button className={deafened ? "toggled" : undefined} onClick={toggleDeafen}>
            {deafened ? "Undeafen" : "Deafen"}
          </button>
        </>
      ) : (
        <>
          {/* Voice is elsewhere. Saying so, and offering the move explicitly, is
              why switching tabs does not silently drag the microphone along. */}
          <p className="muted">
            Voice is on another server. Your microphone is not going to{" "}
            {serverName}.
          </p>
          <button onClick={onTakeVoice}>Talk here instead</button>
        </>
      )}
      <button className="danger" onClick={onDisconnect}>
        Disconnect
      </button>
    </aside>
  );
}
