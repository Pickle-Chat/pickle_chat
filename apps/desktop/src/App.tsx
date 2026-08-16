import { useCallback, useEffect, useMemo, useRef, useState } from "react";
import {
  api,
  type Channel,
  type Identity,
  type Message,
  type ServerEvent,
  type Session,
  type User,
} from "./api";

export function App() {
  const [identity, setIdentity] = useState<Identity | null>(null);
  const [session, setSession] = useState<Session | null>(null);
  const [users, setUsers] = useState<User[]>([]);
  const [messages, setMessages] = useState<Message[]>([]);
  const [activeChannel, setActiveChannel] = useState<number | null>(null);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    api.identityInfo().then(setIdentity).catch((e) => setError(String(e)));
  }, []);

  // Server events drive the whole UI. Voice never arrives here — it is mixed
  // on the Rust side and goes straight to the speakers.
  useEffect(() => {
    const unlisten = api.onServerEvent((event) => applyEvent(event));
    return () => {
      unlisten.then((fn) => fn());
    };
  }, []);

  const applyEvent = useCallback((event: ServerEvent) => {
    switch (event.type) {
      case "userJoined":
        setUsers((current) => [...current.filter((u) => u.clientId !== event.user.clientId), event.user]);
        break;
      case "userLeft":
        setUsers((current) => current.filter((u) => u.clientId !== event.clientId));
        break;
      case "userMoved":
        setUsers((current) =>
          current.map((u) => (u.clientId === event.clientId ? { ...u, channel: event.channel } : u)),
        );
        break;
      case "userUpdated":
        setUsers((current) =>
          current.map((u) => (u.clientId === event.user.clientId ? event.user : u)),
        );
        break;
      case "message":
        setMessages((current) => [...current, event.message]);
        break;
      case "serverError":
        setError(event.detail);
        break;
      case "disconnected":
        setError(`Disconnected: ${event.reason}`);
        setSession(null);
        setUsers([]);
        break;
      case "typing":
        break;
    }
  }, []);

  const onConnected = (next: Session) => {
    setSession(next);
    setUsers(next.users);
    setMessages([]);
    setActiveChannel(next.defaultChannel);
    setError(null);
  };

  const onDisconnect = async () => {
    await api.disconnect();
    setSession(null);
    setUsers([]);
    setMessages([]);
  };

  return (
    <div className="app">
      <header className="titlebar">
        <span className="brand">Pickle</span>
        {session ? (
          <span className="server">
            {session.serverName}
            <code className="fingerprint" title={session.serverFingerprint}>
              {session.serverFingerprint.slice(0, 14)}…
            </code>
          </span>
        ) : (
          <span className="muted">Not connected</span>
        )}
        {identity && <IdentityBadge identity={identity} onChange={setIdentity} />}
      </header>

      {error && (
        <div className="banner error" role="alert">
          {error}
          <button onClick={() => setError(null)} aria-label="Dismiss">
            ×
          </button>
        </div>
      )}

      {session ? (
        <main className="layout">
          <ChannelList
            channels={session.channels}
            users={users}
            activeChannel={activeChannel}
            selfId={session.clientId}
            onJoin={(id) => {
              setActiveChannel(id);
              api.joinChannel(id).catch((e) => setError(String(e)));
            }}
          />
          <ChatPane
            channel={session.channels.find((c) => c.id === activeChannel) ?? null}
            messages={messages.filter((m) => m.channel === activeChannel)}
            onSend={(content) => {
              if (activeChannel !== null) {
                api.sendMessage(activeChannel, content).catch((e) => setError(String(e)));
              }
            }}
          />
          <VoiceControls onError={setError} onDisconnect={onDisconnect} />
        </main>
      ) : (
        <ConnectForm onConnected={onConnected} onError={setError} />
      )}
    </div>
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
  onConnected: (session: Session) => void;
  onError: (error: string) => void;
}) {
  const [address, setAddress] = useState("127.0.0.1:42071");
  const [password, setPassword] = useState("");
  const [pushToTalk, setPushToTalk] = useState(false);
  const [busy, setBusy] = useState(false);
  const [known, setKnown] = useState<{ address: string; name: string; fingerprint: string }[]>([]);

  useEffect(() => {
    api.knownServers().then(setKnown).catch(() => setKnown([]));
  }, []);

  const submit = async (e: React.FormEvent) => {
    e.preventDefault();
    setBusy(true);
    try {
      onConnected(await api.connect({ address, password, pushToTalk }));
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
        <label className="row">
          <input
            type="checkbox"
            checked={pushToTalk}
            onChange={(e) => setPushToTalk(e.target.checked)}
          />
          Push to talk
        </label>
        <button type="submit" disabled={busy}>
          {busy ? "Connecting…" : "Connect"}
        </button>
      </form>

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
  channels,
  users,
  activeChannel,
  selfId,
  onJoin,
}: {
  channels: Channel[];
  users: User[];
  activeChannel: number | null;
  selfId: number;
  onJoin: (id: number) => void;
}) {
  const [speaking, setSpeaking] = useState<number[]>([]);

  // Polled rather than pushed: speaking state changes every frame, and an
  // event per change would flood the bridge for something purely cosmetic.
  useEffect(() => {
    const timer = setInterval(() => {
      api.speaking().then(setSpeaking).catch(() => {});
    }, 150);
    return () => clearInterval(timer);
  }, []);

  const sorted = useMemo(
    () => [...channels].sort((a, b) => a.order - b.order || a.name.localeCompare(b.name)),
    [channels],
  );

  return (
    <nav className="channels">
      {sorted.map((channel) => (
        <div key={channel.id} className={channel.parent ? "channel nested" : "channel"}>
          <button
            className={channel.id === activeChannel ? "channel-name active" : "channel-name"}
            onClick={() => onJoin(channel.id)}
            title={channel.topic}
          >
            <span className="glyph">{channel.hasVoice ? "🔊" : "#"}</span>
            {channel.name}
          </button>
          <ul className="occupants">
            {users
              .filter((user) => user.channel === channel.id)
              .map((user) => (
                <li
                  key={user.clientId}
                  className={speaking.includes(user.clientId) ? "speaking" : undefined}
                >
                  {user.nickname}
                  {user.clientId === selfId && <span className="muted"> (you)</span>}
                  {user.selfDeafened ? " 🔇" : user.selfMuted ? " 🎙️̸" : ""}
                </li>
              ))}
          </ul>
        </div>
      ))}
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
  onError,
  onDisconnect,
}: {
  onError: (error: string) => void;
  onDisconnect: () => void;
}) {
  const [muted, setMuted] = useState(false);
  const [deafened, setDeafened] = useState(false);
  const [level, setLevel] = useState(Number.NEGATIVE_INFINITY);

  useEffect(() => {
    const timer = setInterval(() => {
      api.inputLevel().then(setLevel).catch(() => {});
    }, 100);
    return () => clearInterval(timer);
  }, []);

  const toggleMute = () => {
    const next = !muted;
    setMuted(next);
    api.setMuted(next).catch((e) => onError(String(e)));
  };

  const toggleDeafen = () => {
    const next = !deafened;
    setDeafened(next);
    // Deafening implies muting, which is what the server enforces too.
    if (next) setMuted(true);
    api.setDeafened(next).catch((e) => onError(String(e)));
  };

  // Map dBFS onto a 0-100 bar. -60 dB is effectively silence.
  const meter = Number.isFinite(level) ? Math.max(0, Math.min(100, ((level + 60) / 60) * 100)) : 0;

  return (
    <aside className="voice">
      <div className="meter" aria-label="Microphone level">
        <div className="meter-fill" style={{ width: `${meter}%` }} />
      </div>
      <button className={muted ? "toggled" : undefined} onClick={toggleMute}>
        {muted ? "Unmute" : "Mute"}
      </button>
      <button className={deafened ? "toggled" : undefined} onClick={toggleDeafen}>
        {deafened ? "Undeafen" : "Deafen"}
      </button>
      <button className="danger" onClick={onDisconnect}>
        Disconnect
      </button>
    </aside>
  );
}
