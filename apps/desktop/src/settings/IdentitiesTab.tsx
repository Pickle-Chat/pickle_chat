import { useEffect, useState } from "react";
import { api, type IdentityList, type VaultEntry } from "../api";

export function IdentitiesTab({
  connected,
  onActiveChanged,
  onError,
}: {
  connected: boolean;
  /// The titlebar badge shows the active identity, so it has to be told.
  onActiveChanged: () => void;
  onError: (error: string) => void;
}) {
  const [list, setList] = useState<IdentityList | null>(null);
  const [adding, setAdding] = useState(false);
  const [nickname, setNickname] = useState("");
  const [label, setLabel] = useState("");
  const [confirming, setConfirming] = useState<string | null>(null);

  useEffect(() => {
    api.identities().then(setList).catch((e) => onError(String(e)));
  }, [onError]);

  const applied = (next: IdentityList) => {
    setList(next);
    onActiveChanged();
  };

  const add = (event: React.FormEvent) => {
    event.preventDefault();
    if (!nickname.trim()) return;
    api
      .addIdentity(nickname, label)
      .then((next) => {
        applied(next);
        closeAddForm();
      })
      .catch((e) => onError(String(e)));
  };

  const closeAddForm = () => {
    setAdding(false);
    setNickname("");
    setLabel("");
  };

  if (list === null) {
    return <p className="muted settings-pane">Loading…</p>;
  }

  return (
    <div className="settings-pane">
      {connected && (
        <p className="muted">
          You are connected. The server knows you by the key you signed in with,
          so switching or removing an identity is unavailable until you
          disconnect.
        </p>
      )}

      <ul className="identity-list">
        {list.identities.map((entry) => (
          <IdentityRow
            key={entry.fingerprint}
            entry={entry}
            active={entry.fingerprint === list.active}
            locked={connected}
            onlyOne={list.identities.length === 1}
            confirming={confirming === entry.fingerprint}
            onConfirm={() => setConfirming(entry.fingerprint)}
            onCancelConfirm={() => setConfirming(null)}
            onSelect={() =>
              api.setActiveIdentity(entry.fingerprint).then(applied).catch((e) => onError(String(e)))
            }
            onRelabel={(next) =>
              api
                .setIdentityLabel(entry.fingerprint, next)
                .then(setList)
                .catch((e) => onError(String(e)))
            }
            onRemove={() => {
              setConfirming(null);
              api
                .removeIdentity(entry.fingerprint)
                .then(applied)
                .catch((e) => onError(String(e)));
            }}
          />
        ))}
      </ul>

      {adding ? (
        <form className="bookmark-form" onSubmit={add}>
          <strong>New identity</strong>
          <label>
            Nickname
            <input
              autoFocus
              value={nickname}
              onChange={(e) => setNickname(e.target.value)}
              placeholder="Shown to others on a server"
            />
          </label>
          <label>
            Note <span className="muted">(private, just for you)</span>
            <input
              value={label}
              onChange={(e) => setLabel(e.target.value)}
              placeholder="e.g. gaming, work"
            />
          </label>
          <div className="row">
            <button type="submit">Create</button>
            <button type="button" className="linklike" onClick={closeAddForm}>
              cancel
            </button>
          </div>
          <p className="muted">
            A new identity starts at security level 0. Servers that set a minimum
            will refuse it until you raise the level.
          </p>
        </form>
      ) : (
        <button onClick={() => setAdding(true)}>Create an identity</button>
      )}

      <p className="muted">
        An identity is an Ed25519 key on this machine. Servers recognise you by
        its fingerprint, so it is what carries every permission you have been
        granted — back it up like an SSH key, and note that this file is not yet
        encrypted.
      </p>
    </div>
  );
}

function IdentityRow({
  entry,
  active,
  locked,
  onlyOne,
  confirming,
  onConfirm,
  onCancelConfirm,
  onSelect,
  onRelabel,
  onRemove,
}: {
  entry: VaultEntry;
  active: boolean;
  locked: boolean;
  onlyOne: boolean;
  confirming: boolean;
  onConfirm: () => void;
  onCancelConfirm: () => void;
  onSelect: () => void;
  onRelabel: (label: string) => void;
  onRemove: () => void;
}) {
  const [editingLabel, setEditingLabel] = useState(false);
  const [draft, setDraft] = useState(entry.label);

  return (
    <li className={active ? "identity-row active" : "identity-row"}>
      <div className="bookmark-main">
        <span>
          <strong>{entry.nickname}</strong>
          {active && <span className="muted"> — active</span>}
        </span>
        <span className="muted">
          <code className="fingerprint" title={entry.fingerprint}>
            {entry.short}
          </code>{" "}
          L{entry.securityLevel}
          {entry.label && ` · ${entry.label}`}
        </span>
      </div>

      {editingLabel ? (
        <input
          autoFocus
          value={draft}
          onChange={(e) => setDraft(e.target.value)}
          onBlur={() => {
            setEditingLabel(false);
            onRelabel(draft);
          }}
          onKeyDown={(e) => e.key === "Enter" && e.currentTarget.blur()}
        />
      ) : (
        <button className="linklike" onClick={() => setEditingLabel(true)}>
          note
        </button>
      )}

      {!active && (
        <button className="linklike" disabled={locked} onClick={onSelect}>
          use
        </button>
      )}

      {/* Deleting a key is irreversible and costs every permission it holds,
          so it takes a deliberate second click rather than one stray one. */}
      {confirming ? (
        <>
          <button className="danger" onClick={onRemove}>
            delete key
          </button>
          <button className="linklike" onClick={onCancelConfirm}>
            cancel
          </button>
        </>
      ) : (
        <button
          className="linklike"
          disabled={locked || onlyOne}
          title={
            onlyOne
              ? "This is your only identity."
              : locked
                ? "Disconnect first."
                : "Permanently delete this key"
          }
          onClick={onConfirm}
        >
          delete
        </button>
      )}
    </li>
  );
}
