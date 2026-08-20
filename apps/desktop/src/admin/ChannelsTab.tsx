// The Channels tab of the admin dialog: per-channel overwrites.
//
// Channel create/rename/delete is a later PR. What lives here is the
// tri-state editor for who can see and use one channel beyond what roles
// grant — allow and deny per target, with inherit as the deliberate absence
// of an opinion.

import { useEffect, useState } from "react";
import {
  api,
  type Channel,
  type Overwrite,
  type OverwriteTarget,
  type Permission,
  type Role,
  type SessionId,
} from "../api";
import { Fingerprint } from "../Fingerprint";

/** Only the channel-scoped names appear in the grid: the server-wide ones
    (administrator, manageRoles, …) are not resolved per channel, so an
    overwrite naming them would sit in the list and do nothing. */
const CHANNEL_PERMISSIONS: { name: Permission; label: string }[] = [
  { name: "viewChannel", label: "View channel" },
  { name: "sendMessages", label: "Send messages" },
  { name: "readHistory", label: "Read history" },
  { name: "manageMessages", label: "Manage messages" },
  { name: "connect", label: "Connect" },
  { name: "speak", label: "Speak" },
  { name: "muteMembers", label: "Mute members" },
  { name: "moveMembers", label: "Move members" },
];

type Tri = "allow" | "inherit" | "deny";

const TRI_STATES: { value: Tri; glyph: string; title: string }[] = [
  { value: "allow", glyph: "✓", title: "Allow" },
  { value: "inherit", glyph: "/", title: "Inherit — whatever roles say" },
  { value: "deny", glyph: "✕", title: "Deny" },
];

/// A staged overwrite, exactly as setChannelOverwrite will send it: the full
/// allow and deny lists, with inherit as absence from both.
interface Draft {
  allow: Permission[];
  deny: Permission[];
}

/// Roles and members are keyed differently on the wire; this is the one
/// string the stage, the mirror rows, and React keys all agree on.
const keyOf = (target: OverwriteTarget) =>
  target.kind === "role" ? `role:${target.id}` : `member:${target.fingerprint}`;

export function ChannelsTab({
  session,
  channels,
  roles,
  onError,
}: {
  session: SessionId;
  channels: Channel[];
  roles: Role[];
  onError: (e: string) => void;
}) {
  const [selected, setSelected] = useState<number | null>(null);
  // The one copy of server state this tab holds, and deliberately so:
  // nothing pushes the raw overwrite list — permissionsChanged carries our
  // resolved booleans, never the per-target lists — so the mirror is read on
  // selection and re-read after every mutation.
  const [overwrites, setOverwrites] = useState<Overwrite[] | null>(null);
  /// Bumped after every mutation; the load effect below is the only reader.
  const [generation, setGeneration] = useState(0);
  const [drafts, setDrafts] = useState<Record<string, Draft>>({});
  /// Targets staged from the picker but never yet sent: all-inherit rows
  /// that save and render like any other.
  const [added, setAdded] = useState<OverwriteTarget[]>([]);
  /// Text of the member-fingerprint field; null while the field is closed.
  const [memberDraft, setMemberDraft] = useState<string | null>(null);

  const channel = channels.find((c) => c.id === selected);
  // channelRemoved — or losing viewChannel — can take the selection away
  // while the dialog is open. The stale id is kept so the note below stays
  // up until the next pick; everything else renders as none-selected.
  const vanished = selected !== null && channel === undefined;

  useEffect(() => {
    if (channel === undefined) return;
    // Every load goes through here, post-mutation re-reads included (via
    // `generation`), so this one staleness guard covers a reply that lands
    // after the user has moved on to another channel.
    let stale = false;
    api
      .channelOverwrites(session, channel.id)
      .then((list) => {
        if (!stale) setOverwrites(list);
      })
      .catch((e) => onError(String(e)));
    return () => {
      stale = true;
    };
  }, [session, channel?.id, generation, onError]);

  const pick = (id: number | null) => {
    setSelected(id);
    setOverwrites(null);
    setDrafts({});
    setAdded([]);
    setMemberDraft(null);
  };

  const dropDraft = (key: string) =>
    setDrafts((d) => Object.fromEntries(Object.entries(d).filter(([k]) => k !== key)));

  // A mutation went through: the stage for that row is spent, and the mirror
  // decides what the row shows next.
  const applied = (key: string) => {
    dropDraft(key);
    setAdded((a) => a.filter((t) => keyOf(t) !== key));
    setGeneration((g) => g + 1);
  };

  const setTri = (key: string, base: Draft, perm: Permission, state: Tri) => {
    const allow = base.allow.filter((p) => p !== perm);
    const deny = base.deny.filter((p) => p !== perm);
    if (state === "allow") allow.push(perm);
    if (state === "deny") deny.push(perm);
    setDrafts((d) => ({ ...d, [key]: { allow, deny } }));
  };

  const save = (target: OverwriteTarget, staged: Draft) => {
    if (channel === undefined) return;
    api
      .setChannelOverwrite(session, channel.id, target, staged.allow, staged.deny)
      .then(() => applied(keyOf(target)))
      .catch((e) => onError(String(e)));
  };

  const remove = (target: OverwriteTarget, onServer: boolean) => {
    const key = keyOf(target);
    if (!onServer) {
      // Never sent; discarding the stage is the whole delete.
      setAdded((a) => a.filter((t) => keyOf(t) !== key));
      dropDraft(key);
      return;
    }
    if (channel === undefined) return;
    api
      .deleteChannelOverwrite(session, channel.id, target)
      .then(() => applied(key))
      .catch((e) => onError(String(e)));
  };

  const addTarget = (target: OverwriteTarget) => {
    const key = keyOf(target);
    const present =
      (overwrites ?? []).some((o) => keyOf(o.target) === key) ||
      added.some((t) => keyOf(t) === key);
    // One row per target — the existing row is already the editor for it.
    if (present) return;
    setAdded((a) => [...a, target]);
    setDrafts((d) => ({ ...d, [key]: { allow: [], deny: [] } }));
  };

  const rows: { target: OverwriteTarget; saved: Overwrite | null }[] =
    overwrites === null
      ? []
      : [
          ...overwrites.map((o) => ({ target: o.target, saved: o })),
          // Another admin can create the overwrite we have staged; the
          // mirror's row wins, and our stage becomes its pending edit.
          ...added
            .filter((t) => !overwrites.some((o) => keyOf(o.target) === keyOf(t)))
            .map((t) => ({ target: t, saved: null })),
        ];

  // The reducer appends creations rather than sorting, so order here.
  const ordered = [...channels].sort((a, b) => a.order - b.order);

  return (
    <>
      <label>
        Channel
        <select
          value={channel === undefined ? "" : String(channel.id)}
          onChange={(e) => pick(e.target.value === "" ? null : Number(e.target.value))}
        >
          <option value="">— none —</option>
          {ordered.map((c) => (
            <option key={c.id} value={c.id}>
              {c.parent !== null && " "}
              {c.name}
            </option>
          ))}
        </select>
      </label>

      {vanished && (
        <p className="muted">
          The channel you were editing is gone — deleted, or no longer visible
          to you. Pick another.
        </p>
      )}

      {channel === undefined && !vanished && (
        <p className="muted">Pick a channel to edit who can see and use it.</p>
      )}

      {channel !== undefined &&
        (overwrites === null ? (
          <p className="muted">Loading…</p>
        ) : (
          <>
            {rows.length === 0 ? (
              <p className="muted">
                No overwrites — everyone sees this channel exactly as their
                roles allow.
              </p>
            ) : (
              <ul className="admin-overwrite-list">
                {rows.map(({ target, saved }) => {
                  const key = keyOf(target);
                  const staged =
                    drafts[key] ??
                    (saved !== null
                      ? { allow: saved.allow, deny: saved.deny }
                      : { allow: [], deny: [] });
                  return (
                    <OverwriteRow
                      key={key}
                      label={
                        target.kind === "member" ? (
                          <Fingerprint
                            value={target.fingerprint}
                            display={`${target.fingerprint.slice(0, 9)}…`}
                          />
                        ) : (
                          // An overwrite can outlive its role for a moment
                          // between broadcasts; show the id rather than
                          // pretend the row is not there.
                          <strong>
                            {roles.find((r) => r.id === target.id)?.name ??
                              `role #${target.id}`}
                          </strong>
                        )
                      }
                      staged={staged}
                      dirty={key in drafts}
                      unsaved={saved === null}
                      onSet={(perm, state) => setTri(key, staged, perm, state)}
                      onSave={() => save(target, staged)}
                      onDelete={() => remove(target, saved !== null)}
                    />
                  );
                })}
              </ul>
            )}

            <div className="admin-add">
              {/* A menu wearing a select: controlled back to the placeholder,
                  so the same choice can fire again next time. */}
              <select
                value=""
                aria-label="Add an overwrite"
                onChange={(e) => {
                  const value = e.target.value;
                  if (value === "member") setMemberDraft("");
                  else if (value !== "") addTarget({ kind: "role", id: Number(value) });
                }}
              >
                <option value="" disabled>
                  Add an overwrite…
                </option>
                {roles.map((role) => (
                  <option key={role.id} value={role.id}>
                    {role.name}
                  </option>
                ))}
                <option value="member">member fingerprint…</option>
              </select>
            </div>

            {memberDraft !== null && (
              <form
                className="admin-add"
                onSubmit={(e) => {
                  e.preventDefault();
                  const fingerprint = memberDraft.trim();
                  if (!fingerprint) return;
                  addTarget({ kind: "member", fingerprint });
                  setMemberDraft(null);
                }}
              >
                {/* By fingerprint rather than by picking an online user: an
                    overwrite can name someone who is not connected. */}
                <input
                  autoFocus
                  value={memberDraft}
                  onChange={(e) => setMemberDraft(e.target.value)}
                  placeholder="Full fingerprint of the member"
                />
                <button type="submit">Add</button>
                <button
                  type="button"
                  className="linklike"
                  onClick={() => setMemberDraft(null)}
                >
                  cancel
                </button>
              </form>
            )}

            <p className="muted">
              Allow and deny are exceptions for this one channel; inherit
              leaves the answer to roles. Nothing is sent until a row is
              saved.
            </p>
          </>
        ))}
    </>
  );
}

function OverwriteRow({
  label,
  staged,
  dirty,
  unsaved,
  onSet,
  onSave,
  onDelete,
}: {
  label: React.ReactNode;
  staged: Draft;
  /// Whether the stage differs from the mirror — the Save button's cue.
  dirty: boolean;
  /// A row from the picker that has never been sent: its delete is local.
  unsaved: boolean;
  onSet: (perm: Permission, state: Tri) => void;
  onSave: () => void;
  onDelete: () => void;
}) {
  return (
    <li className="admin-overwrite">
      <div className="admin-overwrite-head">
        {label}
        {unsaved && <span className="muted">not saved yet</span>}
        <span className="admin-overwrite-actions">
          {dirty && <button onClick={onSave}>Save</button>}
          <button className="linklike" onClick={onDelete}>
            remove
          </button>
        </span>
      </div>

      <div className="admin-tri-grid">
        {CHANNEL_PERMISSIONS.map(({ name, label: permission }) => {
          const state: Tri = staged.allow.includes(name)
            ? "allow"
            : staged.deny.includes(name)
              ? "deny"
              : "inherit";
          return (
            <div className="admin-tri" key={name}>
              <span className="admin-tri-name">{permission}</span>
              <span
                className="admin-tri-buttons"
                role="radiogroup"
                aria-label={permission}
              >
                {TRI_STATES.map(({ value, glyph, title }) => (
                  <button
                    key={value}
                    type="button"
                    role="radio"
                    aria-checked={state === value}
                    className={
                      state === value ? `admin-tri-${value} on` : `admin-tri-${value}`
                    }
                    title={title}
                    aria-label={title}
                    onClick={() => onSet(name, value)}
                  >
                    {glyph}
                  </button>
                ))}
              </span>
            </div>
          );
        })}
      </div>
    </li>
  );
}
