import { useState } from "react";
import {
  api,
  type MyPermissions,
  type Permission,
  type Role,
  type SessionId,
} from "../api";

// Grouped the way the bits act — shaping the server versus acting inside a
// channel — with each group in api.ts order so the two lists stay comparable.
const SERVER_BITS: Permission[] = [
  "administrator",
  "manageServer",
  "manageRoles",
  "manageChannels",
  "kickMembers",
  "banMembers",
];

const CHANNEL_BITS: Permission[] = [
  "viewChannel",
  "sendMessages",
  "readHistory",
  "manageMessages",
  "connect",
  "speak",
  "muteMembers",
  "moveMembers",
];

/** "manageServer" → "manage server" — the wire names are already words. */
const labelOf = (bit: Permission) => bit.replace(/[A-Z]/g, (c) => ` ${c.toLowerCase()}`);

/** Exactly the shape updateRole takes, so the diff below cannot drift from it. */
type RolePatch = Parameters<typeof api.updateRole>[2];

export function RolesTab({
  session,
  roles,
  permissions,
  onError,
}: {
  session: SessionId;
  roles: Role[];
  permissions: MyPermissions;
  onError: (e: string) => void;
}) {
  const [open, setOpen] = useState<number | null>(null);
  const [confirming, setConfirming] = useState<number | null>(null);
  const [newName, setNewName] = useState("");

  // Rendered senior-first exactly as given, except @everyone is pinned to the
  // bottom no matter what the wire said: it is the floor every member stands
  // on, not a rung that can be outranked.
  const movable = roles.filter((role) => !role.isEveryone);
  const everyone = roles.find((role) => role.isEveryone);
  const ordered = everyone ? [...movable, everyone] : movable;

  const move = (index: number, delta: -1 | 1) => {
    const next = [...movable];
    const other = index + delta;
    [next[index], next[other]] = [next[other], next[index]];
    // One swap on screen, but the wire takes the whole permutation: every id
    // with its new position, dense, seniors high, @everyone anchored at 0.
    const positions = next.map((role, i): [number, number] => [role.id, next.length - i]);
    if (everyone) positions.push([everyone.id, 0]);
    api.reorderRoles(session, positions).catch((e) => onError(String(e)));
  };

  // Resolution means the command went out, not that it was accepted — a
  // refusal comes back as a CommandFailed event into the dialog's banner, and
  // the rolesChanged that follows an acceptance is what redraws the list.
  const save = (roleId: number, patch: RolePatch) =>
    api
      .updateRole(session, roleId, patch)
      .then(() => setOpen(null))
      .catch((e) => onError(String(e)));

  const remove = (role: Role) => {
    setConfirming(null);
    if (open === role.id) setOpen(null);
    api.deleteRole(session, role.id).catch((e) => onError(String(e)));
  };

  const create = (event: React.FormEvent) => {
    event.preventDefault();
    const name = newName.trim();
    if (!name) return;
    // New roles start powerless: bits are granted deliberately in the editor,
    // never guessed at creation.
    api
      .createRole(session, name, [])
      .then(() => setNewName(""))
      .catch((e) => onError(String(e)));
  };

  // The dialog supplies the surrounding .settings-pane, so the tab renders
  // bare content rather than nesting a second pane's padding inside it.
  return (
    <>
      {/* Affordance only — the server is the gate, and its refusals land in
          the dialog's banner with a reason. Nothing here is disabled. */}
      {!permissions.isAdmin && !permissions.isOwner && (
        <p className="muted">
          You are not an administrator here. Everything below is visible, but
          the server will refuse changes.
        </p>
      )}

      <ul className="admin-role-list">
        {ordered.map((role, index) => (
          <li key={role.id}>
            <div className={open === role.id ? "admin-role-row open" : "admin-role-row"}>
              <span
                className={role.color ? "admin-role-chip" : "admin-role-chip unset"}
                style={role.color ? { background: role.color } : undefined}
                aria-hidden="true"
              />
              <button
                className="admin-role-name"
                aria-expanded={open === role.id}
                onClick={() => setOpen(open === role.id ? null : role.id)}
              >
                {role.name}
              </button>

              {!role.isEveryone && (
                <>
                  <button
                    className="admin-move"
                    disabled={index === 0}
                    onClick={() => move(index, -1)}
                    title="Move up — outranks one more role"
                    aria-label={`Move ${role.name} up`}
                  >
                    ↑
                  </button>
                  <button
                    className="admin-move"
                    disabled={index === movable.length - 1}
                    onClick={() => move(index, 1)}
                    title="Move down — outranked by one more role"
                    aria-label={`Move ${role.name} down`}
                  >
                    ↓
                  </button>

                  {/* Deleting a role strips it from every member holding it,
                      so it takes a deliberate second click, not a stray one. */}
                  {confirming === role.id ? (
                    <>
                      <button className="danger" onClick={() => remove(role)}>
                        delete role
                      </button>
                      <button className="linklike" onClick={() => setConfirming(null)}>
                        cancel
                      </button>
                    </>
                  ) : (
                    <button className="linklike" onClick={() => setConfirming(role.id)}>
                      delete
                    </button>
                  )}
                </>
              )}
            </div>

            {open === role.id && (
              <RoleEditor
                role={role}
                onSave={(patch) => save(role.id, patch)}
                onCancel={() => setOpen(null)}
              />
            )}
          </li>
        ))}
      </ul>

      <p className="muted">
        Order is rank: a role outranks every role below it, and @everyone is
        the baseline each member holds.
      </p>

      <form className="bookmark-form" onSubmit={create}>
        <strong>New role</strong>
        <label>
          Name
          <input
            value={newName}
            onChange={(e) => setNewName(e.target.value)}
            placeholder="e.g. moderators"
          />
        </label>
        <div className="row">
          <button type="submit">Create</button>
        </div>
        <p className="muted">A new role starts with no permissions — open it to grant them.</p>
      </form>
    </>
  );
}

function RoleEditor({
  role,
  onSave,
  onCancel,
}: {
  role: Role;
  onSave: (patch: RolePatch) => void;
  onCancel: () => void;
}) {
  // The draft is the only place edits live before Save; the roles prop stays
  // the server's truth. A concurrent edit elsewhere redraws the row above,
  // never this.
  const [name, setName] = useState(role.name);
  const [color, setColor] = useState<string | null>(role.color);
  const [bits, setBits] = useState<Permission[]>(role.permissions);

  const toggle = (bit: Permission) =>
    setBits((prev) =>
      prev.includes(bit) ? prev.filter((b) => b !== bit) : [...prev, bit],
    );

  const save = () => {
    // Only what changed goes on the wire, diffed against the current prop so
    // an untouched field never overwrites an edit that landed meanwhile.
    const patch: RolePatch = {};
    const trimmed = name.trim();
    if (!role.isEveryone && trimmed && trimmed !== role.name) patch.name = trimmed;
    // The input reports lowercase and the server may store either case, so an
    // untouched colour must not read as a change.
    if ((color ?? "").toLowerCase() !== (role.color ?? "").toLowerCase()) {
      patch.color = color === null ? null : parseInt(color.slice(1), 16);
    }
    if (
      bits.length !== role.permissions.length ||
      bits.some((bit) => !role.permissions.includes(bit))
    ) {
      patch.permissions = bits;
    }
    // Nothing changed is a cancel, not an empty command.
    if (Object.keys(patch).length === 0) {
      onCancel();
      return;
    }
    onSave(patch);
  };

  return (
    <div className="admin-role-editor">
      {/* @everyone cannot be renamed and carries no colour of its own, so its
          editor collapses to just the bits. */}
      {!role.isEveryone && (
        <>
          <label>
            Name
            <input value={name} onChange={(e) => setName(e.target.value)} />
          </label>
          <label className="row">
            Colour
            {/* type=color cannot be empty, so an unset colour previews as a
                neutral grey; whether one is actually set is carried by the
                control beside it. */}
            <input
              type="color"
              value={color ?? "#808080"}
              onChange={(e) => setColor(e.target.value)}
            />
            {color !== null ? (
              <button type="button" className="linklike" onClick={() => setColor(null)}>
                clear
              </button>
            ) : (
              <span className="muted">default</span>
            )}
          </label>
        </>
      )}

      <div className="admin-perm-groups">
        <PermGroup title="Server" bits={SERVER_BITS} held={bits} onToggle={toggle} />
        <PermGroup title="Channel" bits={CHANNEL_BITS} held={bits} onToggle={toggle} />
      </div>

      <div className="row">
        <button onClick={save}>Save</button>
        <button className="linklike" onClick={onCancel}>
          cancel
        </button>
      </div>
    </div>
  );
}

function PermGroup({
  title,
  bits,
  held,
  onToggle,
}: {
  title: string;
  bits: Permission[];
  held: Permission[];
  onToggle: (bit: Permission) => void;
}) {
  return (
    <div className="admin-perm-group">
      <span className="settings-label">{title}</span>
      <div className="admin-perm-grid">
        {bits.map((bit) => (
          <label key={bit}>
            <input
              type="checkbox"
              checked={held.includes(bit)}
              onChange={() => onToggle(bit)}
            />
            {labelOf(bit)}
          </label>
        ))}
      </div>
    </div>
  );
}
