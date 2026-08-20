// Members: role grants, keyed by fingerprint.
//
// v1 lists connected users only, with a grant-by-fingerprint form as the
// escape hatch for members who are offline — a browsable directory of every
// fingerprint the server has ever seen needs server support that does not
// exist yet. The wire's `User` carries no role list either, so a row cannot
// show what a member currently holds: the checkboxes stage a replacement set
// from scratch, and the tab says so rather than presenting blank boxes as
// "no roles".

import { useEffect, useState } from "react";
import { api, type Role, type SessionId, type User } from "../api";
import { Fingerprint } from "../Fingerprint";

export function MembersTab({
  session,
  users,
  roles,
  onError,
}: {
  session: SessionId;
  users: User[];
  roles: Role[];
  onError: (e: string) => void;
}) {
  // @everyone is held by definition, so a checkbox for it could only mislead.
  // Ranked order, so the boxes read the same way the Roles tab lists them.
  const grantable = roles
    .filter((role) => !role.isEveryone)
    .sort((a, b) => b.position - a.position);

  return (
    <>
      <p className="muted">
        Apply replaces a member's roles with exactly the boxes ticked.
      </p>

      {grantable.length === 0 && (
        <p className="muted">No roles to grant yet — create one in the Roles tab first.</p>
      )}

      {users.length === 0 ? (
        <p className="muted">Nobody is connected.</p>
      ) : (
        <ul className="admin-member-list">
          {users.map((user) => (
            <MemberRow
              key={user.clientId}
              user={user}
              roles={grantable}
              onApply={(roleIds) =>
                api
                  .setMemberRoles(session, user.fingerprint, roleIds)
                  .catch((e) => onError(String(e)))
              }
            />
          ))}
        </ul>
      )}

      {/* Pointless without a role to grant, so it appears with the first one
          rather than sitting there as a form that can do nothing. */}
      {grantable.length > 0 && (
        <GrantByFingerprint session={session} roles={grantable} onError={onError} />
      )}
    </>
  );
}

function MemberRow({
  user,
  roles,
  onApply,
}: {
  user: User;
  roles: Role[];
  onApply: (roleIds: number[]) => void;
}) {
  // Seeded from the member's real grants and re-seeded when they change
  // underneath — another admin's edit, or our own Apply echoing back as the
  // UserUpdated broadcast. Apply only wakes when the boxes differ from what
  // the server currently says, so an untouched row can never strip anyone.
  const [staged, setStaged] = useState<number[]>(user.roles);
  useEffect(() => setStaged(user.roles), [user.roles]);
  const dirty =
    staged.length !== user.roles.length || staged.some((id) => !user.roles.includes(id));

  const toggle = (roleId: number) => {
    setStaged((prev) =>
      prev.includes(roleId) ? prev.filter((id) => id !== roleId) : [...prev, roleId],
    );
  };

  const apply = () => {
    // Success is silent — the UserUpdated broadcast re-seeds this row, which
    // puts Apply back to sleep; a refusal comes back as a CommandFailed event
    // into the dialog's notice.
    onApply(staged);
  };

  return (
    <li>
      <div className="admin-member-head">
        <strong>{user.nickname}</strong>
        <span className="muted">
          <Fingerprint value={user.fingerprint} display={user.short} />
        </span>
      </div>
      <div className="admin-member-controls">
        <RolePicker roles={roles} staged={staged} onToggle={toggle} />
        <button
          disabled={!dirty}
          title={
            dirty
              ? `Set ${user.nickname}'s roles to the boxes ticked`
              : "The boxes match their current roles"
          }
          onClick={apply}
        >
          Apply
        </button>
      </div>
    </li>
  );
}

function GrantByFingerprint({
  session,
  roles,
  onError,
}: {
  session: SessionId;
  roles: Role[];
  onError: (error: string) => void;
}) {
  const [fingerprint, setFingerprint] = useState("");
  const [staged, setStaged] = useState<number[]>([]);

  const toggle = (roleId: number) =>
    setStaged((prev) =>
      prev.includes(roleId) ? prev.filter((id) => id !== roleId) : [...prev, roleId],
    );

  const submit = (event: React.FormEvent) => {
    event.preventDefault();
    const target = fingerprint.trim();
    if (!target) return;
    api
      .setMemberRoles(session, target, staged)
      .then(() => {
        // Cleared on success so the same grant cannot land twice on a stray
        // second submit — and a fresh fingerprint starts from a clean set.
        setFingerprint("");
        setStaged([]);
      })
      .catch((e) => onError(String(e)));
  };

  return (
    <form className="bookmark-form" onSubmit={submit}>
      <strong>Grant by fingerprint</strong>
      <label>
        Fingerprint
        {/* The full value, not the short form: grants key on the whole
            fingerprint, and the short form is display-only. */}
        <input
          value={fingerprint}
          onChange={(e) => setFingerprint(e.target.value)}
          placeholder="full fingerprint, for a member who is offline"
        />
      </label>
      <RolePicker roles={roles} staged={staged} onToggle={toggle} />
      <div className="row">
        <button type="submit">Apply</button>
      </div>
      <p className="muted">
        This too replaces the member's whole role set with the boxes ticked.
      </p>
    </form>
  );
}

// One checkbox per grantable role, shared between the member rows and the
// grant form so the two groups cannot drift apart.
function RolePicker({
  roles,
  staged,
  onToggle,
}: {
  roles: Role[];
  staged: number[];
  onToggle: (roleId: number) => void;
}) {
  if (roles.length === 0) return null;

  return (
    <div className="admin-role-picks">
      {roles.map((role) => (
        <label key={role.id} className="row">
          <input
            type="checkbox"
            checked={staged.includes(role.id)}
            onChange={() => onToggle(role.id)}
          />
          {/* The role's colour is data from the server, so it cannot live in
              the stylesheet. */}
          <span style={role.color ? { color: role.color } : undefined}>{role.name}</span>
        </label>
      ))}
    </div>
  );
}
