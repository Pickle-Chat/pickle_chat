// The per-server administration surface.
//
// Everything here renders from the connection's reducer state — roles, users,
// channels, bans — so an edit made by another admin appears in this open
// dialog the moment its broadcast lands, with no refresh. The tabs call the
// api and never keep copies of server state; refusals arrive as CommandFailed
// events into the same per-tab notice the rest of the connection uses.

import { useEffect, useState } from "react";
import type { ConnectionState } from "../connections";
import { BansTab } from "./BansTab";
import { ChannelsTab } from "./ChannelsTab";
import { MembersTab } from "./MembersTab";
import { RolesTab } from "./RolesTab";

type TabId = "roles" | "members" | "channels" | "bans";

const TABS: { id: TabId; label: string }[] = [
  { id: "roles", label: "Roles" },
  { id: "members", label: "Members" },
  { id: "channels", label: "Channels" },
  { id: "bans", label: "Bans" },
];

export function AdminDialog({
  connection,
  initialChannel,
  onError,
  onClose,
}: {
  connection: ConnectionState;
  /// Right-clicking a channel opens the dialog straight onto its permissions.
  initialChannel?: number;
  onError: (error: string) => void;
  onClose: () => void;
}) {
  const [tab, setTab] = useState<TabId>(initialChannel === undefined ? "roles" : "channels");

  useEffect(() => {
    const onKey = (event: KeyboardEvent) => {
      if (event.key === "Escape") onClose();
    };
    window.addEventListener("keydown", onKey);
    return () => window.removeEventListener("keydown", onKey);
  }, [onClose]);

  return (
    <div className="modal-backdrop" onClick={onClose}>
      <div
        className="modal settings"
        role="dialog"
        aria-modal="true"
        aria-label={`Administration — ${connection.info.serverName}`}
        onClick={(e) => e.stopPropagation()}
      >
        <header>
          <strong>{connection.info.serverName}</strong>
          <button className="icon" onClick={onClose} aria-label="Close">
            ×
          </button>
        </header>

        <div className="settings-body">
          <nav className="settings-tabs" role="tablist">
            {TABS.map((t) => (
              <button
                key={t.id}
                role="tab"
                aria-selected={tab === t.id}
                className={tab === t.id ? "active" : undefined}
                onClick={() => setTab(t.id)}
              >
                {t.label}
              </button>
            ))}
          </nav>

          <div className="settings-pane">
            {tab === "roles" && (
              <RolesTab
                session={connection.session}
                roles={connection.roles}
                permissions={connection.permissions}
                onError={onError}
              />
            )}
            {tab === "members" && (
              <MembersTab
                session={connection.session}
                users={connection.users}
                roles={connection.roles}
                onError={onError}
              />
            )}
            {tab === "channels" && (
              <ChannelsTab
                session={connection.session}
                channels={connection.channels}
                roles={connection.roles}
                initialSelected={initialChannel}
                onError={onError}
              />
            )}
            {tab === "bans" && (
              <BansTab session={connection.session} bans={connection.bans} onError={onError} />
            )}
          </div>
        </div>
      </div>
    </div>
  );
}
