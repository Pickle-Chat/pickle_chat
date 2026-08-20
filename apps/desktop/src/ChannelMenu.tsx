// The right-click surface for acting on a channel.
//
// Offered only to members with admin standing — for everyone else the row
// keeps the ordinary browser menu. Deletion confirms in place and says what
// happens to the history, because "delete" on a room full of conversation
// should never be one accidental click.

import { useEffect, useRef, useState } from "react";
import { api, type Channel, type SessionId } from "./api";

export interface ChannelMenuTarget {
  channel: Channel;
  x: number;
  y: number;
}

export function ChannelMenu({
  session,
  target,
  onEditPermissions,
  onClose,
  onError,
}: {
  session: SessionId;
  target: ChannelMenuTarget;
  /// Opens the admin dialog on this channel — where the permission grid and
  /// the channel editor live side by side, so one entry covers both.
  onEditPermissions: () => void;
  onClose: () => void;
  onError: (error: string) => void;
}) {
  const [confirmingDelete, setConfirmingDelete] = useState(false);
  const menu = useRef<HTMLDivElement>(null);

  useEffect(() => {
    const away = (e: MouseEvent) => {
      if (!menu.current?.contains(e.target as Node)) onClose();
    };
    const key = (e: KeyboardEvent) => {
      if (e.key === "Escape") onClose();
    };
    window.addEventListener("mousedown", away);
    window.addEventListener("keydown", key);
    return () => {
      window.removeEventListener("mousedown", away);
      window.removeEventListener("keydown", key);
    };
  }, [onClose]);

  return (
    <div
      ref={menu}
      className="user-menu"
      role="menu"
      style={{ left: target.x, top: target.y }}
    >
      <div className="user-menu-title">
        {target.channel.name}
        <code>{target.channel.hasVoice ? "voice" : ""}{target.channel.hasVoice && target.channel.hasText ? " + " : ""}{target.channel.hasText ? "text" : ""}</code>
      </div>

      <button
        role="menuitem"
        onClick={() => {
          onEditPermissions();
          onClose();
        }}
      >
        Edit channel & permissions
      </button>
      {confirmingDelete ? (
        <button
          role="menuitem"
          className="danger"
          onClick={() => {
            api.deleteChannel(session, target.channel.id).catch((e) => onError(String(e)));
            onClose();
          }}
        >
          Really delete? Its messages are kept, orphaned.
        </button>
      ) : (
        <button role="menuitem" className="danger" onClick={() => setConfirmingDelete(true)}>
          Delete channel…
        </button>
      )}
    </div>
  );
}
