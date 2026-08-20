// The right-click surface for acting on a member.
//
// Options come from the Rust-side mirror at open — always fresh, and computed
// by the same rules the server enforces — so what this menu offers and what
// the server accepts cannot drift. Disabled entries carry the one honest
// sentence the mirror gives for why. The server re-checks everything
// regardless; a stale menu produces a CommandFailed notice, never a wrong
// action.

import { useEffect, useRef, useState } from "react";
import { writeText } from "@tauri-apps/plugin-clipboard-manager";
import { api, type Channel, type ModerationOptions, type SessionId, type User } from "./api";

export interface MenuTarget {
  user: User;
  x: number;
  y: number;
}

export function UserMenu({
  session,
  target,
  channels,
  onClose,
  onError,
}: {
  session: SessionId;
  target: MenuTarget;
  channels: Channel[];
  onClose: () => void;
  onError: (error: string) => void;
}) {
  const [options, setOptions] = useState<ModerationOptions | null>(null);
  const [confirmingBan, setConfirmingBan] = useState(false);
  const [banReason, setBanReason] = useState("");
  const menu = useRef<HTMLDivElement>(null);

  useEffect(() => {
    api
      .moderationOptions(session, target.user.clientId)
      .then(setOptions)
      .catch((e) => onError(String(e)));
  }, [session, target.user.clientId, onError]);

  // Click-away and Escape both close; the menu is transient by nature.
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

  const act = (action: Promise<void>) => {
    action.catch((e) => onError(String(e)));
    onClose();
  };

  const voiceChannels = channels.filter((c) => c.hasVoice);
  const none =
    options && !options.canKick && !options.canBan && !options.canMute && !options.canMove;

  return (
    <div
      ref={menu}
      className="user-menu"
      role="menu"
      style={{ left: target.x, top: target.y }}
    >
      <div className="user-menu-title">
        {target.user.nickname}
        <code>{target.user.short}</code>
      </div>

      <button
        role="menuitem"
        onClick={() => {
          writeText(target.user.fingerprint).catch(() => {});
          onClose();
        }}
      >
        Copy fingerprint
      </button>

      {options === null ? (
        <div className="user-menu-note">…</div>
      ) : none ? (
        // One honest sentence instead of four grey entries.
        <div className="user-menu-note">{options.reason}</div>
      ) : (
        <>
          {options.canMute && (
            <button
              role="menuitem"
              onClick={() =>
                act(
                  api.setServerMuted(
                    session,
                    target.user.clientId,
                    !target.user.serverMuted,
                  ),
                )
              }
            >
              {target.user.serverMuted ? "Server unmute" : "Server mute"}
            </button>
          )}
          {options.canMove && target.user.channel !== null && (
            <button
              role="menuitem"
              onClick={() => act(api.moveUser(session, target.user.clientId, null))}
            >
              Disconnect from voice
            </button>
          )}
          {options.canMove &&
            voiceChannels
              .filter((c) => c.id !== target.user.channel)
              .map((c) => (
                <button
                  key={c.id}
                  role="menuitem"
                  onClick={() => act(api.moveUser(session, target.user.clientId, c.id))}
                >
                  Move to {c.name}
                </button>
              ))}
          {options.canKick && (
            <button
              role="menuitem"
              className="danger"
              onClick={() => act(api.kick(session, target.user.clientId))}
            >
              Kick
            </button>
          )}
          {options.canBan && !confirmingBan && (
            <button role="menuitem" className="danger" onClick={() => setConfirmingBan(true)}>
              Ban…
            </button>
          )}
          {confirmingBan && (
            <form
              className="user-menu-ban"
              onSubmit={(e) => {
                e.preventDefault();
                act(api.ban(session, target.user.fingerprint, banReason || "banned"));
              }}
            >
              <input
                autoFocus
                placeholder="Reason"
                value={banReason}
                onChange={(e) => setBanReason(e.target.value)}
              />
              <button type="submit" className="danger">
                Ban
              </button>
            </form>
          )}
        </>
      )}
    </div>
  );
}
