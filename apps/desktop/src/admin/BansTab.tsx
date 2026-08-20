import { useEffect, useState } from "react";
import { api, type BanEntry, type SessionId } from "../api";

export function BansTab({
  session,
  bans,
  onError,
}: {
  session: SessionId;
  /// Null until the first banList event lands. "Not fetched yet" and "no
  /// bans" must read differently, so the reducer starts at null, not [].
  bans: BanEntry[] | null;
  onError: (error: string) => void;
}) {
  const [confirming, setConfirming] = useState<string | null>(null);

  // listBans returns nothing: the reply is a banList event into the reducer,
  // and this tab renders whatever the reducer holds. A copy kept here would be
  // a second source of truth, free to drift from it.
  useEffect(() => {
    api.listBans(session).catch((e) => onError(String(e)));
  }, [session, onError]);

  const refresh = () => api.listBans(session).catch((e) => onError(String(e)));

  const unban = (fingerprint: string) => {
    setConfirming(null);
    // The server does not push ban-list changes, so a successful unban is
    // followed by a fresh fetch rather than an optimistic local edit.
    api
      .unban(session, fingerprint)
      .then(() => api.listBans(session))
      .catch((e) => onError(String(e)));
  };

  if (bans === null) {
    return <p className="muted">Fetching the ban list…</p>;
  }

  const now = Date.now();

  return (
    <>
      {bans.length === 0 ? (
        <p className="muted">No bans.</p>
      ) : (
        <ul className="bookmark-list">
          {bans.map((ban) => {
            const expired = ban.untilUnixMs !== null && ban.untilUnixMs <= now;
            return (
              <li key={ban.fingerprint}>
                <div className="bookmark-main">
                  <span>
                    <code className="fingerprint">{ban.short}</code>
                    {expired && <span className="muted"> · expired</span>}
                  </span>
                  <span className="muted">
                    {ban.reason && `${ban.reason} · `}
                    {ban.untilUnixMs === null
                      ? "permanent"
                      : `until ${new Date(ban.untilUnixMs).toLocaleString()}`}
                    {` · by ${ban.issuedByShort}`}
                  </span>
                </div>

                {/* Unbanning readmits someone a moderator deliberately shut
                    out, so it takes a second click rather than one stray one. */}
                {confirming === ban.fingerprint ? (
                  <>
                    <button onClick={() => unban(ban.fingerprint)}>
                      confirm unban
                    </button>
                    <button
                      className="linklike"
                      onClick={() => setConfirming(null)}
                    >
                      cancel
                    </button>
                  </>
                ) : (
                  <button
                    className="linklike"
                    onClick={() => setConfirming(ban.fingerprint)}
                  >
                    unban
                  </button>
                )}
              </li>
            );
          })}
        </ul>
      )}

      <button onClick={refresh}>Refresh</button>

      <p className="muted">
        An expired ban no longer keeps anyone out, but it stays listed until it
        is unbanned — the list is the server's moderation record, not just what
        is currently enforced.
      </p>
    </>
  );
}
