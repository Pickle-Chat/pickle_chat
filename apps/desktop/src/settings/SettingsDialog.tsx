import { useEffect, useState } from "react";
import { api, type Settings } from "../api";
import { AudioTab } from "./AudioTab";
import { BookmarksTab } from "./BookmarksTab";
import { IdentitiesTab } from "./IdentitiesTab";
import { KeybindsTab } from "./KeybindsTab";

type TabId = "identities" | "audio" | "keybinds" | "bookmarks";

const TABS: { id: TabId; label: string }[] = [
  { id: "identities", label: "Identities" },
  { id: "audio", label: "Audio" },
  { id: "keybinds", label: "Keys" },
  { id: "bookmarks", label: "Servers" },
];

export function SettingsDialog({
  connected,
  onSettingsChange,
  onIdentityChanged,
  onClose,
}: {
  connected: boolean;
  /// Kept in step with the app, which needs the keybinds for its focus-scoped
  /// push-to-talk fallback.
  onSettingsChange: (settings: Settings) => void;
  /// The titlebar badge shows the active identity and has to be refreshed when
  /// it changes here.
  onIdentityChanged: () => void;
  onClose: () => void;
}) {
  const [settings, setSettings] = useState<Settings | null>(null);
  const [tab, setTab] = useState<TabId>("audio");
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    api.settings().then(setSettings).catch((e) => setError(String(e)));
  }, []);

  const update = (next: Settings) => {
    setSettings(next);
    onSettingsChange(next);
  };

  // Escape closes, which is what a dialog is expected to do and the only way
  // out while a key is being rebound and ordinary clicks are being swallowed.
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
        aria-label="Settings"
        // Clicks inside must not reach the backdrop's close handler.
        onClick={(e) => e.stopPropagation()}
      >
        <header>
          <strong>Settings</strong>
          <button className="linklike" onClick={onClose} aria-label="Close settings">
            ×
          </button>
        </header>

        {error && (
          <div className="banner error" role="alert">
            {error}
            <button onClick={() => setError(null)} aria-label="Dismiss">
              ×
            </button>
          </div>
        )}

        <div className="settings-body">
          <nav className="settings-tabs" role="tablist">
            {TABS.map((entry) => (
              <button
                key={entry.id}
                role="tab"
                aria-selected={tab === entry.id}
                className={tab === entry.id ? "active" : undefined}
                onClick={() => setTab(entry.id)}
              >
                {entry.label}
              </button>
            ))}
          </nav>

          {tab === "identities" ? (
            <IdentitiesTab
              connected={connected}
              onActiveChanged={onIdentityChanged}
              onError={setError}
            />
          ) : settings === null ? (
            <p className="muted settings-pane">Loading…</p>
          ) : tab === "audio" ? (
            <AudioTab
              audio={settings.audio}
              connected={connected}
              onChange={(audio) => update({ ...settings, audio })}
              onError={setError}
            />
          ) : tab === "keybinds" ? (
            <KeybindsTab
              keybinds={settings.keybinds}
              onChange={(keybinds) => update({ ...settings, keybinds })}
              onError={setError}
            />
          ) : (
            <BookmarksTab onError={setError} />
          )}
        </div>
      </div>
    </div>
  );
}
