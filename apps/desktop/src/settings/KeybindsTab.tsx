import { useEffect, useState } from "react";
import { api, type BindingStatus, type KeybindAction, type Keybinds } from "../api";
import { captureAccelerator, describeAccelerator } from "../keys";

const BINDINGS: { action: KeybindAction; label: string; help: string }[] = [
  {
    action: "pushToTalk",
    label: "Push to talk",
    help: "Held to transmit, when 'When to transmit' is set to push to talk.",
  },
  { action: "toggleMute", label: "Toggle mute", help: "" },
  { action: "toggleDeafen", label: "Toggle deafen", help: "" },
];

export function KeybindsTab({
  keybinds,
  onChange,
  onError,
}: {
  keybinds: Keybinds;
  onChange: (keybinds: Keybinds) => void;
  onError: (error: string) => void;
}) {
  const [statuses, setStatuses] = useState<BindingStatus[]>([]);
  const [capturing, setCapturing] = useState<KeybindAction | null>(null);
  const [problem, setProblem] = useState<string | null>(null);

  useEffect(() => {
    api.keybindStatus().then(setStatuses).catch((e) => onError(String(e)));
  }, [onError]);

  const save = (next: Keybinds) => {
    onChange(next);
    api.setKeybinds(next).then(setStatuses).catch((e) => onError(String(e)));
  };

  // Capture runs on the window so it catches keys the button itself would never
  // see, and swallows the press so binding Space or Enter does not also
  // activate whatever is focused.
  useEffect(() => {
    if (capturing === null) return;

    const onKeyDown = (event: KeyboardEvent) => {
      event.preventDefault();
      event.stopPropagation();

      if (event.key === "Escape") {
        setCapturing(null);
        setProblem(null);
        return;
      }

      const { accelerator, problem } = captureAccelerator(event);
      if (!accelerator) {
        setProblem(problem ?? "That key cannot be bound.");
        return;
      }

      setProblem(null);
      setCapturing(null);
      save({ ...keybinds, [capturing]: accelerator });
    };

    window.addEventListener("keydown", onKeyDown, true);
    return () => window.removeEventListener("keydown", onKeyDown, true);
  }, [capturing, keybinds]);

  const anyRefused = statuses.some((status) => !status.registered);

  return (
    <div className="settings-pane">
      {BINDINGS.map((binding) => {
        const accelerator = keybinds[binding.action];
        const status = statuses.find((s) => s.action === binding.action);

        return (
          <div key={binding.action} className="settings-field">
            <span className="settings-label">{binding.label}</span>
            <div className="keybind-row">
              <button
                className={capturing === binding.action ? "capturing" : undefined}
                onClick={() => {
                  setProblem(null);
                  setCapturing(binding.action);
                }}
              >
                {capturing === binding.action
                  ? "Press a key… (Escape to cancel)"
                  : accelerator
                    ? describeAccelerator(accelerator)
                    : "Not bound"}
              </button>
              {accelerator && (
                <button
                  className="linklike"
                  onClick={() => save({ ...keybinds, [binding.action]: null })}
                >
                  clear
                </button>
              )}
              {status && !status.registered && (
                <span className="muted" title={status.error ?? undefined}>
                  ⚠ not global
                </span>
              )}
            </div>
            {binding.help && <p className="muted">{binding.help}</p>}
          </div>
        );
      })}

      {problem && (
        <p className="banner error" role="alert">
          {problem}
        </p>
      )}

      {anyRefused && (
        <p className="muted">
          Keys marked <strong>not global</strong> could not be reserved
          system-wide, so they only work while the Pickle window is focused.
          Usually this means the key is not one your keyboard layout can produce
          — F13 through F24 are common culprits — or that your desktop has
          already claimed the combination. Hover the warning for what the system
          reported, and try an ordinary combination such as Control+Shift+M.
        </p>
      )}
    </div>
  );
}
