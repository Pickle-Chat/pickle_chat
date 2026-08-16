import { useEffect, useState } from "react";
import { api, type BindingStatus, type KeybindAction, type Keybinds } from "../api";
import {
  captureAccelerator,
  captureMouseAccelerator,
  describeAccelerator,
  isMouseAccelerator,
  type CaptureResult,
} from "../keys";

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

  // Capture runs on the window so it catches input the button itself would
  // never see, and swallows the press so binding Space, Enter, or a mouse
  // button does not also activate whatever is under the pointer.
  useEffect(() => {
    if (capturing === null) return;

    const accept = ({ accelerator, problem }: CaptureResult, fallback: string) => {
      if (!accelerator) {
        setProblem(problem ?? fallback);
        return;
      }
      setProblem(null);
      setCapturing(null);
      save({ ...keybinds, [capturing]: accelerator });
    };

    const onKeyDown = (event: KeyboardEvent) => {
      event.preventDefault();
      event.stopPropagation();

      if (event.key === "Escape") {
        setCapturing(null);
        setProblem(null);
        return;
      }

      accept(captureAccelerator(event), "That key cannot be bound.");
    };

    const onMouseDown = (event: MouseEvent) => {
      // The left button still has to reach the interface, or there would be no
      // way to click "cancel" out of capture mode.
      if (event.button === 0) return;
      event.preventDefault();
      event.stopPropagation();
      accept(captureMouseAccelerator(event), "That mouse button cannot be bound.");
    };

    const swallow = (event: Event) => {
      event.preventDefault();
      event.stopPropagation();
    };

    window.addEventListener("keydown", onKeyDown, true);
    window.addEventListener("mousedown", onMouseDown, true);
    window.addEventListener("auxclick", swallow, true);
    window.addEventListener("contextmenu", swallow, true);
    return () => {
      window.removeEventListener("keydown", onKeyDown, true);
      window.removeEventListener("mousedown", onMouseDown, true);
      window.removeEventListener("auxclick", swallow, true);
      window.removeEventListener("contextmenu", swallow, true);
    };
  }, [capturing, keybinds]);

  const anyRefused = statuses.some((status) => !status.registered);
  const anyMouse = BINDINGS.some((binding) => {
    const accelerator = keybinds[binding.action];
    return accelerator !== null && isMouseAccelerator(accelerator);
  });

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
                  ? "Press a key or mouse button… (Escape to cancel)"
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
              {accelerator && isMouseAccelerator(accelerator) ? (
                <span
                  className="muted"
                  title="Mouse buttons cannot be reserved system-wide on any platform this app supports."
                >
                  ⚠ only while Pickle is focused
                </span>
              ) : (
                status &&
                !status.registered && (
                  <span className="muted" title={status.error ?? undefined}>
                    ⚠ not global
                  </span>
                )
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

      {anyMouse && (
        <p className="muted">
          Mouse buttons work while Pickle is focused, but cannot be reserved
          system-wide: the shortcut layer this app uses handles keyboard keys
          only. If you need push to talk to reach you while a game is in front,
          bind a key as well — or ask about raw input device support, which can
          read the mouse globally on Linux but needs your user added to the{" "}
          <code>input</code> group.
        </p>
      )}

      {anyRefused && !anyMouse && (
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
