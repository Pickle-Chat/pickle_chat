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

  const refused = statuses.filter((status) => !status.registered);
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
              {status &&
                (status.registered ? (
                  accelerator &&
                  isMouseAccelerator(accelerator) && (
                    <span className="muted" title="Read from the mouse device directly.">
                      global
                    </span>
                  )
                ) : (
                  <span className="muted" title={status.error ?? undefined}>
                    ⚠ only while focused
                  </span>
                ))}
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

      {refused.length > 0 && (
        <div className="settings-field">
          <p className="muted">
            A binding marked <strong>only while focused</strong> could not be
            claimed system-wide, so it does nothing while another window is in
            front. What went wrong differs per binding:
          </p>
          <ul className="muted">
            {refused.map((status) => (
              <li key={status.action}>
                <code>{describeAccelerator(status.accelerator)}</code> —{" "}
                {status.error ?? "the system gave no reason."}
              </li>
            ))}
          </ul>
        </div>
      )}

      {anyMouse && (
        <p className="muted">
          Mouse buttons are read from the input device directly, which is the
          only way to see them while a game has focus. Pickle opens mouse
          devices only, watches only the button you bound, and does not take the
          button away from anything else using it.
        </p>
      )}
    </div>
  );
}
