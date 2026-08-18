import { useEffect, useState } from "react";
import {
  api,
  type BindingStatus,
  type KeybindAction,
  type Keybinds,
  type MouseAccess,
  type Reach,
} from "../api";
import {
  captureAccelerator,
  captureMouseAccelerator,
  describeAccelerator,
  isMouseAccelerator,
  type CaptureResult,
} from "../keys";

/// The badge shown beside a binding, one per reach.
///
/// Every one of these says what the binding *does*, never merely that a call
/// succeeded — "registered" was the old wording and it promised more than a
/// Wayland grab delivers.
const REACH_BADGE: Record<Reach, { text: string; title: string } | null> = {
  // Nothing to say: the key is Pickle's alone, wherever focus is.
  exclusive: null,
  shared: {
    text: "global, shared",
    title:
      "Reaches Pickle while another window is in front, but the focused window receives it too.",
  },
  device: {
    text: "global",
    title: "Read from the mouse device directly, without taking the button from anything else.",
  },
  focused: {
    text: "⚠ only while focused",
    title: "Could not be claimed system-wide.",
  },
};

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
  // Non-null only when a mouse exists that Pickle is not allowed to read, so
  // nobody is shown a permissions change they do not need.
  const [access, setAccess] = useState<MouseAccess | null>(null);
  const [copied, setCopied] = useState(false);

  useEffect(() => {
    api.keybindStatus().then(setStatuses).catch((e) => onError(String(e)));
    api.mouseUdevRule().then(setAccess).catch(() => setAccess(null));
  }, [onError]);

  const save = (next: Keybinds) => {
    onChange(next);
    api.setKeybinds(next).then(setStatuses).catch((e) => onError(String(e)));
    api.mouseUdevRule().then(setAccess).catch(() => setAccess(null));
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

  // Split rather than lumped: a binding that could not be claimed at all is a
  // problem to fix, while a Wayland grab that works but is also seen by the
  // focused window is a caveat to understand. Showing them under one heading
  // would misrepresent both.
  const refused = statuses.filter((status) => status.reach === "focused");
  const shared = statuses.filter((status) => status.reach === "shared");
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
                (() => {
                  const badge = REACH_BADGE[status.reach];
                  if (!badge) return null;
                  // The badge's own one-liner rather than `note`: the full
                  // explanation is spelled out below the list, and a paragraph
                  // in a tooltip is a paragraph nobody reads.
                  return (
                    <span className="muted" title={badge.title}>
                      {badge.text}
                    </span>
                  );
                })()}
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
                {status.note ?? "the system gave no reason."}
              </li>
            ))}
          </ul>
        </div>
      )}

      {shared.length > 0 && (
        <div className="settings-field">
          <p className="muted">
            A binding marked <strong>global, shared</strong> does work while
            another window is in front, but Wayland has no way to take a key
            away from the focused window, so that window receives it too. Pick
            something you would not otherwise type — a function key, or a
            combination with Control or Alt.
          </p>
          <ul className="muted">
            {shared.map((status) => (
              <li key={status.action}>
                <code>{describeAccelerator(status.accelerator)}</code> —{" "}
                {status.note}
              </li>
            ))}
          </ul>
        </div>
      )}

      {anyMouse && (
        <p className="muted">
          Mouse buttons are read from the input device directly, which is the
          only way to see them while a game has focus. Pickle opens a device
          only if it moves a pointer, has buttons, and reports no typing keys at
          all — so a device it opens is not one that could report a keystroke.
          It watches only the button you bound, and does not take that button
          away from anything else using it.
        </p>
      )}

      {anyMouse && access && (
        <div className="settings-field">
          <span className="settings-label">Permission for your mouse</span>
          <p className="muted">
            {access.devices.length === 1
              ? "This mouse exists but Pickle is not allowed to read it:"
              : "These mice exist but Pickle is not allowed to read them:"}
          </p>
          <ul className="muted">
            {access.devices.map((device) => (
              <li key={`${device.vendor}:${device.product}`}>
                {device.name} <code className="fingerprint">
                  {device.vendor}:{device.product}
                </code>
              </li>
            ))}
          </ul>
          <p className="muted">
            Save the rule below as <code className="fingerprint">{access.path}</code>{" "}
            (it needs root), then reload udev and replug the mouse. It grants
            access to that one device, for whoever is signed in at this machine,
            and to nothing else — in particular it does not grant access to any
            keyboard.
          </p>
          <pre className="udev-rule">{access.rule}</pre>
          <div className="keybind-row">
            <button
              onClick={() => {
                navigator.clipboard
                  .writeText(access.rule)
                  .then(() => setCopied(true))
                  .catch(() => setProblem("Could not copy to the clipboard."));
              }}
            >
              {copied ? "Copied" : "Copy the rule"}
            </button>
          </div>
        </div>
      )}
    </div>
  );
}
