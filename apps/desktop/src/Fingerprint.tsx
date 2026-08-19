// A fingerprint you can actually get out of the app.
//
// Fingerprints are the one value here that has to leave the client by hand: a
// server operator needs yours to grant you anything, and verifying a server on
// first contact means comparing its fingerprint against one you were given out
// of band. Both are hostile to retyping — they are long, and a single wrong
// character is the whole point of them.
//
// So every fingerprint is a button. The displayed text may be shortened, but
// what reaches the clipboard is always the full value.

import { useEffect, useRef, useState } from "react";
import { writeText } from "@tauri-apps/plugin-clipboard-manager";

type Status = "idle" | "copied" | "failed";

export function Fingerprint({
  value,
  display,
  className,
}: {
  value: string;
  /** Shown in place of `value`; the full value is still what gets copied. */
  display?: string;
  className?: string;
}) {
  const [status, setStatus] = useState<Status>("idle");
  // Held so a second click restarts the window rather than letting the first
  // timer clear the label early.
  const timer = useRef<number | undefined>(undefined);

  useEffect(() => () => window.clearTimeout(timer.current), []);

  async function copy() {
    try {
      await writeText(value);
      setStatus("copied");
    } catch {
      // Worth surfacing rather than swallowing: a fingerprint that silently
      // did not copy is one the user pastes stale.
      setStatus("failed");
    }
    window.clearTimeout(timer.current);
    timer.current = window.setTimeout(() => setStatus("idle"), 1400);
  }

  return (
    <button
      type="button"
      className={className ? `fingerprint copyable ${className}` : "fingerprint copyable"}
      onClick={copy}
      // The full value, so it is readable without copying and legible to
      // anyone comparing by eye.
      title={status === "idle" ? `${value}\nClick to copy` : value}
      aria-label={`Copy fingerprint ${value}`}
    >
      <code>{display ?? value}</code>
      {status !== "idle" && (
        <span className="copy-flash" role="status">
          {status === "copied" ? "copied" : "copy failed"}
        </span>
      )}
    </button>
  );
}
