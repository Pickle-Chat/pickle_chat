// Translating browser key events to and from the accelerator syntax the Rust
// side registers.
//
// `KeyboardEvent.code` lines up with the accelerator vocabulary almost exactly
// — "KeyA", "F13", "Space", "Numpad0", "ArrowUp" are all understood verbatim —
// so capture is mostly a matter of prefixing the modifiers.

/// Keys that only exist as modifiers. The parser on the Rust side accepts these
/// as *prefixes* but has no code for them on their own, so binding one bare
/// would produce an accelerator that can never register.
///
/// Worth naming explicitly rather than letting it fail: a bare Ctrl or Alt is a
/// popular push-to-talk choice, and "unsupported key" would not explain why.
const MODIFIER_CODES = new Set([
  "ControlLeft",
  "ControlRight",
  "ShiftLeft",
  "ShiftRight",
  "AltLeft",
  "AltRight",
  "MetaLeft",
  "MetaRight",
]);

export interface CaptureResult {
  accelerator?: string;
  problem?: string;
}

/// Turn a keypress into an accelerator, or explain why it cannot be one.
export function captureAccelerator(event: KeyboardEvent): CaptureResult {
  if (MODIFIER_CODES.has(event.code)) {
    return {
      problem:
        "A modifier on its own cannot be bound. Combine it with another key — Control+Shift+M, for example.",
    };
  }

  const parts: string[] = [];
  if (event.ctrlKey) parts.push("Control");
  if (event.shiftKey) parts.push("Shift");
  if (event.altKey) parts.push("Alt");
  if (event.metaKey) parts.push("Super");
  parts.push(event.code);

  return { accelerator: parts.join("+") };
}

/// Render an accelerator for a person to read.
export function describeAccelerator(accelerator: string): string {
  return accelerator
    .split("+")
    .map((token) => token.replace(/^Key/, "").replace(/^Digit/, ""))
    .join(" + ");
}

/// Whether a key event matches an accelerator.
///
/// Used only by the focus-scoped fallback; the global path is matched in Rust
/// by the window manager itself.
export function matchesAccelerator(event: KeyboardEvent, accelerator: string): boolean {
  const tokens = accelerator.split("+");
  const code = tokens[tokens.length - 1];
  if (event.code !== code) return false;

  const wanted = new Set(tokens.slice(0, -1));
  return (
    event.ctrlKey === wanted.has("Control") &&
    event.shiftKey === wanted.has("Shift") &&
    event.altKey === wanted.has("Alt") &&
    event.metaKey === wanted.has("Super")
  );
}

/// Whether a key event is someone typing rather than reaching for a shortcut.
export function isTyping(target: EventTarget | null): boolean {
  if (!(target instanceof HTMLElement)) return false;
  return (
    target.isContentEditable ||
    target.tagName === "INPUT" ||
    target.tagName === "TEXTAREA" ||
    target.tagName === "SELECT"
  );
}
