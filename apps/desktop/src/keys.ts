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

/// Mouse buttons, named the way people who bind them do.
///
/// The numbering is the gaming convention — Mouse4 is the rear thumb button —
/// which is deliberately *not* the DOM's `MouseEvent.button` numbering. The two
/// disagree by more than an offset (DOM orders middle before right), so the
/// mapping is written out rather than computed, because getting it subtly wrong
/// would bind the wrong button in a way nobody would think to check.
const MOUSE_BUTTONS: { accelerator: string; button: number; name: string }[] = [
  { accelerator: "Mouse1", button: 0, name: "Left mouse" },
  { accelerator: "Mouse2", button: 2, name: "Right mouse" },
  { accelerator: "Mouse3", button: 1, name: "Middle mouse" },
  { accelerator: "Mouse4", button: 3, name: "Mouse 4 (back)" },
  { accelerator: "Mouse5", button: 4, name: "Mouse 5 (forward)" },
];

/// Binding the left button would make the interface unusable, since every click
/// on every control would also key the microphone.
const UNBINDABLE_BUTTON = 0;

export function isMouseAccelerator(accelerator: string): boolean {
  return accelerator.startsWith("Mouse");
}

export interface CaptureResult {
  accelerator?: string;
  problem?: string;
}

/// Turn a mouse press into an accelerator, or explain why it cannot be one.
export function captureMouseAccelerator(event: MouseEvent): CaptureResult {
  if (event.button === UNBINDABLE_BUTTON) {
    return {
      problem: "The left mouse button cannot be bound — every click would key your microphone.",
    };
  }

  const known = MOUSE_BUTTONS.find((entry) => entry.button === event.button);
  if (!known) {
    return { problem: `That mouse button (${event.button}) is not one this build knows.` };
  }

  // Modifiers combine with mouse buttons exactly as they do with keys.
  const parts: string[] = [];
  if (event.ctrlKey) parts.push("Control");
  if (event.shiftKey) parts.push("Shift");
  if (event.altKey) parts.push("Alt");
  if (event.metaKey) parts.push("Super");
  parts.push(known.accelerator);

  return { accelerator: parts.join("+") };
}

/// Whether a mouse event matches an accelerator.
export function matchesMouseAccelerator(event: MouseEvent, accelerator: string): boolean {
  const tokens = accelerator.split("+");
  const known = MOUSE_BUTTONS.find((entry) => entry.accelerator === tokens[tokens.length - 1]);
  if (!known || event.button !== known.button) return false;

  const wanted = new Set(tokens.slice(0, -1));
  return (
    event.ctrlKey === wanted.has("Control") &&
    event.shiftKey === wanted.has("Shift") &&
    event.altKey === wanted.has("Alt") &&
    event.metaKey === wanted.has("Super")
  );
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
    .map((token) => {
      const mouse = MOUSE_BUTTONS.find((entry) => entry.accelerator === token);
      if (mouse) return mouse.name;
      return token.replace(/^Key/, "").replace(/^Digit/, "");
    })
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
