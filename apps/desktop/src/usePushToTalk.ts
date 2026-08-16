import { useEffect } from "react";
import { api } from "./api";
import { isTyping, matchesAccelerator } from "./keys";

/// Focus-scoped push-to-talk.
///
/// The real binding is grabbed globally in Rust so it works while another
/// application is in front. This exists because that grab is not available on
/// every platform — notably a native Wayland session — and without it a refused
/// grab would leave push-to-talk silently doing nothing, which is exactly the
/// bug this whole area was added to fix.
///
/// Running both is harmless: the global handler and this one set the same flag
/// to the same value, and the engine reads it as a plain boolean.
export function usePushToTalk(accelerator: string | null, enabled: boolean) {
  useEffect(() => {
    if (!enabled || !accelerator) return;

    // Auto-repeat fires keydown continuously while a key is held; the flag is
    // already set, so re-sending it would be pure bridge traffic.
    const onKeyDown = (event: KeyboardEvent) => {
      if (event.repeat || isTyping(event.target)) return;
      if (matchesAccelerator(event, accelerator)) {
        api.setPushToTalkHeld(true).catch(() => {});
      }
    };

    // Deliberately not filtered by `isTyping`: if focus moves into a text field
    // while the key is down, the release must still be delivered or the
    // microphone would stay open.
    const onKeyUp = (event: KeyboardEvent) => {
      if (matchesAccelerator(event, accelerator)) {
        api.setPushToTalkHeld(false).catch(() => {});
      }
    };

    // Losing focus swallows the keyup entirely, which would otherwise leave the
    // microphone latched open until the key is pressed and released again.
    const onBlur = () => {
      api.setPushToTalkHeld(false).catch(() => {});
    };

    window.addEventListener("keydown", onKeyDown);
    window.addEventListener("keyup", onKeyUp);
    window.addEventListener("blur", onBlur);
    return () => {
      window.removeEventListener("keydown", onKeyDown);
      window.removeEventListener("keyup", onKeyUp);
      window.removeEventListener("blur", onBlur);
      api.setPushToTalkHeld(false).catch(() => {});
    };
  }, [accelerator, enabled]);
}
