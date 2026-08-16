import { useEffect } from "react";
import { api } from "./api";
import { isMouseAccelerator, isTyping, matchesAccelerator, matchesMouseAccelerator } from "./keys";

/// Focus-scoped push-to-talk, for both keys and mouse buttons.
///
/// Keyboard bindings are also grabbed globally in Rust so they work while
/// another application is in front; this covers the platforms that refuse the
/// grab. Running both is harmless, since each sets the same flag to the same
/// value and the engine reads it as a plain boolean.
///
/// Mouse bindings have no global path at all: the shortcut plugin is
/// keyboard-only, so this listener is the *whole* implementation for them and
/// they only work while Pickle has focus.
export function usePushToTalk(accelerator: string | null, enabled: boolean) {
  useEffect(() => {
    if (!enabled || !accelerator) return;

    const release = () => {
      api.setPushToTalkHeld(false).catch(() => {});
    };

    // Losing focus swallows the release event, which would otherwise leave the
    // microphone latched open until the button is pressed and released again.
    window.addEventListener("blur", release);

    const teardown: (() => void)[] = [
      () => window.removeEventListener("blur", release),
      release,
    ];

    if (isMouseAccelerator(accelerator)) {
      const onDown = (event: MouseEvent) => {
        if (!matchesMouseAccelerator(event, accelerator)) return;
        // The back and forward buttons navigate the web view by default, which
        // would tear the app's state down mid-sentence.
        event.preventDefault();
        api.setPushToTalkHeld(true).catch(() => {});
      };

      const onUp = (event: MouseEvent) => {
        if (matchesMouseAccelerator(event, accelerator)) {
          event.preventDefault();
          release();
        }
      };

      // `auxclick` and the context menu are suppressed for the bound button so
      // a middle or right binding does not also paste or open a menu.
      const suppress = (event: MouseEvent) => {
        if (matchesMouseAccelerator(event, accelerator)) event.preventDefault();
      };

      window.addEventListener("mousedown", onDown, true);
      window.addEventListener("mouseup", onUp, true);
      window.addEventListener("auxclick", suppress, true);
      window.addEventListener("contextmenu", suppress as EventListener, true);

      teardown.push(
        () => window.removeEventListener("mousedown", onDown, true),
        () => window.removeEventListener("mouseup", onUp, true),
        () => window.removeEventListener("auxclick", suppress, true),
        () => window.removeEventListener("contextmenu", suppress as EventListener, true),
      );
    } else {
      // Auto-repeat fires keydown continuously while a key is held; the flag is
      // already set, so re-sending it would be pure bridge traffic.
      const onKeyDown = (event: KeyboardEvent) => {
        if (event.repeat || isTyping(event.target)) return;
        if (matchesAccelerator(event, accelerator)) {
          api.setPushToTalkHeld(true).catch(() => {});
        }
      };

      // Deliberately not filtered by `isTyping`: if focus moves into a text
      // field while the key is down, the release must still be delivered or the
      // microphone would stay open.
      const onKeyUp = (event: KeyboardEvent) => {
        if (matchesAccelerator(event, accelerator)) release();
      };

      window.addEventListener("keydown", onKeyDown);
      window.addEventListener("keyup", onKeyUp);

      teardown.push(
        () => window.removeEventListener("keydown", onKeyDown),
        () => window.removeEventListener("keyup", onKeyUp),
      );
    }

    return () => teardown.forEach((fn) => fn());
  }, [accelerator, enabled]);
}
