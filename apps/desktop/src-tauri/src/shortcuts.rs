//! Global keyboard shortcuts.
//!
//! Push-to-talk is the reason this exists. A key that only works while the
//! Pickle window has focus is close to useless — the whole point is to talk
//! while something else is in front — so the binding has to be grabbed from the
//! window manager rather than listened for in the web view.
//!
//! The grab is not guaranteed. On Linux the underlying crate talks X11, so it
//! goes through XWayland in a Wayland session; registration was observed to
//! succeed there for a modifier combination, but a key the X keymap has no
//! keycode for — F13 on a keyboard without one — is refused outright, and
//! whether a grab made through XWayland receives keys while a Wayland-native
//! window holds focus is not something this code can determine.
//!
//! So registration reports per-binding success back to the UI rather than
//! failing silently, and the frontend keeps a focus-scoped listener as a
//! fallback. Push-to-talk therefore works with the window focused no matter what
//! the platform decides about the grab, which is the behaviour this whole module
//! exists to guarantee.
//!
//! Mouse buttons are outside this layer entirely: it has no notion of them, so
//! a `Mouse4` binding is never handed to it. Reaching a mouse button globally
//! on Linux means reading the evdev device, which [`crate::mouse_grab`] does —
//! under a filter narrow enough that no device it opens can report a keystroke,
//! and behind a udev rule scoped to the one mouse rather than the `input`
//! group. Mouse bindings are collected here and passed to it.

use crate::mouse_grab::{self, MouseGrab};
use crate::state::{AppState, VoiceState};
use parking_lot::Mutex;
use serde::Serialize;
use tauri::{AppHandle, Emitter, Manager};
use tauri_plugin_global_shortcut::{GlobalShortcutExt, Shortcut, ShortcutState};
use tracing::{debug, warn};

/// Channel the frontend listens on for voice state it did not initiate.
pub const VOICE_STATE_EVENT: &str = "pickle:voice-state";

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Action {
    PushToTalk,
    ToggleMute,
    ToggleDeafen,
}

impl Action {
    fn label(self) -> &'static str {
        match self {
            Action::PushToTalk => "pushToTalk",
            Action::ToggleMute => "toggleMute",
            Action::ToggleDeafen => "toggleDeafen",
        }
    }
}

/// Whether a binding actually took, reported per action so the settings tab can
/// say which key is live and which the system refused.
#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct BindingStatus {
    pub action: String,
    pub accelerator: String,
    pub registered: bool,
    /// Present only when `registered` is false.
    pub error: Option<String>,
}

/// The shortcuts currently grabbed, so they can be released before rebinding.
#[derive(Default)]
pub struct Registry {
    bound: Mutex<Vec<(Shortcut, Action)>>,
    /// Mouse readers, kept alive here. Replacing this stops the old ones.
    mouse: Mutex<Option<MouseGrab>>,
}

impl Registry {
    fn action_for(&self, shortcut: &Shortcut) -> Option<Action> {
        self.bound
            .lock()
            .iter()
            .find(|(bound, _)| bound == shortcut)
            .map(|(_, action)| *action)
    }
}

/// Release every current binding and grab whatever the settings now say.
///
/// Rebinding is always a full replace: partial application would leave a key
/// grabbed that the user believes they have cleared.
pub fn apply(app: &AppHandle) -> Vec<BindingStatus> {
    let registry = app.state::<Registry>();
    let manager = app.global_shortcut();

    for (shortcut, _) in registry.bound.lock().drain(..) {
        if let Err(error) = manager.unregister(shortcut) {
            // Not fatal: the binding is gone from our table either way, and the
            // most likely cause is that the system already dropped it.
            debug!(%error, "could not unregister a shortcut");
        }
    }

    let keybinds = {
        let state = app.state::<AppState>();
        let keybinds = state.settings.lock().keybinds.clone();
        keybinds
    };

    let wanted = [
        (Action::PushToTalk, keybinds.push_to_talk),
        (Action::ToggleMute, keybinds.toggle_mute),
        (Action::ToggleDeafen, keybinds.toggle_deafen),
    ];

    let mut statuses = Vec::new();
    let mut mouse_bindings: Vec<(String, Action)> = Vec::new();

    for (action, accelerator) in wanted {
        let Some(accelerator) = accelerator.filter(|a| !a.trim().is_empty()) else {
            continue;
        };

        // Mouse bindings never reach the shortcut layer: it is keyboard-only,
        // and handing it "Mouse4" would produce an "unsupported key" complaint
        // that reads like a fault rather than a limit. They are collected and
        // handed to the input-device reader below instead.
        if is_mouse(&accelerator) {
            mouse_bindings.push((accelerator, action));
            continue;
        }

        let status = match accelerator.parse::<Shortcut>() {
            Err(error) => BindingStatus {
                action: action.label().into(),
                accelerator: accelerator.clone(),
                registered: false,
                error: Some(format!(
                    "{accelerator} is not a key this system understands: {error}"
                )),
            },
            Ok(shortcut) => match manager.register(shortcut) {
                Ok(()) => {
                    registry.bound.lock().push((shortcut, action));
                    BindingStatus {
                        action: action.label().into(),
                        accelerator: accelerator.clone(),
                        registered: true,
                        error: None,
                    }
                }
                Err(error) => {
                    warn!(%accelerator, %error, "could not grab a global shortcut");
                    BindingStatus {
                        action: action.label().into(),
                        accelerator: accelerator.clone(),
                        registered: false,
                        error: Some(error.to_string()),
                    }
                }
            },
        };

        statuses.push(status);
    }

    // Replacing the previous grab stops its readers, which is what keeps a
    // rebind from leaving two threads watching one device — they could
    // otherwise split a press and its release and latch the microphone open.
    let (grab, outcome) = if mouse_bindings.is_empty() {
        (None, mouse_grab::GrabOutcome::NoDevice)
    } else {
        mouse_grab::start(app.clone(), &mouse_bindings)
    };
    *registry.mouse.lock() = grab;

    for (accelerator, action) in mouse_bindings {
        statuses.push(BindingStatus {
            action: action.label().into(),
            accelerator,
            registered: outcome.is_active(),
            error: outcome.explain(),
        });
    }

    statuses
}

/// Dispatch a grabbed key to the action it is bound to.
pub fn handle(app: &AppHandle, shortcut: &Shortcut, event_state: ShortcutState) {
    let Some(action) = app.state::<Registry>().action_for(shortcut) else {
        return;
    };
    dispatch(app, action, matches!(event_state, ShortcutState::Pressed));
}

/// Apply an action, however it was triggered.
///
/// Shared with the mouse reader in [`crate::mouse_grab`], so a thumb button and
/// a key bound to the same action cannot drift into behaving differently.
pub fn dispatch(app: &AppHandle, action: Action, pressed: bool) {
    let state = app.state::<AppState>();

    let outcome = match action {
        Action::PushToTalk => {
            state.set_push_to_talk_held(pressed);
            return;
        }
        // Toggles fire on press only; acting on release too would undo them.
        _ if !pressed => return,
        Action::ToggleMute => state.toggle_muted(),
        Action::ToggleDeafen => state.toggle_deafened(),
    };

    match outcome {
        Ok(voice) => emit_voice_state(app, voice),
        // Pressing mute while disconnected is ordinary, not an error to raise.
        Err(error) => debug!(%error, "shortcut had no effect"),
    }
}

/// Whether an accelerator names a mouse button rather than a key.
///
/// Matches the last token so a modified binding like `Shift+Mouse4` is
/// recognised too.
fn is_mouse(accelerator: &str) -> bool {
    accelerator
        .rsplit('+')
        .next()
        .is_some_and(|token| token.trim().starts_with("Mouse"))
}

pub fn emit_voice_state(app: &AppHandle, voice: VoiceState) {
    if let Err(error) = app.emit(VOICE_STATE_EVENT, voice) {
        debug!(%error, "could not emit voice state to the frontend");
    }
}

#[cfg(test)]
mod tests {
    use super::is_mouse;

    #[test]
    fn mouse_bindings_are_told_apart_from_keys() {
        assert!(is_mouse("Mouse4"));
        assert!(
            is_mouse("Shift+Mouse4"),
            "a modified mouse binding still counts"
        );
        assert!(!is_mouse("KeyM"));
        assert!(!is_mouse("Control+Shift+KeyM"));
        assert!(!is_mouse(""));
        // The key whose name merely starts the same way must not be caught.
        assert!(!is_mouse("Control+MouseKeyIsNotAThing+KeyM"));
    }
}
