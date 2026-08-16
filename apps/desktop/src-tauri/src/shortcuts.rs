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

    for (action, accelerator) in wanted {
        let Some(accelerator) = accelerator.filter(|a| !a.trim().is_empty()) else {
            continue;
        };

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

    statuses
}

/// Dispatch a grabbed key to the action it is bound to.
pub fn handle(app: &AppHandle, shortcut: &Shortcut, event_state: ShortcutState) {
    let Some(action) = app.state::<Registry>().action_for(shortcut) else {
        return;
    };
    let state = app.state::<AppState>();

    let outcome = match (action, event_state) {
        (Action::PushToTalk, ShortcutState::Pressed) => {
            state.set_push_to_talk_held(true);
            return;
        }
        (Action::PushToTalk, ShortcutState::Released) => {
            state.set_push_to_talk_held(false);
            return;
        }
        // Toggles fire on press only; acting on release too would undo them.
        (Action::ToggleMute, ShortcutState::Pressed) => state.toggle_muted(),
        (Action::ToggleDeafen, ShortcutState::Pressed) => state.toggle_deafened(),
        _ => return,
    };

    match outcome {
        Ok(voice) => emit_voice_state(app, voice),
        // Pressing mute while disconnected is ordinary, not an error to raise.
        Err(error) => debug!(%error, "shortcut had no effect"),
    }
}

pub fn emit_voice_state(app: &AppHandle, voice: VoiceState) {
    if let Err(error) = app.emit(VOICE_STATE_EVENT, voice) {
        debug!(%error, "could not emit voice state to the frontend");
    }
}
