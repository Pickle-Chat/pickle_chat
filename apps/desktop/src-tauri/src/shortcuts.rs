//! Global keyboard shortcuts.
//!
//! Push-to-talk is the reason this exists. A key that only works while the
//! Pickle window has focus is close to useless — the whole point is to talk
//! while something else is in front — so the binding has to be grabbed from the
//! window manager rather than listened for in the web view.
//!
//! The grab is not guaranteed, and "did it register" is the wrong question to
//! ask about it. On Linux the underlying crate talks X11, so in a Wayland
//! session it goes through XWayland, and there the grab means something weaker
//! than it does under X11:
//!
//! * **Under X11** a grab is exclusive. The key reaches Pickle wherever focus
//!   is, and the focused application never sees it.
//! * **Under Wayland** the grab is made against XWayland, and whether the
//!   compositor honours it is the compositor's decision. On KWin it *is*
//!   honoured — measured, not assumed — but it is not exclusive: the key is
//!   delivered to Pickle *and* to whatever Wayland-native window has focus. A
//!   compositor that does not forward to XWayland at all would leave the grab
//!   registered and silently dead.
//! * A key the X keymap has no keycode for — F13 on a keyboard without one — is
//!   refused outright, in either session.
//!
//! That spread is why [`Reach`] exists rather than a boolean. Reporting a
//! Wayland grab as simply "registered" would promise exclusivity the session
//! cannot deliver, and reporting it as failed would be wrong too.
//!
//! Whatever the answer, the frontend keeps a focus-scoped listener as a
//! fallback. Push-to-talk therefore works with the window focused no matter what
//! the platform decides about the grab, which is the behaviour this whole module
//! exists to guarantee.
//!
//! # Why not the portal
//!
//! The Wayland-native answer to all of this is
//! `org.freedesktop.portal.GlobalShortcuts`, and it is genuinely available:
//! KDE ships the backend, at interface version 2, and it works for an
//! unsandboxed binary once the app id is claimed through
//! `org.freedesktop.host.portal.Registry`. It is deliberately not used, for one
//! disqualifying reason.
//!
//! KDE's release path cannot hold a key down. `GlobalShortcutsRegistry::keyEvent`
//! in `kglobalacceld` handles a key *release* outside the switch on the keycode,
//! so it discards which key was released: any release at all fires the "shortcut
//! released" signal for whatever shortcut is currently held, and then clears it.
//! The portal turns that into `Deactivated`. So holding push-to-talk and
//! releasing an unrelated key — a movement key, in exactly the game this feature
//! exists for — ends the transmission, and because the held shortcut has been
//! cleared no further `Activated` arrives. The microphone stays shut for the
//! rest of the hold.
//!
//! That is the one case push-to-talk exists to serve, so the portal would be a
//! regression against the XWayland grab above, which does work. KDE bug 484525
//! (confirmed, unfixed) tracks it, as does 521565 against Plasma's own
//! push-to-talk, which has the same defect for the same reason; the proposed fix
//! in kglobalacceld MR 124 is unmerged and has an unresolved objection about
//! modifier handling.
//!
//! The portal has costs beyond that which would be worth paying for a mechanism
//! that worked, and are not worth paying for one that does not: the binding
//! belongs to the desktop rather than the app, so the settings tab here could
//! only *suggest* a key and the user would confirm it in a system dialog;
//! shortcuts may be bound only once per session, so every rebind means a new
//! session and another prompt; and a mouse button cannot be expressed at all.
//!
//! Worth revisiting when the `kglobalacceld` release handling is fixed, at which
//! point the portal becomes the better mechanism under Wayland — most of all on
//! compositors that do not forward to XWayland, where the grab above is inert
//! and the portal would be the only thing that works.
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

/// How far a binding actually reaches.
///
/// A boolean cannot say this. "Registered" covers both an X11 grab that takes
/// the key away from every other application and an XWayland grab under Wayland
/// that shares it with the focused window, and those behave differently enough
/// that a user choosing a push-to-talk key needs to be told which one they got.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub enum Reach {
    /// Grabbed from the window system and taken away from everything else: the
    /// key reaches Pickle wherever focus is, and nothing else sees it.
    Exclusive,
    /// Grabbed, and delivered while another window is in front, but not taken
    /// away from that window — it receives the key too.
    Shared,
    /// Read from the input device, below the window system entirely.
    /// Deliberately passive, so whatever is focused still gets the button.
    Device,
    /// Only while Pickle has focus, via the frontend listener.
    Focused,
}

impl Reach {
    /// Whether the binding does anything while another window is in front.
    pub fn is_global(self) -> bool {
        !matches!(self, Reach::Focused)
    }
}

/// What a binding actually does, reported per action so the settings tab can
/// describe it honestly rather than claiming a grab it does not have.
#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct BindingStatus {
    pub action: String,
    pub accelerator: String,
    pub reach: Reach,
    /// What the user needs to know about this reach. `None` only when the
    /// binding is exclusive, which is the case that needs no explanation.
    pub note: Option<String>,
}

/// The window system in play, which decides what a keyboard grab can promise.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum WindowSystem {
    /// A grab is exclusive and reliable.
    X11,
    /// A grab goes through XWayland and is the compositor's to honour.
    Wayland,
    /// Not a session this module can reason about — every other platform, where
    /// the shortcut layer grabs the key natively and exclusively.
    Other,
}

impl WindowSystem {
    /// What a *successful* keyboard grab reaches under this window system.
    fn reach(self) -> Reach {
        match self {
            WindowSystem::Wayland => Reach::Shared,
            WindowSystem::X11 | WindowSystem::Other => Reach::Exclusive,
        }
    }
}

/// Classify the session from the environment it advertises.
///
/// Split from the environment lookup so the interesting part is testable.
/// `XDG_SESSION_TYPE` is the stated answer, but it is absent often enough —
/// bare compositors, `su`, some display managers — that the presence of
/// `WAYLAND_DISPLAY` is worth consulting as a fallback. `DISPLAY` alone proves
/// nothing in a Wayland session, since XWayland sets it too.
fn classify(
    session_type: Option<&str>,
    wayland_display: Option<&str>,
    display: Option<&str>,
) -> WindowSystem {
    match session_type.map(str::trim) {
        Some("wayland") => return WindowSystem::Wayland,
        Some("x11") => return WindowSystem::X11,
        _ => {}
    }
    if wayland_display.is_some_and(|value| !value.is_empty()) {
        WindowSystem::Wayland
    } else if display.is_some_and(|value| !value.is_empty()) {
        WindowSystem::X11
    } else {
        WindowSystem::Other
    }
}

/// The window system this process is actually running under.
pub fn window_system() -> WindowSystem {
    if !cfg!(target_os = "linux") {
        return WindowSystem::Other;
    }
    let var = |name| std::env::var(name).ok();
    classify(
        var("XDG_SESSION_TYPE").as_deref(),
        var("WAYLAND_DISPLAY").as_deref(),
        var("DISPLAY").as_deref(),
    )
}

/// Whether an accelerator is a key that would put a character on the screen if
/// the focused window also received it.
///
/// Only bare keys qualify. `Control+KeyV` is delivered to the focused window
/// too, but almost nothing types a character in response to it, whereas a bare
/// `KeyV` would — and under Wayland that is the difference between a fine
/// push-to-talk binding and one that scatters letters through whatever the user
/// is looking at.
fn types_a_character(accelerator: &str) -> bool {
    if accelerator.contains('+') {
        return false;
    }
    accelerator.starts_with("Key")
        || accelerator.starts_with("Digit")
        || accelerator.starts_with("Numpad")
        || matches!(
            accelerator,
            "Space"
                | "Enter"
                | "Tab"
                | "Minus"
                | "Equal"
                | "Comma"
                | "Period"
                | "Slash"
                | "Semicolon"
                | "Quote"
                | "Backquote"
                | "Backslash"
                | "BracketLeft"
                | "BracketRight"
        )
}

/// The caveat that comes with a grab made under Wayland.
///
/// Both halves are worth saying. The key really does arrive while another
/// window is in front — that was measured on KWin, not assumed — but it is also
/// still delivered to that window. And a compositor that declines to forward to
/// XWayland at all leaves the grab registered and silently dead, which is
/// exactly the case the focus-scoped fallback covers.
///
/// The sharing only actually hurts for a key that types something, so the
/// warning to pick a different one is attached to that case rather than to
/// every binding. Telling someone their `Control+Shift+F8` will "also reach the
/// focused window" is true and useless; telling them their bare `V` will type a
/// V into their game every time they talk is neither.
fn wayland_note(accelerator: &str) -> String {
    let shared = format!(
        "{accelerator} was claimed through XWayland, which is the only global keyboard grab \
         Wayland offers an ordinary application. It reaches Pickle while another window is in \
         front, but Wayland still delivers it to that window as well."
    );
    let typing = if types_a_character(accelerator) {
        " Because it is a key that types, holding it will also put characters into whatever you \
         are looking at — a function key, or a combination with Control or Alt, would not."
    } else {
        ""
    };
    format!(
        "{shared}{typing} Not every compositor forwards to XWayland; if it does nothing while \
         another window is in front, that is why, and it still works while Pickle is focused."
    )
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
    let system = window_system();

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

        let (reach, note) = match accelerator.parse::<Shortcut>() {
            Err(error) => (
                Reach::Focused,
                Some(format!(
                    "{accelerator} is not a key this system understands: {error}. \
                     It works while Pickle is focused."
                )),
            ),
            Ok(shortcut) => match manager.register(shortcut) {
                Ok(()) => {
                    registry.bound.lock().push((shortcut, action));
                    let reach = system.reach();
                    let note = match reach {
                        Reach::Shared => Some(wayland_note(&accelerator)),
                        _ => None,
                    };
                    (reach, note)
                }
                Err(error) => {
                    warn!(%accelerator, %error, "could not grab a global shortcut");
                    (
                        Reach::Focused,
                        Some(format!("{error}. It works while Pickle is focused.")),
                    )
                }
            },
        };

        statuses.push(BindingStatus {
            action: action.label().into(),
            accelerator,
            reach,
            note,
        });
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
            reach: if outcome.is_active() {
                Reach::Device
            } else {
                Reach::Focused
            },
            note: outcome.explain(),
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
    use super::{classify, is_mouse, types_a_character, wayland_note, Reach, WindowSystem};

    #[test]
    fn the_session_type_is_believed_when_it_is_stated() {
        assert_eq!(
            classify(Some("wayland"), None, Some(":0")),
            WindowSystem::Wayland,
            "XWayland sets DISPLAY too, so it must not outvote a stated session",
        );
        assert_eq!(classify(Some("x11"), None, Some(":0")), WindowSystem::X11);
        assert_eq!(
            classify(Some(" wayland "), None, None),
            WindowSystem::Wayland,
            "some display managers pad the value",
        );
    }

    #[test]
    fn a_missing_session_type_falls_back_to_the_display_sockets() {
        assert_eq!(
            classify(None, Some("wayland-0"), Some(":0")),
            WindowSystem::Wayland,
            "a Wayland socket beats DISPLAY, which XWayland also sets",
        );
        assert_eq!(classify(None, None, Some(":0")), WindowSystem::X11);
        assert_eq!(classify(None, None, None), WindowSystem::Other);
        assert_eq!(
            classify(Some("tty"), Some(""), Some("")),
            WindowSystem::Other,
            "empty is not set",
        );
    }

    #[test]
    fn a_wayland_grab_is_reported_as_shared_rather_than_exclusive() {
        // The whole point of `Reach`: under Wayland the key is delivered to the
        // focused window as well, so claiming exclusivity would be a lie.
        assert_eq!(WindowSystem::Wayland.reach(), Reach::Shared);
        assert_eq!(WindowSystem::X11.reach(), Reach::Exclusive);
        assert_eq!(WindowSystem::Other.reach(), Reach::Exclusive);
    }

    #[test]
    fn every_reach_but_focused_works_while_another_window_is_in_front() {
        assert!(Reach::Exclusive.is_global());
        assert!(Reach::Shared.is_global());
        assert!(Reach::Device.is_global());
        assert!(!Reach::Focused.is_global());
    }

    #[test]
    fn the_wayland_note_names_the_key_and_both_halves_of_the_caveat() {
        let note = wayland_note("Control+Shift+KeyV");
        assert!(note.contains("Control+Shift+KeyV"), "names the binding");
        // Registering is not the same as being delivered, and being delivered
        // is not the same as being taken away from the focused window. A note
        // that dropped either half would mislead.
        assert!(note.contains("in front"), "says it does reach Pickle");
        assert!(
            note.contains("as well"),
            "says the focused window gets it too"
        );
        assert!(note.contains("focused"), "says what still works regardless");
    }

    #[test]
    fn only_a_key_that_types_is_warned_about_typing() {
        assert!(
            wayland_note("KeyV").contains("characters into whatever"),
            "a bare letter would scatter itself through the focused window",
        );
        assert!(
            !wayland_note("Control+KeyV").contains("characters into whatever"),
            "a modified key types nothing, so the warning would be noise",
        );
        assert!(!wayland_note("F13").contains("characters into whatever"));
    }

    #[test]
    fn keys_that_put_a_character_on_screen_are_told_from_keys_that_do_not() {
        for typing in [
            "KeyA", "Digit1", "Numpad0", "Space", "Enter", "Comma", "Slash",
        ] {
            assert!(types_a_character(typing), "{typing} types something");
        }
        for silent in [
            "F8", "F13", "ArrowUp", "Escape", "Home", "Delete", "PageUp", "Insert",
        ] {
            assert!(!types_a_character(silent), "{silent} types nothing");
        }
        // A modifier is what stops the focused window turning the key into
        // text, so it is the presence of one that decides this, not the key.
        assert!(!types_a_character("Control+KeyA"));
        assert!(!types_a_character("Alt+Space"));
    }

    #[test]
    fn reach_serialises_as_the_camel_case_the_frontend_matches_on() {
        let json = |reach| serde_json::to_string(&reach).unwrap();
        assert_eq!(json(Reach::Exclusive), "\"exclusive\"");
        assert_eq!(json(Reach::Shared), "\"shared\"");
        assert_eq!(json(Reach::Device), "\"device\"");
        assert_eq!(json(Reach::Focused), "\"focused\"");
    }

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
