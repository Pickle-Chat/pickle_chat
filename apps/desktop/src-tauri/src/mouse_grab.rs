//! Global mouse buttons on Linux, read from the input device directly.
//!
//! The shortcut layer is keyboard-only, so a thumb button bound to push to talk
//! is invisible to it. Reading the mouse's evdev node sidesteps that entirely:
//! it works under Wayland and X11 alike, focused or not, because it sees the
//! device rather than the window system.
//!
//! # What this reads, and what it does not
//!
//! Reading an input device is a privileged, wide-reaching capability, so the
//! scope here is deliberately narrow:
//!
//! * **Mouse devices only.** A device qualifies only if it reports `BTN_LEFT`
//!   *and* the button actually bound. Keyboards are never opened, so nothing
//!   here can observe typing.
//! * **The bound button only.** Every other event — including pointer motion —
//!   is discarded without inspection, and no event is ever logged.
//! * **Passive.** The device is not grabbed with `EVIOCGRAB`, so the button
//!   still reaches the game or application underneath. Stealing a thumb button
//!   from everything else on the system is not a trade anyone asked for.
//!
//! # Modifiers
//!
//! A binding like `Shift+Mouse4` is deliberately *not* handled here. Knowing
//! whether Shift is down would mean opening a keyboard device and watching
//! every key on it, which is exactly the capability the scope above rules out.
//! Modified mouse bindings fall back to the focus-scoped listener in the
//! frontend.

use crate::shortcuts::Action;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use tauri::AppHandle;

/// Why a global mouse binding is or is not live, for reporting to the UI.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum GrabOutcome {
    /// Reading the device, on this many devices.
    Active { devices: usize },
    /// Devices carrying the button exist but none could be opened.
    NoPermission { seen: usize },
    /// No device reports the bound button.
    NoDevice,
    /// The binding carries modifiers, which would require watching a keyboard.
    Modified,
    /// No input-device path exists on this platform.
    #[cfg(not(target_os = "linux"))]
    Unsupported,
}

impl GrabOutcome {
    pub fn is_active(&self) -> bool {
        matches!(self, GrabOutcome::Active { .. })
    }

    /// A sentence for the settings tab, or `None` when the grab is working.
    pub fn explain(&self) -> Option<String> {
        match self {
            GrabOutcome::Active { .. } => None,
            // Deliberately does not claim the button was found on them: a
            // device we cannot open is one whose capabilities we cannot read.
            GrabOutcome::NoPermission { seen } => Some(format!(
                "Found {seen} mouse device(s), but could not open any of them. \
                 Reading the mouse directly needs your user in the `input` group: \
                 run `sudo usermod -aG input $USER`, then log out and back in. \
                 Until then the button works while Pickle is focused.",
            )),
            GrabOutcome::NoDevice => Some(
                "No mouse reporting that button was found. It works while Pickle is focused."
                    .into(),
            ),
            GrabOutcome::Modified => Some(
                "A mouse binding with modifiers only works while Pickle is focused: checking \
                 whether a modifier is held would mean reading your keyboard, which this app \
                 deliberately does not do."
                    .into(),
            ),
            #[cfg(not(target_os = "linux"))]
            GrabOutcome::Unsupported => Some(
                "Mouse buttons cannot be reserved system-wide on this platform; this works while \
                 Pickle is focused."
                    .into(),
            ),
        }
    }
}

/// A running set of device readers. Dropping it stops them.
pub struct MouseGrab {
    stop: Arc<AtomicBool>,
}

impl Drop for MouseGrab {
    fn drop(&mut self) {
        self.stop.store(true, Ordering::Relaxed);
    }
}

/// Translate the last token of an accelerator into an evdev button code.
///
/// Returns `None` for a modified binding, matching the scope note above.
#[cfg(target_os = "linux")]
fn button_code(accelerator: &str) -> Option<evdev::KeyCode> {
    use evdev::KeyCode;

    // Modified bindings are refused rather than silently ignoring the modifier,
    // which would fire on the bare button and surprise the user.
    if accelerator.contains('+') {
        return None;
    }

    // BTN_SIDE is the rear thumb button on essentially every mouse, which is
    // what "Mouse4" means to the people who bind it.
    match accelerator {
        "Mouse2" => Some(KeyCode::BTN_RIGHT),
        "Mouse3" => Some(KeyCode::BTN_MIDDLE),
        "Mouse4" => Some(KeyCode::BTN_SIDE),
        "Mouse5" => Some(KeyCode::BTN_EXTRA),
        // Mouse1 is refused in the UI; binding it would key the microphone on
        // every click.
        _ => None,
    }
}

#[cfg(target_os = "linux")]
pub fn start(app: AppHandle, bindings: &[(String, Action)]) -> (Option<MouseGrab>, GrabOutcome) {
    use evdev::KeyCode;

    let mut wanted: Vec<(KeyCode, Action)> = Vec::new();
    let mut modified = false;

    for (accelerator, action) in bindings {
        match button_code(accelerator) {
            Some(code) => wanted.push((code, *action)),
            None if accelerator.contains('+') => modified = true,
            None => {}
        }
    }

    if wanted.is_empty() {
        return (
            None,
            if modified {
                GrabOutcome::Modified
            } else {
                GrabOutcome::NoDevice
            },
        );
    }

    let stop = Arc::new(AtomicBool::new(false));
    let mut opened = 0usize;
    let mut seen = 0usize;

    // `enumerate` yields only what it can open, so a device we cannot read
    // simply does not appear. Counting the nodes separately is what lets the
    // "you are not in the input group" case be told apart from "no such
    // button", which are very different things to report.
    for (path, device) in evdev::enumerate() {
        let Some(keys) = device.supported_keys() else {
            continue;
        };
        // A mouse, not a keyboard that happens to claim a button code.
        if !keys.contains(KeyCode::BTN_LEFT) {
            continue;
        }
        let codes: Vec<(KeyCode, Action)> = wanted
            .iter()
            .filter(|(code, _)| keys.contains(*code))
            .copied()
            .collect();
        if codes.is_empty() {
            continue;
        }

        seen += 1;
        match spawn_reader(app.clone(), device, codes, Arc::clone(&stop)) {
            Ok(()) => opened += 1,
            Err(error) => {
                tracing::debug!(path = %path.display(), %error, "could not read a mouse device");
            }
        }
    }

    // Mice we could not even open, so the permission case is visible rather
    // than looking like the button simply does not exist.
    seen += unreadable_mice();

    if opened == 0 {
        return (
            None,
            if seen == 0 {
                GrabOutcome::NoDevice
            } else {
                GrabOutcome::NoPermission { seen }
            },
        );
    }

    tracing::info!(devices = opened, "reading mouse buttons globally");
    (
        Some(MouseGrab { stop }),
        GrabOutcome::Active { devices: opened },
    )
}

/// How many mouse event nodes exist that we cannot open.
///
/// Used only to tell "you are not in the `input` group" apart from "no such
/// device", which are very different things to tell a user. Nothing is read
/// from the devices themselves.
///
/// udev tags mouse nodes in `/dev/input/by-id` with an `-event-mouse` suffix,
/// which identifies them without opening anything — necessary here, since a
/// device we lack permission to open is also a device whose capabilities we
/// cannot inspect. Counting bare `event*` nodes instead would report every
/// keyboard and power button on the machine as a mouse.
#[cfg(target_os = "linux")]
fn unreadable_mice() -> usize {
    let Ok(entries) = std::fs::read_dir("/dev/input/by-id") else {
        // No udev tagging available. Better to report nothing than to report a
        // count of things that are probably not mice.
        return 0;
    };
    entries
        .flatten()
        .filter(|entry| {
            entry
                .file_name()
                .to_str()
                .is_some_and(|name| name.ends_with("-event-mouse"))
        })
        .filter(|entry| std::fs::File::open(entry.path()).is_err())
        .count()
}

/// Read one device until told to stop.
///
/// Non-blocking with a short poll rather than a blocking read, so a rebind
/// retires the thread promptly. Two readers briefly overlapping on one device
/// could otherwise split a press and its release between them and latch the
/// microphone open. The poll interval is well under a single 20 ms audio frame,
/// so it costs no perceptible latency.
#[cfg(target_os = "linux")]
fn spawn_reader(
    app: AppHandle,
    mut device: evdev::Device,
    codes: Vec<(evdev::KeyCode, Action)>,
    stop: Arc<AtomicBool>,
) -> std::io::Result<()> {
    use evdev::EventSummary;

    device.set_nonblocking(true)?;
    let name = device.name().unwrap_or("unnamed").to_string();

    std::thread::Builder::new()
        .name("pickle-mouse-grab".into())
        .spawn(move || {
            while !stop.load(Ordering::Relaxed) {
                match device.fetch_events() {
                    Ok(events) => {
                        for event in events {
                            // Anything that is not one of the bound buttons is
                            // dropped here, unexamined and unlogged.
                            let EventSummary::Key(_, code, value) = event.destructure() else {
                                continue;
                            };
                            let Some((_, action)) = codes.iter().find(|(bound, _)| *bound == code)
                            else {
                                continue;
                            };
                            // 1 is press and 0 release; 2 is auto-repeat, which
                            // a held button does not need re-applied.
                            match value {
                                1 => dispatch(&app, *action, true),
                                0 => dispatch(&app, *action, false),
                                _ => {}
                            }
                        }
                    }
                    Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {
                        std::thread::sleep(std::time::Duration::from_millis(8));
                    }
                    Err(error) => {
                        // Unplugged, most likely. Releasing is important: the
                        // microphone must not stay open because the mouse the
                        // button belonged to went away mid-press.
                        tracing::debug!(device = %name, %error, "mouse reader stopping");
                        for (_, action) in &codes {
                            if matches!(action, Action::PushToTalk) {
                                dispatch(&app, Action::PushToTalk, false);
                            }
                        }
                        return;
                    }
                }
            }
            tracing::debug!(device = %name, "mouse reader stopped");
        })
        .map(|_| ())
}

/// Apply a button press to the action it is bound to.
#[cfg(target_os = "linux")]
fn dispatch(app: &AppHandle, action: Action, pressed: bool) {
    crate::shortcuts::dispatch(app, action, pressed);
}

#[cfg(not(target_os = "linux"))]
pub fn start(_app: AppHandle, _bindings: &[(String, Action)]) -> (Option<MouseGrab>, GrabOutcome) {
    (None, GrabOutcome::Unsupported)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn an_active_grab_needs_no_explanation() {
        assert!(GrabOutcome::Active { devices: 1 }.explain().is_none());
        assert!(GrabOutcome::Active { devices: 1 }.is_active());
    }

    #[test]
    fn the_permission_case_names_the_fix() {
        // The whole point of telling this case apart from "no such device".
        let message = GrabOutcome::NoPermission { seen: 3 }.explain().unwrap();
        assert!(message.contains("input"), "names the group");
        assert!(message.contains("usermod"), "gives the command");
    }

    #[test]
    fn every_inactive_outcome_explains_itself() {
        for outcome in [
            GrabOutcome::NoPermission { seen: 1 },
            GrabOutcome::NoDevice,
            GrabOutcome::Modified,
            #[cfg(not(target_os = "linux"))]
            GrabOutcome::Unsupported,
        ] {
            assert!(!outcome.is_active());
            let message = outcome.explain().expect("must explain itself");
            assert!(
                message.contains("focused"),
                "must say what still works: {message}",
            );
        }
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn accelerators_map_to_the_expected_buttons() {
        use evdev::KeyCode;
        // BTN_SIDE is the rear thumb button. Getting this wrong would bind a
        // different button in a way nobody would think to check.
        assert_eq!(super::button_code("Mouse4"), Some(KeyCode::BTN_SIDE));
        assert_eq!(super::button_code("Mouse5"), Some(KeyCode::BTN_EXTRA));
        assert_eq!(super::button_code("Mouse3"), Some(KeyCode::BTN_MIDDLE));
        assert_eq!(super::button_code("Mouse2"), Some(KeyCode::BTN_RIGHT));
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn left_click_and_modified_bindings_are_refused() {
        assert_eq!(
            super::button_code("Mouse1"),
            None,
            "left would key on every click"
        );
        assert_eq!(
            super::button_code("Shift+Mouse4"),
            None,
            "would require watching a keyboard",
        );
        assert_eq!(super::button_code("KeyM"), None);
    }
}
