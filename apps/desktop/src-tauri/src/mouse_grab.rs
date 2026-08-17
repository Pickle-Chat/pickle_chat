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
//! scope here is deliberately narrow. The rule is that the promise made to the
//! user must be the one the filter actually enforces:
//!
//! * **Devices that are a mouse and only a mouse.** [`is_mouse_only`] requires
//!   `REL_X` *and* `REL_Y` — a thing that moves a pointer — together with
//!   `BTN_LEFT` and the button actually bound, and it rejects outright any
//!   device that reports a key from the typing block. Requiring `BTN_LEFT`
//!   alone would not be enough: a laptop keyboard with a trackpoint, a unifying
//!   receiver presenting a keyboard and a mouse behind one node, and plenty of
//!   gaming keyboards with a mouse-emulation mode all report `BTN_LEFT` and the
//!   full `KEY_*` range on a single node, and would sail through such a check.
//!   With the typing block excluded, no device this opens is capable of
//!   reporting a keystroke in the first place.
//! * **The bound button only.** Every other event — including pointer motion —
//!   is discarded without inspection, and no event is ever logged.
//! * **Passive.** The device is not grabbed with `EVIOCGRAB`, so the button
//!   still reaches the game or application underneath. Stealing a thumb button
//!   from everything else on the system is not a trade anyone asked for.
//!
//! # Permission
//!
//! Opening an evdev node needs permission the desktop does not grant by
//! default. Adding the user to the `input` group would fix it and is what most
//! projects tell people to do, but it is a wildly disproportionate trade: every
//! process that user runs, forever, gains read access to every
//! `/dev/input/event*` node on the machine — every keyboard included. One
//! compromised application anywhere in the session then has a keylogger.
//!
//! So the advice here is a udev rule scoped to the one mouse instead, which
//! [`udev_rule`] generates for the hardware actually present. See
//! [`UdevAdvice`].
//!
//! # Modifiers
//!
//! A binding like `Shift+Mouse4` is deliberately *not* handled here. Knowing
//! whether Shift is down would mean opening a keyboard device and watching
//! every key on it, which is exactly the capability the scope above rules out.
//! Modified mouse bindings fall back to the focus-scoped listener in the
//! frontend.

use crate::shortcuts::Action;
use serde::Serialize;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use tauri::AppHandle;

/// Where the generated rule is meant to be installed.
pub const UDEV_RULE_PATH: &str = "/etc/udev/rules.d/70-pickle-mouse.rules";

/// One mouse, identified well enough to write a udev rule for it.
///
/// Deliberately not a device path: `/dev/input/event7` is assigned in probe
/// order and will not survive a reboot, whereas the vendor and product ids are
/// the device itself.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct MouseDevice {
    /// What the device calls itself, for the human reading the rule.
    pub name: String,
    /// Vendor id, four lower-case hex digits, as udev writes it.
    pub vendor: String,
    /// Product id, four lower-case hex digits.
    pub product: String,
}

/// A ready-to-install udev rule for the mice Pickle cannot currently open.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct UdevAdvice {
    /// Where to put [`Self::rule`].
    pub path: String,
    /// The file, comments and all.
    pub rule: String,
    /// The devices the rule covers, so the UI can name them.
    pub devices: Vec<MouseDevice>,
}

/// Why a global mouse binding is or is not live, for reporting to the UI.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum GrabOutcome {
    /// Reading the device, on this many devices.
    Active { devices: usize },
    /// Devices carrying the button exist but none could be opened.
    NoPermission { devices: Vec<MouseDevice> },
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
            //
            // The fix is deliberately *not* `usermod -aG input`: that hands
            // every process this user runs a permanent read on every keyboard
            // on the machine. The udev rule below grants one device instead.
            GrabOutcome::NoPermission { devices } => Some(format!(
                "Found {} mouse device(s), but could not open any of them. \
                 Reading a mouse directly needs permission on that one device, \
                 which a small udev rule grants — Pickle can write the exact \
                 rule for your hardware. Until then the button works while \
                 Pickle is focused.",
                devices.len(),
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

/// Whether a device is a pointer, and *only* a pointer.
///
/// Three conditions, each load-bearing:
///
/// * `REL_X` and `REL_Y` — it moves a pointer by a relative amount, which is
///   what a mouse is. A keyboard that merely claims a button code does not.
/// * `BTN_LEFT` — a pointing device with buttons, rather than a dial, a
///   scroll-only surface, or a tablet.
/// * No key from the typing block. This is the one that matters for the
///   promise in the module docs: `BTN_LEFT` plus `REL_X`/`REL_Y` is perfectly
///   compatible with a laptop keyboard that also has a trackpoint, or a
///   keyboard/mouse combo behind a single receiver, and those report the whole
///   `KEY_*` range on the same node. Excluding the typing block means a node
///   this opens is physically incapable of telling us what was typed.
///
/// The typing block is `KEY_1` (2) through `KEY_SLASH` (53): the number row,
/// all three letter rows, and the punctuation between them. It stops short of
/// `KEY_BACK` and `KEY_FORWARD`, which real mice do map onto side buttons, so
/// an ordinary mouse is not rejected for having browser navigation on it.
#[cfg(target_os = "linux")]
fn is_mouse_only(device: &evdev::Device) -> bool {
    device
        .supported_keys()
        .is_some_and(|keys| capabilities_are_mouse_only(keys, device.supported_relative_axes()))
}

/// The decision itself, over nothing but the capability bitmaps.
///
/// Separate from [`is_mouse_only`] because an `evdev::Device` can only be
/// obtained from real hardware, and this is the rule the privacy promise rests
/// on — it needs tests that do not depend on what is plugged in.
#[cfg(target_os = "linux")]
fn capabilities_are_mouse_only(
    keys: &evdev::AttributeSetRef<evdev::KeyCode>,
    axes: Option<&evdev::AttributeSetRef<evdev::RelativeAxisCode>>,
) -> bool {
    use evdev::{KeyCode, RelativeAxisCode};

    let moves_a_pointer = axes.is_some_and(|axes| {
        axes.contains(RelativeAxisCode::REL_X) && axes.contains(RelativeAxisCode::REL_Y)
    });
    let types = (KeyCode::KEY_1.0..=KeyCode::KEY_SLASH.0).any(|code| keys.contains(KeyCode(code)));

    moves_a_pointer && keys.contains(KeyCode::BTN_LEFT) && !types
}

/// How a device identifies itself, for the udev rule that will name it.
#[cfg(target_os = "linux")]
fn identify(device: &evdev::Device) -> MouseDevice {
    let id = device.input_id();
    MouseDevice {
        name: clean_name(device.name().unwrap_or("unnamed mouse")),
        vendor: format!("{:04x}", id.vendor()),
        product: format!("{:04x}", id.product()),
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
    let mut blocked: Vec<MouseDevice> = Vec::new();

    // `enumerate` yields only what it can open, so a device we cannot read
    // simply does not appear. Listing the nodes separately is what lets the
    // "no permission on the device" case be told apart from "no such button",
    // which are very different things to report.
    for (path, device) in evdev::enumerate() {
        // A mouse and nothing but a mouse — see `is_mouse_only`.
        if !is_mouse_only(&device) {
            continue;
        }
        let Some(keys) = device.supported_keys() else {
            continue;
        };
        let codes: Vec<(KeyCode, Action)> = wanted
            .iter()
            .filter(|(code, _)| keys.contains(*code))
            .copied()
            .collect();
        if codes.is_empty() {
            continue;
        }

        let identity = identify(&device);
        match spawn_reader(app.clone(), device, codes, Arc::clone(&stop)) {
            Ok(()) => opened += 1,
            Err(error) => {
                tracing::debug!(path = %path.display(), %error, "could not read a mouse device");
                blocked.push(identity);
            }
        }
    }

    // Mice we could not even open, so the permission case is visible rather
    // than looking like the button simply does not exist.
    blocked.extend(unreadable_mice());
    dedupe(&mut blocked);

    if opened == 0 {
        return (
            None,
            if blocked.is_empty() {
                GrabOutcome::NoDevice
            } else {
                GrabOutcome::NoPermission { devices: blocked }
            },
        );
    }

    tracing::info!(devices = opened, "reading mouse buttons globally");
    (
        Some(MouseGrab { stop }),
        GrabOutcome::Active { devices: opened },
    )
}

/// The mouse event nodes that exist but cannot be opened.
///
/// Used to tell "no permission on this device" apart from "no such device",
/// which are very different things to tell a user, and to name the devices the
/// generated udev rule has to cover. No event is read from them; only the ids
/// udev itself already publishes.
///
/// udev tags mouse nodes in `/dev/input/by-id` with an `-event-mouse` suffix,
/// which identifies them without opening anything — necessary here, since a
/// device we lack permission to open is also a device whose capabilities we
/// cannot inspect. Listing bare `event*` nodes instead would report every
/// keyboard and power button on the machine as a mouse.
///
/// That the suffix comes from udev's own `ID_INPUT_MOUSE` classification is
/// what makes it the right signal: the generated rule matches on exactly the
/// same property, so what is listed here is what the rule will cover.
#[cfg(target_os = "linux")]
fn unreadable_mice() -> Vec<MouseDevice> {
    let Ok(entries) = std::fs::read_dir("/dev/input/by-id") else {
        // No udev tagging available. Better to report nothing than to report
        // things that are probably not mice.
        return Vec::new();
    };
    let mut found: Vec<MouseDevice> = entries
        .flatten()
        .filter(|entry| {
            entry
                .file_name()
                .to_str()
                .is_some_and(|name| name.ends_with("-event-mouse"))
        })
        .filter(|entry| std::fs::File::open(entry.path()).is_err())
        .filter_map(|entry| identify_from_sysfs(&entry.path()))
        .collect();
    dedupe(&mut found);
    found
}

/// Read a device's ids out of sysfs, without opening its event node.
///
/// The whole point: a node we cannot `open(2)` is a node whose capabilities and
/// name `ioctl` cannot tell us either, yet those ids are exactly what the user
/// needs to write a rule. sysfs publishes them world-readably.
#[cfg(target_os = "linux")]
fn identify_from_sysfs(link: &std::path::Path) -> Option<MouseDevice> {
    let node = std::fs::canonicalize(link).ok()?;
    let node = node.file_name()?.to_str()?;
    let base = std::path::Path::new("/sys/class/input")
        .join(node)
        .join("device");

    let read = |relative: &str| std::fs::read_to_string(base.join(relative)).ok();
    // A malformed id would produce a rule that silently matches nothing, which
    // is far worse than admitting we could not identify the device.
    let hex = |value: Option<String>| {
        value
            .map(|value| value.trim().to_ascii_lowercase())
            .filter(|value| value.len() == 4 && value.bytes().all(|b| b.is_ascii_hexdigit()))
    };

    Some(MouseDevice {
        name: clean_name(read("name").as_deref().unwrap_or("unnamed mouse").trim()),
        vendor: hex(read("id/vendor"))?,
        product: hex(read("id/product"))?,
    })
}

/// Collapse devices sharing a vendor and product id.
///
/// One physical mouse routinely presents more than one `-event-mouse` node, and
/// a single rule covers them all — listing it three times would only suggest
/// the user has three mice.
fn dedupe(devices: &mut Vec<MouseDevice>) {
    let mut seen: Vec<(String, String)> = Vec::new();
    devices.retain(|device| {
        let key = (device.vendor.clone(), device.product.clone());
        if seen.contains(&key) {
            return false;
        }
        seen.push(key);
        true
    });
}

/// Make a device name safe to paste into a udev rule as a comment.
///
/// The name comes from the hardware, so it is attacker-controlled in the sense
/// that anyone who can plug in a USB device chooses it. A newline in it would
/// end the comment and let the rest become a rule of its own, in a file the
/// user is about to run through `sudo tee`.
fn clean_name(name: &str) -> String {
    let cleaned: String = name
        .chars()
        .map(|c| if c.is_control() { ' ' } else { c })
        .collect();
    let cleaned = cleaned.split_whitespace().collect::<Vec<_>>().join(" ");
    if cleaned.is_empty() {
        return "unnamed mouse".into();
    }
    cleaned.chars().take(80).collect()
}

/// Build a udev rule file granting this user access to exactly these mice.
///
/// # Why this shape
///
/// * `TAG+="uaccess"` hands the device to whoever is logged in at the local
///   seat, through an ACL that logind puts on and takes off with the session.
///   No new group, nothing persistent, and nobody logged in over SSH inherits
///   it. A blanket `MODE="0666"` would instead expose the mouse to every
///   account on the machine.
/// * `ATTRS{idVendor}`/`ATTRS{idProduct}` name the one device. Matching a path
///   such as `/dev/input/event3` would be useless: that number is assigned in
///   probe order and moves when something else is plugged in first.
/// * `ENV{ID_INPUT_MOUSE}=="1", ENV{ID_INPUT_KEYBOARD}!="1"` are what keep the
///   grant from widening. The vendor and product ids belong to the *physical*
///   device, and a keyboard with a built-in mouse node — which is precisely the
///   hardware in question here, since that is where the bound thumb button
///   often lives — publishes its keyboard on the same pair. Without these two
///   clauses the rule would hand out the keyboard along with the mouse and
///   quietly recreate the problem the `input` group had.
/// * The file must sort between `60-input-id.rules`, which sets those two
///   properties, and `73-seat-late.rules`, which acts on the tag. Hence `70-`.
pub fn udev_rule(devices: &[MouseDevice]) -> String {
    let mut rule = format!(
        "# Pickle: read one mouse's buttons, and nothing else.\n\
         #\n\
         # Install with:\n\
         #   sudo cp <this file> {UDEV_RULE_PATH}\n\
         #   sudo udevadm control --reload\n\
         #   sudo udevadm trigger --subsystem-match=input\n\
         # then unplug and replug the mouse, or reboot.\n\
         #\n\
         # Each rule grants access to one device, for whoever is logged in at\n\
         # this machine's own screen and keyboard, for as long as that session\n\
         # lasts. It is not the `input` group: nothing here gives any process\n\
         # access to a keyboard, to another user's devices, or to a device that\n\
         # is not named below.\n\
         #\n\
         # Derive the ids for a mouse yourself with:\n\
         #   udevadm info -a -n /dev/input/eventN | grep -m2 -E 'idVendor|idProduct'\n\
         # For a Bluetooth or I2C mouse, which has no USB parent, use\n\
         # ATTRS{{id/vendor}} and ATTRS{{id/product}} in place of\n\
         # ATTRS{{idVendor}} and ATTRS{{idProduct}}.\n"
    );

    for device in devices {
        // Cleaned here rather than trusting the constructor: this is the point
        // where a newline in a hardware-chosen name would stop being a comment
        // and start being a rule.
        rule.push_str(&format!(
            "\n# {}\n\
             SUBSYSTEM==\"input\", KERNEL==\"event*\", \
             ENV{{ID_INPUT_MOUSE}}==\"1\", ENV{{ID_INPUT_KEYBOARD}}!=\"1\", \
             ATTRS{{idVendor}}==\"{}\", ATTRS{{idProduct}}==\"{}\", TAG+=\"uaccess\"\n",
            clean_name(&device.name),
            device.vendor,
            device.product,
        ));
    }

    rule
}

/// The rule the user needs right now, or `None` when nothing is blocked.
///
/// Returning `None` rather than a speculative rule matters: a rule is a change
/// to a system's permissions, and there is no reason to show one to someone
/// whose mouse already works.
#[cfg(target_os = "linux")]
pub fn udev_advice() -> Option<UdevAdvice> {
    let devices = unreadable_mice();
    if devices.is_empty() {
        return None;
    }
    Some(UdevAdvice {
        path: UDEV_RULE_PATH.into(),
        rule: udev_rule(&devices),
        devices,
    })
}

#[cfg(not(target_os = "linux"))]
pub fn udev_advice() -> Option<UdevAdvice> {
    None
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

    fn a_mouse(vendor: &str, product: &str) -> MouseDevice {
        MouseDevice {
            name: "Test Mouse".into(),
            vendor: vendor.into(),
            product: product.into(),
        }
    }

    #[test]
    fn the_permission_case_names_the_fix() {
        // The whole point of telling this case apart from "no such device".
        let message = GrabOutcome::NoPermission {
            devices: vec![a_mouse("04a5", "800a"), a_mouse("31e3", "1220")],
        }
        .explain()
        .unwrap();
        assert!(message.contains('2'), "says how many: {message}");
        assert!(message.contains("udev"), "points at the fix: {message}");
    }

    #[test]
    fn the_permission_case_does_not_advise_the_input_group() {
        // Joining `input` grants every process this user runs a permanent read
        // on every keyboard on the machine. That advice must not come back.
        let message = GrabOutcome::NoPermission {
            devices: vec![a_mouse("04a5", "800a")],
        }
        .explain()
        .unwrap();
        assert!(!message.contains("usermod"), "{message}");
        assert!(!message.contains("group"), "{message}");
    }

    #[test]
    fn the_rule_grants_one_device_and_never_a_keyboard() {
        let rule = udev_rule(&[a_mouse("04a5", "800a")]);
        assert!(rule.contains(r#"ATTRS{idVendor}=="04a5""#), "{rule}");
        assert!(rule.contains(r#"ATTRS{idProduct}=="800a""#), "{rule}");
        // Without these the rule would also match the keyboard node of a
        // keyboard-and-mouse combo sharing one vendor and product id.
        assert!(rule.contains(r#"ENV{ID_INPUT_MOUSE}=="1""#), "{rule}");
        assert!(rule.contains(r#"ENV{ID_INPUT_KEYBOARD}!="1""#), "{rule}");
        // Session-scoped ACL, not a world-readable node or a new group.
        assert!(rule.contains(r#"TAG+="uaccess""#), "{rule}");
        assert!(!rule.contains("MODE="), "{rule}");
        assert!(!rule.contains("GROUP="), "{rule}");
    }

    #[test]
    fn the_rule_covers_every_device_it_was_given() {
        let rule = udev_rule(&[a_mouse("04a5", "800a"), a_mouse("3434", "d030")]);
        assert_eq!(rule.matches("TAG+=\"uaccess\"").count(), 2, "{rule}");
    }

    #[test]
    fn a_device_name_cannot_smuggle_a_rule_of_its_own() {
        // The name is chosen by whoever made the hardware, and the file it
        // lands in is one the user is about to install as root.
        let hostile = MouseDevice {
            name: "Mouse\nKERNEL==\"event*\", MODE=\"0666\"".into(),
            vendor: "0000".into(),
            product: "0000".into(),
        };
        let rule = udev_rule(std::slice::from_ref(&hostile));
        // The smuggled text may survive as comment prose; what it must not do
        // is reach a line udev will act on.
        for line in rule.lines() {
            if line.is_empty() || line.starts_with('#') {
                continue;
            }
            assert!(
                line.starts_with(r#"SUBSYSTEM=="input", KERNEL=="event*""#)
                    && line.ends_with(r#"TAG+="uaccess""#),
                "stray rule line: {line}",
            );
        }
    }

    #[test]
    fn one_mouse_with_several_nodes_is_listed_once() {
        let mut devices = vec![
            a_mouse("04a5", "800a"),
            a_mouse("04a5", "800a"),
            a_mouse("3434", "d030"),
        ];
        dedupe(&mut devices);
        assert_eq!(devices.len(), 2);
    }

    #[test]
    fn every_inactive_outcome_explains_itself() {
        for outcome in [
            GrabOutcome::NoPermission {
                devices: vec![a_mouse("04a5", "800a")],
            },
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

    /// The capability check, exercised against bitmaps copied from the real
    /// devices this was developed against plus the composite hardware the old
    /// `BTN_LEFT`-only check would have let through.
    #[cfg(target_os = "linux")]
    mod device_filter {
        use evdev::{AttributeSet, KeyCode, RelativeAxisCode};

        fn accepts(keys: &[KeyCode], axes: &[RelativeAxisCode]) -> bool {
            let keys: AttributeSet<KeyCode> = keys.iter().collect();
            let axes: AttributeSet<RelativeAxisCode> = axes.iter().collect();
            super::super::capabilities_are_mouse_only(&keys, Some(&axes))
        }

        /// What every one of the three real mice on the development machine
        /// reports: five buttons, relative X and Y, no key codes at all.
        const MOUSE_BUTTONS: [KeyCode; 5] = [
            KeyCode::BTN_LEFT,
            KeyCode::BTN_RIGHT,
            KeyCode::BTN_MIDDLE,
            KeyCode::BTN_SIDE,
            KeyCode::BTN_EXTRA,
        ];
        const POINTER_AXES: [RelativeAxisCode; 4] = [
            RelativeAxisCode::REL_X,
            RelativeAxisCode::REL_Y,
            RelativeAxisCode::REL_WHEEL,
            RelativeAxisCode::REL_HWHEEL,
        ];

        #[test]
        fn an_ordinary_mouse_is_accepted() {
            assert!(accepts(&MOUSE_BUTTONS, &POINTER_AXES));
        }

        #[test]
        fn a_mouse_with_browser_buttons_is_still_accepted() {
            // Plenty of mice map the side buttons to KEY_BACK and KEY_FORWARD
            // (158 and 159). Those are above the typing block deliberately: a
            // device cannot spell anything with them.
            let mut keys = MOUSE_BUTTONS.to_vec();
            keys.extend([KeyCode::KEY_BACK, KeyCode::KEY_FORWARD]);
            assert!(accepts(&keys, &POINTER_AXES));
        }

        #[test]
        fn a_composite_keyboard_and_pointer_is_rejected() {
            // The case the old BTN_LEFT-only check missed, and the reason the
            // privacy note in the module docs was a stronger claim than the
            // code enforced: a laptop keyboard with a trackpoint, or a combo
            // behind one receiver, reports both on a single node.
            let mut keys = MOUSE_BUTTONS.to_vec();
            keys.extend([KeyCode::KEY_A, KeyCode::KEY_S, KeyCode::KEY_D]);
            assert!(
                !accepts(&keys, &POINTER_AXES),
                "a node that can report KEY_A must never be opened",
            );
        }

        #[test]
        fn every_key_of_the_typing_block_disqualifies_a_device() {
            for code in KeyCode::KEY_1.0..=KeyCode::KEY_SLASH.0 {
                let mut keys = MOUSE_BUTTONS.to_vec();
                keys.push(KeyCode(code));
                assert!(!accepts(&keys, &POINTER_AXES), "key {code} slipped through");
            }
        }

        #[test]
        fn a_plain_keyboard_is_rejected() {
            let keys = [KeyCode::KEY_A, KeyCode::KEY_ENTER, KeyCode::KEY_LEFTSHIFT];
            assert!(!accepts(&keys, &[]));
        }

        #[test]
        fn a_device_that_cannot_move_a_pointer_is_rejected() {
            // A gamepad or a media-key node may claim BTN_LEFT without being
            // anything a person would call a mouse.
            assert!(!accepts(&MOUSE_BUTTONS, &[RelativeAxisCode::REL_WHEEL]));
            assert!(!accepts(&MOUSE_BUTTONS, &[RelativeAxisCode::REL_X]));
            let keys: AttributeSet<KeyCode> = MOUSE_BUTTONS.iter().collect();
            assert!(!super::super::capabilities_are_mouse_only(&keys, None));
        }

        #[test]
        fn a_pointer_without_buttons_is_rejected() {
            assert!(!accepts(&[KeyCode::BTN_RIGHT], &POINTER_AXES));
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
