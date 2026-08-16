//! Enumerating and selecting audio hardware.
//!
//! Devices are referred to by name rather than by index. Indices shift when a
//! headset is unplugged, which would silently move a user's microphone
//! selection to a different device.

use cpal::traits::{DeviceTrait, HostTrait};
use pickle_proto::voice::SAMPLE_RATE;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DeviceKind {
    Input,
    Output,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DeviceInfo {
    pub name: String,
    pub kind: DeviceKind,
    /// True for the system default, which is what the UI should preselect.
    pub is_default: bool,
    /// Whether the device supports 48 kHz natively.
    ///
    /// Pickle runs the whole path at 48 kHz to avoid resampling, so a device
    /// without it cannot be used yet. Surfacing this lets the UI grey the
    /// device out with a reason instead of failing at stream start.
    pub supports_native_rate: bool,
}

#[derive(Debug, thiserror::Error)]
pub enum DeviceError {
    #[error("no {0} device is available")]
    NoDevice(&'static str),
    #[error("no {kind} device named {name:?}")]
    NotFound { kind: &'static str, name: String },
    #[error(
        "{name} does not support {SAMPLE_RATE} Hz, which Pickle needs in order \
         to avoid resampling"
    )]
    UnsupportedSampleRate { name: String },
    #[error("querying audio devices: {0}")]
    Enumeration(String),
}

impl DeviceKind {
    fn label(self) -> &'static str {
        match self {
            DeviceKind::Input => "input",
            DeviceKind::Output => "output",
        }
    }
}

/// A device's display name.
///
/// Returns `None` for a device that has been unplugged between enumeration and
/// this call, which is common enough to be worth handling rather than
/// unwrapping.
fn device_name(device: &cpal::Device) -> Option<String> {
    device
        .description()
        .ok()
        .map(|description| description.name().to_string())
}

/// List the available devices of one kind.
///
/// A device that cannot be queried is skipped rather than failing the whole
/// list — one broken driver should not hide every other microphone.
pub fn list(kind: DeviceKind) -> Result<Vec<DeviceInfo>, DeviceError> {
    let host = cpal::default_host();

    let default_name = match kind {
        DeviceKind::Input => host.default_input_device(),
        DeviceKind::Output => host.default_output_device(),
    }
    .and_then(|device| device_name(&device));

    let devices = match kind {
        DeviceKind::Input => host.input_devices().map(|d| d.collect::<Vec<_>>()),
        DeviceKind::Output => host.output_devices().map(|d| d.collect::<Vec<_>>()),
    }
    .map_err(|e| DeviceError::Enumeration(e.to_string()))?;

    Ok(devices
        .into_iter()
        .filter_map(|device| {
            let name = device_name(&device)?;
            let supports_native_rate = supports_rate(&device, kind, SAMPLE_RATE);
            Some(DeviceInfo {
                is_default: Some(&name) == default_name.as_ref(),
                name,
                kind,
                supports_native_rate,
            })
        })
        .collect())
}

/// Resolve a device by name, or the system default when `name` is `None`.
pub fn open(kind: DeviceKind, name: Option<&str>) -> Result<cpal::Device, DeviceError> {
    let host = cpal::default_host();

    match name {
        None => match kind {
            DeviceKind::Input => host.default_input_device(),
            DeviceKind::Output => host.default_output_device(),
        }
        .ok_or(DeviceError::NoDevice(kind.label())),

        Some(wanted) => {
            let devices = match kind {
                DeviceKind::Input => host.input_devices().map(|d| d.collect::<Vec<_>>()),
                DeviceKind::Output => host.output_devices().map(|d| d.collect::<Vec<_>>()),
            }
            .map_err(|e| DeviceError::Enumeration(e.to_string()))?;

            devices
                .into_iter()
                .find(|device| device_name(device).is_some_and(|n| n == wanted))
                .ok_or_else(|| DeviceError::NotFound {
                    kind: kind.label(),
                    name: wanted.to_string(),
                })
        }
    }
}

fn supports_rate(device: &cpal::Device, kind: DeviceKind, rate: u32) -> bool {
    let configs = match kind {
        DeviceKind::Input => device
            .supported_input_configs()
            .map(|c| c.collect::<Vec<_>>()),
        DeviceKind::Output => device
            .supported_output_configs()
            .map(|c| c.collect::<Vec<_>>()),
    };

    configs.is_ok_and(|configs| {
        configs
            .into_iter()
            .any(|config| config.min_sample_rate() <= rate && rate <= config.max_sample_rate())
    })
}

/// Pick a stream configuration at 48 kHz, preferring the fewest channels.
///
/// Mono is preferred because that is what Opus is fed; a stereo capture just
/// gets downmixed, so asking for it wastes work.
pub fn pick_config(
    device: &cpal::Device,
    kind: DeviceKind,
) -> Result<cpal::SupportedStreamConfig, DeviceError> {
    let name = device_name(device).unwrap_or_else(|| "unknown".into());

    let configs = match kind {
        DeviceKind::Input => device
            .supported_input_configs()
            .map(|c| c.collect::<Vec<_>>()),
        DeviceKind::Output => device
            .supported_output_configs()
            .map(|c| c.collect::<Vec<_>>()),
    }
    .map_err(|e| DeviceError::Enumeration(e.to_string()))?;

    let chosen = configs
        .into_iter()
        .filter(|config| {
            config.min_sample_rate() <= SAMPLE_RATE && SAMPLE_RATE <= config.max_sample_rate()
        })
        .filter(|config| {
            matches!(
                config.sample_format(),
                cpal::SampleFormat::F32 | cpal::SampleFormat::I16
            )
        })
        .min_by_key(|config| config.channels())
        .ok_or(DeviceError::UnsupportedSampleRate { name })?;

    Ok(chosen.with_sample_rate(SAMPLE_RATE))
}

#[cfg(test)]
mod tests {
    use super::*;

    // These run against whatever hardware the machine has, including none, so
    // they assert on invariants rather than on specific devices.

    #[test]
    fn listing_devices_does_not_fail_on_a_machine_without_any() {
        for kind in [DeviceKind::Input, DeviceKind::Output] {
            let devices = list(kind).unwrap_or_default();
            for device in &devices {
                assert!(!device.name.is_empty());
                assert_eq!(device.kind, kind);
            }
        }
    }

    #[test]
    fn at_most_one_device_of_each_kind_is_the_default() {
        for kind in [DeviceKind::Input, DeviceKind::Output] {
            let devices = list(kind).unwrap_or_default();
            assert!(devices.iter().filter(|d| d.is_default).count() <= 1);
        }
    }

    #[test]
    fn asking_for_a_device_that_does_not_exist_is_a_clear_error() {
        let result = open(DeviceKind::Input, Some("no such microphone, surely"));
        assert!(matches!(result, Err(DeviceError::NotFound { .. })));
    }

    #[test]
    fn a_listed_device_can_be_reopened_by_name() {
        // Names are the stable handle we persist in settings, so this is the
        // property that matters.
        let Ok(devices) = list(DeviceKind::Output) else {
            return;
        };
        let Some(first) = devices.first() else {
            return;
        };
        assert!(open(DeviceKind::Output, Some(&first.name)).is_ok());
    }

    #[test]
    fn a_device_advertising_native_rate_yields_a_config_at_that_rate() {
        let Ok(devices) = list(DeviceKind::Output) else {
            return;
        };
        let Some(device) = devices.iter().find(|d| d.supports_native_rate) else {
            return;
        };
        let Ok(handle) = open(DeviceKind::Output, Some(&device.name)) else {
            return;
        };

        let config = pick_config(&handle, DeviceKind::Output).unwrap();
        assert_eq!(config.sample_rate(), SAMPLE_RATE);
    }
}
