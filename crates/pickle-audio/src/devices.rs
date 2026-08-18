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
    /// Whether the device can be used at all.
    ///
    /// A rate other than 48 kHz no longer disqualifies anything — it is
    /// converted at the device boundary by [`crate::resample`]. This is false
    /// only when the device positively reports no sample format Pickle can
    /// read, which is a real incompatibility rather than a rate.
    ///
    /// A device that could not be queried at all stays `true`. The honest
    /// answer there is that we do not know, and greying out someone's
    /// microphone because its driver was busy for a moment is the worse of the
    /// two mistakes — the stream start will say so properly if it really is
    /// broken.
    pub usable: bool,
    /// The rate the device would be opened at, or `None` when it could not be
    /// queried.
    ///
    /// 48 kHz means the audio path runs end to end with no conversion at all.
    pub sample_rate: Option<u32>,
}

impl DeviceInfo {
    /// Whether audio would pass through a rate conversion on this device.
    pub fn needs_resampling(&self) -> bool {
        matches!(self.sample_rate, Some(rate) if rate != SAMPLE_RATE)
    }
}

#[derive(Debug, thiserror::Error)]
pub enum DeviceError {
    #[error("no {0} device is available")]
    NoDevice(&'static str),
    #[error("no {kind} device named {name:?}")]
    NotFound { kind: &'static str, name: String },
    #[error("{name} offers no 16-bit or floating point format, which Pickle needs")]
    UnsupportedFormat { name: String },
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

            // A device that cannot be queried is reported as usable with an
            // unknown rate, rather than being condemned on no evidence.
            let (usable, sample_rate) = match supported_configs(&device, kind) {
                Ok(configs) => match choose_config(&configs) {
                    Some((_, rate)) => (true, Some(rate)),
                    None => (false, None),
                },
                Err(_) => (true, None),
            };

            Some(DeviceInfo {
                is_default: Some(&name) == default_name.as_ref(),
                name,
                kind,
                usable,
                sample_rate,
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

fn supported_configs(
    device: &cpal::Device,
    kind: DeviceKind,
) -> Result<Vec<cpal::SupportedStreamConfigRange>, DeviceError> {
    match kind {
        DeviceKind::Input => device
            .supported_input_configs()
            .map(|c| c.collect::<Vec<_>>()),
        DeviceKind::Output => device
            .supported_output_configs()
            .map(|c| c.collect::<Vec<_>>()),
    }
    .map_err(|e| DeviceError::Enumeration(e.to_string()))
}

/// Pick the configuration to open a device with, and the rate to open it at.
///
/// 48 kHz is taken whenever it is on offer, because it is what the rest of the
/// pipeline runs at and costs nothing to convert. Otherwise the closest
/// available rate wins, which keeps the conversion ratio — and so the filter's
/// cost and its latency — as small as it can be. Ties go to the higher rate,
/// since discarding bandwidth we have is better than inventing bandwidth we do
/// not, and then to the fewest channels: Opus is fed mono, so a stereo capture
/// only gets downmixed and asking for it wastes work.
fn choose_config(
    configs: &[cpal::SupportedStreamConfigRange],
) -> Option<(cpal::SupportedStreamConfigRange, u32)> {
    configs
        .iter()
        .filter(|config| {
            matches!(
                config.sample_format(),
                cpal::SampleFormat::F32 | cpal::SampleFormat::I16
            )
        })
        .map(|config| {
            let rate = SAMPLE_RATE.clamp(config.min_sample_rate(), config.max_sample_rate());
            (*config, rate)
        })
        .min_by_key(|(config, rate)| {
            (
                rate.abs_diff(SAMPLE_RATE),
                std::cmp::Reverse(*rate),
                config.channels(),
            )
        })
}

/// Resolve a stream configuration for a device.
///
/// The returned rate is not necessarily 48 kHz. The engine compares it against
/// [`SAMPLE_RATE`] and inserts a converter when they differ; every stage after
/// that still sees 48 kHz mono in 20 ms frames.
pub fn pick_config(
    device: &cpal::Device,
    kind: DeviceKind,
) -> Result<cpal::SupportedStreamConfig, DeviceError> {
    let configs = supported_configs(device, kind)?;

    let (chosen, rate) = choose_config(&configs).ok_or_else(|| DeviceError::UnsupportedFormat {
        name: device_name(device).unwrap_or_else(|| "unknown".into()),
    })?;

    Ok(chosen.with_sample_rate(rate))
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
        let Some(device) = devices.iter().find(|d| d.sample_rate == Some(SAMPLE_RATE)) else {
            return;
        };
        let Ok(handle) = open(DeviceKind::Output, Some(&device.name)) else {
            return;
        };

        let config = pick_config(&handle, DeviceKind::Output).unwrap();
        assert_eq!(config.sample_rate(), SAMPLE_RATE);
    }

    #[test]
    fn a_listed_rate_is_the_rate_the_device_is_actually_opened_at() {
        // The UI shows this number, so it has to be the truth rather than a
        // guess. Nothing is asserted about a device whose rate came back
        // unknown, which is exactly what `None` is there to express.
        for kind in [DeviceKind::Input, DeviceKind::Output] {
            let Ok(devices) = list(kind) else { continue };
            for info in devices.iter().filter(|d| d.sample_rate.is_some()) {
                let Ok(handle) = open(kind, Some(&info.name)) else {
                    continue;
                };
                match pick_config(&handle, kind) {
                    Ok(config) => assert_eq!(config.sample_rate(), info.sample_rate.unwrap()),
                    // A driver readable a moment ago can be busy now. That is a
                    // fact about the machine, not about this logic.
                    Err(DeviceError::Enumeration(_)) => {}
                    Err(e) => panic!("{} listed as usable but failed: {e}", info.name),
                }
            }
        }
    }

    #[test]
    fn no_device_is_listed_as_unusable_with_a_rate() {
        // The two fields have to tell the same story, or the UI shows a device
        // greyed out and annotated with the rate it would have used.
        for kind in [DeviceKind::Input, DeviceKind::Output] {
            let Ok(devices) = list(kind) else { continue };
            for info in &devices {
                assert!(
                    info.usable || info.sample_rate.is_none(),
                    "{} is unusable but has a rate",
                    info.name,
                );
            }
        }
    }

    // Selection is pure, so it can be driven with configurations no machine
    // here has — which is the only way to cover the devices this work is for.

    fn range(
        channels: u16,
        min: u32,
        max: u32,
        format: cpal::SampleFormat,
    ) -> cpal::SupportedStreamConfigRange {
        cpal::SupportedStreamConfigRange::new(
            channels,
            min,
            max,
            cpal::SupportedBufferSize::Unknown,
            format,
        )
    }

    #[test]
    fn a_forty_four_one_only_device_is_now_selectable() {
        // The whole point: this device used to be greyed out as unsupported.
        let configs = [range(2, 44_100, 44_100, cpal::SampleFormat::F32)];
        let (chosen, rate) = choose_config(&configs).expect("44.1 kHz is usable now");
        assert_eq!(rate, 44_100);
        assert_eq!(chosen.channels(), 2);
    }

    #[test]
    fn native_rate_wins_over_a_closer_channel_count() {
        // Avoiding the conversion is worth more than avoiding a downmix.
        let configs = [
            range(1, 44_100, 44_100, cpal::SampleFormat::F32),
            range(8, 48_000, 48_000, cpal::SampleFormat::F32),
        ];
        let (chosen, rate) = choose_config(&configs).unwrap();
        assert_eq!(rate, SAMPLE_RATE);
        assert_eq!(chosen.channels(), 8);
    }

    #[test]
    fn the_closest_rate_is_chosen_so_the_conversion_ratio_stays_small() {
        let configs = [
            range(2, 8_000, 8_000, cpal::SampleFormat::I16),
            range(2, 44_100, 44_100, cpal::SampleFormat::I16),
            range(2, 192_000, 192_000, cpal::SampleFormat::I16),
        ];
        assert_eq!(choose_config(&configs).unwrap().1, 44_100);
    }

    #[test]
    fn a_range_spanning_the_native_rate_is_pinned_to_it() {
        let configs = [range(2, 8_000, 192_000, cpal::SampleFormat::F32)];
        assert_eq!(choose_config(&configs).unwrap().1, SAMPLE_RATE);
    }

    #[test]
    fn a_range_entirely_above_or_below_is_clamped_to_its_nearest_edge() {
        let above = [range(2, 96_000, 192_000, cpal::SampleFormat::F32)];
        assert_eq!(choose_config(&above).unwrap().1, 96_000);

        let below = [range(2, 8_000, 16_000, cpal::SampleFormat::F32)];
        assert_eq!(choose_config(&below).unwrap().1, 16_000);
    }

    #[test]
    fn an_equally_distant_pair_prefers_the_higher_rate() {
        // 32 kHz and 64 kHz are both 16 kHz away. Downsampling from 64 keeps
        // the whole voice band; upsampling from 32 cannot put back what the
        // device never captured.
        let configs = [
            range(2, 32_000, 32_000, cpal::SampleFormat::F32),
            range(2, 64_000, 64_000, cpal::SampleFormat::F32),
        ];
        assert_eq!(choose_config(&configs).unwrap().1, 64_000);
    }

    #[test]
    fn fewer_channels_still_break_a_tie_at_the_same_rate() {
        let configs = [
            range(6, 48_000, 48_000, cpal::SampleFormat::F32),
            range(1, 48_000, 48_000, cpal::SampleFormat::F32),
        ];
        assert_eq!(choose_config(&configs).unwrap().0.channels(), 1);
    }

    #[test]
    fn a_format_we_cannot_read_is_still_refused() {
        // Resampling fixes rates, not sample formats. A device offering only
        // 24-bit packed samples remains genuinely unusable, and the UI should
        // keep saying so.
        let configs = [range(2, 48_000, 48_000, cpal::SampleFormat::I24)];
        assert!(choose_config(&configs).is_none());
    }

    #[test]
    fn a_readable_format_is_preferred_over_an_unreadable_one_at_a_better_rate() {
        let configs = [
            range(2, 48_000, 48_000, cpal::SampleFormat::I24),
            range(2, 44_100, 44_100, cpal::SampleFormat::F32),
        ];
        let (chosen, rate) = choose_config(&configs).unwrap();
        assert_eq!(rate, 44_100);
        assert_eq!(chosen.sample_format(), cpal::SampleFormat::F32);
    }

    #[test]
    fn a_device_with_nothing_on_offer_is_unusable() {
        assert!(choose_config(&[]).is_none());
    }

    #[test]
    fn only_a_known_non_native_rate_counts_as_resampled() {
        let native = DeviceInfo {
            name: "native".into(),
            kind: DeviceKind::Input,
            is_default: false,
            usable: true,
            sample_rate: Some(SAMPLE_RATE),
        };
        assert!(!native.needs_resampling());

        let converted = DeviceInfo {
            sample_rate: Some(44_100),
            ..native.clone()
        };
        assert!(converted.needs_resampling());

        // Unknown must not be reported as resampled, or every device behind a
        // driver that would not answer gets an annotation nobody can act on.
        let unknown = DeviceInfo {
            sample_rate: None,
            ..native.clone()
        };
        assert!(!unknown.needs_resampling());
    }
}
