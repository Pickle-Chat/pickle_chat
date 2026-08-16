//! Voice activity detection.
//!
//! Transmitting continuously would work, but it wastes bandwidth and means
//! every keyboard and fan in the channel is always audible. Gating on speech
//! is what makes an open microphone tolerable.
//!
//! This is a level gate with hysteresis, not a speech classifier. It opens
//! above one threshold and closes below a lower one, then holds open for a
//! *hangover* period. Both details matter: without hysteresis the gate
//! chatters on and off at the threshold, and without hangover it clips the
//! quiet consonants at the ends of words — the classic walkie-talkie effect.

use pickle_proto::voice::{FLAG_BURST_END, FLAG_BURST_START, FRAME_MS};

/// Level at which the gate opens, in dBFS. Well above room tone, below speech.
pub const DEFAULT_OPEN_DBFS: f32 = -40.0;

/// Level at which it closes. The gap from the open threshold is the hysteresis
/// that stops the gate chattering.
pub const DEFAULT_CLOSE_DBFS: f32 = -50.0;

/// How long the gate stays open after the level drops, in milliseconds.
pub const DEFAULT_HANGOVER_MS: u32 = 300;

/// What the caller should do with this frame.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Activity {
    /// Below the gate. Send nothing.
    Silent,
    /// First frame of a burst. Send with [`FLAG_BURST_START`].
    BurstStart,
    /// Continuing. Send normally.
    Speaking,
    /// Last frame. Send with [`FLAG_BURST_END`] so receivers can release their
    /// jitter buffer immediately instead of waiting for a timeout.
    BurstEnd,
}

impl Activity {
    pub fn should_transmit(self) -> bool {
        !matches!(self, Activity::Silent)
    }

    /// Voice datagram flags for this frame.
    pub fn flags(self) -> u8 {
        match self {
            Activity::BurstStart => FLAG_BURST_START,
            Activity::BurstEnd => FLAG_BURST_END,
            _ => 0,
        }
    }
}

/// How the microphone is gated.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum GateMode {
    /// Gate on measured level.
    VoiceActivity,
    /// Transmit only while the caller says a key is held.
    PushToTalk,
    /// Always transmit. Useful for testing and for users with their own
    /// external gate.
    Continuous,
}

pub struct VoiceGate {
    pub mode: GateMode,
    open_threshold: f32,
    close_threshold: f32,
    hangover_frames: u32,
    hangover_remaining: u32,
    open: bool,
    /// Last measured level, for a UI meter.
    last_dbfs: f32,
}

impl Default for VoiceGate {
    fn default() -> Self {
        Self::new(
            GateMode::VoiceActivity,
            DEFAULT_OPEN_DBFS,
            DEFAULT_CLOSE_DBFS,
            DEFAULT_HANGOVER_MS,
        )
    }
}

impl VoiceGate {
    pub fn new(mode: GateMode, open_dbfs: f32, close_dbfs: f32, hangover_ms: u32) -> Self {
        Self {
            mode,
            open_threshold: open_dbfs,
            // Guard against a configuration where closing is above opening,
            // which would make the gate oscillate every frame.
            close_threshold: close_dbfs.min(open_dbfs),
            hangover_frames: hangover_ms.div_ceil(FRAME_MS),
            hangover_remaining: 0,
            open: false,
            last_dbfs: f32::NEG_INFINITY,
        }
    }

    pub fn set_thresholds(&mut self, open_dbfs: f32, close_dbfs: f32) {
        self.open_threshold = open_dbfs;
        self.close_threshold = close_dbfs.min(open_dbfs);
    }

    pub fn set_hangover_ms(&mut self, hangover_ms: u32) {
        self.hangover_frames = hangover_ms.div_ceil(FRAME_MS);
    }

    /// Most recent input level in dBFS, for a level meter.
    pub fn level_dbfs(&self) -> f32 {
        self.last_dbfs
    }

    pub fn is_open(&self) -> bool {
        self.open
    }

    /// Classify one frame.
    ///
    /// `key_held` is only consulted in [`GateMode::PushToTalk`].
    pub fn update(&mut self, pcm: &[f32], key_held: bool) -> Activity {
        self.last_dbfs = rms_dbfs(pcm);

        let want_open = match self.mode {
            GateMode::Continuous => true,
            GateMode::PushToTalk => key_held,
            GateMode::VoiceActivity => {
                if self.open {
                    // Already open: stay open until it drops below the *lower*
                    // threshold. This is the hysteresis.
                    self.last_dbfs >= self.close_threshold
                } else {
                    self.last_dbfs >= self.open_threshold
                }
            }
        };

        if want_open {
            self.hangover_remaining = self.hangover_frames;
            if self.open {
                Activity::Speaking
            } else {
                self.open = true;
                Activity::BurstStart
            }
        } else if self.open {
            // Below the gate but still in hangover — keep sending so word
            // endings are not clipped.
            if self.hangover_remaining > 0 {
                self.hangover_remaining -= 1;
                if self.hangover_remaining == 0 {
                    self.open = false;
                    Activity::BurstEnd
                } else {
                    Activity::Speaking
                }
            } else {
                self.open = false;
                Activity::BurstEnd
            }
        } else {
            Activity::Silent
        }
    }

    /// Force the gate shut, e.g. when the user mutes mid-sentence.
    pub fn close(&mut self) -> Activity {
        if self.open {
            self.open = false;
            self.hangover_remaining = 0;
            Activity::BurstEnd
        } else {
            Activity::Silent
        }
    }
}

/// Root-mean-square level of a frame in dBFS, where 0 dB is full scale.
///
/// Digital silence has no logarithm, so it returns negative infinity — which
/// compares correctly against any threshold.
pub fn rms_dbfs(pcm: &[f32]) -> f32 {
    if pcm.is_empty() {
        return f32::NEG_INFINITY;
    }

    // Samples are already normalised to +/-1.0, so full scale is 1.0.
    let sum_squares: f64 = pcm.iter().map(|&s| (s as f64) * (s as f64)).sum();

    let rms = (sum_squares / pcm.len() as f64).sqrt();
    if rms <= 0.0 {
        f32::NEG_INFINITY
    } else {
        20.0 * rms.log10() as f32
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use pickle_proto::voice::SAMPLES_PER_FRAME;

    fn frame_at(amplitude: f32) -> Vec<f32> {
        // Alternating so RMS equals the amplitude, keeping the level exact.
        (0..SAMPLES_PER_FRAME)
            .map(|i| if i % 2 == 0 { amplitude } else { -amplitude })
            .collect()
    }

    fn loud() -> Vec<f32> {
        frame_at(0.25) // about -12 dBFS
    }

    fn quiet() -> Vec<f32> {
        frame_at(0.0006) // about -64 dBFS
    }

    #[test]
    fn silence_measures_as_negative_infinity() {
        assert_eq!(
            rms_dbfs(&vec![0.0f32; SAMPLES_PER_FRAME]),
            f32::NEG_INFINITY
        );
        assert_eq!(rms_dbfs(&[]), f32::NEG_INFINITY);
    }

    #[test]
    fn full_scale_measures_near_zero_dbfs() {
        let level = rms_dbfs(&frame_at(1.0));
        assert!(level.abs() < 0.1, "expected about 0 dBFS, got {level}");
    }

    #[test]
    fn halving_the_amplitude_drops_about_six_db() {
        let a = rms_dbfs(&frame_at(0.25));
        let b = rms_dbfs(&frame_at(0.125));
        assert!((a - b - 6.02).abs() < 0.1, "{a} vs {b}");
    }

    #[test]
    fn the_gate_opens_on_speech_and_marks_the_burst_start() {
        let mut gate = VoiceGate::default();
        assert_eq!(gate.update(&quiet(), false), Activity::Silent);
        assert_eq!(gate.update(&loud(), false), Activity::BurstStart);
        assert_eq!(gate.update(&loud(), false), Activity::Speaking);
    }

    #[test]
    fn the_burst_start_flag_is_set_only_on_the_first_frame() {
        assert_eq!(Activity::BurstStart.flags(), FLAG_BURST_START);
        assert_eq!(Activity::Speaking.flags(), 0);
        assert_eq!(Activity::BurstEnd.flags(), FLAG_BURST_END);
    }

    #[test]
    fn the_gate_holds_open_through_the_hangover() {
        // Without this, quiet word endings get chopped off.
        let mut gate = VoiceGate::new(GateMode::VoiceActivity, -40.0, -50.0, 100);
        gate.update(&loud(), false);

        // 100 ms of hangover is 5 frames at 20 ms.
        for frame in 0..4 {
            assert_eq!(
                gate.update(&quiet(), false),
                Activity::Speaking,
                "frame {frame} should still be transmitting"
            );
        }
        assert_eq!(gate.update(&quiet(), false), Activity::BurstEnd);
        assert_eq!(gate.update(&quiet(), false), Activity::Silent);
    }

    #[test]
    fn hysteresis_stops_the_gate_chattering_at_the_threshold() {
        // A level between the two thresholds must not reopen the gate, but
        // must keep it open once it is.
        let mut gate = VoiceGate::new(GateMode::VoiceActivity, -40.0, -50.0, 0);
        let between = frame_at(0.0045); // roughly -47 dBFS

        assert_eq!(gate.update(&between, false), Activity::Silent);

        gate.update(&loud(), false);
        assert_eq!(gate.update(&between, false), Activity::Speaking);
    }

    #[test]
    fn thresholds_cannot_be_inverted_into_an_oscillator() {
        let gate = VoiceGate::new(GateMode::VoiceActivity, -50.0, -40.0, 0);
        assert!(gate.close_threshold <= gate.open_threshold);
    }

    #[test]
    fn push_to_talk_ignores_the_level() {
        let mut gate = VoiceGate::new(GateMode::PushToTalk, -40.0, -50.0, 0);
        assert_eq!(gate.update(&loud(), false), Activity::Silent);
        assert_eq!(gate.update(&quiet(), true), Activity::BurstStart);
        assert_eq!(gate.update(&quiet(), true), Activity::Speaking);
        assert_eq!(gate.update(&quiet(), false), Activity::BurstEnd);
    }

    #[test]
    fn continuous_mode_always_transmits() {
        let mut gate = VoiceGate::new(GateMode::Continuous, -40.0, -50.0, 0);
        assert_eq!(
            gate.update(&vec![0.0f32; SAMPLES_PER_FRAME], false),
            Activity::BurstStart
        );
        assert_eq!(
            gate.update(&vec![0.0f32; SAMPLES_PER_FRAME], false),
            Activity::Speaking
        );
    }

    #[test]
    fn closing_mid_burst_ends_it_cleanly() {
        // Muting mid-sentence must still tell receivers the burst is over.
        let mut gate = VoiceGate::default();
        gate.update(&loud(), false);
        assert_eq!(gate.close(), Activity::BurstEnd);
        assert_eq!(gate.close(), Activity::Silent);
    }

    #[test]
    fn the_level_meter_tracks_the_last_frame() {
        let mut gate = VoiceGate::default();
        gate.update(&loud(), false);
        let level = gate.level_dbfs();
        assert!((-13.0..-11.0).contains(&level), "got {level}");
    }

    #[test]
    fn only_silence_skips_transmission() {
        assert!(!Activity::Silent.should_transmit());
        assert!(Activity::BurstStart.should_transmit());
        assert!(Activity::Speaking.should_transmit());
        assert!(Activity::BurstEnd.should_transmit());
    }
}
