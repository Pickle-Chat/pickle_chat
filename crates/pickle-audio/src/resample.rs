//! Sample rate conversion, used only at the device boundary.
//!
//! Everything from the microphone downmix to the wire and back runs at 48 kHz
//! mono in 20 ms frames. That assumption is load-bearing — Opus's native rate,
//! the jitter buffer's frame accounting, and the mixer's fixed frame all depend
//! on it — so a device that cannot run at 48 kHz is converted here rather than
//! being allowed to change the rate of anything downstream.
//!
//! # Why this is hand-rolled
//!
//! The obvious alternative is `rubato`. It is good, but it converts whole
//! chunks: either a fixed input size or a fixed output size, whichever you pick
//! at construction. A cpal callback gives us neither — the capture callback
//! arrives with whatever number of frames the driver felt like, and the playback
//! callback asks for whatever it feels like. Either way we would have to wrap it
//! in exactly the push/pull buffering below, at which point the resampler itself
//! is the small part. Owning it also makes the real-time property auditable:
//! everything here is allocated in [`Resampler::new`], and neither [`feed`] nor
//! [`pull`] touches the allocator, takes a lock, or blocks.
//!
//! [`feed`]: Resampler::feed
//! [`pull`]: Resampler::pull
//!
//! # Why not plain linear interpolation
//!
//! For 44.1 kHz — the common case — linear interpolation would be nearly good
//! enough, since the ratio is close to 1 and speech energy sits far below
//! Nyquist. It falls apart on the devices that actually motivate this work:
//! Bluetooth headsets and virtual devices that run at 16 kHz or 8 kHz. Going
//! 48 kHz down to 16 kHz with linear interpolation folds everything above
//! 8 kHz back into the voice band, which is plainly audible. A band-limited
//! kernel costs a few million multiply-adds a second and removes the whole
//! class of problem, so there is no real trade to make.
//!
//! # The kernel
//!
//! A Kaiser-windowed sinc, evaluated by interpolating a table that is built
//! once and shared by every resampler. The table is expressed in units of the
//! kernel's own time axis, so it does not depend on the rate ratio at all: only
//! the time scale `fc` and the number of taps do.
//!
//! Latency is half the kernel's width, and nothing else: there is no block
//! buffering on top. See [`Resampler::latency_samples`].

use std::sync::OnceLock;

/// Zero crossings of the sinc on each side of the centre.
///
/// Sets both the cost (twice this many taps per output, at a ratio near 1) and
/// the transition band, which is roughly `2 / HALF_ZEROS` of the sample rate.
/// At 32 the transition is about 2 kHz wide at 48 kHz, which fits under Nyquist
/// with the cutoff below.
const HALF_ZEROS: usize = 32;

/// Table entries per unit of kernel time. The table is interpolated linearly
/// between entries; at this density that error is around -100 dB, well under
/// the kernel's own stopband.
const DENSITY: usize = 512;

/// Kaiser shape parameter, chosen for roughly 90 dB of stopband rejection.
const BETA: f64 = 9.0;

/// Cutoff as a fraction of the lower of the two Nyquist frequencies.
///
/// Backed off from 1.0 so the filter's transition band fits below Nyquist
/// instead of straddling it. The cost is the top tenth of the band: converting
/// a 44.1 kHz device gives up everything above about 19.8 kHz, which no speech
/// codec was going to carry anyway.
const CUTOFF: f64 = 0.90;

/// `sin(pi x) / (pi x)`, defined at zero.
fn sinc(x: f64) -> f64 {
    if x.abs() < 1e-12 {
        1.0
    } else {
        let pi_x = std::f64::consts::PI * x;
        pi_x.sin() / pi_x
    }
}

/// Modified Bessel function of the first kind, order zero.
///
/// The series converges quickly for the arguments a Kaiser window uses, and
/// this runs once at table construction rather than per sample.
fn bessel_i0(x: f64) -> f64 {
    let mut term = 1.0;
    let mut sum = 1.0;
    let half_x_squared = (x / 2.0) * (x / 2.0);
    for k in 1..64 {
        term *= half_x_squared / ((k * k) as f64);
        sum += term;
        if term < sum * 1e-17 {
            break;
        }
    }
    sum
}

/// Half a Kaiser-windowed sinc, sampled at `1 / DENSITY` steps of kernel time.
///
/// Shared: the shape is independent of the sample rates, so every stream in the
/// process reads the same table. Built on first use, which is stream setup —
/// never inside a callback.
fn kernel() -> &'static [f32] {
    static KERNEL: OnceLock<Vec<f32>> = OnceLock::new();
    KERNEL.get_or_init(|| {
        let len = HALF_ZEROS * DENSITY + 2;
        let denominator = bessel_i0(BETA);
        (0..len)
            .map(|i| {
                let u = i as f64 / DENSITY as f64;
                let edge = u / HALF_ZEROS as f64;
                if edge >= 1.0 {
                    return 0.0;
                }
                let window = bessel_i0(BETA * (1.0 - edge * edge).sqrt()) / denominator;
                (sinc(u) * window) as f32
            })
            .collect()
    })
}

/// Streaming rate conversion for one mono channel.
///
/// Push input with [`Resampler::feed`], take output with [`Resampler::pull`].
/// Both are bounded by the buffers the caller supplies and by the internal
/// capacity fixed at construction, so neither can allocate or block. That is
/// what makes this callable from an audio callback.
pub struct Resampler {
    kernel: &'static [f32],
    /// Cutoff as a fraction of the input Nyquist, and equally the kernel's time
    /// scale: one unit of kernel time is `1 / fc` input samples.
    fc: f64,
    /// Half the kernel's support, in input samples.
    half_width: f64,
    /// Input samples per output sample.
    step: f64,
    /// Input history followed by input not yet consumed, oldest first. Fixed
    /// length; `len` says how much of it is live.
    buf: Vec<f32>,
    len: usize,
    /// Where the next output sample falls, in input samples from `buf[0]`.
    ///
    /// Kept small by compaction, so the accumulated rounding over an hour of
    /// speech stays far below one sample and the two rates never drift apart.
    pos: f64,
}

impl Resampler {
    /// A converter from `in_rate` to `out_rate` accepting up to `max_feed`
    /// samples in one [`Resampler::feed`].
    ///
    /// Returns `None` for a nonsensical rate. Equal rates are allowed and give
    /// a gentle low pass, but callers should skip the stage entirely instead.
    pub fn new(in_rate: u32, out_rate: u32, max_feed: usize) -> Option<Self> {
        if in_rate == 0 || out_rate == 0 || max_feed == 0 {
            return None;
        }

        let step = in_rate as f64 / out_rate as f64;
        // Downsampling has to lower the cutoff to the *output* Nyquist, which
        // stretches the kernel over more input samples. Upsampling is bounded
        // by the input Nyquist instead, so `fc` never exceeds `CUTOFF`.
        let fc = CUTOFF * (1.0f64).min(1.0 / step);
        let half_width = HALF_ZEROS as f64 / fc;

        // Room for the history the kernel reaches back over, a whole `max_feed`
        // on top of it, and the lookahead the kernel reaches forward over.
        let capacity = max_feed + 2 * (half_width.ceil() as usize) + step.ceil() as usize + 8;

        Some(Self {
            kernel: kernel(),
            fc,
            half_width,
            step,
            buf: vec![0.0; capacity],
            len: 0,
            pos: 0.0,
        })
    }

    /// The delay this stage adds, in input samples.
    ///
    /// It is the kernel's own group delay and nothing more — there is no block
    /// buffering here, so this is the whole cost.
    pub fn latency_samples(&self) -> f64 {
        self.half_width
    }

    /// The most output samples `input_len` input samples can produce.
    ///
    /// For sizing a pull buffer at setup. Pulling into a smaller buffer is
    /// still correct, just more round trips.
    pub fn max_output_for(&self, input_len: usize) -> usize {
        (input_len as f64 / self.step).ceil() as usize + 2
    }

    /// How many samples the next [`Resampler::feed`] will accept.
    pub fn space(&mut self) -> usize {
        self.compact();
        self.buf.len() - self.len
    }

    /// Take input samples, returning how many were accepted.
    ///
    /// Short accepts only happen when the caller feeds more than the `max_feed`
    /// it asked for without draining in between; feed the remainder after a
    /// [`Resampler::pull`].
    pub fn feed(&mut self, input: &[f32]) -> usize {
        self.compact();
        let taken = input.len().min(self.buf.len() - self.len);
        self.buf[self.len..self.len + taken].copy_from_slice(&input[..taken]);
        self.len += taken;
        taken
    }

    /// Write as many output samples as are available into `out`.
    ///
    /// Returns how many were written. Zero means the kernel does not yet have
    /// the input it needs to the right of the next output position — feed more.
    pub fn pull(&mut self, out: &mut [f32]) -> usize {
        let mut written = 0;
        while written < out.len() {
            // The rightmost tap must already be in the buffer. The leftmost is
            // allowed to fall off the front, which is what makes the very start
            // of a stream behave as though silence preceded it.
            if self.pos + self.half_width >= self.len as f64 {
                break;
            }
            out[written] = self.sample_at(self.pos);
            self.pos += self.step;
            written += 1;
        }
        written
    }

    /// Reset to a silent, empty state, for reusing a converter across streams.
    pub fn reset(&mut self) {
        self.buf.fill(0.0);
        self.len = 0;
        self.pos = 0.0;
    }

    /// Convolve the kernel with the buffer, centred at `t` input samples.
    fn sample_at(&self, t: f64) -> f32 {
        let first = (t - self.half_width).ceil();
        let first = if first < 0.0 { 0 } else { first as usize };
        let last = ((t + self.half_width).floor() as usize).min(self.len - 1);

        let mut acc = 0.0f32;
        for n in first..=last {
            acc += self.buf[n] * self.tap((t - n as f64).abs());
        }
        // The kernel is stored without its `fc` amplitude factor, which is what
        // makes it rate independent; it is restored once here rather than on
        // every tap.
        acc * self.fc as f32
    }

    /// The kernel at `tau` input samples from its centre.
    fn tap(&self, tau: f64) -> f32 {
        let index = tau * self.fc * DENSITY as f64;
        let whole = index as usize;
        if whole + 1 >= self.kernel.len() {
            return 0.0;
        }
        let fraction = (index - whole as f64) as f32;
        let low = self.kernel[whole];
        low + (self.kernel[whole + 1] - low) * fraction
    }

    /// Drop input the kernel can no longer reach, sliding the rest to the front.
    ///
    /// A `copy_within` of a few hundred samples, and only when there is
    /// something to drop. No allocation: the buffer keeps its fixed length.
    fn compact(&mut self) {
        let stale = self.pos - self.half_width;
        if stale < 1.0 {
            return;
        }
        let drop = (stale as usize).min(self.len);
        self.buf.copy_within(drop..self.len, 0);
        self.len -= drop;
        self.pos -= drop as f64;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Run a whole signal through, draining as we go — the same push/pull shape
    /// the audio callbacks use, so the tests exercise the real path.
    fn convert(resampler: &mut Resampler, input: &[f32], chunk: usize) -> Vec<f32> {
        let mut out = Vec::new();
        let mut scratch = vec![0.0f32; resampler.max_output_for(chunk)];

        for block in input.chunks(chunk) {
            let mut fed = 0;
            while fed < block.len() {
                let taken = resampler.feed(&block[fed..]);
                assert!(taken > 0, "a drained resampler must accept input");
                fed += taken;
                loop {
                    let made = resampler.pull(&mut scratch);
                    if made == 0 {
                        break;
                    }
                    out.extend_from_slice(&scratch[..made]);
                }
            }
        }
        out
    }

    fn tone(rate: u32, hz: f64, amplitude: f64, samples: usize) -> Vec<f32> {
        (0..samples)
            .map(|i| {
                let t = i as f64 / rate as f64;
                (amplitude * (2.0 * std::f64::consts::PI * hz * t).sin()) as f32
            })
            .collect()
    }

    /// Amplitude of `hz` in `signal`, by correlating against a complex
    /// exponential. A whole DFT would be overkill for one bin.
    fn amplitude_at(signal: &[f32], rate: u32, hz: f64) -> f64 {
        let (mut re, mut im) = (0.0, 0.0);
        for (i, &sample) in signal.iter().enumerate() {
            let phase = 2.0 * std::f64::consts::PI * hz * i as f64 / rate as f64;
            re += sample as f64 * phase.cos();
            im += sample as f64 * phase.sin();
        }
        2.0 * (re * re + im * im).sqrt() / signal.len() as f64
    }

    fn rms(signal: &[f32]) -> f64 {
        if signal.is_empty() {
            return 0.0;
        }
        let sum: f64 = signal.iter().map(|&s| (s as f64) * (s as f64)).sum();
        (sum / signal.len() as f64).sqrt()
    }

    /// Skip the kernel's own delay at each end, where the output is ramping in
    /// and out of silence and would drag every measurement down.
    fn steady<'a>(signal: &'a [f32], resampler: &Resampler) -> &'a [f32] {
        let skip = (resampler.latency_samples() / resampler.step).ceil() as usize + 8;
        &signal[skip..signal.len() - skip]
    }

    #[test]
    fn a_tone_survives_upsampling_with_its_frequency_and_level_intact() {
        // 44.1 kHz is the rate that motivates all of this: it is what the
        // average laptop and the average USB headset actually offer.
        let mut resampler = Resampler::new(44_100, 48_000, 512).unwrap();
        let input = tone(44_100, 1_000.0, 0.5, 44_100);
        let output = convert(&mut resampler, &input, 512);

        let measured = steady(&output, &resampler);
        assert!(
            (amplitude_at(measured, 48_000, 1_000.0) - 0.5).abs() < 0.005,
            "amplitude was {}",
            amplitude_at(measured, 48_000, 1_000.0)
        );
        // A tone at the wrong frequency would still show energy, so check that
        // essentially all of the energy is in the bin we asked for.
        let expected_rms = 0.5 / 2.0f64.sqrt();
        assert!(
            (rms(measured) - expected_rms).abs() < 0.005,
            "rms was {}",
            rms(measured)
        );
    }

    #[test]
    fn a_tone_survives_downsampling_with_its_frequency_and_level_intact() {
        let mut resampler = Resampler::new(48_000, 44_100, 512).unwrap();
        let input = tone(48_000, 1_000.0, 0.5, 48_000);
        let output = convert(&mut resampler, &input, 512);

        let measured = steady(&output, &resampler);
        assert!(
            (amplitude_at(measured, 44_100, 1_000.0) - 0.5).abs() < 0.005,
            "amplitude was {}",
            amplitude_at(measured, 44_100, 1_000.0)
        );
    }

    #[test]
    fn the_speech_band_is_flat_across_both_directions() {
        // Voice lives here. A resampler that coloured this band would be worse
        // than the problem it solves.
        for (from, to) in [(44_100, 48_000), (48_000, 44_100), (16_000, 48_000)] {
            for hz in [100.0, 300.0, 1_000.0, 3_400.0] {
                let mut resampler = Resampler::new(from, to, 512).unwrap();
                let input = tone(from, hz, 0.5, from as usize / 2);
                let output = convert(&mut resampler, &input, 512);
                let measured = steady(&output, &resampler);

                let level = amplitude_at(measured, to, hz);
                assert!(
                    (level - 0.5).abs() < 0.01,
                    "{from} -> {to} at {hz} Hz came out at {level}",
                );
            }
        }
    }

    #[test]
    fn dc_passes_at_unity_gain() {
        // The kernel's coefficients have to sum to one at every fractional
        // phase, or the output gains a slow ripple that a tone test would miss.
        let mut resampler = Resampler::new(44_100, 48_000, 512).unwrap();
        let input = vec![0.25f32; 44_100];
        let output = convert(&mut resampler, &input, 512);

        for &sample in steady(&output, &resampler) {
            assert!((sample - 0.25).abs() < 0.001, "dc drifted to {sample}");
        }
    }

    #[test]
    fn silence_in_is_silence_out() {
        let mut resampler = Resampler::new(48_000, 44_100, 512).unwrap();
        let output = convert(&mut resampler, &vec![0.0f32; 48_000], 512);
        assert!(!output.is_empty());
        assert!(output.iter().all(|&s| s == 0.0));
    }

    #[test]
    fn output_length_tracks_the_rate_ratio() {
        for (from, to) in [
            (44_100, 48_000),
            (48_000, 44_100),
            (16_000, 48_000),
            (48_000, 16_000),
            (96_000, 48_000),
            (48_000, 192_000),
        ] {
            let mut resampler = Resampler::new(from, to, 512).unwrap();
            let input = vec![0.1f32; from as usize];
            let output = convert(&mut resampler, &input, 512);

            // One second in, one second out, less the kernel's priming delay.
            let expected = to as f64;
            let delay = resampler.latency_samples() / resampler.step;
            let short = expected - output.len() as f64;
            assert!(
                short >= 0.0 && short <= delay + 2.0,
                "{from} -> {to} produced {} samples, expected about {expected}",
                output.len(),
            );
        }
    }

    #[test]
    fn the_rates_do_not_drift_apart_over_a_long_run() {
        // The failure this guards against is a fractional position that is
        // rounded or reset per call: it looks perfect for one buffer and is
        // seconds out after an hour. Ten minutes of 20 ms frames at the
        // nastiest common ratio, which is long enough that a rounding error of
        // even a thousandth of a sample per frame would show.
        let mut resampler = Resampler::new(44_100, 48_000, 1_024).unwrap();
        let frame = vec![0.0f32; 882]; // 20 ms at 44.1 kHz
        let mut scratch = vec![0.0f32; resampler.max_output_for(882)];

        let frames = 30_000;
        let mut produced = 0usize;
        for _ in 0..frames {
            assert_eq!(resampler.feed(&frame), frame.len());
            loop {
                let made = resampler.pull(&mut scratch);
                if made == 0 {
                    break;
                }
                produced += made;
            }
        }

        let expected = frames * 960;
        let drift = expected as i64 - produced as i64;
        // The only shortfall allowed is the fixed priming delay, which does not
        // grow: a per-frame rounding error would be tens of thousands of
        // samples by now.
        assert!(
            (0..=64).contains(&drift),
            "drifted by {drift} samples over {frames} frames",
        );
    }

    #[test]
    fn content_above_the_output_nyquist_is_filtered_rather_than_folded() {
        // The whole reason for a band-limited kernel. Linear interpolation
        // would fold this 20 kHz tone down to 4 kHz, right into the middle of
        // speech, at nearly full level.
        let mut resampler = Resampler::new(48_000, 16_000, 512).unwrap();
        let input = tone(48_000, 20_000.0, 0.5, 48_000);
        let output = convert(&mut resampler, &input, 512);

        let measured = steady(&output, &resampler);
        assert!(
            rms(measured) < 0.001,
            "20 kHz leaked through at {} rms",
            rms(measured),
        );
        assert!(
            amplitude_at(measured, 16_000, 4_000.0) < 0.001,
            "20 kHz aliased down to 4 kHz",
        );
    }

    #[test]
    fn a_tone_below_the_new_nyquist_still_passes_while_one_above_does_not() {
        // Both halves of the same filter, so a resampler that simply output
        // silence could not pass this.
        let mut resampler = Resampler::new(48_000, 16_000, 512).unwrap();
        let mut input = tone(48_000, 2_000.0, 0.4, 48_000);
        for (slot, high) in input.iter_mut().zip(tone(48_000, 20_000.0, 0.4, 48_000)) {
            *slot += high;
        }
        let output = convert(&mut resampler, &input, 512);
        let measured = steady(&output, &resampler);

        assert!(
            (amplitude_at(measured, 16_000, 2_000.0) - 0.4).abs() < 0.01,
            "2 kHz came out at {}",
            amplitude_at(measured, 16_000, 2_000.0),
        );
        assert!(
            amplitude_at(measured, 16_000, 4_000.0) < 0.005,
            "the 20 kHz component aliased to 4 kHz",
        );
    }

    #[test]
    fn nothing_is_allocated_once_the_stream_is_running() {
        // The property the audio callbacks depend on. Capacity is the honest
        // proxy: a `Vec` that never grows never reallocates.
        let mut resampler = Resampler::new(44_100, 48_000, 512).unwrap();
        let capacity = resampler.buf.capacity();
        let pointer = resampler.buf.as_ptr();

        let mut scratch = vec![0.0f32; 1024];
        for _ in 0..2_000 {
            resampler.feed(&[0.3f32; 441]);
            while resampler.pull(&mut scratch) > 0 {}
        }

        assert_eq!(resampler.buf.capacity(), capacity);
        assert_eq!(resampler.buf.as_ptr(), pointer, "the buffer moved");
    }

    #[test]
    fn odd_sized_feeds_are_handled_without_losing_samples() {
        // Drivers deliver whatever they like; a resampler that only worked on
        // round numbers would drop audio on every callback.
        let mut resampler = Resampler::new(44_100, 48_000, 1_024).unwrap();
        let input = tone(44_100, 440.0, 0.5, 44_100);

        let mut output = Vec::new();
        let mut scratch = vec![0.0f32; 2_048];
        let mut offset = 0;
        let mut size = 1;
        while offset < input.len() {
            let end = (offset + size).min(input.len());
            let mut fed = offset;
            while fed < end {
                fed += resampler.feed(&input[fed..end]);
                loop {
                    let made = resampler.pull(&mut scratch);
                    if made == 0 {
                        break;
                    }
                    output.extend_from_slice(&scratch[..made]);
                }
            }
            offset = end;
            size = (size * 3 % 997) + 1;
        }

        let measured = steady(&output, &resampler);
        assert!(
            (amplitude_at(measured, 48_000, 440.0) - 0.5).abs() < 0.01,
            "amplitude was {}",
            amplitude_at(measured, 48_000, 440.0),
        );
    }

    #[test]
    fn a_short_pull_buffer_is_correct_just_slower() {
        // The playback callback can ask for very few samples at a time.
        let mut wide = Resampler::new(48_000, 44_100, 960).unwrap();
        let mut narrow = Resampler::new(48_000, 44_100, 960).unwrap();
        let input = tone(48_000, 700.0, 0.4, 9_600);

        let mut from_wide = Vec::new();
        let mut from_narrow = Vec::new();
        let mut big = vec![0.0f32; 2_048];
        let mut small = vec![0.0f32; 3];

        for block in input.chunks(960) {
            wide.feed(block);
            loop {
                let made = wide.pull(&mut big);
                if made == 0 {
                    break;
                }
                from_wide.extend_from_slice(&big[..made]);
            }

            narrow.feed(block);
            loop {
                let made = narrow.pull(&mut small);
                if made == 0 {
                    break;
                }
                from_narrow.extend_from_slice(&small[..made]);
            }
        }

        assert_eq!(from_wide, from_narrow);
    }

    #[test]
    fn a_reset_converter_behaves_like_a_fresh_one() {
        let mut reused = Resampler::new(44_100, 48_000, 512).unwrap();
        let input = tone(44_100, 900.0, 0.5, 8_820);
        let first = convert(&mut reused, &input, 512);
        reused.reset();
        let second = convert(&mut reused, &input, 512);
        assert_eq!(first, second);
    }

    #[test]
    fn nonsense_rates_are_refused_rather_than_dividing_by_zero() {
        assert!(Resampler::new(0, 48_000, 512).is_none());
        assert!(Resampler::new(48_000, 0, 512).is_none());
        assert!(Resampler::new(48_000, 44_100, 0).is_none());
    }

    #[test]
    fn the_output_is_never_a_nan_even_at_full_scale() {
        let mut resampler = Resampler::new(48_000, 44_100, 512).unwrap();
        let input: Vec<f32> = (0..48_000)
            .map(|i| if i % 2 == 0 { 1.0 } else { -1.0 })
            .collect();
        let output = convert(&mut resampler, &input, 512);
        assert!(output.iter().all(|s| s.is_finite()));
    }

    #[test]
    fn the_added_latency_stays_within_a_few_milliseconds() {
        // Live voice: this is a budget, not a curiosity. Both the worst
        // realistic capture case and the worst realistic playback case.
        for (from, to, budget_ms) in [
            (44_100u32, 48_000u32, 1.0),
            (48_000, 44_100, 1.0),
            (16_000, 48_000, 2.5),
            (48_000, 16_000, 2.5),
        ] {
            let resampler = Resampler::new(from, to, 512).unwrap();
            let ms = resampler.latency_samples() / from as f64 * 1_000.0;
            assert!(ms <= budget_ms, "{from} -> {to} added {ms} ms");
        }
    }
}
