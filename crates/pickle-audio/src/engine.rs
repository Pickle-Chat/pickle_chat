//! The live audio engine: microphone in, speakers out.
//!
//! cpal's `Stream` is not `Send`, so the streams are created on — and stay on —
//! a dedicated thread. Everything else talks to that thread through channels
//! and atomics, which keeps the audio callbacks lock-free on the paths that run
//! every 20 ms.
//!
//! The one exception is the playback callback, which briefly locks the mixer to
//! render a frame. That lock is uncontended in practice (only the network task
//! touches it, and only to push a decoded packet), but it is the first thing to
//! revisit if playback ever glitches under load.
//!
//! # Devices that are not 48 kHz
//!
//! The pipeline from the frame accumulator to the wire and back is 48 kHz mono
//! in 20 ms frames, always. When a device runs at some other rate, a
//! [`crate::resample::Resampler`] is inserted here and only here: capture
//! converts up or down to 48 kHz before the gate ever sees a sample, and
//! playback converts the mixer's 48 kHz frames down or up on the way out.
//! Everything in between is unaware.
//!
//! Both callbacks are hard real time, so every buffer either stage needs —
//! the downmix scratch, the converted scratch, and the converter's own history
//! — is sized and allocated in [`build_streams`]. Nothing on these paths
//! allocates, locks (beyond the mixer noted above), or blocks.
//!
//! The engine is deliberately ignorant of the network. It hands out encoded
//! frames and accepts decoded ones; wiring those to a connection is the
//! application's job. That keeps this crate testable without a server.

use crate::codec::{CodecError, VoiceEncoder};
use crate::devices::{self, DeviceError, DeviceKind};
use crate::mixer::VoiceMixer;
use crate::resample::Resampler;
use crate::vad::{Activity, GateMode, VoiceGate};
use bytes::Bytes;
use cpal::traits::{DeviceTrait, StreamTrait};
use parking_lot::Mutex;
use pickle_proto::voice::{VoiceDownstream, SAMPLES_PER_FRAME, SAMPLE_RATE};
use pickle_proto::ClientId;
use std::sync::atomic::{AtomicBool, AtomicU32, AtomicU8, Ordering};
use std::sync::mpsc;
use std::sync::Arc;
use std::thread::JoinHandle;
use tracing::{debug, warn};

#[derive(Debug, thiserror::Error)]
pub enum AudioError {
    #[error(transparent)]
    Device(#[from] DeviceError),
    #[error(transparent)]
    Codec(#[from] CodecError),
    #[error("could not open the audio stream: {0}")]
    BuildStream(String),
    #[error("could not start the audio stream: {0}")]
    PlayStream(String),
    #[error("the audio thread stopped unexpectedly")]
    ThreadLost,
}

#[derive(Debug, Clone)]
pub struct EngineConfig {
    /// Device name, or `None` for the system default.
    pub input_device: Option<String>,
    pub output_device: Option<String>,
    pub bitrate: u32,
    pub gate_mode: GateMode,
}

impl Default for EngineConfig {
    fn default() -> Self {
        Self {
            input_device: None,
            output_device: None,
            bitrate: crate::codec::DEFAULT_BITRATE,
            gate_mode: GateMode::VoiceActivity,
        }
    }
}

/// One encoded frame ready to put on the wire.
#[derive(Debug, Clone)]
pub struct CapturedFrame {
    pub seq: u32,
    pub flags: u8,
    pub payload: Bytes,
}

/// Shared with the capture callback. Atomics rather than a lock, because this
/// is read on every audio callback.
struct CaptureControls {
    muted: AtomicBool,
    push_to_talk_held: AtomicBool,
    gate_mode: AtomicU8,
    /// Last measured input level, as `f32` bits, for a UI meter.
    level_dbfs: AtomicU32,
    /// Whether the most recent frame was actually put on the wire.
    ///
    /// Distinct from the input level: a loud room with the gate shut, or a
    /// muted microphone, both move the meter without sending anything. This is
    /// what lets the UI say whether the user is being heard rather than merely
    /// whether the microphone hears them.
    transmitting: AtomicBool,
}

impl CaptureControls {
    fn gate_mode(&self) -> GateMode {
        match self.gate_mode.load(Ordering::Relaxed) {
            1 => GateMode::PushToTalk,
            2 => GateMode::Continuous,
            _ => GateMode::VoiceActivity,
        }
    }

    fn set_gate_mode(&self, mode: GateMode) {
        let encoded = match mode {
            GateMode::VoiceActivity => 0,
            GateMode::PushToTalk => 1,
            GateMode::Continuous => 2,
        };
        self.gate_mode.store(encoded, Ordering::Relaxed);
    }
}

/// A running audio engine. Dropping it stops the streams.
///
/// The frame receiver sits behind a `Mutex` so the whole engine is `Sync` and
/// can live in shared application state. `mpsc::Receiver` is `Send` but not
/// `Sync`, and without this the engine could not be held in an `Arc`.
pub struct AudioEngine {
    frames: Mutex<Option<mpsc::Receiver<CapturedFrame>>>,
    mixer: Arc<Mutex<VoiceMixer>>,
    controls: Arc<CaptureControls>,
    shutdown: Arc<AtomicBool>,
    thread: Option<JoinHandle<()>>,
}

impl AudioEngine {
    /// Open both devices and start streaming.
    ///
    /// Errors from the audio thread's setup are propagated here rather than
    /// being swallowed, so a missing microphone surfaces immediately.
    pub fn start(config: EngineConfig) -> Result<Self, AudioError> {
        let mixer = Arc::new(Mutex::new(VoiceMixer::new()));
        let controls = Arc::new(CaptureControls {
            muted: AtomicBool::new(false),
            push_to_talk_held: AtomicBool::new(false),
            gate_mode: AtomicU8::new(0),
            level_dbfs: AtomicU32::new(f32::NEG_INFINITY.to_bits()),
            transmitting: AtomicBool::new(false),
        });
        controls.set_gate_mode(config.gate_mode);

        let shutdown = Arc::new(AtomicBool::new(false));
        let (frame_tx, frame_rx) = mpsc::channel::<CapturedFrame>();
        let (ready_tx, ready_rx) = mpsc::channel::<Result<(), AudioError>>();

        let thread = std::thread::Builder::new()
            .name("pickle-audio".into())
            .spawn({
                let mixer = Arc::clone(&mixer);
                let controls = Arc::clone(&controls);
                let shutdown = Arc::clone(&shutdown);
                move || {
                    audio_thread(config, mixer, controls, shutdown, frame_tx, ready_tx);
                }
            })
            .map_err(|e| AudioError::BuildStream(e.to_string()))?;

        match ready_rx.recv() {
            Ok(Ok(())) => Ok(Self {
                frames: Mutex::new(Some(frame_rx)),
                mixer,
                controls,
                shutdown,
                thread: Some(thread),
            }),
            Ok(Err(e)) => {
                let _ = thread.join();
                Err(e)
            }
            Err(_) => Err(AudioError::ThreadLost),
        }
    }

    /// Take the next encoded frame, if one is ready. Non-blocking.
    pub fn next_frame(&self) -> Option<CapturedFrame> {
        self.frames.lock().as_ref()?.try_recv().ok()
    }

    /// Drain every frame currently queued.
    ///
    /// Preferable to calling [`AudioEngine::next_frame`] once per tick: if the
    /// caller ever falls behind, frames would otherwise accumulate unbounded.
    pub fn drain_frames(&self) -> Vec<CapturedFrame> {
        let guard = self.frames.lock();
        let Some(receiver) = guard.as_ref() else {
            return Vec::new();
        };
        std::iter::from_fn(|| receiver.try_recv().ok()).collect()
    }

    /// Take exclusive ownership of the frame stream.
    ///
    /// Lets a caller block on `recv` from a dedicated thread instead of
    /// polling, which is how the desktop app forwards audio: a frame reaches
    /// the network the moment it is encoded, with no polling interval added to
    /// the latency budget. Returns `None` if already taken.
    pub fn take_frames(&self) -> Option<mpsc::Receiver<CapturedFrame>> {
        self.frames.lock().take()
    }

    /// Hand an incoming voice packet to the mixer.
    pub fn accept(&self, packet: VoiceDownstream) {
        if let Err(e) = self.mixer.lock().accept(packet) {
            debug!(error = %e, "could not accept a voice packet");
        }
    }

    /// Stop transmitting. Enforced locally *and* by the server, so a bug here
    /// cannot leak audio.
    pub fn set_muted(&self, muted: bool) {
        self.controls.muted.store(muted, Ordering::Relaxed);
    }

    pub fn is_muted(&self) -> bool {
        self.controls.muted.load(Ordering::Relaxed)
    }

    pub fn set_deafened(&self, deafened: bool) {
        self.mixer.lock().set_deafened(deafened);
    }

    pub fn is_deafened(&self) -> bool {
        self.mixer.lock().is_deafened()
    }

    pub fn set_gate_mode(&self, mode: GateMode) {
        self.controls.set_gate_mode(mode);
    }

    /// Called on key down and key up in push-to-talk mode.
    pub fn set_push_to_talk_held(&self, held: bool) {
        self.controls
            .push_to_talk_held
            .store(held, Ordering::Relaxed);
    }

    /// Current microphone level in dBFS, for a level meter.
    pub fn input_level_dbfs(&self) -> f32 {
        f32::from_bits(self.controls.level_dbfs.load(Ordering::Relaxed))
    }

    /// Whether the most recent frame went on the wire.
    ///
    /// Answers "am I being heard", which the level meter cannot: the meter
    /// moves for a loud room with the gate shut, and for a muted microphone.
    pub fn is_transmitting(&self) -> bool {
        self.controls.transmitting.load(Ordering::Relaxed)
    }

    pub fn set_speaker_gain(&self, client: ClientId, gain: f32) {
        self.mixer.lock().set_gain(client, gain);
    }

    pub fn set_speaker_muted(&self, client: ClientId, muted: bool) {
        self.mixer.lock().set_muted(client, muted);
    }

    pub fn set_master_gain(&self, gain: f32) {
        self.mixer.lock().set_master_gain(gain);
    }

    /// Forget every speaker, for when voice moves to a different server whose
    /// speaker ids mean something else entirely.
    pub fn clear_speakers(&self) {
        self.mixer.lock().clear_speakers();
    }

    pub fn remove_speaker(&self, client: ClientId) {
        self.mixer.lock().remove(client);
    }

    /// Who is currently audible — drives the speaking indicator.
    pub fn speaking(&self) -> Vec<ClientId> {
        self.mixer.lock().speaking()
    }
}

impl Drop for AudioEngine {
    fn drop(&mut self) {
        self.shutdown.store(true, Ordering::Relaxed);
        if let Some(thread) = self.thread.take() {
            let _ = thread.join();
        }
    }
}

fn audio_thread(
    config: EngineConfig,
    mixer: Arc<Mutex<VoiceMixer>>,
    controls: Arc<CaptureControls>,
    shutdown: Arc<AtomicBool>,
    frames: mpsc::Sender<CapturedFrame>,
    ready: mpsc::Sender<Result<(), AudioError>>,
) {
    let streams = build_streams(&config, mixer, controls, frames);

    match streams {
        Err(e) => {
            let _ = ready.send(Err(e));
        }
        Ok((input, output)) => {
            let _ = ready.send(Ok(()));
            // The streams stop when they are dropped, so this thread simply
            // keeps them alive until asked to stop.
            while !shutdown.load(Ordering::Relaxed) {
                std::thread::sleep(std::time::Duration::from_millis(50));
            }
            drop(input);
            drop(output);
        }
    }
}

type Streams = (cpal::Stream, cpal::Stream);

fn build_streams(
    config: &EngineConfig,
    mixer: Arc<Mutex<VoiceMixer>>,
    controls: Arc<CaptureControls>,
    frames: mpsc::Sender<CapturedFrame>,
) -> Result<Streams, AudioError> {
    let input_device = devices::open(DeviceKind::Input, config.input_device.as_deref())?;
    let output_device = devices::open(DeviceKind::Output, config.output_device.as_deref())?;

    let input_config = devices::pick_config(&input_device, DeviceKind::Input)?;
    let output_config = devices::pick_config(&output_device, DeviceKind::Output)?;

    let input = build_input(
        &input_device,
        &input_config,
        config.bitrate,
        controls,
        frames,
    )?;
    let output = build_output(&output_device, &output_config, mixer)?;

    input
        .play()
        .map_err(|e| AudioError::PlayStream(e.to_string()))?;
    output
        .play()
        .map_err(|e| AudioError::PlayStream(e.to_string()))?;

    Ok((input, output))
}

/// Accumulates 48 kHz mono samples and emits encoded frames.
///
/// Everything reaching this point is already at 48 kHz: if the device is not,
/// [`CaptureStage`] has converted it first.
struct Capture {
    pending: Vec<f32>,
    /// Somewhere to assemble one frame without asking the allocator for it on
    /// every 20 ms of audio, which is what a `drain(..).collect()` would do.
    scratch: Vec<f32>,
    gate: VoiceGate,
    encoder: VoiceEncoder,
    controls: Arc<CaptureControls>,
    frames: mpsc::Sender<CapturedFrame>,
    /// True while a burst is in progress, so mute can close it cleanly.
    transmitting: bool,
}

impl Capture {
    /// `max_push` is the largest slice [`Capture::push`] will ever be handed.
    ///
    /// It fixes `pending`'s capacity for good. `push` leaves at most one
    /// incomplete frame behind, so a capacity of one frame plus `max_push` can
    /// never be exceeded — which is what turns "extending a `Vec` in an audio
    /// callback" from a latent allocation into a plain memcpy.
    fn new(
        bitrate: u32,
        max_push: usize,
        controls: Arc<CaptureControls>,
        frames: mpsc::Sender<CapturedFrame>,
    ) -> Result<Self, AudioError> {
        Ok(Self {
            pending: Vec::with_capacity(SAMPLES_PER_FRAME + max_push),
            scratch: vec![0.0; SAMPLES_PER_FRAME],
            gate: VoiceGate::default(),
            encoder: VoiceEncoder::new(bitrate)?,
            controls,
            frames,
            transmitting: false,
        })
    }

    /// Feed downmixed mono samples, emitting a frame each time 20 ms accrues.
    fn push(&mut self, samples: &[f32]) {
        debug_assert!(
            self.pending.len() + samples.len() <= self.pending.capacity(),
            "capture buffer sized wrongly; this would allocate in a callback",
        );
        self.pending.extend_from_slice(samples);

        while self.pending.len() >= SAMPLES_PER_FRAME {
            // Swapped out rather than borrowed, so the frame can be handed to
            // `process` while `self` stays mutable. Restored below; no
            // allocation happens either way.
            let mut frame = std::mem::take(&mut self.scratch);
            frame.copy_from_slice(&self.pending[..SAMPLES_PER_FRAME]);
            self.pending.drain(..SAMPLES_PER_FRAME);
            self.process(&frame);
            self.scratch = frame;
        }
    }

    fn process(&mut self, frame: &[f32]) {
        self.gate.mode = self.controls.gate_mode();
        let muted = self.controls.muted.load(Ordering::Relaxed);
        let held = self.controls.push_to_talk_held.load(Ordering::Relaxed);

        let activity = if muted {
            // Close the burst rather than cutting it off, so listeners release
            // their jitter buffers immediately.
            if self.transmitting {
                self.gate.close()
            } else {
                Activity::Silent
            }
        } else {
            self.gate.update(frame, held)
        };

        self.controls
            .level_dbfs
            .store(self.gate.level_dbfs().to_bits(), Ordering::Relaxed);
        // Published before the early return, so the flag drops on the first
        // silent frame rather than sticking at whatever the last sent frame
        // left it as.
        self.controls
            .transmitting
            .store(activity.should_transmit(), Ordering::Relaxed);

        if !activity.should_transmit() {
            self.transmitting = false;
            return;
        }

        if matches!(activity, Activity::BurstStart) {
            // Restart numbering so a receiver's buffer reset lines up.
            self.encoder.reset_seq();
        }
        self.transmitting = !matches!(activity, Activity::BurstEnd);

        match self.encoder.encode(frame) {
            Ok(payload) => {
                let captured = CapturedFrame {
                    seq: self.encoder.next_seq(),
                    flags: activity.flags(),
                    payload,
                };
                // A closed receiver means the app has gone away; nothing to do.
                let _ = self.frames.send(captured);
            }
            Err(e) => warn!(error = %e, "could not encode a captured frame"),
        }
    }
}

/// How many device samples the capture stage converts in one pass.
///
/// Only a working-set size: a callback larger than this is processed in several
/// passes, so nothing depends on the driver's buffer size, which cpal does not
/// promise in advance.
const CAPTURE_CHUNK: usize = 256;

/// The device side of capture: interleaved device-rate samples in, 48 kHz mono
/// out to [`Capture`].
///
/// Both stages it owns are optional work: a 48 kHz mono device goes straight
/// through with nothing but the downmix the codec needs anyway.
struct CaptureStage {
    capture: Capture,
    /// `None` when the device already runs at 48 kHz.
    resampler: Option<Resampler>,
    /// Downmixed device-rate samples, at most [`CAPTURE_CHUNK`] of them.
    mono: Vec<f32>,
    /// The same audio at 48 kHz.
    converted: Vec<f32>,
}

impl CaptureStage {
    fn new(
        device_rate: u32,
        bitrate: u32,
        controls: Arc<CaptureControls>,
        frames: mpsc::Sender<CapturedFrame>,
    ) -> Result<Self, AudioError> {
        let resampler = (device_rate != SAMPLE_RATE)
            .then(|| Resampler::new(device_rate, SAMPLE_RATE, CAPTURE_CHUNK))
            .flatten();

        let converted = match &resampler {
            Some(resampler) => vec![0.0; resampler.max_output_for(CAPTURE_CHUNK)],
            None => Vec::new(),
        };

        // The most `Capture::push` can ever be handed in one call: a whole
        // converted block, or a whole raw block when there is nothing to
        // convert. Slow device rates make the converted block the larger of the
        // two, by the ratio between the rates.
        let max_push = converted.len().max(CAPTURE_CHUNK);

        Ok(Self {
            capture: Capture::new(bitrate, max_push, controls, frames)?,
            resampler,
            mono: vec![0.0; CAPTURE_CHUNK],
            converted,
        })
    }

    /// Take one callback's worth of interleaved samples.
    ///
    /// `to_f32` converts a single device sample to the +/-1.0 range the codec
    /// expects; the downmix itself is the same arithmetic for every format.
    fn push<T: Copy>(&mut self, data: &[T], channels: usize, to_f32: fn(T) -> f32) {
        if channels == 0 {
            return;
        }

        for block in data.chunks(CAPTURE_CHUNK * channels) {
            let mut filled = 0;
            for frame in block.chunks(channels) {
                let sum: f32 = frame.iter().copied().map(to_f32).sum();
                self.mono[filled] = sum / frame.len() as f32;
                filled += 1;
            }

            let Some(resampler) = self.resampler.as_mut() else {
                self.capture.push(&self.mono[..filled]);
                continue;
            };

            // `mono` is never longer than the `max_feed` the converter was
            // built for, so one `feed` always takes the lot — but the loop
            // stands rather than the assumption, since a short accept would
            // otherwise silently drop audio.
            let mut fed = 0;
            while fed < filled {
                let taken = resampler.feed(&self.mono[fed..filled]);
                if taken == 0 {
                    break;
                }
                fed += taken;
                loop {
                    let made = resampler.pull(&mut self.converted);
                    if made == 0 {
                        break;
                    }
                    self.capture.push(&self.converted[..made]);
                }
            }
        }
    }
}

fn build_input(
    device: &cpal::Device,
    supported: &cpal::SupportedStreamConfig,
    bitrate: u32,
    controls: Arc<CaptureControls>,
    frames: mpsc::Sender<CapturedFrame>,
) -> Result<cpal::Stream, AudioError> {
    let channels = supported.channels() as usize;
    let device_rate = supported.sample_rate();
    let stream_config: cpal::StreamConfig = supported.config();

    let mut stage = CaptureStage::new(device_rate, bitrate, controls, frames)?;

    if device_rate != SAMPLE_RATE {
        debug!(
            device_rate,
            channels, "capturing through a rate conversion to 48 kHz"
        );
    }

    let on_error = |e| warn!(error = %e, "input stream error");

    let stream = match supported.sample_format() {
        cpal::SampleFormat::F32 => device.build_input_stream(
            stream_config,
            move |data: &[f32], _: &cpal::InputCallbackInfo| {
                // Already the range the codec wants.
                stage.push(data, channels, |sample| sample);
            },
            on_error,
            None,
        ),
        cpal::SampleFormat::I16 => device.build_input_stream(
            stream_config,
            move |data: &[i16], _: &cpal::InputCallbackInfo| {
                // Widened before summing so a loud multichannel frame cannot
                // overflow, and normalised to +/-1.0.
                stage.push(data, channels, |sample| sample as f32 / -(i16::MIN as f32));
            },
            on_error,
            None,
        ),
        other => {
            return Err(AudioError::BuildStream(format!(
                "unsupported input sample format {other:?}"
            )))
        }
    };

    stream.map_err(|e| AudioError::BuildStream(e.to_string()))
}

/// One mixer frame can never need more rounds than this to yield a sample.
///
/// Two would do — the converter needs its lookahead filled before the first
/// output, so at most one frame is swallowed at stream start. The margin is
/// there only so a mistake becomes silence rather than a locked-up callback.
const MAX_REFILL_ROUNDS: usize = 8;

/// Feeds the output callback, rendering a new mixer frame whenever it runs out.
///
/// When the device is not at 48 kHz the mixer's frames go through a converter
/// on the way, and `ready` holds device-rate samples rather than the frame
/// itself. Either way the callback just takes the next sample.
struct Playback {
    mixer: Arc<Mutex<VoiceMixer>>,
    /// One 48 kHz frame, straight from the mixer. Only used when converting.
    frame: Vec<f32>,
    /// `None` when the device already runs at 48 kHz.
    resampler: Option<Resampler>,
    /// Samples at the device's rate, waiting to be handed out.
    ready: Vec<f32>,
    filled: usize,
    position: usize,
}

impl Playback {
    fn new(device_rate: u32, mixer: Arc<Mutex<VoiceMixer>>) -> Self {
        let resampler = (device_rate != SAMPLE_RATE)
            .then(|| Resampler::new(SAMPLE_RATE, device_rate, SAMPLES_PER_FRAME))
            .flatten();

        // Without a converter this is the mixer's own render target, so it has
        // to be exactly one frame. With one, it holds a frame's worth of
        // device-rate samples instead.
        let ready = match &resampler {
            Some(resampler) => vec![0.0; resampler.max_output_for(SAMPLES_PER_FRAME)],
            None => vec![0.0; SAMPLES_PER_FRAME],
        };

        Self {
            mixer,
            frame: vec![0.0; SAMPLES_PER_FRAME],
            resampler,
            ready,
            // Start empty so the first callback renders immediately.
            filled: 0,
            position: 0,
        }
    }

    fn next_sample(&mut self) -> f32 {
        if self.position >= self.filled {
            self.refill();
            self.position = 0;
        }
        match self.ready.get(self.position) {
            Some(&sample) => {
                self.position += 1;
                sample
            }
            // Unreachable: `refill` always leaves something. Silence rather
            // than a panic, because this runs in an audio callback.
            None => 0.0,
        }
    }

    fn refill(&mut self) {
        let Some(resampler) = self.resampler.as_mut() else {
            self.mixer.lock().render(&mut self.ready);
            self.filled = self.ready.len();
            return;
        };

        for _ in 0..MAX_REFILL_ROUNDS {
            let made = resampler.pull(&mut self.ready);
            if made > 0 {
                self.filled = made;
                return;
            }

            self.mixer.lock().render(&mut self.frame);
            let mut fed = 0;
            while fed < self.frame.len() {
                let taken = resampler.feed(&self.frame[fed..]);
                if taken == 0 {
                    break;
                }
                fed += taken;
            }
        }

        // Nothing came out, which should not be reachable. Hand back silence:
        // a callback that returned no samples would repeat whatever the driver
        // last had in the buffer, which is far more audible than a gap.
        self.ready.fill(0.0);
        self.filled = self.ready.len();
    }
}

fn build_output(
    device: &cpal::Device,
    supported: &cpal::SupportedStreamConfig,
    mixer: Arc<Mutex<VoiceMixer>>,
) -> Result<cpal::Stream, AudioError> {
    let channels = supported.channels() as usize;
    let device_rate = supported.sample_rate();
    let stream_config: cpal::StreamConfig = supported.config();

    let mut playback = Playback::new(device_rate, mixer);

    if device_rate != SAMPLE_RATE {
        debug!(
            device_rate,
            channels, "playing back through a rate conversion from 48 kHz"
        );
    }

    let on_error = |e| warn!(error = %e, "output stream error");

    let stream = match supported.sample_format() {
        cpal::SampleFormat::F32 => device.build_output_stream(
            stream_config,
            move |data: &mut [f32], _: &cpal::OutputCallbackInfo| {
                // Mono is copied to every channel; the mix has no stereo image.
                for frame in data.chunks_mut(channels) {
                    let sample = playback.next_sample();
                    frame.iter_mut().for_each(|slot| *slot = sample);
                }
            },
            on_error,
            None,
        ),
        cpal::SampleFormat::I16 => device.build_output_stream(
            stream_config,
            move |data: &mut [i16], _: &cpal::OutputCallbackInfo| {
                for frame in data.chunks_mut(channels) {
                    let sample = (playback.next_sample().clamp(-1.0, 1.0) * i16::MAX as f32) as i16;
                    frame.iter_mut().for_each(|slot| *slot = sample);
                }
            },
            on_error,
            None,
        ),
        other => {
            return Err(AudioError::BuildStream(format!(
                "unsupported output sample format {other:?}"
            )))
        }
    };

    stream.map_err(|e| AudioError::BuildStream(e.to_string()))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::codec::DEFAULT_BITRATE;

    /// Drive `Capture` directly — no sound card involved, so this runs
    /// anywhere.
    fn test_capture(
        mode: GateMode,
    ) -> (Capture, mpsc::Receiver<CapturedFrame>, Arc<CaptureControls>) {
        let (tx, rx) = mpsc::channel();
        let controls = Arc::new(CaptureControls {
            muted: AtomicBool::new(false),
            push_to_talk_held: AtomicBool::new(false),
            gate_mode: AtomicU8::new(0),
            level_dbfs: AtomicU32::new(f32::NEG_INFINITY.to_bits()),
            transmitting: AtomicBool::new(false),
        });
        controls.set_gate_mode(mode);

        // Generous, because these tests hand over far more at once than any
        // driver would. The real sizing is `CaptureStage`'s job.
        let capture = Capture::new(
            DEFAULT_BITRATE,
            SAMPLES_PER_FRAME * 64,
            Arc::clone(&controls),
            tx,
        )
        .unwrap();
        (capture, rx, controls)
    }

    fn loud(samples: usize) -> Vec<f32> {
        (0..samples)
            .map(|i| if i % 2 == 0 { 0.25 } else { -0.25 })
            .collect()
    }

    #[test]
    fn capture_emits_one_frame_per_twenty_milliseconds_of_audio() {
        let (mut capture, frames, _controls) = test_capture(GateMode::Continuous);
        capture.push(&loud(SAMPLES_PER_FRAME * 3));
        assert_eq!(frames.try_iter().count(), 3);
    }

    #[test]
    fn capture_buffers_a_partial_frame_until_it_is_complete() {
        // Device buffer sizes rarely line up with 960 samples, so this is the
        // normal case rather than an edge case.
        let (mut capture, frames, _controls) = test_capture(GateMode::Continuous);

        capture.push(&loud(SAMPLES_PER_FRAME - 1));
        assert_eq!(frames.try_iter().count(), 0);

        capture.push(&loud(1));
        assert_eq!(frames.try_iter().count(), 1);
    }

    #[test]
    fn odd_sized_pushes_still_produce_whole_frames() {
        let (mut capture, frames, _controls) = test_capture(GateMode::Continuous);
        for _ in 0..10 {
            capture.push(&loud(333));
        }
        // 3330 samples is three whole frames plus a remainder.
        assert_eq!(frames.try_iter().count(), 3);
    }

    #[test]
    fn the_first_transmitted_frame_is_marked_as_a_burst_start() {
        let (mut capture, frames, _controls) = test_capture(GateMode::VoiceActivity);
        capture.push(&loud(SAMPLES_PER_FRAME * 2));

        let collected: Vec<_> = frames.try_iter().collect();
        assert!(collected[0].flags & pickle_proto::voice::FLAG_BURST_START != 0);
        assert_eq!(collected[1].flags, 0);
    }

    #[test]
    fn silence_is_not_transmitted() {
        // The point of the gate: an idle microphone costs no bandwidth.
        let (mut capture, frames, _controls) = test_capture(GateMode::VoiceActivity);
        capture.push(&vec![0.0f32; SAMPLES_PER_FRAME * 5]);
        assert_eq!(frames.try_iter().count(), 0);
    }

    #[test]
    fn muting_stops_transmission() {
        let (mut capture, frames, controls) = test_capture(GateMode::Continuous);
        capture.push(&loud(SAMPLES_PER_FRAME));
        assert_eq!(frames.try_iter().count(), 1);

        controls.muted.store(true, Ordering::Relaxed);
        capture.push(&loud(SAMPLES_PER_FRAME * 5));

        let after_mute: Vec<_> = frames.try_iter().collect();
        // At most one frame, closing the burst; never continued audio.
        assert!(
            after_mute.len() <= 1,
            "got {} frames while muted",
            after_mute.len()
        );
        if let Some(frame) = after_mute.first() {
            assert!(frame.flags & pickle_proto::voice::FLAG_BURST_END != 0);
        }
    }

    #[test]
    fn push_to_talk_gates_on_the_key_not_the_level() {
        let (mut capture, frames, controls) = test_capture(GateMode::PushToTalk);

        capture.push(&loud(SAMPLES_PER_FRAME * 2));
        assert_eq!(
            frames.try_iter().count(),
            0,
            "loud audio without the key held"
        );

        controls.push_to_talk_held.store(true, Ordering::Relaxed);
        capture.push(&loud(SAMPLES_PER_FRAME * 2));
        assert_eq!(frames.try_iter().count(), 2);
    }

    #[test]
    fn the_level_meter_is_updated_even_while_silent() {
        // The meter has to move while the gate is shut, or a user cannot tell
        // whether their microphone works.
        let (mut capture, _frames, controls) = test_capture(GateMode::VoiceActivity);
        capture.push(&loud(SAMPLES_PER_FRAME));

        let level = f32::from_bits(controls.level_dbfs.load(Ordering::Relaxed));
        assert!(level > -20.0 && level < 0.0, "got {level} dBFS");
    }

    #[test]
    fn the_transmit_flag_follows_the_gate_not_the_level() {
        // The distinction the indicator exists to draw: a loud room with the
        // gate shut is not the same as being heard.
        let (mut capture, _frames, controls) = test_capture(GateMode::PushToTalk);

        capture.push(&loud(SAMPLES_PER_FRAME));
        assert!(
            !controls.transmitting.load(Ordering::Relaxed),
            "loud but not keyed",
        );

        controls.push_to_talk_held.store(true, Ordering::Relaxed);
        capture.push(&loud(SAMPLES_PER_FRAME));
        assert!(controls.transmitting.load(Ordering::Relaxed), "keyed");

        // Releasing does not stop transmission immediately: the gate holds open
        // through its hangover so word endings are not clipped, and the
        // indicator should stay lit for exactly as long as audio is still going
        // out. So this pushes past the hangover before expecting it to drop.
        controls.push_to_talk_held.store(false, Ordering::Relaxed);
        let hangover_frames = crate::vad::DEFAULT_HANGOVER_MS.div_ceil(crate::FRAME_MS) as usize;
        capture.push(&loud(SAMPLES_PER_FRAME * (hangover_frames + 2)));
        assert!(
            !controls.transmitting.load(Ordering::Relaxed),
            "once the hangover expires it must drop rather than latch on",
        );
    }

    #[test]
    fn muting_clears_the_transmit_flag() {
        let (mut capture, _frames, controls) = test_capture(GateMode::Continuous);
        capture.push(&loud(SAMPLES_PER_FRAME));
        assert!(controls.transmitting.load(Ordering::Relaxed));

        controls.muted.store(true, Ordering::Relaxed);
        // Two frames: the first closes the burst and still goes out, the second
        // is silent. The indicator must be off by the end.
        capture.push(&loud(SAMPLES_PER_FRAME * 2));
        assert!(
            !controls.transmitting.load(Ordering::Relaxed),
            "a muted microphone must never read as transmitting",
        );
    }

    #[test]
    fn sequence_numbers_restart_on_each_burst() {
        let (mut capture, frames, _controls) = test_capture(GateMode::VoiceActivity);

        capture.push(&loud(SAMPLES_PER_FRAME * 2));
        // Long enough silence to close the gate through its hangover.
        capture.push(&vec![0.0f32; SAMPLES_PER_FRAME * 30]);
        capture.push(&loud(SAMPLES_PER_FRAME * 2));

        let collected: Vec<_> = frames.try_iter().collect();
        let starts: Vec<_> = collected
            .iter()
            .filter(|f| f.flags & pickle_proto::voice::FLAG_BURST_START != 0)
            .collect();
        assert_eq!(starts.len(), 2, "two separate bursts expected");
        assert!(
            starts.iter().all(|f| f.seq == 0),
            "each burst starts at zero"
        );
    }

    // The device boundary. `CaptureStage` and `Playback` are plain types, so
    // the rates no machine here can open are still exercised properly — which
    // is the entire point of putting the conversion in them rather than in the
    // cpal closures.

    fn test_stage(device_rate: u32) -> (CaptureStage, mpsc::Receiver<CapturedFrame>) {
        let (tx, rx) = mpsc::channel();
        let controls = Arc::new(CaptureControls {
            muted: AtomicBool::new(false),
            push_to_talk_held: AtomicBool::new(false),
            gate_mode: AtomicU8::new(0),
            level_dbfs: AtomicU32::new(f32::NEG_INFINITY.to_bits()),
            transmitting: AtomicBool::new(false),
        });
        controls.set_gate_mode(GateMode::Continuous);

        let stage = CaptureStage::new(device_rate, DEFAULT_BITRATE, controls, tx).unwrap();
        (stage, rx)
    }

    /// Interleave one mono signal across `channels` identical channels.
    fn interleave(mono: &[f32], channels: usize) -> Vec<f32> {
        mono.iter().flat_map(|&s| vec![s; channels]).collect()
    }

    #[test]
    fn a_native_rate_device_is_not_put_through_a_converter_at_all() {
        // The common case must stay exactly as cheap as it was.
        let (stage, _frames) = test_stage(SAMPLE_RATE);
        assert!(stage.resampler.is_none());
        assert!(
            Playback::new(SAMPLE_RATE, Arc::new(Mutex::new(VoiceMixer::new())))
                .resampler
                .is_none()
        );
    }

    #[test]
    fn a_forty_four_one_device_is_put_through_a_converter() {
        let (stage, _frames) = test_stage(44_100);
        assert!(stage.resampler.is_some());
        assert!(
            Playback::new(44_100, Arc::new(Mutex::new(VoiceMixer::new())))
                .resampler
                .is_some()
        );
    }

    #[test]
    fn a_second_of_audio_is_still_fifty_frames_whatever_the_device_rate() {
        // The property the whole pipeline downstream depends on: 20 ms of real
        // time is one frame, regardless of how many samples the device used to
        // express it.
        for rate in [8_000, 16_000, 44_100, 48_000, 96_000, 192_000] {
            let (mut stage, frames) = test_stage(rate);
            stage.push(&loud(rate as usize), 1, |s| s);

            let count = frames.try_iter().count();
            // One frame's slack for the converter's priming delay and for the
            // remainder that has not reached 20 ms yet.
            assert!(
                (48..=50).contains(&count),
                "{rate} Hz produced {count} frames for one second of audio",
            );
        }
    }

    #[test]
    fn a_stereo_device_is_downmixed_before_anything_downstream_sees_it() {
        // Opus is fed mono. A device that only offers stereo used to be a
        // separate problem from the rate; both are handled here.
        let (mut stage, frames) = test_stage(44_100);
        let mono = loud(44_100);
        stage.push(&interleave(&mono, 2), 2, |s| s);
        assert!(frames.try_iter().count() >= 48);
    }

    #[test]
    fn opposed_stereo_channels_cancel_rather_than_being_taken_from_one_side() {
        // A downmix that took the left channel, or summed without averaging,
        // would both pass a "some audio came out" test. This one says which.
        let (mut stage, _frames) = test_stage(44_100);
        let interleaved: Vec<f32> = (0..44_100)
            .flat_map(|i| {
                let sample = if i % 2 == 0 { 0.5 } else { -0.5 };
                [sample, -sample]
            })
            .collect();
        stage.push(&interleaved, 2, |s| s);

        let level = f32::from_bits(stage.capture.controls.level_dbfs.load(Ordering::Relaxed));
        assert!(level < -60.0, "opposed channels left {level} dBFS behind");
    }

    #[test]
    fn a_sixteen_bit_device_arrives_at_the_same_level_as_a_float_one() {
        // Two conversions meet here — integer to float and rate — and a factor
        // of two in either is silent until someone measures it.
        let mut levels = Vec::new();

        let (mut float_stage, _f) = test_stage(44_100);
        float_stage.push(&loud(44_100), 1, |s| s);
        levels.push(f32::from_bits(
            float_stage
                .capture
                .controls
                .level_dbfs
                .load(Ordering::Relaxed),
        ));

        let (mut int_stage, _i) = test_stage(44_100);
        let as_i16: Vec<i16> = loud(44_100)
            .iter()
            .map(|&s| (s * -(i16::MIN as f32)) as i16)
            .collect();
        int_stage.push(&as_i16, 1, |s| s as f32 / -(i16::MIN as f32));
        levels.push(f32::from_bits(
            int_stage
                .capture
                .controls
                .level_dbfs
                .load(Ordering::Relaxed),
        ));

        assert!(
            (levels[0] - levels[1]).abs() < 0.5,
            "float read {} dBFS, 16-bit read {} dBFS",
            levels[0],
            levels[1],
        );
    }

    #[test]
    fn a_callback_larger_than_the_working_chunk_is_not_truncated() {
        // cpal promises nothing about buffer size, and some drivers hand over
        // tens of milliseconds at a time.
        let (mut stage, frames) = test_stage(44_100);
        stage.push(&loud(44_100), 1, |s| s);
        let one_go = frames.try_iter().count();

        let (mut piecemeal, frames) = test_stage(44_100);
        for block in loud(44_100).chunks(CAPTURE_CHUNK / 3) {
            piecemeal.push(block, 1, |s| s);
        }
        assert_eq!(one_go, frames.try_iter().count());
    }

    #[test]
    fn the_capture_callback_never_reaches_for_the_allocator() {
        // The constraint the whole design is bent around. A `Vec` that never
        // grows never reallocates, so watching the capacity is the honest test.
        // The `debug_assert` in `Capture::push` guards the same property from
        // the inside; this one proves the sizing holds for every rate.
        for rate in [8_000, 16_000, 44_100, 48_000, 96_000, 192_000] {
            let (mut stage, frames) = test_stage(rate);
            let before = stage.capture.pending.capacity();

            // A few seconds of audio, in blocks that do not divide evenly into
            // anything, since that is what drivers actually do.
            for _ in 0..200 {
                stage.push(&loud(511), 1, |s| s);
                let _ = frames.try_iter().count();
            }

            assert_eq!(
                stage.capture.pending.capacity(),
                before,
                "the capture buffer grew at {rate} Hz",
            );
        }
    }

    #[test]
    fn playback_fills_every_sample_it_is_asked_for_at_any_device_rate() {
        // A callback left partly unwritten repeats whatever the driver had in
        // the buffer, which is a far nastier artefact than silence.
        for rate in [8_000, 16_000, 44_100, 48_000, 96_000, 192_000] {
            let mut playback = Playback::new(rate, Arc::new(Mutex::new(VoiceMixer::new())));
            let taken: Vec<f32> = (0..rate as usize / 10)
                .map(|_| playback.next_sample())
                .collect();

            assert!(
                taken.iter().all(|s| s.is_finite()),
                "{rate} Hz produced a NaN"
            );
            assert!(
                taken.iter().all(|&s| s == 0.0),
                "{rate} Hz invented audio from an empty mixer",
            );
        }
    }

    /// Play a 1 kHz tone through the whole output path — encode at 48 kHz, mix,
    /// convert — and report the amplitude a speaker at `rate` would receive.
    fn tone_through_playback(rate: u32) -> f64 {
        let hz = 1_000.0;
        let frames = 8;
        let mut encoder = VoiceEncoder::new(DEFAULT_BITRATE).unwrap();
        let mixer = Arc::new(Mutex::new(VoiceMixer::new()));

        for frame in 0..frames {
            let pcm: Vec<f32> = (0..SAMPLES_PER_FRAME)
                .map(|i| {
                    let t = (frame * SAMPLES_PER_FRAME + i) as f64 / SAMPLE_RATE as f64;
                    (0.5 * (2.0 * std::f64::consts::PI * hz * t).sin()) as f32
                })
                .collect();
            let payload = encoder.encode(&pcm).unwrap();
            mixer
                .lock()
                .accept(VoiceDownstream {
                    sender: 1,
                    seq: frame as u32,
                    flags: if frame == 0 {
                        pickle_proto::voice::FLAG_BURST_START
                    } else {
                        0
                    },
                    payload,
                })
                .unwrap();
        }

        // 100 ms, taken from the middle of what was queued so neither the
        // converter's priming nor the end of the tone is in the measurement.
        let skip = rate as usize / 50;
        let mut playback = Playback::new(rate, mixer);
        let taken: Vec<f32> = (0..skip + rate as usize / 10)
            .map(|_| playback.next_sample())
            .collect();
        let measured = &taken[skip..];

        let (mut re, mut im) = (0.0f64, 0.0f64);
        for (i, &sample) in measured.iter().enumerate() {
            let phase = 2.0 * std::f64::consts::PI * hz * i as f64 / rate as f64;
            re += sample as f64 * phase.cos();
            im += sample as f64 * phase.sin();
        }
        2.0 * (re * re + im * im).sqrt() / measured.len() as f64
    }

    #[test]
    fn a_converted_device_hears_what_a_native_one_hears() {
        // The claim the whole change rests on, measured end to end rather than
        // argued: what comes out of a 44.1 kHz speaker is what comes out of a
        // 48 kHz one. Comparing the two paths rather than asserting an absolute
        // level keeps this about the conversion instead of about how faithfully
        // Opus renders a sine at 32 kbps.
        let native = tone_through_playback(SAMPLE_RATE);
        assert!(native > 0.2, "the native path produced nothing to compare");

        for rate in [8_000, 16_000, 44_100, 96_000] {
            let converted = tone_through_playback(rate);
            let error = (converted - native).abs() / native;
            assert!(
                error < 0.05,
                "{rate} Hz gave {converted} against {native} natively",
            );
        }
    }

    #[test]
    fn playback_never_starves_even_when_the_mixer_has_nothing() {
        // `refill` loops until it has samples; if that loop could ever fall
        // through without producing any, the callback would spin.
        let mut playback = Playback::new(44_100, Arc::new(Mutex::new(VoiceMixer::new())));
        for _ in 0..100_000 {
            assert_eq!(playback.next_sample(), 0.0);
        }
    }

    #[test]
    fn the_engine_can_be_shared_across_threads() {
        // The desktop app holds this in `Arc` inside Tauri's managed state, so
        // losing `Sync` here would break the integration at a distance.
        fn assert_send_sync<T: Send + Sync>() {}
        assert_send_sync::<AudioEngine>();
    }

    #[test]
    fn a_missing_input_device_reports_a_clear_error() {
        let config = EngineConfig {
            input_device: Some("definitely not a real microphone".into()),
            ..EngineConfig::default()
        };
        match AudioEngine::start(config) {
            Err(AudioError::Device(DeviceError::NotFound { .. })) => {}
            // A machine with no audio at all fails earlier, which is also fine.
            Err(AudioError::Device(DeviceError::NoDevice(_))) => {}
            other => panic!(
                "expected a device error, got {other:?}",
                other = other.map(|_| "ok")
            ),
        }
    }
}
