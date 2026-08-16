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
//! The engine is deliberately ignorant of the network. It hands out encoded
//! frames and accepts decoded ones; wiring those to a connection is the
//! application's job. That keeps this crate testable without a server.

use crate::codec::{CodecError, VoiceEncoder};
use crate::devices::{self, DeviceError, DeviceKind};
use crate::mixer::VoiceMixer;
use crate::vad::{Activity, GateMode, VoiceGate};
use bytes::Bytes;
use cpal::traits::{DeviceTrait, StreamTrait};
use parking_lot::Mutex;
use pickle_proto::voice::{VoiceDownstream, SAMPLES_PER_FRAME};
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

/// Accumulates microphone samples and emits encoded frames.
struct Capture {
    pending: Vec<f32>,
    gate: VoiceGate,
    encoder: VoiceEncoder,
    controls: Arc<CaptureControls>,
    frames: mpsc::Sender<CapturedFrame>,
    /// True while a burst is in progress, so mute can close it cleanly.
    transmitting: bool,
}

impl Capture {
    /// Feed downmixed mono samples, emitting a frame each time 20 ms accrues.
    fn push(&mut self, samples: impl Iterator<Item = f32>) {
        self.pending.extend(samples);

        while self.pending.len() >= SAMPLES_PER_FRAME {
            let frame: Vec<f32> = self.pending.drain(..SAMPLES_PER_FRAME).collect();
            self.process(&frame);
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

fn build_input(
    device: &cpal::Device,
    supported: &cpal::SupportedStreamConfig,
    bitrate: u32,
    controls: Arc<CaptureControls>,
    frames: mpsc::Sender<CapturedFrame>,
) -> Result<cpal::Stream, AudioError> {
    let channels = supported.channels() as usize;
    let stream_config: cpal::StreamConfig = supported.config();

    let mut capture = Capture {
        pending: Vec::with_capacity(SAMPLES_PER_FRAME * 4),
        gate: VoiceGate::default(),
        encoder: VoiceEncoder::new(bitrate)?,
        controls,
        frames,
        transmitting: false,
    };

    let on_error = |e| warn!(error = %e, "input stream error");

    let stream = match supported.sample_format() {
        cpal::SampleFormat::F32 => device.build_input_stream(
            stream_config,
            move |data: &[f32], _: &cpal::InputCallbackInfo| {
                // Already the format the codec wants; just downmix to mono.
                capture.push(
                    data.chunks(channels)
                        .map(|frame| frame.iter().sum::<f32>() / frame.len() as f32),
                );
            },
            on_error,
            None,
        ),
        cpal::SampleFormat::I16 => device.build_input_stream(
            stream_config,
            move |data: &[i16], _: &cpal::InputCallbackInfo| {
                capture.push(data.chunks(channels).map(|frame| {
                    // Sum in f32 so a loud stereo frame cannot overflow, then
                    // normalise to the +/-1.0 range the codec expects.
                    let sum: f32 = frame.iter().map(|&s| s as f32).sum();
                    (sum / frame.len() as f32) / -(i16::MIN as f32)
                }));
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

/// Feeds the output callback, rendering a new frame whenever it runs out.
struct Playback {
    mixer: Arc<Mutex<VoiceMixer>>,
    frame: Vec<f32>,
    position: usize,
}

impl Playback {
    fn next_sample(&mut self) -> f32 {
        if self.position >= self.frame.len() {
            self.mixer.lock().render(&mut self.frame);
            self.position = 0;
        }
        let sample = self.frame[self.position];
        self.position += 1;
        sample
    }
}

fn build_output(
    device: &cpal::Device,
    supported: &cpal::SupportedStreamConfig,
    mixer: Arc<Mutex<VoiceMixer>>,
) -> Result<cpal::Stream, AudioError> {
    let channels = supported.channels() as usize;
    let stream_config: cpal::StreamConfig = supported.config();

    let mut playback = Playback {
        mixer,
        // Start exhausted so the first callback renders immediately.
        frame: vec![0.0; SAMPLES_PER_FRAME],
        position: SAMPLES_PER_FRAME,
    };

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

        let capture = Capture {
            pending: Vec::new(),
            gate: VoiceGate::default(),
            encoder: VoiceEncoder::new(DEFAULT_BITRATE).unwrap(),
            controls: Arc::clone(&controls),
            frames: tx,
            transmitting: false,
        };
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
        capture.push(loud(SAMPLES_PER_FRAME * 3).into_iter());
        assert_eq!(frames.try_iter().count(), 3);
    }

    #[test]
    fn capture_buffers_a_partial_frame_until_it_is_complete() {
        // Device buffer sizes rarely line up with 960 samples, so this is the
        // normal case rather than an edge case.
        let (mut capture, frames, _controls) = test_capture(GateMode::Continuous);

        capture.push(loud(SAMPLES_PER_FRAME - 1).into_iter());
        assert_eq!(frames.try_iter().count(), 0);

        capture.push(loud(1).into_iter());
        assert_eq!(frames.try_iter().count(), 1);
    }

    #[test]
    fn odd_sized_pushes_still_produce_whole_frames() {
        let (mut capture, frames, _controls) = test_capture(GateMode::Continuous);
        for _ in 0..10 {
            capture.push(loud(333).into_iter());
        }
        // 3330 samples is three whole frames plus a remainder.
        assert_eq!(frames.try_iter().count(), 3);
    }

    #[test]
    fn the_first_transmitted_frame_is_marked_as_a_burst_start() {
        let (mut capture, frames, _controls) = test_capture(GateMode::VoiceActivity);
        capture.push(loud(SAMPLES_PER_FRAME * 2).into_iter());

        let collected: Vec<_> = frames.try_iter().collect();
        assert!(collected[0].flags & pickle_proto::voice::FLAG_BURST_START != 0);
        assert_eq!(collected[1].flags, 0);
    }

    #[test]
    fn silence_is_not_transmitted() {
        // The point of the gate: an idle microphone costs no bandwidth.
        let (mut capture, frames, _controls) = test_capture(GateMode::VoiceActivity);
        capture.push(vec![0.0f32; SAMPLES_PER_FRAME * 5].into_iter());
        assert_eq!(frames.try_iter().count(), 0);
    }

    #[test]
    fn muting_stops_transmission() {
        let (mut capture, frames, controls) = test_capture(GateMode::Continuous);
        capture.push(loud(SAMPLES_PER_FRAME).into_iter());
        assert_eq!(frames.try_iter().count(), 1);

        controls.muted.store(true, Ordering::Relaxed);
        capture.push(loud(SAMPLES_PER_FRAME * 5).into_iter());

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

        capture.push(loud(SAMPLES_PER_FRAME * 2).into_iter());
        assert_eq!(
            frames.try_iter().count(),
            0,
            "loud audio without the key held"
        );

        controls.push_to_talk_held.store(true, Ordering::Relaxed);
        capture.push(loud(SAMPLES_PER_FRAME * 2).into_iter());
        assert_eq!(frames.try_iter().count(), 2);
    }

    #[test]
    fn the_level_meter_is_updated_even_while_silent() {
        // The meter has to move while the gate is shut, or a user cannot tell
        // whether their microphone works.
        let (mut capture, _frames, controls) = test_capture(GateMode::VoiceActivity);
        capture.push(loud(SAMPLES_PER_FRAME).into_iter());

        let level = f32::from_bits(controls.level_dbfs.load(Ordering::Relaxed));
        assert!(level > -20.0 && level < 0.0, "got {level} dBFS");
    }

    #[test]
    fn the_transmit_flag_follows_the_gate_not_the_level() {
        // The distinction the indicator exists to draw: a loud room with the
        // gate shut is not the same as being heard.
        let (mut capture, _frames, controls) = test_capture(GateMode::PushToTalk);

        capture.push(loud(SAMPLES_PER_FRAME).into_iter());
        assert!(
            !controls.transmitting.load(Ordering::Relaxed),
            "loud but not keyed",
        );

        controls.push_to_talk_held.store(true, Ordering::Relaxed);
        capture.push(loud(SAMPLES_PER_FRAME).into_iter());
        assert!(controls.transmitting.load(Ordering::Relaxed), "keyed");

        // Releasing does not stop transmission immediately: the gate holds open
        // through its hangover so word endings are not clipped, and the
        // indicator should stay lit for exactly as long as audio is still going
        // out. So this pushes past the hangover before expecting it to drop.
        controls.push_to_talk_held.store(false, Ordering::Relaxed);
        let hangover_frames = crate::vad::DEFAULT_HANGOVER_MS.div_ceil(crate::FRAME_MS) as usize;
        capture.push(loud(SAMPLES_PER_FRAME * (hangover_frames + 2)).into_iter());
        assert!(
            !controls.transmitting.load(Ordering::Relaxed),
            "once the hangover expires it must drop rather than latch on",
        );
    }

    #[test]
    fn muting_clears_the_transmit_flag() {
        let (mut capture, _frames, controls) = test_capture(GateMode::Continuous);
        capture.push(loud(SAMPLES_PER_FRAME).into_iter());
        assert!(controls.transmitting.load(Ordering::Relaxed));

        controls.muted.store(true, Ordering::Relaxed);
        // Two frames: the first closes the burst and still goes out, the second
        // is silent. The indicator must be off by the end.
        capture.push(loud(SAMPLES_PER_FRAME * 2).into_iter());
        assert!(
            !controls.transmitting.load(Ordering::Relaxed),
            "a muted microphone must never read as transmitting",
        );
    }

    #[test]
    fn sequence_numbers_restart_on_each_burst() {
        let (mut capture, frames, _controls) = test_capture(GateMode::VoiceActivity);

        capture.push(loud(SAMPLES_PER_FRAME * 2).into_iter());
        // Long enough silence to close the gate through its hangover.
        capture.push(vec![0.0f32; SAMPLES_PER_FRAME * 30].into_iter());
        capture.push(loud(SAMPLES_PER_FRAME * 2).into_iter());

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
