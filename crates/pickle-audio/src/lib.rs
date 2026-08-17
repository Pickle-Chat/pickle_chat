//! Audio for Pickle.
//!
//! The capture path is: microphone → [`vad`] gate → [`codec`] Opus encode →
//! one datagram per 20 ms frame.
//!
//! The playback path is: datagram → [`jitter`] buffer per speaker → Opus decode
//! → [`mixer`] → speakers.
//!
//! Everything between those two points runs at 48 kHz mono in 20 ms frames.
//! A device that cannot run at 48 kHz is converted by [`resample`] at the
//! device boundary and nowhere else, so the codec, the jitter buffer and the
//! mixer always see exactly the frame geometry they assume.
//!
//! The pure signal path is deliberately free of any dependency on the sound
//! card: [`codec`], [`jitter`], [`vad`], [`mixer`] and [`resample`] are ordinary
//! types that can be tested without audio hardware. Only [`devices`] and
//! [`engine`] touch cpal.

pub mod codec;
pub mod devices;
pub mod engine;
pub mod jitter;
pub mod mixer;
pub mod resample;
pub mod vad;

pub use codec::{CodecError, VoiceDecoder, VoiceEncoder, DEFAULT_BITRATE};
pub use devices::{DeviceInfo, DeviceKind};
pub use engine::{AudioEngine, AudioError, EngineConfig};
pub use jitter::{JitterBuffer, JitterOutput, JitterStats};
pub use mixer::VoiceMixer;
pub use resample::Resampler;
pub use vad::{Activity, GateMode, VoiceGate};

// Re-exported so callers do not need to reach into the protocol crate for the
// frame geometry the whole audio path assumes.
pub use pickle_proto::voice::{CHANNELS, FRAME_MS, SAMPLES_PER_FRAME, SAMPLE_RATE};
