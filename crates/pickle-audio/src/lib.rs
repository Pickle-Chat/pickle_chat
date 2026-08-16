//! Audio for Pickle.
//!
//! The capture path is: microphone → [`vad`] gate → [`codec`] Opus encode →
//! one datagram per 20 ms frame.
//!
//! The playback path is: datagram → [`jitter`] buffer per speaker → Opus decode
//! → [`mixer`] → speakers.
//!
//! Everything runs at 48 kHz mono in 20 ms frames, so no resampling happens
//! anywhere between the microphone and the wire.
//!
//! The pure signal path is deliberately free of any dependency on the sound
//! card: [`codec`], [`jitter`], [`vad`], and [`mixer`] are ordinary types that
//! can be tested without audio hardware. Only [`devices`] and [`engine`] touch
//! cpal.

pub mod codec;
pub mod devices;
pub mod engine;
pub mod jitter;
pub mod mixer;
pub mod vad;

pub use codec::{CodecError, VoiceDecoder, VoiceEncoder, DEFAULT_BITRATE};
pub use devices::{DeviceInfo, DeviceKind};
pub use engine::{AudioEngine, AudioError, EngineConfig};
pub use jitter::{JitterBuffer, JitterOutput, JitterStats};
pub use mixer::VoiceMixer;
pub use vad::{Activity, GateMode, VoiceGate};

// Re-exported so callers do not need to reach into the protocol crate for the
// frame geometry the whole audio path assumes.
pub use pickle_proto::voice::{CHANNELS, FRAME_MS, SAMPLES_PER_FRAME, SAMPLE_RATE};
