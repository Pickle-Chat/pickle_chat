//! Fuzz a *sequence* of packets through one `VoiceDecoder`.
//!
//! `VoiceDecoder` is stateful: Opus carries prediction across frames, and the
//! concealment path extrapolates from whatever was decoded last. Real playback
//! drives one decoder per speaker for the length of a call, mixing valid
//! frames, corrupt frames and concealed gaps, so a bug that needs a particular
//! history to surface is invisible to the single-packet target.

#![no_main]

use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    pickle_fuzz::voice_decode_stream(data);
});
