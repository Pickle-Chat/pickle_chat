//! Fuzz one Opus packet through `VoiceDecoder::decode`.
//!
//! This is the highest-value target in the tree. The bytes reaching this
//! function come straight off a QUIC datagram sent by a remote peer, and the
//! decode runs on the cpal audio callback thread: a panic there does not just
//! drop one frame, it takes playback down for every speaker in the channel.
//!
//! The decoder must therefore treat *any* byte string as a well-formed error,
//! never a panic, and must never hand the mixer a sample it cannot play.

#![no_main]

use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    pickle_fuzz::voice_decode(data);
});
