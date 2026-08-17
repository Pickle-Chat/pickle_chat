//! Fuzz the voice datagram parsers.
//!
//! `VoiceUpstream::decode` runs on the server against bytes from any client
//! that completed a handshake; `VoiceDownstream::decode` runs on every client
//! against whatever the server relays. Both parse hand-rolled headers with
//! manual slicing, so an off-by-one is a panic in the hot path rather than a
//! type error.

#![no_main]

use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    pickle_fuzz::voice_datagram(data);
});
