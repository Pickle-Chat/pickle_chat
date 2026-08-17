//! The bodies of the fuzz targets, factored out of the `fuzz_targets/`
//! binaries.
//!
//! Those binaries are `#![no_main]` and only build under nightly with a
//! sanitizer runtime, so nothing about them can be exercised on the pinned
//! stable toolchain. Keeping the actual logic here means the invariants can be
//! replayed over the committed seed corpus with an ordinary `cargo test` (see
//! `tests/seeds_hold_invariants.rs`), which catches a target that asserts
//! something untrue of *valid* input — a failure mode that would otherwise only
//! show up as a mystifying red CI run.

use bytes::Bytes;
use pickle_audio::codec::VoiceDecoder;
use pickle_proto::voice::{VoiceDownstream, VoiceUpstream, MAX_OPUS_PACKET, SAMPLES_PER_FRAME};

/// Bounds the packets decoded per input so libFuzzer keeps its throughput up.
const MAX_PACKETS_PER_INPUT: usize = 64;

/// Arbitrary; the relay stamps in the authenticated sender, never the client.
const RELAY_SENDER: u32 = 0xDEAD_BEEF;

/// What the playback path assumes about every frame it is handed.
///
/// A frame longer than the fixed geometry would mean the decoder wrote past
/// what the mixer will read; a non-finite sample propagates silently through
/// the mixer and out to the sound card.
fn check_frame(pcm: &[f32]) {
    assert!(
        pcm.len() <= SAMPLES_PER_FRAME,
        "decoded {} samples, more than one {SAMPLES_PER_FRAME} sample frame",
        pcm.len()
    );
    assert!(
        pcm.iter().all(|s| s.is_finite()),
        "decoder produced a non-finite sample"
    );
}

/// Decode a single attacker-supplied Opus packet.
pub fn voice_decode(data: &[u8]) {
    // The transport rejects anything larger before it ever reaches the codec
    // (`VoiceUpstream::decode` returns `PayloadTooLarge`), so spending fuzz
    // budget beyond this bound would be testing an unreachable input.
    if data.len() > MAX_OPUS_PACKET {
        return;
    }

    // A fresh decoder per input keeps a crash reproducible from the single file
    // libFuzzer writes out. Cross-frame decoder state is covered by
    // [`voice_decode_stream`] instead.
    let mut decoder = VoiceDecoder::new().expect("decoder construction is input-independent");

    if let Ok(pcm) = decoder.decode(data) {
        check_frame(pcm);
    }
}

/// Decode a whole sequence of packets through one decoder.
///
/// The input is read as `u16`-LE length-prefixed packets; a zero length is
/// taken as a lost frame and routed through concealment, which is exactly what
/// the jitter buffer does on a gap.
pub fn voice_decode_stream(data: &[u8]) {
    let mut decoder = VoiceDecoder::new().expect("decoder construction is input-independent");
    let mut rest = data;

    for _ in 0..MAX_PACKETS_PER_INPUT {
        let Some((len_bytes, tail)) = rest.split_at_checked(2) else {
            break;
        };
        let len = u16::from_le_bytes([len_bytes[0], len_bytes[1]]) as usize;
        // Modulo rather than a reject keeps most mutations meaningful instead
        // of truncating the stream at the first oversized length.
        let len = (len % (MAX_OPUS_PACKET + 1)).min(tail.len());
        let (packet, tail) = tail.split_at(len);
        rest = tail;

        // An empty packet is the codec's own signal for a lost frame, so route
        // it through the concealment API the playback path actually calls.
        let decoded = if packet.is_empty() {
            decoder.conceal()
        } else {
            decoder.decode(packet)
        };

        if let Ok(pcm) = decoded {
            check_frame(pcm);
        }

        if rest.is_empty() {
            break;
        }
    }
}

/// Parse a raw datagram as both datagram kinds.
///
/// Beyond "does not panic", this asserts the parsers are exact: a datagram that
/// decodes must re-encode to the identical bytes. That rules out a header field
/// being silently dropped or a payload boundary being misplaced.
pub fn voice_datagram(data: &[u8]) {
    let datagram = Bytes::copy_from_slice(data);

    if let Ok(upstream) = VoiceUpstream::decode(datagram.clone()) {
        assert!(
            upstream.payload.len() <= MAX_OPUS_PACKET,
            "accepted a payload larger than a single Opus packet"
        );
        assert_eq!(
            upstream.encode(),
            datagram,
            "re-encoding an accepted upstream datagram must reproduce it byte for byte"
        );

        // The relay path: the server turns an accepted upstream frame into a
        // downstream one, which every client then parses.
        let downstream = upstream.into_downstream(RELAY_SENDER);
        let relayed = downstream.encode();
        assert_eq!(
            VoiceDownstream::decode(relayed).expect("a relayed frame must parse"),
            downstream,
            "relaying must round-trip"
        );
    }

    if let Ok(downstream) = VoiceDownstream::decode(datagram.clone()) {
        assert!(
            downstream.payload.len() <= MAX_OPUS_PACKET,
            "accepted a payload larger than a single Opus packet"
        );
        assert_eq!(
            downstream.encode(),
            datagram,
            "re-encoding an accepted downstream datagram must reproduce it byte for byte"
        );
        // Flag accessors are pure reads, but they run on every received frame.
        let _ = (downstream.starts_burst(), downstream.ends_burst());
    }
}
