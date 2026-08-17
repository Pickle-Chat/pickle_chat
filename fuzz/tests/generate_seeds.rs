//! Regenerates the committed seed corpora under `fuzz/seeds/`.
//!
//! Random bytes are essentially never a valid Opus packet, so a cold fuzzer
//! spends its whole budget rediscovering the table-of-contents byte before it
//! reaches any interesting decoder state. Seeding with real encoder output puts
//! libFuzzer inside the valid region on the first run, which matters a lot for
//! the short, bounded runs CI does.
//!
//! This is a test rather than a binary on purpose: `cargo fuzz` builds the
//! `[[bin]]` targets only, so an extra binary here would be compiled with the
//! sanitizer flags and slow every fuzz build down.
//!
//! Run it after changing the wire format or the frame geometry:
//!
//! ```text
//! cd fuzz && cargo test --test generate_seeds -- --ignored
//! ```

use std::fs;
use std::path::{Path, PathBuf};

use pickle_audio::codec::{VoiceEncoder, DEFAULT_BITRATE};
use pickle_proto::voice::{
    VoiceDownstream, VoiceUpstream, FLAG_BURST_END, FLAG_BURST_START, SAMPLES_PER_FRAME,
    SAMPLE_RATE,
};

fn seed_dir(target: &str) -> PathBuf {
    let dir = Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("seeds")
        .join(target);
    fs::create_dir_all(&dir).expect("seed directory is writable");
    dir
}

fn write_seed(target: &str, name: &str, bytes: &[u8]) {
    fs::write(seed_dir(target).join(name), bytes).expect("seed is writable");
}

fn tone(freq: f32, amplitude: f32) -> Vec<f32> {
    (0..SAMPLES_PER_FRAME)
        .map(|i| {
            let t = i as f32 / SAMPLE_RATE as f32;
            (t * freq * std::f32::consts::TAU).sin() * amplitude
        })
        .collect()
}

/// A few packets that between them cover the encoder settings the client
/// actually uses: the default bitrate, the low end of the range, silence, and a
/// loud signal.
fn representative_packets() -> Vec<(String, Vec<u8>)> {
    let mut packets = Vec::new();

    for (label, bitrate) in [
        ("default", DEFAULT_BITRATE),
        ("low", 8_000),
        ("high", 64_000),
    ] {
        let mut encoder = VoiceEncoder::new(bitrate).expect("encoder");
        for (signal_name, signal) in [
            ("tone", tone(440.0, 0.25)),
            ("loud", tone(180.0, 0.95)),
            ("quiet", tone(2000.0, 0.01)),
            ("silence", vec![0.0; SAMPLES_PER_FRAME]),
        ] {
            // Opus is predictive: the first frames of a stream are not
            // representative of steady-state output, so encode a few and keep
            // the last.
            let mut packet = Vec::new();
            for _ in 0..5 {
                packet = encoder.encode(&signal).expect("encode").to_vec();
            }
            packets.push((format!("{label}_{signal_name}"), packet));
        }
    }

    packets
}

#[test]
#[ignore = "regenerates committed files; run explicitly"]
fn generate_seeds() {
    let packets = representative_packets();

    // voice_decode: one raw Opus packet per file.
    for (name, packet) in &packets {
        write_seed("voice_decode", name, packet);
    }

    // voice_decode_stream: u16-LE length-prefixed packet sequences, including a
    // zero length, which the target reads as a concealed (lost) frame.
    let framed = |packets: &[&[u8]]| {
        let mut out = Vec::new();
        for packet in packets {
            out.extend_from_slice(&(packet.len() as u16).to_le_bytes());
            out.extend_from_slice(packet);
        }
        out
    };
    let steady: Vec<&[u8]> = packets.iter().take(4).map(|(_, p)| p.as_slice()).collect();
    write_seed("voice_decode_stream", "steady", &framed(&steady));
    write_seed(
        "voice_decode_stream",
        "gap",
        &framed(&[steady[0], steady[1], &[], steady[2], &[], &[], steady[3]]),
    );
    write_seed(
        "voice_decode_stream",
        "all_concealed",
        &framed(&[&[], &[], &[], &[]]),
    );

    // voice_datagram: complete datagrams as they appear on the wire.
    let payload = packets[0].1.clone();
    for (name, flags) in [
        ("plain", 0),
        ("burst_start", FLAG_BURST_START),
        ("burst_end", FLAG_BURST_END),
        ("burst_both", FLAG_BURST_START | FLAG_BURST_END),
    ] {
        let upstream = VoiceUpstream {
            seq: 0x0102_0304,
            flags,
            payload: payload.clone().into(),
        };
        write_seed(
            "voice_datagram",
            &format!("upstream_{name}"),
            &upstream.encode(),
        );

        let downstream = VoiceDownstream {
            sender: 42,
            seq: u32::MAX,
            flags,
            payload: payload.clone().into(),
        };
        write_seed(
            "voice_datagram",
            &format!("downstream_{name}"),
            &downstream.encode(),
        );
    }

    // Header-only datagrams: the boundary the manual slicing gets wrong first.
    write_seed(
        "voice_datagram",
        "upstream_empty_payload",
        &VoiceUpstream {
            seq: 0,
            flags: 0,
            payload: Default::default(),
        }
        .encode(),
    );
    write_seed(
        "voice_datagram",
        "downstream_empty_payload",
        &VoiceDownstream {
            sender: 0,
            seq: 0,
            flags: 0,
            payload: Default::default(),
        }
        .encode(),
    );
}
