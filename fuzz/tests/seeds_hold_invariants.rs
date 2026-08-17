//! Replays the seed corpus, plus cheap deterministic mutations of it, through
//! the fuzz target bodies on the ordinary stable toolchain.
//!
//! This is not a substitute for fuzzing — there is no coverage feedback here —
//! but it is the only part of the fuzzing setup that can run without nightly
//! and a sanitizer runtime, and it catches the two things most likely to break
//! it: a target that asserts something untrue of valid input, and a seed
//! corpus that has drifted out of sync with the wire format.

use std::fs;
use std::path::{Path, PathBuf};

fn seeds(target: &str) -> Vec<(PathBuf, Vec<u8>)> {
    let dir = Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("seeds")
        .join(target);
    let mut out: Vec<_> = fs::read_dir(&dir)
        .unwrap_or_else(|e| panic!("seed corpus {} is missing: {e}", dir.display()))
        .map(|entry| {
            let path = entry.expect("readable seed directory").path();
            let bytes = fs::read(&path).expect("readable seed");
            (path, bytes)
        })
        .collect();
    out.sort();
    assert!(!out.is_empty(), "seed corpus {} is empty", dir.display());
    out
}

/// A deterministic mutation set: truncations at every prefix length, plus a
/// single flipped bit at a sample of positions. Enough to cover the length and
/// header-boundary handling that hand-rolled parsers get wrong.
fn mutations(seed: &[u8]) -> Vec<Vec<u8>> {
    let mut out = Vec::new();
    for len in 0..=seed.len() {
        out.push(seed[..len].to_vec());
    }
    for (i, byte) in seed.iter().enumerate() {
        for bit in 0..8 {
            let mut mutated = seed.to_vec();
            mutated[i] = byte ^ (1 << bit);
            out.push(mutated);
        }
    }
    out
}

/// Deterministic pseudo-random buffers, so a failure reproduces exactly.
fn noise(count: usize, max_len: usize) -> Vec<Vec<u8>> {
    let mut state = 0x2545_F491_4F6C_DD1Du64;
    let mut next = move || {
        state ^= state << 13;
        state ^= state >> 7;
        state ^= state << 17;
        state
    };
    (0..count)
        .map(|_| {
            let len = (next() as usize) % (max_len + 1);
            (0..len).map(|_| next() as u8).collect()
        })
        .collect()
}

fn exercise(target: &str, body: fn(&[u8])) {
    for (path, seed) in seeds(target) {
        body(&seed);
        for mutated in mutations(&seed) {
            body(&mutated);
        }
        // Naming the file makes a failure actionable without re-running.
        eprintln!("ok: {}", path.display());
    }
    for buf in noise(512, 2048) {
        body(&buf);
    }
}

#[test]
fn voice_decode_holds() {
    exercise("voice_decode", pickle_fuzz::voice_decode);
}

#[test]
fn voice_decode_stream_holds() {
    exercise("voice_decode_stream", pickle_fuzz::voice_decode_stream);
}

#[test]
fn voice_datagram_holds() {
    exercise("voice_datagram", pickle_fuzz::voice_datagram);
}
