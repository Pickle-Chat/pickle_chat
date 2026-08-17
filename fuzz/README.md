# Fuzzing

`cargo-fuzz` targets for the code that parses bytes from the network.

Everything here is deliberately outside the main workspace (`fuzz/Cargo.toml`
declares an empty `[workspace]` table), so `cargo test --workspace` and
`cargo clippy --workspace` never try to build it on the pinned stable
toolchain. libFuzzer needs nightly's `-Z sanitizer`.

## Targets

| Target | What it feeds | Why it matters |
| --- | --- | --- |
| `voice_decode` | one Opus packet into `VoiceDecoder::decode` | Runs on the cpal audio callback thread. A panic there kills playback for everyone in the channel, not just the sender. |
| `voice_decode_stream` | a sequence of packets and concealed gaps into one decoder | The decoder is stateful and predictive; bugs that need a particular history are invisible to the single-packet target. |
| `voice_datagram` | a raw datagram into `VoiceUpstream`/`VoiceDownstream::decode` | Hand-rolled headers with manual slicing, parsed on both the server and every client. Also asserts the parse is exact: decode then encode must reproduce the input byte for byte. |

## Running

```sh
rustup toolchain install nightly
cargo install cargo-fuzz --locked

# Indefinitely, from the repo root:
cargo +nightly fuzz run voice_decode fuzz/corpus/voice_decode fuzz/seeds/voice_decode

# The bounded run CI does:
cargo +nightly fuzz run voice_decode \
  fuzz/corpus/voice_decode fuzz/seeds/voice_decode -- -max_total_time=60
```

The first corpus path is where libFuzzer writes what it discovers (gitignored);
the second is the committed seed corpus, which it only reads.

Reproduce a crash from the file cargo-fuzz writes into `fuzz/artifacts/`:

```sh
cargo +nightly fuzz run voice_decode fuzz/artifacts/voice_decode/crash-<hash>
```

## Seeds

Random bytes are essentially never a valid Opus packet, so a cold fuzzer burns
its whole budget rediscovering the table-of-contents byte. `seeds/` holds real
encoder output — several bitrates crossed with tone, silence, loud and quiet
signals — plus datagrams built from it, which puts libFuzzer inside the valid
region immediately. That matters most for the short CI runs.

Regenerate them after a change to the wire format or the frame geometry:

```sh
cd fuzz && cargo test --test generate_seeds -- --ignored
```

## Without nightly

The target bodies live in `src/lib.rs` rather than in the `fuzz_targets/`
binaries, so they can be replayed over the seed corpus and cheap deterministic
mutations of it on stable:

```sh
cd fuzz && cargo test
```

That has no coverage feedback and finds nothing on its own. Its job is to catch
a target that asserts something untrue of valid input, or a seed corpus that
has drifted out of sync with the wire format — both of which would otherwise
surface as a baffling red fuzz job.
