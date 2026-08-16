# Architecture

Why the pieces are arranged the way they are. For what goes over the wire, see
[protocol.md](protocol.md).

## The shape of it

```
                 ┌─────────────────────────────────────┐
                 │          apps/desktop               │
                 │   React UI  ←IPC→  Tauri commands   │
                 └──────────────┬──────────────────────┘
                                │
            ┌───────────────────┴────────────────────┐
            │                                        │
    ┌───────▼────────┐                      ┌────────▼───────┐
    │ pickle-client  │                      │  pickle-audio  │
    │  connection    │                      │  capture/gate  │
    │  identity pin  │                      │  codec/jitter  │
    │  event stream  │                      │  mixer/devices │
    └───────┬────────┘                      └────────────────┘
            │
    ┌───────▼────────┐   QUIC    ┌────────────────┐
    │  pickle-proto  │◀─────────▶│ pickle-server  │
    │  messages      │           │  auth/channels │
    │  framing       │           │  voice relay   │
    └───────┬────────┘           └────────┬───────┘
            │                             │
            └────────┬────────────────────┘
                     │
            ┌────────▼─────────┐
            │ pickle-identity  │
            │  keys, PoW, fps  │
            └──────────────────┘
```

## The organising principle

**Nothing that matters depends on a window or a sound card.**

The protocol, the connection logic, the trust model, and the entire signal path
are ordinary Rust types with no I/O device behind them. Only `devices.rs` and
`engine.rs` in `pickle-audio` touch cpal, and only `apps/desktop` touches Tauri.

This is what makes the interesting parts testable. `pickle-client`'s end-to-end
tests stand up a real server on a loopback port and drive real clients through
it — verifying authentication, voice relay, channel isolation, and server-side
mute enforcement — with no audio hardware involved. The jitter buffer, the voice
gate, the mixer and the codec are all tested directly.

The desktop app is deliberately thin. It is glue: wiring three tested libraries
together and exposing them over IPC. If it grows logic worth testing, that logic
belongs in a crate underneath it.

## Threading

The awkward constraint is that cpal's `Stream` is not `Send`, so audio streams
must be created on, and stay on, one thread. Around that:

| Thread / task | Job |
| --- | --- |
| Audio thread | Owns both cpal streams for their lifetime. Parks until shutdown. |
| Capture callback | Downmixes to mono, accumulates 20 ms frames, gates, encodes. Reads its controls from atomics — no locks. |
| Playback callback | Pulls from the mixer, rendering a new frame when it runs out. |
| Capture pump | An OS thread blocking on the encoder's channel, putting each frame straight on the wire. |
| Event pump | An async task draining the client's events: voice to the mixer, everything else to the UI. |
| Server session | Per connection: a control reader, a control writer, and a datagram reader. |

Two details worth keeping:

**The capture pump blocks rather than polls.** Polling on a timer would add up to
a full poll interval of latency for nothing, and `send_datagram` does not block,
so there is nothing to await. A frame reaches the network the moment it is
encoded.

**Voice never crosses the IPC bridge.** Incoming frames go straight to the mixer
in Rust. At 50 packets a second per speaker, serialising them into JavaScript
would dominate the app's work for no benefit. Only state changes reach the UI.

The one lock on a hot path is the mixer, briefly, in the playback callback. It is
uncontended in practice — only the event pump touches it, and only to push a
decoded packet — but it is the first thing to revisit if playback ever glitches
under load.

## Server design

State lives behind a single `RwLock`. Fan-out and voice relay take only the read
lock and never block inside it: sends go to unbounded channels or to quinn's
datagram queue, both of which return immediately. One slow client therefore
cannot stall the relay for everyone else.

Each session runs three concurrent parts, and the first to finish tears down the
others. Voice is read on its own task so an audio burst cannot delay chat and a
long chat frame cannot delay audio.

The server is stateless across restarts apart from its data directory:
configuration, identity, and TLS certificate. Copying that directory moves a
server to another machine without users noticing, because trust is pinned to the
identity rather than the address or the certificate.

## Where the seams are

Some deliberate boundaries, and what they buy:

- **`pickle-audio` knows nothing about the network.** It hands out encoded
  frames and accepts decoded ones. Wiring those to a connection is the
  application's job, which is why the whole signal path can be tested without a
  server.
- **`pickle-client` knows nothing about audio.** It emits voice packets as
  events like any other. A headless bot or a recording tool needs no audio stack
  at all.
- **`DatagramSink` in the server is a trait**, not a bare `quinn::Connection`,
  so relay logic — including the mute and channel-isolation rules that matter
  for security — is tested without a network stack.
- **DTOs at the IPC boundary** rather than serialising protocol types directly,
  so the frontend does not depend on the wire format's stability.

## Known structural gaps

- **No persistence layer.** The server holds everything in memory. Message
  history, bans, and channel permissions all need a store; SQLite is the obvious
  choice, and `MessageId` is already allocated monotonically in anticipation.
- **No permission model.** Every authenticated user can do everything an
  authenticated user can do. Roles keyed to fingerprints are the natural fit,
  since fingerprints already outlive connections.
- **No resampling.** Devices must support 48 kHz natively. A resampler in the
  capture and playback paths would remove the restriction.
