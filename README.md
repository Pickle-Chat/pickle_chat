# Pickle

Self-hosted voice and text chat. TeamSpeak's model — you run the server, you own
the data, there is no cloud and nothing to sign up for — with the kind of text
chat people expect from Discord.

There are no accounts. A user *is* an Ed25519 keypair on their own machine, and
servers recognise returning users by public key. Nothing is registered anywhere.

**Status:** early. Voice works end to end; text chat sends and delivers but is
not yet persisted. See [What works today](#what-works-today).

## Quick start

Run a server:

```bash
cargo run -p pickle-server
```

It prints the address to share and its identity fingerprint, writing its
configuration and keys to a per-user data directory on first run. Share the
address; anyone outside your network will need UDP forwarded to that port.

Run the desktop client:

```bash
cd apps/desktop && bun install && bun run dev:tauri
```

## How it works

Everything rides on one QUIC connection per client, which means one firewall
hole and one congestion controller for both kinds of traffic:

- **Control** — a reliable, ordered stream carrying authentication, channel and
  user state, and text messages.
- **Voice** — QUIC datagrams, unreliable and unordered by design. A 20 ms audio
  frame that arrives late is useless, and retransmitting it would stall
  everything behind it. Loss is absorbed by a jitter buffer and Opus packet-loss
  concealment instead.

The server relays voice rather than mixing it. That costs a little bandwidth and
buys per-speaker volume, independent jitter buffering, and room for positional
audio later.

### Identity and trust

There is no certificate authority anywhere, and a self-hosted server usually has
only a bare IP address — which the public CA system cannot vouch for. So TLS
provides the encrypted channel, and authentication happens one layer up:

- The server signs a hash of its own TLS certificate with its Ed25519 identity
  key. A machine in the middle would have to present its own certificate and
  could not produce a valid signature over it.
- Clients pin that identity on first contact and check it every time after, the
  way SSH does. A changed identity is refused outright and never resolved
  automatically. This does not protect the very first connection to an unknown
  server, which is why the server prints its fingerprint for out-of-band
  comparison.
- Clients sign a server-supplied nonce *together with the server's certificate
  hash*, so a hostile server cannot relay a client's login to a third party.

Because identities are free to generate, an unqualified key deters nobody. As in
TeamSpeak, an identity carries a **security level**: a proof of work over the
public key. Each level doubles the expected search, so level 20 is seconds and
level 30 is tens of minutes. Servers can set a minimum. Mining does not change
the keypair, so raising your level never costs you the permissions a server
granted you.

## Layout

| Crate | What it does |
| --- | --- |
| [`pickle-identity`](crates/pickle-identity) | Ed25519 identities, proof-of-work security levels, on-disk keystore |
| [`pickle-proto`](crates/pickle-proto) | Wire protocol: control messages, framing, voice datagram encoding |
| [`pickle-audio`](crates/pickle-audio) | Opus encode/decode, jitter buffering, voice gating, mixing |
| [`pickle-server`](crates/pickle-server) | The server: QUIC, authentication, channels, voice relay |
| [`pickle-client`](crates/pickle-client) | Client core: connection, identity pinning, event stream |
| [`apps/desktop`](apps/desktop) | Tauri desktop client (Rust + React) |

The signal path and the protocol are deliberately free of any dependency on a
window or a sound card, so both are testable headless. `pickle-client`'s
[end-to-end tests](crates/pickle-client/tests/end_to_end.rs) stand up a real
server on a loopback port and drive real clients through it.

## What works today

Working:

- Server hosting, configuration, channels (including nesting), server passwords
- Identity generation, mining, keystore, fingerprints
- Authentication with proof-of-work enforcement and certificate binding
- Trust-on-first-use server pinning
- Voice: capture, gating, Opus, relay, jitter buffering, mixing, mute/deafen
- Text messages delivered live to a channel
- Desktop client covering all of the above

Not yet built:

- **Message persistence.** History requests return empty, and editing,
  deletion, and reactions are refused. This is the main gap between "text chat"
  and "text chat like Discord".
- **Rich text rendering.** Messages carry markdown; the client renders plain
  text.
- Attachments, permissions and roles, moderation (kick/ban), LAN discovery.

Known issues:

- **Opus FEC is disabled.** The pure-Rust codec produces badly corrupted audio
  with in-band forward error correction enabled — a steady tone decodes with its
  energy swinging between 0.02× and 3.4×. Every other configuration is correct.
  Loss is handled by the jitter buffer and concealment alone, which recovers
  less gracefully from bursts. See `USE_INBAND_FEC` in
  [`codec.rs`](crates/pickle-audio/src/codec.rs); switching to C libopus would
  also resolve it.
- The encoder overshoots its bitrate target by roughly a third.
- Audio devices must support 48 kHz natively; there is no resampling.
- The keystore is unencrypted. Treat it like an SSH private key — and back it
  up, because losing it means losing every permission every server granted you.

## Development

```bash
cargo test --workspace
cargo clippy --workspace --all-targets
```

## Licence

MIT. See [LICENSE](LICENSE).
