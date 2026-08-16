# The Pickle wire protocol

Version 1. ALPN identifier `pickle/1`.

This describes what goes over the wire and, where it matters, why. The
authoritative definitions live in [`pickle-proto`](../crates/pickle-proto).

## Transport

One QUIC connection per client carries everything:

| Traffic | Carrier | Why |
| --- | --- | --- |
| Control | A bidirectional stream | Authentication, channel and user state, text chat. Needs reliability and ordering. |
| Voice | QUIC datagrams | Unreliable and unordered. A late audio frame is worthless; retransmitting it would add latency and head-of-line blocking for everything behind it. |

Sharing one connection means one hole in the host's firewall and one congestion
controller across both kinds of traffic.

Transport settings on both ends: 30 s idle timeout, 10 s keep-alive (which also
holds NAT bindings open while a user sits silent), and datagram buffers sized for
256 frames.

## Handshake

**The server opens the control stream and speaks first.** This ordering is not
arbitrary: QUIC only surfaces a peer-opened stream once data arrives on it, so a
client that opened the stream and then waited for a greeting would deadlock
against a server waiting for the stream.

```
Server ──── ServerHello ────▶ Client
Client ──── ClientAuth  ────▶ Server
Server ──── AuthOk / AuthFailed ────▶ Client
```

### ServerHello

| Field | Purpose |
| --- | --- |
| `protocol_version` | Checked for exact equality pre-1.0; a mismatch is refused, not negotiated. |
| `server_name` | Display name, shown before authentication. |
| `server_identity` | The server's Ed25519 public key and its proof-of-work witness. |
| `nonce` | Fresh 32 bytes per connection. The client signs it to prove key possession. |
| `min_security_level` | Minimum identity proof of work this server accepts. |
| `requires_password` | Whether a server password is needed. |
| `signature` | Over `nonce`, the server's TLS certificate hash, and `server_name`. |

That signature is the whole basis of server authentication. It proves the holder
of `server_identity` is on the other end of *this specific* TLS session — an
interceptor would have to present its own certificate, and could not sign that
certificate's hash without the server's identity key.

It also means the TLS certificate can be regenerated freely without alarming
anyone, as long as the identity key survives. Trust is pinned to the identity,
not the certificate.

The server name is length-prefixed inside the signed bytes so it cannot be
shifted into the adjacent field.

### ClientAuth

Carries the client's public identity, nickname, optional server password, and a
signature over the server's `nonce` **together with the server's certificate
hash**.

Binding to the certificate hash is what stops a hostile server from relaying a
client's response to a third server and logging in as them. Without it, the
signature would be valid anywhere.

The server then checks, cheapest first: protocol version, password (compared
without an early exit, so timing does not leak a prefix), signature, and
proof-of-work level. Nicknames are cosmetic, unverified, and may be rewritten or
rejected — the fingerprint is what identifies a person.

A client has 10 seconds to complete this, bounding what an unauthenticated peer
can hold.

## Identity

An identity is an Ed25519 keypair. Its **fingerprint** is `SHA-256(public_key)`,
rendered as hyphenated base32 so it can be read aloud or compared by eye.

### Security level

```
level = leading_zero_bits(SHA-256("pickle-identity-pow-v1" || public_key || counter))
```

The counter is a witness, not a secret: anyone recomputes the level from the
public key alone, so a peer's claim about its own level is never trusted.

Each level doubles the expected search — level 20 is about a million hashes,
level 30 a billion. Crucially, mining changes only the counter, never the
keypair, so the fingerprint survives an upgrade and users keep the permissions
servers granted them.

## Control messages

Length-prefixed frames: a little-endian `u32` followed by that many
[postcard](https://docs.rs/postcard) bytes. The prefix is validated against a
1 MiB cap *before* allocating, so a peer cannot make the other end reserve
gigabytes by lying about a length.

Client to server: `Auth`, `JoinChannel`, `LeaveChannel`, `SetVoiceState`,
`SetNickname`, `SendMessage`, `EditMessage`, `DeleteMessage`, `React`,
`FetchHistory`, `Typing`, `Ping`.

Server to client: `Hello`, `AuthOk`, `AuthFailed`, `UserJoined`, `UserLeft`,
`UserMoved`, `UserUpdated`, `VoiceActivity`, `ChannelCreated`, `ChannelUpdated`,
`ChannelRemoved`, `MessagePosted`, `MessageEdited`, `MessageDeleted`,
`ReactionUpdated`, `History`, `Typing`, `Pong`, `Error`.

Clients are limited to 30 control messages per second, via a token bucket that
allows short bursts without permitting a sustained flood. Voice is not counted —
it is rate-limited by its own 20 ms cadence.

`SendMessage` carries a client-chosen nonce, echoed back only to the author, so
an optimistic local render can be reconciled with the server's authoritative
copy.

## Voice datagrams

Hand-encoded rather than serde-serialised: this is the hot path, one packet per
20 ms per speaker, and the layout should be readable straight from the bytes.
All integers little-endian.

**Client to server** (6-byte header):

```
[0]      u8    tag = 1
[1..5]   u32   sequence
[5]      u8    flags
[6..]          Opus payload
```

**Server to client** (10-byte header):

```
[0]      u8    tag = 2
[1..5]   u32   sender client id
[5..9]   u32   sequence
[9]      u8    flags
[10..]         Opus payload
```

Flags: bit 0 marks the start of a talk burst, bit 1 the end.

The two directions use distinct tags so a client cannot pass off a downstream
packet as its own upstream and forge the sender field.

### There is no channel id

An upstream packet says nothing about which channel it belongs to. The server
already knows where the sender is and routes on that. If the client named the
channel, anyone could transmit into a channel they had never joined.

For the same reason, **mute is enforced at the server**: a muted client's frames
are dropped in the relay, not merely suppressed in its own UI, so a modified
client gains nothing by lying about its state.

### Relay, not mix

The server forwards each speaker's stream separately rather than summing them.
Mixing would cost CPU proportional to the listener count and would flatten every
stream into one — losing per-speaker volume, independent jitter buffering (so
one person on bad wifi degrades everyone), and any future positional audio.
Relaying keeps the server cheap and the client in control.

## Audio parameters

48 kHz, mono, 20 ms frames (960 samples), Opus in VoIP mode at 32 kbit/s by
default. 48 kHz is Opus's native rate, so nothing resamples between the
microphone and the wire. Samples are `f32` normalised to ±1.0 end to end.

Receivers buffer 3 frames (60 ms) before starting playback and cap the backlog at
16. A frame that never arrives is reported as lost and concealed rather than
skipped, so playback keeps its timing.

Sequence numbers are per-sender and restart on each talk burst. Receivers extend
them to a monotonic 64-bit space internally, because raw `u32` values do not
order correctly across their rollover.

## Versioning

`PROTOCOL_VERSION` is checked for exact equality, and the version is also in the
ALPN identifier, so an incompatible client is rejected during the TLS handshake
rather than after it. Pre-1.0 there is no negotiation or compatibility shim.
