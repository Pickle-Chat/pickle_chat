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

Or with Docker:

```bash
docker run -d --name pickle -p 42071:42071/udp -v pickle-data:/data \
  ghcr.io/pickle-chat/pickle-server:latest
```

The port must be published as **UDP** — Pickle speaks QUIC — and the volume
holds the server's identity, so deleting it makes every client that pinned the
old one refuse to reconnect. `docker run --rm -v pickle-data:/data
ghcr.io/pickle-chat/pickle-server identity` prints the fingerprint to share.
Worked SQLite and Postgres setups are in
[`examples/compose`](examples/compose), or as podman
[quadlets](examples/quadlet) if you would rather systemd supervised it.
Configuration can come from `PICKLE_*` environment variables instead of the
config file.

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

A client may hold several connections at once, but voice lives on one of them at
a time. Speaker ids are assigned per server, so audio from two servers would
collide in a single mixer — and talking into several rooms at once is not
something anyone asks for. Switching tabs deliberately does not move the
microphone; reading one server should not cut you out of a conversation on
another.

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

Your keys live in `identities.json`, written `0600` and refused if the mode has
been widened. It can also be sealed with a passphrase: argon2id (19 MiB, 2
passes) derives a key into XChaCha20-Poly1305, with a fresh salt and nonce and
the cost parameters recorded in the file so they can be raised later without
stranding an older vault. Encryption is opt-in and stays off until you ask for
it, because a passphrase you did not choose to set is a lockout waiting to
happen. See the [known issues](#what-works-today) for what is not wired up yet.

## Layout

| Crate | What it does |
| --- | --- |
| [`pickle-identity`](crates/pickle-identity) | Ed25519 identities, proof-of-work security levels, single-key keystore and multi-identity vault (optionally passphrase-encrypted) |
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
- Several identities per user, switchable, with a chosen one signing each login
- Several servers connected at once, a tab each, reopened on the next launch
- Authentication with proof-of-work enforcement and certificate binding
- Trust-on-first-use server pinning
- Voice: capture, gating, Opus, relay, jitter buffering, mixing, mute/deafen
- Text messages delivered live to a channel
- Settings: identities, saved servers, audio devices, and keybinds, all persisted
- Push to talk, bound to a key and grabbed globally where the platform allows
- Desktop client covering all of the above

Not yet built:

- **Message persistence.** History requests return empty, and editing,
  deletion, and reactions are refused. This is the main gap between "text chat"
  and "text chat like Discord".
- **Rich text rendering.** Messages carry markdown; the client renders plain
  text.
- Attachments, permissions and roles, moderation (kick/ban), LAN discovery.

Known issues:

- **Opus FEC is disabled, because of an upstream bug.** Enabling in-band forward
  error correction corrupts the *ordinary* decode: a steady tone comes back with
  its energy swinging between 0.02× and 5.2×. The cause is in rusty-opus 0.9.1,
  not in how Pickle configures it — its SILK encoder writes the redundant LBRR
  frames without the LTP-scale symbol that its own decoder reads back, so the
  range decoder ends up one symbol out of step and everything after it, starting
  with the real frame's gains, decodes as garbage. It reproduces in both hybrid
  and SILK-only mode, and FEC recovery is equally wrong, so no encoder setting
  works around it. Loss is handled by the jitter buffer and concealment alone,
  which recovers less gracefully from bursts. See `USE_INBAND_FEC` in
  [`codec.rs`](crates/pickle-audio/src/codec.rs) for the full trace; the fix
  belongs upstream, and switching to C libopus would give up the pure-Rust build.
- **Voice uses more bandwidth than the configured bitrate**, by about 16% for the
  Opus payload plus a 10-byte header on every 20 ms datagram — roughly 1.3× the
  configured number on the wire. The encoder is not ignoring the setting: Opus
  bitrate is a VBR target rather than a ceiling, and asking for CBR instead hits
  it exactly. Budget from the measured rate, not from `DEFAULT_BITRATE`.
- Audio devices must support 48 kHz natively; there is no resampling.
- **Global keys are not guaranteed.** The keyboard grab goes through X11, so a
  key your layout cannot produce is refused, and a Wayland session may not
  deliver the key while another window has focus. The settings tab marks any
  binding the system refused, and push to talk falls back to working while
  Pickle is focused, so it is never silently dead.
- **Global mouse buttons need a udev rule.** The keyboard grab cannot see mouse
  buttons at all, so a bound button is read from the mouse's input device
  instead — which works under Wayland and X11 alike, but only if your user can
  open that device. See [Reading a mouse button](#reading-a-mouse-button).
  Without it the button still works while Pickle is focused.
- **The identity vault can be encrypted, but no UI turns it on yet.** The client
  can seal `identities.json` with a passphrase — argon2id into
  XChaCha20-Poly1305, parameters recorded in the file — and the library API,
  `Vault::set_passphrase`, is finished and tested. What is missing is the unlock
  prompt at startup, and until that exists nothing in the app offers to encrypt
  the vault: doing so would produce a file the next launch could not open.
  Existing vaults are unencrypted and keep working untouched; encryption never
  turns itself on.
- **Whether encrypted or not, back the vault up.** Losing it means losing every
  permission every server granted you, and if you do set a passphrase, forgetting
  it is exactly as final. There is no recovery, by design.
- **The server's keystore is deliberately unencrypted.** A server starts
  unattended, so any passphrase it could use would have to sit in a unit file, an
  environment variable, or a file beside the key — all readable by anyone who can
  already read the key. That is obfuscation wearing encryption's name. Protect a
  server key with file permissions (Pickle writes `0600` and refuses to load a
  wider mode), and with full-disk encryption or `systemd` credentials if you want
  more. See the module docs in
  [`keystore.rs`](crates/pickle-identity/src/keystore.rs).

## Reading a mouse button

Binding push to talk to a thumb button is the ordinary case, and the window
system will not deliver it: X11 and Wayland both hand pointer buttons to
whatever is focused, which during a game is not Pickle. The only way to see the
button is to read the mouse's `/dev/input/event*` node directly.

That node is not readable by default. The usual advice is to join the `input`
group:

```bash
sudo usermod -aG input $USER   # don't
```

Do not do this. `input` group membership grants **every** process you run read
access to **every** `/dev/input/event*` node on the machine — every keyboard
included — permanently, for every session. Any other program you run that is
ever compromised then has a keylogger, granted so that one thumb button could
be read. It is an enormous trade for a very small feature.

Grant access to the one mouse instead. Open **Settings → Keybinds** with a mouse
button bound: Pickle enumerates the devices, names the one it needs, and prints
the exact rule for your hardware, ready to copy. Otherwise, find the ids
yourself:

```bash
# Which node is your mouse? The name is at the end of each symlink.
ls -l /dev/input/by-id/*-event-mouse

# Its vendor and product ids, four hex digits each:
udevadm info -a -n /dev/input/event3 | grep -m2 -E 'idVendor|idProduct'
```

Then write `/etc/udev/rules.d/70-pickle-mouse.rules`, substituting your own ids:

```udev
SUBSYSTEM=="input", KERNEL=="event*", ENV{ID_INPUT_MOUSE}=="1", \
  ENV{ID_INPUT_KEYBOARD}!="1", ATTRS{idVendor}=="04a5", \
  ATTRS{idProduct}=="800a", TAG+="uaccess"
```

```bash
sudo udevadm control --reload
sudo udevadm trigger --subsystem-match=input
```

then unplug and replug the mouse, or reboot.

Each clause is doing something:

- `TAG+="uaccess"` gives the device to whoever is logged in at this machine's
  own screen, through an ACL that logind adds and removes with the session. No
  new group, nothing persistent, and nobody logged in over SSH inherits it. A
  blanket `MODE="0666"` would instead expose the mouse to every account on the
  box.
- `ATTRS{idVendor}`/`ATTRS{idProduct}` name the device itself. Matching a path
  like `/dev/input/event3` would be useless — that number is assigned in probe
  order and moves when something else is plugged in first.
- `ENV{ID_INPUT_MOUSE}=="1", ENV{ID_INPUT_KEYBOARD}!="1"` are what stop the
  grant widening. The ids belong to the *physical* device, and a keyboard with
  a built-in mouse node publishes its keyboard on the same pair — which is
  common in exactly the hardware at issue, since that is often where the bound
  button lives. Without these two clauses the rule would hand over the keyboard
  as well and quietly recreate the problem the `input` group had.
- The filename must sort between `60-input-id.rules`, which sets those two
  properties, and `73-seat-late.rules`, which acts on the tag. Hence `70-`.

A Bluetooth or I2C mouse has no USB parent and so no `idVendor`; use
`ATTRS{id/vendor}` and `ATTRS{id/product}` instead. `uaccess` needs logind or
elogind; without either, fall back to `MODE="0660", GROUP="yourgroup"` on the
same match.

What Pickle does with the device once it can open it:

- **It opens a device only if that device cannot report typing.** A device
  qualifies only if it reports `REL_X` and `REL_Y` (it moves a pointer) and
  `BTN_LEFT` and the button you bound, and reports **no** key in the typing
  block — `KEY_1` through `KEY_SLASH`, the number row, the letters, and the
  punctuation between them. That last condition is the one that matters:
  requiring `BTN_LEFT` alone is not enough, because a laptop keyboard with a
  trackpoint, a keyboard/mouse combo behind one receiver, and many gaming
  keyboards report `BTN_LEFT` and the full `KEY_*` range on a single node.
- **Only the button you bound.** Every other event, pointer motion included, is
  discarded without being examined, and no event is ever logged.
- **Passively.** The device is not grabbed with `EVIOCGRAB`, so the button still
  reaches the game underneath.

## Development

```bash
cargo test --workspace
cargo clippy --workspace --all-targets
```

CI also audits dependencies against the [RUSTSEC](https://rustsec.org) advisory
database — vulnerabilities fail the build, unmaintained and unsound advisories
are reported in the run summary without blocking it — and fuzzes the code that
parses bytes off the network: the Opus decoder and the voice datagram parsers.
Both run weekly as well as per push, since a new advisory needs no commit to
become relevant. See [`fuzz/`](fuzz) for running the fuzzers locally.

## Licence

MIT. See [LICENSE](LICENSE).
