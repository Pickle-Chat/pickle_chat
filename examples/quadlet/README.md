# Quadlets

Podman's systemd integration. A `.container` file is not a unit — systemd's
podman generator turns it into one, so the server gets proper dependency
ordering, journald logging, and restart handling without a compose process
supervising anything.

Prefer these over the compose files if you run podman. Prefer compose if you run
Docker, or if you want one file you can hand to someone.

## Rootless, which is what you want

Copy the files for the backend you want into your user's quadlet directory:

```bash
mkdir -p ~/.config/containers/systemd
cp examples/quadlet/sqlite/* ~/.config/containers/systemd/
systemctl --user daemon-reload
systemctl --user start pickle-server
```

**Enable lingering, or the server stops when you log out.** Rootless user
services are tied to your login session unless you say otherwise:

```bash
loginctl enable-linger $USER
```

For a system-wide service instead, the files go in `/etc/containers/systemd/`
and the commands drop `--user`. Rootless is the better default: the server needs
no privileges beyond binding a high UDP port and writing its own data.

## Checking it

```bash
systemctl --user status pickle-server
journalctl --user -u pickle-server -f

# The fingerprint to share, read from the same volume the service uses.
podman run --rm -v pickle-data:/data \
  ghcr.io/pickle-chat/pickle-server:latest identity
```

## The two things that cost you a server

**The port must be UDP.** `PublishPort=42071:42071/udp`. Pickle speaks QUIC;
without `/udp` you publish a TCP port nothing ever connects to, and it presents
as a timeout that looks like a firewall problem.

**The volume holds the server's identity.** `pickle-data` carries the Ed25519
keypair clients pin on first contact. Delete it and the server returns as a
different server — every existing client refuses to reconnect and reports a
possible impersonation, which is correct and is recoverable only by every user
verifying the new fingerprint out of band. Back it up.

## Do not put this behind a reverse proxy

There is no TLS worth terminating. The certificate is self-signed by design — a
self-hosted server has no domain a public CA would vouch for — and
authentication is bound to a hash of that exact certificate. A proxy presenting
its own certificate breaks the check that makes the connection trustworthy.
Publish the UDP port directly.
