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

### Postgres needs its secrets created first

The `postgres/` files take the database password from podman secrets rather
than from a file sitting in your home directory, and **both secrets must exist
before the units will start**. Skip this and `pickle-db` fails with:

```
Error: running container create option: no secret with name or id "pickle-db-password": no such secret
```

which surfaces as the *server* failing to start, because it requires the
database.

Create both from one password, then copy the files as above:

```bash
PW=$(openssl rand -base64 32 | tr -d '/+=')
printf '%s' "$PW" | podman secret create pickle-db-password -
printf 'postgres://pickle:%s@pickle-db:5432/pickle' "$PW" \
  | podman secret create pickle-database-url -

cp examples/quadlet/postgres/* ~/.config/containers/systemd/
systemctl --user daemon-reload
systemctl --user start pickle-server
```

Two secrets rather than one because quadlet does not interpolate: the server
needs the password inside a connection URL, and a `${...}` in an `Environment=`
line would reach the container verbatim. So the assembled URL is its own secret.

The exact form of those commands is load-bearing. `printf` rather than `echo`
because podman stores stdin verbatim, so a trailing newline ends up inside the
password; `tr -d '/+='` because `+`, `/` and `=` would need percent-encoding
inside the URL. Either mistake gives you a database that starts and a server
that cannot authenticate against it — a far more confusing failure than a
missing secret.

Secrets belong to the user that owns the units. Creating them with `sudo
podman` puts them where a `systemctl --user` service cannot see them.

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

The server states at startup whether it has an owner and names the fingerprint,
so a `PICKLE_OWNER` that never reached the container is visible rather than
silent — the two cases are otherwise indistinguishable, because a server with no
owner starts perfectly happily:

```bash
journalctl --user -u pickle-server | grep -i owner
```

A malformed fingerprint is different again: set through the environment it stops
the server rather than being ignored, so a typo shows up as a unit that will not
start, not as a server you quietly do not own.

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
