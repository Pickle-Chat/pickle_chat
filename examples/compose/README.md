# Compose examples

Two worked setups:

- [`sqlite/`](sqlite) — one container, one volume, no database to run. What most
  self-hosted servers want.
- [`postgres/`](postgres) — adds a Postgres service, for people who already run
  one or want its backup and replication tooling.

Both work with Docker and with Podman. `podman compose` delegates to whichever
compose implementation is installed, so the same file serves both:

```bash
docker compose up -d      # or: podman compose up -d
```

If you run Podman and would rather systemd supervised the service — with proper
dependency ordering, journald logging, and restarts from the init system — see
the [quadlets](../quadlet) instead.

## Read before running either

The two mistakes that cost you a server are documented in the compose files
themselves, and both are worth repeating:

- **Publish the port as UDP.** Pickle speaks QUIC. `"42071:42071/udp"`. Without
  the suffix you publish a TCP port nothing connects to, and it looks like a
  firewall problem rather than a typo.
- **The `pickle-data` volume is the server's identity.** It holds the Ed25519
  keypair clients pin on first contact. Deleting it makes the server come back
  as a different server, and every existing client refuses to reconnect and
  reports a possible impersonation — correct behaviour, recoverable only by
  everyone verifying the new fingerprint out of band. With Postgres this volume
  still matters: history is in the database, but the identity is not, so backing
  up only the database is not enough.

Do not put either behind a reverse proxy. The certificate is self-signed by
design and authentication is bound to a hash of it, so terminating TLS breaks
the check that makes the connection trustworthy.
