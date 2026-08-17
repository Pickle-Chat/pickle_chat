# The Pickle server.
#
# Only the server is built here. It has no audio dependency and no window, so
# none of the ALSA or WebKitGTK packages the desktop client needs are involved —
# `cargo build -p pickle-server` pulls a much smaller tree than the workspace.
#
# The resulting binary links exactly three shared libraries: libc, libm and
# libgcc_s. There is no OpenSSL, because TLS goes through rustls and ring; and
# no libsqlite3, because sqlx's `sqlite` feature compiles SQLite from source and
# links it statically. That is what makes the tiny runtime image below possible
# without static-linking gymnastics.

FROM rust:1-bookworm AS builder

WORKDIR /src

# `ring` and the bundled SQLite both compile C, so a toolchain is required in
# the builder. It does not follow the binary into the runtime stage.
RUN apt-get update \
    && apt-get install -y --no-install-recommends build-essential \
    && rm -rf /var/lib/apt/lists/*

COPY . .

RUN cargo build --release -p pickle-server \
    && strip target/release/pickle-server


# `cc` rather than `static`: the binary is dynamically linked against glibc.
# `nonroot` so the server does not run as uid 0 — it needs no privileges beyond
# binding a high UDP port and writing its data directory.
FROM gcr.io/distroless/cc-debian12:nonroot

COPY --from=builder /src/target/release/pickle-server /usr/local/bin/pickle-server

# Identity, certificate, configuration, and the SQLite database all live here.
#
# Mount a volume over it. This directory holds the server's Ed25519 identity,
# which clients pin on first contact — losing it means every existing client
# refuses to reconnect and reports the server as possibly impersonated, which is
# correct behaviour and recoverable only by every user verifying a new
# fingerprint out of band.
VOLUME ["/data"]

# QUIC is UDP. A published port without `/udp` accepts nothing, and the symptom
# looks like a firewall problem rather than a typo.
EXPOSE 42071/udp

# There is no shell in this image, so the entrypoint is the binary itself.
# Subcommands still work as one-shot containers:
#
#   docker run --rm -v pickle-data:/data ghcr.io/pickle-chat/pickle-server identity
#
ENTRYPOINT ["/usr/local/bin/pickle-server", "--data-dir", "/data"]
CMD ["run"]
