-- One migration set has to be valid on both SQLite and Postgres, so this stays
-- inside the portable subset: BIGINT, TEXT, BOOLEAN, and nothing else.
--
-- No AUTOINCREMENT or BIGSERIAL anywhere. Message ids are assigned by the
-- application rather than the database, which is what makes a single schema
-- possible here — the two backends spell generated keys quite differently.

CREATE TABLE IF NOT EXISTS messages (
    id                 BIGINT PRIMARY KEY,
    channel            BIGINT NOT NULL,
    -- The fingerprint outlives the connection; the client id does not, so it is
    -- deliberately not stored. History has to render long after the author has
    -- gone.
    author_fingerprint TEXT   NOT NULL,
    -- Snapshotted at send time, so old messages keep the name they were sent
    -- under rather than following a later rename.
    author_nickname    TEXT   NOT NULL,
    sent_at_unix_ms    BIGINT NOT NULL,
    edited_at_unix_ms  BIGINT,
    content            TEXT   NOT NULL,
    reply_to           BIGINT
);

-- Paging walks backwards from the newest message in one channel, which is the
-- only access pattern history has.
CREATE INDEX IF NOT EXISTS messages_by_channel ON messages (channel, id DESC);

-- Retention prunes by age across all channels.
CREATE INDEX IF NOT EXISTS messages_by_age ON messages (sent_at_unix_ms);

CREATE TABLE IF NOT EXISTS roles (
    name         TEXT   PRIMARY KEY,
    rank         BIGINT NOT NULL,
    -- The capability list as JSON. A join table would be more normalised, but
    -- capabilities are read as a whole set every time and never queried across
    -- roles, so a row per role is the shape that gets used.
    capabilities TEXT   NOT NULL
);

CREATE TABLE IF NOT EXISTS role_assignments (
    fingerprint TEXT PRIMARY KEY,
    role        TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS bans (
    fingerprint   TEXT   PRIMARY KEY,
    reason        TEXT   NOT NULL,
    -- NULL is permanent. Expiry is compared on read rather than swept by a
    -- task, so a lapsed ban needs nothing running to stop applying.
    until_unix_ms BIGINT,
    -- Fingerprint of whoever issued it, for accountability.
    issued_by     TEXT   NOT NULL,
    issued_at_unix_ms BIGINT NOT NULL
);
