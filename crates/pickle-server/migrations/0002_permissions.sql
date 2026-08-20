-- The Discord-model permission tables, in the same portable subset as 0001:
-- BIGINT, TEXT and nothing else, ids assigned by the application, one schema
-- serving both SQLite and Postgres.
--
-- The 0001 roles and role_assignments tables are dropped rather than
-- migrated: they were written by no code path that ever shipped — the JSON
-- file was the real store — so they have been empty on every deployment that
-- ever existed. The 0001 bans table is kept and finally used as-is.

DROP TABLE IF EXISTS role_assignments;
DROP TABLE IF EXISTS roles;

CREATE TABLE IF NOT EXISTS roles (
    -- Application-assigned. 0 is @everyone: present as an ordinary row so
    -- there is exactly one code path, pinned at position 0 by handler rule.
    id          BIGINT PRIMARY KEY,
    name        TEXT   NOT NULL,
    -- Dense and unique; higher outranks. Kept dense by the reorder handler.
    position    BIGINT NOT NULL,
    -- 0xRRGGBB, or NULL for the default. Cosmetic.
    color       BIGINT,
    -- The permission bitset. Bit 63 is permanently unassigned, so a u64 mask
    -- always round-trips a signed BIGINT via a plain cast.
    permissions BIGINT NOT NULL
);

CREATE TABLE IF NOT EXISTS role_members (
    -- Full fingerprint text, the stable identity of a member across sessions.
    fingerprint TEXT   NOT NULL,
    role_id     BIGINT NOT NULL,
    PRIMARY KEY (fingerprint, role_id)
);

CREATE TABLE IF NOT EXISTS channel_overwrites (
    channel     BIGINT NOT NULL,
    -- 0 = role, 1 = member; matches OverwriteTarget's postcard indices.
    target_kind BIGINT NOT NULL,
    -- The role id in decimal, or the full fingerprint string.
    target      TEXT   NOT NULL,
    allow       BIGINT NOT NULL,
    deny        BIGINT NOT NULL,
    PRIMARY KEY (channel, target_kind, target)
);

-- Channels move out of the config file so their ids are stable: overwrites
-- reference channel ids, and config-index-derived ids would silently
-- retarget every overwrite whenever an operator reordered their file. The
-- config seeds this table on first boot and is a template thereafter.
CREATE TABLE IF NOT EXISTS channels (
    id         BIGINT PRIMARY KEY,
    parent     BIGINT,
    name       TEXT   NOT NULL,
    topic      TEXT   NOT NULL,
    -- 'voice', 'text' or 'voice_and_text' — the config file's spellings.
    kind       TEXT   NOT NULL,
    max_users  BIGINT,
    sort_order BIGINT NOT NULL
);
