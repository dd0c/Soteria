-- Soteria schema version 1 (SRS 5.6).
--
-- Conventions:
--   * Timestamps are RFC 3339 UTC text.
--   * Filesystem paths are BLOBs holding the raw bytes: Linux paths need not
--     be valid UTF-8, and lossy conversion could let two files collide.
--   * Evidence is append-only. Triggers below stop alert evidence and sealed
--     baselines from being rewritten through normal SQL. They raise the bar
--     against accidents and casual tampering only; a local root attacker can
--     still edit the file (SRS 5.6, 10.2).

CREATE TABLE meta (
    key   TEXT PRIMARY KEY,
    value TEXT NOT NULL
) STRICT;

CREATE TABLE schema_migrations (
    version         INTEGER PRIMARY KEY,
    applied_at      TEXT NOT NULL,
    soteria_version TEXT NOT NULL
) STRICT;

-- Current inventory and file state (FR-001..004).
CREATE TABLE files (
    id             INTEGER PRIMARY KEY,
    path           BLOB NOT NULL UNIQUE,
    kind           TEXT NOT NULL,
    file_type      TEXT NOT NULL,          -- regular, directory, symlink, ...
    sha256         TEXT,                   -- NULL when not hashed; see last_error
    size           INTEGER,
    uid            INTEGER,
    gid            INTEGER,
    mode           INTEGER,
    mtime_ns       INTEGER,
    ctime_ns       INTEGER,
    inode          INTEGER,
    device         INTEGER,
    symlink_target BLOB,
    capabilities   BLOB,                   -- raw security.capability xattr
    security_label TEXT,                   -- SELinux context / AppArmor label
    first_seen     TEXT NOT NULL,
    last_verified  TEXT NOT NULL,
    last_error     TEXT
) STRICT;
CREATE INDEX files_kind ON files(kind);
CREATE INDEX files_sha256 ON files(sha256);

-- Baseline versions with approval provenance (FR-005, FR-006, FR-044).
CREATE TABLE baseline_versions (
    id             INTEGER PRIMARY KEY,
    version        INTEGER NOT NULL UNIQUE,
    state          TEXT NOT NULL CHECK (state IN ('draft', 'approved', 'superseded', 'rejected')),
    created_at     TEXT NOT NULL,
    created_by     TEXT NOT NULL,
    parent_version INTEGER REFERENCES baseline_versions(version),
    entry_count    INTEGER NOT NULL DEFAULT 0,
    approved_at    TEXT,
    approved_by    TEXT,
    approved_uid   INTEGER,
    digest         TEXT,                   -- SHA-256 over the canonical entry list
    signature      BLOB,                   -- Ed25519 signature over the digest
    key_id         TEXT,                   -- fingerprint of the signing key
    note           TEXT
) STRICT;

CREATE TABLE baseline_entries (
    baseline_id    INTEGER NOT NULL REFERENCES baseline_versions(id),
    path           BLOB NOT NULL,
    kind           TEXT NOT NULL,
    file_type      TEXT NOT NULL,
    sha256         TEXT,
    size           INTEGER,
    uid            INTEGER,
    gid            INTEGER,
    mode           INTEGER,
    mtime_ns       INTEGER,
    ctime_ns       INTEGER,
    inode          INTEGER,
    device         INTEGER,
    symlink_target BLOB,
    capabilities   BLOB,
    security_label TEXT,
    PRIMARY KEY (baseline_id, path)
) STRICT, WITHOUT ROWID;

CREATE TRIGGER baseline_sealed_no_update
BEFORE UPDATE OF version, created_at, created_by, parent_version, entry_count,
                 approved_at, approved_by, approved_uid, digest, signature, key_id
ON baseline_versions
WHEN OLD.state IN ('approved', 'superseded')
BEGIN
    SELECT RAISE(ABORT, 'sealed baseline versions are immutable');
END;

CREATE TRIGGER baseline_sealed_no_delete
BEFORE DELETE ON baseline_versions
WHEN OLD.state IN ('approved', 'superseded')
BEGIN
    SELECT RAISE(ABORT, 'sealed baseline versions cannot be deleted');
END;

CREATE TRIGGER baseline_entries_sealed_no_update
BEFORE UPDATE ON baseline_entries
WHEN (SELECT state FROM baseline_versions WHERE id = OLD.baseline_id) IN ('approved', 'superseded')
BEGIN
    SELECT RAISE(ABORT, 'entries of sealed baseline versions are immutable');
END;

CREATE TRIGGER baseline_entries_sealed_no_delete
BEFORE DELETE ON baseline_entries
WHEN (SELECT state FROM baseline_versions WHERE id = OLD.baseline_id) IN ('approved', 'superseded')
BEGIN
    SELECT RAISE(ABORT, 'entries of sealed baseline versions cannot be deleted');
END;

CREATE TRIGGER baseline_entries_sealed_no_insert
BEFORE INSERT ON baseline_entries
WHEN (SELECT state FROM baseline_versions WHERE id = NEW.baseline_id) IN ('approved', 'superseded')
BEGIN
    SELECT RAISE(ABORT, 'entries cannot be added to sealed baseline versions');
END;

-- Raw sensor and system events.
CREATE TABLE events (
    id        INTEGER PRIMARY KEY,
    ts        TEXT NOT NULL,
    sensor    TEXT NOT NULL,
    type      TEXT NOT NULL,
    severity  TEXT NOT NULL CHECK (severity IN ('info', 'low', 'medium', 'high', 'critical')),
    path      BLOB,
    pid       INTEGER,
    uid       INTEGER,
    data      TEXT NOT NULL DEFAULT '{}'      -- JSON
) STRICT;
CREATE INDEX events_ts ON events(ts);
CREATE INDEX events_type_ts ON events(type, ts);
CREATE INDEX events_path ON events(path);

-- Correlated incidents (FR-018).
CREATE TABLE incidents (
    id         INTEGER PRIMARY KEY,
    created_at TEXT NOT NULL,
    updated_at TEXT NOT NULL,
    severity   TEXT NOT NULL CHECK (severity IN ('info', 'low', 'medium', 'high', 'critical')),
    title      TEXT NOT NULL,
    status     TEXT NOT NULL CHECK (status IN ('open', 'closed'))
) STRICT;

-- Detection findings and lifecycle (FR-029, FR-030).
CREATE TABLE alerts (
    id             INTEGER PRIMARY KEY,
    uuid           TEXT NOT NULL UNIQUE,
    created_at     TEXT NOT NULL,
    updated_at     TEXT NOT NULL,
    severity       TEXT NOT NULL CHECK (severity IN ('info', 'low', 'medium', 'high', 'critical')),
    type           TEXT NOT NULL,
    status         TEXT NOT NULL CHECK (status IN ('open', 'acknowledged', 'investigated', 'suppressed', 'closed')),
    hostname       TEXT NOT NULL,
    object         TEXT,
    rule_id        TEXT NOT NULL,
    reason         TEXT NOT NULL,
    evidence       TEXT NOT NULL DEFAULT '{}', -- JSON: previous/current state, hashes, user context
    recommendation TEXT NOT NULL,
    incident_id    INTEGER REFERENCES incidents(id),
    event_id       INTEGER REFERENCES events(id)
) STRICT;
CREATE INDEX alerts_status_severity ON alerts(status, severity);
CREATE INDEX alerts_created_at ON alerts(created_at);

-- Acknowledgement must not alter original evidence (FR-030).
CREATE TRIGGER alerts_evidence_immutable
BEFORE UPDATE OF uuid, created_at, severity, type, hostname, object, rule_id,
                 reason, evidence, recommendation, event_id
ON alerts
BEGIN
    SELECT RAISE(ABORT, 'alert evidence is immutable');
END;

CREATE TRIGGER alerts_no_delete
BEFORE DELETE ON alerts
BEGIN
    SELECT RAISE(ABORT, 'alerts cannot be deleted');
END;

-- Append-only lifecycle history: status changes and notes, with actor.
CREATE TABLE alert_history (
    id          INTEGER PRIMARY KEY,
    alert_id    INTEGER NOT NULL REFERENCES alerts(id),
    ts          TEXT NOT NULL,
    actor       TEXT NOT NULL,
    action      TEXT NOT NULL CHECK (action IN ('created', 'status', 'note')),
    from_status TEXT,
    to_status   TEXT,
    note        TEXT
) STRICT;
CREATE INDEX alert_history_alert ON alert_history(alert_id);

CREATE TRIGGER alert_history_append_only_update
BEFORE UPDATE ON alert_history
BEGIN
    SELECT RAISE(ABORT, 'alert history is append-only');
END;

CREATE TRIGGER alert_history_append_only_delete
BEFORE DELETE ON alert_history
BEGIN
    SELECT RAISE(ABORT, 'alert history is append-only');
END;

-- Execution records (FR-009, FR-010, FR-013).
CREATE TABLE processes (
    id             INTEGER PRIMARY KEY,
    ts             TEXT NOT NULL,
    pid            INTEGER NOT NULL,
    ppid           INTEGER,
    uid            INTEGER,
    euid           INTEGER,
    gid            INTEGER,
    exe            BLOB,
    sha256         TEXT,
    comm           TEXT,
    argv           TEXT,                   -- JSON array, subject to privacy settings
    cwd            BLOB,
    classification TEXT NOT NULL CHECK (classification IN ('trusted', 'known_modified', 'unknown', 'suspicious', 'unverified')),
    rationale      TEXT NOT NULL,
    severity       TEXT NOT NULL CHECK (severity IN ('info', 'low', 'medium', 'high', 'critical')),
    sensor         TEXT NOT NULL,
    event_id       INTEGER REFERENCES events(id)
) STRICT;
CREATE INDEX processes_ts ON processes(ts);
CREATE INDEX processes_exe ON processes(exe);
CREATE INDEX processes_pid ON processes(pid);
CREATE INDEX processes_uid ON processes(uid);

-- Rule definitions, versions and enabled state.
CREATE TABLE rules (
    id         TEXT PRIMARY KEY,
    version    INTEGER NOT NULL,
    source     TEXT NOT NULL CHECK (source IN ('builtin', 'admin')),
    enabled    INTEGER NOT NULL CHECK (enabled IN (0, 1)),
    severity   TEXT NOT NULL CHECK (severity IN ('info', 'low', 'medium', 'high', 'critical')),
    definition TEXT NOT NULL,
    updated_at TEXT NOT NULL
) STRICT;

-- Scan results (FR-034). 'running' rows found at startup are interrupted scans.
CREATE TABLE scan_history (
    id          INTEGER PRIMARY KEY,
    uuid        TEXT NOT NULL UNIQUE,
    type        TEXT NOT NULL,
    target      TEXT,
    started_at  TEXT NOT NULL,
    finished_at TEXT,
    status      TEXT NOT NULL CHECK (status IN ('running', 'completed', 'failed', 'interrupted')),
    checked     INTEGER NOT NULL DEFAULT 0,
    skipped     INTEGER NOT NULL DEFAULT 0,
    errors      INTEGER NOT NULL DEFAULT 0,
    changes     INTEGER NOT NULL DEFAULT 0,
    detail      TEXT NOT NULL DEFAULT '{}'
) STRICT;
CREATE INDEX scan_history_started ON scan_history(started_at);

-- Sensor and service status over time (FR-037, FR-039).
CREATE TABLE sensor_health (
    id     INTEGER PRIMARY KEY,
    ts     TEXT NOT NULL,
    sensor TEXT NOT NULL,
    state  TEXT NOT NULL,
    detail TEXT
) STRICT;
CREATE INDEX sensor_health_sensor_ts ON sensor_health(sensor, ts);

-- Coverage gaps (FR-017). Open while closed_at is NULL.
CREATE TABLE coverage_gaps (
    id        INTEGER PRIMARY KEY,
    opened_at TEXT NOT NULL,
    closed_at TEXT,
    kind      TEXT NOT NULL,              -- inaccessible, not_hashed, excluded, overflow, sensor_down, scan_incomplete, ...
    sensor    TEXT,
    path      BLOB,
    detail    TEXT NOT NULL
) STRICT;
CREATE INDEX coverage_gaps_open ON coverage_gaps(closed_at);

-- Administrator-approved suppressions.
CREATE TABLE suppression_rules (
    id         INTEGER PRIMARY KEY,
    created_at TEXT NOT NULL,
    created_by TEXT NOT NULL,
    rule_id    TEXT,
    matcher    TEXT NOT NULL,             -- JSON
    reason     TEXT NOT NULL,
    expires_at TEXT,
    enabled    INTEGER NOT NULL CHECK (enabled IN (0, 1))
) STRICT;
