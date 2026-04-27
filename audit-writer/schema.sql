-- audit.db schema — EmergenIT Linux Telemetry

CREATE TABLE IF NOT EXISTS audit_runs (
    id              INTEGER PRIMARY KEY AUTOINCREMENT,
    run_at          TEXT NOT NULL,
    host            TEXT NOT NULL,
    report_file     TEXT NOT NULL UNIQUE,
    lynis_version   TEXT,
    hardening_index INTEGER,
    warnings_count  INTEGER DEFAULT 0,
    suggestions_count INTEGER DEFAULT 0,
    prior_run_id    INTEGER REFERENCES audit_runs(id),
    index_delta     INTEGER
);

CREATE TABLE IF NOT EXISTS findings (
    id              INTEGER PRIMARY KEY AUTOINCREMENT,
    run_id          INTEGER NOT NULL REFERENCES audit_runs(id) ON DELETE CASCADE,
    test_id         TEXT NOT NULL,
    finding_type    TEXT NOT NULL CHECK(finding_type IN ('warning','suggestion')),
    severity        TEXT NOT NULL CHECK(severity IN ('CRITICAL','HIGH','MEDIUM','LOW','INFO')),
    description     TEXT,
    solution        TEXT,
    category        TEXT
);

CREATE INDEX IF NOT EXISTS idx_findings_run_id  ON findings(run_id);
CREATE INDEX IF NOT EXISTS idx_findings_test_id ON findings(test_id);
CREATE INDEX IF NOT EXISTS idx_runs_host        ON audit_runs(host);
CREATE INDEX IF NOT EXISTS idx_runs_run_at      ON audit_runs(run_at);
