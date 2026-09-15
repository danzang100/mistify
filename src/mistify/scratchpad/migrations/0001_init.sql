-- Mistify scratchpad schema, v1.
-- One database per incident. This is the working memory of the whole system: every stage
-- writes here and the investigator reads here rather than re-reading raw logs.

-- Incident identity and provenance. Without this there is no defined point at which an
-- incident is created and nowhere for `investigate` / `report` to resolve their
-- --incident-id against.
CREATE TABLE incidents (
  incident_id   TEXT PRIMARY KEY,
  created_at    TEXT NOT NULL,
  source        TEXT NOT NULL,
  format        TEXT,
  redaction_mode TEXT
);

-- One row per unique template, with the statistics the investigator ranks on.
CREATE TABLE templates (
  template_id       INTEGER PRIMARY KEY,
  pattern           TEXT NOT NULL,
  occurrence_count  INTEGER NOT NULL DEFAULT 0,
  first_seen        TEXT,
  last_seen         TEXT,
  severity_mix_json TEXT NOT NULL DEFAULT '{}',
  max_severity_rank INTEGER NOT NULL DEFAULT 0,
  -- Frequency deviation from baseline. Populated by the scoring pass after load; the
  -- adversarial check's "was a high-scoring template excluded from the conclusion" test
  -- depends on it being non-constant, so it is a requirement rather than an improvement.
  anomaly_score     REAL NOT NULL DEFAULT 0.0
);

CREATE TABLE log_events (
  id          INTEGER PRIMARY KEY,
  ts          TEXT NOT NULL,
  source      TEXT,
  severity    TEXT,
  template_id INTEGER REFERENCES templates(template_id),
  raw         TEXT,
  message     TEXT,
  fields_json TEXT
);
CREATE INDEX idx_log_events_ts ON log_events(ts);
CREATE INDEX idx_log_events_template ON log_events(template_id);
CREATE INDEX idx_log_events_severity ON log_events(severity);

-- The investigator's running notes. Evidence is mandatory and enforced here rather than in
-- Python: it is what lets the adversarial check verify claims against data instead of
-- re-reading the narrative.
CREATE TABLE scratchpad_notes (
  id                       INTEGER PRIMARY KEY,
  step                     INTEGER NOT NULL,
  note                     TEXT NOT NULL,
  supporting_evidence_json TEXT NOT NULL,
  confidence               TEXT NOT NULL,
  created_at               TEXT NOT NULL,
  CHECK (length(trim(supporting_evidence_json)) > 0),
  CHECK (trim(supporting_evidence_json) NOT IN ('[]', '{}', 'null', '""')),
  CHECK (length(trim(note)) > 0),
  CHECK (confidence IN ('low', 'medium', 'high'))
);

-- Every slice or query the investigator requested, for auditability.
CREATE TABLE query_log (
  id        INTEGER PRIMARY KEY,
  step      INTEGER,
  sql_query TEXT NOT NULL,
  row_count INTEGER,
  ts        TEXT NOT NULL
);

-- Per-stage health metrics. The architecture states that a health metric per stage is not
-- optional polish, but the original four-table schema had nowhere to put one, so nothing
-- could be asserted in a test or declared in a report.
CREATE TABLE run_metadata (
  id        INTEGER PRIMARY KEY,
  stage     TEXT NOT NULL,
  metric    TEXT NOT NULL,
  value     TEXT NOT NULL,
  value_num REAL,
  ts        TEXT NOT NULL
);
CREATE INDEX idx_run_metadata_stage ON run_metadata(stage);
CREATE UNIQUE INDEX idx_run_metadata_key ON run_metadata(stage, metric);
