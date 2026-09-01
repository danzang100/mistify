-- The adversarial pass's own output, v2.
--
-- Until now the critique produced objections, an alternative explanation and a set of
-- rebuttals, and the only thing that survived was a count in `run_metadata`. A report could
-- say "2 evidence-backed objections at high severity" and not what they were, which is the
-- half a reader actually needs: an objection the investigation *conceded* changes what the
-- conclusion is worth, and a plausible alternative is the first thing to check next.
--
-- Stored as scratchpad state like everything else, so the report keeps reading one source
-- and `mistify report` can be re-run without re-running the check.

CREATE TABLE adversarial_objections (
  id                 INTEGER PRIMARY KEY,
  claim              TEXT NOT NULL,
  objection          TEXT NOT NULL,
  severity           TEXT NOT NULL DEFAULT 'medium',
  template_ids_json  TEXT NOT NULL DEFAULT '[]',
  log_event_ids_json TEXT NOT NULL DEFAULT '[]',
  -- The investigation's answer, when it was given one. NULL means unanswered, which is a
  -- different and worse state than answered-and-not-conceded.
  response           TEXT,
  conceded           INTEGER,
  created_at         TEXT NOT NULL
);

-- One row. The pass's verdict on the investigation as a whole.
CREATE TABLE adversarial_summary (
  id                 INTEGER PRIMARY KEY CHECK (id = 1),
  assessment         TEXT NOT NULL DEFAULT '',
  alternative        TEXT NOT NULL DEFAULT '',
  -- What the investigation said its confidence was *after* being challenged. Dropped on the
  -- floor before this table existed, which meant a conclusion that had conceded ground still
  -- reported the confidence it started with.
  revised_confidence TEXT NOT NULL DEFAULT '',
  outcome            TEXT NOT NULL,
  created_at         TEXT NOT NULL
);
