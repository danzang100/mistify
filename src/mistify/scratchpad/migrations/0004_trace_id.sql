-- Trace correlation, v4.
--
-- Distributed logs carry a trace id on every line, and it is the one axis that ties a request
-- across services together -- exactly the correlation an investigator reaches for and could
-- not perform here. The field was being parsed and stored inside `fields_json`, which no
-- index reaches and no tool filters on, so it may as well not have been kept.
--
-- Promoted to a column with an index. Backfilled from `fields_json` for incidents already
-- ingested, so an existing scratchpad gains the capability without a re-ingest. A record with
-- no trace id keeps NULL: absent and empty are different, and grouping on "" would collapse
-- every untraced line into one imaginary request.

ALTER TABLE log_events ADD COLUMN trace_id TEXT;

UPDATE log_events
   SET trace_id = json_extract(fields_json, '$.trace_id')
 WHERE trace_id IS NULL
   AND fields_json IS NOT NULL
   AND json_valid(fields_json)
   AND json_extract(fields_json, '$.trace_id') IS NOT NULL;

CREATE INDEX idx_log_events_trace ON log_events(trace_id);
