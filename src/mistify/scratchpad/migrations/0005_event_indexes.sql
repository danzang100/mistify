-- Reshape two log_events indexes that were the wrong shape rather than unnecessary.
--
-- Measured on a 1,000,000-event Loghub-2.0 BGL scratchpad (297 MB vacuumed).
--
-- `idx_log_events_severity` indexed severity alone. Severity has four distinct values and the
-- commonest is half the table, so SQLite used the index to find the rows and then built a temp
-- B-tree to satisfy `ORDER BY ts, id` -- 124 ms to return 200 rows for a common severity, and
-- 111 ms for severity plus a time window. Those sorts grow with the table: at the 64M events a
-- 10 GB corpus would hold, the same query is seconds rather than milliseconds.
--
-- Dropping it outright was the first idea and was wrong. Without any severity index a *rare*
-- severity -- which is precisely what an investigation looks for -- went from 0.2 ms to 170 ms,
-- because the only way left to find 216 ERROR rows in a million is to walk the whole table.
--
-- The composite serves both: the severity prefix finds the rows and the trailing `ts` supplies
-- the order, so no temp B-tree is built at all.
--
--     severity = ERROR (rare, 216 rows)     0.2 ms -> 0.1 ms
--     severity = FATAL (half the table)   124.2 ms -> 0.2 ms
--     severity + ts window                111.1 ms -> 0.0 ms
--
-- It costs about 3% more on disk than the plain index it replaces. That is a deliberate trade
-- of storage for latency, and the opposite direction from the rest of the scale work.
DROP INDEX IF EXISTS idx_log_events_severity;
CREATE INDEX IF NOT EXISTS idx_log_events_severity_ts ON log_events(severity, ts);

-- `trace_id` is NULL on every row of any log that does not carry traces -- all 1,000,000 of
-- the BGL events, and every unstructured log there is -- and the full index still cost 9 MB
-- indexing those NULLs. A partial index holds only the rows a `trace_id = ?` lookup can ever
-- match, so it is free on logs without traces and identical on logs with them.
DROP INDEX IF EXISTS idx_log_events_trace;
CREATE INDEX IF NOT EXISTS idx_log_events_trace ON log_events(trace_id) WHERE trace_id IS NOT NULL;
