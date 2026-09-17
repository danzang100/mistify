-- The incident brief, v6.
--
-- What was reported, in the reporter's words: the user, the action, the items, the symptom.
-- Until now the investigator had the log and nothing else, so on a full production day it
-- answered "what is anomalous here" rather than "why did this happen" -- on a customer log
-- whose evidence sat at rank 2 of the digest, it led with an unrelated chronic error and
-- dismissed the evidence as noise, because nothing told it what the incident was.
--
-- Stored redacted, with the incident's own redactor, at ingest. That is the only moment it
-- can be: the salt is drawn per incident and kept nowhere, so a brief redacted later would
-- name the user by a placeholder that appears on no line. Redacted here, the placeholder in
-- the brief is the one on every line the user touched, and the join survives. NULL means no
-- brief was given, and the report says so.

ALTER TABLE incidents ADD COLUMN brief TEXT;
