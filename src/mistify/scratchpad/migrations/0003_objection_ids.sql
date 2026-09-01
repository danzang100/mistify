-- Objections get a stable id, v3.
--
-- The rebuttal was matched to the objection it answered by position in the reply list, which
-- held only while the model returned exactly as many responses as there were objections. It
-- names the objection it is answering in free text, and that is not something to key on: a
-- mispaired reply attaches a concession to the wrong claim, which is worse than no pairing at
-- all because it reads as an admission the investigation never made.
--
-- The ids are assigned by us, not asked of the model. It is shown them and required to quote
-- one back, so a model that ignores the instruction produces an unmatched response we can
-- report as unmatched rather than a plausible-looking mispairing.

ALTER TABLE adversarial_objections ADD COLUMN objection_id TEXT NOT NULL DEFAULT '';
