-- What the rebuttal read, v7.
--
-- The rebuttal used to answer from the notes and the objections alone: no tools, so no way to
-- fetch the row that settles an objection. On a customer log the critique objected that the
-- cited rows showed no failure -- true of the citations -- and the line that answered it
-- (`No Solr data found for part number: ...`, one second later on the same thread) sat unread
-- because the loop had never opened it and the rebuttal could not. It restated the conclusion
-- instead, and a correct answer came out of the challenge downgraded to medium.
--
-- The rebuttal now gets the reading tools for a few calls and may cite what it fetched. Those
-- citations are kept beside the response, checked against what it was actually shown, so a
-- reader can follow the answer back to rows the same way they can the objection.

ALTER TABLE adversarial_objections ADD COLUMN response_log_event_ids_json TEXT NOT NULL DEFAULT '[]';
