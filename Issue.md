# Deferred issues

Problems found during the Phase 2 architecture review that are **not** being fixed now. Each
one records what the problem is, why it matters, the fix that should land, and the phase it
belongs to. Nothing here is a bug in shipped behaviour; they are consequences of the current
design that will bite in a later phase, written down so they are decided deliberately rather
than rediscovered mid-investigation.

Where a decision here contradicts an entry in [`docs/v1-decisions.md`](docs/v1-decisions.md)
or one of the design documents, the fix column says which document to amend.

| Issue | Severity | Target phase |
|---|---|---|
| 1. Two rankings coexist | Medium | 3 |
| 2. Anomaly scores are global, computed once | Medium | 3 |
| 3. The anomaly baseline is the incident itself | High | 4/5 — promote from "Future" |
| 4. No index for trace correlation | Medium | 3 |
| 5. Unimplemented adapters are dropped silently | Low | 4 |
| 6. Noise thresholds are defined in two places | Medium | 3 — blocks the agent loop |

---

## 1 — Two rankings coexist

**Problem.** The Phase 1 skeleton investigator picks its target with
`db.top_templates(limit=10, order_by="severity")`, which orders by `max_severity_rank DESC,
occurrence_count DESC`. The report ranks the same templates with
`order_by="anomaly_score"`. Two orderings, two different definitions of "the template that
matters most", both live at once.

**Why it matters.** They agree on the current synthetic fixture, so nothing fails today. They
are not required to agree on anything else. When they diverge, the report leads with one
template and the finding underneath it is about a different one, and the disagreement is
invisible to the reader: both halves look internally consistent.

**Recommended fix.** When the real agent loop lands in Phase 3, make `anomaly_score`
authoritative everywhere and delete the severity-ordered selection path. Severity is already
the heaviest input to the score (weight 0.5, decision G3), so nothing is lost by dropping the
separate severity ranking — it is a coarser version of a signal the score already carries.

**Where.** `src/mistify/agent/skeleton.py`, `src/mistify/report/generator.py`,
`ScratchpadDB.top_templates` in `src/mistify/scratchpad/db.py`.

**Target phase.** 3.

## 2 — Anomaly scores are global, computed once

**Problem.** Scoring runs as a single post-load pass over the whole incident, at the end of
ingest, and the result is written once into `templates.anomaly_score`. The Phase 3 agent will
narrow to time windows via `get_slice`, but the scores it reads stay whole-file.

**Why it matters.** The score stops describing what the agent is looking at. A template that
is uniform across the file but bursts inside the chosen window scores low exactly when it
matters most; a template that is globally rare but constant within the window scores high for
no reason the window can justify. Burstiness is the component that inverts most sharply, since
it is measured against the mean over the entire incident span. The agent would be ranking a
slice using numbers computed for a file.

**Recommended fix.** Either recompute scores per slice when the agent narrows — `score_templates`
already takes burst statistics as an argument, so this is a query-scope change rather than a
rewrite — or document that ranking is valid only at full-file scope and have the tool layer
say so in the slice results. Either is defensible; leaving it undecided is not.

**Where.** `src/mistify/scratchpad/anomaly.py`, the scoring pass in `src/mistify/pipeline.py`,
`ScratchpadDB.get_slice`.

**Target phase.** 3.

## 3 — The anomaly baseline is the incident itself

**Problem.** `anomaly_score` is computed entirely from the ingested file's own distribution.
No baseline corpus, no history: rare within this file equals suspicious. That is a deliberate
Phase 2 choice (decision G3) and it is what makes the score work on the first file from a
service nobody has ingested before.

**Why it matters.** The assumption underneath it is that the export contains mostly-normal
traffic with a rare fault buried in it. People export logs because something broke. Hand the
pipeline the five minutes around an outage and the failing template becomes the *most common*
thing in the file, while the surviving healthy requests are the rare ones. Rarity does not
merely weaken there — it inverts, and points away from the cause.

Severity partly compensates, which is why it carries the heaviest weight. That compensation
disappears on logs with no severity field, where every event defaults to INFO and the severity
component is constant across all templates, leaving burstiness and an inverted rarity to carry
the whole ranking.

**Recommended fix.** The architecture document lists "persist and reuse template trees across
incidents" under future improvements. It is not a nice-to-have. It is the only real fix for
the baseline problem, and it should be promoted out of "Future" into a numbered phase —
alongside the adapter work in Phase 4 or the evaluation harness in Phase 5, whichever picks up
cross-incident state first. Cross-incident persistence is what makes "first time this error
has ever occurred" expressible at all; without it, novelty can only ever mean "rare in this
export".

**Where.** `src/mistify/scratchpad/anomaly.py`; decision G3 in `docs/v1-decisions.md`.

**Amend.** Architecture §4 — move persisted template trees out of "future improvements".

**Target phase.** 4/5, reclassified from "Future".

## 4 — No index for trace correlation

**Problem.** Structured fields are stored as a single `fields_json` TEXT column on
`log_events`, with indexes on `ts`, `template_id` and `severity` only. `trace_id` lives inside
that JSON blob and nothing indexes it.

**Why it matters.** The architecture names trace_id correlation as the skew-independent
fallback when clocks drift between sources — the answer to time-window slicing misaligning
causally-related events. Reaching a trace through `fields_json` means a full table scan with
`json_extract` over every event in the incident, on a corpus deliberately sized in gigabytes.
No query does this today, so nothing is slow yet; the cost lands the moment Phase 3 implements
the correlation, which is also the moment it is least convenient to discover.

**Recommended fix.** Add a generated column for `trace_id` extracted from `fields_json`, plus
an index on it, when the Phase 3 agent actually needs the correlation. Doing it earlier
commits schema to a field no code reads.

**Where.** `src/mistify/scratchpad/migrations/0001_init.sql`;
architecture §6 failure table, "Clock skew across sources".

**Target phase.** 3.

## 5 — Unimplemented adapters are dropped silently

**Problem.** `detect_format` intersects the configured `adapters.registered` list with the
implemented `ADAPTERS` map: `[n for n in registered if n in ADAPTERS]`. A configured name with
no implementation behind it — `elastic`, `loki` and `otlp` today — is filtered out with no
error, no warning and no metric.

**Why it matters.** It contradicts the design principle that every stage must be able to fail
loudly with a measurable signal rather than silently degrading. Someone who enables `elastic`
in `config.yaml` one commit before it is wired up gets a run that looks entirely healthy and
quietly used a different adapter, or none. The configuration and the behaviour disagree and
nothing in the report says so.

**Recommended fix.** Warn, or record a metric, naming the configured adapters that were
skipped for lack of an implementation. The report already turns metrics into explicit
warnings, so a single `record_metric` call puts it in front of the reader.

Deliberately deferred rather than overlooked: the gap is unreachable until Phase 4 registers
the first adapter that can be named but not built.

**Where.** `detect_format` in `src/mistify/adapters/registry.py`; `adapters.registered` in
`config.yaml`.

**Target phase.** 4.

## 6. Noise thresholds are defined in two places

**Problem.** `noise_template_ids`, `top_templates` and `get_slice` in
`src/mistify/scratchpad/db.py` each default `share_threshold`/`noise_share` to `0.15` and
`anomaly_ceiling`/`noise_ceiling` to `0.35`. The same two numbers are also
`anomaly.noise_share_threshold` and `anomaly.noise_anomaly_ceiling` in `config.yaml`, which
the config module documents as the single source of truth for pipeline behaviour. Four copies
of two numbers.

**Why it matters.** It is latent today only because no production caller passes
`exclude_noise=True` without naming both thresholds: the skeleton investigator and the report
both omit it, so only tests exercise the defaults. It stops being latent the moment the Phase 3
agent calls `get_slice(exclude_noise=True)` — which is exactly what noise suppression was built
for. The agent would then be handed a threshold `config.yaml` never set, and tuning the config
would silently change nothing.

**Recommended fix.** Make the thresholds required arguments at those three call sites and
delete the defaults, so the only way to suppress noise is to say what counts as noise. The
Phase 3 tool layer then threads `config.anomaly` through, the way every other tuned value
already reaches the code that uses it.

**Where.** `src/mistify/scratchpad/db.py`; `src/mistify/common/config.py` lines 121-122.

**Target phase.** 3, and before the agent loop rather than after — it is cheaper to thread
config through three signatures than to explain later why a documented setting had no effect.

**Note.** This was raised as its own candidate in the Phase 2 architecture review and did not
make it into this register at the time. Recorded now so it is not rediscovered a third time.
