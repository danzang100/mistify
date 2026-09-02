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
| 4. No index for trace correlation | ~~Medium~~ | **Fixed** |
| 5. Unimplemented adapters are dropped silently | Low | 4 |
| 6. Noise thresholds are defined in two places | ~~Medium~~ | **Fixed** |
| 7. The provider seam drops thinking blocks | ~~Medium~~ | **Fixed** — it was a hard requirement, not a cost |
| 8. The anomaly score has no duration term | Medium | 4 — worked around, not solved |
| 9. Conversation growth is bounded but not budgeted | Medium | 4 |
| 11. The quiet-hour bar cannot tell right from wrong | High | next |
| 10. The investigator under-cites what it reasons over | ~~Medium~~ | **Fixed** — the check moved earlier, not a better prompt |

---

## 8 — The anomaly score has no duration term

**Problem.** Severity, burstiness and rarity say nothing about how long a template was active.
A steady background error stream — 350 events spread evenly across the whole log — scores as
signal, ranks above templates confined to the outage, and is then held against the
investigation for not explaining it.

**Symptom, now fixed downstream.** `unexplained_signal_templates` faulted every run on the
sample incident for ignoring two chronic templates that were correctly ignored. A warning that
fires on every run is one a reader learns to skip, which costs more than the check is worth.

**What landed.** Chronic templates — active for at least `CHRONIC_SHARE` of the log's own span —
are excluded from the unexplained-signal warning and counted separately as an observation. The
report labels them, and an issue resting entirely on chronic templates is marked *background*.

**What has not.** The ranking itself is unchanged, so a chronic template still outranks an
acute one in the digest the investigator is handed first. Fixing that means a duration term in
the score and a re-run of the calibration tests, which is its own change.

**Where.** `ScratchpadDB.chronic_template_ids` defines it once; `mistify/scratchpad/anomaly.py`
is where the score would gain the term.

---

## 9 — Conversation growth is bounded but not budgeted

**Problem.** The loop re-sends the whole conversation on every step, so cost is quadratic in
steps. `pipeline.max_agent_tool_calls` caps calls, not context.

**What landed.** Three things, all measured rather than assumed: slices return 60 lines by
default instead of 200 and say how many they withheld; tool output older than
`pipeline.tool_result_history_steps` is reduced to the summary line the tool wrote; and
`investigate.input_growth_factor` warns when the last step's input is more than five times the
first's.

**What has not.** There is still no token ceiling. A run that grows anyway is reported, not
stopped. The mechanism to stop it already exists — `_converge` takes the tools away and demands
a conclusion — and wiring a `llm.max_run_tokens` into it is the remaining work.

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

## 4 — No index for trace correlation — FIXED

**Resolved.** Migration `0004_trace_id` promotes `trace_id` to a real column with an index and
backfills it from `fields_json`, so an existing scratchpad gains the capability without a
re-ingest. `get_slice` takes a `trace_id` filter and returns each line's trace id, which is
what makes the value discoverable before it can be followed. A record with no trace id stores
NULL rather than `""`: grouping on an empty string would invent one request out of every
untraced line in the file.

The prediction below was right about the timing and wrong about the reason. The cost never
landed, because no query was ever written — the field sat unread for three phases. What forced
it was reading a real run: the investigator had no way to follow one request across services,
and the field it needed was in the database the whole time.

The original write-up follows.

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

**Where.** `src/mistify/scratchpad/migrations/0004_trace_id.sql`;
architecture §6 failure table, "Clock skew across sources".

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

## 6. Noise thresholds are defined in two places — FIXED

**Resolved.** `NoiseThresholds` is now a single value built from config by
`AnomalyConfig.noise_thresholds()`, and the query layer has no defaults to fall back on.
`exclude_noise` went with them: passing thresholds *is* the request to suppress, so one
argument replaced two and half a rule can no longer be specified. The original write-up
follows.

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

## 7. The provider seam drops thinking blocks — FIXED

**Resolved, and it turned out to be more serious than recorded below.** On Anthropic — whose
adapter has since been removed — this was a token cost. On Gemini it is a hard requirement: replaying a `functionCall` part without its
`thought_signature` is rejected with `400 INVALID_ARGUMENT`, so the second turn of every
investigation failed. `ToolCall` now carries an opaque `signature` that adapters populate and
hand back verbatim. Opaque is the load-bearing word — nothing above the seam reads it, because
the moment it acquires a meaning it stops being a seam and becomes one vendor's data model
leaking upward.

Worth noting how it was found: it did not show up in review or in any test, because with one
adapter there was nothing to disagree with. The second adapter is what made the seam's gap
visible on its first real run. That is the argument for two adapters, demonstrated — and worth
remembering now that the codebase is back down to one.

The original write-up follows.


**Problem.** `Turn` in `src/mistify/llm/base.py` carries text, tool calls, a stop reason and
usage — but not the model's reasoning blocks. `AnthropicProvider` therefore discards them, and
the loop never sends them back.

**Why it matters.** On a provider that returns reasoning, replaying it unchanged on the next
turn is how the model keeps its own train of thought across a tool-using loop. Dropping it
means the model re-derives its reasoning at every step of an investigation that may run twenty
tool calls, which costs output tokens and can cost coherence. It is invisible in a two-step
test and expensive in a real run.

**Recommended fix.** Add an opaque `reasoning` field to `Turn` and `Message` that adapters
populate and echo back verbatim, without the loop ever inspecting it. Opaque is the important
part: the seam must not acquire a vendor's notion of what a thinking block contains, or it
stops being a seam. Providers with nothing to put there leave it empty.

**Where.** `src/mistify/llm/base.py` (the fix), `src/mistify/llm/anthropic.py` (populate and
replay).

**Target phase.** 3 if the loop turns out to wander across steps; otherwise 5, where the eval
harness will measure the token cost directly and say whether it is worth the seam widening.

**Note.** Found while building the Anthropic adapter, not by the review. The seam is mine and
this is a gap in it — recorded rather than absorbed, because a silently costlier loop is
exactly the kind of thing that gets attributed to the model later.

---

## 10 — The investigator under-cites what it reasons over

**Problem.** Across nine runs of the sample incident the loop cited templates 8 and 9 every
time and template 7 never — while three of those runs named template 7 in the finding's prose
as the precursor. It cites what the claim is chiefly about and omits the context it reasons
over.

**Why it matters.** Two consequences, and the second is worse. `unexplained_signal_templates`
tests citation, so a template discussed in a note is still reported as unaccounted for: the
warning is correct by its own definition and misleading to a reader. And a claim whose
supporting context cannot be followed back to rows is the exact failure the citation discipline
exists to prevent — the report says "preceded by slow connection acquisitions" and offers no
way to check it.

**Fixed, and not by the prompt.** Asking for it in the system prompt changed nothing: the run
after that change cited 8 and 9 and did not mention template 7 at all. Ten runs, zero hits. The
prompt fix also could not have worked in the six runs where the model never named the template
— there was nothing for "cite what you name" to bite on.

What worked was moving a check that already existed. `unexplained_signal_templates` is
model-free and ran in the adversarial pass, after the investigation had ended, where it could
only report. It now runs in the loop: when the model stops calling tools, an acute signal
template with no citation sends one more turn asking it to cite the template or say why it is
not relevant. Bounded by `pipeline`-level `coverage_nudges` so a model that keeps declining
cannot spin the loop, and chronic templates are excluded on the same grounds as issue 8.

First run with it: templates 7, 8 and 9 cited across two notes, `unexplained_signal` 0, no
warnings — against 0/10 before. One run, and one positive against a stable zero baseline is
strong but not conclusive; the confirmation runs are still owed.

**Note on the diagnosis.** "Cite what you name" was aimed at the 3-in-9 case where prose and
citations disagreed. That was the visible symptom, not the problem. The problem was that
nothing asked the model about coverage while it could still act.

**Note on how this was found.** It was nearly missed, and then twice reported as something it
was not. The metric counted citations while the comparison being made counted prose mentions,
which invented first a regression and then a mechanism for it. Scoring the two separately is
now part of the repeat protocol in `docs/baseline.md`.

---

## 11 — The quiet-hour bar cannot tell right from wrong

**Problem.** The negative control scores `invents-no-incident` as "no note recorded at high
confidence". Measured over three runs it scored 0/3, and one of those three had written the
correct answer: that the hour contains only routine operational warnings and no failure. The
check fails a confident *correct* finding for exactly the same reason it fails a confident
wrong one.

**Why it matters more than a wrong number.** This is the case the whole fixture exists for, and
it currently cannot distinguish the behaviour we want from the behaviour we are guarding
against. A check that fails both is worse than no check, because its output looks like evidence.

**Fix.** A judge question, not a threshold: *does this finding assert that something is wrong?*
One call, one boolean, and unlike the entailment judge it is asking about the claim rather than
about its citations. Deterministic checks on this case stay as secondary signals.

**Note.** The bar was chosen deliberately over "zero notes", on my framing that a
high-confidence note meant an invented incident. The framing was wrong and the data showed it
on the first sweep. Recorded because the same mistake -- picking a proxy before seeing what the
behaviour actually looks like -- produced two wrong conclusions in `docs/baseline.md` earlier.
