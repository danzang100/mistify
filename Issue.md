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
| 13. `parse_timestamp` cannot read common log format | Low | 5 |
| 12. Model requests had no timeout | ~~High~~ | **Fixed** |
| 11. The quiet-hour bar cannot tell right from wrong | High | next — vacuity gated, judge question outstanding |
| 10. The investigator under-cites what it reasons over | ~~Medium~~ | **Fixed** — the check moved earlier, not a better prompt |
| 14. Burstiness and rarity are degenerate on ordinal timestamps | Medium | next |
| 15. The accounting role is decided by citations alone | Medium | next |
| 16. Templating is the ingest bottleneck and its share grows | High | next — scale |
| 17. Threshold calibration adds almost nothing over a constant | High | 5 — scorecard |

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

**Wider than filed, and half fixed.** The same defect runs through the positive cases:
`avoids[...]` is a substring search over the conclusion, so an empty conclusion passes every one
of them. It passed 81 times out of 81 across a day of runs and never failed. `jest-nextjs`
scored 5 of 12 having written no notes at all, and three runs killed by a provider outage
*before their first tool call* scored 5 of 13.

**What landed.** `Check.scorable`. A run with no conclusion has `avoids[...]`,
`citations-resolve` and `does-not-lead-with[...]` recorded as unscorable rather than passed,
with a new `concludes-something` check as the gate; totals, per-check rates and the CLI count
only what could be asked. Re-scored over every recorded run: the three outage runs go from
15/42 to 0/27, the recorded `jest-nextjs` from 5/13 to 0/8, and **every run that actually
concluded is unchanged**, which is the control.

**Still open: the quiet hour itself.** A judge question, not a threshold: *does this finding
assert that something is wrong?* One call, one boolean, and unlike the entailment judge it asks
about the claim rather than about its citations. `judge.py` already has the machinery; this is a
second prompt and a second entry point. Deterministic checks stay as secondary signals.

**Note.** The bar was chosen deliberately over "zero notes", on my framing that a
high-confidence note meant an invented incident. The framing was wrong and the data showed it
on the first sweep. Recorded because the same mistake -- picking a proxy before seeing what the
behaviour actually looks like -- produced two wrong conclusions in `docs/baseline.md` earlier.

---

## 12 — Model requests had no timeout — FIXED

**Problem.** The Gemini adapter set no request timeout, so a request the server never answered
blocked forever. Found the expensive way: an OTLP eval run sat alive for over thirty minutes
having burned 0.016 seconds of CPU, its investigation already complete -- 17 steps, 15 tool
calls, 2 notes, `converged` -- and no adversarial metrics recorded at all. It was blocked in a
single call in the adversarial pass.

**Why it hid.** `_is_retryable` already treats `DEADLINE_EXCEEDED` and 504 as worth another
attempt. That path was correct and simply unreachable: without a client-side ceiling the SDK
never produces the error the retry was waiting for. A recovery mechanism that cannot be reached
is indistinguishable from one that does not exist, and the tests for it passed throughout.

**What was not the cause.** The first hypothesis was the critique model, `gemini-3.6-flash`,
which had been switched on two turns earlier and never exercised live. Tested directly it
answers in 10.6 seconds. `gemini-3.5-flash` -- the judge model -- returned 504 after 30 seconds
in the same test, so slowness is real on some models, but the hang was the missing ceiling
rather than any particular model.

**Fix.** `llm.request_timeout_seconds`, default 120, set on the client so every request is
bounded including ones added later. The conversion to the SDK's milliseconds is its own tested
function: the wrong factor gives a 120-millisecond timeout that fails everything or a
120,000-second one that fails nothing, and neither is visible by reading the call site.

---

## 13 — `parse_timestamp` cannot read common log format

**Problem.** `30/Aug/2026:14:22:01 +0000` — the Apache/nginx access-log timestamp — raises
`ValueError`. The bootstrapper recognises the shape, so a CLF file infers a schema that matches
every line and then produces zero records.

**Currently contained, not fixed.** The match-rate gate now checks that the timestamp it
extracts actually parses, so a CLF file fails the gate and falls to raw-line mode: readable,
labelled, and honest. Before that check the same file validated at 100% and ingested nothing,
silently — the exact failure the gate exists to prevent, and it was the gate that was letting it
through.

**Fix.** Teach `parse_timestamp` the CLF shape. It is a self-contained addition to one function
with an existing test module; the reason it is not done here is that it belongs to the shared
timestamp parser rather than to the bootstrapper, and widening a shared parser deserves its own
change.

**Where.** `mistify/common/models.py::parse_timestamp`, and the `clf` entry in
`mistify/bootstrap/schema.py::TIMESTAMP_PATTERNS` documents the situation.

---

## 14 — Burstiness and rarity are degenerate on ordinal timestamps

**Problem.** A file read as `raw_lines` has no timestamps; the adapter supplies line ordinals so
the schema and every ordering query have something to work with. Burstiness is then measured
over one-minute buckets of *line numbers*, and its formula saturates for anything rare:
`max_per_bucket / (count / total_buckets)` gives a template with one occurrence a burstiness of
`1 - 1/total_buckets` regardless of what it is. Rarity is near-constant for the same reason —
9,307 templates for 10,992 events means almost every template has a count of one. Two of the
three terms carry no information, and until Phase 5 the third carried none either, which is how
the digest came to be ordered by first appearance.

**What landed.** Severity is now recovered from the template text when the source has no
severity field, which lifted ground-truth markers inside the top 40 from 1 of 65 to 39 of 65
across 20 LogDx-CI cases (`docs/digest-rerank.md`). **Burstiness then lost its worst case**: a
template with one occurrence scored `1 - 1/total_buckets`, the maximum, because the mean it
divides by is `1/total_buckets`. Singletons now score zero there, which moved markers into the
top five from 14 of 65 to 19 and cleared the section banners out of the set the coverage nudge
enforces. Rarity is untouched.

**Measured, and deliberately not taken.** Zeroing burstiness and rarity as well scores best of
six weightings — 31 of 47 markers on unseen cases against the shipped 27 — but the corpus that
says so is entirely ordinal-timestamped. An unlabelled log *with* real timestamps is the case
that would be damaged, and nothing here measures it.

**Fix.** Detect the condition rather than the corpus: the pipeline already counts
`unparseable_timestamp` per line, so a file whose timestamps are synthetic could drop
burstiness the same way an unlabelled file drops severity — one rule, one metric, the same
redistribution. Rarity needs its own answer; inverse log frequency against the most common
template says nothing when the mode is one, which is the remaining half of the flat-tie problem
now that singleton burstiness is gone.

**Related, and now fixed at the source.** The flat tie had a second cause outside the scorer:
GitHub Actions stamps an ISO instant on the front of every line, and Drain3 kept it, so almost
every line was its own template. Masking it as transport rather than content took the twenty
LogDx-CI cases from **43,589 templates to 7,795** — hibernate from 22,071 to 453 — with Loghub
grouping accuracy unchanged to the digit. Rarity is still degenerate, but on a far smaller
population.

**Where.** `mistify/scratchpad/anomaly.py::_burstiness_component` and `_rarity_component`;
`severity_source` is the shape the decision should take. Related: Issue 2 (scores are global)
and Issue 8 (no duration term), both of which also live in the same function.

## 15 — The accounting role is decided by citations alone

**Problem.** `ToolBox._write_note` tags a note `accounting` when its cited templates fall
entirely inside the set a coverage nudge named. That is the only structural signal available:
timing cannot work, because the nudge fires once a conclusion has been offered, so every note
after it is post-nudge and a run that answers the nudge and *then* finds something real would
have the real finding demoted.

The rule is exact when it fires and silent when it does not. Measured on three runs:

| run | nudged | note answering it | tagged |
|---|---|---|---|
| sample incident | `{7}` | cites 7 and 9 — establishes the precursor | `finding`, correctly |
| quiet-hour | `{1,3,4}` | dismisses 1, 3, 4 and re-cites 5, 6 from its own earlier note | `finding`, **arguably wrong** |
| customer-log slice | `{4,14,35,45,47}` | dismisses exactly those | `accounting`, correctly |

The middle row is the gap. The note is a dismissal, but it re-states the two templates its own
previous note rested on, so it leaves the nudged set and reads as a finding. The system prompt
actively causes this: *"Cite every template your note names, not only the one the claim is
chiefly about"*, because a template discussed in prose but missing from citations is reported as
unaccounted for. So the two rules pull against each other and this will recur.

**Why it is not fixed now.** The obvious widening — accounting when the note introduces nothing
outside *nudged ∪ already-cited* — was checked against the same three runs and mis-tags the
sample incident's second note, which cites one nudged template plus one the run had already
cited and is a genuine finding about the precursor. Strict has a false negative, wide has a
false positive, and at n=3 there is nothing to choose between them. Trading one error for the
other without measuring is the mistake this project has already made once with the ranking keys.

**Recommended fix.** Gather cases first. `investigate.nudged_templates` now records what each
nudge asked about, so any run from here on is re-scorable against a candidate rule without
being re-run. Revisit once a handful of runs on logs with degenerate rankings exist — that is
the only shape where the tag does any work, since a fixture whose ranking works has the nudge
naming the real cause.

**Target phase.** Next, alongside the plausible-but-wrong set, whose seeded conclusions can
produce both shapes deliberately rather than waiting for a model to produce them by chance.

## 16 — Templating is the ingest bottleneck, and its share grows with scale

**Problem.** Ingest throughput decays badly: 7,444 lines/s at 500k lines, 4,347 at 2M, and
about 2,100 by 7.5M on the same corpus. Measured with the database removed entirely, Drain3
alone accounts for it:

| lines | end-to-end lines/s | templating alone | templating share | µs/line | clusters |
|---|---|---|---|---|---|
| 500,000 | 7,444 | 11,615 | 64% | 86.1 | 1,488 |
| 2,000,000 | 4,347 | 5,553 | **78%** | 180.1 | 2,208 |

Templating decays **2.09×** where the whole pipeline decays 1.71×, so it is not merely the
largest component — it is the one getting worse, and every other optimisation is working on a
shrinking share. Note also that per-line cost more than doubled while the cluster count grew
only 1.48×, so the cost is not simply proportional to clusters.

**What it is not.** The obvious suspect was SQLite's page cache: 2 MB is 125 pages at this
project's 16 KB page size, against four B-trees on a table growing into the gigabytes. Measured
at 2, 64 and 256 MB:

| lines | 2 MB | 64 MB | 256 MB |
|---|---|---|---|
| 500,000 | 7,444 | 7,059 | 7,510 |
| 2,000,000 | 4,347 | 4,294 | 4,350 |

Within noise, and the gap does not widen with scale — which it must if cache were the
constraint. A 128× increase buys nothing. The knob was removed rather than shipped; the numbers
are in a comment at the PRAGMA site so the next person with this very reasonable idea does not
spend the time again.

**Candidate fixes, with what is already measured about each.**

*   **Memoise the masked message — measured and rejected.** 36.0% of 500k and 38.1% of 2M
    masked messages are exact repeats, so a cache from masked message to template id looked
    like ~38% off templating for nothing. It is not exact, it is not fast, and it is not cheap:

    *   **It changes the answer on 6.46% of lines.** A prototype's template assignments were
        compared line for line against an uncached run over 200,000 lines and differed on
        12,913 of them.
    *   **Only a twentieth of that is Drain3's own instability.** Clustered with no cache at
        all, 250 of 66,849 distinct masked messages (0.37%) are assigned more than one cluster
        id over a run, covering 644 lines (0.32%). The other 6.1% is caused *by* the cache:
        withholding a repeat from `add_log_message` changes how the tree evolves, so later
        and entirely different messages cluster differently. The optimisation is not
        transparent, it participates in the result.
    *   **The speedup is 1.08x, not 1.38x.** At 2M lines with the per-template statistics still
        maintained, 322.4s became 298.8s. The hit rate is an upper bound on calls skipped, not
        on time saved: hashing a 150-byte string and probing a dict is paid on every line,
        including the 62% that miss.
    *   **The cache costs 96 MB at 500k lines and 377 MB at 2M**, one entry per distinct
        message, extrapolating to roughly 3 GB at 16.6M. Against a 2.5 GB corpus that is worse
        than the storage this project has spent days shaving.

    Recorded rather than deleted because the reasoning that "an identical message must yield an
    identical template" is wrong in a way nobody would expect, and the next person will have
    the same idea.
*   **Fewer clusters.** Already banked: header masking took Thunderbird from 2,001 templates to
    1,485 and cut clustering time ~20% at 100k. More of the same helps directly.
*   **Drain tree depth.** A 4→12 sweep was measured once on BGL at 601→671 lines/s and shelved
    as marginal. That was a different regime -- a corpus with 320 templates, not thousands --
    and depth is what bounds how many clusters share a leaf, which is the cost that is growing.
    Worth re-measuring here before anything more elaborate.
*   **Parallel templating** is not on this list. Two-phase learn-then-match was measured and
    rejected: a tree learned on 100k BGL lines matched only 57.5% of the next 200k, so 42% of
    lines would go untemplated.

**The depth sweep is done, and the answer is that depth 4 already wins.** Swept on 500k
Thunderbird lines and scored against Loghub-2k's annotation, which is the only thing that can
say whether a faster setting is still clustering correctly:

| depth | mean grouping accuracy | Thunderbird lines/s | Thunderbird clusters |
|---|---|---|---|
| **4** | **0.910** | 11,918 | 1,488 |
| 8 | 0.859 | 12,427 | 1,488 |
| 12 | 0.885 | 98,464 | 769 |
| 16 | 0.885 | 97,867 | 804 |

Depth 12 is 8.26x faster and must not be taken. Every deeper setting clusters worse than 4, and
the direction check says why the speed is not real: on Loghub, deeper produces *more* templates
(OpenSSH 23 -> 36) exactly as a more specific tree should, while on Thunderbird depth 12
produced *half*. A setting that inverts the expected direction on one corpus and loses accuracy
on another is a pathology, not a win.

**The remaining costs outside Drain3 are about 2% combined**, measured rather than assumed, and
neither is recommended:

*   `LogRecord.isoformat()` is computed twice per event -- once in `pipeline.ingest` for the
    templater's `ts`, once again in `bulk_insert_events`. 2.31 us a call, so 4.6s of pure waste
    on a 2M ingest, 1.0%. Removing it means either a third element in the batch tuple (nine
    test call sites) or a cache on `LogRecord` that `dataclasses.replace` could later carry
    stale. Both are more risk than 1% buys.
*   `mask_header_timestamps` tries all four timestamp shapes per line where `raw_lines` has
    already adopted exactly one and recorded it as `ingest.timestamp_shape`. One pattern
    instead of four is 3.05 us -> 1.17 us a line, 3.7s on a 2M ingest, 0.8%. It needs the
    adopted shape threaded from the adapter through the pipeline into the templater.

Both are recorded rather than done because templating costs **180 us a line** and these are one
and two. The bottleneck is inside Drain3's own `add_log_message`, which is pure Python, and the
cheap levers around it are now exhausted: fewer clusters is banked (header masking, 2,001 ->
1,485), memoisation is rejected, depth is already optimal, and parallelism is ruled out by the
incremental tree. What is left is a faster templater, which is a different project.

**Root cause found, and it is not that Drain3 is slow.** Templating on Thunderbird is far
more expensive than on a real 569 MB customer log at the same event count and a similar cluster
count. Measured structurally, which needs no clock:

| | Thunderbird | customer log |
|---|---|---|
| clusters | 786 | 654 |
| leaves | **32** | **279** |
| clusters per leaf, mean | 24.6 | 2.3 |
| clusters per leaf, p95 | 102 | 9 |
| clusters scanned by the average line | **89.7** | **7.4** |
| five fattest leaves | 68% of all clusters | 17% |

The average Thunderbird line scans **12.1x more clusters** at its leaf. Drain routes on token
count first and the first token second, and Thunderbird has no diversity in either:

| | distinct first tokens | distinct token counts |
|---|---|---|
| Thunderbird | **1** (`-`, on 100% of lines) | 28 |
| customer log | 145 (`<TS>` on 97%) | 174 |

786 clusters squeeze into 32 leaves. The customer log's first token is near-constant too, so
its advantage is line-length diversity rather than prefix diversity -- 174 token counts against
28. This is a degenerate routing case on one corpus, not a templater that is too slow.

**Consequence for the plan.** The decision rule fixed before measuring was: a templating gap
driven by fat leaves means an in-place fix, not a rewrite. It is fat leaves. **No rewrite, and
no compiled inner loop.**

**Candidate fix, deliberately not implemented yet.** Tree depth controls how many tokens
participate in routing, and depth 12 gave 8.26x on Thunderbird -- consistent with splitting the
fat leaves -- while costing grouping accuracy on Loghub. One global constant cannot serve both,
which is exactly the problem `sim_th` calibration already solves by choosing per file from a
sample with an over-merge guard. Extending that calibration to depth reuses the machinery.

Blocked on one unexplained result: depth 12 produced **fewer** clusters on Thunderbird, 769
against 1,488, where deeper routing should produce more. Until that inverts back or is
explained, this would be building on a result nobody understands.

**Wall-clock on this machine cannot support a stage attribution.** The Thunderbird pass reported
templating at 868.0s inside a full ingest of 459.4s -- a negative remainder, so the pass
contradicts itself. Five anomalous readings in one day, including the same parse measuring 41.9s
and 18.2s. Cause identified rather than guessed: the working tree is inside OneDrive, and
`OneDrive.Sync.Service.exe`, `MsMpEng.exe` and `SearchIndexer.exe` all watch the directory the
ingest writes its multi-gigabyte scratchpads into. Anything timing-based here needs the corpora
and scratchpads moved to a path none of those three watch, and repeats reported as a minimum
rather than a single pass. Every structural finding above is a deterministic count and needs
none of that.

The customer log's own pass was at least internally consistent -- parse 7%, redact 24%,
template 16%, rest 53% -- and is recorded as an indication rather than a measurement.

**Why depth 12 produced fewer clusters — answered, and it is not the child cap.** The
suspicion was Drain's `max_children` limit of 100 funnelling excess tokens into a shared `<*>`
child. Measured: **zero** nodes at the cap on either corpus. The mechanism is
`parametrize_numeric_tokens`, which turns any digit-bearing token into `<*>` for routing. Deeper
routing uses more token positions, so numeric-heavy lines funnel down shared wildcard paths and
merge at the leaf. Thunderbird lines are dense with numbers, which is why it inverts there and
why Loghub grouping accuracy falls for the same reason.

| | clusters | leaves | scanned/line | `<*>` edges | at 100-child cap |
|---|---|---|---|---|---|
| Thunderbird depth 4 | 786 | 32 | 89.7 | 0 | 0 |
| Thunderbird depth 12 | 756 | 644 | **7.5** | 231 | 0 |
| customer depth 4 | 654 | 279 | 7.4 | 8 | 1 |
| customer depth 12 | 1,257 | 1,099 | 2.6 | 676 | 1 |

Depth 12 takes Thunderbird's scan from 89.7 to 7.5, matching the customer log. That is the 8.26x.
The inversion is also much smaller at 300k lines (786 to 756, -4%) than at 500k (1,488 to 769,
-48%), so it grows with data and is not a fixed property.

**Stripping a constant leading prefix was tried and is a regression.** Thunderbird's first token
is `-` on 100% of lines, so the obvious idea is to drop leading tokens that carry no routing
information, the way the timestamp shape is already dropped. Measured on 300k lines, dropping
the 3 leading positions that are constant across 95% of a sample:

| | clusters | leaves | scanned/line |
|---|---|---|---|
| Thunderbird, as shipped | 786 | 32 | 89.7 |
| Thunderbird, strip 3 | **1,547** | 32 | **303.1** |
| customer, as shipped | 654 | 279 | 7.4 |
| customer, strip 3 | 694 | 250 | 11.7 |

Worse on both. **Leaves stayed at 32**, which is the number that explains it: the constant prefix
was never gating leaf count. Leaf count comes from token-count diversity — 28 distinct counts on
Thunderbird against 174 on the customer log — and removing the same three tokens from every line
shifts every count equally and adds no diversity at all.

Clusters then doubled because Drain's similarity is matching positions over total positions.
Always-matching constant tokens pad that ratio: a line with two differences goes from 11/13 =
0.85 to 8/10 = 0.80 once three constants are removed, dropping under `sim_th` more often and
splitting. **A constant prefix helps clustering, and no special handling is wanted.**

**The timing instability is not attributable to OneDrive on the evidence available.** Parse-only
repeated five times, 300k records, inside the synced tree and outside it: spread 1.29x against
1.07x, with the plain path's minimum actually higher. No meaningful difference. That test only
exercises reads for two seconds, where the anomalies were on multi-minute runs writing gigabytes,
so the write-path hypothesis is untested rather than refuted.

The useful part is that short repeats are stable at all — 1.07x to 1.29x — where single long
passes swung two- to fourfold. That points at a time-correlated perturbation rather than a
location-correlated one, and it makes the mitigation the same either way: **measure in short
repeats and report the minimum**, never a single long pass. Minimum is the right estimator
because transient load can only add time.

**Superseded recommendation.** The depth sweep, now that memoisation is out: it is the one remaining
candidate that does not change what the templater produces, so it stays checkable against the
existing Loghub grouping-accuracy and LogDx digest-recall numbers. Header masking has already
taken Thunderbird from 2,001 templates to 1,485, and anything further that lowers cluster count
lowers matching cost directly.

**A separate finding, worth its own look.** 0.37% of distinct messages are assigned more than
one cluster over a run with no cache involved. That fragments a template's statistics across
two ids — the same condition counted twice, with two anomaly scores — and it is a property of
the templater rather than of anything downstream. Small, but it is the sort of thing that makes
a count in a report quietly wrong.

**Target phase.** Next, ahead of any further storage work: at 2M lines the whole storage layer
is 22% of ingest and falling, and the safe storage wins left are worth about 3%.

## 17 — Grouping accuracy is 0.745, and threshold selection is near its ceiling

**What was measured.** Grouping accuracy across all fifteen Loghub-2k systems, not the four the
handoff reports:

| | mean grouping accuracy |
|---|---|
| calibrated, as the pipeline ships | **0.745** |
| fixed `sim_th=0.4` | 0.740 |
| best threshold per system, chosen with the answer key | 0.842 |

The handoff's **0.910 is optimistic**: Apache, BGL, Hadoop and OpenSSH were picked as a spread
of log families and turn out to be the favourable ones. Proxifier scores 0.025, OpenStack 0.309,
Windows 0.571, HealthApp 0.576. **0.745 is the honest scorecard figure.**

**The 0.097 gap is not recoverable, and the first version of this issue was wrong to claim it
was.** Seven selection rules were built and scored against a grid of every system at every
threshold. Each rule sees only what the pipeline sees at run time -- template count, compression
ratio, over-merge risk -- and never the accuracy it is scored on:

| rule | mean GA | vs shipped |
|---|---|---|
| plateau end | 0.755 | +0.010 |
| **current: fewest templates among safe** | **0.745** | — |
| fixed 0.4 | 0.740 | -0.005 |
| fixed 0.6 | 0.697 | -0.048 |
| knee of the count curve | 0.684 | -0.061 |
| strictest safe threshold | 0.473 | -0.273 |

`strictest safe` is what the previous version of this issue recommended -- "the loosest threshold
that does not merge distinct conditions". It is the **worst** of the seven, 0.273 below what
ships, taking HDFS to 0.00 and Spark to 0.08.

**Why no rule can close it.** The best threshold per system does not follow from anything
visible at run time:

    0.2  Apache, HDFS, Spark, Hadoop, HealthApp
    0.3  Thunderbird
    0.4  BGL, Linux
    0.6  OpenSSH, HPC, Mac, OpenStack, Zookeeper
    0.7  Windows, Proxifier

Template counts sit on a plateau and then cliff -- HDFS is `[17, 17, 17, 17, 406, 700, 1185]`
across 0.2 to 0.8 -- and the best threshold is sometimes mid-plateau and sometimes at its edge.
No monotone function of count, ratio or wildcard density separates those two groups. The 0.842
is only visible because the annotation is in hand, and the pipeline never has it.

So the shipped rule is within 0.010 of the best rule that could be constructed over the
available signals. **This is a ceiling, not a defect**, and the value of the measurement is that
it stops someone spending days on "better calibration" believing a tenth of accuracy is sitting
there.

**The one angle left untested.** Calibration runs before records carry severity, so its
over-merge guard uses wildcard density as a structural stand-in. The real severity-span check,
`find_over_merged`, only works post-load. A calibrate, load, check, re-cluster loop could use it
-- at the price of a second templating pass, on the stage already measured at 78% of ingest.
Worth pricing before attempting, and worth nothing at all unless severity is informative, which
on a raw-lines read it frequently is not: Thunderbird reports 99.6% unmapped severity.

**Target phase.** 5, as a scorecard row that reports 0.745 with the per-system table beside it.
Proxifier at 0.025 and OpenStack at 0.309 are worth naming individually: a mean hides that two
log families are essentially not clustered at all.
