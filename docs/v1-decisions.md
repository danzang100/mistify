# v1 design decisions

Resolutions to the eight open questions raised in the
[v1 build plan](log-agent-v1-build-plan.html). Where a decision contradicts the original
architecture, scaffolding or testing document, **this file wins** and the affected section is
noted so the design docs can be amended.

Settled 2026-08-31, before Phase 0.

---

## G1 — Redaction moves ahead of templating

**Was:** architecture §2.3a placed redaction after Drain3 templating, while asserting it ran
"before anything ... reaches an LLM". §2.2a sends raw sample lines to a model before
templating happens at all, so the assertion was false on the unknown-format path.

**Now:** redaction runs immediately after adapter `parse()`. The pipeline order is
`parse → redact → template → scratchpad`. Redaction is the first stage to touch a
`LogRecord`, and it covers `raw`, `message` and every string inside `fields`.

**Where:** `mistify/pipeline.py`. Regression tests in `tests/test_pipeline.py`
(`test_no_planted_secret_reaches_the_scratchpad`).

**Amend:** architecture §2.2a, §2.3, §2.3a; scaffolding §6.

## G2 — Drain3 snapshot can no longer hold secrets

**Was:** the tree was trained on unredacted text and persisted to disk, making
`drain3_state.json` a durable artifact full of PII and credentials.

**Now:** closed by G1 — the templater only ever sees redacted text. Two supporting changes:

- The templater masks the `[TYPE:hash]` placeholder shape, so a redacted value contributes
  one stable token instead of fragmenting a template into one cluster per source value.
- `read_snapshot()` decodes Drain3's base64/zlib state. Any leak check must go through it;
  scanning the raw file matches nothing and passes regardless of contents.

**Where:** `mistify/templating/drain_wrapper.py`. Tests in `tests/test_templating.py`,
including a control test proving the leak check can actually fail.

## G3 — `anomaly_score` is a v1 requirement, not a future improvement

**Was:** listed under future improvements, yet referenced by the `templates` schema, the
`query_templates` ordering enum, and step 3 of the adversarial check.

**Now:** the column ships in `0001_init.sql` and `top_templates(order_by="anomaly_score")`
works. Scoring shipped in Phase 2 as a deterministic post-load pass over the scratchpad. No
model call, no baseline corpus — the score comes from the incident's own distribution, so it
works on the first file from a service nobody has ingested before. Cross-incident novelty
still waits for reusable template trees.

**Correction:** this document previously recorded the score as
`rarity × severity_weight × burstiness`. That was wrong and the implementation deliberately
differs. It is a **weighted sum** — severity 0.5, burstiness 0.3, rarity 0.2, normalised.
A product zeroes the entire score whenever any single component is zero, and the most frequent
template in any incident has rarity exactly 0 by construction. Under a product the loudest
template in the file would score zero no matter how severe it was.

The three components:

- **severity** — a non-linear weight per level, TRACE `0.0` through FATAL `1.0`. The step from
  WARN to ERROR should count for more than the step from TRACE to DEBUG.
- **burstiness** — max events in any one-minute bucket against the mean over the *whole
  incident span*, mapped through `1 - 1/ratio` so extreme peaks saturate instead of running
  away. The denominator is the subtlety found during implementation: measuring against the
  buckets a template itself occupies is wrong, because a template firing 40 times inside one
  minute occupies that single bucket uniformly and scores as perfectly even — exactly
  inverting the signal the component exists to capture.
- **rarity** — inverse log frequency, scaled against the most common template in the incident.

The weights are config-driven (`anomaly:` in `config.yaml`) rather than constants, so the
Phase 5 evaluation harness can sweep them instead of requiring a code change per experiment.
Components are retained alongside the score, not collapsed into it, so a report or the
adversarial pass can say *why* a template ranked where it did rather than quoting an
unexplained number.

**Where:** `mistify/scratchpad/anomaly.py`. Tests in `tests/test_anomaly.py`.

**Amend:** architecture §4 — move anomaly scoring out of "future".

## G4 — Read-only SQL is enforced by SQLite, not a keyword blocklist

**Was:** `run_readonly_sql()` was to reject `INSERT/UPDATE/DELETE/DROP/ATTACH` by inspecting
the query text. The input is a model-authored string and the testing doc correctly calls this
a security boundary; a blocklist loses to comments, string literals and CTEs.

**Now:** three layers, none of them text inspection:

1. A separate connection opened `file:...?mode=ro` — not writable at the OS level.
2. `PRAGMA query_only=ON`.
3. `set_authorizer()` allowing only `SQLITE_SELECT`, `SQLITE_READ` and `SQLITE_FUNCTION`,
   which is what denies `ATTACH`, `PRAGMA` and extension loading.

**Where:** `mistify/scratchpad/db.py`. Tests in `tests/test_scratchpad.py` include an
evasion suite (comment-prefixed deletes, CTE-wrapped mutations, `ATTACH`, `load_extension`).

**Amend:** scaffolding §7.

## G5 — Credit card detection is out of scope for v1

**Was:** `"credit_card": r"\b(?:\d[ -]*?){13,16}\b"`, enabled by default in strict mode.

**Now:** removed from the pattern library entirely. That expression matches any 13–16 digit
run — epoch-millisecond timestamps, request IDs, trace IDs — which destroys the correlation
keys an investigation depends on. If it returns it needs a Luhn checksum and a
false-positive corpus first.

A related fix shipped alongside: `1.2.3.4` is a valid address shape, so version strings were
being redacted as IPs. Handled with a context guard (`CONTEXT_GUARDS` in
`redaction/patterns.py`) rather than by loosening the address pattern.

**Phase 2 addition:** `phone` is implemented but **off by default**, for the same reason as
credit_card one step milder. The canonical `NNN-NNN-NNNN` shape is structurally identical to a
numeric identifier or a range, and unlike a card number it carries no checksum to
disambiguate. Tightening it to require a `+` country code or a parenthesised area code would
miss the most common written form, so it is available and opt-in rather than silently
destroying identifiers in every deployment that never logs a phone number. Default entities
are now `api_key`, `email`, `ipv6`, `ipv4`, `ssn`.

`ipv6` was written to require either a full eight-group form or a `::`. That requirement is
what keeps clock times out: `14:22:01` has colons but neither eight groups nor a double colon,
and a timestamp swallowed by the address pattern would misalign every time slice downstream.

**Amend:** scaffolding §6; architecture §2.3a entity list.

## G6 — Ingestion is where an incident comes into existence

**Was:** `investigate` and `report` were keyed on `--incident-id`, but `ingest` took only
`--source` and no table recorded an incident.

**Now:** `ingest` accepts `--incident-id`, defaulting to a date-and-slug derived from the
source filename. An `incidents` table records id, creation time, source, detected format and
redaction mode.

**Amend:** scaffolding §7 schema, §10 CLI.

## G7 — Per-stage health metrics have somewhere to live

**Was:** architecture §6 states that a health metric per stage "is not optional polish", but
the four-table schema had no column for compression ratio, parse errors or the budget-limited
flag. Nothing could be asserted in a test or declared in a report.

**Now:** a `run_metadata(stage, metric, value, value_num, ts)` table. Every stage writes its
numbers; the report renders them as a health block and turns threshold breaches into explicit
warnings (poor compression, skipped lines, disabled redaction, orphaned events).

**Amend:** scaffolding §7 schema.

## G8 — Citation faithfulness splits into a unit test and an eval

**Was:** classified as a unit test — "diff the claim text against what those rows contain".
Checking whether a natural-language claim is *entailed* by log rows is not a text diff, and
written as one it would pass everything.

**Now:** two separate checks.

- **Deterministic (unit, shipped):** `verify_citations()` resolves every cited
  `log_event.id` and `template_id` back to real rows and warns on any that do not exist.
  Fabricated citations surface in the report.
- **Semantic (eval, Phase 5):** an entailment judge on a labelled fixture set, using a model
  distinct from both the loop and the adversarial pass.

**Amend:** testing strategy §1 matrix (report row becomes unit **+** eval), §2.5.

---

## Other decisions taken at the same time

| Decision | Resolution |
|---|---|
| Package name | `mistify` throughout — distribution, package and CLI. The scaffolding doc's `log-agent/` is superseded. |
| Chunking config | `chunk_window_minutes` and `chunk_overlap_minutes` dropped. No pipeline stage consumed them; the investigator slices on demand via `get_slice`. Overlapping windows remain a recorded future improvement. |
| Loop model | ~~`claude-opus-5`~~ — superseded, see [The default provider is Gemini](#the-default-provider-is-gemini). |
| Adversarial model | ~~`claude-sonnet-5`~~ — superseded. The rule it served stands: must differ from the loop model (architecture §6.3), enforced by a test. |
| Bootstrapper model | ~~`claude-haiku-4-5`~~ — superseded. Still a narrow structured-output task behind a match-rate gate. |
| Entailment judge model | ~~`claude-opus-5`~~ — superseded. Still distinct from the adversarial model. |
| `LogRecord.message` | Added alongside `raw`. `raw` stays the unmodified source line; `message` is the free-text portion the templater clusters on. Templating a whole JSON line produces templates full of key names. |
| Phase 1 redaction entities | `email`, `ipv4`, `api_key`. The rest arrive in Phase 2 with their false-positive corpus. |

---

## Phase 2 additions

Decisions taken during Phase 2 rather than at the outset. They resolve architecture §6.1,
which called for compression health to be measured but did not say how.

### Compression is not the objective; findability is

**Superseded:** an earlier version of this section described calibration as choosing the
threshold whose compression ratio landed inside a target band. That was wrong, and wrong in
the direction that matters.

Compression ratio is a proxy, and it breaks in exactly the case the system exists for. A
threshold that merges a rare FATAL template into a chatty INFO one scores *better* on ratio
while destroying the only line worth finding. Demonstrated: 200 distinct messages collapse
into a single `event <*> <*> <*> <*> <*>` template at a loose threshold — a ratio of 0.005,
the best score any candidate can post, and total loss of every distinction in the file.

The real objective is that an LLM handed the compressed representation can find the needle.
That reframes every part of the templating stage:

- **Coverage is the invariant.** Every event must be reachable through a template. An event
  whose template is missing is a line no template search can ever surface.
- **Reduction is the goal, measured honestly.** `reduction_factor` (lines per template) says
  how much smaller the agent's search space got. `compression_ratio` is kept as a diagnostic
  only, because a ratio near 1.0 still means nothing was collapsed.
- **Ranking is the delivery mechanism.** The template list is ordered by anomaly score, so
  the rarest, most severe and most concentrated templates are met before the noise. The
  ranked list *is* the answer to needle-in-a-haystack; compression only makes the list short
  enough to read.

Calibration became a gate followed by a preference rather than a target band:

1. Reject any candidate that over-merges, however well it compresses.
2. Among survivors, prefer the fewest templates — a shorter list is strictly easier to search.
3. If every candidate over-merges, take the strictest threshold and flag `signal_at_risk`,
   because under-clustering only costs tokens while over-clustering loses the needle.

Statuses are `selected`, `under_clustered`, `signal_at_risk`, `skipped`, `disabled`.

### Drain3 eviction can no longer orphan events

Drain3 evicts clusters on an LRU once `max_clusters` is reached, and evicted clusters vanish
from its tree. Final statistics were read from that tree, so every event assigned to an
evicted cluster referenced a template row that was never written.

Measured before the fix, on a 2,000-line high-cardinality file with `max_clusters: 50`:
**1,950 events (98%) orphaned, while the compression ratio read 0.0250** — mid-band, and
indistinguishable from an excellent result. Calibration would have accepted it.

`DrainTemplater` now keeps its own registry of every template it has ever seen, so eviction
is a matching concern only: the tree may forget a shape, but the scratchpad never does.
Coverage on that same file is now 1.0, and a single FATAL line planted among the 2,000
unique noise lines ranks **#1** by anomaly score. Eviction is still reported
(`evicted_templates`) because a shape that reappears after eviction gets a fresh id, which
splits one condition's counts across several templates.

### Over-merge detection is separate from the ratio

The compression ratio cannot see over-clustering. A low ratio looks like excellent
compression right up until you notice one template holds both routine INFO lines and FATAL
ones, which means two different conditions were merged and one of them is now invisible.

Post-load, templates whose members span three or more severity levels
(`drain3.over_merge_severity_span`) are flagged. During calibration severity labels are not
yet available, so the structural stand-in is wildcard density: a template that is mostly
`<*>` has kept almost none of the original words, which is what absorbing unrelated messages
looks like.

**Known limit:** neither detector catches two *same-severity* distinct conditions merging.
That is what Loghub's annotated ground-truth templates measure, and it is the Phase 5 job.

### Events stream to SQLite

Records were buffered whole before the first INSERT — roughly a kilobyte each, so ~16 GB
resident on the 16.6M-line Thunderbird corpus that the Phase 5 stress test is meant to run.
The pipeline would have died before reaching the thing it was measuring. Events now flush in
fixed batches (`EVENT_BATCH_SIZE`), bounding peak memory to the batch plus the template
registry.

### Timestamps are fixed-width

`ts` is stored as TEXT and compared lexicographically, but `datetime.isoformat()` omits
microseconds when they are zero. `.` sorts before `Z`, so `14:38:00.442000Z` compared as
*earlier* than `14:38:00Z` — inverted ordering for any second containing both forms, which
the synthetic incident did. `LogRecord.isoformat()` now always emits microseconds, making
string order and chronological order the same thing.

**Where:** `mistify/templating/calibration.py`, `mistify/templating/drain_wrapper.py`,
`mistify/pipeline.py`, `mistify/common/models.py`.

**Amend:** architecture §6.1 — compression ratio is a diagnostic, not the health metric.
Coverage is the invariant and anomaly ranking is what solves needle-in-a-haystack.

## Post-review fixes

Changes made after the Phase 2 architecture review. Issues found in the same review but
deliberately deferred are recorded in [`Issue.md`](../Issue.md).

### Severity stops voting when it has nothing to say

Severity carries the heaviest weight in the anomaly score (0.5), which is right when the
source labels its lines and actively harmful when it does not. On a log with no severity
field every line normalises to the same default, so the term adds an identical constant to
every template: the largest single input to the ranking, contributing nothing, silently.
That is not an edge case — it is most of Loghub, the corpus Phase 5 grades against.

When the share of unmapped severities exceeds `anomaly.severity_unmapped_ceiling` (0.9) the
severity weight is dropped and redistributed across burstiness and rarity. Measured on an
HDFS-shaped file with four planted exception lines among a thousand block reports, the
separation between needle and noise widened from 0.512/0.097 to 0.873/0.044. The component
is still computed and reported; it just stops contributing to the ranking, and
`anomaly.severity_informative` records which mode the run used.

### "High anomaly" is a gap, not a threshold

The adversarial check's one mechanical test is whether a high-scoring template was left out
of the conclusion, which needs a definition of high. A constant is the wrong shape: scores
are relative to each incident's own distribution, so any fixed value is tuned to whichever
fixture was on hand, and a quiet incident where nothing clears the bar yields an empty set
instead of its own best candidates.

`select_signal_templates` places the cut at the largest gap between consecutive scores in the
ranked list — the point where the distribution itself separates unusual from ordinary —
bounded by `signal_min_templates` and `signal_max_templates` so there is always something to
check against and never more than can be reasoned about. The chosen set is recorded as
`anomaly.signal_template_ids`.

### Noise suppression at the slice level

Architecture §6.4 calls for capping or suppressing templates above an occurrence threshold
unless the anomaly score flags them as relevant. Volume alone is not noise — a flood can be
the incident — so the test is both: at least `noise_share_threshold` of the file *and* below
`noise_anomaly_ceiling`.

This matters most in `get_slice`, where it is the needle problem in miniature: on a file
whose heartbeat template is 99% of the lines, an eight-line slice returned eight heartbeats
and no signal. With suppression the same call returns the four lines the investigation is
about. `top_templates` and `get_slice` both take `exclude_noise`; asking for a template by id
explicitly overrides it, since that is a deliberate act rather than a default.

### Reversible redaction, opt in

The hash is one-way, so an engineer investigating their own production incident could not
recover the address behind `[IPV4:a7f2]`. `redaction.vault` records the mapping, and
`mistify reveal` reads it back.

Off by default, because the vault is plaintext on disk and enabling it trades away part of
what redaction buys. It is written to its **own file**, never the scratchpad: the
investigator's read-only SQL channel can read any table in the database it is pointed at, so
a vault table living there would be directly readable by the model. `ATTACH` is already
denied by the authorizer, which is what makes a separate file genuinely isolated.

### Smaller

- `drain3.max_clusters` raised from 2,000 to 10,000. Eviction no longer orphans events, but
  a shape that reappears after eviction gets a fresh id, splitting one condition's counts
  across several templates. Templates are cheap; fragmented statistics are not.
- `verify_citations` resolves template ids with an existence query rather than loading the
  whole templates table to build a set.
- The report states how many templates it is showing out of how many exist, instead of
  presenting a truncated list as complete.

---

## Phase 3 additions

### The default provider is Gemini

**Superseded:** the model table above pins four Claude models. No Anthropic credential is
available on this machine, so those defaults named a provider that could not run.

The seam already existed for exactly this, and switching providers is the first thing that
proved it was real rather than decorative. Shipped defaults:

| Role | Model |
|---|---|
| Loop | `gemini-3.5-flash-lite` |
| Adversarial | `gemini-3.5-flash` |
| Bootstrapper | `gemini-3.5-flash-lite` |
| Entailment judge | `gemini-3.5-flash` |

The cheap tiers, deliberately. An investigation is roughly fifteen loop calls to the
critique's one, so the critique is the cheapest place to spend more — which is also what
satisfies §6.3's different-model requirement rather than working around it. A free AI Studio
key is real API access, and `GEMINI_API_KEY` is read from the environment or from a `.env`
file the CLI loads on startup.

`AnthropicProvider` is unchanged and still selectable with `llm.provider: anthropic`. Nothing
above the seam moved.

### A second adapter is what made the seam's gap visible

Issue #7 recorded that the seam drops thinking blocks, rated Medium, priced as a token cost
on long loops. On Gemini it is not a cost: a `functionCall` replayed without its
`thought_signature` is rejected with `400 INVALID_ARGUMENT`, so the second turn of every
investigation failed outright. `ToolCall` now carries an opaque `signature` that adapters
populate and hand back verbatim.

Opaque is load-bearing. Nothing above the seam reads it, because the moment the field acquires
a meaning it stops being a seam and becomes one vendor's data model leaking upward.

Worth recording *how* it was found: not in review, and not by any test. With one adapter there
was nothing for the seam to disagree with. The second adapter surfaced it on its first real
run. That is the argument for two adapters, demonstrated rather than asserted.

### Provider differences are declared, not assumed

Two capabilities the Gemini adapter answers differently, both already expressible:

- **Task budgets.** `supports_task_budget` is False, so the loop falls back to its own
  tool-call cap and forced convergence. The config setting is kept and ignored rather than
  removed, since it still applies to Anthropic.
- **Throttling is routine.** Free-tier quotas are per-minute, so a 429 mid-investigation is
  expected rather than exceptional. The adapter retries with full-jitter backoff; a fixed
  schedule would march its own retries into the next rate-limit window together.
  `llm.min_interval_seconds` spaces calls out for anyone whose quota that is not enough for.

Three translation details are load-bearing and documented at the top of
`src/mistify/llm/gemini.py`: tool use is detected from `function_call` parts rather than the
finish reason (Gemini returns `STOP` either way, so reading the finish reason would end every
investigation on its first tool call), function responses are matched by name rather than by
call id, and `additionalProperties` is stripped from tool schemas because the parser rejects
it.
