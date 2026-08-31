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
works. Computation lands in **Phase 2** as a deterministic post-load SQL pass:
`rarity` (inverse log frequency) × `severity_weight` × `burstiness` (max events in any
one-minute bucket ÷ mean). No model call, no baseline corpus. Cross-incident novelty waits
for reusable template trees.

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
| Loop model | `claude-opus-5` |
| Adversarial model | `claude-sonnet-5` — must differ from the loop model (architecture §6.3). Enforced by a test. |
| Bootstrapper model | `claude-haiku-4-5` — narrow structured-output task behind a match-rate gate. |
| Entailment judge model | `claude-opus-5` — distinct from the adversarial model. |
| `LogRecord.message` | Added alongside `raw`. `raw` stays the unmodified source line; `message` is the free-text portion the templater clusters on. Templating a whole JSON line produces templates full of key names. |
| Phase 1 redaction entities | `email`, `ipv4`, `api_key`. The rest arrive in Phase 2 with their false-positive corpus. |
