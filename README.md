# Mistify

Incident log analysis agent. Compresses gigabyte-scale, heterogeneous incident logs into a
queryable SQLite representation, lets a bounded agent loop investigate it via SQL slices,
adversarially checks the conclusion, and emits a structured incident report.

Design documents live in [`docs/`](docs/). The build order and the resolved v1 design questions
are in [`docs/log-agent-v1-build-plan.html`](docs/log-agent-v1-build-plan.html) and
[`docs/v1-decisions.md`](docs/v1-decisions.md).

## Status

**Phase 3 of 6 complete.** A model now drives the investigation through the scratchpad tools,
behind a provider seam, with an adversarial pass that objects to the conclusion rather than
rewriting it.

**Running the model-driven path needs a credential** (see Investigate below). Everything else —
ingest, templating, scoring, reporting, and the deterministic `--investigator skeleton` — runs
with no account anywhere, and so does the entire test suite.

| Phase | Scope | State |
|-------|-------|-------|
| 0 | Decisions, repo skeleton, config | done |
| 1 | Walking skeleton: JSONL → redact → Drain3 → SQLite → report | done |
| 2 | `anomaly_score`, Drain3 threshold calibration, over-merge detection, full redaction set | done |
| 3 | Provider seam, agent loop, adversarial pass with rebuttal | done |
| 4 | Elastic / Loki / OTLP adapters, unknown-format bootstrapper | not started |
| 5 | Evaluation harness (Loghub, LogDx-CI, baselines) | not started |
| 6 | MCP server, HTML/PDF reports, packaging | not started |

Deferred problems, each with a recommended fix and a target phase, are in
[`Issue.md`](Issue.md). Two of them (#1 two rankings, #2 whole-file anomaly scores) are Phase 3
decisions that are now due.

## Install

```bash
uv sync
```

## Use

Generate the sample incident (deterministic, ~4,900 lines with a planted root cause and a
deliberate red herring), then run the pipeline over it:

```bash
uv run python tests/fixtures/synthetic_incident.py examples/sample_incident.jsonl
```

```bash
uv run mistify run --source examples/sample_incident.jsonl --incident-id demo
```

The report lands in `reports/demo.md`. Against your own logs:

```bash
uv run mistify run --source path/to/incident.jsonl
```

### Investigate

`investigate` and `run` default to `--investigator loop`, which drives a model and needs a
credential. The default provider is Gemini: set `GEMINI_API_KEY`, either in the environment or
in a `.env` file at the repo root, which the CLI loads on startup. A free AI Studio key is
enough.

The shipped models are the cheap tiers — `gemini-3.5-flash-lite` for the loop and
`gemini-3.5-flash` for the adversarial pass. They must differ: architecture §6.3 requires the
critique to run on a different model from the reasoning, and config rejects a run where they
match. The loop is roughly fifteen calls to the critique's one, so the critique is the cheap
place to spend more.

Free-tier quotas are per-minute. The adapter retries throttling with backoff; if that is not
enough, set `llm.min_interval_seconds` to space calls out.

Anthropic is supported by the same seam (`llm.provider: anthropic`, with `ANTHROPIC_API_KEY`
or an `ant auth login` profile) but is not the default.

```bash
uv run mistify run --source examples/sample_incident.jsonl --investigator skeleton
```

`--investigator skeleton` uses the deterministic heuristic instead and calls no model, which
is how to exercise the whole pipeline without an account. `--no-adversarial` skips the
critique when you want one model call instead of three.

That is shorthand for the three-step pipeline:

```bash
uv run mistify ingest --source path/to/incident.jsonl --incident-id my-incident
uv run mistify investigate --incident-id my-incident
uv run mistify report --incident-id my-incident
```

Pipeline behaviour is configured in [`config.yaml`](config.yaml).

### What a run costs

Every report carries a **Token usage** table: one row per stage that called a model, with the
model it used, how many calls it made, input and output tokens, and how much of the input was
served from cache. The loop and the adversarial pass are billed separately, on different
models, so they are counted separately and then totalled.

Cached tokens are a *subset* of input, not a fourth number to add — the total is input plus
output. The two adapters normalise to that rule, because the vendors disagree about it: see
`Usage` in [`src/mistify/llm/base.py`](src/mistify/llm/base.py).

A cache share of zero on the first run against a file and a large one on the next is normal:
the loop's system prompt is the stable prefix, and a provider's implicit cache only has
something to hit once it has seen it. Zero *across* a multi-step run is worth looking at.

No prices are printed. They change without notice and differ per model; the token counts are
the part that stays true.

Reports are written to `report.output_dir` in `config.yaml`, which defaults to `./reports`,
one file per incident id.

## Develop

```bash
uv run pytest
uv run ruff check .
uv run mypy
```
