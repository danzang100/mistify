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
credential — either `ANTHROPIC_API_KEY`, or a profile from `ant auth login`. A Claude Pro
subscription includes a monthly programmatic allowance billed at API rates; it is separate
from chat usage.

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

## Develop

```bash
uv run pytest
uv run ruff check .
uv run mypy
```
