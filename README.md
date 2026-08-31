# Mistify

Incident log analysis agent. Compresses gigabyte-scale, heterogeneous incident logs into a
queryable SQLite representation, lets a bounded agent loop investigate it via SQL slices,
adversarially checks the conclusion, and emits a structured incident report.

Design documents live in [`docs/`](docs/). The build order and the resolved v1 design questions
are in [`docs/log-agent-v1-build-plan.html`](docs/log-agent-v1-build-plan.html) and
[`docs/v1-decisions.md`](docs/v1-decisions.md).

## Status

**Phase 1 of 6 — walking skeleton.** The full path from a JSON Lines file to a rendered
markdown report runs end to end, but the investigation step is a hardcoded heuristic, not a
model-driven loop. See the build plan for what each remaining phase adds.

| Phase | Scope | State |
|-------|-------|-------|
| 0 | Decisions, repo skeleton, config | done |
| 1 | Walking skeleton: JSONL → redact → Drain3 → SQLite → report | done |
| 2 | Read-only SQL hardening, `anomaly_score`, full redaction set | not started |
| 3 | Real agent loop, adversarial pass, rebuttal | not started |
| 4 | Elastic / Loki / OTLP adapters, unknown-format bootstrapper | not started |
| 5 | Evaluation harness (Loghub, LogDx-CI, baselines) | not started |
| 6 | MCP server, HTML/PDF reports, packaging | not started |

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
