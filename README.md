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
enough, set `llm.min_interval_seconds` to space calls out. A run over the sample incident costs
roughly 48k tokens end to end — see `docs/baseline.md`.

Gemini is the only real provider that ships. The seam it sits behind (`src/mistify/llm/`) took
a second adapter once and would take another; an Anthropic implementation lived there and was
removed when no credential for it existed.

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

The investigator has five tools: `query_templates` and `get_slice` to read the scratchpad,
`run_sql` for a read-only aggregate over it, `read_notes` to read back its own findings, and
`write_note` to record one. `write_note` refuses a log event id that was never returned to the
investigation — an id nobody read resolves to a real row that says nothing about the claim,
which is the one bad citation the report's existence check cannot catch. Lines carry their
`trace_id`, and passing it back to `get_slice` returns one request across every service.

Pipeline behaviour is configured in [`config.yaml`](config.yaml).

### What the report contains

The document is a fixed Jinja template, not model-written prose: the same sections in the same
order for every incident, whatever the investigation did. A model contributes note text into
labelled slots and nothing else — it never decides the shape of the report.

Responder-facing, in order:

1. **What was found** — every issue the investigation recorded, most significant first,
   ordered on the anomaly ranking of the templates each cites rather than on the order they
   were written. An issue resting entirely on templates active across the whole log is marked
   *background*. Two or more issues carry a note that they are not necessarily one incident.
2. **Read this first** — the warnings, above the machinery rather than below it.
3. **The incident at a glance** — window, duration, per-severity volume and per-source
   activity, all computed from the events. Signal templates are timed individually, and one
   active across the whole log is labelled chronic: a background problem that was already
   there is not part of the event, and folding it into the window turns a six-minute outage
   into an hour-long one.
4. **Findings** — every recorded hypothesis with its cited rows.
5. **The challenge** — what the critique actually argued, what it cited, and what the
   investigation conceded. Objections carry ids the rebuttal quotes back, so an answer lands on
   the objection it was written for rather than on whichever one shared its position in a list.
6. **Templates by anomaly score**.

Then an appendix: run signals, token usage, the investigation trail, and pipeline
configuration. It is there so a conclusion can be checked, not because a responder needs it.

### Formats

`report.format` in config, or `--format` on the command, takes `markdown`, `html` or `pdf`:

```bash
uv run mistify report --incident-id demo --format html
```

Each format renders the same collected data through its own template rather than converting one
output into another — the HTML report is a rendering of the incident, not a translation of the
markdown one. HTML is self-contained: no CDN stylesheet, no fetched fonts, so it still looks
right in an email attachment or on a machine with no network, and it carries print styles.

PDF needs the optional extra, because the good HTML-to-PDF engines want system libraries that a
stock Windows machine does not have:

```bash
uv sync --extra pdf
```

Without it, `--format pdf` says so and names the fix. The engine is pure Python and renders a
subset of CSS; a browser's print-to-PDF on the HTML gives a better-looking file if you need one.

### What a run costs

`docs/baseline.md` records the reference numbers for the sample incident. Compare against it
rather than against memory.

The loop re-sends the whole conversation on every step, so an early slice is paid for again on
every step after it. Three things keep that bounded, and all three are measured rather than
assumed:

- `get_slice` returns 60 lines by default (ceiling 200) and states how many matched in total,
  so a narrower default costs nothing the investigation cannot ask for — it knows what it did
  not see.
- Tool output older than `pipeline.tool_result_history_steps` keeps the summary line the tool
  wrote and loses the rows. Citations resolve against the scratchpad, not the transcript, so
  nothing the report reads is lost. Set it to 0 to keep everything.
- `investigate.input_tokens_per_step` records the curve and `investigate.input_growth_factor`
  warns above 5×. The total hides the shape, and the shape is what decides whether a longer
  incident is affordable.

There is no token ceiling yet — a run that grows anyway is reported, not stopped.


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

### Evaluate

Every eval case is a log file whose answer is known by construction, so the score is arithmetic
rather than judgement:

```bash
uv run mistify eval --case quiet-hour --runs 3
```

`--list` shows the cases and what passing means for each. `--case` is repeatable and defaults
to all of them; running one at a time matters on a free tier where a full sweep is several
minutes of quota. `--no-adversarial` halves the cost. Results print per check — an aggregate
pass rate cannot tell you *which* question failed — and are written as JSON so two sweeps can
be diffed rather than remembered.

Two cases ship today:

- **pool-exhaustion** — the original incident. Must cite the pool exhaustion *and* the latency
  precursor, and must not lead with the red herring, which fires 350 times against the root
  cause's 40.
- **quiet-hour** — an hour of healthy service with nothing planted. The bar is that no finding
  is recorded at high confidence: a low or medium note describing normal operation is fine,
  inventing a root cause is not. This is the only case that asks whether the agent makes
  something up, which is the failure that matters most on a page that turns out to be nothing.

`--judge` adds the semantic half of decision G8: a model is asked whether each claim actually
follows from the rows it cites. `verify_citations` proves the ids exist and cannot prove the
rows say what the note says — a measured run cited two genuine log events, both unrelated INFO
lines from other services, for a claim about database credentials. Off by default because it
costs a model call per note.

### Template accuracy on somebody else's logs

```bash
uv run mistify eval-templating --sim-th 0.3 --sim-th 0.4 --sim-th 0.5
```

Scores clustering against [Loghub-2k](https://github.com/logpai/loghub)'s human-annotated event
templates. No model is called — this measures the foundation everything else sits on, since a
template that merged two conditions has lost the distinction before an investigation starts.
The metric is Grouping Accuracy: a line counts as correct only when the set of lines sharing
its parsed template is exactly the set sharing its annotated one, so a nearly-right cluster
scores zero for every line in it.

Measured, four systems across three thresholds — mean **0.907**:

| System | GA @0.3 | @0.4 | @0.5 | Templates (ours/annotated) |
|---|---|---|---|---|
| Apache | 1.000 | 1.000 | 1.000 | 6 / 6 |
| BGL | 0.931 | 0.969 | 0.963 | 105 / 120 |
| Hadoop | 0.962 | 0.954 | 0.948 | 100 / 114 |
| OpenSSH | 0.718 | 0.718 | 0.718 | 23 / 27 |

OpenSSH is the standing weak spot and does not move with `sim_th` at all, which points at
something structural rather than a threshold to tune. Data downloads on demand into `.cache/`
and is never committed: Loghub is free for research use with citation terms, and a vendored
corpus is a licence question nobody wants later. Cite the LogPub paper if you publish these.

The remaining external work is LogDx-CI for end-to-end diagnosis quality. `EvalCase.source` is
a callable returning a path, so it arrives as a case rather than as a second kind of thing. The
model-driven cases have still only been measured against logs this project generated.

## Develop

```bash
uv run pytest
uv run ruff check .
uv run mypy
```
