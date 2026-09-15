# Mistify

Incident log analysis agent. Compresses gigabyte-scale, heterogeneous incident logs into a
queryable SQLite representation, lets a bounded agent loop investigate it via SQL slices,
adversarially checks the conclusion, and emits a structured incident report.

## Status

**What works today.** A model drives the investigation through
the scratchpad tools, behind a provider seam, with an adversarial pass that objects to the
conclusion rather than rewriting it. Four formats are read - JSON Lines, OTLP, Loki, and
anything else via the bootstrapper or the raw-line fallback. An Elastic adapter is written but
not registered: it has not yet been validated against a capture from a live stack, and a
hand-authored fixture is exactly the kind of evidence it should not be trusted on.

**Running the model-driven path needs a credential** (see Investigate below). Everything else -
ingest, templating, scoring, reporting, and the deterministic `--investigator skeleton` - runs
with no account anywhere, and so does the entire test suite.

| Area | State |
|------|-------|
| Ingest: adapters, redaction, Drain3 templating with threshold calibration, SQLite scratchpad | done |
| Anomaly scoring and over-merge detection | done |
| Provider seam, agent loop, adversarial pass with rebuttal | done |
| JSON Lines / OTLP / Loki adapters, unknown-format bootstrapper, raw-line fallback | done |
| Elastic adapter | written, unregistered |
| Evaluation harness: Loghub, LogDx-CI, grep baselines, seeded wrong conclusions | done |
| Markdown / HTML / PDF reports | done |
| MCP server, PyPI packaging | not started |

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

The shipped models are the cheap tiers - `gemini-3.5-flash-lite` for the loop and
`gemini-3.5-flash` for the adversarial pass. They must differ: a critique that shares the
reasoning model shares its blind spots, so config rejects a run where they match. The loop is roughly fifteen calls to the critique's one, so the critique is the cheap
place to spend more.

Free-tier quotas are per-minute. The adapter retries throttling with backoff; if that is not
enough, set `llm.min_interval_seconds` to space calls out. A run over the sample incident costs
roughly 48k tokens end to end (see *What a run costs*).

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
investigation - an id nobody read resolves to a real row that says nothing about the claim,
which is the one bad citation the report's existence check cannot catch. Lines carry their
`trace_id`, and passing it back to `get_slice` returns one request across every service.

Pipeline behaviour is configured in [`config.yaml`](config.yaml).

### What the report contains

The document is a fixed Jinja template, not model-written prose: the same sections in the same
order for every incident, whatever the investigation did. A model contributes note text into
labelled slots and nothing else - it never decides the shape of the report.

Responder-facing, in order:

1. **What was found** - every issue the investigation recorded, most significant first,
   ordered on the anomaly ranking of the templates each cites rather than on the order they
   were written. An issue resting entirely on templates active across the whole log is marked
   *background*. Two or more issues carry a note that they are not necessarily one incident.
2. **Read this first** - the warnings, above the machinery rather than below it.
3. **The incident at a glance** - window, duration, per-severity volume and per-source
   activity, all computed from the events. Signal templates are timed individually, and one
   active across the whole log is labelled chronic: a background problem that was already
   there is not part of the event, and folding it into the window turns a six-minute outage
   into an hour-long one.
4. **Findings** - every recorded hypothesis with its cited rows.
5. **The challenge** - what the critique actually argued, what it cited, and what the
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
output into another - the HTML report is a rendering of the incident, not a translation of the
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

Reference numbers for `examples/sample_incident.jsonl`, recorded 2026-09-01, so a later change
has something to be compared against rather than argued about from memory. The deterministic
half should reproduce exactly; the model-driven half will move.

| | Reference |
|---|---|
| Events ingested / templates | 4,946 / 9 |
| Compression ratio | 0.00182 |
| Redactions | 7,282 (6,226 ipv4, 1,044 email, 12 api_key) |
| Signal templates, chronic among them | 5, 2 |
| Steps / tool calls / notes written | 9 / 8 / 1 |
| Loop tokens (in / out) | 46,648 / 393 |
| Critique tokens (in / out) | 1,009 / 320 |
| **Total tokens** | **48,370** |
| Input growth factor | 2.69x |

The loop re-sends the whole conversation on every step, so an early slice is paid for again on
every step after it. Three things keep that bounded, and all three are measured rather than
assumed:

- `get_slice` returns 60 lines by default (ceiling 200) and states how many matched in total,
  so a narrower default costs nothing the investigation cannot ask for - it knows what it did
  not see.
- Tool output older than `pipeline.tool_result_history_steps` keeps the summary line the tool
  wrote and loses the rows. Citations resolve against the scratchpad, not the transcript, so
  nothing the report reads is lost. Set it to 0 to keep everything.
- `investigate.input_tokens_per_step` records the curve and `investigate.input_growth_factor`
  warns above 5×. The total hides the shape, and the shape is what decides whether a longer
  incident is affordable.

There is no token ceiling yet - a run that grows anyway is reported, not stopped.


Every report carries a **Token usage** table: one row per stage that called a model, with the
model it used, how many calls it made, input and output tokens, and how much of the input was
served from cache. The loop and the adversarial pass are billed separately, on different
models, so they are counted separately and then totalled.

Cached tokens are a *subset* of input, not a fourth number to add - the total is input plus
output. The two adapters normalise to that rule, because the vendors disagree about it: see
`Usage` in [`src/mistify/llm/base.py`](src/mistify/llm/base.py).

A cache share of zero on the first run against a file and a large one on the next is normal:
the loop's system prompt is the stable prefix, and a provider's implicit cache only has
something to hit once it has seen it. Zero *across* a multi-step run is worth looking at.

No prices are printed. They change without notice and differ per model; the token counts are
the part that stays true.

Reports are written to `report.output_dir` in `config.yaml`, which defaults to `./reports`,
one file per incident id.

### What you can point it at

`--source` takes a file or a directory.

```bash
uv run mistify run --source ./incident-logs/ --investigator skeleton
```

A directory is read recursively, one adapter chosen **per file**, so a folder holding JSON from
one service and syslog from another is read as both rather than forced through one reader. Every
record carries the file it came from in `source_file`, and a file whose adapter could not name a
source is named after the file - in a per-service layout that *is* the service. A source the
data named is never overwritten by a filename.

Compressed sources are read directly: gzip, bzip2 and xz, detected by magic number rather than
by extension, because a rotated `.log` is routinely gzip and a `.gz` is occasionally not.

Anything that is neither text nor a compression we can undo is **refused**, by name:

```
Error: screenshot.png is a PNG image, not a log file. Extract or convert it first:
reading it as text produces records that look real and are not.
```

That refusal is the important one. Every adapter used to open files with `errors="replace"`,
which never raises - a gzipped 400-line log ingested as 48 "events" of replacement characters,
reported `parse_errors: 0`, and produced a report. In a directory, one unreadable file is
skipped and counted rather than failing the ingest; a directory with nothing readable in it is
refused outright.

### Formats

| Format | Recognised from | Written against |
|---|---|---|
| `json_lines` | JSON objects carrying a timestamp | application logs |
| `otlp` | `resourceLogs` | the protobuf-JSON mapping, which is normative |
| `loki` | `resultType: streams`, `{labels, line}`, or `{"streams": [...]}` | captures from a running Loki |
| `raw_lines` | nothing - never wins detection | the last resort, selected deliberately |

Elastic is written (`src/mistify/adapters/elastic.py`) but left out of `adapters.registered`.
Its export shape is a convention rather than a specification, and a hand-authored fixture gets
the `_source` nesting subtly wrong in exactly the ways the adapter would exist to absorb - so it
needs a capture from its own stack, which `otel-lgtm` is not. `tests/fixtures/capture_elastic.py`
takes that capture against a single-node Elasticsearch with filebeat shipping into it; the
adapter is registered once its fixtures come from there rather than from a document.

Loki was the first adapter that could not be written from a document. What lands in a label set
is decided by the collector, the distributor and Loki's own enrichment, so it was written
against captures taken from a real one:

```bash
docker run -d --name otel-lgtm -p 3000:3000 -p 4317:4317 -p 4318:4318 -p 3100:3100     grafana/otel-lgtm:latest

uv run python tests/fixtures/capture_loki.py --source synthetic
uv run python tests/fixtures/capture_loki.py --source loghub --system OpenSSH
```

That was worth doing. Loki flattens everything the producer sent - severity, trace ids,
application fields - onto the *stream*, not the entry, so severity is a property of the label
set; `service.name` arrives as `service_name`; every value is a string; and because labels
define stream identity, sending `observedTimeUnixNano` turned a 500-record push into 500
streams of one entry where omitting it gave 2 streams of 250. Both are ordinary deployments.
A fixture written by hand would have had one stream, many entries, and severity on the line.

Captures land in `.cache/` and are not committed, for the same reason nothing else generated
here is. `tests/test_loki_adapter.py` transcribes the shapes they showed, and its
`test_live_round_trip` re-reads a real stack when one is running - the control on a
transcription, which cannot notice when the thing it was copied from changes.

Detection picks the highest-scoring adapter of the *most specific* tier that clears
`adapters.min_detect_confidence`, not the highest score outright. The two are not the same
claim: on `logcli --output=jsonl` output `json_lines` scores a perfect 1.0, correctly, because
those lines are JSON objects with timestamps - and no confidence the Loki adapter returns could
beat it. Ranked by number alone a Loki export routes to the generic reader, `labels` and `line`
become two opaque fields, and every record is quietly wrong. `registry.detection_matrix()`
prints the whole grid, which is how a near-miss becomes visible before it becomes a bad parse.

### Unknown formats

A file no adapter recognises is read anyway. With `bootstrap.enabled`, the pipeline tries to
work the format out: structural inspection first - timestamp shapes, severity words, field
order - which costs nothing and handles most real formats, then a model only if that fails, and
in either case a match-rate gate against lines the inference never saw. Nothing is persisted or
used below `bootstrap.min_match_rate`, and a schema that clears it is saved so the next file
from that source skips inference entirely.

The model is never asked for a regex. It is asked to quote the substrings - which part is the
timestamp, which is the severity - and each claim is checked against the line it came from
before a schema is built. A quoted substring can be verified; a generated pattern can only be
trusted, and a persisted one would be a pattern nobody reviewed running on every future file.

Failing all that, the file is read line by line: no real timestamps, severity guessed from the
text, and the report says so in words rather than presenting the resulting incident window as a
fact. It is off by default - this stage's failure mode is silent, a confidently wrong schema
producing garbage templates with no error thrown, so it is opted into rather than inherited.

### Evaluate

Every eval case is a log file whose answer is known by construction, so the score is arithmetic
rather than judgement:

```bash
uv run mistify eval --case quiet-hour --runs 3
```

`--list` shows the cases and what passing means for each. `--case` is repeatable and defaults
to all of them; running one at a time matters on a free tier where a full sweep is several
minutes of quota. `--no-adversarial` halves the cost. Results print per check - an aggregate
pass rate cannot tell you *which* question failed - and are written as JSON so two sweeps can
be diffed rather than remembered.

Two cases ship today:

- **pool-exhaustion** - the original incident. Must cite the pool exhaustion *and* the latency
  precursor, and must not lead with the red herring, which fires 350 times against the root
  cause's 40.
- **quiet-hour** - an hour of healthy service with nothing planted. The bar is that no finding
  is recorded at high confidence: a low or medium note describing normal operation is fine,
  inventing a root cause is not. This is the only case that asks whether the agent makes
  something up, which is the failure that matters most on a page that turns out to be nothing.

Each sweep writes into `reports/eval/<timestamp>.json` alongside `reports/eval/reports/`, one
rendered report per run. The checks say whether a run passed; only the report says what it
concluded, and a sweep that kept just the score cannot be re-read later to find out why - which
is exactly what happened to this project's first nine runs.

`--digest` answers the cheap question that belongs *before* a paid sweep: is the evidence a
correct diagnosis rests on anywhere in the ranked list the model reads first? It ingests each
case, resolves its known markers against the digest, prints the rank of every one and exits
non-zero if any sits below it. No model is called. The question was worth asking: on the five
LogDx-CI dev cases the answer was zero of eighteen markers, which is why severity is now
recovered from the template text when a file carries no severity field.

```bash
uv run mistify eval --digest --logdx dev
```

`--baseline naive|templated` replaces the investigation with a grep pipeline and scores it
with the same checks - no model calls. On the incident both variants lead with the red herring;
on the quiet hour both correctly claim nothing. The agent is the mirror image.

`--judge` adds the semantic half of citation checking: a model is asked whether each claim actually
follows from the rows it cites. `verify_citations` proves the ids exist and cannot prove the
rows say what the note says - a measured run cited two genuine log events, both unrelated INFO
lines from other services, for a claim about database credentials. Off by default because it
costs a model call per note.

### Template accuracy on somebody else's logs

```bash
uv run mistify eval-templating --sim-th 0.3 --sim-th 0.4 --sim-th 0.5
```

Scores clustering against [Loghub-2k](https://github.com/logpai/loghub)'s human-annotated event
templates. No model is called - this measures the foundation everything else sits on, since a
template that merged two conditions has lost the distinction before an investigation starts.
The metric is Grouping Accuracy: a line counts as correct only when the set of lines sharing
its parsed template is exactly the set sharing its annotated one, so a nearly-right cluster
scores zero for every line in it.

Measured across all fifteen Loghub-2k systems, at the threshold the shipped calibrator
chooses for each - mean **0.745**:

| System | GA | System | GA |
|---|---|---|---|
| Apache | 1.000 | HPC | 0.741 |
| HDFS | 0.998 | Mac | 0.715 |
| BGL | 0.969 | Linux | 0.684 |
| Zookeeper | 0.967 | HealthApp | 0.576 |
| Thunderbird | 0.955 | Windows | 0.571 |
| Hadoop | 0.954 | OpenStack | 0.309 |
| Spark | 0.922 | Proxifier | 0.025 |
| OpenSSH | 0.718 | | |

A fixed `sim_th=0.4` scores 0.740 over the same fifteen, and the best threshold per system,
chosen with the answer key in hand, reaches 0.842. That 0.097 is not recoverable at run time:
seven selection rules were scored against the full grid, each seeing only what the pipeline
sees, and the shipped rule sits within 0.010 of the best of them. A mean also
hides that two log families are essentially not clustered at all - OpenStack and Proxifier are
worth reading individually, not as part of an average.

An earlier version of this table reported 0.907 on four systems. Those four turned out to be
the favourable ones; the fifteen-system figure is the honest one.

Data downloads on demand into `.cache/` and is never committed: Loghub is free for research use
with citation terms, and a vendored corpus is a licence question nobody wants later. Cite the
LogPub paper if you publish these.

`fetch_loghub` pulls the annotated CSV that this table scores against; `fetch_loghub_raw` pulls
the unstructured `.log` the CSV was annotated *from*, which is the only form the ingest path can
read. The two answer different questions - one measures clustering against an answer key, the
other measures whether the adapters and the bootstrapper can reach the lines at all:

```bash
uv run mistify run --source .cache/loghub/OpenSSH_2k.log --investigator skeleton
```

That needs no credential and no adapter: nothing recognises the file, so it falls through to
the bootstrapper or the raw-line reader and says which in `run_metadata`. On OpenSSH the
structural pass - no model - infers a syslog schema, recovers every timestamp the raw-line
fallback would have lost, and cuts 131 templates to 23.

The remaining external work is LogDx-CI for end-to-end diagnosis quality. `EvalCase.source` is
a callable returning a path, so it arrives as a case rather than as a second kind of thing. The
model-driven cases have still only been measured against logs this project generated.

## Develop

```bash
uv run pytest
uv run ruff check .
uv run mypy
```
