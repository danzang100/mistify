# Handoff - Phase 4 and the scale work

Branch `phase4-adapters-and-scale`, thirty-nine commits ahead of `master`. **997 tests, ruff
and mypy clean.** Nothing pushed; no remote is configured.

The sections are in the order they were written, and each later one revises the ones before it.
Sections 1-3 are the state as of 4 September. **Section 4** is the two days after: the digest
was blind and now is not, silence no longer scores, and the loop converged twice on a 568 MB
customer log nobody here wrote. **Section 5 is 5-6 September** and revises more of the same --
in particular, **section 2's grouping accuracy of 0.910 is optimistic**, measured on four of
fifteen Loghub systems which turn out to be the favourable ones; the figure over all fifteen is
**0.745**.

This document is the session's working memory: what landed, what the numbers actually are, what
was tried and rejected, and what is worth doing next. `README.md` describes the project;
`Issue.md` holds deferred problems with target phases; commit messages carry the measurement
behind each change. Where this file and the repo disagree, the repo is right.

Every number below was measured on this machine (16 logical cores, Windows). Extrapolations are
labelled as such.

---

## 1. What landed

### Formats

**Loki adapter**, the last one that could not be written from a specification. Written against
captures taken from a real stack - `grafana/otel-lgtm` with ports published, logs pushed through
its OTLP collector into its Loki and read back from `/loki/api/v1/query_range` by
`tests/fixtures/capture_loki.py`. Four things the capture showed that a hand-authored fixture
would have got wrong: severity arrives on the **stream** not the entry, `service.name` becomes
`service_name`, every label value is a string, and sending `observedTimeUnixNano` turns a
500-record push into 500 streams where omitting it gives 2.

**`LogAdapter.specificity`.** Detection now picks the best-scoring adapter of the most *specific*
tier above the confidence floor, not the highest score outright. On `logcli --output=jsonl`,
`json_lines` scores a perfect 1.0 - correctly, they are JSON objects with timestamps - so no
score Loki returns could ever win, and the file routed to a reader that saw `labels` and `line`
as two opaque fields.

**Elastic is the one format still unread.** It needs its own container, which otel-lgtm is not.

### Ingest robustness

- **Compression** (gzip/bzip2/xz) read transparently, by magic number, never by extension.
- **Binary refused** by name. A gzipped 400-line log previously ingested as 48 events of
  mojibake with `parse_errors: 0`.
- **A directory** of mixed formats reads as one incident, each file detected independently,
  unreadable files counted rather than dropped.
- **The bootstrapper's schema cache** was keyed on timestamp shape alone, so OpenSSH syslog and
  application syslog shared one entry and whichever was ingested first decided how the other was
  read - silently dropping the second file's severities.
- **`adapters.registered` defaulted to `["json_lines"]`** with a comment promising Loki and OTLP
  "arrive in Phase 4". They arrived; the default did not move. Now derived from the registry.

### Redaction

- **An IP inside a reverse-DNS hostname survived strict mode.**
  `rhost=5.36.59.76.dynamic.cablesurf.de` passed through untouched, because the guard against
  `1.2.3.4.5` also refused a following letter-label. Found on real OpenSSH logs, not on any
  fixture.
- **Every redaction metric was double-counted** on unstructured logs: `raw` and `message` are the
  same string there and were redacted separately. OpenSSH_2k reported 3,464 IPv4s against a true
  1,734.
- **`redaction.workers`** spreads redaction across processes, byte-identical output, degrading to
  serial rather than failing when a pool cannot spawn.

### Scale

- **Drain3 was writing its entire cluster tree on every new cluster** - 97.5% of a 489-second
  ingest, and every write discarded by the next, since the pipeline already snapshots once at
  the end.
- **`message` stored NULL when it equals `raw`**, read back with COALESCE.
- **Migration 0005**: composite `(severity, ts)` index replacing the plain severity index, and a
  partial trace index.
- **A cardinality circuit-breaker**: a file calibration reports as `under_clustered` gets a lower
  cluster ceiling, recorded as `templating.max_clusters`. Never applied to a file that compressed.
- **OTLP and Loki now stream.** Both read the whole file into memory purely to evaluate a layout
  check; the layout is now decided from the first few lines.
- Stdlib `fromisoformat` before dateutil; Drain3 parameter extraction off the hot path; 16 KB
  pages; `scratchpad.store_raw`.

### Evaluation

**LogDx-CI**: 35 real GitHub Actions failures with author-verified diagnoses, CC-BY-4.0, fetched
on demand into `.cache`, never committed. `expected_diagnosis.must_not_claim` becomes `avoids[]`
checks - the plausible-but-wrong test the testing strategy says no public dataset provided.

Three scorer defects were found by running it and fixed: distinctiveness measured in events not
templates, markers absent from the log dropped rather than failed, and matching that ignores
terminal escape sequences.

---

## 2. Benchmark numbers

### Ingest throughput, low cardinality

Measured at 200k–600k events. Memory is flat to the byte across a 3× file size for all four.

| format | rec/s | file B/event | scratchpad B/event | peak RAM |
|---|---|---|---|---|
| `loki` (logcli jsonl) | 4,504 | 200 | 410 | **12.4 MB** |
| `raw_lines` (BGL, real) | 3,363 | 141 | 302 | **7.3 MB** |
| `json_lines` | 3,040 | 221 | 558 | **20.3 MB** |
| `otlp` | 2,855 | 493 | 759 | **23.0 MB** |

OTLP is not fastest. It looks quickest per megabyte only because its envelope is bulky: 1 GB of
OTLP holds ~203k events where 1 GB of JSON Lines holds ~450k.

### Time by file size - **extrapolated**

Single-threaded, cold. The largest ingest actually run is 1M events / 141 MB, so 10 GB is 70×
beyond measurement.

| format | 100 MB | 1 GB | 10 GB | 10 GB, `workers: 8` |
|---|---|---|---|---|
| `otlp` | 1.2 min | 12 min | 2.0 h | 1.3 h |
| `loki` | 1.9 min | 18 min | 3.1 h | 2.0 h |
| `json_lines` | 2.5 min | 25 min | 4.1 h | **2.7 h** |
| `raw_lines` | 3.5 min | 35 min | 5.9 h | 3.9 h |

Scratchpad at 10 GB: ~15 GB (otlp) to ~25 GB (json_lines). **Storage binds before CPU.**

### Individual optimisations

| change | effect |
|---|---|
| Drain3 snapshot per-cluster write removed | 130.31s → 3.06s at 4,000 lines (**43×**) |
| OTLP streaming | peak 291 MB → **23.0 MB** (200k); 870 MB → **23.0 MB** (600k) |
| Loki streaming | peak **12.4 MB** flat at both sizes |
| Redaction dedup (`raw` == `message`) | 34.2s → 24.7s (**28%**); counts 3,464 → 1,734 |
| `message` NULL when equal to `raw` | **33%** off the scratchpad |
| `scratchpad.store_raw: false` | **40.9%** on json_lines, **0.0%** on raw_lines |
| Cardinality circuit-breaker | 22.1s → 10.3s (**2.15×**) on a CI log; no effect on BGL |
| Composite `(severity, ts)` index | severity+ts query 124.2 ms → **0.0 ms**; costs +4% ingest, +7% storage |
| `fromisoformat` before dateutil | **30.3×** on timestamp parsing |
| Drain3 params off the hot path | ~6% of ingest |
| 16 KB pages | 3.1% storage |

### Parallel redaction

| workers | 1 | 2 | 4 | 8 | 12 | 16 |
|---|---|---|---|---|---|---|
| redaction stage | 1.00× | 1.32× | 2.23× | **3.20×** | 3.45× | 3.87× |
| whole ingest | 1.00× | - | 1.40× | **1.55×** | - | 1.59× |

Redaction is ~42% of ingest, so **Amdahl caps the whole run near 1.7×**. Eight workers reach 90%
of that ceiling; sixteen buy 2% more. `redaction.vault: true` forces serial.

### Investigation loop - five LogDx-CI dev cases, one run each

`gemini-3.5-flash-lite` loop, `gemini-3.5-flash` critique. ~843k tokens total, no rate-limit
errors at `min_interval_seconds: 5.5`.

| case | templates | score | cites | mentions | avoids | notes | tokens |
|---|---|---|---|---|---|---|---|
| pytest-pandas | 1,134 | 11/13 | **4/4** | 2/4 | 4/4 | 2 | 179,827 |
| mypy-pandas | 2,848 | 11/13 | 2/4 | **4/4** | 4/4 | 2 | 149,068 |
| lint-react | 170 | 10/12 | 1/2 | 3/4 | 5/5 | 2 | 128,705 |
| cargo-tokio | 498 | 8/14 | 1/5 | 2/4 | 4/4 | 2 | 176,405 |
| jest-nextjs | 9,307 | 5/12 | 0/3 | 0/4 | 4/4 | **0** | 209,283 |
| **total** | | **45/64** | 8/18 | 11/20 | **21/21** | | |

- **avoids 21/21.** Not one hallucinated diagnosis across five real CI failures.
- **pytest-pandas cited 4 of 4 markers from a digest containing none of them.**
- **jest-nextjs wrote no notes at all** in 21 steps. Its `avoids` and `citations-resolve` pass
  trivially, so its real score is 1/12. The failure is graceful - no conclusion rather than a
  wrong one - and it is the highest-cardinality case.
- ~170k tokens per real case, **3.5× the 48,370-token synthetic baseline**, because these runs
  take 15–21 steps against the baseline's 9.

### Corpora cached in `.cache`

- **Loghub-2k** - 4 systems, grouping accuracy mean 0.907.
- **Loghub-2.0 BGL** - Zenodo record 8275861, CC-BY-4.0, 719 MB, 4.6M lines, 320 templates.
- **LogDx-CI** - github.com/eyuansu62/LogDx, CC-BY-4.0, 35 cases in 6 splits.

None are committed. All are re-fetchable on demand.

---

## 3. Tried and rejected - with the numbers

Each of these looked promising and was killed by measurement. They are recorded so nobody spends
the time twice.

| idea | result |
|---|---|
| **RE2 for redaction** | Rejects **4 of 6 patterns** (`invalid perl operator: (?<!`), including `ipv4` and `ssn` whose lookarounds close a real leak. 1.19–2.84× on the two it accepts → ~1.27× overall, **less than the 1.51× parallel redaction already gives**. |
| **Combined detector regex** before the five redaction passes | **Slower.** 0.96× on BGL (0.0% of lines match), 0.61× on OpenSSH (86.7% match). One alternation costs about what five scans cost. |
| **Caching redaction results** | Ceiling is **24%, not 50%**. 49.6% of *calls* repeat, but `raw` (median 233 chars, **0% repeat**) is 76% of the character volume. On real BGL lines the repeat rate is 0.0%. |
| **More Drain3 masking** to cut cardinality | 9,304 → 9,099 clusters, no speed change. |
| **Deeper prefix tree** (depth 4→12) | 601 → 671 lines/s. |
| **Stripping ANSI to help templating** | **Worse**: 498 → 568 templates. |
| **`synchronous=OFF`** | 5%, in exchange for a scratchpad that may not survive a power cut. |
| **Deferred index building** | 4%. Bulk insert is only 5% of ingest. |
| **Dropping the severity index** | Rare-severity lookups **850× slower** (0.2 → 170 ms) - and that is the lookup an investigation makes. |
| **Larger redaction chunks** | 10,000 beat 40,000 (13.5s) and 100,000 (13.8s) at 12.2s. |
| **`ts` as INTEGER** | Saves ~5% of storage but the index would move off the text column, so the investigator's `WHERE ts >= '...'` stops using an index. A virtual generated column does not rescue it. |
| **Two-phase learn-then-match** for parallel templating | A tree learned on the first 100k BGL lines matched only **57.5%** of the next 200k - 42% of lines would go untemplated. |

Three claims of mine were also wrong and corrected: a 5.74× parallel figure measured by sending
strings where the pipeline sends `LogRecord`s (real: 3.20×); a worker cap justified by a sweep
that never ran past 8; and a 3× ingest "speedup" that was cold-versus-warm page cache.

---

## 4. What changed after this handoff was written

Two days of work, 4-5 September, all on this branch. Each subsection carries the measurement
that justified it; the commit messages carry the rest. Read this before section 5, because
several things section 5 used to recommend are now done.

### Done since: the digest was re-ranked

Severity is now recovered from the template text when the file carries no severity field, rather
than being dropped. Ground-truth markers inside the top 40 went **1 of 65 to 39 of 65** across
20 LogDx-CI cases; on the 15 cases and 47 markers the change was *not* designed on, 1 to 25. The
full measurement, the weight sweep that was rejected, and the three cases it does not help are
in [`docs/digest-rerank.md`](docs/digest-rerank.md). `mistify eval --digest` runs the
check on any split for the price of an ingest.

**The re-scoring half of that plan produced nothing, and could not have.** The five recorded
investigations re-score to the same 45/64 under both rankings, check for check, even though the
two orderings share not one template in their top ten. No LogDx check reads the ranking:
`does-not-lead-with[...]` is the only one that does and it needs `must_not_lead`, which no LogDx
case sets. Whether a better digest produces a better diagnosis was then measured directly:
five dev cases re-run, **45/64 before and 45/64 after**, and hardly the same 45. `jest-nextjs`
went from no notes at all in 21 steps to a converged conclusion citing the real root cause
(1/12 to 8/12 on the handoff's own accounting); `cargo-tokio` gained one; `pytest-pandas` lost
four by concluding in 13 steps with one note where it used to take 21 and write two. The whole
sweep cost 607k tokens against 837k. **Then three runs per case** (`--runs 3
--no-adversarial`, 1.77M tokens, mean 42.3/64) said which of those was signal: the two cases the
change moved are the two with **zero spread across three runs** - `jest-nextjs` at 8/12 three
times out of three, `pytest-pandas` at 7/13 three times out of three. The middle three cases
vary by one to three checks, which is the margin to hold in mind before reading anything into a
single run, the two above included.

`pytest-pandas` is now diagnosed rather than mysterious: the signal set is ranks 1-5, the run
cited all five and satisfied the nudge, and the three markers it missed sit at ranks 16, 20 and
20 - inside the digest, outside the signal set, so nothing asked. Ranks 1-5 are single-occurrence
pytest **banners** (`==== ERRORS ====`, the summary count, `##[error]Process completed with exit
code 1`), which take the maximum of all three terms. The old ranking failed randomly; this one
fails towards section headers about errors. The coverage nudge fired on 15 runs of 15.

**Chasing that found a real defect in burstiness.** Two follow-ups - discounting
mostly-punctuation templates, and breaking score ties by recency rather than template id - were
implemented, measured on all twenty cases and rejected: the first costs a marker at every depth,
the second moves `jest-nextjs`'s root cause from rank 3 to 504, and that is the marker three
runs of three cited. (The earlier claim that the signal cut lands *inside* a tie was wrong. The
cut is right; the tie is the problem - 507 of that case's 9,307 templates share the top score.)
The cause: `max_per_bucket / (count / total_buckets)` gives a template that fired **once** a
burstiness of `1 - 1/total_buckets`, so every singleton in every file is maximally bursty.
Zeroing it moves markers into the top five from 14 of 65 to 19 and into the top ten from 22 to
26, empties the banners out of `pytest-pandas`'s signal set, and leaves depth 40 flat.

Note for any batch: **the critique's free tier is 20 requests per day** on `gemini-3.5-flash`,
which `min_interval_seconds` cannot help with. `--no-adversarial` keeps a sweep on the loop
model's own quota.

### One regex took 43,589 templates to 7,795

The architecture assumes Drain3 hands the ranking hundreds of templates; on CI logs it was
handing it tens of thousands. The cause was not assertion values, hex or UUIDs - those are
already absorbed by `parametrize_numeric_tokens`. It was the ISO instant GitHub Actions stamps
on the front of **every** line, which Drain3 keeps, because a token is only generalised once two
messages share a cluster and these never did.

Masked as transport rather than content: jest-nextjs 9,501 templates to 848, hibernate 22,342 to
600, pytest-pandas 1,512 to 941; across all twenty LogDx-CI cases 43,589 to 7,795. **Loghub
grouping accuracy is unchanged to the digit** (0.910 mean; the mask is anchored and matches only
the `T...Z` form, so syslog, Hadoop and BGL dates pass through). Numbers, hex and paths were
measured on top of it and left out - numbers buy 14 templates on one corpus and cost 8 on
another.

Digest recall barely moves - @5 flat at 19, @10 26 to 28, @20 35 to 36, @40 40 to 39 - and that
is the point worth reading: the mask does not find more evidence, it makes the digest a
meaningful share of the file. Hibernate's forty templates were 0.2% of its file and are now 8.8%.

### The loop converged on a real customer log, on the fourth attempt

A 568 MB Java application log, 2,188,970 events, 2,824 templates, ingested in 82 seconds.
Its actual defect is a Solr core that failed to initialise and stayed down: `SolrCore
'mainitemdata' is not available due to init failure: Error opening new searcher`, **37,653
times in one day**, every hour. The ranking never surfaced it - the digest is forty
two-occurrence templates, because 78% of the file is level ERROR (the application writes its
INFO to STDERR) so severity is a constant and rarity picks singletons.

| run | change | notes | tool calls | outcome | input tokens |
|---|---|---|---|---|---|
| 1 | as shipped | 2 | 20 (cap) | budget-limited | 1,581,188 |
| 2 | + digest char budget | 0 | 20 (cap) | budget-limited | 289,496 |
| 3 | + whole-line reads | 0 | 20 (cap) | budget-limited | 311,643 |
| 4 | + silent nudge, budget 30 | **3** | 26 of 30 | **converged** | 434,969 |

Every run found the Solr template by search - steps 8, 10, 10 and 5 - and the first three
then kept searching until the wall. What changed on the fourth is that something asked it to
write. The silent nudge fired at call 18; note @19 named the core failure with evidence; two
more notes followed unprompted; the coverage nudge then made it account for the ranking's own
signal templates, which it dismissed as startup warnings with four event ids. The critique
ran on `gemini-3.5-flash` for 3,729 tokens, raised one low-severity objection (an INFO line
cited as a timeout), and the investigation rebutted it rather than folding.

A fifth run, same configuration, reproduced it exactly: converged, 3 notes, 26 of 30 calls,
silent nudge at call 18, first note at step 19 naming the same core failure. Left alone the
loop circles (three runs); asked once it writes (two runs). It also found a second failure
the fourth run missed - connection refused to an external pricing host,
`capplink.cappcon.com:33443` - so the primary cause is stable across runs and the secondary
is not.

**The critique earned its keep on the fifth run.** Two medium objections, both conceded: the
conclusion claimed a 503 status the cited rows do not contain (they show `errorCode 3003` and
`status:500`), and attributed a bare `java.net.ConnectException: Connection timed out` to Solr
with nothing in the row saying so. Verified by hand against the file. That is the entailment
gap - ids that resolve, claims that do not follow - caught by the mechanism built for it, on
somebody's real production log, for 5,874 tokens.

Read with care: one run, three changes in it. The nudge is the one with a visible causal
chain; the extra ten calls cannot be separated from it at n=1.

### The digest is budgeted in characters, not templates

`digest_limit` counts templates, which is the wrong unit when a template can be five
kilobytes. Measured across twenty-two real incidents the digest is a median 7,222 characters;
on a Java application log whose lines carry JSON payloads it reached **208,843** - 52k tokens,
re-sent on every step. That run spent **1.58M input tokens**, thirteen times a normal case,
and hit its tool-call cap before it could finish.

`DIGEST_CHAR_BUDGET` (24,000 characters, ~6k tokens) shortens patterns rather than dropping
templates - dropping one changes what the ranking says, shortening one changes only how much
of a line is read before `get_slice` opens it properly, and the digest says how many were
shortened. That log's prompt goes 208,843 → **22,982** with all forty templates still listed;
the twenty LogDx cases are byte-identical because they were already under budget.
`investigate.digest_chars` records the size and the report warns above 40,000.

### The loop looks past the first five now, and cannot inherit another run's notes

**A digest-coverage nudge.** Measured across fifteen runs, the loop opened a median of **four
of the forty** templates it was handed, and every ground-truth marker it failed to cite sat in
a template it never opened. The existing nudge only asks about the signal set, so `pytest-pandas`
cited all five, satisfied it, and stopped with its evidence unopened at ranks 16, 20 and 20. A
second, weaker question now follows the first: the three highest-ranked digest templates the run
never pulled lines from, open them or say why they do not matter. `investigate.digest_nudges`
records which question fired. `pipeline.coverage_nudges` is now config, having been a
constructor default the runner never passed.

**`investigate` refuses a scratchpad that already holds notes**, and takes `--resume` (keep them
and tell the investigator they are there) or `--restart` (delete the previous notes, queries and
critique). The harness has always copied a fresh scratchpad per run; the CLI inherited silently,
which is how a run comes to be scored against findings it did not write.

Neither is measured against a model yet: `pytest-pandas` x3 is the sweep that would say whether
the nudge converts into citations, and it is still blocked on `flash-lite` returning 503.

### Scoring: silence no longer passes

`Check.scorable` landed. `avoids[...]` is a substring search over the conclusion, so an empty
conclusion passed every one - 81 times out of 81 across a day of runs, never once failing. Runs
with no conclusion now record those checks as unscorable, gated by a new `concludes-something`
check. Re-scored across every recorded investigation: three runs a provider outage killed before
their first tool call go from **15/42 to 0/27**, the recorded `jest-nextjs` from 5/13 to **0/8**,
and every run that actually concluded is unchanged. Issue 11's other half - a judge question
asking whether a finding asserts that something is wrong - is still open.

## 5. What changed on 5-6 September

Everything here was measured; commit messages carry the numbers and `Issue.md` 15-17 carry the
ones that became deferred problems. Read this before section 6, because several things it
recommends are now either done or measured and rejected.

### The report no longer leads with a dismissal

`findings.rank_notes` ordered findings by the peak anomaly score of the templates a note cites,
so on the customer log the note *dismissing* three two-occurrence templates (0.885 each) led the
report and the SolrCore root cause (889 occurrences, 0.798) came second.

Twenty-one recorded investigations were re-ranked under four candidate keys. Weighting by
evidence volume ties the shipped key at 19/21 - it fixes two cases and breaks two others - and
every volume-weighted key then leads with the planted herring in `pool-exhaustion`, which fires
350 times to the root cause's 40. The fix is a term *orthogonal* to the score: a note is tagged
`accounting` when its citations fall entirely inside the templates a coverage nudge named, and
those rank below findings. Where no nudge fired the ordering is unchanged.

`mistify eval-ranking` keeps the instrument, so the next change to the ordering is answered with
a table rather than an argument.

### Elastic, and which half of it is still a guess

The `_search` response and the NDJSON dump envelope are normative, and both are read and tested.
What sits inside `_source` is convention - nested versus dotted, `log.level` versus `level`,
whether `message` is the whole line - and every lookup tries both spellings, but **the mapping
has not been checked against a capture**. `tests/fixtures/capture_elastic.py` ships real lines
through a real Filebeat into a real Elasticsearch; it has not been run, because the Docker daemon
was not up. Two defects found by testing: bare ECS documents scored 0.0 and were being lost to
`json_lines` at 1.0, and one corrupt line made a whole dump unreadable.

### raw_lines reads the timestamp that is on the line

It stamped `1970-01-01T00:00:0N` per line and stored `{"line_number": N}` beside it. A shape is
now adopted from a 400-line sample and applied to the whole file; where none reaches 90% the
ordinals are unchanged. The preference order is **not** the bootstrapper's, because year-bearing
shapes must win: Thunderbird matches `syslog` and `epoch` at 100% each and they disagree by 21
years. `ingest.timestamp_year_inferred` is load-bearing, and the report says when durations are
sound but absolute dates are not. Measured on 500k Thunderbird lines: 6.7% smaller, templates
identical, and a real 41-hour window in place of a row count.

### The transport header is masked before clustering

`CONTEXT.md` says the source line and the text the templater clusters on "are different things
and are never conflated", and `raw_lines` conflated them. Masking timestamps in the first 64
characters - in the templater, not the adapter, because doing it at the adapter breaks the
`message`-equals-`raw` dedup and costs 147 bytes an event - took Thunderbird from 2,001
templates to 1,485 with storage unchanged, and LogDx digest recall from 18/22 to 19/22 on dev.

This also dissolved a false alarm: `score_dataset` clusters Loghub's `Content` column, which has
the header already stripped, so the apparent over-splitting against 1,241 annotated templates was
partly two different strings being compared.

### Conclusions that are wrong on purpose

`mistify eval-seeded` plants five defects and two sound controls derived from each log's own
statistics - chronic templates, signal set, volume distribution - so the same cases land on any
corpus, and a log that cannot support a defect yields nothing rather than a faked case. Across 94
scratchpads and 562 conclusions: **catch 388/401 by the check built for each defect, false flips
0/161**.

Both numbers needed correcting on the way. Catch read 99% until each defect was required to be
found by *its own* check rather than by one over-broad one, and `signal-ignored` was itself
broken - it compared against the acute subset, so it sat silent on 20 of the conclusions it
exists for. All 18 false flips came from logs where the check had nothing to separate; guarding
each check by what the log can distinguish took them to zero, at a cost of 13 catches, every one
of them on a log that had previously false-flipped.

### Storage, and what is not worth taking

`source` is stored NULL when unknown and read back with COALESCE, about 2.7%.
`tests/test_storage_invariants.py` holds all seven ingestion paths - json_lines, otlp, loki,
elastic, raw_lines, a directory, the bootstrapper - to the same round-trip checks. The directory
case is the one that would have broken, since `MultiFileAdapter` deliberately replaces `unknown`
with the filename.

**The timestamp is deliberately not shortened.** Trimming a whole-second stamp to `...:01Z`
saves seven bytes in the table and in both indexes carrying it, about 7%, and breaks ordering:
`ts` is TEXT and `.` sorts before `Z`, so `14:38:00.442Z` would compare as earlier than
`14:38:00Z`. A test now asserts 27 characters on every format.

Index cost measured at 500k events, net of the 12.4 B/event a VACUUM alone reclaims: the two
ts-bearing indexes are 26.3% of the scratchpad, the partial trace index costs nothing, and the
table itself is 65.8%.

### Latency: what was tried, and the one thing that is true

Ingest decays with scale - 7,900 lines/s at 500k, 4,347 at 2M, about 2,100 by 7.5M. Templating
is 78% of a 2M-line ingest and rising. Rejected, each with numbers in `Issue.md` 16:

| tried | result |
|---|---|
| SQLite page cache at 2 / 64 / 256 MB | within noise at both scales, and the gap does not widen - cache is not the constraint |
| memoising masked message to template id | changes 6.46% of assignments; only 0.37% is Drain3's own instability, the rest is caused by the cache |
| tree depth 8 / 12 / 16 | depth 4 already best on grouping accuracy; depth 12's 8.26x comes with a degenerate clustering |
| stripping a constant line prefix | regression on both corpora - leaves stayed at 32, and constant tokens pad Drain's similarity ratio |
| extra delimiters | recovers context inside templates but is 2.1x worse on scan depth for the customer log |

**"Replace the templater" is closed.** Thunderbird is slow because 786 clusters share **32
leaves** where the customer log's 654 share 279 - the average line scans 89.7 clusters against
7.4. Its first token is `-` on 100% of lines and it has 28 distinct token counts against 174.
That is degenerate routing on one corpus, not a slow templater.

**Wall-clock on this machine is not trustworthy**: one pass reported templating at 868.0s inside
a 459.4s full ingest. Measure in short repeats and quote the minimum. Structural counts -
clusters, leaves, scanned-per-line - need no clock, and every conclusion above rests on those.

### The scorecard's first rows, and a correction to this document

| row | number |
|---|---|
| grouping accuracy, 15 Loghub systems, as shipped | **0.745** |
| best threshold per system, chosen with the answer key | 0.842 |
| digest marker recall, 20 LogDx cases | 39/65 - dev 15/18, holdout 9/19, v2 15/28 |
| baselines on LogDx dev | naive 38/69, templated 38/69 |
| seeded conclusions | catch 388/401, false flips 0/161 |

**Section 2's 0.910 is optimistic.** It was measured on Apache, BGL, Hadoop and OpenSSH, picked
as a spread of log families; the other eleven are worse, and Proxifier scores 0.025. Calibration
is worth 0.005 over a fixed constant and sits within 0.010 of the best rule constructible from
run-time signals, so `Issue.md` 17 records it as a ceiling rather than a defect - the first draft
of that issue claimed the opposite and was wrong.

Digest recall is 83% on the split the ranking was tuned against and about 51% on the two it was
not, which is the shape of an overfit and belongs on the scorecard as such.

### The largest free win found, and not taken

The rarity term rewards rare templates, and evidence is usually common. Measured on two corpora
of opposite shape:

| weighting | LogDx recall@40 | customer-log root cause rank |
|---|---|---|
| shipped `5/3/2` | 61.5% | 203 of 2,769 |
| rarity removed | 61.5% | 199 |
| **rarity negated `5/3/-2`** | **72.3%** | **8** |
| severity alone | 63.1% | 511 |

The digest shows forty, so the shipped ranking puts that root cause outside it - the failure
recorded in section 4, now with a cause. Ranking rare-first scores 1.5% against random's 26.2%,
so the term is worse than chance, and severity alone beats the full three-term score.

`severity_informative` is wrong in the same family: it tests whether severity *parses*, not
whether it *varies*, so a log that is 78% ERROR with 1.0% unmapped passes and half the weight
goes on a constant.

Raising `DIGEST_LIMIT` from 40 to 200 is the other lever - recall 61.5% to 92.3%, for 7,152 to
18,160 characters re-sent every step. Note that *visible* recall plateaus near 60% at any depth,
because the marker often sits in the part templating wildcards away and the model must open the
template to read it.

**Nothing in this section is implemented.** It is measurement only.

## 6. What to do next

Ordered by value per unit of effort, revised by what the last two days measured.

### ~~The report leads with the wrong finding~~ - done, see section 5

Fixed by the `accounting` role term. This entry was written before section 5 and is kept only
so the ordering of the two is legible; the numbers are there, not here.

`mistify eval-ranking` reproduces the 19/21 with **both** markers supplied:

```bash
uv run mistify eval-ranking --scratchpads .cache --marker "is not available due to init failure" --marker "Database connection pool exhausted"
```

Without them the command scores 16 runs, reports `current 15/16`, and touches no `accounting`
note at all - every run carrying the tag is a non-LogDx one. It now says so rather than
printing a clean sweep for a key whose deciding term never ran.

### Run the critique enough to know anything about it

**Five objections exist across every scratchpad on disk.** Three conceded, two of those
touching the leading finding. Every LogDx sweep lost its critique to the 20-per-day cap on
`gemini-3.5-flash`, so the least-exercised component in the system is the one that checks the
others. Any work on amendment - having the critique fix what it catches rather than only
recording it - needs more than five data points behind it. The design constraints, if it
happens: amend by superseding, never rewrite; conceded objections only; one round, no
recursion; the amendment gets verified like any other claim.

### Rarity, the last degenerate term

53-99% of templates in every case occur exactly once, so rarity hands three-quarters of every
file the same value. Dropping it when the modal count dominates is the same shape as
`severity_source` and is free to measure. Replacing it with token IDF was tried and is worse
at every depth.

### Timestamps, for capability rather than accuracy

`parse_timestamp` already handles every shape in play - this app's `2026-05-04 17:05:37`,
Actions' ISO-with-Z, Hadoop's comma-milliseconds, syslog. Only BGL's dotted form fails. The
capability exists and nothing calls it: `raw_lines` never tries, and the bootstrapper's schema
cannot express filler between the timestamp and the severity, so it scores 0% on this format
and correctly refuses. Measured: real wall-clock buckets change marker recall by nothing
(@5 19→18, @10 30→29, @40 41→42). The case for fixing it is `get_slice(start_ts, end_ts)`,
an incident window that is not 1970, and 'when did this start' - which is the question the
customer-log run could not ask.

### Cheap and well understood

- **Elastic adapter.** The last format. Needs `elasticsearch:8` plus Filebeat for authentic ECS
  `_source`; the Loki capture script is the template for doing it honestly.
- **Decide `store_raw`.** Built, tested, default on. 41% of disk on structured formats for the
  loss of the byte-exact source line - every parsed field keeps its own column. Probably right as
  the default at volume and wrong for a small incident.
- **`synthesis.py`** is 91 statements at **0% coverage**, disabled by config. Either an eval
  earns it a place or it goes.

### Bigger, and needs a decision first

- **A planted root cause at scale.** Take BGL (4.6M lines, cached) and plant a known cause the
  way `eval/fixtures.py` does, then run the same `cites[]` / `avoids[]` checks at 100k, 1M and
  10M events. `EvalCase.source` is already a callable, so the harness supports it. This is the
  thing standing between "ingestion scales" and "the product scales".
- **Parse inside the redaction workers.** Moves the parallel fraction from 42% to 56% and the
  Amdahl ceiling from 1.7× to **2.27×**. Adapters accumulate stats and some emit many records
  per line, so the worker boundary moves from "redact these records" to "parse and redact these
  lines" - a design change to the ingest seam, not a tuning knob.
- **Multi-line records.** Stack traces become one event per line. Probably why OpenSSH sits at
  0.718 grouping accuracy and will not move with `sim_th`.
- **JSON bodies inside Loki lines.** An app logging structured output into Loki gets its whole
  blob as the message. Degraded, not wrong, and recorded as such.

### Known and deliberately deferred

`Issue.md` carries these with target phases. The two that matter most at scale: **Issue 3** (the
anomaly baseline is the incident itself, so a log entirely on fire has nothing to stand out
against) and **Issue 11** (the quiet-hour bar cannot separate confident-and-right from
confident-and-wrong).

---

## 7. Operational notes

- **`gemini-3.5-flash` allows 20 requests per day** on the free tier
  (`GenerateRequestsPerDayPerProjectPerModel-FreeTier`). Every critique in the 4 September
  sweeps died on it. `min_interval_seconds` does nothing about a daily cap; plan a batch
  around it or run `--no-adversarial`.
- **`gemini-3.5-flash-lite` returned 503 for about an hour** on 4 September - capacity, not
  quota, and it answers nothing including a one-token ping. Wait it out.
- **Throughput does not transfer between corpora.** The 3,363 rec/s in section 2 is a BGL
  figure; a 568 MB Java application log ingested at **26,600 rec/s**, 2.19M events in 82
  seconds with `redaction.workers: 8`.
- **`investigate` refuses a scratchpad that already holds notes.** Pass `--resume` (keep them
  and tell the investigator) or `--restart` (clear notes, queries and critique).
- **Budget 30, not 20**, on a large real log: the two runs that converged used 26 of 30. The
  shipped `pipeline.max_agent_tool_calls` is still 20.
- **Never `git add -A` in this repo.** Logs handed over for analysis live in `test-logs/`,
  which is now in `.gitignore` - 582 MB of somebody's production data was committed once and
  had to be reset out before it went anywhere.

- **`min_interval_seconds: 4.0`** in the shipped config is exactly 15 req/min, the free-tier
  ceiling, with no headroom. **Use 5.5 for a batch** - that is what made a five-case run clean.
- Budget **~170k tokens and 15–21 steps** per real case.
- `mistify eval --logdx dev` fetches the corpus on demand; `--case logdx-<id>` selects one.
- Ingest is free. Before paying for a run on a new corpus, resolve its ground-truth markers
  against the digest first - it says whether the run tests the loop or the ranking.
- A killed run can leave a truncated Drain3 snapshot. That is now survivable (discarded and
  re-clustered) and snapshots are written atomically, but older `.cache` files may still exist.
