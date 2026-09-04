# Handoff — Phase 4 and the scale work

Branch `phase4-adapters-and-scale`, nine commits ahead of `master`. **883 tests, 90% coverage,
ruff and mypy clean.** Nothing pushed; no remote is configured.

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
captures taken from a real stack — `grafana/otel-lgtm` with ports published, logs pushed through
its OTLP collector into its Loki and read back from `/loki/api/v1/query_range` by
`tests/fixtures/capture_loki.py`. Four things the capture showed that a hand-authored fixture
would have got wrong: severity arrives on the **stream** not the entry, `service.name` becomes
`service_name`, every label value is a string, and sending `observedTimeUnixNano` turns a
500-record push into 500 streams where omitting it gives 2.

**`LogAdapter.specificity`.** Detection now picks the best-scoring adapter of the most *specific*
tier above the confidence floor, not the highest score outright. On `logcli --output=jsonl`,
`json_lines` scores a perfect 1.0 — correctly, they are JSON objects with timestamps — so no
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
  read — silently dropping the second file's severities.
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

- **Drain3 was writing its entire cluster tree on every new cluster** — 97.5% of a 489-second
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
checks — the plausible-but-wrong test the testing strategy says no public dataset provided.

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

### Time by file size — **extrapolated**

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
| whole ingest | 1.00× | — | 1.40× | **1.55×** | — | 1.59× |

Redaction is ~42% of ingest, so **Amdahl caps the whole run near 1.7×**. Eight workers reach 90%
of that ceiling; sixteen buy 2% more. `redaction.vault: true` forces serial.

### Investigation loop — five LogDx-CI dev cases, one run each

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
  trivially, so its real score is 1/12. The failure is graceful — no conclusion rather than a
  wrong one — and it is the highest-cardinality case.
- ~170k tokens per real case, **3.5× the 48,370-token synthetic baseline**, because these runs
  take 15–21 steps against the baseline's 9.

### Corpora cached in `.cache`

- **Loghub-2k** — 4 systems, grouping accuracy mean 0.907.
- **Loghub-2.0 BGL** — Zenodo record 8275861, CC-BY-4.0, 719 MB, 4.6M lines, 320 templates.
- **LogDx-CI** — github.com/eyuansu62/LogDx, CC-BY-4.0, 35 cases in 6 splits.

None are committed. All are re-fetchable on demand.

---

## 3. Tried and rejected — with the numbers

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
| **Dropping the severity index** | Rare-severity lookups **850× slower** (0.2 → 170 ms) — and that is the lookup an investigation makes. |
| **Larger redaction chunks** | 10,000 beat 40,000 (13.5s) and 100,000 (13.8s) at 12.2s. |
| **`ts` as INTEGER** | Saves ~5% of storage but the index would move off the text column, so the investigator's `WHERE ts >= '...'` stops using an index. A virtual generated column does not rescue it. |
| **Two-phase learn-then-match** for parallel templating | A tree learned on the first 100k BGL lines matched only **57.5%** of the next 200k — 42% of lines would go untemplated. |

Three claims of mine were also wrong and corrected: a 5.74× parallel figure measured by sending
strings where the pipeline sends `LogRecord`s (real: 3.20×); a worker cap justified by a sweep
that never ran past 8; and a 3× ingest "speedup" that was cold-versus-warm page cache.

---

## 4. What to do next

Ordered by value per unit of effort.

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
sweep cost 607k tokens against 837k. One run per arm, so a three-check swing is not
distinguishable from noise — and **every new run lost its critique to a 20-requests-per-day cap
on `gemini-3.5-flash`**, which cannot move a scored check but means these are investigations
without critiques. The next measurement worth paying for is repeats: `--runs 3
--no-adversarial` keeps the whole sweep on the loop model's own quota.

### Cheap and well understood

- **Elastic adapter.** The last format. Needs `elasticsearch:8` plus Filebeat for authentic ECS
  `_source`; the Loki capture script is the template for doing it honestly.
- **Decide `store_raw`.** Built, tested, default on. 41% of disk on structured formats for the
  loss of the byte-exact source line — every parsed field keeps its own column. Probably right as
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
  lines" — a design change to the ingest seam, not a tuning knob.
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

## 5. Operational notes

- **`min_interval_seconds: 4.0`** in the shipped config is exactly 15 req/min, the free-tier
  ceiling, with no headroom. **Use 5.5 for a batch** — that is what made a five-case run clean.
- Budget **~170k tokens and 15–21 steps** per real case.
- `mistify eval --logdx dev` fetches the corpus on demand; `--case logdx-<id>` selects one.
- Ingest is free. Before paying for a run on a new corpus, resolve its ground-truth markers
  against the digest first — it says whether the run tests the loop or the ranking.
- A killed run can leave a truncated Drain3 snapshot. That is now survivable (discarded and
  re-clustered) and snapshots are written atomically, but older `.cache` files may still exist.
