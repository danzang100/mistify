# Re-ranking the digest: severity read out of the template text

The investigation starts from one ranked list of 40 templates. Measured before this change,
across all five LogDx-CI dev cases, **zero** ground-truth evidence markers were in it —
including a 170-template case where the top 40 is a quarter of the file. This is what that
measurement led to, what it fixed, and what it did not.

Everything here is free: ingest and scoring only, no model calls. `mistify eval --digest`
reproduces it.

## What was actually broken

On a CI log read as `raw_lines`, all three terms of the anomaly score collapse:

* **severity** is guessed per line by `RawLinesAdapter`, which matches only upper-case log
  levels. 97.1% of lines in the pytest case map to nothing, so the score's heaviest term was
  correctly detected as uninformative and its weight redistributed;
* **burstiness** saturates. It is `max_per_bucket / (count / total_buckets)`, so a template
  with one occurrence scores `1 - 1/total_buckets` ≈ 1 whatever it says;
* **rarity** cannot separate anything when almost every line is unique — 1,134 templates for
  3,788 events, 9,307 for 10,992.

So thousands of templates tie on score, and the tie is broken by `occurrence_count DESC,
template_id`. Template ids are assigned in first-seen order, so **the ranking was "whatever the
build printed earliest"** — which on a CI log is the setup section. The old top ten for both
pandas cases is literally template ids 1-8, 10 and 11.

That is worse than arbitrary. It is systematically anti-correlated with where a build failure
appears.

## The change

When the source carries no usable severity field, severity is now **recovered from the template
text** instead of being dropped: an ERROR-equivalent 0.8 for a pattern containing failure
vocabulary (`error`, `failed`, `fatal`, `traceback`, `panic`, `assertion`, …), a WARN-equivalent
0.5 for hedging vocabulary (`timeout`, `refused`, `denied`, `cannot`, `not found`, …), INFO 0.15
otherwise — the same scale `_SEVERITY_WEIGHT` already used, so no weight needed retuning.

Case-insensitive, which is the whole point: `error[E0308]: mismatched types` and `error: Module
has no attribute` are the exact lines the ground truth calls critical, and the line-level guess
reads neither. ANSI escapes are stripped first, because a CI log paints its errors red and
`\x1b[31;1merror` has no word boundary before `error`.

It is dropped, exactly as before, when the recovered values are **constant across templates** —
a log entirely on fire ranks nothing above anything else, which is Issue 3's shape. `anomaly.
severity_source` records which of the three happened (`field` / `lexical` / `none`), the report
warns on `none`, and the system prompt tells the model when its ranking came from words rather
than from a parsed level.

## Result: markers inside the top 40

20 LogDx-CI cases, 65 critical markers. Both arms computed from the same ingest, each using the
severity decision that ingest actually recorded, so nothing but the ordering differs.

| split | cases | markers | before | after |
|---|---|---|---|---|
| dev | 5 | 18 | 0 | **14** |
| holdout | 5 | 19 | 1 | **10** |
| v2/holdout | 10 | 28 | 0 | **15** |
| **total** | **20** | **65** | **1** | **39** |

The change was designed on dev. The 15 cases and 47 markers outside it went **1/47 → 25/47**,
so the lift is not the vocabulary having been fitted to five files.

The synthetic cases are the control: `pool-exhaustion` carries a real severity field, reports
`severity_source=field`, and its markers rank #1 and #3 before and after.

## Where it still fails, and why

* **The evidence is worded calmly.** `lint-react-001` (0/2) rests on `This project uses
  prettier to format all JavaScript code.` and a test file's path; `tsc-typescript-001` (0/3)
  and `pnpm-audit-vuln-ip-address-v2-001` (0/1) are the same shape. Nothing in those lines says
  failure, so they now sit *below* the templates that do — marginally worse than before
  (#131 → #140 of 170). Recovering severity from words ranks the wording, and some evidence is
  not worded like evidence.
* **Cardinality still wins.** `hibernate-orm-dbversion-test-batch6-v2-001` clusters into 22,071
  templates for 46,195 events. One marker reached #4; the rest are past #21,000. At that
  cardinality the digest is 0.2% of the file and no ordering rescues it — this is a templating
  problem, not a ranking one.
* **A file can have a severity field and still rank badly.** `dependabot-cargo-001` is 59.5%
  mapped, so the field is used, and its four markers sit at #64–#86 of 101. This change does
  not touch that path.

## Re-scoring the recorded runs changed nothing, and could not have

The five recorded dev investigations re-score to **45/64 under both rankings**, identical
check for check — with the old and new orderings sharing not one template in their top ten.

That is not evidence the ranking does not matter. It is a property of the scorecard: the notes
were written by a model that is not being re-run, and **no LogDx check reads the ranking**.
`does-not-lead-with[...]` is the only ranking-sensitive check and it exists only for cases that
set `must_not_lead`, which no LogDx case does. So the recorded score is ranking-independent by
construction, and the only way to find out whether a better digest produces a better diagnosis
is a fresh run — five cases, ~170k tokens each, at `min_interval_seconds: 5.5`.

## Tried, and not taken

Weight sweep over the same 20 cases, with the recovered term forced on everywhere (so these
totals are the recovered path in isolation, not the shipped pipeline's):

| weights (severity / burstiness / rarity) | dev | unseen |
|---|---|---|
| 0 / .3 / .2 — before this change | 0/18 | 1/47 |
| **.5 / .3 / .2 — shipped** | 14/18 | 27/47 |
| 1 / 0 / 0 | 15/18 | 31/47 |
| .5 / 0 / .2 | 14/18 | 28/47 |
| .7 / .3 / 0 | 14/18 | 28/47 |
| .5 / .1 / .4 | 13/18 | 27/47 |

Dropping burstiness and rarity entirely scores best, by four markers of 47. It was not taken:
those terms are degenerate *on this corpus* because its timestamps are line ordinals, and
zeroing them would also change ranking on an unlabelled log that has real timestamps, where
there is no measurement saying it should. The narrower version of that idea — dropping
burstiness only when the timestamps are synthetic — is recorded as Issue 14.

Two tie-break variants scored slightly better on dev (16/18 for last-seen-first) and were
dropped as a prior about where in a file a failure appears, tuned on 18 markers.

## Reproducing

```bash
uv run mistify eval --digest --logdx dev
```

Ingests each case, resolves its ground-truth markers against the ranked digest, prints the rank
of every marker, and writes them beside the recall in `reports/eval/digest-*.json`. Exits
non-zero when any marker is below the digest. Nothing is spent; the corpus downloads on demand.
