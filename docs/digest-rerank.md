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

## The paid run: the total did not move, the failure mode did

Five dev cases, one run each, same models and `min_interval_seconds: 5.5`, scored against the
five recorded runs the ranking change was measured against.

**45/64 before, 45/64 after** — and almost none of that is the same 45.

| case | before | after | steps | notes | outcome | tokens |
|---|---|---|---|---|---|---|
| pytest-pandas | 11/13 | **7/13** | 21 → 13 | 2 → 1 | budget-limited → converged | 178k → 94k |
| mypy-pandas | 11/13 | 11/13 | 20 → 22 | 2 → 3 | converged → budget-limited | 147k → 189k |
| lint-react | 10/12 | 10/12 | 15 → 9 | 2 → 2 | converged | 128k → 125k |
| cargo-tokio | 8/14 | **9/14** | 20 → 9 | 2 → 2 | converged | 175k → 76k |
| jest-nextjs | 5/12 | **8/12** | 21 → 14 | **0 → 2** | budget-limited → converged | 209k → 122k |
| **total** | **45/64** | **45/64** | | | | 837k → **607k** |

The number worth reading is `jest-nextjs`. Before, it was the case that spent 21 steps and 209k
tokens and wrote **no notes at all** — its 5/12 was `avoids` and `citations-resolve` passing
trivially on an empty conclusion, so its real score was 1/12. It now converges in 14 steps
citing `fatal: detected dubious ownership in repository at '/work'`, which is the root cause.
That is 1/12 to 8/12 on the case the old digest failed hardest.

`pytest-pandas` went the other way, and it is not a search failure: its four markers are all
inside the new digest. It concluded in 13 steps with one note where it previously took 21 and
wrote two, and the three citations it lost are the ones the second note carried. A better
starting list appears to have made it stop sooner, and stopping sooner cost it evidence.

**Caveats, both load-bearing.** One run per arm, on a loop whose run-to-run spread has never
been measured — a three-check swing is not distinguishable from noise at n=1. And every run in
the new arm lost its critique to the free tier's 20-requests-per-day cap on `gemini-3.5-flash`
(the first two to a 503 before that). The critique writes only to the adversarial tables, never
to notes, so no scored check can move because of it — but "the investigation was scored, the
critique never ran" is what these five runs are.

The honest reading: the ranking demonstrably fixed what it was built to fix — the model now
starts from the evidence, converges more often, and costs 28% less — and the scorecard total is
unchanged, because it was never a measurement of where the search started.

## Three runs per case: what was signal and what was one lucky run

The comparison above is one run against one run. Repeating it three times per case, loop model
only (`--runs 3 --no-adversarial`, 1.77M tokens), separates the two.

| case | recorded n=1 | first re-run n=1 | three runs | spread |
|---|---|---|---|---|
| pytest-pandas | 11/13 | 7/13 | 7, 7, 7 | **none** |
| mypy-pandas | 11/13 | 11/13 | 8, 8, 11 | 3 |
| lint-react | 10/12 | 10/12 | 10, 10, 11 | 1 |
| cargo-tokio | 8/14 | 9/14 | 8, 9, 7 | 2 |
| jest-nextjs | 5/12 | 8/12 | 8, 8, 8 | **none** |
| **total** | **45/64** | **45/64** | **mean 42.3/64** | |

The two cases the ranking change actually moved are the two with **zero** spread, which is the
result. `jest-nextjs` writes two notes and cites `fatal: detected dubious ownership` in three
runs out of three — against a recorded run that wrote nothing at all in 21 steps. `pytest-pandas`
scores 7/13 in three runs out of three, having scored 11/13 before. Neither is the model varying.

The middle three vary by one to three checks, which is the number to keep in mind before
reading anything into a single run — including the two single runs above. The old arm's own
spread was never measured, so the totals are not comparable; the per-case zero-spread results
are.

## Why pytest-pandas lost four checks

Not a search failure and not variance. Its scratchpad says exactly what happened:

* the **signal set is ranks 1-5**, and the run **cited all five** — the coverage nudge fired and
  was satisfied;
* the three missed markers sit at ranks **16, 20 and 20** — inside the 40-template digest, and
  outside the signal set, so nothing ever asked about them;
* ranks 1-5 are all single-occurrence **banner lines**: `==== ERRORS ====`,
  `=== FAILURES ===`, `= 45 failed, 162298 passed, ... =`,
  `##[error]Process completed with exit code 1.`

A pytest banner is rare, bursty, and contains the word ERROR, so it takes the maximum of all
three terms. The old ranking failed randomly; this one fails **systematically, towards section
headers about errors rather than the errors themselves**. The model then concludes from the
summary — true, and shallower than the ground truth wants.

The coverage nudge fired on **15 runs out of 15**, so it is now part of the normal path rather
than a backstop, and on this case it enforced the wrong five templates.

## The banners were a symptom: one occurrence is not a burst

Two fixes were proposed from the paragraph above, implemented, measured across all twenty cases,
and **both rejected**. A correction first: the claim that the signal cut *landed inside* a tie
was wrong. The largest-gap rule put the cut at exactly the end of the tied block, which is what
it is supposed to do. What is true is worse -- **the tied block itself is enormous**: 507 of
`jest-nextjs`'s 9,307 templates share the top score, so its entire 40-template digest came from
inside one flat block, ordered by template id, which is first-seen order.

Measured at three depths, 65 markers:

| variant | top 5 | top 10 | top 40 |
|---|---|---|---|
| neither | 16 | 24 | 41 |
| discount mostly-punctuation templates | 15 | 23 | 40 |
| break ties by recency instead of id | 14 | 25 | **48** |
| both | 13 | 24 | 47 |
| **one occurrence is not bursty** | **21** | **27** | 42 |

* The **punctuation discount** removes banners from the top five, which was its purpose, and
  costs a marker at every depth. Nothing free supports it.
* The **recency tie-break** wins at 40 and is a trap: it moves `jest-nextjs`'s root cause,
  `fatal: detected dubious ownership`, from rank 3 to rank **504** -- out of the digest. That is
  the marker three runs out of three cited. It is a git checkout failure near the *start* of a
  build, and "prefer the end of the file" is precisely wrong for it.

Asking why the ties existed found the actual defect. Burstiness is
`max_per_bucket / (count / total_buckets)`, so a template that fired **once** divides by a mean
of `1/total_buckets` and scores `1 - 1/total_buckets`: maximal burstiness, for every singleton
in the file. Not a measurement -- an artefact of the denominator, and the thing that fuses the
top of the ranking into one tie.

A single occurrence now scores zero burstiness, and that alone does everything the two rejected
fixes were meant to do. Measured through `mistify eval --digest` on all twenty cases:

| depth | before | after |
|---|---|---|
| top 5 | 14 | **19** |
| top 10 | 22 | **26** |
| top 20 | 35 | 35 |
| top 40 | 39 | 40 |

Depth 40 is a wash; the evidence moves *up*, which is the half that matters -- the set the
coverage nudge enforces is five templates, not forty. `pytest-pandas`'s top five is now five
lines that each name a failing test, with no banners in it: the punctuation discount was
redundant, because banners only ever ranked through the artefact. `jest-nextjs` keeps its root
cause in the digest (3 to 12) and gains a second marker (510 to **3**).

Not free of losses: `lint-react` (140,144 to 161,165) and `tsc-typescript` (167 to 192) sink
further. Both are cases whose evidence is worded calmly and was already far outside the digest.

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
