# Baseline run

The reference numbers for `examples/sample_incident.jsonl`. Recorded 2026-09-01, immediately
after the token-growth work landed, so later changes have something to be compared against
rather than being argued about from memory.

Reproduce with:

```bash
uv run mistify run --source examples/sample_incident.jsonl --incident-id baseline
```

Provider Gemini, `gemini-3.5-flash-lite` for the loop and `gemini-3.5-flash` for the critique.
The deterministic half of the pipeline is identical on every run; only the model-driven half
moves, so those rows are the ones worth comparing.

## Deterministic - expect these to be identical

| | |
|---|---|
| Events ingested | 4,946 |
| Templates | 9 |
| Template coverage | 1.0 |
| Compression ratio | 0.00182 |
| Calibrated `sim_th` | 0.5 |
| Redactions | 7,282 (6,226 ipv4, 1,044 email, 12 api_key) |
| Needle position | 1 |
| Signal templates | 5 |
| Chronic among them | 2 (templates 5 and 6) |

## Model-driven - expect these to move

| | Baseline |
|---|---|
| Steps | 9 |
| Tool calls | 8 |
| Notes written | 1 |
| Outcome | converged |
| Loop tokens (in / out) | 46,648 / 393 |
| Critique tokens (in / out) | 1,009 / 320 |
| **Total** | **48,370** |
| Input per step | 1902, 4303, 4814, 4919, 6415, 6728, 6782, 5661, 5124 |
| Input growth factor | 2.69× |
| History compactions | 5 |
| Objections raised | 1 |
| Conceded | 1 |
| Unrebutted at high severity | 0 |
| Unexplained acute templates | 1 |
| Unexplained chronic templates | 2 (observation, not a warning) |

## What the numbers say

**Cost fell 3.7×.** The run immediately before this work totalled 180,707 tokens for the same
file. The three changes together - 60-line slices instead of 200, tool output older than three
steps reduced to its summary line, and the withheld-line count that makes a smaller slice safe
to ask for - brought it to 48,370.

**There was no regression, and two earlier readings of this were wrong.** This document first
guessed the baseline run's thinner investigation was model noise, then claimed a measured
regression against it. Both were artefacts of comparing two different things: the "before"
figure counted templates the model *named in prose*, the "after" figure counted templates it
*cited*. Those disagree in almost every run.

Measured properly across nine runs: template 7 is cited by none of them, and was cited by none
of the runs before the cost work either. The model consistently cites the templates its claim
is chiefly about - 8 and 9, in all nine runs - and omits the one it names as context. Three of
the nine name template 7 in the finding's prose while citing only 8 and 9.

So the standing defect is under-citation, not a lost precursor and not compaction. The loop's
prompt now asks for every template a note names to appear in its citations. That is untested:
the runs below predate it.

**`ELIDE_MIN_LINES` is kept, on narrower evidence than it was introduced with.** Results at or
below twenty lines are no longer compacted. The justification is not the precursor story, which
did not hold: it is `rep5`, which re-queried templates 7, 5 and 6 at steps 14–16 after reading
all three at steps 3, 6 and 7 - compaction had elided them, so the run paid twice. Whether the
exemption improves conclusions is unproven, and it did not reduce tokens: the three runs after
it span 54k–89k against 40k–99k before.

**The curve bends down.** Input per step rises to 6,782 at step seven and then *falls*, because
compaction is retiring older tool output faster than new output arrives. Before this, the
series only ever rose. That is the difference between a loop whose cost is quadratic in steps
and one that is roughly flat, and it is what decides whether a long investigation is affordable.

**Cache reads are zero, and that is a real trade.** Compaction rewrites messages near the front
of the conversation, which is exactly the prefix a provider's implicit cache keys on, so the
cache never hits. Earlier runs saw 36–37% cache reads on a much larger prompt. Cutting absolute
tokens by 3.7× wins by a wide margin over discounting a prompt four times the size - but the
two could be had together by compacting in batches, so the prefix stays stable for several
steps instead of changing on every one. Not done; worth doing.

**The adversarial pass earned its keep on this run.** The investigation cited log events 1 and 2
for a claim about checkout-service credentials; those rows are unrelated payment-service and
inventory-service lines. The critique caught it, the investigation conceded, and the report
leads with *Contested* and a confidence revised from high to medium. The deterministic citation
resolver could not have caught this - the ids exist, they just do not say what the note claims,
which is the semantic half of decision G8 and is exactly what the second model is for.

**One acute template is genuinely unexplained.** Template 7 - connection acquisition delays for
seven minutes before the outage - is signal, is within the event, and no note mentions it. That
warning is now worth reading, which it was not while it fired on the two chronic templates
every single run.

## Repeat protocol

Cost that buys a worse answer is not a saving, so the quality metric is checked alongside the
token count. Five runs, distinct incident ids:

```bash
for i in 1 2 3 4 5; do uv run mistify run --source examples/sample_incident.jsonl --incident-id rep$i; done
```

Score each report on four questions the fixture already answers:

| Question | Where to look | Pass |
|---|---|---|
| Does a finding cite the pool exhaustion? | *What was found* | template 9 in the citations |
| Does a finding cite the precursor? | *What was found* | template 7 in the citations |
| Does a finding *name* the precursor at all? | *What was found* | "template 7" in the prose |
| Is the red herring kept out of the causal story? | *What was found* | template 5 absent, or marked background |
| Are all cited event ids real *and* relevant? | *The challenge* | no conceded citation objection |

Citation and prose mention are scored separately and must stay that way. Conflating them is
what produced two wrong conclusions in this document: the model routinely names a template it
does not cite, so reading one number and reporting the other invents a change that never
happened.

Then compare tokens and `input_growth_factor` against the table above. Report the median, not
the best run: the failure mode being watched for is a wide spread, and a single good run hides
it.

Two of these are cheap to automate later and one is not. The first three resolve against
template ids the fixture plants at known positions; the fourth needs a judge, which is the
Phase 5 eval harness and not this.

## Measured, nine runs

All nine post-date the cost work. `baseline` is the reference run; `rep1`–`rep5` the first
repeat batch; `fix1`–`fix3` after `ELIDE_MIN_LINES` landed. Every one of the nine cited
templates 8 and 9, recorded exactly one note, and was not budget-limited.

| | Result |
|---|---|
| Cites the root cause (t9) | 9/9 |
| Cites the precursor (t7) | 0/9 |
| Names the precursor in prose | 3/9 |
| Keeps the red herring out | 9/9 |
| No conceded citation objection | 8/9 |
| Notes recorded | 1 in all nine |
| Loop tokens | 40k–99k |

Two things worth keeping from the batch. `rep5` tried to cite log events 1054 and 1154, which
it had never been shown, was refused by `write_note`, re-queried for real ids and cited those -
the citation gate doing exactly what it was added for. And three of five runs in the first
batch died on a 429: the free tier allows 15 requests per minute for `gemini-3.5-flash-lite`, a
failed request counts against it, and the adapter was backing off on a guess capped at 30s
while the API returned `retryDelay: '54s'` in the error body. Both fixed.

The one note per run is the open question. The three runs before the cost work recorded two or
three notes each; all nine since record one. That is a real difference on a small sample, and
it is confounded - the prompt changed as well - so it is not yet a finding.

## The coverage nudge

Eleventh run, after `unexplained_signal_templates` moved from the adversarial pass into the
loop:

| | Before (10 runs) | `nudge1` |
|---|---|---|
| Cites the precursor (t7) | 0/10 | yes |
| Notes recorded | 1 | 2 |
| Unexplained signal templates | 1 | 0 |
| Warnings in the report | 1 | none |
| Steps / tool calls | 8–20 / 8–19 | 14 / 12 |
| Loop tokens | 40k–99k | 64k |

The nudge fired once and the model answered it with a second note citing templates 7 and 9.
That is the first report this project has produced with no warnings.

One run. A single positive against a baseline of ten consecutive negatives is strong evidence
the behaviour changed, and no evidence about how often it holds. Two confirmation runs are
owed before this number goes in the table above.

## First harness sweep

`mistify eval --case quiet-hour --runs 3`, loop on `gemini-3.5-flash-lite`, critique on
`gemini-3.6-flash`, synthesis off.

| | |
|---|---|
| citations-resolve | 3/3 |
| invents-no-incident | **0/3** |
| Coverage nudges fired | 0 |
| Tokens | 35k, 62k, 87k |

**The 0/3 is not the finding it looks like, and the bar is wrong.** Run 3 wrote: *"The incident
consists entirely of routine operational warnings and background telemetry ... without any
critical errors, fatal exceptions, or unexpected service outages."* That is the correct answer.
It failed only because it was recorded at high confidence, and being confident that nothing is
wrong is exactly what should happen here.

Run 1 is the genuine miss: *"intermittent performance degradation ... two primary anomalous
behaviors ... minor resource contention or degraded upstream inventory performance"* - retries
and slow responses reframed as degradation, hedged but wrong. Run 2 sits between them.

So the deterministic bar conflates two opposite outcomes. Confidence is a property of how the
finding was stated; whether it asserts a fault is a property of what it says, and no threshold
over the scratchpad can separate them. The check needs a judge asking one question - *does this
finding assert that something is wrong?* - which is a different question from the entailment
judge already behind `--judge`.

Worth keeping from the sweep: the coverage nudge did not fire once, which is correct. Every
template on a quiet file spans the whole hour, so all of them are chronic, and chronic templates
are excluded from the unexplained-signal check. The exclusion added for the pool-exhaustion case
turns out to be what keeps the negative control quiet as well.

## The grep baseline

`mistify eval --baseline templated` - no model calls, scored by the same checks as an agent
run, because comparing a number to an anecdote is not a comparison.

Two opponents. **naive** is the literal pipeline: severity-keyword filter, group identical
lines, rank by count. **templated** concedes this project's own clustering to the baseline
before ranking, which asks the harder question - does the *investigation* add anything beyond
ranking error-level templates by frequency?

| Check | grep (naive) | grep (templated) | agent |
|---|---|---|---|
| cites the root cause | 0/1 | 0/1 | 11/11 |
| cites the precursor | 0/1 | 0/1 | 1/11 |
| does not lead with the herring | 0/1 | 0/1 | 11/11 |
| quiet hour: invents nothing | 1/1 | 1/1 | 0/3 |
| Tokens | 0 | 0 | 35k–99k |

**The two fail in opposite directions, and that is the finding.** On the incident, grep matches
396 lines and leads with the red herring in both variants - 350 payment-gateway timeouts drown
40 pool exhaustions, which is exactly what the fixture was built to provoke. The agent never
once led with the herring and always cited the root cause. On the quiet hour, grep matches
nothing, writes nothing, and wins outright; the agent wrote a confident finding all three times.

So the model calls buy discrimination on a real incident, and cost restraint on a quiet one.
That is a defensible trade to state out loud, and it is the first time this project has had a
floor to measure against rather than only a ceiling.

One correction worth recording. The first version filtered the *extracted message* and found
six matching lines on a file with 396 at ERROR or above, because the JSON fixture carries
severity in a `level` field the message text never mentions. That baseline scored better than
it deserved on the herring check and flattered the agent. `grep` reads the raw line, so the
filter now does too.
