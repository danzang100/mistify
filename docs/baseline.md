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

## Deterministic — expect these to be identical

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

## Model-driven — expect these to move

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
file. The three changes together — 60-line slices instead of 200, tool output older than three
steps reduced to its summary line, and the withheld-line count that makes a smaller slice safe
to ask for — brought it to 48,370.

**The curve bends down.** Input per step rises to 6,782 at step seven and then *falls*, because
compaction is retiring older tool output faster than new output arrives. Before this, the
series only ever rose. That is the difference between a loop whose cost is quadratic in steps
and one that is roughly flat, and it is what decides whether a long investigation is affordable.

**Cache reads are zero, and that is a real trade.** Compaction rewrites messages near the front
of the conversation, which is exactly the prefix a provider's implicit cache keys on, so the
cache never hits. Earlier runs saw 36–37% cache reads on a much larger prompt. Cutting absolute
tokens by 3.7× wins by a wide margin over discounting a prompt four times the size — but the
two could be had together by compacting in batches, so the prefix stays stable for several
steps instead of changing on every one. Not done; worth doing.

**The adversarial pass earned its keep on this run.** The investigation cited log events 1 and 2
for a claim about checkout-service credentials; those rows are unrelated payment-service and
inventory-service lines. The critique caught it, the investigation conceded, and the report
leads with *Contested* and a confidence revised from high to medium. The deterministic citation
resolver could not have caught this — the ids exist, they just do not say what the note claims,
which is the semantic half of decision G8 and is exactly what the second model is for.

**One acute template is genuinely unexplained.** Template 7 — connection acquisition delays for
seven minutes before the outage — is signal, is within the event, and no note mentions it. That
warning is now worth reading, which it was not while it fired on the two chronic templates
every single run.
