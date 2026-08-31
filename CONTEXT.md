# Mistify

Takes heterogeneous incident logs, compresses them into a representation an LLM can search
without losing the rare signal, and drives a bounded investigation over that representation.

## Language

### The incident

**Incident**:
One investigation, keyed by an incident id and backed by exactly one scratchpad. Comes into
existence at ingestion, not before.
_Avoid_: case, run, job

**Scratchpad**:
The per-incident SQLite database that is the working memory of the whole system. Every stage
writes here and the investigator reads here rather than re-reading the source.
_Avoid_: database, store, cache

**Log record**:
One normalised line. Carries both the source line as it arrived and the free-text portion
templating clusters on; those are different things and are never conflated.
_Avoid_: entry, event (an event is the persisted row, a record is the in-flight object)

### Compression and search

**Template**:
A mined message shape standing in for every line that matches it. The template list is the
investigator's search space, so its length is what "compression" is actually for.
_Avoid_: cluster, pattern (pattern is the template's text, not the template)

**Signal**:
The templates an investigation is expected to account for. Determined by anomaly score, cut
where the score distribution separates rather than at a fixed threshold.
_Avoid_: finding, hit

**Noise**:
A template that is both a large share of the incident and low-scoring. Volume alone is not
noise; a flood can be the incident.
_Avoid_: chatter, spam

**Anomaly score**:
A per-template number derived from the incident's own distribution — severity, burstiness and
rarity — computed without any model involvement, so ranking is independent of whatever
narrative an investigation settles on.
_Avoid_: severity score, priority, weight

**Coverage**:
The share of events reachable through a template. The invariant of the templating stage: an
event whose template is missing is a line no template search can surface.
_Avoid_: completeness, recall

**Calibration**:
Choosing a clustering threshold by measuring candidates against a sample, rejecting any that
merge distinct conditions and preferring whichever leaves the fewest templates.
_Avoid_: tuning, optimisation

### Redaction

**Placeholder**:
The stable token a redacted value is replaced by. The same source value always yields the same
placeholder within an incident, so correlation survives redaction.
_Avoid_: mask, token, hash

**Vault**:
The opt-in record of which value each placeholder stands for. Lives in its own file, never in
the scratchpad, so the investigator's read-only channel cannot reach it.
_Avoid_: keystore, lookup table

### Running the pipeline

**Adapter**:
A format-specific parser producing log records. Knows one source format and nothing about
redaction, templating or the scratchpad.
_Avoid_: parser, reader, driver

**Bootstrapper**:
The fallback that infers a parse for a format no adapter claims, rather than failing ingestion.
_Avoid_: sniffer, detector (detection is choosing among known adapters; bootstrapping is
inferring an unknown one)

**Investigator**:
Whatever produces the notes an incident report is built from. Names which one ran, because a
heuristic and a model-driven loop must not be presented as the same thing.
_Avoid_: agent, analyser

**Health metric**:
A single named number or flag a stage publishes about its own run, so a degraded run is
visible rather than inferred from a report that reads fine. Belongs to the stage that
publishes it, not to whoever renders it.
_Avoid_: stat, telemetry, log

**Load-bearing metric**:
A health metric some reader acts on, as opposed to one that is only displayed. The distinction
matters because renaming the first silently disables behaviour and renaming the second does
not.
_Avoid_: important metric, key metric
