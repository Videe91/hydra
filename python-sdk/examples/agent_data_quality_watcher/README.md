# Demo Agent 1 — Data Quality Incident Watcher

The first demo agent in the Hydra examples. ~150 lines of Python that prove Hydra is a *living database*, not just an event log.

> **The living loop:** observe → evidence → claim → action → explain

## The story

Snowflake reports that `orders.customer_id` suddenly has **38% nulls** (vs. a 2% baseline). Five seconds later, the agent has:

1. **Observed** the spike as a `warehouse.null_spike` Signal.
2. **Recorded** the metric reading as Evidence with reliability 0.94.
3. **Proposed** the Claim that the `orders` table has a data-quality incident (kind `AnomalyFinding`, confidence 0.91), supported by the evidence.
4. **Proposed** a `Quarantine` Action against the dataset, related to the claim.
5. **Asked Hydra to explain** the chain — *one* `hy.lineage(seed_event_id)` call returns every record that descended from the original signal, plus a server-rendered prose summary.

That last step is the "aha." Four independent Python calls left behind a causal chain Hydra can replay on demand.

## Run it

You need a running Hydra engine. From the repo root:

```bash
cargo run -p hydra-api  # or whatever binary you boot Hydra with
```

Then:

```bash
cd python-sdk
pip install -e ".[dev]"
python examples/agent_data_quality_watcher/data_quality_watcher.py
```

If your engine isn't at `http://localhost:8080`, set the env vars:

```bash
HYDRA_BASE_URL=http://hydra.internal:8080 \
HYDRA_TOKEN=your_bearer_token \
HYDRA_TENANT=tenant_demo \
python examples/agent_data_quality_watcher/data_quality_watcher.py
```

## Expected output

```
Hydra Data Quality Watcher
  base_url = http://localhost:8080
  tenant   = tenant_default

Observed:
  warehouse.null_spike on snowflake.prod.orders.customer_id
  seed event id: evt_01J9XYZ...

Evidence:
  evd_orders_customer_id_null_spike
  reliability: 0.94

Claim:
  claim_orders_customer_id_corrupted
  confidence: 0.91

Action proposed:
  act_quarantine_orders
  kind: Quarantine

Explanation:
  Seed event: signal: warehouse.null_spike. Recorded 1 evidence
  record(s) (metric_observation). Produced 1 claim(s)
  (has_data_quality_incident=Proposed). Resulted in 1 action(s)
  (Quarantine(Proposed)).

Causal chain:
  events:    1
  evidence:  1
  claims:    1
  actions:   1

Diagnostics:
  anomalies: 0
  coverage:  0 model(s) (complete)
  counterfactual magnitude: 1.0
```

The exact event id and counterfactual magnitude will differ; the structure won't.

## Files in this demo

```
agent_data_quality_watcher/
├── README.md                  ← this file
├── data_quality_watcher.py    ← the agent (~150 lines)
└── sample_incident.json       ← the synthetic null-spike payload
```

## What this demo proves

Hydra is not just storing events. It's storing:

- *why* the event mattered — Evidence ties data observations to events
- *what belief* was formed — Claims encode confidence and provenance
- *what action* followed — Actions reference the claims that motivated them
- *how to explain* the chain — Lineage replays the loop on demand

That is what makes Hydra a *living* database for agentic AI: an agent can act, and weeks later another agent (or a human) can ask "why did this happen?" and get a complete, causally-linked answer.

## How the chain is wired

Hydra's lineage walker discovers downstream records by following two graphs:

1. **Event → Event** via `Event.caused_by` (BFS through the cascade tree).
2. **Record → Event** via each Evidence/Claim/Action's own `caused_by: Option<EventId>` field — the *enrichment* scan filters every store's records by "was this record caused by an event in the lineage?"

The agent's four ingest calls land in four separate cascades, so the *event* tree is just `[seed]`. But each downstream record is threaded back to the seed via `caused_by=seed_event_id`, so the enrichment scan finds them. The SDK exposes this via:

```python
hy.add_evidence(..., caused_by=seed_event_id)
hy.propose_claim(..., caused_by=seed_event_id)
hy.propose_action(..., caused_by=seed_event_id)
```

Real agents that ingest a cascade in *one* call (via a custom Event with multiple reactions) wouldn't need this manual threading — the cascade engine assigns `caused_by` itself. The pattern in this demo is the easiest way to get the loop visible end-to-end with four separate, idempotent agent calls.

## What's next

The current demo runs **once**. The agent observes, decides, proposes, explains, and exits. The next demo upgrade turns it into a long-lived watcher:

```python
# Future: hy.subscribe_commits()
async for batch in hy.subscribe_commits(after_sequence=...):
    for event in batch.events:
        if matches_data_quality_signal(event):
            agent_react(event)
```

That requires a `GET /commits/stream` SSE endpoint on the engine and an `hy.subscribe_commits()` method in the SDK — both intentionally out of scope for this demo. This patch ships the run-once loop so the *visible* "aha" lands first; the always-on watcher follows once the substrate exists.

## Caveats

- This is a **demo**, not a production agent. Real production agents would mint unique IDs, handle re-runs more carefully, retry transient failures, and proxy through an approvals workflow before any Quarantine action gets promoted past `Proposed`.
- The action is intentionally left in `Proposed` state. Hydra has the vocabulary for `Approved` / `Executed` / `Failed`, but those transitions belong to a separate operator (a human, or a policy agent). This demo stops at "propose remediation" because that's where most well-behaved agents should stop.
- The diagnostics bonus pass is best-effort. If your engine has no anomaly rules or coverage models registered, those endpoints return empty responses — the demo prints "0 anomalies" and "complete" coverage. That's fine.
