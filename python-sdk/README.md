# hydra-py

Python client for [Hydra](https://github.com/Videe91/hydra) — the programmable living database for agentic AI systems.

Hydra is more than a graph store: it observes (signals), remembers (events), reasons (claims + evidence), reacts (actions + outcomes), and explains (lineage + diagnostics). `hydra-py` is the Python surface that makes those primitives feel native to an agent.

```python
from hydra import HydraSync, ClaimSubject, ClaimObject, EvidenceSource

with HydraSync("http://localhost:8080", token="...", tenant="tenant_default") as hy:
    hy.add_evidence(
        evidence_id="evd_001",
        source=EvidenceSource.warehouse(system="snowflake", table="orders"),
        payload_kind="row_count_delta",
        payload_data={"delta": -42},
        reliability=0.9,
    )
    hy.propose_claim(
        claim_id="claim_001",
        subject=ClaimSubject.dataset("revenue_daily"),
        predicate="is_stale",
        object=ClaimObject.value(True),
        created_by="actor_agent",
        kind="AnomalyFinding",
        confidence=0.91,
        evidence_for=["evd_001"],
    )
    lin = hy.lineage("evt_001")
    print(lin.explanation_summary)
```

## Install

```bash
pip install hydra-py
```

Local development:

```bash
pip install -e ./python-sdk
```

Requires Python 3.10+. Dependencies: `httpx>=0.27`, `pydantic>=2.5`.

## Two clients, one surface

`hydra-py` ships an async client (`Hydra`) and a sync mirror (`HydraSync`) with method-for-method parity. They share every wire type, every error class, every namespace.

### Async — for agent loops, FastAPI, anyio

```python
import asyncio
from hydra import Hydra

async def main():
    async with Hydra("http://localhost:8080", token="...", tenant="t") as hy:
        resp = await hy.ingest_signal(name="cloudtrail/CreateBucket", source="node_aws")
        print(resp.event_ids)

asyncio.run(main())
```

### Sync — for scripts, Jupyter, threaded servers

```python
from hydra import HydraSync

with HydraSync("http://localhost:8080", token="...", tenant="t") as hy:
    resp = hy.ingest_signal(name="cloudtrail/CreateBucket", source="node_aws")
    print(resp.event_ids)
```

**When to pick which.** Use `Hydra` if your code is already inside an event loop. Use `HydraSync` from notebooks (Jupyter runs its own kernel loop — nested `asyncio.run` will raise), from scripts, and from threaded WSGI/Flask. The sync client is a real sync implementation (`httpx.Client`), not an `asyncio.run` wrapper, so it works in any context.

## Concepts at a glance

Hydra's vocabulary maps to four SDK verbs you'll use constantly:

| Hydra concept | What it is | SDK method |
|---|---|---|
| **Signal** | "I observed something." | `ingest_signal(name, source=..., payload=...)` |
| **Evidence** | "Here's the data I observed." | `add_evidence(evidence_id, source=..., payload_kind=..., reliability=...)` |
| **Claim** | "I believe X is true (with confidence c)." | `propose_claim(claim_id, subject=..., predicate=..., object=..., kind=..., confidence=...)` |
| **Action** | "Take this step in the world." | `propose_action(action_id, kind=..., targets=..., proposed_by=...)` |

The full agent loop is **observe → support → propose → act → explain**. Lineage lets you trace any event back to the signals and claims that caused it.

## Method index

### Top-level (`hy.*`)

```
ingest_signal             propose_claim          add_evidence         propose_action

get_node                  get_edge               get_event            get_claim
get_evidence              get_action

list_claims               list_claims_for_subject
list_claims_for_evidence  list_actions           list_outcomes_for_action

lineage(event_id, depth=...)
```

### Diagnostics namespace (`hy.diagnostics.*`)

```
anomaly(severity_min=..., kind=..., limit=...)
coverage(model=..., failing_only=..., limit=...)
counterfactual(event_id, include_diff=...)
evolution(subscription_id=..., min_fires=..., include_logs=..., limit=...)
```

### Schemas namespace (`hy.schemas.*`)

```
list_active / list_disabled / list_archived
get_entity / get_edge / get_evidence / get_claim_predicate / get_action / get_policy
register_entity / register_edge / register_evidence / register_claim_predicate
register_action / register_policy_condition
disable(schema_id, reason=...) / archive(schema_id, reason=...)
validate_action / validate_evidence / validate_claim
validate_node_create / validate_node_update
validate_edge_create / validate_edge_update
```

`validate_policy` is intentionally deferred to a future patch alongside the full Policy surface.

### Replication namespace (`hy.replication.*`)

```
status()                       # cluster head + peers
peers()                        # all registered peers
peer(peer_id)                  # single peer (404 on miss)
peer_lag(peer_id)              # observed lag; never 404s — None = no data
role()                         # "leader" | "follower"
promotion_status()             # durable promotion audit
```

Write routes (`POST /replication/role`, `POST /replication/promote`, `POST /replication/apply`) and puller-internal routes (`/replication/commits`, `/replication/snapshot/*`) are not exposed in v0 — operator UX surfaces only.

## Errors

Eight typed exception classes, all subclasses of `HydraError`:

| Class | HTTP status | When |
|---|---|---|
| `HydraValidationError` | 400 | Malformed request, schema violation at register time |
| `HydraAuthError` | 401, 403 | Missing/invalid bearer, insufficient scope |
| `HydraNotFoundError` | 404 | Unknown id (node/edge/event/claim/...) |
| `HydraReadOnlyFollowerError` | 409 | Write attempted on a follower |
| `HydraRateLimitedError` | 429 | Rate limit |
| `HydraServerError` | 5xx | Engine bug, ledger error |
| `HydraConnectionError` | (none) | TLS/DNS/timeout — Hydra never replied |
| `HydraError` | * | Catch-all base |

Every exception carries `.status_code`, `.body` (parsed JSON or raw text), and `.url`.

**Validation methods are different.** `hy.schemas.validate_action(...)` and friends return a `ValidationResponse` with `.valid: bool` and `.errors: list`. They do **not** raise on `valid: False` — schema mismatch is the engine's correct verdict, not a transport error.

## Tenant + idempotency

Every method accepts a per-call `tenant=` to override the client default (design rule #7):

```python
await hy.get_node("node_x", tenant="tenant_other")
```

Every ingest method accepts `idempotency_key=`:

```python
await hy.ingest_signal("x", source="node_y", idempotency_key="dedup_key_001")
```

The key is sent as the `Idempotency-Key` HTTP header; the engine short-circuits duplicates.

## Token redaction

Bearer tokens never appear in `repr(hy)`, `str(hy)`, or `print(hy)`. If an uncaught exception's traceback includes locals, the token still doesn't leak.

```python
hy = HydraSync("http://x", token="secret_pat_abc123")
print(hy)
# HydraSync(base_url='http://x', tenant=None, token=<set>)
```

## Examples

Four runnable scripts in [`examples/`](./examples) that exercise the full surface against a local Hydra:

- [`01_ingest_and_lineage.py`](./examples/01_ingest_and_lineage.py) — ingest a signal, fetch its lineage
- [`02_belief_loop.py`](./examples/02_belief_loop.py) — evidence → claim → action → outcome
- [`03_schema_register_and_validate.py`](./examples/03_schema_register_and_validate.py) — register an entity schema, preflight-validate a payload
- [`04_replication_status.py`](./examples/04_replication_status.py) — poll replication status, peer lag, promotion-status

Each is ~40-80 lines and assumes Hydra is reachable at `http://localhost:8080`. Run with `python examples/01_ingest_and_lineage.py`.

## Known v0 limitations

- **First-page-only pagination.** `list_claims()` and `list_actions()` without a filter hit the paginated `/query/claims` and `/query/actions` routes and return only the first page. Use the filter variants (`list_claims(status=...)`, `list_actions(status=...)`) for the full result set. A pagination wrapper lands in a post-1.0 patch.
- **`validate_policy` deferred.** Requires the full Policy surface, which lands in a future patch.
- **No retries.** Design rule #5 — every call is one HTTP attempt. If you need retries for transient failures, layer them above the SDK using your preferred policy.
- **No local caching.** Design rule #6 — every method call hits the engine.
- **`SchemaDefinition` list endpoints return `list[dict]`.** Entity and edge schemas share the same field shape on the wire; the SDK doesn't fake a discriminated type. Use the typed `get_entity` / `get_edge` for known-variant cases.

## Design rules

This SDK was built against twelve immutable rules ([HYDRA_SDK_DESIGN_RULES.md](../HYDRA_SDK_DESIGN_RULES.md) at the repo root). The big ones:

1. Semantic method names, not endpoint mirrors.
2. Transport DTOs mirror the wire format exactly.
3. Async-first (sync mirror is provided).
4. All public methods fully typed.
5. No hidden retries.
6. No local caching.
7. Tenant override always available.
8. Server errors preserved verbatim.
9. No raw HTTP escape hatch.
10. One client class per Hydra connection.
11. Backward compatibility is a load-bearing promise.
12. Errors are typed, not stringly-typed.

## Development

```bash
cd python-sdk
pip install -e ".[dev]"
pytest
ruff check src tests
mypy src
```

The test suite mocks the engine via [respx](https://github.com/lundberg/respx) — no running Hydra needed. Both `Hydra` and `HydraSync` are exercised; sync-specific tests live in `tests/test_sync_*.py`.

## License

MIT.
