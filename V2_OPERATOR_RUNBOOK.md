# Hydra V2 — Operator Runbook

*Manual failover, not Raft. The operator is the consensus.*

This runbook covers the operational workflows for a Hydra V2 cluster: starting nodes, promoting a follower, recovering an old leader, re-pointing followers, verifying lag, and avoiding split-brain. It assumes you've built the binary or are embedding `hydra-api`'s `serve_with_security` in your own process.

V2 has **no automatic election, no quorum, no consensus**. Promotion is an explicit HTTP call. Cluster topology changes are explicit operator actions. The system is designed to never silently corrupt — the cost is that operators do the coordination.

---

## Quick reference — admin HTTP routes

| Verb + Path | Purpose | Scope |
|---|---|---|
| `GET /replication/status` | Cluster head + role + peers | `read:replication` |
| `GET /replication/role` | Current HTTP role of this node | `read:replication` |
| `GET /replication/peers` | All registered peers | `read:replication` |
| `GET /replication/peers/:peer_id/lag` | Observed lag for a peer | `read:replication` |
| `GET /replication/promotion-status` | This node's promotion audit | `read:replication` |
| `POST /replication/role` | Flip role at runtime | `admin:replication` |
| `POST /replication/promote` | Promote this follower to leader | `admin:replication` |
| `POST /replication/apply` | Apply leader-supplied commits (follower-internal) | `admin:replication` |
| `GET /metrics` | Prometheus metrics | (none by default; operator can gate) |

Every route uses bearer auth (`Authorization: Bearer <token>`) when auth is enabled. Token scopes must include the one listed above.

---

## 1. Start a leader

Default Hydra is already a leader — no special config required if your topology has only one writer.

```rust
use hydra_api::{ServerSecurityConfig, AuthConfig, serve_with_security};
use hydra_net::role::RuntimeRole;
use hydra_core::ReplicaId;

let security = ServerSecurityConfig::with_auth(auth)
    .with_role(RuntimeRole::Leader)                         // default; explicit for clarity
    .with_self_peer_id(ReplicaId::from_str("replica_node_a")); // required if you ever want
                                                              // to promote on a different node

serve_with_security(runtime, "0.0.0.0:8080", security).await?;
```

**Key choices**:
- `with_self_peer_id` is optional for a leader but recommended — without it, no follower in this cluster can ever promote a node *to* this id later (mismatch). Set it once at cluster design time and keep it stable.
- If you plan to add followers later, register them on the leader once they're up — see *Register a follower* below.

**Sanity check after boot**:
```bash
curl -H 'Authorization: Bearer <token>' http://leader:8080/replication/status
# → {"role":"Leader","head_sequence":0,"head_commit_id":null,"peers":[]}

curl -H 'Authorization: Bearer <token>' http://leader:8080/replication/role
# → {"role":"leader"}
```

---

## 2. Start a follower

A follower needs:
- HTTP role = `Follower` (so the role middleware rejects mutating routes)
- Engine role = `Follower` (so in-process ingest is rejected — defense-in-depth)
- A `ReplicationServerConfig` so the puller auto-spawns
- `self_peer_id` (required if you ever want to promote this follower)

```rust
use hydra_api::{ServerSecurityConfig, ReplicationServerConfig, serve_with_security};
use hydra_net::replication_worker::ReplicationPullerConfig;
use hydra_net::role::RuntimeRole;
use hydra_core::{ActorId, ReplicaId};
use std::path::PathBuf;

// Set engine role to Follower BEFORE the server starts.
{
    let hydra = runtime.hydra();
    let mut hydra = hydra.write().await;
    hydra.set_role(hydra_engine::prelude::EngineRole::Follower);
}

// Puller config — pulls from the leader's HTTPS endpoint.
let mut puller = ReplicationPullerConfig::new(
    ReplicaId::from_str("replica_node_a"),                  // the LEADER's id
    "https://leader.internal:8443",
    ActorId::from_str("actor_replica_node_b_restorer"),
);
puller.poll_interval = std::time::Duration::from_secs(1);
puller.bootstrap_on_start = true;
puller.cursor_path    = Some(PathBuf::from("/var/lib/hydra/cursor.json"));
puller.heartbeat_path = Some(PathBuf::from("/var/lib/hydra/heartbeat.json"));
puller.leader_roots   = Some(vec![PathBuf::from("/etc/hydra/leader-ca.pem")]); // pin if private CA

let security = ServerSecurityConfig::with_auth(auth)
    .with_role(RuntimeRole::Follower)
    .with_replication(ReplicationServerConfig::new(puller))
    .with_self_peer_id(ReplicaId::from_str("replica_node_b"));

serve_with_security(runtime, "0.0.0.0:8080", security).await?;
```

**What happens at boot**:
1. The replication worker auto-spawns (V2 P4I).
2. If `bootstrap_on_start`, it does a snapshot bootstrap from the leader first.
3. Then enters the poll loop with `poll_interval` cadence and equal-jitter retry on transient failures.
4. The HTTP role middleware rejects mutating routes with 409. Engine ingest paths return `ReadOnlyFollower`.
5. The cursor is persisted to disk on every apply — restarts resume where they left off, no re-bootstrap needed.

**Register the follower on the leader** (optional but recommended for cluster visibility):

```bash
# On the LEADER, register the new follower as a known peer:
curl -X POST -H 'Authorization: Bearer <token>' \
  -H 'Content-Type: application/json' \
  -H 'X-Hydra-Tenant: cluster' \
  -d '{
    "event_kind": {
      "kind": "ReplicaRegistered",
      "peer": {
        "id": "replica_node_b",
        "role": "Follower",
        "status": "Registered",
        "mode": "SnapshotThenTail",
        "registered_by": "actor_admin",
        "registered_at": "2026-05-27T18:00:00Z",
        "updated_at": "2026-05-27T18:00:00Z",
        "metadata": {}
      }
    }
  }' \
  http://leader:8080/ingest
```

This registration replicates to the follower on the next pull. After that, every node knows about every other node.

**Sanity check after boot**:
```bash
# On the follower:
curl -H 'Authorization: Bearer <token>' http://follower:8080/replication/role
# → {"role":"follower"}

curl -H 'Authorization: Bearer <token>' \
  http://follower:8080/replication/peers/replica_node_a/lag
# → {"peer_id":"replica_node_a","lag":{"leader_sequence":42,"follower_sequence":42,"lag_commits":0}}
```

---

## 3. Promote a follower

The big workflow. Used when the current leader is unreachable, suspect, or being decommissioned.

### Pre-flight

1. **Confirm the leader is actually down.** Don't promote on flaky network. Examples of "actually down":
   - Process exited (operator killed it, OOMed, crashed)
   - Host unreachable for >N minutes (your call on N — usually >1 minute is enough)
   - Disk failure on the leader
2. **Verify follower lag** before promoting:
   ```bash
   curl -H 'Authorization: Bearer <token>' \
     http://follower-2:8080/replication/peers/replica_node_a/lag
   ```
   `lag_commits: 0` is required for non-forced promotion. Anything > 0 means the follower lost the leader before catching up — you'll either need to wait, choose a different follower, or `force=true`.

### Promote

```bash
curl -X POST -H 'Authorization: Bearer <admin-token>' \
  -H 'Content-Type: application/json' \
  -d '{
    "promoted_by": "actor_oncall_alice",
    "reason": "leader replica_node_a unreachable >5min",
    "force": false
  }' \
  http://follower-2:8080/replication/promote
```

**Expected 200 response**:
```json
{
  "previous_role": "follower",
  "new_role": "leader",
  "promoted_at": "2026-05-27T18:42:00Z",
  "promotion_sequence": 12345,
  "applied_sequence_before_promotion": 12344,
  "lag_at_promotion": 0,
  "forced": false,
  "changed": true
}
```

**Expected 409 response (catch-up failure)**:
```json
{
  "error": "follower not caught up",
  "applied_sequence": 12340,
  "lag_commits": 4,
  "hint": "wait until lag=0 or retry with force=true (accepts divergence risk)"
}
```

If 409, either:
- Wait for the follower to catch up (poll lag every few seconds)
- Retry with `force: true` if you accept losing the 4 unreplicated writes

### What happens internally

1. The handler reads the previous role from the engine.
2. Catch-up check via `latest_replication_lag(leader_peer_id).lag_commits`.
3. Engine role flipped to `Leader` FIRST (so the audit ingest passes the engine guard).
4. `ReplicaPromoted { peer_id: self_peer_id, promoted_by, reason }` committed via standard ingest.
5. HTTP role state flipped to `Leader` (the always-on middleware sees the new role on the next request).
6. The replication worker observes `EngineRole::Leader` at the top of its next loop iteration and self-exits cleanly (no need to fire the shutdown token).
7. `tracing::info!` (or `tracing::warn!` if forced) audit log emitted.

### Sanity check after promote

```bash
curl -H 'Authorization: Bearer <token>' http://follower-2:8080/replication/role
# → {"role":"leader"}

curl -H 'Authorization: Bearer <token>' http://follower-2:8080/replication/promotion-status
# → {
#     "self_peer_id": "replica_node_b",
#     "current_role": "leader",
#     "last_promotion": {
#       "promoted_at": "2026-05-27T18:42:00Z",
#       "promotion_sequence": 12345,
#       "promoted_by": "actor_oncall_alice",
#       "reason": "leader replica_node_a unreachable >5min"
#     }
#   }

curl -H 'Authorization: Bearer <token>' \
  -H 'X-Hydra-Tenant: cluster' \
  -H 'Content-Type: application/json' \
  -d '{"event_kind":{"kind":"Signal","source":"node_x","name":"write-after-promote","payload":{}}}' \
  http://follower-2:8080/ingest
# → 200 OK (this node now accepts writes)
```

---

## 4. Recover an old leader

When the old leader comes back online (network restored, process restarted), **it has stale data**. The cluster is now ahead of it. You have two choices:

### Option A — Demote and re-follow (preferred)

The old leader becomes a follower of the new leader. It bootstraps from the new leader's snapshot (or its tail) and catches up.

```bash
# On the OLD leader, flip HTTP role to follower first (stops accepting writes):
curl -X POST -H 'Authorization: Bearer <admin-token>' \
  -H 'Content-Type: application/json' \
  -d '{"role":"follower"}' \
  http://old-leader:8080/replication/role
```

Then restart the old-leader process with new config:
- `with_role(RuntimeRole::Follower)`
- Engine `set_role(EngineRole::Follower)` at boot
- `with_replication(...)` pointing the puller at the **new leader's URL**, with `peer_id = <new_leader_id>`
- **Clear the persisted cursor** if there's one — the old leader has commits past the new leader's history; the cursor must reset. `rm /var/lib/hydra/cursor.json`
- `bootstrap_on_start = true` — the new leader's snapshot becomes the new starting point

The bootstrap path resets the old leader's local commit ledger to the new leader's snapshot. Any commits the old leader had that weren't replicated before the failover are **lost**. This is the expected tradeoff: V2 has no merge.

### Option B — Decommission and replace

If the old leader's data integrity is in doubt (disk failure, etc.), don't try to rejoin it. Destroy the process, wipe its data directory, and treat it as a new follower joining the cluster from scratch.

---

## 5. Re-point other followers

Every other follower is still pulling from the **old** leader's URL. They'll start failing with transient network errors (which the puller retries with backoff + jitter). You need to update each one's puller config to point at the new leader.

For each remaining follower:

1. **Update the puller config** in your deployment:
   - `peer_id` → the new leader's `ReplicaId`
   - `leader_base_url` → the new leader's URL
   - `leader_roots` → the new leader's cert if you pin (or keep the same private CA cert if you signed both)
2. **Clear the cursor file** if the new leader's history diverges from the old (i.e. forced promotion, or any time you're unsure):
   ```bash
   rm /var/lib/hydra/cursor.json
   ```
3. **Restart the follower process.** The puller will bootstrap from the new leader's snapshot on next start (if `bootstrap_on_start = true`).

There's no in-process API to update `leader_base_url` at runtime today — it's restart-required. If you need hot-reconfig, that's a future patch.

---

## 6. Verify lag

Three ways, in order of detail:

### a. Per-peer lag endpoint

```bash
curl -H 'Authorization: Bearer <token>' \
  http://follower:8080/replication/peers/<leader_id>/lag
```

Returns 200 with either:
```json
{ "peer_id": "...", "lag": null }                                 // no observation yet
{ "peer_id": "...", "lag": { "leader_sequence": 100,
                              "follower_sequence": 97,
                              "lag_commits": 3,
                              "observed_at": "..." } }
```

### b. Prometheus metrics

```bash
curl http://follower:8080/metrics
# ...
# hydra_replication_lag_commits{peer_id="replica_node_a"} 3
# hydra_replication_leader_head_sequence{peer_id="replica_node_a"} 100
# hydra_replication_follower_cursor_sequence{peer_id="replica_node_a"} 97
# hydra_replication_consecutive_failures{peer_id="replica_node_a"} 0
# hydra_replication_pull_attempts_total{outcome="ok",peer_id="replica_node_a"} 4218
# ...
```

Wire these into your dashboards. Alert on `lag_commits` rising for > N minutes, or on `consecutive_failures > 5`.

### c. On-disk heartbeat file

If you configured `heartbeat_path`, the follower writes a JSON heartbeat per pull (debounced to ~30s when no material change). Useful for diagnostics from the host:

```bash
cat /var/lib/hydra/heartbeat.json
# {
#   "version": 1,
#   "heartbeats": {
#     "replica_node_a": {
#       "peer_id": "replica_node_a",
#       "last_observed_lag": { "lag_commits": 3, ... },
#       "last_heartbeat_at": "...",
#       "total_transient_failures": 0,
#       "last_fatal_error_kind": null
#     }
#   }
# }
```

---

## 7. Avoid split-brain

V2 has no automatic election. **The cluster trusts you to never promote two followers simultaneously.** Without consensus, two leaders writing different commits creates divergent hash chains that cannot be merged.

### Rules

1. **One promotion at a time.** If you're promoting, you're the only one running the runbook.
2. **Confirm the old leader is down before promoting.** Process actually exited; host actually unreachable; not a 30-second blip. If you're not sure, wait.
3. **Stop the old leader's process** (or call `POST /replication/role {"role":"follower"}` on it) before letting it back into the network. An old leader that comes back online thinking it's still the leader, while writes are flowing to the new leader, IS the split-brain.
4. **Don't run two `serve_*` processes against the same data directory** — file locks (polish #3) catch most overlap, but the safer rule is "one process per data dir."
5. **`force=true` accepts divergence.** If the leader was reachable enough to commit some writes the follower hadn't yet seen, those writes are gone after a forced promotion. The cluster doesn't merge them later.
6. **The audit trail is your forensic record.** Every promotion lands a `ReplicaPromoted` in the local ledger; `GET /replication/promotion-status` surfaces it. If something goes wrong, `GET /events?kind=replica_promoted` shows the full history.

### What V2 explicitly doesn't have

- Automatic leader election
- Quorum / consensus
- Multi-leader writes
- Conflict resolution between divergent chains
- Automatic split-brain recovery

If you need those, V3+ would be a Raft (or similar consensus) implementation. Don't try to fake it with shell scripts.

---

## 8. Common workflows — cheat sheet

### Healthy cluster, planned leader replacement

1. Verify all followers caught up (`lag_commits = 0` on each).
2. Stop the current leader cleanly.
3. Promote chosen follower with `force=false`.
4. Re-point other followers at the new leader (config update + restart).
5. Old leader rejoins as a fresh follower (Option A in §4).

### Unplanned leader loss, force promotion

1. Confirm old leader unreachable (network + process check).
2. Pick the follower with the smallest lag.
3. `POST /replication/promote` with `force=true`. Accept that writes between `applied_sequence_before_promotion` and the old leader's actual head are lost.
4. Re-point survivors.
5. If old leader recovers, treat its data as suspect (Option B in §4).

### Routine diagnostics

```bash
# 1. Who is leader?
curl ... /replication/role
curl ... /replication/status        # also lists peers

# 2. How far behind is each follower?
for f in follower-1 follower-2; do
  echo "=== $f ==="
  curl ... http://$f:8080/replication/peers/<leader_id>/lag
done

# 3. Any promotion history?
curl ... /replication/promotion-status

# 4. Metrics
curl http://node:8080/metrics | grep hydra_replication
```

---

## 9. Configuration reference

| Type | Location | Purpose |
|---|---|---|
| `ServerSecurityConfig` | `hydra_api::security` | Top-level server config (auth, TLS, rate limit, role, replication, self_peer_id) |
| `AuthConfig` | `hydra_api::auth` | Bearer tokens + scopes |
| `TlsConfig` | `hydra_api::security` | PEM-backed TLS (server-side) |
| `RuntimeRole` | `hydra_net::role` | HTTP role enum (`leader`/`follower`) |
| `EngineRole` | `hydra_engine::prelude` | Engine role enum (must match RuntimeRole) |
| `ReplicationServerConfig` | `hydra_api::security` | Puller config + shutdown token |
| `ReplicationPullerConfig` | `hydra_net::replication_worker` | The puller itself: peer_id, leader_base_url, auth_token, cursor_path, heartbeat_path, leader_roots, jitter, etc. |
| `ReplicationRetryConfig` | `hydra_net::replication_worker` | Backoff policy (`max_attempts`, `initial_backoff`, `max_backoff`, `jitter`) |
| `MetricsRecorder` trait | `hydra_net::metrics` | Operator's metrics backend hook |
| `PrometheusTextRecorder` | `hydra_net::metrics` | Built-in `/metrics` exposition |

---

## 10. What's NOT in V2 (deferred to V3+)

- Automatic leader election (Raft / Paxos / Zab)
- Multi-leader writes / multi-master replication
- Quorum-based commit
- Conflict resolution / merge
- Automatic split-brain detection or recovery
- Hot-reload of `leader_base_url` (currently restart-required)
- Pre-promotion drain (queueing writes during transition)
- Heartbeat-triggered auto-promotion (risks split-brain without consensus)

If you find yourself wanting any of these, you've outgrown V2's operator-coordinated model. That's the line where Raft starts.

---

## Appendix — files this runbook references

- `crates/hydra-net/src/role.rs` — `RuntimeRole` + `RoleState`
- `crates/hydra-net/src/replication_worker.rs` — puller, retry, jitter, heartbeat, cursor, pinning
- `crates/hydra-net/src/http/replication.rs` — `/replication/*` handlers including `POST /replication/promote` and `GET /replication/promotion-status`
- `crates/hydra-net/src/metrics.rs` — `MetricsRecorder` + `PrometheusTextRecorder`
- `crates/hydra-api/src/security.rs` — `ServerSecurityConfig`, `TlsConfig`, `ReplicationServerConfig`
- `crates/hydra-api/src/server.rs` — `serve_with_security`, `build_router_with_security`
- `crates/hydra-api/src/auth.rs` — `AuthConfig`, `AuthToken`, `required_scopes_for`, `rejected_on_follower`, `role_middleware`
- `crates/hydra-engine/src/hydra.rs` — `Hydra::set_role`, `EngineRole`, `latest_replication_lag`
- `HYDRA_SYSTEM_STUDY.md` — full system map
