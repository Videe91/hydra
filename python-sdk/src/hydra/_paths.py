"""Internal URL path construction helpers.

NOT part of the public API.

Centralizing path construction now (when there are 11 routes)
prevents drift as Patches 3 and 4 add diagnostic, lineage,
schema, and replication routes. Every public method that hits an
HTTP route calls one of these helpers; route changes in Hydra are
fixed in exactly one place.

Path-segment values get URL-encoded so IDs containing reserved
characters (slashes in `Dataset` names, etc.) don't break the
route match.
"""

from __future__ import annotations

from urllib.parse import quote


def _seg(value: str) -> str:
    """URL-encode a single path segment. Hydra IDs are ULID-shaped
    today and don't need encoding, but `Dataset` subject names can
    contain dots, slashes, and other reserved bytes."""
    return quote(value, safe="")


# === /ingest ===


def ingest_path() -> str:
    return "/ingest"


# === /query/* (single-get) ===


def query_node_path(node_id: str) -> str:
    return f"/query/nodes/{_seg(node_id)}"


def query_edge_path(edge_id: str) -> str:
    return f"/query/edges/{_seg(edge_id)}"


def query_claim_path(claim_id: str) -> str:
    return f"/query/claims/{_seg(claim_id)}"


def query_evidence_path(evidence_id: str) -> str:
    return f"/query/evidence/{_seg(evidence_id)}"


def query_action_path(action_id: str) -> str:
    return f"/query/actions/{_seg(action_id)}"


def query_outcome_path(outcome_id: str) -> str:
    return f"/query/outcomes/{_seg(outcome_id)}"


# === /events/* ===
#
# Note: there is no `/query/events/:event_id` route — the
# get-by-id lives at `/events/:event_id` under the events router
# (auth scope `read:audit` rather than `read:query`).


def event_path(event_id: str) -> str:
    return f"/events/{_seg(event_id)}"


# === /query/* (list with filter variants) ===


def query_claims_path() -> str:
    return "/query/claims"


def query_claims_by_status_path(status: str) -> str:
    return f"/query/claims/status/{_seg(status)}"


def query_claims_by_kind_path(kind: str) -> str:
    return f"/query/claims/kind/{_seg(kind)}"


def query_claims_for_subject_path() -> str:
    """Returns the path. Caller supplies `subject_kind` and
    `subject_value` as query params."""
    return "/query/claims-for-subject"


def query_claims_using_evidence_path(evidence_id: str) -> str:
    return f"/query/evidence/{_seg(evidence_id)}/claims"


def query_actions_path() -> str:
    return "/query/actions"


def query_actions_by_status_path(status: str) -> str:
    return f"/query/actions/status/{_seg(status)}"


def query_outcomes_for_action_path(action_id: str) -> str:
    return f"/query/actions/{_seg(action_id)}/outcomes"


# === /lineage/* ===


def lineage_path(event_id: str) -> str:
    return f"/lineage/{_seg(event_id)}"


# === /diagnostics/* ===


def diagnostics_anomaly_path() -> str:
    return "/diagnostics/anomaly"


def diagnostics_coverage_path() -> str:
    return "/diagnostics/coverage"


def diagnostics_counterfactual_path(event_id: str) -> str:
    return f"/diagnostics/counterfactual/{_seg(event_id)}"


def diagnostics_evolution_path() -> str:
    return "/diagnostics/evolution"


# === /diagnostics/micromodels/* (Patch 5 — external evaluation surface) ===


def diagnostics_micromodels_commit_rate_evaluate_path() -> str:
    """`POST /diagnostics/micromodels/commit-rate/evaluate` — drive the
    built-in CommitRateAnomalyModel from outside the engine. Body
    carries `mode` ("prediction_only" / "claim" / "action") and
    `requested_by` (ActorId)."""
    return "/diagnostics/micromodels/commit-rate/evaluate"


def diagnostics_micromodels_replication_lag_evaluate_path() -> str:
    """`POST /diagnostics/micromodels/replication-lag/evaluate` —
    drive the built-in ReplicationLagAnomalyModel (Patch 16) from
    outside the engine.

    Body carries `mode` ("prediction_only" / "claim" / "action"),
    `peer_id` (ReplicaId of the follower to evaluate), and
    `requested_by` (ActorId).

    Returns `ReplicationLagAnomalyAssessment` with the prediction,
    optional evidence/claim/action ids, the `peer_id` echoed back,
    a server-rendered `summary`, and a `lineage_url` pointing at
    the prediction event.

    404 on unknown peer_id."""
    return "/diagnostics/micromodels/replication-lag/evaluate"


def diagnostics_micromodels_agent_loop_storm_evaluate_path() -> str:
    """`POST /diagnostics/micromodels/agent-loop-storm/evaluate` —
    drive the built-in AgentLoopStormModel (Patch 18) from outside
    the engine.

    Patch 18 is Hydra's safety reflex: it watches whether the
    system is producing too many self-triggered events / actions
    / claims in a short window — i.e. agents chasing their own
    tail. Hydra-internal actors (cascade, trust-gate, verification
    agent, model auto-registers) are filtered out server-side so
    the storm signal reflects non-Hydra agent activity only.

    Body carries `mode` ("prediction_only" / "claim" / "action")
    and `requested_by` (ActorId). No per-instance selector — the
    model watches the global recent event log.

    Returns `AgentLoopStormAssessment` with the prediction,
    optional evidence/claim/action ids, a server-rendered
    `summary`, and a `lineage_url`. Storm action target is
    `System("hydra.agents")`, payload carries `top_actor` and
    `window_secs`."""
    return "/diagnostics/micromodels/agent-loop-storm/evaluate"


def diagnostics_micromodels_observation_from_outcome_path(outcome_id: str) -> str:
    """`POST /diagnostics/micromodels/observations/from-outcome/{outcome_id}`
    — Patch 8 outcome learning loop. Walks the causal chain from a
    recorded Outcome back to the originating MicroModelPrediction and
    records a MicroModelObservation matched by `prediction.run_id`.
    Body: `{observed_by}`. 400 on chain-walk failure; 404 on unknown
    outcome_id."""
    return f"/diagnostics/micromodels/observations/from-outcome/{_seg(outcome_id)}"


def diagnostics_micromodels_observation_from_rejected_action_path(action_id: str) -> str:
    """`POST /diagnostics/micromodels/observations/from-rejected-action/{action_id}`
    — Trust Patch 5 (Patch 13). Corrective-memory companion to the
    from-outcome path: synthesizes a MicroModelObservation for an
    OPERATOR-rejected model-derived action. Body: `{observed_by}`.

    Refused (400) when:
      - action is not in Rejected status
      - action was rejected by cascade (policy enforcement), not
        by an operator — cascade rejections aren't learning signal
      - action isn't model-derived (no related_claims, or claim
        not traced to a MicroModelPrediction)

    404 on unknown action_id. Reuses `write:diagnostics` scope."""
    return (
        f"/diagnostics/micromodels/observations/from-rejected-action/"
        f"{_seg(action_id)}"
    )


# === /actions/* (Patch 6 — operator approval workflow) ===


def action_approve_path(action_id: str) -> str:
    """`POST /actions/{action_id}/approve` — operator-triggered
    flip from Proposed → Approved (idempotent in v0; the response
    surfaces `previous_status`). Body: `{actor, reason?}`."""
    return f"/actions/{_seg(action_id)}/approve"


def action_reject_path(action_id: str) -> str:
    """`POST /actions/{action_id}/reject` — operator-triggered
    flip to Rejected. Reason is required (load-bearing for the
    audit log and future outcome learning). Body: `{actor, reason}`."""
    return f"/actions/{_seg(action_id)}/reject"


def action_execute_path(action_id: str) -> str:
    """`POST /actions/{action_id}/execute` — operator-triggered
    Notify-action execution stub (Patch 7). Walks an Approved
    Notify action through Executing → Executed and records an
    OutcomeObserved with `kind: Custom("notification_recorded")`.
    Body: `{actor}`. No real network delivery — Patch 7B adds it.
    400 on non-Approved status or non-Notify kind; 404 on unknown id."""
    return f"/actions/{_seg(action_id)}/execute"


def action_auto_execute_path(action_id: str) -> str:
    """`POST /actions/{action_id}/auto-execute` — Trust Patch 3
    (Patch 11). Trust-gated auto-execution. Hydra reads the
    claim's TrustAssessment (Patch 9/10); if `level == High` AND
    `score >= min_trust_score`, calls execute_notify_action.
    Returns 200 with an `AutoExecutionDecision` envelope on every
    non-error case — the `executed` boolean is the decision, NOT
    the success axis. 400 only on wrong kind (Backfill etc.);
    404 on unknown id.

    Body: `{actor, min_trust_score}`. Auth requires BOTH
    `read:trust` and `write:execute` (Patch 11 ordering rule)."""
    return f"/actions/{_seg(action_id)}/auto-execute"


def action_auto_approve_path(action_id: str) -> str:
    """`POST /actions/{action_id}/auto-approve` — Trust Patch 7
    (Patch 15). Trust-gated auto-approval. Hydra reads the
    claim's TrustAssessment; if `level == High` AND
    `score >= min_trust_score` AND the model has at least one
    prior operator-approved action AND no hard-block factors
    apply (contradicting_evidence, claim_disputed,
    claim_retracted, model_operator_rejected_historically), it
    ingests ActionApproved stamped with the trust-gate actor
    (`actor_hydra_trust_gate`). Otherwise it returns a skip
    envelope explaining which gate vetoed.

    Returns 200 with an `AutoApprovalDecision` envelope on every
    non-error case — the `approved` boolean is the decision, NOT
    the success axis. 400 only on wrong kind (Backfill etc.);
    404 on unknown id.

    Body: `{actor, min_trust_score}`. Auth requires BOTH
    `read:trust` and `write:approvals` (the trust-gate combo
    mirrors auto-execute's read:trust + write:execute)."""
    return f"/actions/{_seg(action_id)}/auto-approve"


# === /trust/* (Trust Patch 2 / Patch 10 — read-only trust surface) ===
#
# The `/trust/*` namespace is reserved for the whole Trust Layer.
# Patch 10 mounts only `/trust/claims/{id}`; future patches will
# add `/trust/sources/*`, `/trust/datasets/*`, `/trust/actions/*`,
# `/trust/models/*` etc. All share the `read:trust` auth scope.


def trust_claim_path(claim_id: str) -> str:
    """`GET /trust/claims/{claim_id}` — read-only trust assessment
    of one claim (Patch 10). Strict tenant-scoped: requires
    `X-Hydra-Tenant` header; missing → 400, wrong tenant or
    unknown id → 404. Returns a `TrustAssessment`."""
    return f"/trust/claims/{_seg(claim_id)}"


# === /schemas/* — read ===


def schemas_active_path() -> str:
    return "/schemas/active"


def schemas_disabled_path() -> str:
    return "/schemas/disabled"


def schemas_archived_path() -> str:
    return "/schemas/archived"


def schema_entity_path(type_id: str) -> str:
    return f"/schemas/entity/{_seg(type_id)}"


def schema_edge_path(type_id: str) -> str:
    return f"/schemas/edge/{_seg(type_id)}"


def schema_evidence_path(kind: str) -> str:
    return f"/schemas/evidence/{_seg(kind)}"


def schema_claim_predicate_path(predicate: str) -> str:
    return f"/schemas/claim/{_seg(predicate)}"


def schema_action_path(action_kind: str) -> str:
    return f"/schemas/action/{_seg(action_kind)}"


def schema_policy_path(policy_kind: str) -> str:
    return f"/schemas/policy/{_seg(policy_kind)}"


# === /schemas/* — register ===


def schemas_register_entity_path() -> str:
    return "/schemas/entity"


def schemas_register_edge_path() -> str:
    return "/schemas/edge"


def schemas_register_evidence_path() -> str:
    return "/schemas/evidence"


def schemas_register_claim_predicate_path() -> str:
    return "/schemas/claim-predicate"


def schemas_register_action_path() -> str:
    return "/schemas/action"


def schemas_register_policy_condition_path() -> str:
    return "/schemas/policy-condition"


# === /schemas/:schema_id/* — lifecycle ===


def schema_disable_path(schema_id: str) -> str:
    return f"/schemas/{_seg(schema_id)}/disable"


def schema_archive_path(schema_id: str) -> str:
    return f"/schemas/{_seg(schema_id)}/archive"


# === /schemas/validate/* ===


def schemas_validate_action_path() -> str:
    return "/schemas/validate/action"


def schemas_validate_evidence_path() -> str:
    return "/schemas/validate/evidence"


def schemas_validate_claim_path() -> str:
    return "/schemas/validate/claim"


def schemas_validate_node_create_path() -> str:
    return "/schemas/validate/node-create"


def schemas_validate_node_update_path() -> str:
    return "/schemas/validate/node-update"


def schemas_validate_edge_create_path() -> str:
    return "/schemas/validate/edge-create"


def schemas_validate_edge_update_path() -> str:
    return "/schemas/validate/edge-update"


# === /commits/stream — SSE subscription ===


def commits_stream_path() -> str:
    """Server-Sent-Events stream of every committed batch. Caller
    supplies `?after_sequence=N` to tail strictly after a known
    sequence; defaults to 0 (replay everything still in memory)."""
    return "/commits/stream"


# === /replication/* (read-only operator surface) ===


def replication_status_path() -> str:
    return "/replication/status"


def replication_peers_path() -> str:
    return "/replication/peers"


def replication_peer_path(peer_id: str) -> str:
    return f"/replication/peers/{_seg(peer_id)}"


def replication_peer_lag_path(peer_id: str) -> str:
    return f"/replication/peers/{_seg(peer_id)}/lag"


def replication_role_path() -> str:
    return "/replication/role"


def replication_promotion_status_path() -> str:
    return "/replication/promotion-status"
