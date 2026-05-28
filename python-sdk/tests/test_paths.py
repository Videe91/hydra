"""Tests for the internal URL path helpers.

Patch 2 introduces `_paths.py` as the single source of truth for
URL construction. These tests pin the exact strings so future patches
catch accidental drift.
"""

from __future__ import annotations

from hydra import _paths


def test_ingest_path() -> None:
    assert _paths.ingest_path() == "/ingest"


def test_query_single_get_paths() -> None:
    assert _paths.query_node_path("node_x") == "/query/nodes/node_x"
    assert _paths.query_edge_path("edge_x") == "/query/edges/edge_x"
    assert _paths.query_claim_path("claim_x") == "/query/claims/claim_x"
    assert _paths.query_evidence_path("evd_x") == "/query/evidence/evd_x"
    assert _paths.query_action_path("act_x") == "/query/actions/act_x"
    assert _paths.query_outcome_path("oc_x") == "/query/outcomes/oc_x"


def test_event_path_lives_under_events_router_not_query() -> None:
    """Hydra's `GET /events/:event_id` is under `events_router`
    (scope `read:audit`), not `query_router`. The SDK abstracts the
    distinction; this test pins the path so we don't accidentally
    rewire to `/query/events/:id` (which doesn't exist on the server)."""
    assert _paths.event_path("evt_x") == "/events/evt_x"


def test_query_list_paths() -> None:
    assert _paths.query_claims_path() == "/query/claims"
    assert _paths.query_claims_by_status_path("Verified") == "/query/claims/status/Verified"
    assert _paths.query_claims_by_kind_path("AnomalyFinding") == "/query/claims/kind/AnomalyFinding"
    assert _paths.query_claims_for_subject_path() == "/query/claims-for-subject"
    assert (
        _paths.query_claims_using_evidence_path("evd_x") == "/query/evidence/evd_x/claims"
    )
    assert _paths.query_actions_path() == "/query/actions"
    assert _paths.query_actions_by_status_path("Proposed") == "/query/actions/status/Proposed"
    assert (
        _paths.query_outcomes_for_action_path("act_x")
        == "/query/actions/act_x/outcomes"
    )


def test_path_segment_encoding_handles_reserved_chars() -> None:
    """Hydra `Dataset` subject names can contain dots and slashes.
    The SDK URL-encodes each segment so the route match doesn't
    explode."""
    # Dot is safe in path segments; slash must be encoded.
    assert _paths.query_node_path("node/with/slash") == "/query/nodes/node%2Fwith%2Fslash"
    # A realistic dataset-like id (no encoding needed, just sanity).
    assert (
        _paths.query_claim_path("claim_01J9XYZ_ABC123") == "/query/claims/claim_01J9XYZ_ABC123"
    )


def test_lineage_path() -> None:
    """`/lineage/:event_id` is its own router, not under `/query/`."""
    assert _paths.lineage_path("evt_abc") == "/lineage/evt_abc"


def test_diagnostics_paths() -> None:
    """Four diagnostic surfaces; counterfactual takes the event_id
    in the path, the others take filters as query params."""
    assert _paths.diagnostics_anomaly_path() == "/diagnostics/anomaly"
    assert _paths.diagnostics_coverage_path() == "/diagnostics/coverage"
    assert (
        _paths.diagnostics_counterfactual_path("evt_abc")
        == "/diagnostics/counterfactual/evt_abc"
    )
    assert _paths.diagnostics_evolution_path() == "/diagnostics/evolution"


# === Patch 4: schemas + replication ===


def test_schema_read_paths() -> None:
    """Three list-by-status endpoints plus six single-fetch reads
    keyed by the natural identifier (type_id / kind / predicate /
    action_kind / policy_kind)."""
    assert _paths.schemas_active_path() == "/schemas/active"
    assert _paths.schemas_disabled_path() == "/schemas/disabled"
    assert _paths.schemas_archived_path() == "/schemas/archived"
    assert _paths.schema_entity_path("type_invoice") == "/schemas/entity/type_invoice"
    assert _paths.schema_edge_path("type_depends_on") == "/schemas/edge/type_depends_on"
    assert _paths.schema_evidence_path("bank_transaction") == "/schemas/evidence/bank_transaction"
    assert _paths.schema_claim_predicate_path("is_stale") == "/schemas/claim/is_stale"
    assert _paths.schema_action_path("PostLedgerEntry") == "/schemas/action/PostLedgerEntry"
    assert _paths.schema_policy_path("AutoApproval") == "/schemas/policy/AutoApproval"


def test_schema_register_paths() -> None:
    """One register endpoint per SchemaDefinition variant. Note
    `claim-predicate` and `policy-condition` use hyphenated paths
    (matches the engine), distinct from the lookup paths
    (`/schemas/claim/...`, `/schemas/policy/...`)."""
    assert _paths.schemas_register_entity_path() == "/schemas/entity"
    assert _paths.schemas_register_edge_path() == "/schemas/edge"
    assert _paths.schemas_register_evidence_path() == "/schemas/evidence"
    assert (
        _paths.schemas_register_claim_predicate_path()
        == "/schemas/claim-predicate"
    )
    assert _paths.schemas_register_action_path() == "/schemas/action"
    assert (
        _paths.schemas_register_policy_condition_path()
        == "/schemas/policy-condition"
    )


def test_schema_lifecycle_paths() -> None:
    """Disable + archive routes — schema_id goes in the path."""
    assert _paths.schema_disable_path("sch_x") == "/schemas/sch_x/disable"
    assert _paths.schema_archive_path("sch_x") == "/schemas/sch_x/archive"


def test_schema_validate_paths() -> None:
    """Seven preflight validators (`validate_policy` deferred per
    Patch 4 scope)."""
    assert _paths.schemas_validate_action_path() == "/schemas/validate/action"
    assert _paths.schemas_validate_evidence_path() == "/schemas/validate/evidence"
    assert _paths.schemas_validate_claim_path() == "/schemas/validate/claim"
    assert (
        _paths.schemas_validate_node_create_path() == "/schemas/validate/node-create"
    )
    assert (
        _paths.schemas_validate_node_update_path() == "/schemas/validate/node-update"
    )
    assert (
        _paths.schemas_validate_edge_create_path() == "/schemas/validate/edge-create"
    )
    assert (
        _paths.schemas_validate_edge_update_path() == "/schemas/validate/edge-update"
    )


def test_replication_read_paths() -> None:
    """Six operator-facing replication reads. Puller-internal routes
    (`/replication/commits`, `/replication/snapshot/*`) are
    intentionally NOT exposed via _paths."""
    assert _paths.replication_status_path() == "/replication/status"
    assert _paths.replication_peers_path() == "/replication/peers"
    assert _paths.replication_peer_path("replica_a") == "/replication/peers/replica_a"
    assert (
        _paths.replication_peer_lag_path("replica_a")
        == "/replication/peers/replica_a/lag"
    )
    assert _paths.replication_role_path() == "/replication/role"
    assert (
        _paths.replication_promotion_status_path()
        == "/replication/promotion-status"
    )
