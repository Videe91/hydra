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
