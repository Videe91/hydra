"""Tests for the 10 query methods on `Hydra`.

Verifies:
  - Each get_* method hits the right path and returns a typed model
  - list_claims filter routing (no-filter → /query/claims paginated,
    status/kind → filtered path)
  - list_claims_for_subject sends subject_kind/subject_value params
  - list_claims_for_evidence hits /query/evidence/:id/claims
  - list_actions filter routing
  - list_outcomes_for_action hits the per-action path
  - 404 → HydraNotFoundError
  - ValueError when list_claims passed conflicting filters
"""

from __future__ import annotations

import httpx
import pytest
import respx

from hydra import Hydra, HydraNotFoundError


# === fixtures: realistic wire shapes ===

NODE_FIXTURE = {
    "node": {
        "meta": {
            "id": "node_x",
            "type_id": "dataset",
            "created_at": "2026-01-01T00:00:00Z",
            "updated_at": "2026-01-01T00:00:00Z",
            "version": 1,
            "alive": True,
            "tenant_id": "tenant_test",
        },
        "properties": {"name": "revenue_daily"},
    }
}

EDGE_FIXTURE = {
    "edge": {
        "meta": {
            "id": "edge_x",
            "type_id": "depends_on",
            "source": "node_a",
            "target": "node_b",
            "created_at": "2026-01-01T00:00:00Z",
            "updated_at": "2026-01-01T00:00:00Z",
            "version": 1,
            "alive": True,
            "tenant_id": "tenant_test",
        },
        "properties": {},
    }
}

EVENT_FIXTURE = {
    "event": {
        "id": "evt_x",
        "timestamp": "2026-01-01T00:00:00Z",
        "kind": {"Signal": {"source": "node_y", "name": "test", "payload": {}}},
        "caused_by": [],
        "cascade_id": "csc_x",
        "cascade_depth": 0,
        "cascade_breadth_index": 0,
        "tenant_id": "tenant_test",
    }
}

CLAIM_BODY = {
    "id": "claim_x",
    "tenant_id": "tenant_test",
    "kind": "AnomalyFinding",
    "subject": {"Dataset": "revenue_daily"},
    "predicate": "is_stale",
    "object": {"Value": True},
    "confidence": 0.9,
    "status": "Verified",
    "evidence_for": ["evd_a"],
    "evidence_against": [],
    "valid_from": "2026-01-01T00:00:00Z",
    "valid_until": None,
    "created_by": "actor_agent",
    "created_at": "2026-01-01T00:00:00Z",
    "updated_at": "2026-01-01T00:00:00Z",
    "caused_by": None,
}

EVIDENCE_BODY = {
    "id": "evd_x",
    "tenant_id": "tenant_test",
    "source": {"System": {"name": "test_sensor"}},
    "payload": {"kind": "obs", "data": {"k": 1}},
    "reliability": 0.95,
    "observed_at": "2026-01-01T00:00:00Z",
    "recorded_at": "2026-01-01T00:00:00Z",
    "caused_by": None,
}

ACTION_BODY = {
    "id": "act_x",
    "tenant_id": "tenant_test",
    "kind": "Quarantine",
    "status": "Proposed",
    "targets": [{"Dataset": "d1"}],
    "related_claims": [],
    "supporting_evidence": [],
    "proposed_by": "actor_agent",
    "approved_by": None,
    "policy_id": None,
    "payload": {},
    "created_at": "2026-01-01T00:00:00Z",
    "updated_at": "2026-01-01T00:00:00Z",
    "approved_at": None,
    "executed_at": None,
    "caused_by": None,
}

OUTCOME_BODY = {
    "id": "oc_x",
    "tenant_id": "tenant_test",
    "action_id": "act_x",
    "kind": "Success",
    "observed_events": [],
    "updated_claims": [],
    "produced_evidence": [],
    "impact": {},
    "observed_at": "2026-01-01T00:00:00Z",
    "recorded_at": "2026-01-01T00:00:00Z",
    "recorded_by": "actor_agent",
    "caused_by": None,
}


# === get_* ===


@pytest.mark.asyncio
async def test_get_node_parses_response(hy: Hydra, respx_mock: respx.MockRouter) -> None:
    respx_mock.get("https://hydra.test/query/nodes/node_x").mock(
        return_value=httpx.Response(200, json=NODE_FIXTURE)
    )
    node = await hy.get_node("node_x")
    assert node.meta.id == "node_x"
    assert node.meta.type_id == "dataset"
    assert node.properties == {"name": "revenue_daily"}


@pytest.mark.asyncio
async def test_get_edge_parses_response(hy: Hydra, respx_mock: respx.MockRouter) -> None:
    respx_mock.get("https://hydra.test/query/edges/edge_x").mock(
        return_value=httpx.Response(200, json=EDGE_FIXTURE)
    )
    edge = await hy.get_edge("edge_x")
    assert edge.meta.source == "node_a"
    assert edge.meta.target == "node_b"


@pytest.mark.asyncio
async def test_get_event_hits_events_router_not_query(
    hy: Hydra, respx_mock: respx.MockRouter
) -> None:
    """get_event uses `/events/:event_id`, not `/query/events/:event_id`
    (the latter doesn't exist on the server)."""
    route = respx_mock.get("https://hydra.test/events/evt_x").mock(
        return_value=httpx.Response(200, json=EVENT_FIXTURE)
    )
    event = await hy.get_event("evt_x")
    assert event.id == "evt_x"
    assert event.cascade_id == "csc_x"
    # Confirm the path actually used.
    assert str(route.calls.last.request.url) == "https://hydra.test/events/evt_x"


@pytest.mark.asyncio
async def test_get_claim_parses_response(hy: Hydra, respx_mock: respx.MockRouter) -> None:
    respx_mock.get("https://hydra.test/query/claims/claim_x").mock(
        return_value=httpx.Response(200, json={"claim": CLAIM_BODY})
    )
    claim = await hy.get_claim("claim_x")
    assert claim.id == "claim_x"
    assert claim.kind == "AnomalyFinding"
    assert claim.status == "Verified"
    assert claim.subject == {"Dataset": "revenue_daily"}


@pytest.mark.asyncio
async def test_get_evidence_parses_response(
    hy: Hydra, respx_mock: respx.MockRouter
) -> None:
    respx_mock.get("https://hydra.test/query/evidence/evd_x").mock(
        return_value=httpx.Response(200, json={"evidence": EVIDENCE_BODY})
    )
    evidence = await hy.get_evidence("evd_x")
    assert evidence.id == "evd_x"
    assert evidence.payload.kind == "obs"
    assert evidence.reliability == 0.95


@pytest.mark.asyncio
async def test_get_action_parses_response(hy: Hydra, respx_mock: respx.MockRouter) -> None:
    respx_mock.get("https://hydra.test/query/actions/act_x").mock(
        return_value=httpx.Response(200, json={"action": ACTION_BODY})
    )
    action = await hy.get_action("act_x")
    assert action.id == "act_x"
    assert action.kind == "Quarantine"
    assert action.targets == [{"Dataset": "d1"}]


@pytest.mark.asyncio
async def test_get_node_404_raises_not_found(
    hy: Hydra, respx_mock: respx.MockRouter
) -> None:
    respx_mock.get("https://hydra.test/query/nodes/missing").mock(
        return_value=httpx.Response(404, json={"error": "node not found"})
    )
    with pytest.raises(HydraNotFoundError):
        await hy.get_node("missing")


# === list_claims with filter routing ===


@pytest.mark.asyncio
async def test_list_claims_no_filter_hits_paginated_route(
    hy: Hydra, respx_mock: respx.MockRouter
) -> None:
    """`/query/claims` is paginated — Page<Claim> shape. SDK unwraps
    `items` and returns a `list[Claim]` for v0."""
    route = respx_mock.get("https://hydra.test/query/claims").mock(
        return_value=httpx.Response(
            200, json={"items": [CLAIM_BODY], "next_cursor": "claim_y"}
        )
    )
    claims = await hy.list_claims()
    assert len(claims) == 1
    assert claims[0].id == "claim_x"
    assert str(route.calls.last.request.url) == "https://hydra.test/query/claims"


@pytest.mark.asyncio
async def test_list_claims_status_filter_hits_filtered_route(
    hy: Hydra, respx_mock: respx.MockRouter
) -> None:
    route = respx_mock.get("https://hydra.test/query/claims/status/Verified").mock(
        return_value=httpx.Response(200, json={"claims": [CLAIM_BODY]})
    )
    claims = await hy.list_claims(status="Verified")
    assert len(claims) == 1
    assert route.called


@pytest.mark.asyncio
async def test_list_claims_kind_filter_hits_filtered_route(
    hy: Hydra, respx_mock: respx.MockRouter
) -> None:
    route = respx_mock.get(
        "https://hydra.test/query/claims/kind/AnomalyFinding"
    ).mock(return_value=httpx.Response(200, json={"claims": [CLAIM_BODY]}))
    claims = await hy.list_claims(kind="AnomalyFinding")
    assert len(claims) == 1
    assert route.called


@pytest.mark.asyncio
async def test_list_claims_both_filters_raises_value_error(hy: Hydra) -> None:
    """The engine doesn't support combined status+kind filtering;
    the SDK rejects it client-side rather than silently picking one."""
    with pytest.raises(ValueError, match="at most one"):
        await hy.list_claims(status="Verified", kind="AnomalyFinding")


# === list_claims_for_subject ===


@pytest.mark.asyncio
async def test_list_claims_for_subject_passes_query_params(
    hy: Hydra, respx_mock: respx.MockRouter
) -> None:
    route = respx_mock.get("https://hydra.test/query/claims-for-subject").mock(
        return_value=httpx.Response(200, json={"claims": [CLAIM_BODY]})
    )
    claims = await hy.list_claims_for_subject(
        subject_kind="Dataset", subject_value="revenue_daily"
    )
    assert len(claims) == 1
    request = route.calls.last.request
    assert request.url.params["subject_kind"] == "Dataset"
    assert request.url.params["subject_value"] == "revenue_daily"


# === list_claims_for_evidence ===


@pytest.mark.asyncio
async def test_list_claims_for_evidence_hits_nested_route(
    hy: Hydra, respx_mock: respx.MockRouter
) -> None:
    route = respx_mock.get("https://hydra.test/query/evidence/evd_x/claims").mock(
        return_value=httpx.Response(200, json={"claims": [CLAIM_BODY]})
    )
    claims = await hy.list_claims_for_evidence("evd_x")
    assert len(claims) == 1
    assert route.called


# === list_actions ===


@pytest.mark.asyncio
async def test_list_actions_no_filter_hits_paginated_route(
    hy: Hydra, respx_mock: respx.MockRouter
) -> None:
    respx_mock.get("https://hydra.test/query/actions").mock(
        return_value=httpx.Response(
            200, json={"items": [ACTION_BODY], "next_cursor": None}
        )
    )
    actions = await hy.list_actions()
    assert len(actions) == 1
    assert actions[0].kind == "Quarantine"


@pytest.mark.asyncio
async def test_list_actions_status_filter(
    hy: Hydra, respx_mock: respx.MockRouter
) -> None:
    route = respx_mock.get(
        "https://hydra.test/query/actions/status/Proposed"
    ).mock(return_value=httpx.Response(200, json={"actions": [ACTION_BODY]}))
    actions = await hy.list_actions(status="Proposed")
    assert len(actions) == 1
    assert route.called


# === list_outcomes_for_action ===


@pytest.mark.asyncio
async def test_list_outcomes_for_action_returns_outcomes(
    hy: Hydra, respx_mock: respx.MockRouter
) -> None:
    respx_mock.get("https://hydra.test/query/actions/act_x/outcomes").mock(
        return_value=httpx.Response(200, json={"outcomes": [OUTCOME_BODY]})
    )
    outcomes = await hy.list_outcomes_for_action("act_x")
    assert len(outcomes) == 1
    assert outcomes[0].kind == "Success"
    assert outcomes[0].action_id == "act_x"
