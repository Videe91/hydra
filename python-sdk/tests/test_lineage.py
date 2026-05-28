"""Tests for `hy.lineage(...)`.

Verifies:
  - Basic call parses the typed LineageResponse
  - `depth` is sent as query parameter
  - 404 raises HydraNotFoundError
  - Per-call tenant override applies
"""

from __future__ import annotations

import httpx
import pytest
import respx

from hydra import Hydra, HydraNotFoundError


# A realistic LineageResponse with the seed + 2 ancestors + 1
# descendant + claim + evidence + action. The shape exactly mirrors
# `hydra-net::http::lineage::LineageResponse`.
LINEAGE_FIXTURE: dict = {
    "seed_event_id": "evt_seed",
    "depth": 10,
    "events": [
        {
            "id": "evt_ancestor",
            "timestamp": "2026-01-01T00:00:00Z",
            "kind": "signal",
            "summary": "signal: cloudtrail/CreateBucket",
            "caused_by": [],
            "cascade_id": "csc_a",
            "cascade_depth": 0,
        },
        {
            "id": "evt_seed",
            "timestamp": "2026-01-01T00:00:01Z",
            "kind": "evidence_added",
            "summary": "evidence_added: cloudtrail",
            "caused_by": ["evt_ancestor"],
            "cascade_id": "csc_a",
            "cascade_depth": 1,
        },
        {
            "id": "evt_descendant",
            "timestamp": "2026-01-01T00:00:02Z",
            "kind": "claim_proposed",
            "summary": "claim_proposed: is_anomalous",
            "caused_by": ["evt_seed"],
            "cascade_id": "csc_a",
            "cascade_depth": 2,
        },
    ],
    "evidence": [
        {
            "id": "evd_x",
            "kind": "cloudtrail",
            "reliability": 0.92,
            "observed_at": "2026-01-01T00:00:01Z",
            "caused_by": "evt_seed",
        }
    ],
    "claims": [
        {
            "id": "claim_y",
            "kind": "AnomalyFinding",
            "status": "Proposed",
            "predicate": "is_anomalous",
            "confidence": 0.91,
            "caused_by": "evt_descendant",
        }
    ],
    "actions": [],
    "outcomes": [],
    "policy_decisions": [],
    "approval_requests": [],
    "ancestors": ["evt_ancestor"],
    "descendants": ["evt_descendant"],
    "truncated": False,
    "explanation_summary": (
        "Seed event: evidence_added: cloudtrail. "
        "Recorded 1 evidence record(s) (cloudtrail). "
        "Produced 1 claim(s) (is_anomalous=Proposed)."
    ),
}


@pytest.mark.asyncio
async def test_lineage_returns_typed_response(
    hy: Hydra, respx_mock: respx.MockRouter
) -> None:
    respx_mock.get("https://hydra.test/lineage/evt_seed").mock(
        return_value=httpx.Response(200, json=LINEAGE_FIXTURE)
    )
    lin = await hy.lineage("evt_seed")
    assert lin.seed_event_id == "evt_seed"
    assert lin.depth == 10
    assert len(lin.events) == 3
    assert lin.events[1].id == "evt_seed"
    assert lin.events[1].kind == "evidence_added"
    assert len(lin.claims) == 1
    assert lin.claims[0].predicate == "is_anomalous"
    assert lin.claims[0].confidence == 0.91
    assert lin.evidence[0].reliability == 0.92
    assert lin.ancestors == ["evt_ancestor"]
    assert lin.descendants == ["evt_descendant"]
    assert not lin.truncated
    assert "Seed event" in lin.explanation_summary


@pytest.mark.asyncio
async def test_lineage_depth_param_passed_as_query(
    hy: Hydra, respx_mock: respx.MockRouter
) -> None:
    route = respx_mock.get("https://hydra.test/lineage/evt_seed").mock(
        return_value=httpx.Response(200, json=LINEAGE_FIXTURE)
    )
    await hy.lineage("evt_seed", depth=20)
    request = route.calls.last.request
    assert request.url.params["depth"] == "20"


@pytest.mark.asyncio
async def test_lineage_404_raises_not_found(
    hy: Hydra, respx_mock: respx.MockRouter
) -> None:
    respx_mock.get("https://hydra.test/lineage/evt_missing").mock(
        return_value=httpx.Response(404, json={"error": "event not found: evt_missing"})
    )
    with pytest.raises(HydraNotFoundError):
        await hy.lineage("evt_missing")


@pytest.mark.asyncio
async def test_lineage_tenant_override(
    hy: Hydra, respx_mock: respx.MockRouter
) -> None:
    """Rule #7 — tenant override available on every endpoint."""
    route = respx_mock.get("https://hydra.test/lineage/evt_x").mock(
        return_value=httpx.Response(
            200,
            json={
                **LINEAGE_FIXTURE,
                "seed_event_id": "evt_x",
                "events": [],
                "claims": [],
                "evidence": [],
                "ancestors": [],
                "descendants": [],
            },
        )
    )
    await hy.lineage("evt_x", tenant="tenant_other")
    request = route.calls.last.request
    assert request.headers["X-Hydra-Tenant"] == "tenant_other"
