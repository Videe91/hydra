"""Tests for `Hydra.assess_causal_cell_trust(...)` (Patch 24 —
CausalCell Trust HTTP + Python SDK).

Verifies:
  - Hits GET /trust/cells/{cell_id} with the right path
  - Returns typed CausalCellTrustAssessment envelope
    (PascalCase TrustLevel, all 12 factors, child_scores)
  - Factor list preserves applied=false entries verbatim
  - child_scores round-trips through Pydantic
  - Per-call tenant override propagates as X-Hydra-Tenant
  - Sync mirror returns the same typed envelope
  - 404 → HydraNotFoundError (unknown cell OR wrong tenant OR
    `None`-tenanted system cell — all three indistinguishable
    by design)
"""

from __future__ import annotations

from typing import Any

import httpx
import pytest
import respx

from hydra import (
    CausalCellChildTrust,
    CausalCellTrustAssessment,
    Hydra,
    HydraNotFoundError,
    HydraSync,
)


# === Fixtures ===

# A composed-cell assessment: two child reflex cells + cell-level
# outcomes + observation + executed action. Exercises every
# factor type and the child_scores serialization path.
CELL_ASSESSMENT_BODY: dict[str, Any] = {
    "cell_id": "cell_hydra_health",
    "score": 0.95,
    "level": "High",
    "explanation": (
        "Cell trust High (score 0.95) for hydra.health: "
        "children present, known child trust scores, "
        "high average child trust, all children high trust, "
        "outcomes recorded, observations present, "
        "actions executed. (5 factor(s) checked but did not fire.)"
    ),
    "factors": [
        {"kind": "children_present", "weight": 0.10, "applied": True, "detail": "2 direct child cell(s)"},
        {"kind": "known_child_trust_scores", "weight": 0.10, "applied": True, "detail": "2 of 2 children have trust scores"},
        {"kind": "high_average_child_trust", "weight": 0.20, "applied": True, "detail": "average trust 0.85 >= 0.80"},
        {"kind": "all_children_high_trust", "weight": 0.15, "applied": True, "detail": "2 of 2 known score(s) at or above 0.80"},
        {"kind": "outcomes_recorded", "weight": 0.10, "applied": True, "detail": "3 outcome(s) referenced"},
        {"kind": "observations_present", "weight": 0.10, "applied": True, "detail": "2 observation run(s) referenced"},
        {"kind": "actions_executed", "weight": 0.10, "applied": True, "detail": "2 of 4 referenced action(s) in Executed status"},
        {"kind": "any_child_low_trust", "weight": -0.20, "applied": False, "detail": "0 of 2 known score(s) below 0.50"},
        {"kind": "failed_outcomes_present", "weight": -0.20, "applied": False, "detail": "0 outcome(s) with kind Failure or Regression"},
        {"kind": "rejected_actions_present", "weight": -0.15, "applied": False, "detail": "0 referenced action(s) in Rejected status"},
        {"kind": "contradicting_claims_present", "weight": -0.20, "applied": False, "detail": "0 referenced claim(s) with non-empty evidence_against"},
        {"kind": "missing_child_trust", "weight": -0.10, "applied": False, "detail": "0 of 2 children have no trust_score"},
    ],
    "child_scores": [
        {
            "cell_id": "cell_commit_rate",
            "trust_score": 0.85,
            "claim_ids": ["claim_cr"],
            "outcome_ids": ["out_cr"],
        },
        {
            "cell_id": "cell_replication_lag",
            "trust_score": 0.85,
            "claim_ids": ["claim_rl"],
            "outcome_ids": ["out_rl"],
        },
    ],
    "assessed_at": "2026-05-30T12:00:00Z",
}


# === Async tests ===


@pytest.mark.asyncio
async def test_assess_causal_cell_trust_returns_typed_assessment(
    hy: Hydra, respx_mock: respx.MockRouter
) -> None:
    route = respx_mock.get(
        "https://hydra.test/trust/cells/cell_hydra_health"
    ).mock(return_value=httpx.Response(200, json=CELL_ASSESSMENT_BODY))

    assessment = await hy.assess_causal_cell_trust("cell_hydra_health")

    assert isinstance(assessment, CausalCellTrustAssessment)
    assert assessment.cell_id == "cell_hydra_health"
    assert assessment.level == "High"
    assert abs(assessment.score - 0.95) < 1e-9
    # Tenant propagated as X-Hydra-Tenant from the client's
    # default tenant fixture.
    assert "X-Hydra-Tenant" in route.calls.last.request.headers


@pytest.mark.asyncio
async def test_assess_causal_cell_trust_factor_list_preserved(
    hy: Hydra, respx_mock: respx.MockRouter
) -> None:
    """Pin that all 12 Patch 23 factors come through Pydantic
    unchanged — applied=true AND applied=false entries.
    Client-side code that branches on factor names MUST see
    every factor, not just the ones that fired."""
    respx_mock.get(
        "https://hydra.test/trust/cells/cell_hydra_health"
    ).mock(return_value=httpx.Response(200, json=CELL_ASSESSMENT_BODY))

    assessment = await hy.assess_causal_cell_trust("cell_hydra_health")

    assert len(assessment.factors) == 12
    # Each of the 12 factor kinds appears, with its weight + detail.
    expected_kinds = {
        "children_present",
        "known_child_trust_scores",
        "high_average_child_trust",
        "all_children_high_trust",
        "outcomes_recorded",
        "observations_present",
        "actions_executed",
        "any_child_low_trust",
        "failed_outcomes_present",
        "rejected_actions_present",
        "contradicting_claims_present",
        "missing_child_trust",
    }
    seen_kinds = {f.kind for f in assessment.factors}
    assert seen_kinds == expected_kinds

    # At least one applied=false factor survives — guard against
    # accidental client-side filtering.
    unapplied = [f for f in assessment.factors if not f.applied]
    assert len(unapplied) == 5  # matches the fixture


@pytest.mark.asyncio
async def test_assess_causal_cell_trust_child_scores_preserved(
    hy: Hydra, respx_mock: respx.MockRouter
) -> None:
    """child_scores must round-trip through Pydantic with each
    child's cell_id, trust_score, claim_ids, outcome_ids
    preserved. Dashboards depend on this to render the
    composition tree."""
    respx_mock.get(
        "https://hydra.test/trust/cells/cell_hydra_health"
    ).mock(return_value=httpx.Response(200, json=CELL_ASSESSMENT_BODY))

    assessment = await hy.assess_causal_cell_trust("cell_hydra_health")

    assert len(assessment.child_scores) == 2
    first = assessment.child_scores[0]
    assert isinstance(first, CausalCellChildTrust)
    assert first.cell_id == "cell_commit_rate"
    assert first.trust_score == 0.85
    assert first.claim_ids == ["claim_cr"]
    assert first.outcome_ids == ["out_cr"]


@pytest.mark.asyncio
async def test_assess_causal_cell_trust_tenant_override(
    hy: Hydra, respx_mock: respx.MockRouter
) -> None:
    """Per-call tenant override propagates as X-Hydra-Tenant."""
    route = respx_mock.get(
        "https://hydra.test/trust/cells/cell_x"
    ).mock(return_value=httpx.Response(200, json={
        **CELL_ASSESSMENT_BODY,
        "cell_id": "cell_x",
    }))

    await hy.assess_causal_cell_trust(
        "cell_x",
        tenant="tenant_other",
    )

    assert (
        route.calls.last.request.headers["X-Hydra-Tenant"]
        == "tenant_other"
    )


@pytest.mark.asyncio
async def test_assess_causal_cell_trust_unknown_raises_not_found(
    hy: Hydra, respx_mock: respx.MockRouter
) -> None:
    """404 → HydraNotFoundError. Unknown cell, wrong tenant, AND
    None-tenanted system cells all surface identically by design
    (strict tenant isolation — no cross-tenant probing)."""
    respx_mock.get(
        "https://hydra.test/trust/cells/cell_ghost"
    ).mock(
        return_value=httpx.Response(
            404,
            json={"error": "causal cell not found: cell_ghost"},
        )
    )

    with pytest.raises(HydraNotFoundError):
        await hy.assess_causal_cell_trust("cell_ghost")


# === Sync mirror ===


def test_assess_causal_cell_trust_sync_mirror(
    hy_sync: HydraSync, respx_mock: respx.MockRouter
) -> None:
    """`HydraSync.assess_causal_cell_trust` returns the same
    typed envelope as the async client. Sync parity is non-
    negotiable for operator-facing methods — trust dashboards
    often call from non-async runbooks."""
    respx_mock.get(
        "https://hydra.test/trust/cells/cell_hydra_health"
    ).mock(return_value=httpx.Response(200, json=CELL_ASSESSMENT_BODY))

    assessment = hy_sync.assess_causal_cell_trust("cell_hydra_health")

    assert isinstance(assessment, CausalCellTrustAssessment)
    assert assessment.level == "High"
    assert len(assessment.factors) == 12
    assert len(assessment.child_scores) == 2
