"""Tests for `Hydra.assess_claim_trust(...)` (Trust Patch 2 / Patch 10
— Trust HTTP + Python SDK).

Verifies:
  - Hits GET /trust/claims/{claim_id} with the right path
  - Returns typed TrustAssessment envelope (PascalCase TrustLevel)
  - Factor list preserves applied=false entries verbatim
  - Per-call tenant override propagates as X-Hydra-Tenant
  - Sync mirror returns the same typed envelope
  - 404 → HydraNotFoundError (unknown claim OR wrong tenant — both
    surface identically by design)
"""

from __future__ import annotations

from typing import Any

import httpx
import pytest
import respx

from hydra import (
    Hydra,
    HydraNotFoundError,
    HydraSync,
    TrustAssessment,
    TrustFactor,
)


# === Fixtures ===

ASSESSMENT_BODY: dict[str, Any] = {
    "claim_id": "claim_abc",
    "score": 0.85,
    "level": "High",
    "explanation": (
        "High trust (score 0.85) for claim claim_abc: claim verified, "
        "high confidence claim, supporting evidence present, reliable "
        "supporting evidence, action executed, outcome recorded, model "
        "observation exists. (5 factor(s) checked but did not fire.)"
    ),
    "factors": [
        {"kind": "claim_verified", "weight": 0.20, "applied": True, "detail": "claim.status == Verified"},
        {"kind": "claim_supported", "weight": 0.10, "applied": False, "detail": "claim is not at Supported status"},
        {"kind": "high_confidence_claim", "weight": 0.10, "applied": True, "detail": "claim.confidence = 0.92 (threshold 0.80)"},
        {"kind": "supporting_evidence_present", "weight": 0.10, "applied": True, "detail": "1 supporting evidence record(s)"},
        {"kind": "reliable_supporting_evidence", "weight": 0.10, "applied": True, "detail": "at least one supporting evidence has reliability >= 0.75"},
        {"kind": "operator_approved", "weight": 0.15, "applied": False, "detail": "no operator approval found (cascade auto-approvals don't count)"},
        {"kind": "action_executed", "weight": 0.15, "applied": True, "detail": "at least one related action reached Executed status"},
        {"kind": "outcome_recorded", "weight": 0.10, "applied": True, "detail": "1 outcome(s) recorded across related actions"},
        {"kind": "model_observation_exists", "weight": 0.10, "applied": True, "detail": "MicroModelObservation recorded for run_id mmrun_xyz"},
        {"kind": "contradicting_evidence", "weight": -0.20, "applied": False, "detail": "0 contradicting evidence record(s)"},
        {"kind": "claim_disputed", "weight": -0.30, "applied": False, "detail": "claim is not at Disputed status"},
        {"kind": "claim_retracted", "weight": -1.00, "applied": False, "detail": "claim is not retracted"},
    ],
    "related_action_ids": ["act_abc"],
    "related_outcome_ids": ["out_xyz"],
    "observation_run_ids": ["mmrun_xyz"],
    "assessed_at": "2026-05-29T00:00:00Z",
}


# === Async tests ===


@pytest.mark.asyncio
async def test_assess_claim_trust_returns_typed_assessment(
    hy: Hydra, respx_mock: respx.MockRouter
) -> None:
    """Happy path: returns typed TrustAssessment with PascalCase
    level field and all eight envelope fields populated."""
    route = respx_mock.get(
        "https://hydra.test/trust/claims/claim_abc"
    ).mock(return_value=httpx.Response(200, json=ASSESSMENT_BODY))

    result = await hy.assess_claim_trust("claim_abc")

    assert isinstance(result, TrustAssessment)
    assert result.claim_id == "claim_abc"
    assert result.score == 0.85
    assert result.level == "High"
    assert "High trust" in result.explanation
    assert len(result.factors) == 12
    assert result.related_action_ids == ["act_abc"]
    assert result.related_outcome_ids == ["out_xyz"]
    assert result.observation_run_ids == ["mmrun_xyz"]
    assert result.assessed_at == "2026-05-29T00:00:00Z"
    # Verify the SDK sent X-Hydra-Tenant (from the conftest default).
    assert route.calls.last.request.headers.get("X-Hydra-Tenant") == "tenant_test"


@pytest.mark.asyncio
async def test_assess_claim_trust_factor_list_preserved(
    hy: Hydra, respx_mock: respx.MockRouter
) -> None:
    """The applied=false factors are LOAD-BEARING — they're part of
    the engine's contract for explainability and Patch 11's
    auto-execution policy will branch on them. Pin that the SDK
    preserves them verbatim and doesn't filter."""
    respx_mock.get(
        "https://hydra.test/trust/claims/claim_abc"
    ).mock(return_value=httpx.Response(200, json=ASSESSMENT_BODY))

    result = await hy.assess_claim_trust("claim_abc")

    # Every factor is a typed TrustFactor.
    assert all(isinstance(f, TrustFactor) for f in result.factors)
    applied = [f for f in result.factors if f.applied]
    unapplied = [f for f in result.factors if not f.applied]
    assert len(applied) == 7
    assert len(unapplied) == 5
    # Specific applied=false factor preserved verbatim, including weight.
    operator_factor = next(f for f in result.factors if f.kind == "operator_approved")
    assert operator_factor.applied is False
    assert operator_factor.weight == 0.15
    assert "no operator approval found" in operator_factor.detail
    # Specific applied=true factor preserved.
    verified = next(f for f in result.factors if f.kind == "claim_verified")
    assert verified.applied is True
    assert verified.weight == 0.20


@pytest.mark.asyncio
async def test_assess_claim_trust_tenant_override(
    hy: Hydra, respx_mock: respx.MockRouter
) -> None:
    """Per-call tenant override applies (Rule #7) — the SDK sends
    the override as X-Hydra-Tenant, replacing the default tenant
    captured at construction time."""
    route = respx_mock.get(
        "https://hydra.test/trust/claims/claim_abc"
    ).mock(return_value=httpx.Response(200, json=ASSESSMENT_BODY))

    await hy.assess_claim_trust("claim_abc", tenant="tenant_other")

    assert route.calls.last.request.headers["X-Hydra-Tenant"] == "tenant_other"


@pytest.mark.asyncio
async def test_assess_claim_trust_unknown_raises_not_found(
    hy: Hydra, respx_mock: respx.MockRouter
) -> None:
    """Unknown claim OR wrong-tenant claim → 404 → `HydraNotFoundError`.
    Patch 10's strict isolation means these two cases are
    indistinguishable from the caller's perspective."""
    respx_mock.get(
        "https://hydra.test/trust/claims/claim_does_not_exist"
    ).mock(
        return_value=httpx.Response(
            404, json={"error": "claim not found: claim_does_not_exist"}
        )
    )

    with pytest.raises(HydraNotFoundError):
        await hy.assess_claim_trust("claim_does_not_exist")


@pytest.mark.asyncio
async def test_assess_claim_trust_level_pascal_case(
    hy: Hydra, respx_mock: respx.MockRouter
) -> None:
    """TrustLevel uses PascalCase on the wire (matches the Rust
    serde default). Validate the Literal accepts every wire form."""
    for level_value in ("High", "Medium", "Low", "Unknown"):
        body = dict(ASSESSMENT_BODY)
        body["level"] = level_value
        respx_mock.get(
            f"https://hydra.test/trust/claims/claim_{level_value.lower()}"
        ).mock(return_value=httpx.Response(200, json=body))
        result = await hy.assess_claim_trust(f"claim_{level_value.lower()}")
        assert result.level == level_value


# === Sync mirror ===


def test_assess_claim_trust_sync_mirror(
    hy_sync: HydraSync, respx_mock: respx.MockRouter
) -> None:
    """`HydraSync.assess_claim_trust` returns the same typed envelope
    as the async client. Sync parity is non-negotiable for operator-
    facing methods — trust dashboards frequently call from non-async
    tooling."""
    respx_mock.get(
        "https://hydra.test/trust/claims/claim_abc"
    ).mock(return_value=httpx.Response(200, json=ASSESSMENT_BODY))

    result = hy_sync.assess_claim_trust("claim_abc")

    assert isinstance(result, TrustAssessment)
    assert result.level == "High"
    assert result.score == 0.85
    assert len(result.factors) == 12


# === Patch 12 — Reflex Trust Calibration ===
#
# Patch 12 adds 3 new historical factors to the engine's trust
# assessment: reflex_history_present, model_proven_executed,
# model_operator_approved_historically. The SDK side has ZERO new
# methods or types — TrustFactor and TrustAssessment carry the
# data as-is.
#
# The one critical contract: the SDK MUST preserve factor entries
# verbatim, including factors whose `kind` is unknown to this SDK
# version. Future patches will add more factors; old SDK builds
# must round-trip them without filtering or normalising.


REFLEX_CALIBRATED_BODY: dict[str, Any] = {
    "claim_id": "claim_xyz",
    "score": 0.85,
    "level": "High",
    "explanation": "High trust: claim verified + model has 3 prior successful executions.",
    "factors": [
        # Patch 9 baseline (truncated for brevity — only the ones
        # this test asserts on are needed).
        {"kind": "claim_verified", "weight": 0.20, "applied": True, "detail": "claim.status == Verified"},
        {"kind": "operator_approved", "weight": 0.15, "applied": False, "detail": "no operator approval found"},
        # Patch 12 historical factors:
        {"kind": "reflex_history_present", "weight": 0.10, "applied": True, "detail": "model has 3 prior observation(s)"},
        {"kind": "model_proven_executed", "weight": 0.15, "applied": True, "detail": "model has 3 prior observation(s) (proven threshold = 3)"},
        {"kind": "model_operator_approved_historically", "weight": 0.10, "applied": True, "detail": "at least one of the model's prior actions had a non-cascade approver"},
        # Forward-compat: a HYPOTHETICAL future Patch 13 factor.
        # The SDK MUST preserve this without filtering or
        # normalisation — even though the SDK doesn't know about
        # `future_outcome_resolved` yet.
        {"kind": "future_outcome_resolved", "weight": 0.05, "applied": True, "detail": "(future patch — SDK should preserve verbatim)"},
    ],
    "related_action_ids": ["act_x"],
    "related_outcome_ids": ["out_x"],
    "observation_run_ids": ["mmrun_x"],
    "assessed_at": "2026-05-29T00:00:00Z",
}


@pytest.mark.asyncio
async def test_sdk_preserves_patch_12_factor_kinds_verbatim(
    hy: Hydra, respx_mock: respx.MockRouter
) -> None:
    """Patch 12 (reflex calibration) and beyond add new factor
    `kind` strings. The SDK MUST preserve them all — clients are
    expected to branch on factor kind without prior knowledge of
    which version of Hydra added which factor. Don't filter or
    normalise unknown kinds on the client side.

    This test pins ALL THREE Patch 12 factors AND one
    forward-compat hypothetical-future factor. If the SDK ever
    starts filtering by kind allow-list, this test fires
    immediately."""
    respx_mock.get(
        "https://hydra.test/trust/claims/claim_xyz"
    ).mock(return_value=httpx.Response(200, json=REFLEX_CALIBRATED_BODY))

    result = await hy.assess_claim_trust("claim_xyz")

    kinds = {f.kind for f in result.factors}
    # Patch 12's 3 historical factors round-trip with their exact
    # kind strings — these are public API contracts.
    assert "reflex_history_present" in kinds
    assert "model_proven_executed" in kinds
    assert "model_operator_approved_historically" in kinds
    # A factor unknown to this SDK version still round-trips. This
    # is the forward-compatibility invariant — Patch 13+ will add
    # more factors; old SDK builds must surface them as-is.
    assert "future_outcome_resolved" in kinds
    # And the details for the Patch 12 factors are preserved.
    proven = next(f for f in result.factors if f.kind == "model_proven_executed")
    assert proven.applied is True
    assert proven.weight == 0.15
    assert "proven threshold" in proven.detail
