"""Tests for `Hydra.auto_execute_action_if_trusted(...)` (Trust
Patch 3 / Patch 11 — trust-aware auto-execution gate).

Verifies:
  - Hits POST /actions/{id}/auto-execute with the right body
  - executed=true path returns full envelope (trust + execution
    both populated)
  - executed=false path on low trust returns 200 with trust
    populated, execution=None
  - executed=false path on no related claim returns 200 with
    both sub-objects None
  - Sync mirror returns the same envelope
  - Unknown action_id → HydraNotFoundError (404)
  - Wrong kind → HydraValidationError (400)
  - Tenant override propagates
"""

from __future__ import annotations

import json
from typing import Any

import httpx
import pytest
import respx

from hydra import (
    AutoExecutionDecision,
    Hydra,
    HydraNotFoundError,
    HydraSync,
    HydraValidationError,
)


# === Fixtures ===

EXECUTED_RESPONSE: dict[str, Any] = {
    "executed": True,
    "reason": "trust High (score 0.85) meets threshold 0.80; auto-executed",
    "trust": {
        "claim_id": "claim_abc",
        "score": 0.85,
        "level": "High",
        "explanation": "High trust: claim verified, action executed (sibling), outcome recorded.",
        "factors": [
            {"kind": "claim_verified", "weight": 0.20, "applied": True, "detail": "claim.status == Verified"},
            {"kind": "operator_approved", "weight": 0.15, "applied": False, "detail": "no operator approval found"},
        ],
        "related_action_ids": ["act_sibling", "act_new"],
        "related_outcome_ids": ["out_sibling"],
        "observation_run_ids": ["mmrun_x"],
        "assessed_at": "2026-05-29T00:00:00Z",
    },
    "execution": {
        "action_id": "act_new",
        "previous_status": "approved",
        "final_status": "executed",
        "outcome_id": "out_new",
        "executed_by": "actor_hydra_trust_gate",
        "executed_at": "2026-05-29T00:00:01Z",
    },
}

LOW_TRUST_SKIP_RESPONSE: dict[str, Any] = {
    "executed": False,
    "reason": "trust insufficient: level=Medium, score=0.50 (min=0.80)",
    "trust": {
        "claim_id": "claim_abc",
        "score": 0.50,
        "level": "Medium",
        "explanation": "Medium trust: verified claim, no execution history.",
        "factors": [],
        "related_action_ids": [],
        "related_outcome_ids": [],
        "observation_run_ids": [],
        "assessed_at": "2026-05-29T00:00:00Z",
    },
    "execution": None,
}

NO_CLAIM_SKIP_RESPONSE: dict[str, Any] = {
    "executed": False,
    "reason": "action has no related_claims — not trust-assessable (likely not a model-derived action)",
    "trust": None,
    "execution": None,
}


# === Async tests ===


@pytest.mark.asyncio
async def test_auto_execute_with_high_trust_returns_full_envelope(
    hy: Hydra, respx_mock: respx.MockRouter
) -> None:
    """Happy path: trust passes → executed=True, BOTH trust and
    execution sub-objects populated."""
    route = respx_mock.post(
        "https://hydra.test/actions/act_new/auto-execute"
    ).mock(return_value=httpx.Response(200, json=EXECUTED_RESPONSE))

    decision = await hy.auto_execute_action_if_trusted(
        "act_new", actor="actor_hydra_trust_gate"
    )

    assert isinstance(decision, AutoExecutionDecision)
    assert decision.executed is True
    assert "trust High" in decision.reason
    assert decision.trust is not None
    assert decision.trust.level == "High"
    assert decision.trust.score == 0.85
    assert decision.execution is not None
    assert decision.execution.final_status == "executed"
    assert decision.execution.executed_by == "actor_hydra_trust_gate"

    body = json.loads(route.calls.last.request.content)
    assert body == {"actor": "actor_hydra_trust_gate", "min_trust_score": 0.80}


@pytest.mark.asyncio
async def test_auto_execute_with_low_trust_returns_skip_envelope(
    hy: Hydra, respx_mock: respx.MockRouter
) -> None:
    """The decision endpoint contract: low trust returns 200 with
    executed=False, trust populated, execution=None. NOT a 400 or
    409 — the decision IS the data."""
    respx_mock.post(
        "https://hydra.test/actions/act_x/auto-execute"
    ).mock(return_value=httpx.Response(200, json=LOW_TRUST_SKIP_RESPONSE))

    decision = await hy.auto_execute_action_if_trusted(
        "act_x", actor="actor_hydra_trust_gate"
    )

    assert decision.executed is False
    assert "trust insufficient" in decision.reason
    assert decision.trust is not None
    assert decision.trust.level == "Medium"
    assert decision.trust.score == 0.50
    assert decision.execution is None


@pytest.mark.asyncio
async def test_auto_execute_with_no_related_claims_returns_skip(
    hy: Hydra, respx_mock: respx.MockRouter
) -> None:
    """No related_claims: 200 with executed=False AND trust=None.
    Distinct from low-trust (which has trust populated) — operators
    can branch on which sub-object is null to know which gate
    failed."""
    respx_mock.post(
        "https://hydra.test/actions/act_y/auto-execute"
    ).mock(return_value=httpx.Response(200, json=NO_CLAIM_SKIP_RESPONSE))

    decision = await hy.auto_execute_action_if_trusted(
        "act_y", actor="actor_hydra_trust_gate"
    )

    assert decision.executed is False
    assert "no related_claims" in decision.reason
    assert decision.trust is None
    assert decision.execution is None


@pytest.mark.asyncio
async def test_auto_execute_tenant_override(
    hy: Hydra, respx_mock: respx.MockRouter
) -> None:
    """Per-call tenant override propagates as X-Hydra-Tenant."""
    route = respx_mock.post(
        "https://hydra.test/actions/act_new/auto-execute"
    ).mock(return_value=httpx.Response(200, json=EXECUTED_RESPONSE))

    await hy.auto_execute_action_if_trusted(
        "act_new",
        actor="actor_hydra_trust_gate",
        tenant="tenant_other",
    )

    assert route.calls.last.request.headers["X-Hydra-Tenant"] == "tenant_other"


@pytest.mark.asyncio
async def test_auto_execute_unknown_action_raises_not_found(
    hy: Hydra, respx_mock: respx.MockRouter
) -> None:
    """Unknown action_id → 404 → `HydraNotFoundError`."""
    respx_mock.post(
        "https://hydra.test/actions/act_ghost/auto-execute"
    ).mock(
        return_value=httpx.Response(
            404, json={"error": "unknown action: act_ghost"}
        )
    )

    with pytest.raises(HydraNotFoundError):
        await hy.auto_execute_action_if_trusted(
            "act_ghost", actor="actor_hydra_trust_gate"
        )


@pytest.mark.asyncio
async def test_auto_execute_non_notify_kind_raises_validation_error(
    hy: Hydra, respx_mock: respx.MockRouter
) -> None:
    """Wrong kind → 400 → `HydraValidationError`. This is a HARD
    contract: a Backfill action can NEVER be auto-executed by this
    method, so it's an error rather than a decision skip."""
    respx_mock.post(
        "https://hydra.test/actions/act_backfill/auto-execute"
    ).mock(
        return_value=httpx.Response(
            400,
            json={
                "error": (
                    "invalid action kind: act_backfill is not Notify "
                    "(Patch 11 only auto-executes Notify actions; got Backfill)"
                )
            },
        )
    )

    with pytest.raises(HydraValidationError) as exc_info:
        await hy.auto_execute_action_if_trusted(
            "act_backfill", actor="actor_hydra_trust_gate"
        )
    assert "invalid action kind" in str(exc_info.value)


# === Sync mirror ===


def test_auto_execute_sync_mirror(
    hy_sync: HydraSync, respx_mock: respx.MockRouter
) -> None:
    """`HydraSync.auto_execute_action_if_trusted` returns the same
    typed envelope as the async client. Sync parity is non-
    negotiable for operator-facing methods — trust dashboards
    often call from non-async runbooks."""
    respx_mock.post(
        "https://hydra.test/actions/act_new/auto-execute"
    ).mock(return_value=httpx.Response(200, json=EXECUTED_RESPONSE))

    decision = hy_sync.auto_execute_action_if_trusted(
        "act_new",
        actor="actor_hydra_trust_gate",
        min_trust_score=0.85,
    )

    assert isinstance(decision, AutoExecutionDecision)
    assert decision.executed is True
    assert decision.trust is not None
    assert decision.trust.level == "High"
    assert decision.execution is not None
