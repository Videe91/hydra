"""Tests for `Hydra.auto_approve_action_if_trusted(...)` (Trust
Patch 7 / Patch 15 — trust-gated auto-approval).

Verifies:
  - Hits POST /actions/{id}/auto-approve with the right body and
    SDK default min_trust_score=0.90 (stricter than auto-execute)
  - approved=true path stamps actor_hydra_trust_gate as approver
  - approved=false path on low trust returns 200 with trust
    populated, approved_by=None
  - approved=false path on hard-block factor (e.g.
    contradicting_evidence) returns 200 with the reason naming
    the blocking factor
  - Sync mirror returns the same envelope
  - Unknown action_id → HydraNotFoundError (404)
"""

from __future__ import annotations

import json
from typing import Any

import httpx
import pytest
import respx

from hydra import (
    AutoApprovalDecision,
    Hydra,
    HydraNotFoundError,
    HydraSync,
)


# === Fixtures ===

APPROVED_RESPONSE: dict[str, Any] = {
    "approved": True,
    "reason": (
        "auto-approved: trust High (score 0.85 >= 0.80) AND model has "
        "operator-approved history AND no hard-block factors"
    ),
    "trust": {
        "claim_id": "claim_abc",
        "score": 0.85,
        "level": "High",
        "explanation": "High trust: claim verified, model operator approved historically.",
        "factors": [
            {
                "kind": "model_operator_approved_historically",
                "weight": 0.10,
                "applied": True,
                "detail": "at least one of the model's prior actions had a non-Hydra approver (human endorsement)",
            },
        ],
        "related_action_ids": ["act_sibling", "act_new"],
        "related_outcome_ids": ["out_sibling"],
        "observation_run_ids": ["mmrun_x"],
        "assessed_at": "2026-05-29T00:00:00Z",
    },
    "action_id": "act_new",
    "approved_by": "actor_hydra_trust_gate",
}

LOW_TRUST_SKIP_RESPONSE: dict[str, Any] = {
    "approved": False,
    "reason": "trust insufficient: level=Medium, score=0.50 (min=0.90)",
    "trust": {
        "claim_id": "claim_abc",
        "score": 0.50,
        "level": "Medium",
        "explanation": "Medium trust.",
        "factors": [],
        "related_action_ids": [],
        "related_outcome_ids": [],
        "observation_run_ids": [],
        "assessed_at": "2026-05-29T00:00:00Z",
    },
    "action_id": "act_x",
    "approved_by": None,
}

HARD_BLOCK_SKIP_RESPONSE: dict[str, Any] = {
    "approved": False,
    "reason": (
        "hard-block factor applied: contradicting_evidence "
        "(auto-approval vetoed regardless of score)"
    ),
    "trust": {
        "claim_id": "claim_abc",
        "score": 0.65,
        "level": "Medium",
        "explanation": "Medium trust with contradicting evidence.",
        "factors": [
            {
                "kind": "contradicting_evidence",
                "weight": -0.20,
                "applied": True,
                "detail": "1 contradicting evidence record(s)",
            },
        ],
        "related_action_ids": [],
        "related_outcome_ids": [],
        "observation_run_ids": [],
        "assessed_at": "2026-05-29T00:00:00Z",
    },
    "action_id": "act_disputed",
    "approved_by": None,
}


# === Async tests ===


@pytest.mark.asyncio
async def test_auto_approve_with_high_trust_stamps_trust_gate_actor(
    hy: Hydra, respx_mock: respx.MockRouter
) -> None:
    """Happy path: trust passes + operator history + no hard
    blocks → approved=True, approved_by=actor_hydra_trust_gate.
    SDK default min_trust_score=0.90 is in the body."""
    route = respx_mock.post(
        "https://hydra.test/actions/act_new/auto-approve"
    ).mock(return_value=httpx.Response(200, json=APPROVED_RESPONSE))

    decision = await hy.auto_approve_action_if_trusted(
        "act_new", actor="actor_ops"
    )

    assert isinstance(decision, AutoApprovalDecision)
    assert decision.approved is True
    assert "auto-approved" in decision.reason
    assert decision.approved_by == "actor_hydra_trust_gate"
    assert decision.action_id == "act_new"
    assert decision.trust is not None
    assert decision.trust.level == "High"

    body = json.loads(route.calls.last.request.content)
    assert body == {"actor": "actor_ops", "min_trust_score": 0.90}


@pytest.mark.asyncio
async def test_auto_approve_with_low_trust_returns_skip_envelope(
    hy: Hydra, respx_mock: respx.MockRouter
) -> None:
    """Decision envelope: trust below threshold → 200 with
    approved=False. trust is populated, approved_by is None."""
    respx_mock.post(
        "https://hydra.test/actions/act_x/auto-approve"
    ).mock(return_value=httpx.Response(200, json=LOW_TRUST_SKIP_RESPONSE))

    decision = await hy.auto_approve_action_if_trusted(
        "act_x", actor="actor_ops"
    )

    assert decision.approved is False
    assert "trust insufficient" in decision.reason
    assert decision.trust is not None
    assert decision.trust.level == "Medium"
    assert decision.approved_by is None


@pytest.mark.asyncio
async def test_auto_approve_with_hard_block_factor_returns_skip(
    hy: Hydra, respx_mock: respx.MockRouter
) -> None:
    """Hard-block factor (contradicting_evidence) veto → 200 with
    approved=False. The reason names the specific blocking
    factor so operators can act on it. trust still surfaced."""
    respx_mock.post(
        "https://hydra.test/actions/act_disputed/auto-approve"
    ).mock(return_value=httpx.Response(200, json=HARD_BLOCK_SKIP_RESPONSE))

    decision = await hy.auto_approve_action_if_trusted(
        "act_disputed", actor="actor_ops"
    )

    assert decision.approved is False
    assert "hard-block" in decision.reason
    assert "contradicting_evidence" in decision.reason
    assert decision.trust is not None
    assert decision.approved_by is None


@pytest.mark.asyncio
async def test_auto_approve_unknown_action_raises_not_found(
    hy: Hydra, respx_mock: respx.MockRouter
) -> None:
    """Unknown action_id → 404 → `HydraNotFoundError`."""
    respx_mock.post(
        "https://hydra.test/actions/act_ghost/auto-approve"
    ).mock(
        return_value=httpx.Response(
            404, json={"error": "unknown action: act_ghost"}
        )
    )

    with pytest.raises(HydraNotFoundError):
        await hy.auto_approve_action_if_trusted(
            "act_ghost", actor="actor_ops"
        )


# === Sync mirror ===


def test_auto_approve_sync_mirror_returns_same_envelope(
    hy_sync: HydraSync, respx_mock: respx.MockRouter
) -> None:
    """`HydraSync.auto_approve_action_if_trusted` returns the same
    typed envelope as the async client. Sync parity is non-
    negotiable for operator-facing methods."""
    respx_mock.post(
        "https://hydra.test/actions/act_new/auto-approve"
    ).mock(return_value=httpx.Response(200, json=APPROVED_RESPONSE))

    decision = hy_sync.auto_approve_action_if_trusted(
        "act_new",
        actor="actor_ops",
        min_trust_score=0.80,
    )

    assert isinstance(decision, AutoApprovalDecision)
    assert decision.approved is True
    assert decision.approved_by == "actor_hydra_trust_gate"
    assert decision.trust is not None
    assert decision.trust.level == "High"
