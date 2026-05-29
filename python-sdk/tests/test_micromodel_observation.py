"""Tests for `hy.diagnostics.record_observation_from_outcome(...)`
(MicroModel Patch 8 — outcome learning loop).

Verifies:
  - Hits POST /diagnostics/micromodels/observations/from-outcome/{id}
    with the right body and outcome_id in the path
  - Returns typed MicroModelObservation with run_id populated
  - observed_outcome JSON is preserved verbatim from the wire
  - Sync mirror returns the same typed envelope
  - Per-call tenant override propagates as X-Hydra-Tenant
  - 404 → HydraNotFoundError
  - 400 → HydraValidationError (chain-walk failure)
"""

from __future__ import annotations

import json
from typing import Any

import httpx
import pytest
import respx

from hydra import (
    Hydra,
    HydraNotFoundError,
    HydraSync,
    HydraValidationError,
    MicroModelObservation,
)


# === Fixtures ===

OBSERVATION_RESPONSE: dict[str, Any] = {
    "run_id": "mmrun_critical",
    "observed_outcome": {
        "outcome_id": "out_xyz",
        "action_id": "act_abc",
        "claim_id": "claim_aaa",
        "outcome_kind": "Custom(notification_recorded)",
        "outcome_summary": "Notify action executed as internal stub",
        "action_lifecycle": "executed",
        "operator_approved": True,
        "operator_rejected": False,
        "observed_by": "actor_ops",
    },
    "error": None,
    "observed_at": "2026-05-29T00:00:00Z",
}


# === Async tests ===


@pytest.mark.asyncio
async def test_record_observation_from_outcome_returns_typed_observation(
    hy: Hydra, respx_mock: respx.MockRouter
) -> None:
    """Happy path: returns typed MicroModelObservation with run_id
    populated from the prediction it walked back to."""
    route = respx_mock.post(
        "https://hydra.test/diagnostics/micromodels/observations/from-outcome/out_xyz"
    ).mock(return_value=httpx.Response(200, json=OBSERVATION_RESPONSE))

    result = await hy.diagnostics.record_observation_from_outcome(
        "out_xyz", observed_by="actor_ops"
    )

    assert isinstance(result, MicroModelObservation)
    assert result.run_id == "mmrun_critical"
    assert result.error is None
    assert result.observed_at == "2026-05-29T00:00:00Z"

    body = json.loads(route.calls.last.request.content)
    assert body == {"observed_by": "actor_ops"}


@pytest.mark.asyncio
async def test_record_observation_preserves_observed_outcome_audit_linkage(
    hy: Hydra, respx_mock: respx.MockRouter
) -> None:
    """The audit linkage Patch 8 packs into observed_outcome must
    round-trip verbatim. Patch 9 / trust scoring will read these
    fields without re-walking the chain — the SDK MUST NOT mutate
    them."""
    respx_mock.post(
        "https://hydra.test/diagnostics/micromodels/observations/from-outcome/out_xyz"
    ).mock(return_value=httpx.Response(200, json=OBSERVATION_RESPONSE))

    result = await hy.diagnostics.record_observation_from_outcome(
        "out_xyz", observed_by="actor_ops"
    )

    assert result.observed_outcome["outcome_id"] == "out_xyz"
    assert result.observed_outcome["action_id"] == "act_abc"
    assert result.observed_outcome["claim_id"] == "claim_aaa"
    assert (
        result.observed_outcome["outcome_kind"]
        == "Custom(notification_recorded)"
    )
    assert result.observed_outcome["action_lifecycle"] == "executed"
    assert result.observed_outcome["operator_approved"] is True
    assert result.observed_outcome["operator_rejected"] is False


@pytest.mark.asyncio
async def test_record_observation_tenant_override(
    hy: Hydra, respx_mock: respx.MockRouter
) -> None:
    """Per-call tenant override applies (Rule #7)."""
    route = respx_mock.post(
        "https://hydra.test/diagnostics/micromodels/observations/from-outcome/out_xyz"
    ).mock(return_value=httpx.Response(200, json=OBSERVATION_RESPONSE))

    await hy.diagnostics.record_observation_from_outcome(
        "out_xyz", observed_by="actor_ops", tenant="tenant_other"
    )

    assert route.calls.last.request.headers["X-Hydra-Tenant"] == "tenant_other"


@pytest.mark.asyncio
async def test_record_observation_unknown_outcome_raises_not_found(
    hy: Hydra, respx_mock: respx.MockRouter
) -> None:
    """Unknown outcome_id → 404 → `HydraNotFoundError`."""
    respx_mock.post(
        "https://hydra.test/diagnostics/micromodels/observations/from-outcome/out_ghost"
    ).mock(
        return_value=httpx.Response(
            404, json={"error": "unknown outcome: out_ghost"}
        )
    )

    with pytest.raises(HydraNotFoundError):
        await hy.diagnostics.record_observation_from_outcome(
            "out_ghost", observed_by="actor_ops"
        )


@pytest.mark.asyncio
async def test_record_observation_chain_break_raises_validation_error(
    hy: Hydra, respx_mock: respx.MockRouter
) -> None:
    """The outcome exists but the chain walk fails (e.g., the
    action had no related_claims). The HTTP layer surfaces this as
    400 → `HydraValidationError` so callers can distinguish 'not a
    model-derived outcome' from 'outcome doesn't exist'."""
    respx_mock.post(
        "https://hydra.test/diagnostics/micromodels/observations/from-outcome/out_xyz"
    ).mock(
        return_value=httpx.Response(
            400,
            json={
                "error": (
                    "outcome not traceable: action act_abc has no "
                    "related_claims — not a model-derived action"
                )
            },
        )
    )

    with pytest.raises(HydraValidationError) as exc_info:
        await hy.diagnostics.record_observation_from_outcome(
            "out_xyz", observed_by="actor_ops"
        )
    assert "outcome not traceable" in str(exc_info.value)


# === Sync mirror ===


def test_record_observation_sync_mirror(
    hy_sync: HydraSync, respx_mock: respx.MockRouter
) -> None:
    """`HydraSync.diagnostics.record_observation_from_outcome`
    returns the same typed envelope as the async client."""
    respx_mock.post(
        "https://hydra.test/diagnostics/micromodels/observations/from-outcome/out_xyz"
    ).mock(return_value=httpx.Response(200, json=OBSERVATION_RESPONSE))

    result = hy_sync.diagnostics.record_observation_from_outcome(
        "out_xyz", observed_by="actor_ops"
    )

    assert isinstance(result, MicroModelObservation)
    assert result.run_id == "mmrun_critical"
    assert result.observed_outcome["outcome_id"] == "out_xyz"
    assert result.error is None


# === Trust Patch 5 (Patch 13) — rejection-path observations ===


REJECTED_OBSERVATION_RESPONSE: dict[str, Any] = {
    "run_id": "mmrun_rejected",
    "observed_outcome": {
        "outcome_id": None,
        "action_id": "act_rejected",
        "claim_id": "claim_xyz",
        "outcome_kind": "Rejected",
        "outcome_summary": (
            "Action rejected by operator: false alarm during maintenance"
        ),
        "action_lifecycle": "rejected",
        "operator_approved": False,
        "operator_rejected": True,
        "rejection_reason": "false alarm during maintenance",
        "observed_by": "actor_oncall_alice",
    },
    "error": None,
    "observed_at": "2026-05-29T00:00:00Z",
}


@pytest.mark.asyncio
async def test_record_observation_from_rejected_action_returns_typed_observation(
    hy: Hydra, respx_mock: respx.MockRouter
) -> None:
    """Happy path: operator-rejected model-derived action produces
    a rejection-shaped observation. `action_lifecycle == "rejected"`,
    `operator_rejected == true`, `rejection_reason` populated."""
    route = respx_mock.post(
        "https://hydra.test/diagnostics/micromodels/observations/from-rejected-action/act_rejected"
    ).mock(
        return_value=httpx.Response(200, json=REJECTED_OBSERVATION_RESPONSE)
    )

    result = await hy.diagnostics.record_observation_from_rejected_action(
        "act_rejected", observed_by="actor_oncall_alice"
    )

    assert isinstance(result, MicroModelObservation)
    assert result.observed_outcome["action_lifecycle"] == "rejected"
    assert result.observed_outcome["operator_rejected"] is True
    assert result.observed_outcome["operator_approved"] is False
    assert (
        result.observed_outcome["rejection_reason"]
        == "false alarm during maintenance"
    )

    body = json.loads(route.calls.last.request.content)
    assert body == {"observed_by": "actor_oncall_alice"}


@pytest.mark.asyncio
async def test_record_observation_from_rejected_action_unknown_raises_not_found(
    hy: Hydra, respx_mock: respx.MockRouter
) -> None:
    """Unknown action_id → 404 → `HydraNotFoundError`."""
    respx_mock.post(
        "https://hydra.test/diagnostics/micromodels/observations/from-rejected-action/act_ghost"
    ).mock(
        return_value=httpx.Response(
            404, json={"error": "unknown action: act_ghost"}
        )
    )

    from hydra import HydraNotFoundError

    with pytest.raises(HydraNotFoundError):
        await hy.diagnostics.record_observation_from_rejected_action(
            "act_ghost", observed_by="actor_ops"
        )


@pytest.mark.asyncio
async def test_record_observation_from_rejected_action_wrong_status_raises_validation(
    hy: Hydra, respx_mock: respx.MockRouter
) -> None:
    """Action exists but is Approved (not Rejected) → 400 →
    `HydraValidationError`."""
    respx_mock.post(
        "https://hydra.test/diagnostics/micromodels/observations/from-rejected-action/act_x"
    ).mock(
        return_value=httpx.Response(
            400,
            json={
                "error": (
                    "invalid action state: act_x is Approved, expected Rejected"
                )
            },
        )
    )

    with pytest.raises(HydraValidationError) as exc_info:
        await hy.diagnostics.record_observation_from_rejected_action(
            "act_x", observed_by="actor_ops"
        )
    assert "invalid action state" in str(exc_info.value)


@pytest.mark.asyncio
async def test_record_observation_from_rejected_action_cascade_rejection_raises_validation(
    hy: Hydra, respx_mock: respx.MockRouter
) -> None:
    """Cascade-rejected action → 400 → `HydraValidationError`. The
    load-bearing safety property: only HUMAN rejections produce a
    learning signal."""
    respx_mock.post(
        "https://hydra.test/diagnostics/micromodels/observations/from-rejected-action/act_x"
    ).mock(
        return_value=httpx.Response(
            400,
            json={
                "error": (
                    "action act_x was rejected by cascade "
                    "(actor_hydra_policy), not operator"
                )
            },
        )
    )

    with pytest.raises(HydraValidationError) as exc_info:
        await hy.diagnostics.record_observation_from_rejected_action(
            "act_x", observed_by="actor_ops"
        )
    assert "rejected by cascade" in str(exc_info.value)


def test_record_observation_from_rejected_action_sync_mirror(
    hy_sync: HydraSync, respx_mock: respx.MockRouter
) -> None:
    """`HydraSync.diagnostics.record_observation_from_rejected_action`
    returns the same typed envelope as the async client."""
    respx_mock.post(
        "https://hydra.test/diagnostics/micromodels/observations/from-rejected-action/act_rejected"
    ).mock(
        return_value=httpx.Response(200, json=REJECTED_OBSERVATION_RESPONSE)
    )

    result = hy_sync.diagnostics.record_observation_from_rejected_action(
        "act_rejected", observed_by="actor_oncall_alice"
    )

    assert isinstance(result, MicroModelObservation)
    assert result.observed_outcome["action_lifecycle"] == "rejected"
    assert result.observed_outcome["operator_rejected"] is True


def test_action_model_accepts_rejected_by_and_rejected_at_round_trip() -> None:
    """The Action Pydantic model gained `rejected_by` and
    `rejected_at` fields in Patch 13. They round-trip from wire
    JSON, including when populated AND when null (for actions that
    were never rejected). This is the SDK-side pin of the new
    audit-symmetric fields."""
    from hydra import Action

    body_rejected: dict[str, Any] = {
        "id": "act_x",
        "tenant_id": None,
        "kind": "Notify",
        "status": "Rejected",
        "targets": [],
        "related_claims": [],
        "supporting_evidence": [],
        "proposed_by": "actor_proposer",
        "approved_by": None,
        "rejected_by": "actor_oncall_alice",
        "policy_id": None,
        "payload": {},
        "created_at": "2026-05-29T00:00:00Z",
        "updated_at": "2026-05-29T00:00:01Z",
        "approved_at": None,
        "rejected_at": "2026-05-29T00:00:01Z",
        "executed_at": None,
        "caused_by": None,
    }
    a = Action.model_validate(body_rejected)
    assert a.rejected_by == "actor_oncall_alice"
    assert a.rejected_at == "2026-05-29T00:00:01Z"

    # Action that was never rejected — both fields default to None
    # (pre-Patch-13 wire envelopes never carried them).
    body_approved = dict(body_rejected)
    body_approved["status"] = "Approved"
    body_approved["approved_by"] = "actor_oncall_alice"
    body_approved["approved_at"] = "2026-05-29T00:00:00Z"
    body_approved["rejected_by"] = None
    body_approved["rejected_at"] = None
    a2 = Action.model_validate(body_approved)
    assert a2.rejected_by is None
    assert a2.rejected_at is None
    # And the legacy shape (no rejected_* fields at all) still
    # validates thanks to the default-None Pydantic fields. This
    # mirrors the Rust #[serde(default)] backward-compat.
    del body_approved["rejected_by"]
    del body_approved["rejected_at"]
    a3 = Action.model_validate(body_approved)
    assert a3.rejected_by is None
    assert a3.rejected_at is None
