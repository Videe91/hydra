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
