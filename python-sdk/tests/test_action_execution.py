"""Tests for `Hydra.execute_action(...)` (MicroModel Patch 7 —
Notify action execution stub).

Verifies:
  - Execute hits POST /actions/{id}/execute with the right body
  - Returns typed ActionExecutionResponse with previous_status="approved"
    and final_status="executed"
  - Sync mirror (HydraSync.execute_action) round-trips identically
  - Per-call tenant override propagates as X-Hydra-Tenant
  - Unknown action_id → HydraNotFoundError (404)
  - Non-Approved status → HydraValidationError (400)
  - Non-Notify kind → HydraValidationError (400)
"""

from __future__ import annotations

import json
from typing import Any

import httpx
import pytest
import respx

from hydra import (
    ActionExecutionResponse,
    Hydra,
    HydraNotFoundError,
    HydraSync,
    HydraValidationError,
)


# === Fixtures ===

EXECUTED_RESPONSE: dict[str, Any] = {
    "action_id": "act_abc",
    "previous_status": "approved",
    "final_status": "executed",
    "outcome_id": "out_xyz",
    "executed_by": "actor_ops",
    "executed_at": "2026-05-29T00:00:00Z",
}


# === Async tests ===


@pytest.mark.asyncio
async def test_execute_action_walks_approved_to_executed(
    hy: Hydra, respx_mock: respx.MockRouter
) -> None:
    """Happy path: an Approved Notify action returns a typed
    envelope with both status fields populated and the recorded
    outcome id reachable."""
    route = respx_mock.post(
        "https://hydra.test/actions/act_abc/execute"
    ).mock(return_value=httpx.Response(200, json=EXECUTED_RESPONSE))

    result = await hy.execute_action("act_abc", actor="actor_ops")

    assert isinstance(result, ActionExecutionResponse)
    assert result.action_id == "act_abc"
    assert result.previous_status == "approved"
    assert result.final_status == "executed"
    assert result.outcome_id == "out_xyz"
    assert result.executed_by == "actor_ops"
    assert result.executed_at == "2026-05-29T00:00:00Z"

    body = json.loads(route.calls.last.request.content)
    assert body == {"actor": "actor_ops"}


@pytest.mark.asyncio
async def test_execute_action_tenant_override(
    hy: Hydra, respx_mock: respx.MockRouter
) -> None:
    """Per-call tenant override applies (Rule #7)."""
    route = respx_mock.post(
        "https://hydra.test/actions/act_abc/execute"
    ).mock(return_value=httpx.Response(200, json=EXECUTED_RESPONSE))

    await hy.execute_action(
        "act_abc", actor="actor_ops", tenant="tenant_other"
    )

    assert route.calls.last.request.headers["X-Hydra-Tenant"] == "tenant_other"


@pytest.mark.asyncio
async def test_execute_action_unknown_raises_not_found(
    hy: Hydra, respx_mock: respx.MockRouter
) -> None:
    """Unknown action_id → 404 → `HydraNotFoundError`."""
    respx_mock.post(
        "https://hydra.test/actions/act_does_not_exist/execute"
    ).mock(
        return_value=httpx.Response(
            404, json={"error": "unknown action: act_does_not_exist"}
        )
    )

    with pytest.raises(HydraNotFoundError):
        await hy.execute_action("act_does_not_exist", actor="actor_ops")


@pytest.mark.asyncio
async def test_execute_action_non_approved_raises_validation_error(
    hy: Hydra, respx_mock: respx.MockRouter
) -> None:
    """Engine returns 400 with 'invalid action state' when the
    action is not Approved. The HTTP layer surfaces 400 →
    `HydraValidationError`."""
    respx_mock.post("https://hydra.test/actions/act_abc/execute").mock(
        return_value=httpx.Response(
            400,
            json={
                "error": "invalid action state: act_abc is Proposed, expected Approved"
            },
        )
    )

    with pytest.raises(HydraValidationError) as exc_info:
        await hy.execute_action("act_abc", actor="actor_ops")
    assert "invalid action state" in str(exc_info.value)


@pytest.mark.asyncio
async def test_execute_action_non_notify_kind_raises_validation_error(
    hy: Hydra, respx_mock: respx.MockRouter
) -> None:
    """Engine returns 400 with 'invalid action kind' when the
    action is not Notify."""
    respx_mock.post("https://hydra.test/actions/act_abc/execute").mock(
        return_value=httpx.Response(
            400,
            json={
                "error": (
                    "invalid action kind: act_abc is not Notify "
                    "(Patch 7 only executes Notify actions; got Backfill)"
                )
            },
        )
    )

    with pytest.raises(HydraValidationError) as exc_info:
        await hy.execute_action("act_abc", actor="actor_ops")
    assert "invalid action kind" in str(exc_info.value)


# === Sync mirror ===


def test_execute_action_sync_mirror(
    hy_sync: HydraSync, respx_mock: respx.MockRouter
) -> None:
    """`HydraSync.execute_action` returns the same typed envelope
    as the async client. Sync parity is non-negotiable for
    operator-facing methods — runbooks frequently call execute
    from non-async tooling."""
    respx_mock.post(
        "https://hydra.test/actions/act_abc/execute"
    ).mock(return_value=httpx.Response(200, json=EXECUTED_RESPONSE))

    result = hy_sync.execute_action("act_abc", actor="actor_ops")

    assert isinstance(result, ActionExecutionResponse)
    assert result.final_status == "executed"
    assert result.outcome_id == "out_xyz"
