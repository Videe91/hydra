"""Tests for `Hydra.approve_action(...)` / `reject_action(...)`
(MicroModel Patch 6 — operator approval workflow).

Verifies:
  - Approve flips Proposed → Approved and returns the typed envelope
  - Reject flips Proposed → Rejected
  - Approve without `reason` succeeds; the SDK omits it from the body
  - Reject's `reason` parameter is required (mypy/keyword enforcement)
  - Sync mirrors (`HydraSync.approve_action` / `reject_action`)
  - Per-call tenant override propagates as `X-Hydra-Tenant`
  - Unknown action_id surfaces as `HydraNotFoundError` (404)
  - Idempotent re-approve surfaces `previous_status == "approved"`
"""

from __future__ import annotations

import json
from typing import Any

import httpx
import pytest
import respx

from hydra import (
    ActionTransitionResponse,
    Hydra,
    HydraNotFoundError,
    HydraSync,
)


# === Fixtures ===

APPROVED_RESPONSE: dict[str, Any] = {
    "action_id": "act_abc",
    "status": "approved",
    "previous_status": "proposed",
    "approved_by": "actor_oncall_alice",
    "rejected_by": None,
    "reason": "confirmed by alice",
    "approved_at": "2026-05-29T00:00:00Z",
    "updated_at": "2026-05-29T00:00:00Z",
}

APPROVED_NO_REASON_RESPONSE: dict[str, Any] = {
    "action_id": "act_abc",
    "status": "approved",
    "previous_status": "proposed",
    "approved_by": "actor_ops",
    "rejected_by": None,
    "reason": None,
    "approved_at": "2026-05-29T00:00:00Z",
    "updated_at": "2026-05-29T00:00:00Z",
}

REJECTED_RESPONSE: dict[str, Any] = {
    "action_id": "act_abc",
    "status": "rejected",
    "previous_status": "proposed",
    "approved_by": None,
    "rejected_by": "actor_oncall_alice",
    "reason": "false alarm — planned maintenance",
    "approved_at": None,
    "updated_at": "2026-05-29T00:00:00Z",
}

IDEMPOTENT_REAPPROVE_RESPONSE: dict[str, Any] = {
    "action_id": "act_abc",
    "status": "approved",
    "previous_status": "approved",
    "approved_by": "actor_second",
    "rejected_by": None,
    "reason": None,
    "approved_at": "2026-05-29T00:00:00Z",
    "updated_at": "2026-05-29T00:00:00Z",
}


# === Async tests ===


@pytest.mark.asyncio
async def test_approve_action_flips_proposed_to_approved(
    hy: Hydra, respx_mock: respx.MockRouter
) -> None:
    """Approve hits `POST /actions/{id}/approve`, returns the typed
    transition envelope with both status fields populated."""
    route = respx_mock.post(
        "https://hydra.test/actions/act_abc/approve"
    ).mock(return_value=httpx.Response(200, json=APPROVED_RESPONSE))

    result = await hy.approve_action(
        "act_abc",
        actor="actor_oncall_alice",
        reason="confirmed by alice",
    )

    assert isinstance(result, ActionTransitionResponse)
    assert result.action_id == "act_abc"
    assert result.status == "approved"
    assert result.previous_status == "proposed"
    assert result.approved_by == "actor_oncall_alice"
    assert result.rejected_by is None
    assert result.reason == "confirmed by alice"
    assert result.approved_at == "2026-05-29T00:00:00Z"

    body = json.loads(route.calls.last.request.content)
    assert body == {"actor": "actor_oncall_alice", "reason": "confirmed by alice"}


@pytest.mark.asyncio
async def test_reject_action_flips_proposed_to_rejected(
    hy: Hydra, respx_mock: respx.MockRouter
) -> None:
    """Reject hits `POST /actions/{id}/reject`. `reason` is required
    and round-trips back on `rejected_by` + `reason`."""
    route = respx_mock.post(
        "https://hydra.test/actions/act_abc/reject"
    ).mock(return_value=httpx.Response(200, json=REJECTED_RESPONSE))

    result = await hy.reject_action(
        "act_abc",
        actor="actor_oncall_alice",
        reason="false alarm — planned maintenance",
    )

    assert result.status == "rejected"
    assert result.previous_status == "proposed"
    assert result.rejected_by == "actor_oncall_alice"
    assert result.approved_by is None
    assert result.reason == "false alarm — planned maintenance"
    assert result.approved_at is None

    body = json.loads(route.calls.last.request.content)
    assert body == {
        "actor": "actor_oncall_alice",
        "reason": "false alarm — planned maintenance",
    }


@pytest.mark.asyncio
async def test_approve_action_omits_reason_when_none(
    hy: Hydra, respx_mock: respx.MockRouter
) -> None:
    """When the caller omits `reason`, the SDK must NOT send a `null`
    on the wire — the field is `#[serde(default)]` on the engine and
    the existing audit-log payload distinguishes "no reason given"
    from "reason was explicitly null"."""
    route = respx_mock.post(
        "https://hydra.test/actions/act_abc/approve"
    ).mock(return_value=httpx.Response(200, json=APPROVED_NO_REASON_RESPONSE))

    result = await hy.approve_action("act_abc", actor="actor_ops")

    assert result.status == "approved"
    assert result.reason is None

    body = json.loads(route.calls.last.request.content)
    assert "reason" not in body
    assert body == {"actor": "actor_ops"}


@pytest.mark.asyncio
async def test_reject_action_tenant_override(
    hy: Hydra, respx_mock: respx.MockRouter
) -> None:
    """Per-call tenant override applies (Rule #7)."""
    route = respx_mock.post(
        "https://hydra.test/actions/act_abc/reject"
    ).mock(return_value=httpx.Response(200, json=REJECTED_RESPONSE))

    await hy.reject_action(
        "act_abc",
        actor="actor_ops",
        reason="not now",
        tenant="tenant_other",
    )

    assert route.calls.last.request.headers["X-Hydra-Tenant"] == "tenant_other"


@pytest.mark.asyncio
async def test_approve_action_unknown_raises_not_found(
    hy: Hydra, respx_mock: respx.MockRouter
) -> None:
    """The HTTP layer maps 404 → `HydraNotFoundError`."""
    respx_mock.post(
        "https://hydra.test/actions/act_does_not_exist/approve"
    ).mock(
        return_value=httpx.Response(
            404, json={"error": "unknown action: act_does_not_exist"}
        )
    )

    with pytest.raises(HydraNotFoundError):
        await hy.approve_action("act_does_not_exist", actor="actor_ops")


@pytest.mark.asyncio
async def test_approve_action_idempotent_surfaces_previous_status(
    hy: Hydra, respx_mock: respx.MockRouter
) -> None:
    """v0 does NOT enforce terminal states: re-approving an Approved
    action returns 200 with `previous_status == "approved"`. The
    response surface lets callers detect idempotent flips without
    a separate state lookup."""
    respx_mock.post(
        "https://hydra.test/actions/act_abc/approve"
    ).mock(return_value=httpx.Response(200, json=IDEMPOTENT_REAPPROVE_RESPONSE))

    result = await hy.approve_action("act_abc", actor="actor_second")

    assert result.status == "approved"
    assert result.previous_status == "approved"
    assert result.approved_by == "actor_second"


# === Sync mirrors ===


def test_approve_action_sync_mirror(
    hy_sync: HydraSync, respx_mock: respx.MockRouter
) -> None:
    """`HydraSync.approve_action` round-trips the same envelope as the
    async client. Sync parity is non-negotiable for Patch 6 — operator
    runbooks frequently call this from non-async tooling."""
    respx_mock.post(
        "https://hydra.test/actions/act_abc/approve"
    ).mock(return_value=httpx.Response(200, json=APPROVED_RESPONSE))

    result = hy_sync.approve_action(
        "act_abc",
        actor="actor_oncall_alice",
        reason="confirmed by alice",
    )

    assert isinstance(result, ActionTransitionResponse)
    assert result.status == "approved"
    assert result.previous_status == "proposed"
    assert result.reason == "confirmed by alice"


def test_reject_action_sync_mirror(
    hy_sync: HydraSync, respx_mock: respx.MockRouter
) -> None:
    """`HydraSync.reject_action` — same wire contract, sync flavor."""
    route = respx_mock.post(
        "https://hydra.test/actions/act_abc/reject"
    ).mock(return_value=httpx.Response(200, json=REJECTED_RESPONSE))

    result = hy_sync.reject_action(
        "act_abc",
        actor="actor_oncall_alice",
        reason="false alarm — planned maintenance",
    )

    assert result.status == "rejected"
    assert result.rejected_by == "actor_oncall_alice"

    body = json.loads(route.calls.last.request.content)
    assert body == {
        "actor": "actor_oncall_alice",
        "reason": "false alarm — planned maintenance",
    }
