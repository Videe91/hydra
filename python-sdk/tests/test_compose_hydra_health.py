"""Tests for `Hydra.compose_hydra_health_cell(...)` (Patch 27 —
HydraHealthCell HTTP + Python SDK).

Verifies:
  - Hits `POST /causal-cells/hydra-health/compose` with
    `{actor: ActorId}` body and `X-Hydra-Tenant` header
  - Returns a typed `CausalCell` parsed from the
    `{cell: CausalCell}` envelope
  - Per-call tenant override propagates as `X-Hydra-Tenant`
  - 404 (zero self-health reflex cells found for the tenant)
    surfaces as `HydraNotFoundError` — preserving the engine's
    precondition message in the exception
  - Sync mirror returns the same typed envelope

The route's strict-tenant-isolation and partial-composition
contract is covered at the Rust HTTP layer (see
`crates/hydra-net/src/http/causal_cells.rs::tests`); these
tests focus on the SDK wire round-trip.
"""

from __future__ import annotations

from typing import Any

import httpx
import pytest
import respx

from hydra import (
    CausalCell,
    Hydra,
    HydraNotFoundError,
    HydraSync,
)


# === Fixtures ===

HEALTH_CELL_BODY: dict[str, Any] = {
    "id": "cell_hydra_health_compose",
    "tenant_id": "tenant_test",
    "kind": "Health",
    "subject": "hydra.health",
    "source_events": [],
    "evidence_ids": [],
    "claim_ids": ["claim_cr", "claim_rl", "claim_als", "claim_afr"],
    "action_ids": [],
    "outcome_ids": [],
    "observation_run_ids": [],
    "child_cell_ids": [
        "cell_commit_rate",
        "cell_replication_lag",
        "cell_agent_loop_storm",
        "cell_action_failure_rate",
    ],
    "trust_score": 0.65,
    "summary": (
        "hydra.health composed from 4 of 4 self-health reflexes. "
        "Present: commit-rate, replication-lag, agent-loop-storm, "
        "action-failure-rate."
    ),
    "created_by": "actor_ops",
    "created_at": "2026-05-30T12:00:00Z",
    "caused_by": None,
}


# === Async tests ===


@pytest.mark.asyncio
async def test_compose_hydra_health_cell_returns_typed_cell(
    hy: Hydra, respx_mock: respx.MockRouter
) -> None:
    route = respx_mock.post(
        "https://hydra.test/causal-cells/hydra-health/compose"
    ).mock(
        return_value=httpx.Response(200, json={"cell": HEALTH_CELL_BODY})
    )

    cell = await hy.compose_hydra_health_cell(actor="actor_ops")

    assert isinstance(cell, CausalCell)
    assert cell.kind == "Health"
    assert cell.subject == "hydra.health"
    assert len(cell.child_cell_ids) == 4
    assert cell.trust_score == 0.65
    # Body shape: {"actor": "actor_ops"}.
    sent_body = route.calls.last.request.read()
    assert b'"actor"' in sent_body
    assert b'"actor_ops"' in sent_body
    # Tenant header propagated from the fixture default.
    assert "X-Hydra-Tenant" in route.calls.last.request.headers


@pytest.mark.asyncio
async def test_compose_hydra_health_cell_tenant_override_propagates(
    hy: Hydra, respx_mock: respx.MockRouter
) -> None:
    """Per-call `tenant=` overrides the client default and lands
    as `X-Hydra-Tenant`."""
    route = respx_mock.post(
        "https://hydra.test/causal-cells/hydra-health/compose"
    ).mock(
        return_value=httpx.Response(200, json={"cell": HEALTH_CELL_BODY})
    )

    await hy.compose_hydra_health_cell(
        actor="actor_ops",
        tenant="tenant_other",
    )

    assert (
        route.calls.last.request.headers["X-Hydra-Tenant"]
        == "tenant_other"
    )


@pytest.mark.asyncio
async def test_compose_hydra_health_cell_404_raises_not_found(
    hy: Hydra, respx_mock: respx.MockRouter
) -> None:
    """Zero self-health reflex cells for the tenant → engine
    `QueryError` → HTTP 404 → SDK `HydraNotFoundError`. The
    precondition message must survive the error round-trip so
    operators see WHICH tenant + expected subjects in the
    exception message, not a generic "not found"."""
    respx_mock.post(
        "https://hydra.test/causal-cells/hydra-health/compose"
    ).mock(
        return_value=httpx.Response(
            404,
            json={
                "error": (
                    "no self-health reflex cells found for tenant "
                    "tenant_test; expected one or more of ["
                    "\"hydra/under_abnormal_load\", "
                    "\"hydra.replication/replica_lagging\", "
                    "\"hydra.agents/agent_loop_storm\", "
                    "\"hydra.actions/action_failure_rate_high\"]"
                ),
            },
        )
    )

    with pytest.raises(HydraNotFoundError) as excinfo:
        await hy.compose_hydra_health_cell(actor="actor_ops")
    # Precondition explainer survives end-to-end.
    assert "no self-health reflex cells found" in str(excinfo.value)


# === Sync mirror ===


def test_compose_hydra_health_cell_sync_mirror(
    hy_sync: HydraSync, respx_mock: respx.MockRouter
) -> None:
    """`HydraSync.compose_hydra_health_cell` returns the same
    typed envelope as the async client. Sync parity is non-
    negotiable for operator-facing methods — Jupyter notebooks
    and non-async runbooks both drive this from sync."""
    respx_mock.post(
        "https://hydra.test/causal-cells/hydra-health/compose"
    ).mock(
        return_value=httpx.Response(200, json={"cell": HEALTH_CELL_BODY})
    )

    cell = hy_sync.compose_hydra_health_cell(actor="actor_ops")

    assert isinstance(cell, CausalCell)
    assert cell.kind == "Health"
    assert cell.subject == "hydra.health"
    assert len(cell.child_cell_ids) == 4
