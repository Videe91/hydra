"""Tests for `hy.diagnostics.agent_loop_storm(...)` (MicroModel
Patch 18 — third built-in model, Hydra's safety reflex).

Verifies:
  - Default `mode` is `"action"` when caller omits it
  - All three modes route to the same `/diagnostics/micromodels/
    agent-loop-storm/evaluate` endpoint with the right body
    (no per-instance selector like commit-rate)
  - Typed `AgentLoopStormAssessment` returned with the storm
    level vocabulary (no `warming_up`)
  - Sync mirror parity
"""

from __future__ import annotations

import json
from typing import Any

import httpx
import pytest
import respx

from hydra import (
    AgentLoopStormAssessment,
    Hydra,
    HydraSync,
)


# === Fixtures ===

NORMAL_RESPONSE: dict[str, Any] = {
    "level": "normal",
    "prediction": {
        "model_id": "mm_builtin_agent_loop_storm_v0",
        "run_id": "mmrun_storm_normal",
        "input": {
            "observed_at": "2026-05-30T00:00:00Z",
            "window_secs": 60,
            "agent_event_count": 2,
            "action_proposed_count": 0,
            "claim_proposed_count": 1,
            "top_actor": "actor_oncall_alice",
            "top_actor_event_count": 2,
            "warning_agent_events": 50,
            "critical_agent_events": 200,
        },
        "output": {
            "level": "normal",
            "window_secs": 60,
            "agent_event_count": 2,
            "action_proposed_count": 0,
            "claim_proposed_count": 1,
            "top_actor": "actor_oncall_alice",
            "top_actor_event_count": 2,
            "reason": "2 agent events / 0 actions / 1 claims in 60s — within thresholds",
        },
        "confidence": 0.85,
        "explanation": "2 agent events / 0 actions / 1 claims in 60s — within thresholds",
        "created_at": "2026-05-30T00:00:00Z",
    },
    "prediction_event_id": "evt_pred_storm_normal",
    "evidence_id": None,
    "evidence_event_id": None,
    "claim_id": None,
    "claim_event_id": None,
    "action_ids": [],
    "summary": "Agent activity within thresholds; no claim or action.",
    "lineage_url": "/lineage/evt_pred_storm_normal",
}


CRITICAL_RESPONSE: dict[str, Any] = {
    "level": "critical",
    "prediction": {
        "model_id": "mm_builtin_agent_loop_storm_v0",
        "run_id": "mmrun_storm_crit",
        "input": {
            "observed_at": "2026-05-30T00:01:00Z",
            "window_secs": 60,
            "agent_event_count": 245,
            "action_proposed_count": 68,
            "claim_proposed_count": 92,
            "top_actor": "actor_data_quality_agent",
            "top_actor_event_count": 180,
            "warning_agent_events": 50,
            "critical_agent_events": 200,
        },
        "output": {
            "level": "critical",
            "window_secs": 60,
            "agent_event_count": 245,
            "action_proposed_count": 68,
            "claim_proposed_count": 92,
            "top_actor": "actor_data_quality_agent",
            "top_actor_event_count": 180,
            "reason": (
                "agent loop storm at critical level: 245 agent events / 68 "
                "actions / 92 claims in 60s; top actor "
                "actor_data_quality_agent contributed 180 events"
            ),
        },
        "confidence": 0.95,
        "explanation": "agent loop storm at critical level...",
        "created_at": "2026-05-30T00:01:00Z",
    },
    "prediction_event_id": "evt_pred_storm_crit",
    "evidence_id": "evi_storm_crit",
    "evidence_event_id": "evt_evi_storm_crit",
    "claim_id": "claim_storm_crit",
    "claim_event_id": "evt_claim_storm_crit",
    "action_ids": ["act_storm_crit"],
    "summary": "Critical: agent loop storm detected; Notify action proposed.",
    "lineage_url": "/lineage/evt_pred_storm_crit",
}


# === Async tests ===


@pytest.mark.asyncio
async def test_agent_loop_storm_default_mode_is_action(
    hy: Hydra, respx_mock: respx.MockRouter
) -> None:
    route = respx_mock.post(
        "https://hydra.test/diagnostics/micromodels/agent-loop-storm/evaluate"
    ).mock(return_value=httpx.Response(200, json=NORMAL_RESPONSE))

    assessment = await hy.diagnostics.agent_loop_storm(
        requested_by="actor_ops",
    )

    assert isinstance(assessment, AgentLoopStormAssessment)
    assert assessment.level == "normal"
    assert assessment.claim_id is None
    assert assessment.action_ids == []
    assert "within thresholds" in assessment.summary

    body = json.loads(route.calls.last.request.content)
    assert body == {"mode": "action", "requested_by": "actor_ops"}


@pytest.mark.asyncio
async def test_agent_loop_storm_critical_response_carries_full_chain(
    hy: Hydra, respx_mock: respx.MockRouter
) -> None:
    respx_mock.post(
        "https://hydra.test/diagnostics/micromodels/agent-loop-storm/evaluate"
    ).mock(return_value=httpx.Response(200, json=CRITICAL_RESPONSE))

    assessment = await hy.diagnostics.agent_loop_storm(
        requested_by="actor_ops",
    )

    assert assessment.level == "critical"
    assert assessment.evidence_id == "evi_storm_crit"
    assert assessment.claim_id == "claim_storm_crit"
    assert assessment.action_ids == ["act_storm_crit"]
    assert "Notify action proposed" in assessment.summary
    # Output payload carries the Patch 18 fields.
    assert assessment.prediction.output["agent_event_count"] == 245
    assert assessment.prediction.output["top_actor"] == "actor_data_quality_agent"


@pytest.mark.asyncio
async def test_agent_loop_storm_prediction_only_mode_body(
    hy: Hydra, respx_mock: respx.MockRouter
) -> None:
    route = respx_mock.post(
        "https://hydra.test/diagnostics/micromodels/agent-loop-storm/evaluate"
    ).mock(return_value=httpx.Response(200, json=NORMAL_RESPONSE))

    await hy.diagnostics.agent_loop_storm(
        requested_by="actor_ops",
        mode="prediction_only",
    )

    body = json.loads(route.calls.last.request.content)
    assert body["mode"] == "prediction_only"
    assert body["requested_by"] == "actor_ops"


@pytest.mark.asyncio
async def test_agent_loop_storm_tenant_override(
    hy: Hydra, respx_mock: respx.MockRouter
) -> None:
    route = respx_mock.post(
        "https://hydra.test/diagnostics/micromodels/agent-loop-storm/evaluate"
    ).mock(return_value=httpx.Response(200, json=NORMAL_RESPONSE))

    await hy.diagnostics.agent_loop_storm(
        requested_by="actor_ops",
        tenant="tenant_other",
    )

    assert route.calls.last.request.headers["X-Hydra-Tenant"] == "tenant_other"


# === Sync mirror ===


def test_agent_loop_storm_sync_mirror_returns_same_envelope(
    hy_sync: HydraSync, respx_mock: respx.MockRouter
) -> None:
    """`HydraSync.diagnostics.agent_loop_storm` returns the same
    typed envelope as the async client."""
    respx_mock.post(
        "https://hydra.test/diagnostics/micromodels/agent-loop-storm/evaluate"
    ).mock(return_value=httpx.Response(200, json=CRITICAL_RESPONSE))

    assessment = hy_sync.diagnostics.agent_loop_storm(
        requested_by="actor_ops",
    )

    assert isinstance(assessment, AgentLoopStormAssessment)
    assert assessment.level == "critical"
    assert assessment.action_ids == ["act_storm_crit"]


# === Patch 28 — auto-created causal_cell_id ===


@pytest.mark.asyncio
async def test_agent_loop_storm_assessment_has_causal_cell_id(
    hy: Hydra, respx_mock: respx.MockRouter
) -> None:
    """Patch 28 — Critical storm → engine auto-creates a Reflex
    cell and the SDK surfaces its id."""
    body = {**CRITICAL_RESPONSE, "causal_cell_id": "cell_reflex_als"}
    respx_mock.post(
        "https://hydra.test/diagnostics/micromodels/agent-loop-storm/evaluate"
    ).mock(return_value=httpx.Response(200, json=body))

    assessment = await hy.diagnostics.agent_loop_storm(
        requested_by="actor_ops",
    )
    assert assessment.causal_cell_id == "cell_reflex_als"
