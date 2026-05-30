"""Tests for `hy.diagnostics.action_failure_rate(...)` (MicroModel
Patch 19 — fourth built-in model, Hydra's self-health reflex).

Verifies:
  - Default `mode` is `"action"` when caller omits it
  - All three modes route to the same `/diagnostics/micromodels/
    action-failure-rate/evaluate` endpoint
  - Typed `ActionFailureRateAssessment` returned with the
    failure-rate level vocabulary (no `warming_up`)
  - Sync mirror parity
"""

from __future__ import annotations

import json
from typing import Any

import httpx
import pytest
import respx

from hydra import (
    ActionFailureRateAssessment,
    Hydra,
    HydraSync,
)


# === Fixtures ===

NORMAL_RESPONSE: dict[str, Any] = {
    "level": "normal",
    "prediction": {
        "model_id": "mm_builtin_action_failure_rate_v0",
        "run_id": "mmrun_afr_normal",
        "input": {
            "observed_at": "2026-05-30T00:00:00Z",
            "window_secs": 300,
            "actions_seen": 0,
            "failed_actions": 0,
            "top_failed_kind": None,
            "min_actions_for_ratio": 5,
            "warning_failure_count": 3,
            "critical_failure_count": 10,
            "warning_failure_ratio": 0.25,
            "critical_failure_ratio": 0.50,
        },
        "output": {
            "level": "normal",
            "window_secs": 300,
            "actions_seen": 0,
            "failed_actions": 0,
            "failure_ratio": 0.0,
            "top_failed_kind": None,
            "reason": "no actions reached terminal state in 300s — delivery healthy by absence",
        },
        "confidence": 0.85,
        "explanation": "no actions reached terminal state in 300s — delivery healthy by absence",
        "created_at": "2026-05-30T00:00:00Z",
    },
    "prediction_event_id": "evt_pred_afr_normal",
    "evidence_id": None,
    "evidence_event_id": None,
    "claim_id": None,
    "claim_event_id": None,
    "action_ids": [],
    "summary": "Action delivery within thresholds; no claim or action.",
    "lineage_url": "/lineage/evt_pred_afr_normal",
}


CRITICAL_RESPONSE: dict[str, Any] = {
    "level": "critical",
    "prediction": {
        "model_id": "mm_builtin_action_failure_rate_v0",
        "run_id": "mmrun_afr_crit",
        "input": {
            "observed_at": "2026-05-30T00:05:00Z",
            "window_secs": 300,
            "actions_seen": 24,
            "failed_actions": 15,
            "top_failed_kind": "Notify",
            "min_actions_for_ratio": 5,
            "warning_failure_count": 3,
            "critical_failure_count": 10,
            "warning_failure_ratio": 0.25,
            "critical_failure_ratio": 0.50,
        },
        "output": {
            "level": "critical",
            "window_secs": 300,
            "actions_seen": 24,
            "failed_actions": 15,
            "failure_ratio": 0.625,
            "top_failed_kind": "Notify",
            "reason": (
                "action delivery critical: 15 of 24 actions failed in 300s; "
                "failure ratio 62.5%; top failed kind Notify"
            ),
        },
        "confidence": 0.95,
        "explanation": "action delivery critical...",
        "created_at": "2026-05-30T00:05:00Z",
    },
    "prediction_event_id": "evt_pred_afr_crit",
    "evidence_id": "evi_afr_crit",
    "evidence_event_id": "evt_evi_afr_crit",
    "claim_id": "claim_afr_crit",
    "claim_event_id": "evt_claim_afr_crit",
    "action_ids": ["act_afr_crit"],
    "summary": "Critical: action failure rate anomalous; Notify action proposed.",
    "lineage_url": "/lineage/evt_pred_afr_crit",
}


# === Async tests ===


@pytest.mark.asyncio
async def test_action_failure_rate_default_mode_is_action(
    hy: Hydra, respx_mock: respx.MockRouter
) -> None:
    route = respx_mock.post(
        "https://hydra.test/diagnostics/micromodels/action-failure-rate/evaluate"
    ).mock(return_value=httpx.Response(200, json=NORMAL_RESPONSE))

    assessment = await hy.diagnostics.action_failure_rate(
        requested_by="actor_ops",
    )

    assert isinstance(assessment, ActionFailureRateAssessment)
    assert assessment.level == "normal"
    assert assessment.claim_id is None
    assert assessment.action_ids == []
    assert "within thresholds" in assessment.summary

    body = json.loads(route.calls.last.request.content)
    assert body == {"mode": "action", "requested_by": "actor_ops"}


@pytest.mark.asyncio
async def test_action_failure_rate_critical_response_carries_full_chain(
    hy: Hydra, respx_mock: respx.MockRouter
) -> None:
    respx_mock.post(
        "https://hydra.test/diagnostics/micromodels/action-failure-rate/evaluate"
    ).mock(return_value=httpx.Response(200, json=CRITICAL_RESPONSE))

    assessment = await hy.diagnostics.action_failure_rate(
        requested_by="actor_ops",
    )

    assert assessment.level == "critical"
    assert assessment.evidence_id == "evi_afr_crit"
    assert assessment.claim_id == "claim_afr_crit"
    assert assessment.action_ids == ["act_afr_crit"]
    assert "Notify action proposed" in assessment.summary
    # Output payload carries the Patch 19 fields.
    assert assessment.prediction.output["failed_actions"] == 15
    assert assessment.prediction.output["actions_seen"] == 24
    assert assessment.prediction.output["top_failed_kind"] == "Notify"
    assert abs(assessment.prediction.output["failure_ratio"] - 0.625) < 1e-9


@pytest.mark.asyncio
async def test_action_failure_rate_prediction_only_mode_body(
    hy: Hydra, respx_mock: respx.MockRouter
) -> None:
    route = respx_mock.post(
        "https://hydra.test/diagnostics/micromodels/action-failure-rate/evaluate"
    ).mock(return_value=httpx.Response(200, json=NORMAL_RESPONSE))

    await hy.diagnostics.action_failure_rate(
        requested_by="actor_ops",
        mode="prediction_only",
    )

    body = json.loads(route.calls.last.request.content)
    assert body["mode"] == "prediction_only"
    assert body["requested_by"] == "actor_ops"


@pytest.mark.asyncio
async def test_action_failure_rate_tenant_override(
    hy: Hydra, respx_mock: respx.MockRouter
) -> None:
    route = respx_mock.post(
        "https://hydra.test/diagnostics/micromodels/action-failure-rate/evaluate"
    ).mock(return_value=httpx.Response(200, json=NORMAL_RESPONSE))

    await hy.diagnostics.action_failure_rate(
        requested_by="actor_ops",
        tenant="tenant_other",
    )

    assert route.calls.last.request.headers["X-Hydra-Tenant"] == "tenant_other"


# === Sync mirror ===


def test_action_failure_rate_sync_mirror_returns_same_envelope(
    hy_sync: HydraSync, respx_mock: respx.MockRouter
) -> None:
    """`HydraSync.diagnostics.action_failure_rate` returns the same
    typed envelope as the async client."""
    respx_mock.post(
        "https://hydra.test/diagnostics/micromodels/action-failure-rate/evaluate"
    ).mock(return_value=httpx.Response(200, json=CRITICAL_RESPONSE))

    assessment = hy_sync.diagnostics.action_failure_rate(
        requested_by="actor_ops",
    )

    assert isinstance(assessment, ActionFailureRateAssessment)
    assert assessment.level == "critical"
    assert assessment.action_ids == ["act_afr_crit"]
    assert assessment.prediction.output["top_failed_kind"] == "Notify"


# === Patch 28 — auto-created causal_cell_id ===


@pytest.mark.asyncio
async def test_action_failure_rate_assessment_has_causal_cell_id(
    hy: Hydra, respx_mock: respx.MockRouter
) -> None:
    """Patch 28 — Critical action-failure-rate → engine auto-
    creates a Reflex cell and the SDK surfaces its id."""
    body = {**CRITICAL_RESPONSE, "causal_cell_id": "cell_reflex_afr"}
    respx_mock.post(
        "https://hydra.test/diagnostics/micromodels/action-failure-rate/evaluate"
    ).mock(return_value=httpx.Response(200, json=body))

    assessment = await hy.diagnostics.action_failure_rate(
        requested_by="actor_ops",
    )
    assert assessment.causal_cell_id == "cell_reflex_afr"
