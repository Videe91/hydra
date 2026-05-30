"""Tests for `hy.diagnostics.replication_lag_anomaly(...)` (MicroModel
Patch 16 — second built-in model on the same reflex stack).

Verifies:
  - Default `mode` is `"action"` when caller omits it
  - All three modes route to the same `/diagnostics/micromodels/
    replication-lag/evaluate` endpoint with the right body
    (including `peer_id`)
  - Typed `ReplicationLagAnomalyAssessment` returned
  - `peer_id` echoed back from the server
  - Unknown peer → `HydraNotFoundError` (404 mapping)
  - Sync mirror parity (`HydraSync.diagnostics.replication_lag_anomaly`)
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
    ReplicationLagAnomalyAssessment,
)


# === Fixtures ===

NORMAL_RESPONSE: dict[str, Any] = {
    "level": "normal",
    "prediction": {
        "model_id": "mm_builtin_replication_lag_v0",
        "run_id": "mmrun_replag_001",
        "input": {
            "observed_at": "2026-05-29T00:00:00Z",
            "peer_id": "replica_a",
            "lag_commits": 2,
            "last_observed_at": "2026-05-28T23:59:50Z",
            "warning_lag_commits": 10,
            "critical_lag_commits": 100,
            "stale_heartbeat_after_secs": 60,
        },
        "output": {
            "level": "normal",
            "lag_commits": 2,
            "stale_heartbeat": False,
            "reason": "replication lag 2 commits within warning threshold 10",
        },
        "confidence": 0.85,
        "explanation": "replication lag 2 commits within warning threshold 10",
        "created_at": "2026-05-29T00:00:00Z",
    },
    "prediction_event_id": "evt_pred_replag_normal",
    "evidence_id": None,
    "evidence_event_id": None,
    "claim_id": None,
    "claim_event_id": None,
    "action_ids": [],
    "peer_id": "replica_a",
    "summary": "Replication lag within thresholds; no claim or action.",
    "lineage_url": "/lineage/evt_pred_replag_normal",
}


CRITICAL_RESPONSE: dict[str, Any] = {
    "level": "critical",
    "prediction": {
        "model_id": "mm_builtin_replication_lag_v0",
        "run_id": "mmrun_replag_002",
        "input": {
            "observed_at": "2026-05-29T00:01:00Z",
            "peer_id": "replica_b",
            "lag_commits": 500,
            "last_observed_at": "2026-05-29T00:00:50Z",
            "warning_lag_commits": 10,
            "critical_lag_commits": 100,
            "stale_heartbeat_after_secs": 60,
        },
        "output": {
            "level": "critical",
            "lag_commits": 500,
            "stale_heartbeat": False,
            "reason": "replication lag 500 commits exceeds critical threshold 100",
        },
        "confidence": 0.95,
        "explanation": "replication lag 500 commits exceeds critical threshold 100",
        "created_at": "2026-05-29T00:01:00Z",
    },
    "prediction_event_id": "evt_pred_replag_crit",
    "evidence_id": "evi_replag_crit",
    "evidence_event_id": "evt_evi_replag_crit",
    "claim_id": "claim_replag_crit",
    "claim_event_id": "evt_claim_replag_crit",
    "action_ids": ["act_replag_crit"],
    "peer_id": "replica_b",
    "summary": "Critical: replication lag anomalous; Notify action proposed.",
    "lineage_url": "/lineage/evt_pred_replag_crit",
}


# === Async tests ===


@pytest.mark.asyncio
async def test_replication_lag_default_mode_is_action_and_body_carries_peer_id(
    hy: Hydra, respx_mock: respx.MockRouter
) -> None:
    route = respx_mock.post(
        "https://hydra.test/diagnostics/micromodels/replication-lag/evaluate"
    ).mock(return_value=httpx.Response(200, json=NORMAL_RESPONSE))

    assessment = await hy.diagnostics.replication_lag_anomaly(
        peer_id="replica_a",
        requested_by="actor_ops",
    )

    assert isinstance(assessment, ReplicationLagAnomalyAssessment)
    assert assessment.level == "normal"
    assert assessment.peer_id == "replica_a"
    assert assessment.claim_id is None
    assert assessment.action_ids == []

    body = json.loads(route.calls.last.request.content)
    assert body == {
        "mode": "action",
        "peer_id": "replica_a",
        "requested_by": "actor_ops",
    }


@pytest.mark.asyncio
async def test_replication_lag_critical_response_carries_full_chain(
    hy: Hydra, respx_mock: respx.MockRouter
) -> None:
    respx_mock.post(
        "https://hydra.test/diagnostics/micromodels/replication-lag/evaluate"
    ).mock(return_value=httpx.Response(200, json=CRITICAL_RESPONSE))

    assessment = await hy.diagnostics.replication_lag_anomaly(
        peer_id="replica_b",
        requested_by="actor_ops",
    )

    assert assessment.level == "critical"
    assert assessment.peer_id == "replica_b"
    assert assessment.evidence_id == "evi_replag_crit"
    assert assessment.claim_id == "claim_replag_crit"
    assert assessment.action_ids == ["act_replag_crit"]
    assert "Notify action proposed" in assessment.summary
    # Output payload carries the Patch 16 fields (lag_commits +
    # stale_heartbeat) instead of commit-rate's z_score.
    assert assessment.prediction.output["lag_commits"] == 500
    assert assessment.prediction.output["stale_heartbeat"] is False


@pytest.mark.asyncio
async def test_replication_lag_prediction_only_mode_body(
    hy: Hydra, respx_mock: respx.MockRouter
) -> None:
    route = respx_mock.post(
        "https://hydra.test/diagnostics/micromodels/replication-lag/evaluate"
    ).mock(return_value=httpx.Response(200, json=NORMAL_RESPONSE))

    await hy.diagnostics.replication_lag_anomaly(
        peer_id="replica_a",
        requested_by="actor_ops",
        mode="prediction_only",
    )

    body = json.loads(route.calls.last.request.content)
    assert body["mode"] == "prediction_only"
    assert body["peer_id"] == "replica_a"


@pytest.mark.asyncio
async def test_replication_lag_unknown_peer_raises_not_found(
    hy: Hydra, respx_mock: respx.MockRouter
) -> None:
    respx_mock.post(
        "https://hydra.test/diagnostics/micromodels/replication-lag/evaluate"
    ).mock(
        return_value=httpx.Response(
            404,
            json={"error": "unknown replication peer: replica_ghost"},
        )
    )

    with pytest.raises(HydraNotFoundError):
        await hy.diagnostics.replication_lag_anomaly(
            peer_id="replica_ghost",
            requested_by="actor_ops",
        )


# === Sync mirror ===


def test_replication_lag_sync_mirror_returns_same_envelope(
    hy_sync: HydraSync, respx_mock: respx.MockRouter
) -> None:
    """`HydraSync.diagnostics.replication_lag_anomaly` returns the
    same typed envelope as the async client. Sync parity is non-
    negotiable for operator-facing methods."""
    respx_mock.post(
        "https://hydra.test/diagnostics/micromodels/replication-lag/evaluate"
    ).mock(return_value=httpx.Response(200, json=CRITICAL_RESPONSE))

    assessment = hy_sync.diagnostics.replication_lag_anomaly(
        peer_id="replica_b",
        requested_by="actor_ops",
    )

    assert isinstance(assessment, ReplicationLagAnomalyAssessment)
    assert assessment.level == "critical"
    assert assessment.peer_id == "replica_b"
    assert assessment.action_ids == ["act_replag_crit"]


# === Patch 28 — auto-created causal_cell_id ===


@pytest.mark.asyncio
async def test_replication_lag_assessment_has_causal_cell_id(
    hy: Hydra, respx_mock: respx.MockRouter
) -> None:
    """Patch 28 — Critical replication-lag → engine auto-creates
    a Reflex cell and the SDK surfaces its id."""
    body = {**CRITICAL_RESPONSE, "causal_cell_id": "cell_reflex_rl"}
    respx_mock.post(
        "https://hydra.test/diagnostics/micromodels/replication-lag/evaluate"
    ).mock(return_value=httpx.Response(200, json=body))

    assessment = await hy.diagnostics.replication_lag_anomaly(
        peer_id="replica_b",
        requested_by="actor_ops",
    )
    assert assessment.causal_cell_id == "cell_reflex_rl"
