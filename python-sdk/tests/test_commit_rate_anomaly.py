"""Tests for `hy.diagnostics.commit_rate_anomaly(...)` (Patch 5 — the
external evaluation surface for the built-in commit-rate micro-model).

Verifies:
  - Default `mode` is `"action"` when caller omits it
  - All three modes route to the same `/diagnostics/micromodels/
    commit-rate/evaluate` endpoint with the right body shape
  - Typed `CommitRateAnomalyAssessment` returned
  - `evidence_id` / `claim_id` / `action_ids` semantics across
    levels
  - Tenant override
  - Sync mirror parity (`HydraSync.diagnostics.commit_rate_anomaly`)
"""

from __future__ import annotations

import json
from typing import Any

import httpx
import pytest
import respx

from hydra import (
    CommitRateAnomalyAssessment,
    Hydra,
    HydraSync,
)


# === Fixtures ===

WARMUP_RESPONSE: dict[str, Any] = {
    "level": "warming_up",
    "prediction": {
        "model_id": "mm_builtin_commit_rate_v0",
        "run_id": "mmrun_001",
        "input": {
            "observed_at": "2026-05-29T00:00:00Z",
            "window_secs": 60,
            "commit_count_in_window": 2,
            "samples_seen_before_this": 0,
        },
        "output": {
            "level": "warming_up",
            "direction": "stable",
            "observed_rate": 2.0,
            "expected_rate": 0.0,
            "z_score": 0.0,
            "reason": "warming up: 1/5 samples collected",
        },
        "confidence": 0.50,
        "explanation": "warming up: 1/5 samples collected",
        "created_at": "2026-05-29T00:00:00Z",
    },
    "prediction_event_id": "evt_pred_warmup",
    "evidence_id": None,
    "evidence_event_id": None,
    "claim_id": None,
    "claim_event_id": None,
    "action_ids": [],
    "summary": "Model warming up; no claim or action.",
    "lineage_url": "/lineage/evt_pred_warmup",
}


CRITICAL_RESPONSE: dict[str, Any] = {
    "level": "critical",
    "prediction": {
        "model_id": "mm_builtin_commit_rate_v0",
        "run_id": "mmrun_002",
        "input": {
            "observed_at": "2026-05-29T00:01:00Z",
            "window_secs": 60,
            "commit_count_in_window": 100,
            "samples_seen_before_this": 10,
        },
        "output": {
            "level": "critical",
            "direction": "spike",
            "observed_rate": 100.0,
            "expected_rate": 10.0,
            "z_score": 90.0,
            "reason": (
                "commit rate 100/min vastly exceeds expected 10/min by "
                "z-score 90.0"
            ),
        },
        "confidence": 0.90,
        "explanation": (
            "commit rate 100/min vastly exceeds expected 10/min by "
            "z-score 90.0"
        ),
        "created_at": "2026-05-29T00:01:00Z",
    },
    "prediction_event_id": "evt_pred_critical",
    "evidence_id": "evd_critical",
    "evidence_event_id": "evt_evidence_critical",
    "claim_id": "claim_critical",
    "claim_event_id": "evt_claim_critical",
    "action_ids": ["act_critical_notify"],
    "summary": "Critical: commit rate anomalous; Notify action proposed.",
    "lineage_url": "/lineage/evt_pred_critical",
}


# === Async tests ===


@pytest.mark.asyncio
async def test_commit_rate_anomaly_default_mode_is_action(
    hy: Hydra, respx_mock: respx.MockRouter
) -> None:
    """Per the approved spec — `mode="action"` is the default when
    callers omit it. The SDK sends `"action"` on the wire."""
    route = respx_mock.post(
        "https://hydra.test/diagnostics/micromodels/commit-rate/evaluate"
    ).mock(return_value=httpx.Response(200, json=WARMUP_RESPONSE))

    await hy.diagnostics.commit_rate_anomaly(requested_by="actor_ops")

    body = json.loads(route.calls.last.request.content)
    assert body["mode"] == "action"
    assert body["requested_by"] == "actor_ops"


@pytest.mark.asyncio
async def test_commit_rate_anomaly_passes_mode_in_body(
    hy: Hydra, respx_mock: respx.MockRouter
) -> None:
    """All three modes round-trip on the wire as snake_case strings."""
    route = respx_mock.post(
        "https://hydra.test/diagnostics/micromodels/commit-rate/evaluate"
    ).mock(return_value=httpx.Response(200, json=WARMUP_RESPONSE))

    for mode in ("prediction_only", "claim", "action"):
        await hy.diagnostics.commit_rate_anomaly(
            requested_by="actor_ops", mode=mode
        )
        body = json.loads(route.calls.last.request.content)
        assert body["mode"] == mode


@pytest.mark.asyncio
async def test_commit_rate_anomaly_returns_typed_assessment(
    hy: Hydra, respx_mock: respx.MockRouter
) -> None:
    """The response parses into a typed `CommitRateAnomalyAssessment`
    — agents branch on `.level` directly, not on raw JSON."""
    respx_mock.post(
        "https://hydra.test/diagnostics/micromodels/commit-rate/evaluate"
    ).mock(return_value=httpx.Response(200, json=CRITICAL_RESPONSE))

    assessment = await hy.diagnostics.commit_rate_anomaly(
        requested_by="actor_ops"
    )

    assert isinstance(assessment, CommitRateAnomalyAssessment)
    assert assessment.level == "critical"
    assert assessment.prediction_event_id == "evt_pred_critical"
    assert assessment.evidence_id == "evd_critical"
    assert assessment.evidence_event_id == "evt_evidence_critical"
    assert assessment.claim_id == "claim_critical"
    assert assessment.claim_event_id == "evt_claim_critical"
    assert assessment.action_ids == ["act_critical_notify"]
    # The prediction is a typed model with confidence + output dict.
    assert assessment.prediction.confidence == 0.90
    assert assessment.prediction.output["direction"] == "spike"


@pytest.mark.asyncio
async def test_commit_rate_anomaly_handles_warmup_with_none_fields(
    hy: Hydra, respx_mock: respx.MockRouter
) -> None:
    """When the model is in warmup, every id is `None` and
    `action_ids` is empty. The SDK must surface `None` (not empty
    strings) so agents can branch on `is None` checks."""
    respx_mock.post(
        "https://hydra.test/diagnostics/micromodels/commit-rate/evaluate"
    ).mock(return_value=httpx.Response(200, json=WARMUP_RESPONSE))

    assessment = await hy.diagnostics.commit_rate_anomaly(
        requested_by="actor_ops"
    )

    assert assessment.level == "warming_up"
    assert assessment.evidence_id is None
    assert assessment.evidence_event_id is None
    assert assessment.claim_id is None
    assert assessment.claim_event_id is None
    assert assessment.action_ids == []
    assert "warming up" in assessment.summary
    assert assessment.lineage_url == "/lineage/evt_pred_warmup"


@pytest.mark.asyncio
async def test_commit_rate_anomaly_tenant_override(
    hy: Hydra, respx_mock: respx.MockRouter
) -> None:
    """Per-call tenant override applies (Rule #7 — same as every other
    SDK method)."""
    route = respx_mock.post(
        "https://hydra.test/diagnostics/micromodels/commit-rate/evaluate"
    ).mock(return_value=httpx.Response(200, json=WARMUP_RESPONSE))

    await hy.diagnostics.commit_rate_anomaly(
        requested_by="actor_ops", tenant="tenant_other"
    )

    assert (
        route.calls.last.request.headers["X-Hydra-Tenant"]
        == "tenant_other"
    )


@pytest.mark.asyncio
async def test_commit_rate_anomaly_lineage_url_is_relative(
    hy: Hydra, respx_mock: respx.MockRouter
) -> None:
    """`lineage_url` is intentionally relative (`/lineage/<id>`) so the
    caller chooses the deployment host. Pinned by name so a future
    patch doesn't accidentally absolute-ize it."""
    respx_mock.post(
        "https://hydra.test/diagnostics/micromodels/commit-rate/evaluate"
    ).mock(return_value=httpx.Response(200, json=CRITICAL_RESPONSE))

    assessment = await hy.diagnostics.commit_rate_anomaly(
        requested_by="actor_ops"
    )

    assert assessment.lineage_url.startswith("/lineage/")
    assert assessment.prediction_event_id in assessment.lineage_url


# === Sync mirror ===


def test_commit_rate_anomaly_sync_mirror(
    hy_sync: HydraSync, respx_mock: respx.MockRouter
) -> None:
    """The sync mirror returns the same typed `CommitRateAnomalyAssessment`
    and routes through the same endpoint. Pinned because Patch 5 is
    the first diagnostics method that mutates state — the sync
    parity rule extends to writes, not just reads."""
    route = respx_mock.post(
        "https://hydra.test/diagnostics/micromodels/commit-rate/evaluate"
    ).mock(return_value=httpx.Response(200, json=CRITICAL_RESPONSE))

    assessment = hy_sync.diagnostics.commit_rate_anomaly(
        requested_by="actor_ops"
    )

    assert isinstance(assessment, CommitRateAnomalyAssessment)
    assert assessment.level == "critical"
    assert assessment.action_ids == ["act_critical_notify"]

    # Body shape on the wire is identical to the async path.
    body = json.loads(route.calls.last.request.content)
    assert body == {"mode": "action", "requested_by": "actor_ops"}


def test_commit_rate_anomaly_sync_tenant_override(
    hy_sync: HydraSync, respx_mock: respx.MockRouter
) -> None:
    route = respx_mock.post(
        "https://hydra.test/diagnostics/micromodels/commit-rate/evaluate"
    ).mock(return_value=httpx.Response(200, json=WARMUP_RESPONSE))

    hy_sync.diagnostics.commit_rate_anomaly(
        requested_by="actor_ops", tenant="tenant_x"
    )

    assert (
        route.calls.last.request.headers["X-Hydra-Tenant"]
        == "tenant_x"
    )


# === Path helper ===


def test_commit_rate_evaluate_path_pinned() -> None:
    """Hyphenated, under /diagnostics/. Pinned so a future patch
    doesn't drift the URL out from under deployed agents."""
    from hydra import _paths

    assert (
        _paths.diagnostics_micromodels_commit_rate_evaluate_path()
        == "/diagnostics/micromodels/commit-rate/evaluate"
    )
