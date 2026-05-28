"""Tests for `hy.diagnostics.{anomaly, coverage, counterfactual,
evolution}`.

The four diagnostic surfaces share the namespace `hy.diagnostics`
and follow the same shape: thin HTTP call + `model_validate`.

This file pins three load-bearing semantic boundaries:
  - Counterfactual `diff: None` (omitted) vs `Some(empty)` (zero impact)
  - Evolution `precision/recall/fpr: None` (undefined) vs `0.0` (genuine)
  - Evolution `fire_log/miss_log: None` (not requested) vs `[]` (empty)
"""

from __future__ import annotations

import httpx
import pytest
import respx

from hydra import Hydra, HydraNotFoundError, HydraValidationError


# === Anomaly fixtures ===

ANOMALY_RESPONSE_OK = {
    "anomalies": [
        {
            "anomaly_id": "anom_abc123",
            "kind": {
                "kind": "structural_orphan",
                "details": {
                    "node_id": "node_orphan",
                    "missing_edge_type": "depends_on",
                },
            },
            "description": "dataset node_orphan has 0 'depends_on' edges (expected 1-100)",
            "severity": 0.7,
            "affected_nodes": ["node_orphan"],
            "trigger_event": None,
            "detected_at": "2026-01-01T00:00:00Z",
        }
    ],
    "rule_count": 5,
    "anomaly_count": 1,
    "truncated": False,
    "summary": "Found 1 anomaly(ies). Severity: 0 critical, 1 warning, 0 info. Top category: structural_orphan (1).",
    "engine_duration_ms": 3,
    "analysis_scope": "global",
}


# === Coverage fixtures ===

COVERAGE_RESPONSE_OK = {
    "reports": [
        {
            "model_name": "sentinel_aws_coverage",
            "score": 0.8,
            "total_expectations": 5,
            "met": 4,
            "gaps": [
                {
                    "expectation_index": 2,
                    "description": "at least 1 backup_policy expected (found 0)",
                    "fulfillment": 0.0,
                    "affected_nodes": [],
                }
            ],
            "evaluated_at": "2026-01-01T00:00:00Z",
        }
    ],
    "model_count": 1,
    "report_count": 1,
    "truncated": False,
    "summary": "Coverage evaluated 1 model(s). sentinel_aws_coverage: 80% complete (4 of 5 expectations met).",
    "engine_duration_ms": 2,
    "analysis_scope": "global",
}


# === Counterfactual fixtures ===

COUNTERFACTUAL_FULL_RESPONSE = {
    "event_id": "evt_abc",
    "event_found": True,
    "counterfactual_mode": "single_event_removal",
    "causal_subtree_size": 5,
    "nodes_affected": 1,
    "edges_affected": 0,
    "properties_changed": 0,
    "affected_types": {"dataset": 1},
    "magnitude": 10.0,
    "diff": {
        "nodes_only_in_actual": ["node_x"],
        "nodes_only_in_counterfactual": [],
        "nodes_changed": [],
        "edges_only_in_actual": [],
        "edges_only_in_counterfactual": [],
        "edges_changed": [],
    },
    "summary": "Removing event evt_abc would undo 5 cascaded event(s).",
    "engine_duration_ms": 12,
    "analysis_scope": "global",
}

COUNTERFACTUAL_NO_DIFF_RESPONSE = {
    **COUNTERFACTUAL_FULL_RESPONSE,
    "diff": None,
    "summary": "Removing event evt_abc would undo 5 cascaded event(s). (diff omitted via include_diff=false)",
}


# === Evolution fixtures ===

EVOLUTION_RESPONSE_NO_LOGS = {
    "metrics": [
        {
            "subscription_id": "sub_abc",
            "subscription_name": "Detect orphan datasets",
            "total_fires": 100,
            "total_reactions": 250,
            "true_positives": 60,
            "false_positives": 30,
            "auto_accepted": 5,
            "false_negatives": 4,
            "precision": 0.667,
            "recall": 0.938,
            "false_positive_rate": 0.333,
            "pending_outcomes": 5,
            "fire_log": None,
            "miss_log": None,
        }
    ],
    "subscription_count": 1,
    "metric_count": 1,
    "truncated": False,
    "total_fires_across_all": 100,
    "summary": "Tracked 1 subscription(s), 100 total fires across all.",
    "engine_duration_ms": 1,
    "analysis_scope": "global",
}

EVOLUTION_RESPONSE_WITH_LOGS = {
    "metrics": [
        {
            "subscription_id": "sub_new",
            "subscription_name": "Newly registered",
            "total_fires": 2,
            "total_reactions": 4,
            "true_positives": 0,
            "false_positives": 0,
            "auto_accepted": 0,
            "false_negatives": 0,
            # No judged outcomes yet — precision/recall/fpr are null
            "precision": None,
            "recall": None,
            "false_positive_rate": None,
            "pending_outcomes": 2,
            "fire_log": [
                {
                    "timestamp": "2026-01-01T00:00:00Z",
                    "trigger_event_id": "evt_a",
                    "reaction_count": 2,
                    "outcome": None,
                },
                {
                    "timestamp": "2026-01-01T00:00:01Z",
                    "trigger_event_id": "evt_b",
                    "reaction_count": 2,
                    "outcome": "confirmed",
                },
            ],
            "miss_log": [],  # asked for, but empty
        }
    ],
    "subscription_count": 1,
    "metric_count": 1,
    "truncated": False,
    "total_fires_across_all": 2,
    "summary": "Tracked 1 subscription(s), 2 total fires across all.",
    "engine_duration_ms": 1,
    "analysis_scope": "global",
}


# === Anomaly tests ===


@pytest.mark.asyncio
async def test_anomaly_basic_call(hy: Hydra, respx_mock: respx.MockRouter) -> None:
    respx_mock.get("https://hydra.test/diagnostics/anomaly").mock(
        return_value=httpx.Response(200, json=ANOMALY_RESPONSE_OK)
    )
    resp = await hy.diagnostics.anomaly()
    assert resp.anomaly_count == 1
    assert resp.rule_count == 5
    assert resp.analysis_scope == "global"
    entry = resp.anomalies[0]
    # AnomalyEntry has anomaly_id flattened with the Anomaly fields.
    assert entry.anomaly_id == "anom_abc123"
    assert entry.severity == 0.7
    assert entry.affected_nodes == ["node_orphan"]
    # kind stays as a dict; the inner discriminator is at kind["kind"].
    assert entry.kind["kind"] == "structural_orphan"


@pytest.mark.asyncio
async def test_anomaly_filter_params_pass_through(
    hy: Hydra, respx_mock: respx.MockRouter
) -> None:
    route = respx_mock.get("https://hydra.test/diagnostics/anomaly").mock(
        return_value=httpx.Response(200, json=ANOMALY_RESPONSE_OK)
    )
    await hy.diagnostics.anomaly(severity_min=0.5, kind="structural_orphan", limit=10)
    request = route.calls.last.request
    assert request.url.params["severity_min"] == "0.5"
    assert request.url.params["kind"] == "structural_orphan"
    assert request.url.params["limit"] == "10"


@pytest.mark.asyncio
async def test_anomaly_no_filters_sends_no_query_params(
    hy: Hydra, respx_mock: respx.MockRouter
) -> None:
    route = respx_mock.get("https://hydra.test/diagnostics/anomaly").mock(
        return_value=httpx.Response(200, json=ANOMALY_RESPONSE_OK)
    )
    await hy.diagnostics.anomaly()
    request = route.calls.last.request
    assert request.url.query == b""


@pytest.mark.asyncio
async def test_anomaly_invalid_kind_400(
    hy: Hydra, respx_mock: respx.MockRouter
) -> None:
    """Server validates `kind` server-side and returns 400 for unknowns.
    The SDK surfaces this as HydraValidationError, body preserved."""
    respx_mock.get("https://hydra.test/diagnostics/anomaly").mock(
        return_value=httpx.Response(400, json={"error": "unknown anomaly kind 'nonsense'"})
    )
    with pytest.raises(HydraValidationError) as exc_info:
        await hy.diagnostics.anomaly(kind="nonsense")
    assert "nonsense" in str(exc_info.value)


# === Coverage tests ===


@pytest.mark.asyncio
async def test_coverage_basic_call(hy: Hydra, respx_mock: respx.MockRouter) -> None:
    respx_mock.get("https://hydra.test/diagnostics/coverage").mock(
        return_value=httpx.Response(200, json=COVERAGE_RESPONSE_OK)
    )
    resp = await hy.diagnostics.coverage()
    assert resp.model_count == 1
    assert resp.report_count == 1
    report = resp.reports[0]
    assert report.model_name == "sentinel_aws_coverage"
    assert report.score == 0.8
    assert report.met == 4
    assert len(report.gaps) == 1
    assert report.gaps[0].fulfillment == 0.0


@pytest.mark.asyncio
async def test_coverage_filter_params_pass_through(
    hy: Hydra, respx_mock: respx.MockRouter
) -> None:
    route = respx_mock.get("https://hydra.test/diagnostics/coverage").mock(
        return_value=httpx.Response(200, json=COVERAGE_RESPONSE_OK)
    )
    await hy.diagnostics.coverage(model="sentinel_aws_coverage", failing_only=True, limit=5)
    request = route.calls.last.request
    assert request.url.params["model"] == "sentinel_aws_coverage"
    assert request.url.params["failing_only"] == "true"
    assert request.url.params["limit"] == "5"


@pytest.mark.asyncio
async def test_coverage_empty_reports_array(
    hy: Hydra, respx_mock: respx.MockRouter
) -> None:
    """No registered models: response is well-formed with empty
    reports[]."""
    respx_mock.get("https://hydra.test/diagnostics/coverage").mock(
        return_value=httpx.Response(
            200,
            json={
                "reports": [],
                "model_count": 0,
                "report_count": 0,
                "truncated": False,
                "summary": "Coverage evaluated 0 models.",
                "engine_duration_ms": 0,
                "analysis_scope": "global",
            },
        )
    )
    resp = await hy.diagnostics.coverage()
    assert resp.reports == []
    assert resp.model_count == 0


# === Counterfactual tests ===


@pytest.mark.asyncio
async def test_counterfactual_full_diff(hy: Hydra, respx_mock: respx.MockRouter) -> None:
    respx_mock.get("https://hydra.test/diagnostics/counterfactual/evt_abc").mock(
        return_value=httpx.Response(200, json=COUNTERFACTUAL_FULL_RESPONSE)
    )
    resp = await hy.diagnostics.counterfactual("evt_abc")
    assert resp.event_id == "evt_abc"
    assert resp.event_found is True
    assert resp.counterfactual_mode == "single_event_removal"
    assert resp.nodes_affected == 1
    assert resp.magnitude == 10.0
    # `diff` is present (Some) with one node in `nodes_only_in_actual`.
    assert resp.diff is not None
    assert resp.diff.nodes_only_in_actual == ["node_x"]


@pytest.mark.asyncio
async def test_counterfactual_include_diff_false_returns_none(
    hy: Hydra, respx_mock: respx.MockRouter
) -> None:
    """CRITICAL semantic test: `include_diff=false` → server returns
    `diff: null` → SDK exposes `resp.diff is None`. This is
    DIFFERENT from `Some(GraphDiff with all-empty arrays)` which
    would mean "removing this event changes nothing"."""
    route = respx_mock.get(
        "https://hydra.test/diagnostics/counterfactual/evt_abc"
    ).mock(return_value=httpx.Response(200, json=COUNTERFACTUAL_NO_DIFF_RESPONSE))
    resp = await hy.diagnostics.counterfactual("evt_abc", include_diff=False)
    # The query param is passed through.
    request = route.calls.last.request
    assert request.url.params["include_diff"] == "false"
    # The Optional[GraphDiff] is None — transport-level omission.
    assert resp.diff is None
    # Aggregates are still present.
    assert resp.nodes_affected == 1
    assert resp.magnitude == 10.0


@pytest.mark.asyncio
async def test_counterfactual_404_raises_not_found(
    hy: Hydra, respx_mock: respx.MockRouter
) -> None:
    respx_mock.get(
        "https://hydra.test/diagnostics/counterfactual/evt_missing"
    ).mock(return_value=httpx.Response(404, json={"error": "event not found: evt_missing"}))
    with pytest.raises(HydraNotFoundError):
        await hy.diagnostics.counterfactual("evt_missing")


@pytest.mark.asyncio
async def test_counterfactual_zero_impact_diff_distinguishable(
    hy: Hydra, respx_mock: respx.MockRouter
) -> None:
    """A zero-impact event returns `Some(GraphDiff with empty arrays)`,
    NOT `None`. The SDK must distinguish this from include_diff=false."""
    zero_impact = {
        **COUNTERFACTUAL_FULL_RESPONSE,
        "nodes_affected": 0,
        "edges_affected": 0,
        "properties_changed": 0,
        "magnitude": 0.0,
        "diff": {
            "nodes_only_in_actual": [],
            "nodes_only_in_counterfactual": [],
            "nodes_changed": [],
            "edges_only_in_actual": [],
            "edges_only_in_counterfactual": [],
            "edges_changed": [],
        },
    }
    respx_mock.get("https://hydra.test/diagnostics/counterfactual/evt_abc").mock(
        return_value=httpx.Response(200, json=zero_impact)
    )
    resp = await hy.diagnostics.counterfactual("evt_abc")
    assert resp.diff is not None  # NOT omitted
    assert resp.diff.nodes_only_in_actual == []  # really empty
    assert resp.nodes_affected == 0


# === Evolution tests ===


@pytest.mark.asyncio
async def test_evolution_basic_call(hy: Hydra, respx_mock: respx.MockRouter) -> None:
    respx_mock.get("https://hydra.test/diagnostics/evolution").mock(
        return_value=httpx.Response(200, json=EVOLUTION_RESPONSE_NO_LOGS)
    )
    resp = await hy.diagnostics.evolution()
    assert resp.subscription_count == 1
    assert resp.total_fires_across_all == 100
    metric = resp.metrics[0]
    assert metric.subscription_id == "sub_abc"
    assert metric.precision == 0.667
    assert metric.recall == 0.938


@pytest.mark.asyncio
async def test_evolution_filter_params_pass_through(
    hy: Hydra, respx_mock: respx.MockRouter
) -> None:
    route = respx_mock.get("https://hydra.test/diagnostics/evolution").mock(
        return_value=httpx.Response(200, json=EVOLUTION_RESPONSE_NO_LOGS)
    )
    await hy.diagnostics.evolution(
        subscription_id="sub_abc",
        min_fires=10,
        include_logs=False,
        limit=50,
    )
    request = route.calls.last.request
    assert request.url.params["subscription_id"] == "sub_abc"
    assert request.url.params["min_fires"] == "10"
    assert request.url.params["include_logs"] == "false"
    assert request.url.params["limit"] == "50"


@pytest.mark.asyncio
async def test_evolution_logs_none_when_not_requested(
    hy: Hydra, respx_mock: respx.MockRouter
) -> None:
    """CRITICAL semantic test: when `include_logs=false`, the engine
    returns `fire_log: null` and `miss_log: null` — the SDK exposes
    these as `None`. Different from `[]` (requested but empty)."""
    respx_mock.get("https://hydra.test/diagnostics/evolution").mock(
        return_value=httpx.Response(200, json=EVOLUTION_RESPONSE_NO_LOGS)
    )
    resp = await hy.diagnostics.evolution()
    metric = resp.metrics[0]
    assert metric.fire_log is None
    assert metric.miss_log is None


@pytest.mark.asyncio
async def test_evolution_logs_lists_when_requested(
    hy: Hydra, respx_mock: respx.MockRouter
) -> None:
    """When `include_logs=true`, the engine returns lists. `fire_log`
    has 2 records here; `miss_log` is `[]` (requested but no misses
    yet). Both are `Some` (not None)."""
    respx_mock.get("https://hydra.test/diagnostics/evolution").mock(
        return_value=httpx.Response(200, json=EVOLUTION_RESPONSE_WITH_LOGS)
    )
    resp = await hy.diagnostics.evolution(include_logs=True)
    metric = resp.metrics[0]
    assert metric.fire_log is not None
    assert len(metric.fire_log) == 2
    assert metric.fire_log[0].outcome is None  # not judged yet
    assert metric.fire_log[1].outcome == "confirmed"
    assert metric.miss_log is not None
    assert metric.miss_log == []  # requested, no misses


@pytest.mark.asyncio
async def test_evolution_precision_none_when_undefined(
    hy: Hydra, respx_mock: respx.MockRouter
) -> None:
    """A subscription with no judged outcomes yet has
    precision/recall/fpr = None. This is distinct from 0.0
    (all judged were FP / all catch-set missed)."""
    respx_mock.get("https://hydra.test/diagnostics/evolution").mock(
        return_value=httpx.Response(200, json=EVOLUTION_RESPONSE_WITH_LOGS)
    )
    resp = await hy.diagnostics.evolution(include_logs=True)
    metric = resp.metrics[0]
    assert metric.precision is None
    assert metric.recall is None
    assert metric.false_positive_rate is None
    assert metric.pending_outcomes == 2


# === Namespace tests ===


@pytest.mark.asyncio
async def test_diagnostics_namespace_is_single_instance(hy: Hydra) -> None:
    """`hy.diagnostics` is one instance per client (per the
    'instantiated in __init__' design choice), not a property
    that creates new instances on each access."""
    assert hy.diagnostics is hy.diagnostics
    assert hy.diagnostics.__class__.__name__ == "_Diagnostics"


@pytest.mark.asyncio
async def test_diagnostics_tenant_override_on_anomaly(
    hy: Hydra, respx_mock: respx.MockRouter
) -> None:
    """Rule #7 — tenant override on every method, including
    namespaced ones."""
    route = respx_mock.get("https://hydra.test/diagnostics/anomaly").mock(
        return_value=httpx.Response(200, json=ANOMALY_RESPONSE_OK)
    )
    await hy.diagnostics.anomaly(tenant="tenant_other")
    request = route.calls.last.request
    assert request.headers["X-Hydra-Tenant"] == "tenant_other"
