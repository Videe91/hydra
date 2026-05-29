"""Diagnostics namespace — `hy.diagnostics.{anomaly, coverage,
counterfactual, evolution}`.

Not constructed directly. The public `Hydra` class instantiates one
`_Diagnostics` in `__init__` and exposes it as `hy.diagnostics`.

Each method is intentionally thin (HTTP call + `model_validate`)
per the SDK posture: the server owns semantics; the SDK owns typing,
routing, auth/tenant headers, and error mapping.
"""

from __future__ import annotations

from typing import Any

from . import _paths
from ._http import HydraHttpClient, HydraHttpClientSync
from ._types import (
    ActorId,
    AnomalyResponse,
    CommitRateAnomalyAssessment,
    CounterfactualDiagnosticsResponse,
    CoverageDiagnosticsResponse,
    EvaluationMode,
    EventId,
    EvolutionDiagnosticsResponse,
    TenantId,
)


class _Diagnostics:
    """Namespace for Hydra's diagnostic surfaces — anomaly,
    coverage, counterfactual, evolution.

    Access via `hy.diagnostics.<method>` on a `Hydra` client. Not
    intended for direct construction.
    """

    def __init__(self, http: HydraHttpClient, default_tenant: TenantId | None) -> None:
        self._http = http
        # The default tenant is captured from the parent client at
        # construction time. Per-call `tenant=` overrides win (Rule #7);
        # this default applies when no override is passed.
        self._default_tenant = default_tenant

    async def anomaly(
        self,
        *,
        severity_min: float | None = None,
        kind: str | None = None,
        limit: int | None = None,
        tenant: TenantId | None = None,
    ) -> AnomalyResponse:
        """Return the current set of anomalies the engine has detected, optionally filtered by severity, kind, or limit."""
        params: dict[str, Any] = {}
        if severity_min is not None:
            params["severity_min"] = severity_min
        if kind is not None:
            params["kind"] = kind
        if limit is not None:
            params["limit"] = limit
        data = await self._http.get(
            _paths.diagnostics_anomaly_path(),
            params=params or None,
            tenant=tenant,
        )
        return AnomalyResponse.model_validate(data)

    async def coverage(
        self,
        *,
        model: str | None = None,
        failing_only: bool | None = None,
        limit: int | None = None,
        tenant: TenantId | None = None,
    ) -> CoverageDiagnosticsResponse:
        """Return coverage reports for every registered coverage model, optionally filtered to one model or to failing models only."""
        params: dict[str, Any] = {}
        if model is not None:
            params["model"] = model
        if failing_only is not None:
            params["failing_only"] = "true" if failing_only else "false"
        if limit is not None:
            params["limit"] = limit
        data = await self._http.get(
            _paths.diagnostics_coverage_path(),
            params=params or None,
            tenant=tenant,
        )
        return CoverageDiagnosticsResponse.model_validate(data)

    async def counterfactual(
        self,
        event_id: EventId,
        *,
        include_diff: bool | None = None,
        tenant: TenantId | None = None,
    ) -> CounterfactualDiagnosticsResponse:
        """Return the causal-simulation result for an event: what would the graph look like if this event hadn't happened?"""
        params: dict[str, Any] = {}
        if include_diff is not None:
            params["include_diff"] = "true" if include_diff else "false"
        data = await self._http.get(
            _paths.diagnostics_counterfactual_path(event_id),
            params=params or None,
            tenant=tenant,
        )
        return CounterfactualDiagnosticsResponse.model_validate(data)

    async def evolution(
        self,
        *,
        subscription_id: str | None = None,
        min_fires: int | None = None,
        include_logs: bool | None = None,
        limit: int | None = None,
        tenant: TenantId | None = None,
    ) -> EvolutionDiagnosticsResponse:
        """Return subscription-effectiveness metrics (precision, recall, false-positive rate) for every tracked subscription."""
        params: dict[str, Any] = {}
        if subscription_id is not None:
            params["subscription_id"] = subscription_id
        if min_fires is not None:
            params["min_fires"] = min_fires
        if include_logs is not None:
            params["include_logs"] = "true" if include_logs else "false"
        if limit is not None:
            params["limit"] = limit
        data = await self._http.get(
            _paths.diagnostics_evolution_path(),
            params=params or None,
            tenant=tenant,
        )
        return EvolutionDiagnosticsResponse.model_validate(data)

    async def commit_rate_anomaly(
        self,
        *,
        requested_by: ActorId,
        mode: EvaluationMode = "action",
        tenant: TenantId | None = None,
    ) -> CommitRateAnomalyAssessment:
        """Drive the built-in commit-rate anomaly micro-model from outside the engine.

        `mode` controls how far down the reflex chain the engine walks:

          - `"prediction_only"` — record only the prediction event
          - `"claim"` — prediction + (Warning/Critical) evidence + claim
          - `"action"` (default) — full chain through the Notify action
            when the verification gate passes

        Returns a typed `CommitRateAnomalyAssessment` carrying every
        id the engine produced plus a server-rendered `summary` and
        a relative `lineage_url` pointing at the prediction event.
        Absent ids are `None`, NOT empty strings; `action_ids` is an
        empty list when no action was proposed.

        The engine method records `MicroModelPredictionRecorded` and
        (for actionable levels at modes `claim`/`action`) downstream
        `EvidenceAdded` / `ClaimProposed` / `ActionProposed` events.
        Patch 5 does NOT execute the action — `ActionStatus::Proposed`
        is the highest state reached. Execution, delivery, and
        approval are explicit future patches.
        """
        body: dict[str, Any] = {
            "mode": mode,
            "requested_by": requested_by,
        }
        raw = await self._http.post(
            _paths.diagnostics_micromodels_commit_rate_evaluate_path(),
            json=body,
            tenant=tenant,
        )
        return CommitRateAnomalyAssessment.model_validate(raw)


# === Patch 5: sync mirror ===
#
# Line-by-line parity with `_Diagnostics`. Same parameter names, same
# defaults, same return types. The only differences:
#   - `self._http` is a `HydraHttpClientSync` (not `HydraHttpClient`)
#   - No `async`/`await`
#
# Kept in the same file as the async class so a reviewer can verify
# parity by visual diff. Future changes should land in both.


class _DiagnosticsSync:
    """Synchronous mirror of `_Diagnostics`. Access via
    `hy.diagnostics.<method>` on a `HydraSync` client."""

    def __init__(
        self, http: HydraHttpClientSync, default_tenant: TenantId | None
    ) -> None:
        self._http = http
        self._default_tenant = default_tenant

    def anomaly(
        self,
        *,
        severity_min: float | None = None,
        kind: str | None = None,
        limit: int | None = None,
        tenant: TenantId | None = None,
    ) -> AnomalyResponse:
        """Return the current set of anomalies the engine has detected, optionally filtered by severity, kind, or limit."""
        params: dict[str, Any] = {}
        if severity_min is not None:
            params["severity_min"] = severity_min
        if kind is not None:
            params["kind"] = kind
        if limit is not None:
            params["limit"] = limit
        data = self._http.get(
            _paths.diagnostics_anomaly_path(),
            params=params or None,
            tenant=tenant,
        )
        return AnomalyResponse.model_validate(data)

    def coverage(
        self,
        *,
        model: str | None = None,
        failing_only: bool | None = None,
        limit: int | None = None,
        tenant: TenantId | None = None,
    ) -> CoverageDiagnosticsResponse:
        """Return coverage reports for every registered coverage model, optionally filtered to one model or to failing models only."""
        params: dict[str, Any] = {}
        if model is not None:
            params["model"] = model
        if failing_only is not None:
            params["failing_only"] = "true" if failing_only else "false"
        if limit is not None:
            params["limit"] = limit
        data = self._http.get(
            _paths.diagnostics_coverage_path(),
            params=params or None,
            tenant=tenant,
        )
        return CoverageDiagnosticsResponse.model_validate(data)

    def counterfactual(
        self,
        event_id: EventId,
        *,
        include_diff: bool | None = None,
        tenant: TenantId | None = None,
    ) -> CounterfactualDiagnosticsResponse:
        """Return the causal-simulation result for an event: what would the graph look like if this event hadn't happened?"""
        params: dict[str, Any] = {}
        if include_diff is not None:
            params["include_diff"] = "true" if include_diff else "false"
        data = self._http.get(
            _paths.diagnostics_counterfactual_path(event_id),
            params=params or None,
            tenant=tenant,
        )
        return CounterfactualDiagnosticsResponse.model_validate(data)

    def evolution(
        self,
        *,
        subscription_id: str | None = None,
        min_fires: int | None = None,
        include_logs: bool | None = None,
        limit: int | None = None,
        tenant: TenantId | None = None,
    ) -> EvolutionDiagnosticsResponse:
        """Return subscription-effectiveness metrics (precision, recall, false-positive rate) for every tracked subscription."""
        params: dict[str, Any] = {}
        if subscription_id is not None:
            params["subscription_id"] = subscription_id
        if min_fires is not None:
            params["min_fires"] = min_fires
        if include_logs is not None:
            params["include_logs"] = "true" if include_logs else "false"
        if limit is not None:
            params["limit"] = limit
        data = self._http.get(
            _paths.diagnostics_evolution_path(),
            params=params or None,
            tenant=tenant,
        )
        return EvolutionDiagnosticsResponse.model_validate(data)

    def commit_rate_anomaly(
        self,
        *,
        requested_by: ActorId,
        mode: EvaluationMode = "action",
        tenant: TenantId | None = None,
    ) -> CommitRateAnomalyAssessment:
        """Sync mirror of the async `commit_rate_anomaly` — drives
        the built-in commit-rate micro-model from outside the engine
        via `POST /diagnostics/micromodels/commit-rate/evaluate`.
        See the async docstring for full semantics, gate behavior,
        and the level → action recording rules."""
        body: dict[str, Any] = {
            "mode": mode,
            "requested_by": requested_by,
        }
        raw = self._http.post(
            _paths.diagnostics_micromodels_commit_rate_evaluate_path(),
            json=body,
            tenant=tenant,
        )
        return CommitRateAnomalyAssessment.model_validate(raw)
