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
from ._http import HydraHttpClient
from ._types import (
    AnomalyResponse,
    CounterfactualDiagnosticsResponse,
    CoverageDiagnosticsResponse,
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
