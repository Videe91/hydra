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
    ActionId,
    ActorId,
    AgentLoopStormAssessment,
    AnomalyResponse,
    CommitRateAnomalyAssessment,
    CounterfactualDiagnosticsResponse,
    CoverageDiagnosticsResponse,
    EvaluationMode,
    EventId,
    EvolutionDiagnosticsResponse,
    MicroModelObservation,
    OutcomeId,
    ReplicationLagAnomalyAssessment,
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

    async def replication_lag_anomaly(
        self,
        *,
        peer_id: str,
        requested_by: ActorId,
        mode: EvaluationMode = "action",
        tenant: TenantId | None = None,
    ) -> ReplicationLagAnomalyAssessment:
        """Drive the built-in replication-lag anomaly micro-model
        (MicroModel Patch 16) from outside the engine.

        Second built-in model. Same reflex stack as commit-rate
        (prediction → evidence → claim → Notify action), threshold-
        based (no warmup). The model judges one peer at a time:
        `lag_commits` against `warning_lag_commits=10` /
        `critical_lag_commits=100`, with a stale-heartbeat override
        (`stale_heartbeat_after_secs=60`) that forces Critical when
        the most recent observation is too old.

        `mode` controls how far down the reflex chain the engine walks:

          - `"prediction_only"` — record only the prediction event
          - `"claim"` — prediction + (Warning/Critical) evidence + claim
          - `"action"` (default) — full chain through the Notify
            action when the verification gate passes

        The Notify action's payload carries `peer_id` so the Patch
        14 delivery adapter can route alerts per-peer.

        Returns a typed `ReplicationLagAnomalyAssessment` carrying
        every id the engine produced PLUS the `peer_id` echoed back
        from the request, a server-rendered `summary`, and a
        relative `lineage_url` pointing at the prediction event.

        Errors:
          - 404 → `HydraNotFoundError`: unknown `peer_id`
          - Everything else → `HydraError` subclasses
        """
        body: dict[str, Any] = {
            "mode": mode,
            "peer_id": peer_id,
            "requested_by": requested_by,
        }
        raw = await self._http.post(
            _paths.diagnostics_micromodels_replication_lag_evaluate_path(),
            json=body,
            tenant=tenant,
        )
        return ReplicationLagAnomalyAssessment.model_validate(raw)

    async def agent_loop_storm(
        self,
        *,
        requested_by: ActorId,
        mode: EvaluationMode = "action",
        tenant: TenantId | None = None,
    ) -> AgentLoopStormAssessment:
        """Drive the built-in agent-loop-storm micro-model
        (MicroModel Patch 18) from outside the engine.

        Hydra's first safety reflex: it watches whether the
        system is producing too many self-triggered events /
        actions / claims in a short window — i.e. agents chasing
        their own tail. Hydra-internal actors (cascade,
        trust-gate, verification agent, model auto-register
        actors) are filtered out server-side so the storm signal
        reflects non-Hydra agent activity only.

        Default thresholds (60s window): 50 / 200 agent events,
        10 / 50 actions, 30 / 100 same-actor events. Stateless
        threshold detector — no warmup, no EWMA.

        `mode` controls how far down the reflex chain the engine
        walks:

          - `"prediction_only"` — record only the prediction event
          - `"claim"` — prediction + (Warning/Critical) evidence + claim
          - `"action"` (default) — full chain through the Notify
            action targeting `System("hydra.agents")`. Action
            payload carries `top_actor` and `window_secs`.

        **Auto-approval safety**: the storm model has no
        operator-approved history at launch, so Patch 15's
        trust-gated auto-approval is structurally blocked until a
        human has explicitly approved at least one prior storm
        action. Storm response is operator judgment in v0 — no
        throttle or quarantine action kind ships in Patch 18.
        """
        body: dict[str, Any] = {
            "mode": mode,
            "requested_by": requested_by,
        }
        raw = await self._http.post(
            _paths.diagnostics_micromodels_agent_loop_storm_evaluate_path(),
            json=body,
            tenant=tenant,
        )
        return AgentLoopStormAssessment.model_validate(raw)

    async def record_observation_from_outcome(
        self,
        outcome_id: OutcomeId,
        *,
        observed_by: ActorId,
        tenant: TenantId | None = None,
    ) -> MicroModelObservation:
        """Close the model feedback loop (MicroModel Patch 8).

        Walks the causal chain from a recorded `Outcome` back to
        the originating `MicroModelPrediction` and records a
        `MicroModelObservation` matched by the prediction's
        `run_id`. The audit linkage (outcome_id / action_id /
        claim_id / outcome_kind / outcome_summary / action_lifecycle
        / operator_approved / operator_rejected / observed_by) lives
        inside `observed_outcome` as a JSON dict.

        Patch 8 v0 sets `error = None` because the executed-action
        path is a stub — no scalar loss metric is meaningful yet.
        Future patches add real error scoring.

        Errors:
          - 404 → `HydraNotFoundError`: outcome_id unknown
          - 400 → `HydraValidationError`: outcome exists but the
            chain walk failed (not a model-derived executed
            outcome — e.g., the action had no `related_claims` or
            the claim had no `caused_by`)

        The `MicroModelStore` keys observations by `run_id`, so a
        second recording overwrites the cached observation. The
        audit log keeps every event.
        """
        body = {"observed_by": observed_by}
        raw = await self._http.post(
            _paths.diagnostics_micromodels_observation_from_outcome_path(outcome_id),
            json=body,
            tenant=tenant,
        )
        return MicroModelObservation.model_validate(raw)

    async def record_observation_from_rejected_action(
        self,
        action_id: ActionId,
        *,
        observed_by: ActorId,
        tenant: TenantId | None = None,
    ) -> MicroModelObservation:
        """Record an observation for an OPERATOR-rejected model-derived
        action (Trust Patch 5 / Patch 13). Corrective-memory companion
        to `record_observation_from_outcome`.

        Walks `action.related_claims[0]` → `claim.caused_by` →
        MicroModelPredictionRecorded → `prediction.run_id` and
        synthesizes a MicroModelObservation whose `observed_outcome`
        JSON carries `action_lifecycle == "rejected"`,
        `operator_rejected == true`, and the `rejection_reason`
        copied from the original `EventKind::ActionRejected` event.

        Refused when:
          - action_id unknown → `HydraNotFoundError` (404)
          - action.status != Rejected → `HydraValidationError` (400)
          - action.rejected_by is cascade actor (policy enforcement,
            not human judgment) → `HydraValidationError` (400)
          - action not traceable to a MicroModelPrediction →
            `HydraValidationError` (400)

        v0 caveat: cascade rejections never produce observations.
        The negative trust factor `model_operator_rejected_historically`
        therefore reflects HUMAN rejection history only — which is
        the intended invariant.
        """
        body = {"observed_by": observed_by}
        raw = await self._http.post(
            _paths.diagnostics_micromodels_observation_from_rejected_action_path(
                action_id
            ),
            json=body,
            tenant=tenant,
        )
        return MicroModelObservation.model_validate(raw)


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

    def replication_lag_anomaly(
        self,
        *,
        peer_id: str,
        requested_by: ActorId,
        mode: EvaluationMode = "action",
        tenant: TenantId | None = None,
    ) -> ReplicationLagAnomalyAssessment:
        """Sync mirror of the async `replication_lag_anomaly` —
        drives the built-in replication-lag micro-model (Patch 16)
        via `POST /diagnostics/micromodels/replication-lag/evaluate`.
        See the async docstring for full semantics, thresholds,
        and the stale-heartbeat override."""
        body: dict[str, Any] = {
            "mode": mode,
            "peer_id": peer_id,
            "requested_by": requested_by,
        }
        raw = self._http.post(
            _paths.diagnostics_micromodels_replication_lag_evaluate_path(),
            json=body,
            tenant=tenant,
        )
        return ReplicationLagAnomalyAssessment.model_validate(raw)

    def agent_loop_storm(
        self,
        *,
        requested_by: ActorId,
        mode: EvaluationMode = "action",
        tenant: TenantId | None = None,
    ) -> AgentLoopStormAssessment:
        """Sync mirror of the async `agent_loop_storm` — drives
        the built-in agent-loop-storm micro-model (Patch 18) via
        `POST /diagnostics/micromodels/agent-loop-storm/evaluate`.
        See the async docstring for full semantics, thresholds,
        and the auto-approval safety note."""
        body: dict[str, Any] = {
            "mode": mode,
            "requested_by": requested_by,
        }
        raw = self._http.post(
            _paths.diagnostics_micromodels_agent_loop_storm_evaluate_path(),
            json=body,
            tenant=tenant,
        )
        return AgentLoopStormAssessment.model_validate(raw)

    def record_observation_from_outcome(
        self,
        outcome_id: OutcomeId,
        *,
        observed_by: ActorId,
        tenant: TenantId | None = None,
    ) -> MicroModelObservation:
        """Sync mirror of the async `record_observation_from_outcome`
        — walks the causal chain from a recorded `Outcome` back to
        the originating `MicroModelPrediction` and records a
        `MicroModelObservation`. See the async docstring for full
        semantics and error mapping."""
        body = {"observed_by": observed_by}
        raw = self._http.post(
            _paths.diagnostics_micromodels_observation_from_outcome_path(outcome_id),
            json=body,
            tenant=tenant,
        )
        return MicroModelObservation.model_validate(raw)

    def record_observation_from_rejected_action(
        self,
        action_id: ActionId,
        *,
        observed_by: ActorId,
        tenant: TenantId | None = None,
    ) -> MicroModelObservation:
        """Sync mirror of the async
        `record_observation_from_rejected_action` — synthesizes a
        rejection-shaped MicroModelObservation for an
        operator-rejected action. See the async docstring for full
        semantics and error mapping."""
        body = {"observed_by": observed_by}
        raw = self._http.post(
            _paths.diagnostics_micromodels_observation_from_rejected_action_path(
                action_id
            ),
            json=body,
            tenant=tenant,
        )
        return MicroModelObservation.model_validate(raw)
