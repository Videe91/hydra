"""The synchronous public client — `HydraSync`.

Method-for-method mirror of `Hydra` from `client.py`. Same signatures,
same defaults, same return types, same docstrings. The only
differences:

  - `httpx.Client` instead of `httpx.AsyncClient`
  - No `async`/`await`
  - `with` / `close()` instead of `async with` / `aclose()`

Both `Hydra` and `HydraSync` can coexist in the same process. They do
not share state — each holds its own `HydraHttpClient(Sync)`. Use
`Hydra` from async code (anything inside an event loop) and
`HydraSync` from scripts, notebooks (a Jupyter kernel runs its own
event loop, which would conflict with a nested `asyncio.run`), and
synchronous web frameworks.

See `client.py` for the async version. Future API additions land in
both, kept in sync by review.
"""

from __future__ import annotations

from types import TracebackType
from typing import Any

import httpx

from . import _paths
from ._http import HydraHttpClientSync
from ._types import (
    Action,
    ActionExecutionResponse,
    ActionId,
    ActionStatus,
    ActionTransitionResponse,
    ActorId,
    AutoExecutionDecision,
    Claim,
    ClaimId,
    ClaimKind,
    ClaimStatus,
    Confidence,
    Edge,
    EdgeId,
    Event,
    EventId,
    Evidence,
    EvidenceId,
    IngestResponse,
    LineageResponse,
    Node,
    NodeId,
    Outcome,
    TenantId,
    TrustAssessment,
)
from .diagnostics import _DiagnosticsSync
from .replication import _ReplicationSync
from .schemas import _SchemasSync

IDEMPOTENCY_KEY_HEADER = "Idempotency-Key"


class HydraSync:
    """Synchronous client for a Hydra living database.

    Construct once per connection; reuse across an agent's lifetime.
    Connection pooling lives inside the underlying `httpx.Client`.

    Use as a context manager:

        with HydraSync("http://localhost:8080", token="...") as hy:
            resp = hy.ingest_signal(name="x", source="node_y")

    Or manually:

        hy = HydraSync(...)
        try:
            hy.ingest_signal(...)
        finally:
            hy.close()
    """

    def __init__(
        self,
        base_url: str,
        *,
        token: str | None = None,
        tenant: TenantId | None = None,
        verify: bool = True,
        timeout: float = 10.0,
        client: httpx.Client | None = None,
    ) -> None:
        self._http = HydraHttpClientSync(
            base_url=base_url,
            token=token,
            tenant=tenant,
            verify=verify,
            timeout=timeout,
            client=client,
        )
        self.base_url = self._http.base_url
        self.tenant = tenant
        # `_token` intentionally not exposed; redacted in __repr__.
        self._has_token = token is not None
        # Namespaces — same pattern as the async `Hydra` class.
        self.diagnostics = _DiagnosticsSync(self._http, tenant)
        self.schemas = _SchemasSync(self._http, tenant)
        self.replication = _ReplicationSync(self._http, tenant)

    def __repr__(self) -> str:
        """Token-redacted representation. Same shape as `Hydra.__repr__`
        — prevents bearer-token leaks via `print(hy)`, repl inspection,
        or uncaught-exception tracebacks that include locals."""
        token_repr = "<set>" if self._has_token else "<unset>"
        return (
            f"HydraSync(base_url={self.base_url!r}, "
            f"tenant={self.tenant!r}, "
            f"token={token_repr})"
        )

    def close(self) -> None:
        self._http.close()

    def __enter__(self) -> HydraSync:
        return self

    def __exit__(
        self,
        exc_type: type[BaseException] | None,
        exc: BaseException | None,
        tb: TracebackType | None,
    ) -> None:
        self.close()

    # ========================================================================
    # Ingest helpers (Rule #1 — semantic verbs, NOT endpoint mirrors)
    # ========================================================================

    def ingest_signal(
        self,
        name: str,
        *,
        source: NodeId,
        payload: dict[str, Any] | None = None,
        tenant: TenantId | None = None,
        idempotency_key: str | None = None,
    ) -> IngestResponse:
        """Ingest a `Signal` event.

        See `Hydra.ingest_signal` for full semantics. Sync mirror.
        """
        event_kind: dict[str, Any] = {
            "Signal": {
                "source": source,
                "name": name,
                "payload": payload or {},
            }
        }
        return self._ingest(event_kind, tenant=tenant, idempotency_key=idempotency_key)

    def propose_claim(
        self,
        *,
        claim_id: ClaimId,
        subject: dict[str, Any],
        predicate: str,
        object: dict[str, Any],
        created_by: str,
        kind: ClaimKind = "Inference",
        confidence: Confidence = 1.0,
        status: ClaimStatus = "Proposed",
        evidence_for: list[EvidenceId] | None = None,
        evidence_against: list[EvidenceId] | None = None,
        valid_from: str | None = None,
        valid_until: str | None = None,
        caused_by: EventId | None = None,
        tenant: TenantId | None = None,
        idempotency_key: str | None = None,
    ) -> IngestResponse:
        """Propose a new claim. Sync mirror of `Hydra.propose_claim`.

        See `Hydra.propose_claim` for the `caused_by` semantics —
        threading the upstream signal event id makes the claim show up
        in `hy.lineage(signal_event_id)`."""
        from datetime import datetime, timezone

        now_iso = datetime.now(timezone.utc).isoformat()
        claim: dict[str, Any] = {
            "id": claim_id,
            "tenant_id": tenant if tenant is not None else self.tenant,
            "kind": kind,
            "subject": subject,
            "predicate": predicate,
            "object": object,
            "confidence": confidence,
            "status": status,
            "evidence_for": evidence_for or [],
            "evidence_against": evidence_against or [],
            "valid_from": valid_from or now_iso,
            "valid_until": valid_until,
            "created_by": created_by,
            "created_at": now_iso,
            "updated_at": now_iso,
            "caused_by": caused_by,
        }
        event_kind = {"ClaimProposed": {"claim": claim}}
        return self._ingest(event_kind, tenant=tenant, idempotency_key=idempotency_key)

    def add_evidence(
        self,
        *,
        evidence_id: EvidenceId,
        source: dict[str, Any],
        payload_kind: str,
        payload_data: dict[str, Any] | None = None,
        reliability: Confidence = 1.0,
        observed_at: str | None = None,
        caused_by: EventId | None = None,
        tenant: TenantId | None = None,
        idempotency_key: str | None = None,
    ) -> IngestResponse:
        """Add an Evidence record. Sync mirror of `Hydra.add_evidence`.

        See `Hydra.add_evidence` for the `caused_by` semantics."""
        from datetime import datetime, timezone

        now_iso = datetime.now(timezone.utc).isoformat()
        observed_iso = observed_at or now_iso
        evidence: dict[str, Any] = {
            "id": evidence_id,
            "tenant_id": tenant if tenant is not None else self.tenant,
            "source": source,
            "payload": {"kind": payload_kind, "data": payload_data or {}},
            "reliability": reliability,
            "observed_at": observed_iso,
            "recorded_at": now_iso,
            "caused_by": caused_by,
        }
        event_kind = {"EvidenceAdded": {"evidence": evidence}}
        return self._ingest(event_kind, tenant=tenant, idempotency_key=idempotency_key)

    def propose_action(
        self,
        *,
        action_id: ActionId,
        kind: str | dict[str, Any],
        targets: list[dict[str, Any]],
        proposed_by: str,
        related_claims: list[ClaimId] | None = None,
        supporting_evidence: list[EvidenceId] | None = None,
        payload: dict[str, Any] | None = None,
        caused_by: EventId | None = None,
        tenant: TenantId | None = None,
        idempotency_key: str | None = None,
    ) -> IngestResponse:
        """Propose a new Action. Sync mirror of `Hydra.propose_action`.

        See `Hydra.propose_action` for the `caused_by` semantics."""
        from datetime import datetime, timezone

        now_iso = datetime.now(timezone.utc).isoformat()
        action: dict[str, Any] = {
            "id": action_id,
            "tenant_id": tenant if tenant is not None else self.tenant,
            "kind": kind,
            "status": "Proposed",
            "targets": targets,
            "related_claims": related_claims or [],
            "supporting_evidence": supporting_evidence or [],
            "proposed_by": proposed_by,
            "approved_by": None,
            "policy_id": None,
            "payload": payload or {},
            "created_at": now_iso,
            "updated_at": now_iso,
            "approved_at": None,
            "executed_at": None,
            "caused_by": caused_by,
        }
        event_kind = {"ActionProposed": {"action": action}}
        return self._ingest(event_kind, tenant=tenant, idempotency_key=idempotency_key)

    # ========================================================================
    # Patch 6 — operator approval workflow (sync mirror)
    # ========================================================================

    def approve_action(
        self,
        action_id: ActionId,
        *,
        actor: ActorId,
        reason: str | None = None,
        tenant: TenantId | None = None,
    ) -> ActionTransitionResponse:
        """Sync mirror of `Hydra.approve_action`. See the async
        version for full semantics — same wire contract, same
        idempotent behaviour, same 404 mapping."""
        body: dict[str, Any] = {"actor": actor}
        if reason is not None:
            body["reason"] = reason
        raw = self._http.post(
            _paths.action_approve_path(action_id),
            json=body,
            tenant=tenant,
        )
        return ActionTransitionResponse.model_validate(raw)

    def reject_action(
        self,
        action_id: ActionId,
        *,
        actor: ActorId,
        reason: str,
        tenant: TenantId | None = None,
    ) -> ActionTransitionResponse:
        """Sync mirror of `Hydra.reject_action`. `reason` required."""
        body = {"actor": actor, "reason": reason}
        raw = self._http.post(
            _paths.action_reject_path(action_id),
            json=body,
            tenant=tenant,
        )
        return ActionTransitionResponse.model_validate(raw)

    # ========================================================================
    # Patch 7 — Notify execution stub (sync mirror)
    # ========================================================================

    def execute_action(
        self,
        action_id: ActionId,
        *,
        actor: ActorId,
        tenant: TenantId | None = None,
    ) -> ActionExecutionResponse:
        """Sync mirror of `Hydra.execute_action`. See the async
        version for full semantics — same wire contract, same
        preconditions, same outcome shape."""
        body = {"actor": actor}
        raw = self._http.post(
            _paths.action_execute_path(action_id),
            json=body,
            tenant=tenant,
        )
        return ActionExecutionResponse.model_validate(raw)

    # ========================================================================
    # Trust Patch 2 (Patch 10) — read-only trust assessment (sync mirror)
    # ========================================================================

    def auto_execute_action_if_trusted(
        self,
        action_id: ActionId,
        *,
        actor: ActorId,
        min_trust_score: float = 0.80,
        tenant: TenantId | None = None,
    ) -> AutoExecutionDecision:
        """Sync mirror of `Hydra.auto_execute_action_if_trusted`.
        Same wire contract, same decision-envelope semantics,
        same error mapping. See the async docstring for full
        details."""
        body: dict[str, Any] = {
            "actor": actor,
            "min_trust_score": min_trust_score,
        }
        raw = self._http.post(
            _paths.action_auto_execute_path(action_id),
            json=body,
            tenant=tenant,
        )
        return AutoExecutionDecision.model_validate(raw)

    def assess_claim_trust(
        self,
        claim_id: ClaimId,
        *,
        tenant: TenantId | None = None,
    ) -> TrustAssessment:
        """Sync mirror of `Hydra.assess_claim_trust`. Same wire
        contract, same strict-tenant isolation, same error
        mapping (400 missing tenant, 404 unknown or wrong tenant).
        See the async docstring for full semantics."""
        raw = self._http.get(
            _paths.trust_claim_path(claim_id),
            tenant=tenant,
        )
        return TrustAssessment.model_validate(raw)

    def _ingest(
        self,
        event_kind: dict[str, Any],
        *,
        tenant: TenantId | None,
        idempotency_key: str | None,
    ) -> IngestResponse:
        """Centralized POST /ingest call (sync). Mirror of `Hydra._ingest`."""
        extra_headers: dict[str, str] | None = None
        if idempotency_key is not None:
            extra_headers = {IDEMPOTENCY_KEY_HEADER: idempotency_key}
        body = {"event_kind": event_kind}
        raw = self._http.post(
            _paths.ingest_path(),
            json=body,
            tenant=tenant,
            extra_headers=extra_headers,
        )
        return IngestResponse.model_validate(raw)

    # ========================================================================
    # Query methods
    # ========================================================================

    def get_node(self, node_id: NodeId, *, tenant: TenantId | None = None) -> Node:
        raw = self._http.get(_paths.query_node_path(node_id), tenant=tenant)
        return Node.model_validate(raw["node"])

    def get_edge(self, edge_id: EdgeId, *, tenant: TenantId | None = None) -> Edge:
        raw = self._http.get(_paths.query_edge_path(edge_id), tenant=tenant)
        return Edge.model_validate(raw["edge"])

    def get_event(self, event_id: EventId, *, tenant: TenantId | None = None) -> Event:
        """Sync mirror of `Hydra.get_event`. Hits `/events/:event_id`."""
        raw = self._http.get(_paths.event_path(event_id), tenant=tenant)
        return Event.model_validate(raw["event"])

    def get_claim(self, claim_id: ClaimId, *, tenant: TenantId | None = None) -> Claim:
        raw = self._http.get(_paths.query_claim_path(claim_id), tenant=tenant)
        return Claim.model_validate(raw["claim"])

    def get_evidence(
        self, evidence_id: EvidenceId, *, tenant: TenantId | None = None
    ) -> Evidence:
        raw = self._http.get(_paths.query_evidence_path(evidence_id), tenant=tenant)
        return Evidence.model_validate(raw["evidence"])

    def get_action(self, action_id: ActionId, *, tenant: TenantId | None = None) -> Action:
        raw = self._http.get(_paths.query_action_path(action_id), tenant=tenant)
        return Action.model_validate(raw["action"])

    def list_claims(
        self,
        *,
        status: ClaimStatus | None = None,
        kind: ClaimKind | None = None,
        tenant: TenantId | None = None,
    ) -> list[Claim]:
        """Sync mirror of `Hydra.list_claims`. Same three-mode routing."""
        if status is not None and kind is not None:
            raise ValueError(
                "list_claims accepts at most one of `status`/`kind`; "
                "filter combinations are not supported by the engine in v0"
            )
        if status is not None:
            path = _paths.query_claims_by_status_path(status)
            raw = self._http.get(path, tenant=tenant)
            return [Claim.model_validate(c) for c in raw["claims"]]
        if kind is not None:
            path = _paths.query_claims_by_kind_path(kind)
            raw = self._http.get(path, tenant=tenant)
            return [Claim.model_validate(c) for c in raw["claims"]]
        raw = self._http.get(_paths.query_claims_path(), tenant=tenant)
        return [Claim.model_validate(c) for c in raw["items"]]

    def list_claims_for_subject(
        self,
        *,
        subject_kind: str,
        subject_value: str,
        tenant: TenantId | None = None,
    ) -> list[Claim]:
        raw = self._http.get(
            _paths.query_claims_for_subject_path(),
            params={"subject_kind": subject_kind, "subject_value": subject_value},
            tenant=tenant,
        )
        return [Claim.model_validate(c) for c in raw["claims"]]

    def list_claims_for_evidence(
        self, evidence_id: EvidenceId, *, tenant: TenantId | None = None
    ) -> list[Claim]:
        raw = self._http.get(
            _paths.query_claims_using_evidence_path(evidence_id), tenant=tenant
        )
        return [Claim.model_validate(c) for c in raw["claims"]]

    def list_actions(
        self,
        *,
        status: ActionStatus | None = None,
        tenant: TenantId | None = None,
    ) -> list[Action]:
        if status is not None:
            path = _paths.query_actions_by_status_path(status)
            raw = self._http.get(path, tenant=tenant)
            return [Action.model_validate(a) for a in raw["actions"]]
        raw = self._http.get(_paths.query_actions_path(), tenant=tenant)
        return [Action.model_validate(a) for a in raw["items"]]

    def list_outcomes_for_action(
        self, action_id: ActionId, *, tenant: TenantId | None = None
    ) -> list[Outcome]:
        raw = self._http.get(
            _paths.query_outcomes_for_action_path(action_id), tenant=tenant
        )
        return [Outcome.model_validate(o) for o in raw["outcomes"]]

    # ========================================================================
    # Lineage
    # ========================================================================

    def lineage(
        self,
        event_id: EventId,
        *,
        depth: int | None = None,
        tenant: TenantId | None = None,
    ) -> LineageResponse:
        """Return the causal context around an event. Sync mirror of `Hydra.lineage`."""
        params: dict[str, Any] = {}
        if depth is not None:
            params["depth"] = depth
        raw = self._http.get(
            _paths.lineage_path(event_id),
            params=params or None,
            tenant=tenant,
        )
        return LineageResponse.model_validate(raw)
