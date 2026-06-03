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
from .client import _link_kind_param
from ._http import HydraHttpClientSync
from ._types import (
    Action,
    ActionExecutionResponse,
    ActionId,
    ActionStatus,
    ActionTransitionResponse,
    ActorId,
    AutoApprovalDecision,
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
    CausalCellChildTrust,
    CausalCell,
    CausalCellId,
    CausalCellKind,
    CausalCellTrustAssessment,
    CorrelationCandidate,
    CorrelationSignalRef,
    IdentityAlias,
    IdentityEntity,
    IdentityEntityId,
    IdentityEntityKind,
    IdentityEntityTrustAssessment,
    IdentityLink,
    IdentityLinkId,
    IdentityLinkKind,
    IdentityLinkTrustAssessment,
    IdentityMatchTrustAssessment,
    SourceTrustAssessment,
    SemanticIdentityMatchAssessment,
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

    def auto_approve_action_if_trusted(
        self,
        action_id: ActionId,
        *,
        actor: ActorId,
        min_trust_score: float = 0.90,
        tenant: TenantId | None = None,
    ) -> AutoApprovalDecision:
        """Sync mirror of `Hydra.auto_approve_action_if_trusted`
        (Trust Patch 7 / Patch 15). Same wire contract, same
        decision-envelope semantics, same error mapping. See the
        async docstring for full details including hard-block
        factors, the operator-history requirement, and the
        Patch 12 trust-spiral fix that makes auto-approvals NOT
        count as operator endorsement in future trust calibration."""
        body: dict[str, Any] = {
            "actor": actor,
            "min_trust_score": min_trust_score,
        }
        raw = self._http.post(
            _paths.action_auto_approve_path(action_id),
            json=body,
            tenant=tenant,
        )
        return AutoApprovalDecision.model_validate(raw)

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

    def assess_causal_cell_trust(
        self,
        cell_id: CausalCellId,
        *,
        tenant: TenantId | None = None,
    ) -> CausalCellTrustAssessment:
        """Sync mirror of `Hydra.assess_causal_cell_trust` (Patch
        24). Same wire contract, same strict-tenant isolation
        (including `None`-tenanted cells invisible to tenanted
        queries), same error mapping (400 missing tenant, 404
        unknown / wrong tenant / system-cell, 500 dangling child).
        See the async docstring for the full Patch 23 factor
        algorithm."""
        raw = self._http.get(
            _paths.trust_cell_path(cell_id),
            tenant=tenant,
        )
        return CausalCellTrustAssessment.model_validate(raw)

    def causal_cell(
        self,
        cell_id: CausalCellId,
        *,
        tenant: TenantId | None = None,
    ) -> CausalCell:
        """Sync mirror of `Hydra.causal_cell` (Patch 25). Reads one
        CausalCell by id from `/causal-cells/{cell_id}`. Same strict
        tenant isolation as the async client (`None`-tenanted cells
        invisible to tenanted queries; wrong tenant → 404
        indistinguishable from unknown id)."""
        raw = self._http.get(
            _paths.causal_cell_path(cell_id),
            tenant=tenant,
        )
        return CausalCell.model_validate(raw["cell"])

    def causal_cells(
        self,
        *,
        kind: CausalCellKind | None = None,
        limit: int | None = None,
        after: str | None = None,
        tenant: TenantId | None = None,
    ) -> list[CausalCell]:
        """Sync mirror of `Hydra.causal_cells` (Patch 25). Two modes:
        unfiltered cursor pagination (`kind=None`, `limit`/`after`
        params) vs filtered-by-kind unpaginated. Built-in kinds
        are snake_case; any other label maps to `Custom(label)`
        server-side and returns an empty list when no cells match.
        See the async docstring for full contract."""
        kind_param: str | None
        if kind is None:
            kind_param = None
        elif isinstance(kind, dict):
            kind_param = kind.get("Custom") or next(iter(kind.values()), None)
        else:
            kind_param = kind
        params: dict[str, str | int] = {}
        if kind_param is not None:
            params["kind"] = kind_param
        if limit is not None:
            params["limit"] = limit
        if after is not None:
            params["after"] = after
        raw = self._http.get(
            _paths.causal_cells_list_path(),
            params=params if params else None,
            tenant=tenant,
        )
        return [CausalCell.model_validate(c) for c in raw["cells"]]

    def compose_hydra_health_cell(
        self,
        *,
        actor: ActorId,
        tenant: TenantId | None = None,
    ) -> CausalCell:
        """Sync mirror of `Hydra.compose_hydra_health_cell` (Patch
        27). Composes the canonical `hydra.health` parent cell
        from the calling tenant's latest self-health reflex
        cells. See the async docstring for the full Patch 26+27
        contract — trust semantics, partial-composition, strict
        tenant scoping, and the auto-create-reflex-cells
        precondition (Patch 28+) all carry."""
        body = {"actor": str(actor)}
        raw = self._http.post(
            _paths.compose_hydra_health_cell_path(),
            json=body,
            tenant=tenant,
        )
        return CausalCell.model_validate(raw["cell"])

    # ========================================================================
    # Identity Graph (Patch 31) — sync mirrors
    # ========================================================================

    def create_identity_entity(
        self,
        entity: IdentityEntity,
        *,
        tenant: TenantId | None = None,
    ) -> IdentityEntity:
        """Sync mirror of `Hydra.create_identity_entity` (Patch
        31). Server overwrites `entity.tenant_id` with the
        header — anti-smuggling rule. See the async docstring
        for the full contract."""
        body = {"entity": entity.model_dump(mode="json")}
        raw = self._http.post(
            _paths.identity_entities_path(),
            json=body,
            tenant=tenant,
        )
        return IdentityEntity.model_validate(raw["entity"])

    def identity_entity(
        self,
        entity_id: IdentityEntityId,
        *,
        tenant: TenantId | None = None,
    ) -> IdentityEntity:
        """Sync mirror of `Hydra.identity_entity`. Strict tenant
        scoping — `None`-tenanted entities invisible to public
        routes."""
        raw = self._http.get(
            _paths.identity_entity_path(entity_id),
            tenant=tenant,
        )
        return IdentityEntity.model_validate(raw["entity"])

    def identity_entities(
        self,
        *,
        kind: IdentityEntityKind | None = None,
        limit: int | None = None,
        after: str | None = None,
        tenant: TenantId | None = None,
    ) -> list[IdentityEntity]:
        """Sync mirror of `Hydra.identity_entities`. Same two-mode
        contract: paginated unfiltered vs filtered-by-kind
        unpaginated."""
        kind_param: str | None
        if kind is None:
            kind_param = None
        elif isinstance(kind, dict):
            kind_param = kind.get("Custom") or next(iter(kind.values()), None)
        else:
            kind_param = kind
        params: dict[str, str | int] = {}
        if kind_param is not None:
            params["kind"] = kind_param
        if limit is not None:
            params["limit"] = limit
        if after is not None:
            params["after"] = after
        raw = self._http.get(
            _paths.identity_entities_path(),
            params=params if params else None,
            tenant=tenant,
        )
        return [
            IdentityEntity.model_validate(e) for e in raw["entities"]
        ]

    def suggest_identity_matches(
        self,
        *,
        source: str,
        normalized: str,
        namespace: str | None = None,
        kind: IdentityEntityKind | None = None,
        limit: int = 10,
        tenant: TenantId | None = None,
    ) -> SemanticIdentityMatchAssessment:
        """Sync mirror of `Hydra.suggest_identity_matches`
        (Patch 30 engine, Patch 31 wire). Read-only,
        deterministic, suggestion-only contract — false
        positives expected, see the async docstring."""
        params: dict[str, str | int] = {
            "source": source,
            "normalized": normalized,
        }
        if namespace is not None:
            params["namespace"] = namespace
        if kind is not None:
            kind_param: str
            if isinstance(kind, dict):
                kind_param = (
                    kind.get("Custom") or next(iter(kind.values()), "") or ""
                )
            else:
                kind_param = kind
            if kind_param:
                params["kind"] = kind_param
        params["limit"] = limit
        raw = self._http.get(
            _paths.identity_matches_path(),
            params=params,
            tenant=tenant,
        )
        return SemanticIdentityMatchAssessment.model_validate(
            raw["assessment"]
        )

    # ========================================================================
    # Accept Semantic Match (Patch 42) — sync mirror
    # ========================================================================

    def accept_semantic_identity_match(
        self,
        *,
        candidate_entity_id: IdentityEntityId,
        alias: IdentityAlias,
        added_by: ActorId,
        tenant: TenantId | None = None,
    ) -> IdentityEntity:
        """Sync mirror of `Hydra.accept_semantic_identity_match`
        (Patch 41 engine, Patch 42 wire). Trust-gated alias
        attach: composes match (Strong) + entity (High) + source
        (High) gates with all scores >= 0.80. Idempotent
        re-accept returns same body shape — wire cannot
        distinguish first-accept from no-op. STRUCTURAL trust
        only — auto-actions MUST compose with semantic
        validation + operator approval + durable audit. See the
        async docstring for the full suggestion-only contract."""
        body = {
            "candidate_entity_id": candidate_entity_id,
            "alias": alias.model_dump(mode="json"),
            "added_by": added_by,
        }
        raw = self._http.post(
            _paths.identity_matches_accept_path(),
            json=body,
            tenant=tenant,
        )
        return IdentityEntity.model_validate(raw["entity"])

    # ========================================================================
    # IdentityLink (Patch 38) — sync mirrors
    # ========================================================================

    def create_identity_link(
        self,
        link: IdentityLink,
        *,
        tenant: TenantId | None = None,
    ) -> IdentityLink:
        """Sync mirror of `Hydra.create_identity_link` (Patch 37
        engine, Patch 38 wire). Server overwrites `link.tenant_id`
        from the header; v0 contract carries forward —
        informational confidence only, no trust verdict, no
        update/delete. See async docstring."""
        body = {"link": link.model_dump(mode="json")}
        raw = self._http.post(
            _paths.identity_links_path(),
            json=body,
            tenant=tenant,
        )
        return IdentityLink.model_validate(raw["link"])

    def identity_link(
        self,
        link_id: IdentityLinkId,
        *,
        tenant: TenantId | None = None,
    ) -> IdentityLink:
        """Sync mirror of `Hydra.identity_link`. Strict tenant
        scoping; unknown / wrong-tenant / `None`-tenanted link
        all surface as `HydraNotFoundError`."""
        raw = self._http.get(
            _paths.identity_link_path(link_id),
            tenant=tenant,
        )
        return IdentityLink.model_validate(raw["link"])

    def identity_links(
        self,
        *,
        from_entity_id: IdentityEntityId | None = None,
        to_entity_id: IdentityEntityId | None = None,
        kind: IdentityLinkKind | None = None,
        after: str | None = None,
        limit: int | None = None,
        tenant: TenantId | None = None,
    ) -> tuple[list[IdentityLink], str | None]:
        """Sync mirror of `Hydra.identity_links`. Returns
        `(links, next_cursor)`. `?kind=` accepts snake_case only;
        `"DownstreamOf"` becomes `Custom("DownstreamOf")` and
        returns empty (documented wart, see async docstring)."""
        params: dict[str, str | int] = {}
        if from_entity_id is not None:
            params["from_entity_id"] = from_entity_id
        if to_entity_id is not None:
            params["to_entity_id"] = to_entity_id
        kp = _link_kind_param(kind)
        if kp is not None:
            params["kind"] = kp
        if after is not None:
            params["after"] = after
        if limit is not None:
            params["limit"] = limit
        raw = self._http.get(
            _paths.identity_links_path(),
            params=params if params else None,
            tenant=tenant,
        )
        links = [IdentityLink.model_validate(l) for l in raw["links"]]
        return links, raw.get("next_cursor")

    def identity_links_for_entity(
        self,
        entity_id: IdentityEntityId,
        *,
        kind: IdentityLinkKind | None = None,
        after: str | None = None,
        limit: int | None = None,
        tenant: TenantId | None = None,
    ) -> tuple[list[IdentityLink], str | None]:
        """Sync mirror of `Hydra.identity_links_for_entity`.
        Returns `(links, next_cursor)` covering both incoming and
        outgoing links for `entity_id`. Server probes entity
        tenant first; missing → 404."""
        params: dict[str, str | int] = {}
        kp = _link_kind_param(kind)
        if kp is not None:
            params["kind"] = kp
        if after is not None:
            params["after"] = after
        if limit is not None:
            params["limit"] = limit
        raw = self._http.get(
            _paths.identity_entity_links_path(entity_id),
            params=params if params else None,
            tenant=tenant,
        )
        links = [IdentityLink.model_validate(l) for l in raw["links"]]
        return links, raw.get("next_cursor")

    # ========================================================================
    # Identity trust (Patch 34) — sync mirrors
    # ========================================================================

    def assess_identity_entity_trust(
        self,
        entity_id: IdentityEntityId,
        *,
        tenant: TenantId | None = None,
    ) -> IdentityEntityTrustAssessment:
        """Sync mirror of `Hydra.assess_identity_entity_trust`
        (Patch 33 engine, Patch 34 wire). Strict tenant scoping;
        unknown / wrong-tenant / `None`-tenanted entity all
        surface as `HydraNotFoundError`. See the async
        docstring for the full suggestion-only contract."""
        raw = self._http.get(
            _paths.trust_identity_entity_path(entity_id),
            tenant=tenant,
        )
        return IdentityEntityTrustAssessment.model_validate(raw)

    def assess_identity_match_trust(
        self,
        *,
        source: str,
        normalized: str,
        candidate_entity_id: IdentityEntityId,
        namespace: str | None = None,
        kind: IdentityEntityKind | None = None,
        tenant: TenantId | None = None,
    ) -> IdentityMatchTrustAssessment:
        """Sync mirror of `Hydra.assess_identity_match_trust`
        (Patch 32 engine, Patch 34 wire). Required kwargs:
        `source`, `normalized`, `candidate_entity_id`. The
        returned envelope carries BOTH axes — `match_level`
        (P30 similarity, including the `"None"` STRING) AND
        `level` (P32 trust verdict). Don't conflate them. See
        the async docstring for the full suggestion-only
        contract."""
        params: dict[str, str] = {
            "source": source,
            "normalized": normalized,
            "candidate_entity_id": str(candidate_entity_id),
        }
        if namespace is not None:
            params["namespace"] = namespace
        if kind is not None:
            kind_param: str
            if isinstance(kind, dict):
                kind_param = (
                    kind.get("Custom") or next(iter(kind.values()), "") or ""
                )
            else:
                kind_param = kind
            if kind_param:
                params["kind"] = kind_param
        raw = self._http.get(
            _paths.trust_identity_matches_path(),
            params=params,
            tenant=tenant,
        )
        return IdentityMatchTrustAssessment.model_validate(raw)

    # ========================================================================
    # Source trust (Patch 36) — sync mirror
    # ========================================================================

    def assess_source_trust(
        self,
        source: str,
        *,
        tenant: TenantId | None = None,
    ) -> SourceTrustAssessment:
        """Sync mirror of `Hydra.assess_source_trust` (Patch 35
        engine, Patch 36 wire). Trust verdict over a free-form
        source string — identity-backed, NOT operational. v1
        folds entity P33 trust + clean-mapped evidence
        reliability; freshness / heartbeat / SLA are out of
        scope. Unknown-but-valid source returns a 200 verdict
        with `level="Unknown"`, NOT 404. See the async docstring
        for the full suggestion-only contract."""
        raw = self._http.get(
            _paths.trust_identity_source_path(source),
            tenant=tenant,
        )
        return SourceTrustAssessment.model_validate(raw)

    # ========================================================================
    # Identity link trust (Patch 40) — sync mirror
    # ========================================================================

    def assess_identity_link_trust(
        self,
        link_id: IdentityLinkId,
        *,
        tenant: TenantId | None = None,
    ) -> IdentityLinkTrustAssessment:
        """Sync mirror of `Hydra.assess_identity_link_trust`
        (Patch 39 engine, Patch 40 wire). Trust verdict over a
        persisted `IdentityLink` edge — STRUCTURAL only, NOT
        semantic correctness. Acyclicity contract: link-trust
        depends on entity-trust; entity-trust MUST NOT depend
        on link-trust. See the async docstring for the full
        suggestion-only contract."""
        raw = self._http.get(
            _paths.trust_identity_link_path(link_id),
            tenant=tenant,
        )
        return IdentityLinkTrustAssessment.model_validate(raw)

    # ========================================================================
    # Correlation (Patch 46/48) — sync mirrors
    # ========================================================================

    def assess_correlation_candidate(
        self,
        signals: list[CorrelationSignalRef],
        *,
        tenant: TenantId | None = None,
    ) -> CorrelationCandidate:
        """Sync mirror of `Hydra.assess_correlation_candidate`
        (Patch 45 engine, Patch 46 wire). Assess whether a
        caller-provided set of signals belong to the same
        real-world story. Returns a `CorrelationCandidate` with
        REQUIRED trust verdict (two-axis: `level` + `strength`).
        The server OVERWRITES every `signal.tenant_id` with the
        `X-Hydra-Tenant` header (anti-smuggling). v1 assesses
        caller-provided groupings — does NOT discover. See the
        async docstring for the full suggestion-only contract."""
        body = {
            "signals": [s.model_dump(mode="json") for s in signals],
        }
        raw = self._http.post(
            _paths.correlations_assess_path(),
            json=body,
            tenant=tenant,
        )
        return CorrelationCandidate.model_validate(raw["candidate"])

    def anchor_correlation_candidate(
        self,
        candidate: CorrelationCandidate,
        *,
        actor: ActorId,
        tenant: TenantId | None = None,
    ) -> CausalCell:
        """Sync mirror of `Hydra.anchor_correlation_candidate`
        (Patch 47 engine, Patch 48 wire). Anchor a trust-gated
        `CorrelationCandidate` as a durable
        `CausalCellKind::Incident`. Returns the typed
        `CausalCell`.

        The server VALIDATES (does NOT overwrite) both
        `candidate.tenant_id` and every `signal.tenant_id`
        against `X-Hydra-Tenant`; mismatch → 400. P47's
        load-bearing "trust the supplied verdict" contract holds
        — the server does NOT re-call
        `assess_correlation_candidate`.

        See the async docstring for the full trust-gate +
        no-dedup contract."""
        body = {
            "candidate": candidate.model_dump(mode="json"),
            "actor": str(actor),
        }
        raw = self._http.post(
            _paths.correlations_anchor_path(),
            json=body,
            tenant=tenant,
        )
        return CausalCell.model_validate(raw["cell"])

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
