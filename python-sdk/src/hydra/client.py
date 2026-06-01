"""The public `Hydra` client — async, typed, semantic.

Patch 2 ships:
  - Constructor + context manager + token redaction in repr
  - 4 ingest helpers (semantic — Rule #1)
  - 10 query methods

Methods are flat on the `Hydra` class. Each is fully typed (Rule #4),
each accepts a per-call `tenant=` override (Rule #7), each preserves
server errors verbatim (Rule #8) via the typed exception hierarchy.

Future patches add:
  - Patch 3 (shipped): `lineage(...)`, `diagnostics.{anomaly, coverage,
    counterfactual, evolution}(...)`
  - Patch 4 (shipped): `schemas.*`, `replication.*` (read-only)
  - Patch 5: sync mirror, README, quickstart
"""

from __future__ import annotations

from types import TracebackType
from typing import Any

import httpx

from . import _paths
from ._http import HydraHttpClient
from ._types import (
    Action,
    ActionExecutionResponse,
    ActionId,
    ActionStatus,
    ActionTransitionResponse,
    ActorId,
    AutoApprovalDecision,
    AutoExecutionDecision,
    CausalCell,
    CausalCellChildTrust,
    CausalCellId,
    CausalCellKind,
    CausalCellTrustAssessment,
    IdentityAlias,
    IdentityEntity,
    IdentityEntityId,
    IdentityEntityKind,
    IdentityEntityTrustAssessment,
    IdentityLink,
    IdentityLinkId,
    IdentityLinkKind,
    IdentityMatchTrustAssessment,
    SemanticIdentityMatchAssessment,
    SourceTrustAssessment,
    Claim,
    ClaimId,
    ClaimKind,
    ClaimStatus,
    CommitBatchLite,
    CommitStreamCommit,
    CommitStreamError,
    CommitStreamHeartbeat,
    CommitStreamItem,
    CommitStreamLag,
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
from .diagnostics import _Diagnostics
from .replication import _Replication
from .schemas import _Schemas

IDEMPOTENCY_KEY_HEADER = "Idempotency-Key"


def _link_kind_param(kind: IdentityLinkKind | None) -> str | None:
    """Extract the URL `?kind=` value from an `IdentityLinkKind`.

    Patch 38 server expects snake_case discriminants OR the raw
    `Custom` label. dict-form input (`{"Custom": "uses_metric"}`)
    is unwrapped to the inner label. String input passes through
    verbatim — callers passing `"DownstreamOf"` (PascalCase) will
    be treated as a `Custom("DownstreamOf")` filter server-side
    and almost always get an empty result; this is a documented
    parsing/intent wart, see `parse_identity_link_kind` in
    `hydra-net/src/http/identity.rs`.

    Shared by `Hydra.identity_links` and
    `Hydra.identity_links_for_entity`; re-imported by the sync
    client to keep the extraction logic single-source.
    """
    if kind is None:
        return None
    if isinstance(kind, dict):
        return kind.get("Custom") or next(iter(kind.values()), None)
    return kind


class Hydra:
    """Async client for a Hydra living database.

    Construct once per connection; reuse across an agent's lifetime.
    Connection pooling lives inside the underlying `httpx.AsyncClient`.

    Use as an async context manager:

        async with Hydra("http://localhost:8080", token="...") as hy:
            resp = await hy.ingest_signal(name="x", source="node_y")

    Or manually:

        hy = Hydra(...)
        try:
            await hy.ingest_signal(...)
        finally:
            await hy.aclose()
    """

    def __init__(
        self,
        base_url: str,
        *,
        token: str | None = None,
        tenant: TenantId | None = None,
        verify: bool = True,
        timeout: float = 10.0,
        client: httpx.AsyncClient | None = None,
    ) -> None:
        self._http = HydraHttpClient(
            base_url=base_url,
            token=token,
            tenant=tenant,
            verify=verify,
            timeout=timeout,
            client=client,
        )
        # Public-ish settings — exposed read-only via attributes so
        # callers can inspect what was configured.
        self.base_url = self._http.base_url
        self.tenant = tenant
        # `_token` is intentionally NOT exposed publicly. The redacted
        # `__repr__` below guards against accidental leaks via print
        # or tracebacks (per the strategic-review additional
        # recommendation).
        self._has_token = token is not None
        # Diagnostic-surface namespace — one instance per client, no
        # property-descriptor magic. Methods are
        # `hy.diagnostics.{anomaly,coverage,counterfactual,evolution}`.
        self.diagnostics = _Diagnostics(self._http, tenant)
        # Patch 4 — schema register/read/lifecycle/validate, and
        # read-only replication operator introspection.
        self.schemas = _Schemas(self._http, tenant)
        self.replication = _Replication(self._http, tenant)

    def __repr__(self) -> str:
        """Token-redacted representation. Prevents bearer-token leaks
        via `print(hy)`, repl inspection, and uncaught-exception
        tracebacks that include locals."""
        token_repr = "<set>" if self._has_token else "<unset>"
        return (
            f"Hydra(base_url={self.base_url!r}, "
            f"tenant={self.tenant!r}, "
            f"token={token_repr})"
        )

    # `__str__` falls back to `__repr__`, so the redacted form covers
    # both `str(hy)` and `print(hy)`.

    async def aclose(self) -> None:
        await self._http.aclose()

    async def __aenter__(self) -> Hydra:
        return self

    async def __aexit__(
        self,
        exc_type: type[BaseException] | None,
        exc: BaseException | None,
        tb: TracebackType | None,
    ) -> None:
        await self.aclose()

    # ========================================================================
    # Ingest helpers (Rule #1 — semantic verbs, NOT endpoint mirrors)
    # ========================================================================

    async def ingest_signal(
        self,
        name: str,
        *,
        source: NodeId,
        payload: dict[str, Any] | None = None,
        tenant: TenantId | None = None,
        idempotency_key: str | None = None,
    ) -> IngestResponse:
        """Ingest a `Signal` event.

        Signals are the most common agent-side input: an observation
        about the world that doesn't yet have a structural commitment.
        Sensors emit them; agents emit them; reflexes can fire on them.

        Args:
            name: short identifier, e.g. `"cloudtrail/CreateBucket"`.
            source: the `NodeId` that emitted the signal — usually
                the sensor or agent node.
            payload: free-form structured detail (default `{}`).
            tenant: per-call tenant override.
            idempotency_key: when set, the engine short-circuits a
                duplicate ingest with the same key (returns the
                original cascade events).
        """
        event_kind: dict[str, Any] = {
            "Signal": {
                "source": source,
                "name": name,
                "payload": payload or {},
            }
        }
        return await self._ingest(event_kind, tenant=tenant, idempotency_key=idempotency_key)

    async def propose_claim(
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
        """Propose a new claim. Wraps `EventKind::ClaimProposed`.

        Use `ClaimSubject.dataset("...")` (and siblings) to construct
        the `subject` argument; same for `object` via `ClaimObject`.
        The engine accepts the claim with whatever id you supply —
        callers generate ULIDs/UUIDs themselves (Rule #11: the SDK
        does not auto-generate identities).

        `caused_by` is the upstream `EventId` this claim was formed in
        response to — typically the signal event whose evidence
        motivated this belief. Setting it lets
        `hy.lineage(seed_event_id)` surface this claim in the chain.
        """
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
        return await self._ingest(event_kind, tenant=tenant, idempotency_key=idempotency_key)

    async def add_evidence(
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
        """Add an `Evidence` record. Wraps `EventKind::EvidenceAdded`.

        Use `EvidenceSource.warehouse(...)` / `.api(...)` / `.human(...)`
        / `.agent(...)` / `.document(...)` / `.system(...)` to construct
        the `source` argument.

        `caused_by` is the upstream `EventId` this evidence ties back
        to — typically the signal event that motivated recording it.
        Setting it lets `hy.lineage(seed_event_id)` discover this
        evidence record during enrichment.
        """
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
        return await self._ingest(event_kind, tenant=tenant, idempotency_key=idempotency_key)

    async def propose_action(
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
        """Propose a new `Action`. Wraps `EventKind::ActionProposed`.

        `kind`: either a PascalCase string (`"Quarantine"`,
        `"Backfill"`) or a dict for `Custom("...")`:
        `{"Custom": "my_custom_action"}`. The variants are
        `Notify`, `CreateTicket`, `AssignOwner`, `RequestEvidence`,
        `Quarantine`, `Backfill`, `Repair`, `Approve`, `Reject`,
        `ExecuteWorkflow`, `PostLedgerEntry`, `RunPayroll`, plus
        `Custom(String)`.

        `targets`: list of `ActionTarget.node("...")` /
        `ActionTarget.dataset("...")` etc.

        `caused_by` is the upstream `EventId` this action was proposed
        in response to — typically the signal event whose claim
        motivated this remediation. Setting it lets
        `hy.lineage(seed_event_id)` surface this action in the chain.
        """
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
        return await self._ingest(event_kind, tenant=tenant, idempotency_key=idempotency_key)

    # ========================================================================
    # Patch 6 — operator approval workflow
    # ========================================================================

    async def approve_action(
        self,
        action_id: ActionId,
        *,
        actor: ActorId,
        reason: str | None = None,
        tenant: TenantId | None = None,
    ) -> ActionTransitionResponse:
        """Approve a proposed action — `POST /actions/{id}/approve`.

        The first human governance gate (MicroModel Patch 6). Flips
        the action's status to `Approved` and records the operator
        + reason in the audit log. v0 does NOT enforce terminal
        states: a second approve on an Approved action returns 200
        with `previous_status == "approved"`, letting the caller
        detect idempotent flips.

        `reason` is optional on approve (audit-only when present;
        the engine does not yet project it onto `Action.payload`).
        Unknown `action_id` → `HydraNotFoundError` (404).
        """
        body: dict[str, Any] = {"actor": actor}
        if reason is not None:
            body["reason"] = reason
        raw = await self._http.post(
            _paths.action_approve_path(action_id),
            json=body,
            tenant=tenant,
        )
        return ActionTransitionResponse.model_validate(raw)

    async def reject_action(
        self,
        action_id: ActionId,
        *,
        actor: ActorId,
        reason: str,
        tenant: TenantId | None = None,
    ) -> ActionTransitionResponse:
        """Reject a proposed action — `POST /actions/{id}/reject`.

        `reason` is **required** — load-bearing for the audit log
        and future outcome learning. Symmetry with `approve_action`
        is intentional; the asymmetric reason requirement is the
        engine contract. Unknown `action_id` → `HydraNotFoundError`.
        """
        body = {"actor": actor, "reason": reason}
        raw = await self._http.post(
            _paths.action_reject_path(action_id),
            json=body,
            tenant=tenant,
        )
        return ActionTransitionResponse.model_validate(raw)

    # ========================================================================
    # Patch 7 — operator-triggered Notify execution stub
    # ========================================================================

    async def execute_action(
        self,
        action_id: ActionId,
        *,
        actor: ActorId,
        tenant: TenantId | None = None,
    ) -> ActionExecutionResponse:
        """Execute an Approved Notify action — `POST /actions/{id}/execute`.

        v0 is a STUB. No webhook is called, no Slack message is sent.
        The engine walks the action through `Executing → Executed`
        and records an `OutcomeObserved` with kind
        `"notification_recorded"`. The returned envelope carries
        the outcome id so callers can fetch the full outcome
        without a follow-up query.

        Strict preconditions enforced by the engine:
          - action.kind must be `Notify` (other kinds → 400)
          - action.status must be `Approved` (other states → 400)
          - action_id must exist (404 otherwise)

        The SDK method is named `execute_action` (not
        `execute_notify_action`) because Patch 7B will add real
        delivery and Patch 8+ may broaden execution to other kinds
        — the signature is stable across that evolution.
        """
        body = {"actor": actor}
        raw = await self._http.post(
            _paths.action_execute_path(action_id),
            json=body,
            tenant=tenant,
        )
        return ActionExecutionResponse.model_validate(raw)

    # ========================================================================
    # Trust Patch 2 (Patch 10) — read-only trust assessment
    # ========================================================================

    async def auto_execute_action_if_trusted(
        self,
        action_id: ActionId,
        *,
        actor: ActorId,
        min_trust_score: float = 0.80,
        tenant: TenantId | None = None,
    ) -> AutoExecutionDecision:
        """Trust-gated auto-execution (Trust Patch 3 / Patch 11) —
        `POST /actions/{action_id}/auto-execute`.

        Hydra reads the action's claim trust; if `level == High`
        AND `score >= min_trust_score`, it fires the underlying
        execute path. Otherwise returns a decision envelope with
        `executed=false` and the trust assessment so callers
        understand WHY.

        v0 boundary:
          - Notify-kind ONLY. Other kinds → 400.
          - `status == Approved` required (manual operator approval
            is NOT skipped — Patch 11 only auto-EXECUTES). Other
            statuses → 200 with `executed=false` (decision skip).
          - Single related_claim. Multi-claim aggregation is a
            future patch.

        Default `min_trust_score=0.80` matches Patch 9's High
        threshold; operators can pass a stricter value (e.g.
        `0.95`) for higher-blast-radius actions even though Patch
        11 itself only runs on Notify.

        Errors:
          - 400 → `HydraValidationError`: wrong kind (hard contract)
          - 404 → `HydraNotFoundError`: unknown action_id
          - All other outcomes (low trust, wrong status, no
            related claim) return 200 with `executed=false`
            and an explanatory `reason`.
        """
        body: dict[str, Any] = {
            "actor": actor,
            "min_trust_score": min_trust_score,
        }
        raw = await self._http.post(
            _paths.action_auto_execute_path(action_id),
            json=body,
            tenant=tenant,
        )
        return AutoExecutionDecision.model_validate(raw)

    async def auto_approve_action_if_trusted(
        self,
        action_id: ActionId,
        *,
        actor: ActorId,
        min_trust_score: float = 0.90,
        tenant: TenantId | None = None,
    ) -> AutoApprovalDecision:
        """Trust-gated auto-approval (Trust Patch 7 / Patch 15) —
        `POST /actions/{action_id}/auto-approve`.

        Hydra reads the action's claim trust; if `level == High`
        AND `score >= min_trust_score` AND the model has at least
        one prior operator-approved action AND no hard-block
        factor applied, it ingests `ActionApproved` stamped with
        the trust-gate actor (`actor_hydra_trust_gate`).
        Otherwise returns a decision envelope with
        `approved=false` and the trust assessment so callers
        understand WHY.

        Patch 15 is the FIRST automation that bypasses the
        explicit human approval gate — so defaults are
        conservative. Default `min_trust_score=0.90` is stricter
        than Patch 11's auto-execute (0.80) because approval is
        the human-on-the-loop step.

        v0 boundary:
          - Notify-kind ONLY. Other kinds → 400.
          - `status == Proposed` required. Other statuses → 200
            with `approved=false` (decision skip).
          - At least one related_claim is required.
          - Auto-approval ONLY — does NOT auto-execute. Operators
            wanting auto-approve-then-execute call the Patch 11
            auto-execute endpoint on the resulting Approved
            action.

        Hard-block factors that veto regardless of score:
          - `contradicting_evidence`
          - `claim_disputed`
          - `claim_retracted`
          - `model_operator_rejected_historically`

        Errors:
          - 400 → `HydraValidationError`: wrong kind (hard contract)
          - 404 → `HydraNotFoundError`: unknown action_id
          - All other outcomes (low trust, wrong status, hard-block
            factor, no operator history) return 200 with
            `approved=false` and an explanatory `reason`.
        """
        body: dict[str, Any] = {
            "actor": actor,
            "min_trust_score": min_trust_score,
        }
        raw = await self._http.post(
            _paths.action_auto_approve_path(action_id),
            json=body,
            tenant=tenant,
        )
        return AutoApprovalDecision.model_validate(raw)

    async def assess_claim_trust(
        self,
        claim_id: ClaimId,
        *,
        tenant: TenantId | None = None,
    ) -> TrustAssessment:
        """Read the trust assessment for one claim
        (`GET /trust/claims/{claim_id}`).

        Walks the audit chain (Patches 3–8) and returns a
        deterministic, rule-based `TrustAssessment` with `score`,
        `level`, `explanation`, and the full factor list (including
        `applied=false` factors). Read-only — the engine method
        emits no events.

        Strict tenant isolation: the route requires `X-Hydra-Tenant`
        (the SDK propagates it automatically). A claim that exists
        but belongs to a different tenant surfaces as
        `HydraNotFoundError`, indistinguishable from a missing id
        — by design, so trust queries can't probe across tenants.

        Errors:
          - 400 → `HydraValidationError`: missing tenant header
          - 404 → `HydraNotFoundError`: unknown claim id OR wrong tenant

        Top-level method (not under `hy.diagnostics` or `hy.trust`)
        for v0. Future patches may regroup once `/trust/sources`,
        `/trust/datasets` etc. land.
        """
        raw = await self._http.get(
            _paths.trust_claim_path(claim_id),
            tenant=tenant,
        )
        return TrustAssessment.model_validate(raw)

    async def assess_causal_cell_trust(
        self,
        cell_id: CausalCellId,
        *,
        tenant: TenantId | None = None,
    ) -> CausalCellTrustAssessment:
        """Read the trust assessment for one CausalCell
        (`GET /trust/cells/{cell_id}` — Patch 24).

        Folds Patch 23's 12-factor cell trust over the cell + its
        direct children. For composed cells, the base score is
        the arithmetic mean of known direct-child `trust_score`
        values; for leaf cells, the cell's OWN `trust_score`
        acts as the single "child" for averaging. Modifiers
        from the 12-factor table (outcomes recorded, observations
        present, executed actions, failed outcomes, rejected
        actions, contradicting claims, etc.) push the score up
        or down; the result is clamped to `[0.0, 1.0]` and
        bucketed into `TrustLevel`.

        Read-only — the engine method emits no events; the
        cell's stored `trust_score` (set by Patch 22's naïve
        mean at composition time) is NOT updated.

        Strict tenant isolation: requires `X-Hydra-Tenant`
        (propagated automatically). A cell that exists but
        belongs to a different tenant — OR a `None`-tenanted
        (system-wide) cell queried with a tenant header — both
        surface as `HydraNotFoundError`, indistinguishable from
        a missing id.

        Errors:
          - 400 → `HydraValidationError`: missing tenant header
          - 404 → `HydraNotFoundError`: unknown cell, wrong
            tenant, or `None`-tenanted cell under a tenanted
            query
          - 500 → defensive: composed cell with a dangling
            child id (indicates store corruption — Patch 22
            normally prevents this at create time)

        Top-level method (not under `hy.diagnostics` or
        `hy.trust`) for v0, matching `assess_claim_trust`.
        """
        raw = await self._http.get(
            _paths.trust_cell_path(cell_id),
            tenant=tenant,
        )
        return CausalCellTrustAssessment.model_validate(raw)

    async def causal_cell(
        self,
        cell_id: CausalCellId,
        *,
        tenant: TenantId | None = None,
    ) -> CausalCell:
        """Read one CausalCell by id (`GET /causal-cells/{cell_id}` —
        Patch 25).

        Returns the typed `CausalCell` (fractal-layer composition
        primitive) without any trust folding — for trust use
        `assess_causal_cell_trust`. The two surfaces are
        intentionally separate: cells under `/causal-cells/*`,
        trust under `/trust/cells/*`.

        Strict tenant isolation: requires `X-Hydra-Tenant`
        (propagated automatically). A cell that belongs to a
        different tenant — OR a `None`-tenanted (system) cell
        queried with a tenant header — surfaces as
        `HydraNotFoundError`, indistinguishable from a missing
        id by design.

        Errors:
          - 400 → `HydraValidationError`: missing tenant header
          - 404 → `HydraNotFoundError`: unknown id, wrong tenant,
            or `None`-tenanted cell under a tenanted query
        """
        raw = await self._http.get(
            _paths.causal_cell_path(cell_id),
            tenant=tenant,
        )
        return CausalCell.model_validate(raw["cell"])

    async def causal_cells(
        self,
        *,
        kind: CausalCellKind | None = None,
        limit: int | None = None,
        after: str | None = None,
        tenant: TenantId | None = None,
    ) -> list[CausalCell]:
        """List CausalCells for the caller's tenant
        (`GET /causal-cells` — Patch 25).

        Two modes (mutually exclusive in v0):

          - **Paginated unfiltered** (`kind=None`): cursor-based
            page over all of the caller's tenant cells, sorted by
            id. `limit` defaults to 100 server-side, capped at
            500. `after` walks the cursor returned by a previous
            call. v0 returns the page items as a `list[CausalCell]`
            — the cursor lives on the wire as `next_cursor` but
            is NOT surfaced through this convenience method.
            Callers that need cursor chaining call
            `/causal-cells` directly via `httpx` or wait for the
            future `Page[CausalCell]` helper.

          - **Filtered by kind** (`kind="reflex"` etc.): returns
            the full filtered set, unpaginated. Built-in kind
            labels are snake_case (`"reflex"`, `"health"`,
            `"incident"`, `"dataset"`, `"agent"`, `"workflow"`,
            `"source"`, `"tenant"`, `"case"`); any other non-
            empty string is treated as `Custom(label)` server-
            side. Unknown labels return an empty list, NOT 400.

        `None`-tenanted (system) cells are NEVER included.

        Errors:
          - 400 → `HydraValidationError`: missing tenant header
            OR an unknown `after` cursor (mirrors the rest of
            the cursor API — silent empty would mask client bugs)
        """
        # The kind arg accepts either the union form (str |
        # dict[str, str]) for symmetry with the wire type, or a
        # plain snake_case label. Custom kinds on the wire are
        # `{"Custom": "label"}` but the URL query param wants
        # the label directly — extract it when a dict is passed.
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
        raw = await self._http.get(
            _paths.causal_cells_list_path(),
            params=params if params else None,
            tenant=tenant,
        )
        return [CausalCell.model_validate(c) for c in raw["cells"]]

    async def compose_hydra_health_cell(
        self,
        *,
        actor: ActorId,
        tenant: TenantId | None = None,
    ) -> CausalCell:
        """Compose the canonical `hydra.health` parent cell
        (`POST /causal-cells/hydra-health/compose` — Patch 27).

        Walks the calling tenant's stored `Reflex`-kind cells,
        picks the LATEST cell per built-in self-health subject
        (commit-rate, replication-lag, agent-loop-storm,
        action-failure-rate), and composes them into a single
        `Health`-kind cell with `subject = "hydra.health"`.

        Partial composition is OK: 1–4 self-health subjects
        present → returns the composed cell with a summary
        listing present + missing subjects. ZERO found → 404
        (`HydraNotFoundError`).

        Strict tenant scoping: requires `X-Hydra-Tenant`
        (propagated automatically). Only THIS tenant's reflex
        cells participate; `None`-tenanted (system) reflex
        cells are INVISIBLE to this route — a system-wide
        admin composer is a future patch.

        ## Trust

        The returned `cell.trust_score` is Patch 22's arithmetic
        mean of children's stored scores (cheap). For the
        richer 12-factor folding (P23), call
        `assess_causal_cell_trust(cell.id)` after composing —
        same surface shape as claim trust.

        ## Precondition

        The reflex pipeline does NOT auto-create reflex cells
        today (Patch 28 will). A fresh tenant calling this
        method immediately gets `HydraNotFoundError` until
        something seeds reflex cells. The error body echoes
        the engine's precondition message naming the tenant +
        expected subjects.

        Errors:
          - 400 → `HydraValidationError`: missing tenant header
          - 404 → `HydraNotFoundError`: no self-health reflex
            cells found for the tenant
        """
        body = {"actor": str(actor)}
        raw = await self._http.post(
            _paths.compose_hydra_health_cell_path(),
            json=body,
            tenant=tenant,
        )
        return CausalCell.model_validate(raw["cell"])

    # ========================================================================
    # Identity Graph (Patch 31)
    # ========================================================================

    async def create_identity_entity(
        self,
        entity: IdentityEntity,
        *,
        tenant: TenantId | None = None,
    ) -> IdentityEntity:
        """Create a canonical `IdentityEntity` (Patch 29 vocab,
        Patch 31 wire) via `POST /identity/entities`.

        The caller fully populates the entity — `id`, timestamps,
        aliases, etc. The server overwrites `entity.tenant_id`
        with the `X-Hydra-Tenant` header value (anti-smuggling
        rule) so the persisted entity always belongs to the
        calling tenant regardless of what the body says.

        Errors:
          - 400 → `HydraValidationError`: duplicate alias,
            duplicate canonical_key, reserved sentinel in alias
            source/namespace, empty alias source/normalized,
            missing tenant header.
        """
        body = {"entity": entity.model_dump(mode="json")}
        raw = await self._http.post(
            _paths.identity_entities_path(),
            json=body,
            tenant=tenant,
        )
        return IdentityEntity.model_validate(raw["entity"])

    async def identity_entity(
        self,
        entity_id: IdentityEntityId,
        *,
        tenant: TenantId | None = None,
    ) -> IdentityEntity:
        """Look up one `IdentityEntity` by id (`GET /identity/entities/{id}`).

        Strict tenant scoping (mirrors the Patch 29 store
        contract): wrong-tenant AND `None`-tenanted (system)
        entities surface identically as `HydraNotFoundError`.
        No cross-tenant probing.

        Errors:
          - 400 → `HydraValidationError`: missing tenant header
          - 404 → `HydraNotFoundError`: unknown id, wrong tenant,
            or `None`-tenanted entity under a tenanted query
        """
        raw = await self._http.get(
            _paths.identity_entity_path(entity_id),
            tenant=tenant,
        )
        return IdentityEntity.model_validate(raw["entity"])

    async def identity_entities(
        self,
        *,
        kind: IdentityEntityKind | None = None,
        limit: int | None = None,
        after: str | None = None,
        tenant: TenantId | None = None,
    ) -> list[IdentityEntity]:
        """List `IdentityEntity`s for the caller's tenant
        (`GET /identity/entities`).

        Two modes:

          - **Paginated unfiltered** (`kind=None`): cursor-based
            over all tenant entities sorted by id. `limit`
            defaults to 100 server-side, capped at 500. v0
            returns the page items only; `next_cursor` lives on
            the wire but isn't surfaced through this convenience
            method.

          - **Filtered by kind** (`kind="dataset"` etc.): returns
            the full filtered set, unpaginated. Built-in kind
            labels are snake_case
            (`"dataset"`, `"table"`, `"dashboard"`, `"metric"`,
            `"service"`, `"agent"`, `"workflow"`, `"source"`,
            `"user"`, `"system"`, `"incident"`); any other
            non-empty string maps to `Custom(label)`
            server-side. Unknown labels return an empty list,
            NOT 400.

        `None`-tenanted entities are NEVER included.
        """
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
        raw = await self._http.get(
            _paths.identity_entities_path(),
            params=params if params else None,
            tenant=tenant,
        )
        return [
            IdentityEntity.model_validate(e) for e in raw["entities"]
        ]

    async def suggest_identity_matches(
        self,
        *,
        source: str,
        normalized: str,
        namespace: str | None = None,
        kind: IdentityEntityKind | None = None,
        limit: int = 10,
        tenant: TenantId | None = None,
    ) -> SemanticIdentityMatchAssessment:
        """Suggest canonical `IdentityEntity`s that the
        `(source, namespace, normalized)` triple probably refers
        to (`GET /identity/matches` — Patch 30 engine, Patch 31
        wire).

        Read-only and deterministic. Returns
        `SemanticIdentityMatchAssessment` with candidates sorted
        by score desc, entity_id asc. Zero-score candidates are
        excluded server-side. `MatchLevel` on each candidate is
        `"Strong"` / `"Possible"` / `"Weak"` / `"None"` —
        the `"None"` value is a STRING (no match), distinct
        from Python `None`.

        ## Suggestion-only contract

        The deterministic weights are calibrated for
        **explainability, NOT guaranteed correctness**. False
        positives are expected (e.g., `revenue_daily` matching
        `revenue_daily_archived` via token_overlap_high). Any
        auto-action based on these scores must add a separate
        trust gate, gate on `level == "Strong"`, and require a
        minimum score floor.

        Strict tenant scoping: `None`-tenanted entities are
        invisible. Missing tenant header → 400.
        """
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
        raw = await self._http.get(
            _paths.identity_matches_path(),
            params=params,
            tenant=tenant,
        )
        return SemanticIdentityMatchAssessment.model_validate(
            raw["assessment"]
        )

    # ========================================================================
    # IdentityLink (Patch 38 — wire surface over P37 vocabulary)
    # ========================================================================

    async def create_identity_link(
        self,
        link: IdentityLink,
        *,
        tenant: TenantId | None = None,
    ) -> IdentityLink:
        """Create a durable directed `IdentityLink` between two
        `IdentityEntity`s (`POST /identity/links` — Patch 38).

        The server OVERWRITES `link.tenant_id` with the
        `X-Hydra-Tenant` header value — caller cannot smuggle a
        different tenant or `None` via the body. All other
        fields (`id`, `created_by`, `created_at`, `caused_by`,
        evidence/claim/cell ids, metadata) pass through as
        supplied.

        ## Strategic warning (P37 carry-forward)

        IdentityLink is a DURABLE assertion. v0 has NO trust
        verdict over the link itself; `confidence` is
        informational only. **Auto-actions MUST gate on a future
        `IdentityLinkTrustAssessment` (P39+), NOT raw confidence.**
        There is NO update or delete in v0 — wrong links are
        corrected by creating new links; the wrong link remains
        in the audit log forever. NO referential integrity on
        evidence/claim/cell ids; NO cycle prevention; NO graph
        projection.

        Errors:
          - 400 → `HydraValidationError`: missing tenant header,
            self-link (from == to), invalid kind (empty Custom /
            sentinel Custom / built-in-collision Custom),
            duplicate `(tenant, from, to, kind)`, duplicate link
            id
          - 404 → `HydraNotFoundError`: unknown from/to entity,
            wrong-tenant entity, OR `None`-tenanted entity
            (unified error per P37 — no cross-tenant existence
            leak)
        """
        body = {"link": link.model_dump(mode="json")}
        raw = await self._http.post(
            _paths.identity_links_path(),
            json=body,
            tenant=tenant,
        )
        return IdentityLink.model_validate(raw["link"])

    async def identity_link(
        self,
        link_id: IdentityLinkId,
        *,
        tenant: TenantId | None = None,
    ) -> IdentityLink:
        """Read one `IdentityLink` by id
        (`GET /identity/links/{link_id}` — Patch 38).

        Strict tenant scoping: unknown id, wrong tenant, OR
        `None`-tenanted link all surface as `HydraNotFoundError`
        — indistinguishable by design.
        """
        raw = await self._http.get(
            _paths.identity_link_path(link_id),
            tenant=tenant,
        )
        return IdentityLink.model_validate(raw["link"])

    async def identity_links(
        self,
        *,
        from_entity_id: IdentityEntityId | None = None,
        to_entity_id: IdentityEntityId | None = None,
        kind: IdentityLinkKind | None = None,
        after: str | None = None,
        limit: int | None = None,
        tenant: TenantId | None = None,
    ) -> tuple[list[IdentityLink], str | None]:
        """List identity links for the caller's tenant, optionally
        filtered (`GET /identity/links` — Patch 38). Returns
        `(links, next_cursor)`; `next_cursor` is the raw
        `IdentityLinkId` of the last item when more pages exist,
        or `None` on the final page.

        All filters optional. With no filter args, returns all
        tenant links paginated under the server-side default
        page size.

        `kind` accepts either a PascalCase string
        (`"DownstreamOf"`) or the dict form (`{"Custom":
        "uses_metric"}`); the SDK extracts the snake_case
        discriminant for the URL via `_link_kind_param`. **Note
        the wart**: `"DownstreamOf"` becomes
        `Custom("DownstreamOf")` server-side and almost always
        returns empty — use `"downstream_of"` (snake_case) to
        filter for the `DownstreamOf` built-in.

        Strict tenant scoping: `None`-tenanted links never
        appear in results.
        """
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
        raw = await self._http.get(
            _paths.identity_links_path(),
            params=params if params else None,
            tenant=tenant,
        )
        links = [IdentityLink.model_validate(l) for l in raw["links"]]
        return links, raw.get("next_cursor")

    async def identity_links_for_entity(
        self,
        entity_id: IdentityEntityId,
        *,
        kind: IdentityLinkKind | None = None,
        after: str | None = None,
        limit: int | None = None,
        tenant: TenantId | None = None,
    ) -> tuple[list[IdentityLink], str | None]:
        """List all links touching `entity_id` (incoming AND
        outgoing) for the caller's tenant
        (`GET /identity/entities/{entity_id}/links` — Patch 38).
        Returns `(links, next_cursor)`.

        Tenant probe happens server-side BEFORE link listing: if
        the entity doesn't exist OR belongs to a different tenant
        OR is `None`-tenanted → 404 `HydraNotFoundError`. This
        prevents wrong-tenant entity-id enumeration through link
        counts.
        """
        params: dict[str, str | int] = {}
        kp = _link_kind_param(kind)
        if kp is not None:
            params["kind"] = kp
        if after is not None:
            params["after"] = after
        if limit is not None:
            params["limit"] = limit
        raw = await self._http.get(
            _paths.identity_entity_links_path(entity_id),
            params=params if params else None,
            tenant=tenant,
        )
        links = [IdentityLink.model_validate(l) for l in raw["links"]]
        return links, raw.get("next_cursor")

    # ========================================================================
    # Identity trust (Patch 34 — wire surface over P32 + P33)
    # ========================================================================

    async def assess_identity_entity_trust(
        self,
        entity_id: IdentityEntityId,
        *,
        tenant: TenantId | None = None,
    ) -> IdentityEntityTrustAssessment:
        """Read the Patch 33 trust verdict over a canonical
        `IdentityEntity` (`GET /trust/identity/entities/{id}` —
        Patch 34 wire).

        Returns the typed envelope with `score`, `level`
        (`TrustLevel`), `explanation`, and all 12 P33 factor
        records. Strict tenant scoping: requires
        `X-Hydra-Tenant` (propagated automatically); unknown
        id, wrong tenant, OR `None`-tenanted entity under a
        tenanted query all surface as `HydraNotFoundError` —
        indistinguishable by design (no cross-tenant existence
        leak).

        ## Suggestion-only contract

        Trust verdict judges the IDENTITY RECORD ITSELF, not
        operational truth. A High verdict means "well-formed
        and consistent with P29 invariants"; it does NOT mean
        "every operational fact about this entity is
        trustworthy." Auto-actions based on entity trust must
        gate on `level == "High"` + minimum score floor + emit
        a separate audit event.

        Errors:
          - 400 → `HydraValidationError`: missing tenant header
          - 404 → `HydraNotFoundError`: unknown id, wrong
            tenant, or `None`-tenanted entity under a tenanted
            query
        """
        raw = await self._http.get(
            _paths.trust_identity_entity_path(entity_id),
            tenant=tenant,
        )
        return IdentityEntityTrustAssessment.model_validate(raw)

    async def assess_identity_match_trust(
        self,
        *,
        source: str,
        normalized: str,
        candidate_entity_id: IdentityEntityId,
        namespace: str | None = None,
        kind: IdentityEntityKind | None = None,
        tenant: TenantId | None = None,
    ) -> IdentityMatchTrustAssessment:
        """Read the Patch 32 trust verdict over a single (query
        alias → candidate entity) pair
        (`GET /trust/identity/matches` — Patch 34 wire).

        Required kwargs:
          - `source` — alias source (e.g. `"snowflake"`)
          - `normalized` — alias normalized form
          - `candidate_entity_id` — the entity being judged
            against

        Optional kwargs:
          - `namespace` — alias namespace (`None` matches the
            `None`-namespace slot per P29 sentinel design)
          - `kind` — optional kind hint (snake_case discriminant
            or `{"Custom": "label"}`); empty → 400
          - `tenant` — per-call override for `X-Hydra-Tenant`

        Returns the typed envelope carrying BOTH axes:
          - `match_score` / `match_level` — P30 similarity.
            `MatchLevel` is one of `"Strong"` / `"Possible"` /
            `"Weak"` / `"None"`. **NOTE**: `"None"` is a STRING
            literal (no match), NOT Python's `None`. The field
            is always populated.
          - `score` / `level` — P32 trust verdict over the
            match. `level` is `TrustLevel`
            (High/Medium/Low/Unknown).

        These axes are independent. A Strong match can be Low
        trust (e.g., alias conflict drags the verdict down).
        Don't conflate them.

        ## Suggestion-only contract

        Identity match trust is calibrated for explainability,
        NOT correctness. False positives expected. Any
        auto-link MUST add a separate gate, require
        `level == "High"`, require a minimum score floor, AND
        emit a durable `IdentityLink` event for audit. P34
        does NONE of those — it only exposes the verdict.

        Errors:
          - 400 → `HydraValidationError`: missing tenant header,
            missing required query param, empty `kind`
          - 404 → `HydraNotFoundError`: unknown candidate /
            wrong tenant / `None`-tenanted candidate
        """
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
        raw = await self._http.get(
            _paths.trust_identity_matches_path(),
            params=params,
            tenant=tenant,
        )
        return IdentityMatchTrustAssessment.model_validate(raw)

    # ========================================================================
    # Source trust (Patch 36 — wire surface over P35)
    # ========================================================================

    async def assess_source_trust(
        self,
        source: str,
        *,
        tenant: TenantId | None = None,
    ) -> SourceTrustAssessment:
        """Read the Patch 35 trust verdict over a free-form source
        string (`GET /trust/identity/sources/{source}` — Patch 36
        wire).

        Asks: **do I trust this source as a producer of identity /
        evidence signals?** Identity-backed in v1; the verdict
        folds the source's entities (P33 mean trust mutex on
        ≥0.70 / ≤0.40) and clean-mapped evidence reliability
        (Warehouse.system / Api.system / System.name).

        **v1 does NOT measure operational health** — freshness,
        heartbeat, schema drift, SLA conformance, contradiction
        rate are out of scope. A dead Snowflake warehouse with
        five trustworthy historical entities will score `"High"`
        here; that's correct for "did Snowflake produce
        trustworthy identity claims," wrong for "is Snowflake
        alive." Operational signals layer on when connector
        primitives ship in later patches.

        Args:
          - `source` — the source string under judgement. Compared
            verbatim against `IdentityAlias.source` — no
            normalization, no case-folding (`"snowflake"` and
            `"Snowflake"` are distinct sources). URL-encoded
            automatically for sources containing `/` or other
            URL-special characters.
          - `tenant` — per-call override for `X-Hydra-Tenant`.

        Returns a typed `SourceTrustAssessment`:
          - `score` / `level` — overall verdict (`TrustLevel`)
          - `factors` — all 9 P35 records (applied AND unapplied)
          - `related_entity_ids` — entity ids that contributed
            (sorted by id ascending)
          - `entity_sample_size` / `evidence_sample_size` — for
            cap transparency

        Error mapping:
          - 400 → `HydraValidationError`: missing tenant header,
            empty source, reserved sentinel source (`__system__`,
            `__root__`)
          - 200 with `level="Unknown"`: well-formed source with
            no aliases / no evidence in tenant scope. **This is
            NOT a 404.** Empty-result is a legitimate verdict per
            P35's contract. None-tenanted source data probed by a
            tenanted caller also returns 200 with the empty
            verdict (strict tenant isolation surfaced as "no data
            visible," not "not found").

        ## Suggestion-only contract

        Weights are calibrated for **explainability, NOT
        correctness**. False positives are expected. This method
        is read-only and MUST NOT drive auto-actions. Any future
        gate must add a separate trust contract, require
        `level == "High"`, impose a minimum score floor, and emit
        a durable audit event.
        """
        raw = await self._http.get(
            _paths.trust_identity_source_path(source),
            tenant=tenant,
        )
        return SourceTrustAssessment.model_validate(raw)

    async def _ingest(
        self,
        event_kind: dict[str, Any],
        *,
        tenant: TenantId | None,
        idempotency_key: str | None,
    ) -> IngestResponse:
        """Centralized POST /ingest call. Public ingest helpers all
        funnel here so the request envelope + idempotency-key handling
        lives in one place."""
        extra_headers: dict[str, str] | None = None
        if idempotency_key is not None:
            extra_headers = {IDEMPOTENCY_KEY_HEADER: idempotency_key}
        body = {"event_kind": event_kind}
        raw = await self._http.post(
            _paths.ingest_path(),
            json=body,
            tenant=tenant,
            extra_headers=extra_headers,
        )
        return IngestResponse.model_validate(raw)

    # ========================================================================
    # Query methods (Rule #1 — semantic verbs)
    # ========================================================================

    async def get_node(self, node_id: NodeId, *, tenant: TenantId | None = None) -> Node:
        raw = await self._http.get(_paths.query_node_path(node_id), tenant=tenant)
        return Node.model_validate(raw["node"])

    async def get_edge(self, edge_id: EdgeId, *, tenant: TenantId | None = None) -> Edge:
        raw = await self._http.get(_paths.query_edge_path(edge_id), tenant=tenant)
        return Edge.model_validate(raw["edge"])

    async def get_event(self, event_id: EventId, *, tenant: TenantId | None = None) -> Event:
        """Get a single event by id.

        Note: `/events/:event_id` is under the events router (auth
        scope `read:audit`), not `/query/*` (which would be
        `read:query`). The SDK abstracts the distinction; callers
        just need their token to carry `read:audit`.
        """
        raw = await self._http.get(_paths.event_path(event_id), tenant=tenant)
        return Event.model_validate(raw["event"])

    async def get_claim(self, claim_id: ClaimId, *, tenant: TenantId | None = None) -> Claim:
        raw = await self._http.get(_paths.query_claim_path(claim_id), tenant=tenant)
        return Claim.model_validate(raw["claim"])

    async def get_evidence(
        self, evidence_id: EvidenceId, *, tenant: TenantId | None = None
    ) -> Evidence:
        raw = await self._http.get(_paths.query_evidence_path(evidence_id), tenant=tenant)
        return Evidence.model_validate(raw["evidence"])

    async def get_action(self, action_id: ActionId, *, tenant: TenantId | None = None) -> Action:
        raw = await self._http.get(_paths.query_action_path(action_id), tenant=tenant)
        return Action.model_validate(raw["action"])

    async def list_claims(
        self,
        *,
        status: ClaimStatus | None = None,
        kind: ClaimKind | None = None,
        tenant: TenantId | None = None,
    ) -> list[Claim]:
        """List claims.

        Three modes (mutually exclusive):
          - No filter → paginated `/query/claims` (first page only
            in v0; pagination is Patch 5)
          - `status=...` → filtered `/query/claims/status/:status`
          - `kind=...` → filtered `/query/claims/kind/:kind`

        Passing both `status` and `kind` raises `ValueError`.
        """
        if status is not None and kind is not None:
            raise ValueError(
                "list_claims accepts at most one of `status`/`kind`; "
                "filter combinations are not supported by the engine in v0"
            )
        if status is not None:
            path = _paths.query_claims_by_status_path(status)
            raw = await self._http.get(path, tenant=tenant)
            return [Claim.model_validate(c) for c in raw["claims"]]
        if kind is not None:
            path = _paths.query_claims_by_kind_path(kind)
            raw = await self._http.get(path, tenant=tenant)
            return [Claim.model_validate(c) for c in raw["claims"]]
        # No filter — paginated `Page<Claim>` shape.
        raw = await self._http.get(_paths.query_claims_path(), tenant=tenant)
        return [Claim.model_validate(c) for c in raw["items"]]

    async def list_claims_for_subject(
        self,
        *,
        subject_kind: str,
        subject_value: str,
        tenant: TenantId | None = None,
    ) -> list[Claim]:
        """Find all claims about a given subject.

        `subject_kind` is one of `"Node"`, `"Edge"`, `"ExternalRef"`,
        `"Dataset"`, `"Metric"`, `"System"` (PascalCase — matches
        the engine's path-segment parser).
        """
        raw = await self._http.get(
            _paths.query_claims_for_subject_path(),
            params={"subject_kind": subject_kind, "subject_value": subject_value},
            tenant=tenant,
        )
        return [Claim.model_validate(c) for c in raw["claims"]]

    async def list_claims_for_evidence(
        self, evidence_id: EvidenceId, *, tenant: TenantId | None = None
    ) -> list[Claim]:
        """All claims that reference the given evidence in their
        `evidence_for` set. Read this as "what beliefs does this
        evidence support?"
        """
        raw = await self._http.get(
            _paths.query_claims_using_evidence_path(evidence_id), tenant=tenant
        )
        return [Claim.model_validate(c) for c in raw["claims"]]

    async def list_actions(
        self,
        *,
        status: ActionStatus | None = None,
        tenant: TenantId | None = None,
    ) -> list[Action]:
        """List actions, optionally filtered by status.

        Without `status`, hits the paginated `/query/actions` route
        and returns the first page (pagination is Patch 5). With
        `status`, hits `/query/actions/status/:status` (no
        pagination, full result set).
        """
        if status is not None:
            path = _paths.query_actions_by_status_path(status)
            raw = await self._http.get(path, tenant=tenant)
            return [Action.model_validate(a) for a in raw["actions"]]
        raw = await self._http.get(_paths.query_actions_path(), tenant=tenant)
        return [Action.model_validate(a) for a in raw["items"]]

    async def list_outcomes_for_action(
        self, action_id: ActionId, *, tenant: TenantId | None = None
    ) -> list[Outcome]:
        raw = await self._http.get(
            _paths.query_outcomes_for_action_path(action_id), tenant=tenant
        )
        return [Outcome.model_validate(o) for o in raw["outcomes"]]

    # ========================================================================
    # Lineage — the "why did this happen?" surface
    # ========================================================================

    async def lineage(
        self,
        event_id: EventId,
        *,
        depth: int | None = None,
        tenant: TenantId | None = None,
    ) -> LineageResponse:
        """Return the causal context around an event: ancestors, descendants, and every related evidence/claim/action/outcome/policy artifact."""
        params: dict[str, Any] = {}
        if depth is not None:
            params["depth"] = depth
        raw = await self._http.get(
            _paths.lineage_path(event_id),
            params=params or None,
            tenant=tenant,
        )
        return LineageResponse.model_validate(raw)

    # ========================================================================
    # Commit stream — the "watch forever" surface
    # ========================================================================

    async def subscribe_commits(
        self,
        *,
        after_sequence: int = 0,
        tenant: TenantId | None = None,
    ):
        """Yield committed batches as they happen, plus heartbeat /
        lag / error sentinels.

        Opens a long-lived Server-Sent-Events connection to
        `GET /commits/stream?after_sequence=N`. The engine first
        replays every in-memory commit with sequence strictly
        greater than `after_sequence`, then streams new commits as
        they land. Use `after_sequence=<last commit sequence you
        observed>` to resume cleanly across reconnects.

        Yields one of four typed items per SSE event:

          - `CommitStreamCommit(type="commit", commit=CommitBatchLite)`
            — one per committed batch. The `commit.events` list is
            already parsed into `Event` objects; `commit.raw` carries
            the full wire dict for anything the SDK doesn't yet type.
          - `CommitStreamHeartbeat(type="heartbeat", head_sequence=N)`
            — emitted every 15s so the client knows the connection
            is alive during quiet windows.
          - `CommitStreamLag(type="lag", requested_after_sequence,
            starting_at_sequence)` — at most once at the start of the
            stream, if the caller asked for sequences the engine
            can no longer replay. The stream still opens and
            continues from `starting_at_sequence`. The caller
            decides whether to reconcile via `/replication/commits`.
          - `CommitStreamError(type="error", error, hint?)` —
            terminal. The server emits this when a subscriber lags
            past the broadcast buffer (slow consumer). After this
            event the stream closes; reconnect with `after_sequence`
            set to the last commit sequence you observed.

        Usage:

            async for item in hy.subscribe_commits(after_sequence=0):
                if item.type == "commit":
                    for event in item.commit.events:
                        ...
                elif item.type == "lag":
                    # operator dashboard / re-bootstrap
                elif item.type == "error":
                    break  # connection closing
                # heartbeat is optional to handle

        Cancel by exiting the `async for` (closing the iterator
        cancels the underlying HTTP stream).

        Per Rule #7, `tenant=` overrides the client default on the
        outgoing connection, though the engine does NOT filter the
        stream by tenant — the audit view is cluster-wide and the
        client filters `event.tenant_id` itself if needed.
        """
        params: dict[str, Any] = {}
        if after_sequence > 0:
            params["after_sequence"] = after_sequence

        async for event_name, data in self._http.stream_sse(
            _paths.commits_stream_path(),
            params=params or None,
            tenant=tenant,
        ):
            item = _parse_commit_stream_item(event_name, data)
            if item is not None:
                yield item
                if isinstance(item, CommitStreamError):
                    # Server emitted a terminal error event. The
                    # underlying connection is closing; surface that
                    # to the caller by ending the iterator.
                    return


def _parse_commit_stream_item(
    event_name: str, data: str
) -> CommitStreamItem | None:
    """Translate one SSE `(event_name, data)` pair into a typed
    stream item. Unknown event names are silently skipped (forward-
    compatible with future server-side event types). Malformed
    payloads produce a `CommitStreamError` synthetic so callers see
    a single error vocabulary regardless of whether the failure was
    on the wire or in the parse."""
    import json

    try:
        payload = json.loads(data)
    except json.JSONDecodeError as exc:
        return CommitStreamError(
            error=f"failed to parse SSE data for event '{event_name}': {exc}",
            hint="this is a client-side parse error, not a server signal",
        )

    if event_name == "commit":
        return CommitStreamCommit(commit=CommitBatchLite.from_wire(payload))
    if event_name == "heartbeat":
        return CommitStreamHeartbeat.model_validate(
            {"type": "heartbeat", **payload}
        )
    if event_name == "lag":
        return CommitStreamLag.model_validate({"type": "lag", **payload})
    if event_name == "error":
        return CommitStreamError.model_validate({"type": "error", **payload})
    # Unknown event name — silently skip for forward compatibility.
    return None
