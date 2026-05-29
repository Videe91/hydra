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
)
from .diagnostics import _Diagnostics
from .replication import _Replication
from .schemas import _Schemas

IDEMPOTENCY_KEY_HEADER = "Idempotency-Key"


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
