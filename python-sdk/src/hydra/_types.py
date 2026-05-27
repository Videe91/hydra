"""Pydantic v2 models mirroring Hydra's wire format.

Design rule #2: transport DTOs mirror the wire format exactly. Field
names, casing, optionality, and discriminator shape all match
hydra-net's JSON output byte-for-byte.

## Wire-form conventions (sharp edges)

Most Hydra engine enums use Rust's serde default — externally-tagged
unit variants in **PascalCase**:
  - `ClaimStatus` → `"Proposed"`, `"Verified"`, ...
  - `ClaimKind`   → `"Fact"`, `"AnomalyFinding"`, ...
  - `ActionKind`  → `"Quarantine"`, `"PostLedgerEntry"`, ...
  - `ActionStatus`, `OutcomeKind` — same.

A small number of newer engine types opted into
`#[serde(rename_all = "snake_case")]`:
  - `AnomalyKind`, `DriftDirection`, `SubscriptionOutcome`, `RuntimeRole`.

The SDK Literal types below match each enum's actual wire form,
verified against the engine.

## Tagged unions

`ClaimSubject`, `ClaimObject`, `EvidenceSource`, `ActionTarget` are
externally-tagged Rust enums — JSON shape `{"Node": "..."}` or
`{"Warehouse": {"system": "..."}}`. Pydantic v2's discriminated-union
sugar wants internally-tagged JSON, which doesn't match. For Patch 2
these surface as `dict[str, Any]` with static constructor helpers
(`ClaimSubject.dataset("x")` → `{"Dataset": "x"}`). Patch X may
promote them to proper Pydantic models if user feedback demands.

## What's still receive-side-only

`Event.kind` is `dict[str, Any]` for now. Ingest helpers in
`client.py` construct the right shape; users never touch `EventKind`
directly. A typed discriminated `EventKind` is a future patch.
"""

from __future__ import annotations

from typing import Annotated, Any, Literal

from pydantic import BaseModel, ConfigDict, Field

# === ID newtypes ===
#
# Hydra uses prefixed ULID-sortable string IDs. We expose typed
# aliases so method signatures read clearly; at runtime they're
# plain `str`. mypy treats them as distinct enough to catch the
# common "passed a node_id where an event_id was expected" bug.

EventId = str
NodeId = str
EdgeId = str
ClaimId = str
EvidenceId = str
ActionId = str
OutcomeId = str
ActorId = str
SubscriptionId = str
TenantId = str
CascadeId = str
ReplicaId = str
PolicyId = str
PolicyDecisionId = str
ApprovalId = str
TypeId = str
CommitId = str
SnapshotId = str


# === Confidence — [0.0, 1.0] clamp ===

Confidence = Annotated[float, Field(ge=0.0, le=1.0)]


# === Enums — PascalCase wire form (Rust serde default) ===

ClaimStatus = Literal[
    "Proposed",
    "Supported",
    "Verified",
    "Operational",
    "Disputed",
    "Stale",
    "Retracted",
    "Archived",
]

ClaimKind = Literal[
    "Fact",
    "Inference",
    "Hypothesis",
    "Prediction",
    "Recommendation",
    "PolicyFinding",
    "AnomalyFinding",
    "LineageFinding",
]

ActionStatus = Literal[
    "Proposed",
    "Approved",
    "Rejected",
    "Executing",
    "Executed",
    "Failed",
    "Cancelled",
]

OutcomeKind = Literal[
    "Success",
    "Failure",
    "PartialSuccess",
    "NoEffect",
    "Regression",
    "Unknown",
]


# === Enums — snake_case wire form (engines that opted in) ===

DriftDirection = Literal["increasing", "decreasing"]
SubscriptionOutcome = Literal["confirmed", "dismissed", "auto_accepted"]
RuntimeRole = Literal["leader", "follower"]


# === Tagged-union helpers — `dict` form + static constructors ===
#
# Rust enums like `ClaimSubject::Node(NodeId)` serialize as
# `{"Node": "node_..."}` — externally-tagged. For Patch 2 we expose
# these as `dict[str, Any]` and provide ergonomic constructors so
# users don't write the dict shape by hand:
#
#   ClaimSubject.dataset("revenue_daily")
#     → {"Dataset": "revenue_daily"}
#
#   EvidenceSource.warehouse(system="snowflake", table="orders")
#     → {"Warehouse": {"system": "snowflake", "table": "orders",
#                      "database": None, "schema": None}}


class ClaimSubject:
    """Constructor helpers for `EventKind::ClaimProposed.claim.subject`.

    Each method returns the externally-tagged dict shape that the
    engine's serde expects. Users never compose this shape manually.
    """

    @staticmethod
    def node(node_id: NodeId) -> dict[str, Any]:
        return {"Node": node_id}

    @staticmethod
    def edge(edge_id: EdgeId) -> dict[str, Any]:
        return {"Edge": edge_id}

    @staticmethod
    def external_ref(ref: str) -> dict[str, Any]:
        return {"ExternalRef": ref}

    @staticmethod
    def dataset(name: str) -> dict[str, Any]:
        return {"Dataset": name}

    @staticmethod
    def metric(name: str) -> dict[str, Any]:
        return {"Metric": name}

    @staticmethod
    def system(name: str) -> dict[str, Any]:
        return {"System": name}


class ClaimObject:
    """Constructor helpers for `Claim.object`."""

    @staticmethod
    def node(node_id: NodeId) -> dict[str, Any]:
        return {"Node": node_id}

    @staticmethod
    def edge(edge_id: EdgeId) -> dict[str, Any]:
        return {"Edge": edge_id}

    @staticmethod
    def value(value: Any) -> dict[str, Any]:
        """The `Value` variant — a free JSON value (string, bool,
        number, list, dict). The engine's `hydra_core::Value` is
        polymorphic; we accept whatever the caller hands us."""
        return {"Value": value}

    @staticmethod
    def external_ref(ref: str) -> dict[str, Any]:
        return {"ExternalRef": ref}


class EvidenceSource:
    """Constructor helpers for `Evidence.source`. Each variant has
    its own struct on the engine side; we mirror the named fields."""

    @staticmethod
    def warehouse(
        *,
        system: str,
        database: str | None = None,
        schema: str | None = None,
        table: str | None = None,
    ) -> dict[str, Any]:
        return {
            "Warehouse": {
                "system": system,
                "database": database,
                "schema": schema,
                "table": table,
            }
        }

    @staticmethod
    def api(*, system: str, endpoint: str | None = None) -> dict[str, Any]:
        return {"Api": {"system": system, "endpoint": endpoint}}

    @staticmethod
    def document(uri: str) -> dict[str, Any]:
        return {"Document": {"uri": uri}}

    @staticmethod
    def human(actor_id: ActorId) -> dict[str, Any]:
        return {"Human": {"actor_id": actor_id}}

    @staticmethod
    def agent(actor_id: ActorId) -> dict[str, Any]:
        return {"Agent": {"actor_id": actor_id}}

    @staticmethod
    def system(name: str) -> dict[str, Any]:
        return {"System": {"name": name}}


class ActionTarget:
    """Constructor helpers for `Action.targets[]`."""

    @staticmethod
    def node(node_id: NodeId) -> dict[str, Any]:
        return {"Node": node_id}

    @staticmethod
    def edge(edge_id: EdgeId) -> dict[str, Any]:
        return {"Edge": edge_id}

    @staticmethod
    def claim(claim_id: ClaimId) -> dict[str, Any]:
        return {"Claim": claim_id}

    @staticmethod
    def evidence(evidence_id: EvidenceId) -> dict[str, Any]:
        return {"Evidence": evidence_id}

    @staticmethod
    def external_ref(ref: str) -> dict[str, Any]:
        return {"ExternalRef": ref}

    @staticmethod
    def dataset(name: str) -> dict[str, Any]:
        return {"Dataset": name}

    @staticmethod
    def system(name: str) -> dict[str, Any]:
        return {"System": name}


# === Wire models — Patch 2 expansion ===


class NodeMeta(BaseModel):
    """Mirrors `hydra_core::NodeMeta`."""

    model_config = ConfigDict(extra="forbid")

    id: NodeId
    type_id: str
    created_at: str
    updated_at: str
    version: int
    alive: bool
    tenant_id: TenantId | None = None


class Node(BaseModel):
    """Mirrors `hydra_core::Node`."""

    model_config = ConfigDict(extra="forbid")

    meta: NodeMeta
    properties: dict[str, Any] = Field(default_factory=dict)


class EdgeMeta(BaseModel):
    """Mirrors `hydra_core::EdgeMeta`."""

    model_config = ConfigDict(extra="forbid")

    id: EdgeId
    type_id: str
    source: NodeId
    target: NodeId
    created_at: str
    updated_at: str
    version: int
    alive: bool
    tenant_id: TenantId | None = None


class Edge(BaseModel):
    """Mirrors `hydra_core::Edge`."""

    model_config = ConfigDict(extra="forbid")

    meta: EdgeMeta
    properties: dict[str, Any] = Field(default_factory=dict)


class Event(BaseModel):
    """Mirrors `hydra_core::Event`.

    `kind` carries the externally-tagged `EventKind` variant body
    as a `dict` in Patch 2. A typed discriminated union is a future
    patch — users currently inspect `event.kind` by key.
    """

    model_config = ConfigDict(extra="forbid")

    id: EventId
    timestamp: str
    kind: dict[str, Any] | str
    caused_by: list[EventId] = Field(default_factory=list)
    cascade_id: CascadeId
    cascade_depth: int
    cascade_breadth_index: int = 0
    tenant_id: TenantId | None = None


class EvidencePayload(BaseModel):
    """Mirrors `hydra_core::EvidencePayload`."""

    model_config = ConfigDict(extra="forbid")

    kind: str
    data: dict[str, Any] = Field(default_factory=dict)


class Evidence(BaseModel):
    """Mirrors `hydra_core::Evidence`."""

    model_config = ConfigDict(extra="forbid")

    id: EvidenceId
    tenant_id: TenantId | None = None
    source: dict[str, Any]  # externally-tagged EvidenceSource
    payload: EvidencePayload
    reliability: Confidence
    observed_at: str
    recorded_at: str
    caused_by: EventId | None = None


class Claim(BaseModel):
    """Mirrors `hydra_core::Claim`."""

    model_config = ConfigDict(extra="forbid")

    id: ClaimId
    tenant_id: TenantId | None = None
    kind: ClaimKind
    subject: dict[str, Any]  # externally-tagged ClaimSubject
    predicate: str
    object: dict[str, Any]  # externally-tagged ClaimObject
    confidence: Confidence
    status: ClaimStatus
    evidence_for: list[EvidenceId] = Field(default_factory=list)
    evidence_against: list[EvidenceId] = Field(default_factory=list)
    valid_from: str
    valid_until: str | None = None
    created_by: ActorId
    created_at: str
    updated_at: str
    caused_by: EventId | None = None


class Action(BaseModel):
    """Mirrors `hydra_core::Action`."""

    model_config = ConfigDict(extra="forbid")

    id: ActionId
    tenant_id: TenantId | None = None
    kind: dict[str, Any] | str  # ActionKind: variants OR `{"Custom": "..."}`
    status: ActionStatus
    targets: list[dict[str, Any]] = Field(default_factory=list)
    related_claims: list[ClaimId] = Field(default_factory=list)
    supporting_evidence: list[EvidenceId] = Field(default_factory=list)
    proposed_by: ActorId
    approved_by: ActorId | None = None
    policy_id: PolicyId | None = None
    payload: dict[str, Any] = Field(default_factory=dict)
    created_at: str
    updated_at: str
    approved_at: str | None = None
    executed_at: str | None = None
    caused_by: EventId | None = None


class Outcome(BaseModel):
    """Mirrors `hydra_core::Outcome`."""

    model_config = ConfigDict(extra="forbid")

    id: OutcomeId
    tenant_id: TenantId | None = None
    action_id: ActionId
    kind: OutcomeKind
    observed_events: list[EventId] = Field(default_factory=list)
    updated_claims: list[ClaimId] = Field(default_factory=list)
    produced_evidence: list[EvidenceId] = Field(default_factory=list)
    impact: dict[str, Any] = Field(default_factory=dict)
    observed_at: str
    recorded_at: str
    recorded_by: ActorId
    caused_by: EventId | None = None


# === Ingest response ===


class IngestResponse(BaseModel):
    """Mirrors `hydra_net::http::ingest::IngestResponse`."""

    model_config = ConfigDict(extra="forbid")

    cascade_id: CascadeId | None = None
    event_ids: list[EventId] = Field(default_factory=list)
    event_count: int
    idempotent_hit: bool


# === Patch 1 carryovers — promotion-status / role-get ===
#
# Kept for the carry-over tests in test_types.py. The full living-
# database surface (lineage, diagnostics) gets its types added in
# Patches 3-4.


class ReplicationRoleGetResponse(BaseModel):
    model_config = ConfigDict(extra="forbid")

    role: RuntimeRole


class LastPromotionInfo(BaseModel):
    model_config = ConfigDict(extra="forbid")

    promoted_at: str
    promotion_sequence: int
    promoted_by: ActorId
    reason: str | None = None


class ReplicationPromotionStatusResponse(BaseModel):
    model_config = ConfigDict(extra="forbid")

    self_peer_id: ReplicaId
    current_role: RuntimeRole
    last_promotion: LastPromotionInfo | None = None
