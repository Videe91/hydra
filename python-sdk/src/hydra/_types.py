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


# === Patch 3: lineage wire models ===
#
# Each is a 1:1 mirror of the corresponding `hydra-net::http::lineage`
# struct. Per Design Rule #2, no DTO restructuring.


class LineageEventSummary(BaseModel):
    """Compact event header in a `LineageResponse`. Note: `kind`
    here is the snake_case **discriminator string**
    (e.g. `"signal"`, `"claim_proposed"`), NOT the full tagged-
    union body that `Event.kind` carries elsewhere. Agents fetch
    the full event body via `hy.get_event(id)` if they need it."""

    model_config = ConfigDict(extra="forbid")

    id: EventId
    timestamp: str
    kind: str
    summary: str
    caused_by: list[EventId] = Field(default_factory=list)
    cascade_id: CascadeId
    cascade_depth: int


class LineageEvidence(BaseModel):
    model_config = ConfigDict(extra="forbid")

    id: EvidenceId
    kind: str  # the EvidencePayload.kind discriminator string
    reliability: float
    observed_at: str
    caused_by: EventId


class LineageClaim(BaseModel):
    model_config = ConfigDict(extra="forbid")

    id: ClaimId
    kind: str  # ClaimKind (PascalCase wire form)
    status: str  # ClaimStatus (PascalCase wire form)
    predicate: str
    confidence: float
    caused_by: EventId


class LineageAction(BaseModel):
    model_config = ConfigDict(extra="forbid")

    id: ActionId
    kind: str
    status: str  # ActionStatus
    caused_by: EventId


class LineageOutcome(BaseModel):
    model_config = ConfigDict(extra="forbid")

    id: OutcomeId
    kind: str  # OutcomeKind
    action_id: ActionId
    caused_by: EventId


class LineagePolicyDecision(BaseModel):
    model_config = ConfigDict(extra="forbid")

    id: PolicyDecisionId
    kind: str
    policy_id: str | None = None
    action_id: ActionId
    caused_by: EventId


class LineageApprovalRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    id: ApprovalId
    status: str
    action_id: ActionId
    caused_by: EventId


class LineageResponse(BaseModel):
    """`GET /lineage/:event_id` response. The flat-keyed shape
    (per `HYDRA_SYSTEM_STUDY.md`): `events` carries summaries of
    every event in the causal context; `evidence`/`claims`/
    `actions`/`outcomes`/`policy_decisions`/`approval_requests`
    are the epistemic / action / policy artifacts referenced by
    those events; `ancestors` and `descendants` are id-only DAG
    topology lists. `explanation_summary` is a deterministic
    server-rendered narrative (not LLM-generated)."""

    model_config = ConfigDict(extra="forbid")

    seed_event_id: EventId
    depth: int
    events: list[LineageEventSummary] = Field(default_factory=list)
    evidence: list[LineageEvidence] = Field(default_factory=list)
    claims: list[LineageClaim] = Field(default_factory=list)
    actions: list[LineageAction] = Field(default_factory=list)
    outcomes: list[LineageOutcome] = Field(default_factory=list)
    policy_decisions: list[LineagePolicyDecision] = Field(default_factory=list)
    approval_requests: list[LineageApprovalRequest] = Field(default_factory=list)
    ancestors: list[EventId] = Field(default_factory=list)
    descendants: list[EventId] = Field(default_factory=list)
    truncated: bool
    explanation_summary: str


# === Patch 3: anomaly wire models ===


class Anomaly(BaseModel):
    """Mirrors `hydra-engine::anomaly::Anomaly`.

    `kind` is the AnomalyKind tagged-union body, served as
    `{"kind": "topology_degree", "details": {...}}` per the
    engine's `#[serde(tag="kind", content="details",
    rename_all="snake_case")]`. The SDK leaves it as `dict[str, Any]`
    for v0 — typed discriminated union is a future patch.

    Note the double-`kind` reading: the outer key (`Anomaly.kind`)
    is the struct field, the inner `kind` (inside the dict) is the
    AnomalyKind tag.
    """

    model_config = ConfigDict(extra="forbid")

    kind: dict[str, Any]
    description: str
    severity: float
    affected_nodes: list[NodeId] = Field(default_factory=list)
    trigger_event: EventId | None = None
    detected_at: str


class AnomalyEntry(Anomaly):
    """Anomaly with a stable content-hash id added on top.

    The engine flattens `Anomaly` into `AnomalyEntry` via
    `#[serde(flatten)]`, so the wire form has `anomaly_id` and
    all the Anomaly fields at the same top level.
    """

    anomaly_id: str


class AnomalyResponse(BaseModel):
    """`GET /diagnostics/anomaly` response."""

    model_config = ConfigDict(extra="forbid")

    anomalies: list[AnomalyEntry] = Field(default_factory=list)
    rule_count: int
    anomaly_count: int
    truncated: bool
    summary: str
    engine_duration_ms: int
    analysis_scope: str


# === Patch 3: coverage wire models ===


class CoverageGap(BaseModel):
    """Mirrors `hydra-engine::coverage::CoverageGap`."""

    model_config = ConfigDict(extra="forbid")

    expectation_index: int
    description: str
    fulfillment: float
    affected_nodes: list[NodeId] = Field(default_factory=list)


class CoverageReport(BaseModel):
    """Mirrors `hydra-engine::coverage::CoverageReport`. Returned
    per registered model in the coverage diagnostics response."""

    model_config = ConfigDict(extra="forbid")

    model_name: str
    score: float
    total_expectations: int
    met: int
    gaps: list[CoverageGap] = Field(default_factory=list)
    evaluated_at: str


class CoverageDiagnosticsResponse(BaseModel):
    """`GET /diagnostics/coverage` response."""

    model_config = ConfigDict(extra="forbid")

    reports: list[CoverageReport] = Field(default_factory=list)
    model_count: int
    report_count: int
    truncated: bool
    summary: str
    engine_duration_ms: int
    analysis_scope: str


# === Patch 3: counterfactual wire models ===


class PropertyDiff(BaseModel):
    """Mirrors `hydra-engine::counterfactual::PropertyDiff`.

    `actual` / `counterfactual` are `Optional<Value>` in Rust — the
    Hydra core `Value` is polymorphic; we accept `Any` here."""

    model_config = ConfigDict(extra="forbid")

    key: str
    actual: Any | None = None
    counterfactual: Any | None = None


class NodeDiff(BaseModel):
    """Mirrors `hydra-engine::counterfactual::NodeDiff`.

    `alive_diff` is Rust `Option<(bool, bool)>` → JSON tuple as
    `[actual, counterfactual]` or null."""

    model_config = ConfigDict(extra="forbid")

    node_id: NodeId
    property_diffs: list[PropertyDiff] = Field(default_factory=list)
    alive_diff: tuple[bool, bool] | None = None


class EdgeDiff(BaseModel):
    """Mirrors `hydra-engine::counterfactual::EdgeDiff`."""

    model_config = ConfigDict(extra="forbid")

    edge_id: EdgeId
    property_diffs: list[PropertyDiff] = Field(default_factory=list)
    alive_diff: tuple[bool, bool] | None = None


class GraphDiff(BaseModel):
    """Mirrors `hydra-engine::counterfactual::GraphDiff`. The full
    structural delta between actual and counterfactual projections."""

    model_config = ConfigDict(extra="forbid")

    nodes_only_in_actual: list[NodeId] = Field(default_factory=list)
    nodes_only_in_counterfactual: list[NodeId] = Field(default_factory=list)
    nodes_changed: list[NodeDiff] = Field(default_factory=list)
    edges_only_in_actual: list[EdgeId] = Field(default_factory=list)
    edges_only_in_counterfactual: list[EdgeId] = Field(default_factory=list)
    edges_changed: list[EdgeDiff] = Field(default_factory=list)


class CounterfactualDiagnosticsResponse(BaseModel):
    """`GET /diagnostics/counterfactual/:event_id` response.

    **Three-state `diff` semantics** (preserved exactly from the
    server contract):
      - `Some(GraphDiff with non-empty arrays)` → here's the delta.
      - `Some(GraphDiff with all-empty arrays)` → removing this
        event would change NOTHING. Zero-impact event. Meaningful.
      - `None` (JSON null) → caller passed `include_diff=false`.
        Transport-level omission, NOT zero impact.

    Pydantic's `Optional[GraphDiff]` round-trips this exactly:
    JSON `null` deserializes to `None`; JSON object deserializes
    to a `GraphDiff` (possibly with empty arrays).
    """

    model_config = ConfigDict(extra="forbid")

    event_id: EventId
    event_found: bool
    counterfactual_mode: str
    causal_subtree_size: int
    nodes_affected: int
    edges_affected: int
    properties_changed: int
    affected_types: dict[str, int] = Field(default_factory=dict)
    magnitude: float
    diff: GraphDiff | None = None
    summary: str
    engine_duration_ms: int
    analysis_scope: str


# === Patch 3: evolution wire models ===


class FireRecord(BaseModel):
    """Mirrors `hydra-engine::evolution::FireRecord`.

    `outcome` is `Option<SubscriptionOutcome>` — `None` means the
    human hasn't judged this fire yet."""

    model_config = ConfigDict(extra="forbid")

    timestamp: str
    trigger_event_id: EventId
    reaction_count: int
    outcome: SubscriptionOutcome | None = None


class MissRecord(BaseModel):
    """Mirrors `hydra-engine::evolution::MissRecord` — a
    retroactively-labeled event the subscription should have
    caught but didn't."""

    model_config = ConfigDict(extra="forbid")

    recorded_at: str
    missed_event_id: EventId
    reason: str | None = None


class EvolutionMetricEntry(BaseModel):
    """Mirrors `hydra-net::http::diagnostics::EvolutionMetricEntry`.

    **Two load-bearing Optional semantics**:

      `precision` / `recall` / `false_positive_rate` are
      `Option<f64>` — `None` means undefined (no judged outcomes
      yet for precision; no positives-or-misses for recall).
      Distinct from `0.0` (genuinely zero — all judged were FP,
      or all the catch-set was missed).

      `fire_log` / `miss_log` are `Option<Vec<...>>` —
      `None` means caller didn't request logs
      (`include_logs=False`). `[]` means requested but empty.
    """

    model_config = ConfigDict(extra="forbid")

    subscription_id: SubscriptionId
    subscription_name: str
    total_fires: int
    total_reactions: int
    true_positives: int
    false_positives: int
    auto_accepted: int
    false_negatives: int
    precision: float | None = None
    recall: float | None = None
    false_positive_rate: float | None = None
    pending_outcomes: int
    fire_log: list[FireRecord] | None = None
    miss_log: list[MissRecord] | None = None


class EvolutionDiagnosticsResponse(BaseModel):
    """`GET /diagnostics/evolution` response."""

    model_config = ConfigDict(extra="forbid")

    metrics: list[EvolutionMetricEntry] = Field(default_factory=list)
    subscription_count: int
    metric_count: int
    truncated: bool
    total_fires_across_all: int
    summary: str
    engine_duration_ms: int
    analysis_scope: str


# === Patch 4: schema IDs ===

SchemaId = str


# === Patch 4: schema lifecycle status (PascalCase, Rust serde default) ===

SchemaStatus = Literal["Active", "Disabled", "Archived"]


# === Patch 4: ValueType — recursive, externally-tagged ===
#
# `hydra_core::ValueType` is an externally-tagged Rust enum. Wire form
# is a mix: unit variants serialize as bare JSON strings; the two
# parameterized variants serialize as single-key objects.
#
#   "Null", "Bool", "Int", "Float", "String", "Timestamp",
#   "Object", "Any"
#   {"List": <ValueType>}            # recursive
#   {"Custom": "type_x"}             # TypeId
#
# Per the approved Patch 4 design: keep this as `str | dict[str, Any]`
# and provide ergonomic constructors via `ValueTypeOf` so users don't
# hand-roll the shape. Matches the Patch 2 precedent for ClaimSubject /
# EvidenceSource / ActionTarget tagged unions.

ValueType = str | dict[str, Any]


class ValueTypeOf:
    """Constructor helpers for `ValueType`.

    Each method returns the externally-tagged JSON shape the engine
    expects. Compose recursively:

        ValueTypeOf.list_of("Int")
          → {"List": "Int"}

        ValueTypeOf.list_of(ValueTypeOf.custom("type_invoice"))
          → {"List": {"Custom": "type_invoice"}}
    """

    NULL: str = "Null"
    BOOL: str = "Bool"
    INT: str = "Int"
    FLOAT: str = "Float"
    STRING: str = "String"
    TIMESTAMP: str = "Timestamp"
    OBJECT: str = "Object"
    ANY: str = "Any"

    @staticmethod
    def list_of(inner: ValueType) -> dict[str, Any]:
        return {"List": inner}

    @staticmethod
    def custom(type_id: TypeId) -> dict[str, Any]:
        return {"Custom": type_id}


# === Patch 4: FieldSchema ===


class FieldSchema(BaseModel):
    """Mirrors `hydra_core::FieldSchema`.

    `default_value` is `Option<Value>` server-side and `Value` is
    polymorphic (`String | Int | Float | Bool | Timestamp | List |
    Map | Null`). We accept `Any` here — Pydantic round-trips it
    untyped, matching the engine's permissive value vocabulary.

    `description` and `metadata` default to None / {}, matching
    Rust's `#[serde(default)]`-shaped permissiveness on read.
    """

    model_config = ConfigDict(extra="forbid")

    name: str
    value_type: ValueType
    required: bool
    default_value: Any | None = None
    description: str | None = None
    metadata: dict[str, Any] = Field(default_factory=dict)


# === Patch 4: per-kind schema records ===


class EntityTypeSchema(BaseModel):
    """Mirrors `hydra_core::EntityTypeSchema`. Returned by
    `GET /schemas/entity/:type_id`."""

    model_config = ConfigDict(extra="forbid")

    id: SchemaId
    tenant_id: TenantId | None = None
    type_id: TypeId
    name: str
    status: SchemaStatus
    fields: list[FieldSchema] = Field(default_factory=list)
    created_by: ActorId
    created_at: str
    updated_at: str
    metadata: dict[str, Any] = Field(default_factory=dict)


class EdgeTypeSchema(BaseModel):
    """Mirrors `hydra_core::EdgeTypeSchema`. Structurally identical
    to EntityTypeSchema; distinguished by registration route and by
    the `SchemaDefinition` external tag on list endpoints."""

    model_config = ConfigDict(extra="forbid")

    id: SchemaId
    tenant_id: TenantId | None = None
    type_id: TypeId
    name: str
    status: SchemaStatus
    fields: list[FieldSchema] = Field(default_factory=list)
    created_by: ActorId
    created_at: str
    updated_at: str
    metadata: dict[str, Any] = Field(default_factory=dict)


class EvidencePayloadSchema(BaseModel):
    """Mirrors `hydra_core::EvidencePayloadSchema`."""

    model_config = ConfigDict(extra="forbid")

    id: SchemaId
    tenant_id: TenantId | None = None
    kind: str
    status: SchemaStatus
    fields: list[FieldSchema] = Field(default_factory=list)
    created_by: ActorId
    created_at: str
    updated_at: str
    metadata: dict[str, Any] = Field(default_factory=dict)


class ClaimPredicateSchema(BaseModel):
    """Mirrors `hydra_core::ClaimPredicateSchema`.

    `subject_type` is `Option<TypeId>`: `None` means the predicate
    applies to any entity type; `Some(t)` constrains it.

    `object_type` is a full `ValueType` (primitives or `Custom`),
    NOT a TypeId."""

    model_config = ConfigDict(extra="forbid")

    id: SchemaId
    tenant_id: TenantId | None = None
    predicate: str
    status: SchemaStatus
    subject_type: TypeId | None = None
    object_type: ValueType
    allowed_claim_kinds: list[str] = Field(default_factory=list)
    created_by: ActorId
    created_at: str
    updated_at: str
    metadata: dict[str, Any] = Field(default_factory=dict)


class ActionPayloadSchema(BaseModel):
    """Mirrors `hydra_core::ActionPayloadSchema`."""

    model_config = ConfigDict(extra="forbid")

    id: SchemaId
    tenant_id: TenantId | None = None
    action_kind: str
    status: SchemaStatus
    fields: list[FieldSchema] = Field(default_factory=list)
    created_by: ActorId
    created_at: str
    updated_at: str
    metadata: dict[str, Any] = Field(default_factory=dict)


class PolicyConditionSchema(BaseModel):
    """Mirrors `hydra_core::PolicyConditionSchema`."""

    model_config = ConfigDict(extra="forbid")

    id: SchemaId
    tenant_id: TenantId | None = None
    policy_kind: str
    status: SchemaStatus
    fields: list[FieldSchema] = Field(default_factory=list)
    created_by: ActorId
    created_at: str
    updated_at: str
    metadata: dict[str, Any] = Field(default_factory=dict)


# === Patch 4: schema register / validation responses ===


class SchemaIdResponse(BaseModel):
    """Returned from every `POST /schemas/...` register call."""

    model_config = ConfigDict(extra="forbid")

    schema_id: SchemaId


class SchemaValidationErrorResponse(BaseModel):
    """One validation error inside a `ValidationResponse`."""

    model_config = ConfigDict(extra="forbid")

    schema_id: SchemaId | None = None
    path: str
    message: str


class ValidationResponse(BaseModel):
    """Returned by every `POST /schemas/validate/*` route.

    **Always 200 OK** — validation failure surfaces as `valid: False`
    with a populated `errors[]`, NOT as an HTTP error. The SDK does
    not raise on `valid: False`; callers branch on `.valid`.

    `schema_id` is `None` when no matching schema exists for the
    payload's kind/predicate — the engine treats absence as
    pass-through (permissive). Later enforcement happens at
    ingest-time via the SchemaGate policy.
    """

    model_config = ConfigDict(extra="forbid")

    valid: bool
    schema_id: SchemaId | None = None
    errors: list[SchemaValidationErrorResponse] = Field(default_factory=list)


# === Patch 4: replication wire enums (PascalCase, Rust serde default) ===
#
# Note the deliberate split from `RuntimeRole`:
#   `RuntimeRole` is the lowercase Literal used by `/replication/role`
#     ("leader" | "follower") — runtime-controllable HTTP-layer role.
#   `ReplicationRole` is the PascalCase cluster vocabulary on
#     ReplicationPeer.role and ReplicationStatusResponse.role:
#     "Leader" | "Follower" | "Observer" (Observer reserved).

ReplicationRole = Literal["Leader", "Follower", "Observer"]

ReplicationPeerStatus = Literal[
    "Registered",
    "Online",
    "Lagging",
    "Offline",
    "Failed",
    "Promoted",
    "Demoted",
]

ReplicationMode = Literal["CommitLogStreaming", "SnapshotThenTail"]


# === Patch 4: replication wire models ===


class ReplicationOffset(BaseModel):
    """Mirrors `hydra_core::ReplicationOffset`."""

    model_config = ConfigDict(extra="forbid")

    sequence: int
    commit_id: CommitId | None = None
    commit_hash: str | None = None


class ReplicationLag(BaseModel):
    """Mirrors `hydra_core::ReplicationLag`. `lag_commits` is computed
    server-side as `leader_sequence.saturating_sub(follower_sequence)`
    — floors at 0 on clock skew rather than wrapping."""

    model_config = ConfigDict(extra="forbid")

    leader_sequence: int
    follower_sequence: int
    lag_commits: int
    observed_at: str


class ReplicationPeer(BaseModel):
    """Mirrors `hydra_core::ReplicationPeer`."""

    model_config = ConfigDict(extra="forbid")

    id: ReplicaId
    tenant_id: TenantId | None = None
    role: ReplicationRole
    status: ReplicationPeerStatus
    endpoint: str | None = None
    mode: ReplicationMode
    last_offset: ReplicationOffset | None = None
    last_lag: ReplicationLag | None = None
    registered_by: ActorId
    registered_at: str
    updated_at: str
    metadata: dict[str, Any] = Field(default_factory=dict)


class ReplicationStatusResponse(BaseModel):
    """`GET /replication/status` response.

    Note `role` is `ReplicationRole` (PascalCase, the cluster
    vocabulary), distinct from the lowercase `RuntimeRole` returned
    by `GET /replication/role`."""

    model_config = ConfigDict(extra="forbid")

    role: ReplicationRole
    head_sequence: int
    head_commit_id: CommitId | None = None
    peers: list[ReplicationPeer] = Field(default_factory=list)


class ReplicationLagResponse(BaseModel):
    """`GET /replication/peers/:peer_id/lag` response.

    **`lag: None` is the intentional "no observation yet" state**, not
    a 404. The route never 404s — unknown peer_ids also return
    `{peer_id, lag: null}` for stable polling semantics."""

    model_config = ConfigDict(extra="forbid")

    peer_id: ReplicaId
    lag: ReplicationLag | None = None


# === Patch 6 (commit-stream SSE): `hy.subscribe_commits()` wire types ===
#
# `CommitBatch` on the engine has ~11 fields including
# `event_records`, `commit_hash`, `previous_hash`, `idempotency_key`,
# `metadata`, etc. The full Pydantic port would require modeling
# `EventCommitRecord`, `CommitStatus`, `CommitHash` separately. Per
# the Patch 6 design (Option C — "halfway"), we type the fields
# agents actually use (`id`, `sequence`, `events`, `committed_at`,
# the two hashes) and keep everything else accessible via `raw`.


class CommitBatchLite(BaseModel):
    """Lightly-typed view of an engine `CommitBatch`.

    Agents iterate `events`, branch on `sequence`, and treat
    `committed_at` as the temporal anchor. `commit_hash` and
    `previous_hash` are exposed for callers doing chain verification.

    Anything else the engine carries — `event_records`,
    `idempotency_key`, `metadata`, `committed_by`, `status` — stays
    in `raw` (the full wire dict). Pydantic's `model_validate` reads
    the same dict twice: once to populate the typed fields, once to
    preserve the unfiltered shape on `raw`. Costs ~1 dict copy per
    commit, which is dwarfed by the SSE wire latency.
    """

    model_config = ConfigDict(extra="ignore")

    id: CommitId
    sequence: int
    events: list[Event] = Field(default_factory=list)
    committed_at: str
    commit_hash: str | None = None
    previous_hash: str | None = None
    raw: dict[str, Any] = Field(default_factory=dict)

    @classmethod
    def from_wire(cls, payload: dict[str, Any]) -> CommitBatchLite:
        """Construct from the engine's CommitBatch wire shape. The
        full payload survives on `raw` so callers can reach fields
        the SDK doesn't yet type."""
        return cls(
            id=payload["id"],
            sequence=payload["sequence"],
            events=[Event.model_validate(e) for e in payload.get("events", [])],
            committed_at=payload["committed_at"],
            commit_hash=payload.get("commit_hash"),
            previous_hash=payload.get("previous_hash"),
            raw=payload,
        )


class CommitStreamCommit(BaseModel):
    """SSE `event: commit` — one committed batch fanned out from
    the engine."""

    model_config = ConfigDict(extra="forbid")

    type: Literal["commit"] = "commit"
    commit: CommitBatchLite


class CommitStreamHeartbeat(BaseModel):
    """SSE `event: heartbeat` — emitted every 15s on every open
    stream so clients can distinguish an idle engine from a dropped
    connection. `head_sequence` is the engine's latest committed
    sequence at the moment the heartbeat was emitted."""

    model_config = ConfigDict(extra="forbid")

    type: Literal["heartbeat"] = "heartbeat"
    head_sequence: int


class CommitStreamLag(BaseModel):
    """SSE `event: lag` — emitted at most once at the start of a
    stream if the caller's `after_sequence` is below what the engine
    can replay. The stream continues from `starting_at_sequence`; the
    client decides whether to reconcile the gap via
    `/replication/commits`."""

    model_config = ConfigDict(extra="forbid")

    type: Literal["lag"] = "lag"
    requested_after_sequence: int
    starting_at_sequence: int


class CommitStreamError(BaseModel):
    """SSE `event: error` — terminal. Emitted when a subscriber
    lagged past the broadcast capacity (slow consumer) or the
    server hit a serialization problem. The client should reconnect
    with `after_sequence` set to the last commit it observed."""

    model_config = ConfigDict(extra="forbid")

    type: Literal["error"] = "error"
    error: str
    hint: str | None = None


# Union of every item the SDK yields from
# `hy.subscribe_commits(...)`. Callers branch on `item.type`.
CommitStreamItem = (
    CommitStreamCommit | CommitStreamHeartbeat | CommitStreamLag | CommitStreamError
)
