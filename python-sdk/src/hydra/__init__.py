"""hydra-py — Python client for the Hydra living database.

Two clients with method-for-method parity:

  - `Hydra`     — async (httpx.AsyncClient). Use from inside an
                  event loop (FastAPI, anyio, asyncio.run).
  - `HydraSync` — sync (httpx.Client). Use from scripts, notebooks
                  (Jupyter runs its own event loop), and synchronous
                  web frameworks.

Async quickstart:

    import asyncio
    from hydra import Hydra, ClaimSubject, ClaimObject

    async def main():
        async with Hydra("http://localhost:8080",
                         token="<bearer>",
                         tenant="tenant_default") as hy:
            resp = await hy.ingest_signal(
                name="cloudtrail/CreateBucket",
                source="node_aws_acct",
            )
            print(resp.event_ids)

    asyncio.run(main())

Sync quickstart:

    from hydra import HydraSync, ClaimSubject, ClaimObject

    with HydraSync("http://localhost:8080",
                   token="<bearer>",
                   tenant="tenant_default") as hy:
        resp = hy.ingest_signal(
            name="cloudtrail/CreateBucket",
            source="node_aws_acct",
        )
        print(resp.event_ids)

Both clients share:
  - Wire types: `Node`, `Edge`, `Event`, `Claim`, `Evidence`,
    `Action`, `Outcome`, `IngestResponse`, `LineageResponse`,
    `AnomalyResponse`, `CoverageDiagnosticsResponse`,
    `CounterfactualDiagnosticsResponse`,
    `EvolutionDiagnosticsResponse`, the schema records,
    `ValidationResponse`, replication models.
  - Tagged-union helpers: `ClaimSubject`, `ClaimObject`,
    `EvidenceSource`, `ActionTarget`, `ValueTypeOf`.
  - Namespaces: `.diagnostics`, `.schemas`, `.replication`.
  - Exception hierarchy: `HydraError` + 7 typed subclasses.

See HYDRA_SDK_DESIGN_RULES.md at the repo root for the immutable
design rules every patch follows.
"""

__version__ = "0.1.0"

from ._types import (
    Action,
    ActionExecutionResponse,
    ActionId,
    ActionPayloadSchema,
    ActionStatus,
    ActionTarget,
    ActionTransitionResponse,
    ActionTransitionStatus,
    ActionFailureRateAssessment,
    ActionFailureRateLevel,
    ActorId,
    AgentLoopStormAssessment,
    AgentLoopStormLevel,
    AutoApprovalDecision,
    AutoExecutionDecision,
    Anomaly,
    AnomalyEntry,
    AnomalyResponse,
    ApprovalId,
    CascadeId,
    Claim,
    ClaimId,
    ClaimKind,
    ClaimObject,
    ClaimPredicateSchema,
    CausalCell,
    CausalCellChildTrust,
    CausalCellId,
    CausalCellKind,
    CausalCellTrustAssessment,
    CorrelationCandidate,
    CorrelationReason,
    CorrelationReasonKind,
    CorrelationSignalKind,
    CorrelationSignalRef,
    CorrelationStrength,
    CorrelationTrustAssessment,
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
    MatchLevel,
    SemanticIdentityMatchAssessment,
    SemanticIdentityMatchCandidate,
    SourceTrustAssessment,
    ClaimStatus,
    ClaimSubject,
    CommitBatchLite,
    CommitId,
    CommitRateAnomalyAssessment,
    CommitStreamCommit,
    CommitStreamError,
    CommitStreamHeartbeat,
    CommitStreamItem,
    CommitStreamLag,
    Confidence,
    CounterfactualDiagnosticsResponse,
    CoverageDiagnosticsResponse,
    CoverageGap,
    CoverageReport,
    DriftDirection,
    Edge,
    EdgeDiff,
    EdgeId,
    EdgeMeta,
    EdgeTypeSchema,
    EntityTypeSchema,
    EvaluationMode,
    Event,
    EventId,
    Evidence,
    EvidenceId,
    EvidencePayload,
    EvidencePayloadSchema,
    EvidenceSource,
    EvolutionDiagnosticsResponse,
    EvolutionMetricEntry,
    FieldSchema,
    FireRecord,
    GraphDiff,
    IngestResponse,
    LastPromotionInfo,
    LineageAction,
    LineageApprovalRequest,
    LineageClaim,
    LineageEventSummary,
    LineageEvidence,
    LineageOutcome,
    LineagePolicyDecision,
    LineageResponse,
    MicroModelId,
    MicroModelObservation,
    MicroModelPrediction,
    MicroModelRunId,
    MissRecord,
    Node,
    NodeDiff,
    NodeId,
    NodeMeta,
    Outcome,
    OutcomeId,
    OutcomeKind,
    PolicyConditionSchema,
    PolicyDecisionId,
    PolicyId,
    PropertyDiff,
    ReplicaId,
    ReplicationLag,
    ReplicationLagAnomalyAssessment,
    ReplicationLagAnomalyLevel,
    ReplicationLagResponse,
    ReplicationMode,
    ReplicationOffset,
    ReplicationPeer,
    ReplicationPeerStatus,
    ReplicationPromotionStatusResponse,
    ReplicationRole,
    ReplicationRoleGetResponse,
    ReplicationStatusResponse,
    RuntimeRole,
    SchemaId,
    SchemaIdResponse,
    SchemaStatus,
    SchemaValidationErrorResponse,
    SnapshotId,
    SubscriptionId,
    SubscriptionOutcome,
    TenantId,
    TrustAssessment,
    TrustFactor,
    TrustLevel,
    TypeId,
    ValidationResponse,
    ValueType,
    ValueTypeOf,
)
from .client import Hydra
from .client_sync import HydraSync
from .errors import (
    HydraAuthError,
    HydraConnectionError,
    HydraError,
    HydraNotFoundError,
    HydraRateLimitedError,
    HydraReadOnlyFollowerError,
    HydraServerError,
    HydraValidationError,
)

__all__ = [
    "__version__",
    # Client
    "Hydra",
    "HydraSync",
    # Wire types
    "Action",
    "Claim",
    "Edge",
    "EdgeMeta",
    "Event",
    "Evidence",
    "EvidencePayload",
    "IngestResponse",
    "Node",
    "NodeMeta",
    "Outcome",
    # Lineage (Patch 3)
    "LineageAction",
    "LineageApprovalRequest",
    "LineageClaim",
    "LineageEventSummary",
    "LineageEvidence",
    "LineageOutcome",
    "LineagePolicyDecision",
    "LineageResponse",
    # Diagnostics (Patch 3)
    "Anomaly",
    "AnomalyEntry",
    "AnomalyResponse",
    "CounterfactualDiagnosticsResponse",
    "CoverageDiagnosticsResponse",
    "CoverageGap",
    "CoverageReport",
    "EdgeDiff",
    "EvolutionDiagnosticsResponse",
    "EvolutionMetricEntry",
    "FireRecord",
    "GraphDiff",
    "MissRecord",
    "NodeDiff",
    "PropertyDiff",
    # MicroModel evaluation surface (Patch 5)
    "CommitRateAnomalyAssessment",
    "EvaluationMode",
    "MicroModelId",
    "MicroModelPrediction",
    "MicroModelRunId",
    # Operator approval workflow (Patch 6)
    "ActionTransitionResponse",
    # Notify execution stub (Patch 7)
    "ActionExecutionResponse",
    # Outcome learning loop (Patch 8)
    "MicroModelObservation",
    # Trust layer (Patch 10)
    "TrustAssessment",
    "TrustFactor",
    "TrustLevel",
    # Cell trust HTTP/SDK (Patch 24) — surfaces Patch 23's
    # CausalCell trust folding via `assess_causal_cell_trust`.
    "CausalCellId",
    "CausalCellChildTrust",
    "CausalCellTrustAssessment",
    # CausalCell read/query (Patch 25) — surfaces individual
    # cells + tenant-scoped listing via `causal_cell` /
    # `causal_cells`. `CausalCellKind` covers both built-in
    # PascalCase variants ("Reflex", etc.) and the externally-
    # tagged `{"Custom": "label"}` form.
    "CausalCell",
    "CausalCellKind",
    # Correlation engine (Patch 43 trust vocab, Patch 44 candidate
    # vocab, Patch 45 engine, Patch 46 HTTP/SDK). Two-axis
    # verdict (`strength` + `level`). `CorrelationStrength.None`
    # is a STRING value (no correlation), distinct from
    # Python's `None`. Surface via `assess_correlation_candidate`.
    "CorrelationCandidate",
    "CorrelationReason",
    "CorrelationReasonKind",
    "CorrelationSignalKind",
    "CorrelationSignalRef",
    "CorrelationStrength",
    "CorrelationTrustAssessment",
    # Identity Graph (Patch 29 vocab, Patch 30 matcher, Patch 31
    # HTTP/SDK). `IdentityEntity` is the canonical primitive;
    # `IdentityAlias` is one source-specific name; `MatchLevel`
    # ("Strong"/"Possible"/"Weak"/"None") buckets the matcher
    # score. Note: `MatchLevel.None` is a STRING value, not
    # Python None.
    "IdentityAlias",
    "IdentityEntity",
    "IdentityEntityId",
    "IdentityEntityKind",
    # Identity Graph relationships (Patch 37 engine vocab + store,
    # Patch 38 HTTP/SDK). `IdentityLink` is a durable directed
    # assertion between two entities; built-in kinds cover
    # same_as / depends_on / downstream_of / owned_by /
    # produced_by / consumed_by / derived_from / observed_in /
    # part_of / related_to, plus open-ended Custom.
    # **Informational confidence only — NOT a trust verdict.**
    # Auto-actions must wait for IdentityLinkTrustAssessment
    # (P39+). No update / delete in v0.
    "IdentityLink",
    "IdentityLinkId",
    "IdentityLinkKind",
    # IdentityLink trust (Patch 39 engine + Patch 40 wire).
    # Trust verdict over a persisted `IdentityLink` edge —
    # STRUCTURAL only, NOT semantic correctness. Acyclicity:
    # link-trust depends on entity-trust; entity-trust MUST
    # NOT depend on link-trust.
    "IdentityLinkTrustAssessment",
    # Identity trust HTTP/SDK (Patch 34 — exposes P32/P33
    # verdicts over `/trust/identity/*` + the SDK methods
    # `assess_identity_entity_trust` and
    # `assess_identity_match_trust`).
    "IdentityEntityTrustAssessment",
    "IdentityMatchTrustAssessment",
    "MatchLevel",
    "SemanticIdentityMatchAssessment",
    "SemanticIdentityMatchCandidate",
    # Source trust HTTP/SDK (Patch 36 — exposes P35 over
    # `/trust/identity/sources/:source` + the SDK method
    # `assess_source_trust`). Third identity-trust axis after
    # match (P32) and entity (P33). Identity-backed, NOT
    # operational. Unknown-but-valid source returns level
    # "Unknown" with 200, NOT 404.
    "SourceTrustAssessment",
    # Automation layer (Patch 11 + Patch 15)
    "AutoExecutionDecision",
    "AutoApprovalDecision",
    # Schemas (Patch 4)
    "ActionPayloadSchema",
    "ClaimPredicateSchema",
    "EdgeTypeSchema",
    "EntityTypeSchema",
    "EvidencePayloadSchema",
    "FieldSchema",
    "PolicyConditionSchema",
    "SchemaIdResponse",
    "SchemaStatus",
    "SchemaValidationErrorResponse",
    "ValidationResponse",
    "ValueType",
    "ValueTypeOf",
    # Commit stream (Patch 6 — living-database)
    "CommitBatchLite",
    "CommitStreamCommit",
    "CommitStreamError",
    "CommitStreamHeartbeat",
    "CommitStreamItem",
    "CommitStreamLag",
    # Replication read-only (Patch 4)
    "LastPromotionInfo",
    "ReplicationLag",
    # MicroModel Patch 16 — replication-lag anomaly
    "ReplicationLagAnomalyAssessment",
    "ReplicationLagAnomalyLevel",
    # MicroModel Patch 18 — agent-loop storm
    "AgentLoopStormAssessment",
    "AgentLoopStormLevel",
    # MicroModel Patch 19 — action-failure rate
    "ActionFailureRateAssessment",
    "ActionFailureRateLevel",
    "ReplicationLagResponse",
    "ReplicationMode",
    "ReplicationOffset",
    "ReplicationPeer",
    "ReplicationPeerStatus",
    "ReplicationPromotionStatusResponse",
    "ReplicationRole",
    "ReplicationRoleGetResponse",
    "ReplicationStatusResponse",
    # Tagged-union helpers
    "ActionTarget",
    "ClaimObject",
    "ClaimSubject",
    "EvidenceSource",
    # Type aliases
    "ActionId",
    "ActorId",
    "ApprovalId",
    "CascadeId",
    "ClaimId",
    "CommitId",
    "EdgeId",
    "EventId",
    "EvidenceId",
    "NodeId",
    "OutcomeId",
    "PolicyDecisionId",
    "PolicyId",
    "ReplicaId",
    "SchemaId",
    "SnapshotId",
    "SubscriptionId",
    "TenantId",
    "TypeId",
    # Literal enums
    "ActionStatus",
    "ActionTransitionStatus",
    "ClaimKind",
    "ClaimStatus",
    "Confidence",
    "DriftDirection",
    "OutcomeKind",
    "RuntimeRole",
    "SubscriptionOutcome",
    # Errors
    "HydraAuthError",
    "HydraConnectionError",
    "HydraError",
    "HydraNotFoundError",
    "HydraRateLimitedError",
    "HydraReadOnlyFollowerError",
    "HydraServerError",
    "HydraValidationError",
]
