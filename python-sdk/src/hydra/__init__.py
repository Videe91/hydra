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
    ActorId,
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
