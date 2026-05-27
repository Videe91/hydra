"""hydra-py — Python client for the Hydra living database.

Quickstart:

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

            resp = await hy.propose_claim(
                claim_id="claim_anom_001",
                subject=ClaimSubject.dataset("revenue_daily"),
                predicate="is_stale",
                object=ClaimObject.value(True),
                created_by="actor_agent",
                kind="AnomalyFinding",
                confidence=0.91,
            )

    asyncio.run(main())

Public surface in Patch 2:
  - `Hydra` — the async client
  - Wire types: `Node`, `Edge`, `Event`, `Claim`, `Evidence`,
    `Action`, `Outcome`, `IngestResponse`
  - Tagged-union helpers: `ClaimSubject`, `ClaimObject`,
    `EvidenceSource`, `ActionTarget`
  - Type aliases: `EventId`, `NodeId`, etc.
  - Literal enums: `ClaimStatus`, `ClaimKind`, `ActionStatus`,
    `OutcomeKind`
  - Exception hierarchy: `HydraError` + 7 typed subclasses

See HYDRA_SDK_DESIGN_RULES.md at the repo root for the immutable
design rules every patch follows.
"""

__version__ = "0.1.0"

from ._types import (
    Action,
    ActionId,
    ActionStatus,
    ActionTarget,
    ActorId,
    ApprovalId,
    CascadeId,
    Claim,
    ClaimId,
    ClaimKind,
    ClaimObject,
    ClaimStatus,
    ClaimSubject,
    CommitId,
    Confidence,
    DriftDirection,
    Edge,
    EdgeId,
    EdgeMeta,
    Event,
    EventId,
    Evidence,
    EvidenceId,
    EvidencePayload,
    EvidenceSource,
    IngestResponse,
    Node,
    NodeId,
    NodeMeta,
    Outcome,
    OutcomeId,
    OutcomeKind,
    PolicyDecisionId,
    PolicyId,
    ReplicaId,
    RuntimeRole,
    SnapshotId,
    SubscriptionId,
    SubscriptionOutcome,
    TenantId,
    TypeId,
)
from .client import Hydra
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
    "SnapshotId",
    "SubscriptionId",
    "TenantId",
    "TypeId",
    # Literal enums
    "ActionStatus",
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
