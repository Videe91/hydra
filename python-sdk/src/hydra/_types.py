"""Pydantic v2 models mirroring Hydra's wire format.

Design rule #2: transport DTOs mirror the wire format exactly. Field
names, casing, optionality, and discriminator shape all match
hydra-net's JSON output byte-for-byte.

Patch 1 ships only a minimal set — just enough to prove the
round-trip pattern works (IDs, confidence, enums with snake_case
serde, one tagged union). Full type coverage arrives in later
patches:
  - Patch 2 (ingest + query): Event, EventKind tagged union, Claim,
    Evidence, Action, Outcome
  - Patch 3 (lineage + diagnostics): LineageResponse, AnomalyResponse,
    CoverageReport, CounterfactualResponse, EvolutionResponse
  - Patch 4 (schemas + replication): SchemaDefinition,
    ReplicationStatus, ReplicationPeer, ReplicationLag

Each new type added in a later patch follows the same round-trip
test pattern established here.

NOT public: this module is `hydra._types`, used by the public method
layer. Public types are re-exported from `hydra.__init__` in later
patches.
"""

from __future__ import annotations

from typing import Annotated, Literal

from pydantic import BaseModel, ConfigDict, Field

# === ID newtypes ===
#
# Hydra uses prefixed string IDs (`evt_...`, `node_...`, `claim_...`,
# etc.) that ULID-sort. Python's type system doesn't need newtypes
# for these — they ARE strings — but we expose typed aliases so
# method signatures read clearly:
#
#   async def get_event(self, event_id: EventId) -> Event: ...
#
# At runtime they're identical to `str`; mypy treats them as distinct
# enough to catch the common "passed a node_id where an event_id was
# expected" bug.

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


# === Confidence — newtype-ish wrapper ===
#
# Hydra's `Confidence` is `f64` clamped to [0.0, 1.0]. On the wire
# it's a bare number. We expose a Pydantic model so users get a
# typed handle plus the clamp validation; serialization uses the
# bare-number form via `model_serializer` if needed in later patches.
#
# For Patch 1 we just demonstrate the pattern with a simple type
# alias; a richer wrapper can come later without breaking callers
# that use `float`.

Confidence = Annotated[float, Field(ge=0.0, le=1.0)]


# === Enums — snake_case wire form ===
#
# All Hydra enums on the engine side use #[serde(rename_all =
# "snake_case")], so the wire form is `"verified"`, `"proposed"`,
# `"anomaly_finding"`, etc. Pydantic's `Literal[...]` matches this
# exactly without needing a separate Enum class.

ClaimStatus = Literal[
    "proposed",
    "supported",
    "verified",
    "operational",
    "disputed",
    "stale",
    "retracted",
    "archived",
]

ClaimKind = Literal[
    "fact",
    "inference",
    "hypothesis",
    "prediction",
    "recommendation",
    "policy_finding",
    "anomaly_finding",
    "lineage_finding",
]

ActionStatus = Literal[
    "proposed",
    "approved",
    "rejected",
    "executing",
    "executed",
    "failed",
    "cancelled",
]

DriftDirection = Literal["increasing", "decreasing"]

SubscriptionOutcome = Literal["confirmed", "dismissed", "auto_accepted"]

RuntimeRole = Literal["leader", "follower"]


# === Tagged-union demo: EvidenceSource ===
#
# The engine's `EvidenceSource` enum uses Pydantic's serde tagged
# representation — externally tagged ("Warehouse", "Api", etc. as
# keys). On the wire it serializes as a struct with a single key.
# Pydantic v2 handles this via Field(discriminator=...) once we have
# the full tagged-union model in a later patch. For Patch 1 we ship
# the simpler `"kind"+"details"` form used by `AnomalyKind` etc.,
# which is the dominant convention going forward in newer engine
# types.
#
# This is intentionally just one demo type — the goal is to prove
# the round-trip pattern works against real Hydra JSON.


class EvidenceSourceWarehouse(BaseModel):
    """Internal-tagged variant for `EvidenceSource::Warehouse`.

    The actual engine `EvidenceSource` uses an externally-tagged
    representation (Pydantic-incompatible without a Union-discriminator
    setup); Patch 2 introduces the full Union model. This minimal
    variant is included to exercise nested-model round-trip in tests.
    """

    model_config = ConfigDict(extra="forbid")

    system: str
    database: str | None = None
    schema_: str | None = Field(default=None, alias="schema")
    table: str | None = None


# === Polish #6 / V2 — RoleState GET response ===
#
# A real, currently-shipped Hydra wire type. We bring it in for Patch
# 1's round-trip test because it's small (one field) and exercises
# the lowercase-serde-rename pattern we'll reuse across the SDK.

class ReplicationRoleGetResponse(BaseModel):
    """Mirrors hydra-net's `ReplicationRoleGetResponse`.

    Wire form: `{"role": "leader"}` or `{"role": "follower"}`.
    """

    model_config = ConfigDict(extra="forbid")

    role: RuntimeRole


# === Promotion-status response ===
#
# Living-database surface, shipped in commit 26b3055. Used by Patch
# 1's round-trip tests to demonstrate the SDK can parse an actual
# response from the running engine without intermediate translation.

class LastPromotionInfo(BaseModel):
    """Mirrors hydra-net's `LastPromotionInfo`."""

    model_config = ConfigDict(extra="forbid")

    promoted_at: str  # ISO 8601 string; Patch 2 introduces datetime conversion
    promotion_sequence: int
    promoted_by: ActorId
    reason: str | None = None


class ReplicationPromotionStatusResponse(BaseModel):
    """Mirrors hydra-net's `ReplicationPromotionStatusResponse`."""

    model_config = ConfigDict(extra="forbid")

    self_peer_id: ReplicaId
    current_role: RuntimeRole
    last_promotion: LastPromotionInfo | None = None
