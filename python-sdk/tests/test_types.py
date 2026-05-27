"""Tests for the Pydantic v2 wire-format models.

Design rule #2: transport DTOs mirror the wire format exactly. These
tests round-trip JSON ↔ Pydantic against real Hydra response shapes
to guard against drift.

Patch 1 covers only the foundation set. Each subsequent patch adds
its own type round-trip tests (LineageResponse, AnomalyResponse,
etc.) following this same pattern.
"""

from __future__ import annotations

import pytest
from pydantic import ValidationError

from hydra._types import (
    LastPromotionInfo,
    ReplicationPromotionStatusResponse,
    ReplicationRoleGetResponse,
)


# === ReplicationRoleGetResponse — the simplest live wire shape ===


def test_role_get_response_round_trips_leader() -> None:
    """`GET /replication/role` returns `{"role": "leader"}` from a
    Leader node. Confirms snake_case Literal parsing works."""
    raw = {"role": "leader"}
    parsed = ReplicationRoleGetResponse.model_validate(raw)
    assert parsed.role == "leader"
    # And it round-trips back to the same dict.
    assert parsed.model_dump() == raw


def test_role_get_response_round_trips_follower() -> None:
    raw = {"role": "follower"}
    parsed = ReplicationRoleGetResponse.model_validate(raw)
    assert parsed.role == "follower"
    assert parsed.model_dump() == raw


def test_role_get_response_rejects_unknown_role() -> None:
    """Pydantic validation must catch wire-shape drift early."""
    with pytest.raises(ValidationError):
        ReplicationRoleGetResponse.model_validate({"role": "PRIMARY"})


def test_role_get_response_rejects_extra_fields() -> None:
    """`model_config = ConfigDict(extra="forbid")` catches accidental
    server additions during local SDK development. Once a new field
    lands in the wire form, we add it explicitly in the next SDK
    patch."""
    with pytest.raises(ValidationError):
        ReplicationRoleGetResponse.model_validate({"role": "leader", "extra": 1})


# === ReplicationPromotionStatusResponse — Option<LastPromotionInfo> ===


def test_promotion_status_round_trips_with_null_last_promotion() -> None:
    """Fresh node, never promoted. Hydra returns
    `last_promotion: null` (not omitted) per the lag-endpoint
    convention from polish #1."""
    raw = {
        "self_peer_id": "replica_alpha",
        "current_role": "leader",
        "last_promotion": None,
    }
    parsed = ReplicationPromotionStatusResponse.model_validate(raw)
    assert parsed.self_peer_id == "replica_alpha"
    assert parsed.current_role == "leader"
    assert parsed.last_promotion is None


def test_promotion_status_round_trips_with_populated_last_promotion() -> None:
    """Promoted node — current_role may diverge from history (a
    promoted-then-demoted node shows `last_promotion` populated but
    `current_role: "follower"`)."""
    raw = {
        "self_peer_id": "replica_alpha",
        "current_role": "follower",
        "last_promotion": {
            "promoted_at": "2026-05-27T18:42:00Z",
            "promotion_sequence": 12345,
            "promoted_by": "actor_oncall_alice",
            "reason": "leader unreachable",
        },
    }
    parsed = ReplicationPromotionStatusResponse.model_validate(raw)
    assert parsed.last_promotion is not None
    assert parsed.last_promotion.promotion_sequence == 12345
    assert parsed.last_promotion.promoted_by == "actor_oncall_alice"
    assert parsed.last_promotion.reason == "leader unreachable"


def test_last_promotion_info_reason_optional() -> None:
    """`reason` is `Option<String>` in the engine — must accept missing/null."""
    raw = {
        "promoted_at": "2026-05-27T18:42:00Z",
        "promotion_sequence": 1,
        "promoted_by": "actor_x",
    }
    parsed = LastPromotionInfo.model_validate(raw)
    assert parsed.reason is None


def test_promotion_status_serializes_back_to_wire_form() -> None:
    """Round-trip: parse → re-emit → compare. Field order doesn't
    matter for dict equality."""
    raw = {
        "self_peer_id": "replica_alpha",
        "current_role": "leader",
        "last_promotion": {
            "promoted_at": "2026-05-27T18:42:00Z",
            "promotion_sequence": 7,
            "promoted_by": "actor_x",
            "reason": None,
        },
    }
    parsed = ReplicationPromotionStatusResponse.model_validate(raw)
    re_emitted = parsed.model_dump()
    assert re_emitted == raw


# === Patch 2: tagged-union helper constructors ===
#
# These produce externally-tagged dict shapes that match what the
# engine's serde expects. Tests pin the exact byte-form so any drift
# in the engine's serialization fails loudly.


def test_claim_subject_constructors() -> None:
    from hydra import ClaimSubject

    assert ClaimSubject.node("node_x") == {"Node": "node_x"}
    assert ClaimSubject.edge("edge_x") == {"Edge": "edge_x"}
    assert ClaimSubject.dataset("revenue_daily") == {"Dataset": "revenue_daily"}
    assert ClaimSubject.metric("error_rate") == {"Metric": "error_rate"}
    assert ClaimSubject.external_ref("ext:thing") == {"ExternalRef": "ext:thing"}
    assert ClaimSubject.system("aws") == {"System": "aws"}


def test_claim_object_constructors() -> None:
    from hydra import ClaimObject

    assert ClaimObject.value(True) == {"Value": True}
    assert ClaimObject.value(42) == {"Value": 42}
    assert ClaimObject.value("text") == {"Value": "text"}
    assert ClaimObject.value({"k": "v"}) == {"Value": {"k": "v"}}
    assert ClaimObject.node("node_x") == {"Node": "node_x"}
    assert ClaimObject.external_ref("ext:y") == {"ExternalRef": "ext:y"}


def test_evidence_source_constructors() -> None:
    from hydra import EvidenceSource

    assert EvidenceSource.warehouse(
        system="snowflake", database="prod", schema="public", table="orders"
    ) == {
        "Warehouse": {
            "system": "snowflake",
            "database": "prod",
            "schema": "public",
            "table": "orders",
        }
    }
    # Optional fields default to None — the engine accepts nulls.
    assert EvidenceSource.warehouse(system="snowflake") == {
        "Warehouse": {
            "system": "snowflake",
            "database": None,
            "schema": None,
            "table": None,
        }
    }
    assert EvidenceSource.api(system="github", endpoint="/repos") == {
        "Api": {"system": "github", "endpoint": "/repos"}
    }
    assert EvidenceSource.document("s3://bucket/file") == {
        "Document": {"uri": "s3://bucket/file"}
    }
    assert EvidenceSource.human("actor_h") == {"Human": {"actor_id": "actor_h"}}
    assert EvidenceSource.agent("actor_a") == {"Agent": {"actor_id": "actor_a"}}
    assert EvidenceSource.system("sensor_x") == {"System": {"name": "sensor_x"}}


def test_action_target_constructors() -> None:
    from hydra import ActionTarget

    assert ActionTarget.node("node_x") == {"Node": "node_x"}
    assert ActionTarget.edge("edge_x") == {"Edge": "edge_x"}
    assert ActionTarget.claim("claim_x") == {"Claim": "claim_x"}
    assert ActionTarget.evidence("evd_x") == {"Evidence": "evd_x"}
    assert ActionTarget.external_ref("ext:thing") == {"ExternalRef": "ext:thing"}
    assert ActionTarget.dataset("revenue") == {"Dataset": "revenue"}
    assert ActionTarget.system("aws") == {"System": "aws"}


# === Patch 2: wire-model round-trips ===


def test_node_round_trips() -> None:
    from hydra import Node

    raw = {
        "meta": {
            "id": "node_x",
            "type_id": "dataset",
            "created_at": "2026-01-01T00:00:00Z",
            "updated_at": "2026-01-01T00:00:00Z",
            "version": 1,
            "alive": True,
            "tenant_id": "tenant_t",
        },
        "properties": {"name": "revenue"},
    }
    parsed = Node.model_validate(raw)
    assert parsed.meta.id == "node_x"
    assert parsed.properties == {"name": "revenue"}
    assert parsed.model_dump() == raw


def test_claim_round_trips_with_pascalcase_enums() -> None:
    """Verifies the engine's PascalCase wire form parses cleanly —
    `"Verified"` not `"verified"`, `"AnomalyFinding"` not
    `"anomaly_finding"`. Catches any accidental snake_case drift."""
    from hydra import Claim

    raw = {
        "id": "claim_x",
        "tenant_id": "tenant_t",
        "kind": "AnomalyFinding",
        "subject": {"Dataset": "revenue_daily"},
        "predicate": "is_stale",
        "object": {"Value": True},
        "confidence": 0.91,
        "status": "Verified",
        "evidence_for": ["evd_a"],
        "evidence_against": [],
        "valid_from": "2026-01-01T00:00:00Z",
        "valid_until": None,
        "created_by": "actor_agent",
        "created_at": "2026-01-01T00:00:00Z",
        "updated_at": "2026-01-01T00:00:00Z",
        "caused_by": None,
    }
    parsed = Claim.model_validate(raw)
    assert parsed.kind == "AnomalyFinding"
    assert parsed.status == "Verified"
    assert parsed.confidence == 0.91
    assert parsed.subject == {"Dataset": "revenue_daily"}
    assert parsed.object == {"Value": True}
    assert parsed.model_dump() == raw


def test_action_round_trips_with_simple_kind() -> None:
    from hydra import Action

    raw = {
        "id": "act_x",
        "tenant_id": "tenant_t",
        "kind": "Quarantine",
        "status": "Proposed",
        "targets": [{"Dataset": "d1"}, {"Node": "node_x"}],
        "related_claims": ["claim_a"],
        "supporting_evidence": [],
        "proposed_by": "actor_agent",
        "approved_by": None,
        "policy_id": None,
        "payload": {"reason": "stale"},
        "created_at": "2026-01-01T00:00:00Z",
        "updated_at": "2026-01-01T00:00:00Z",
        "approved_at": None,
        "executed_at": None,
        "caused_by": None,
    }
    parsed = Action.model_validate(raw)
    assert parsed.kind == "Quarantine"
    assert parsed.targets == [{"Dataset": "d1"}, {"Node": "node_x"}]


def test_action_round_trips_with_custom_kind() -> None:
    """ActionKind::Custom(String) serializes as {"Custom": "..."}.
    The DTO accepts either a bare string or that dict shape."""
    from hydra import Action

    raw = {
        "id": "act_x",
        "tenant_id": None,
        "kind": {"Custom": "my_workflow"},
        "status": "Executed",
        "targets": [],
        "related_claims": [],
        "supporting_evidence": [],
        "proposed_by": "a",
        "approved_by": None,
        "policy_id": None,
        "payload": {},
        "created_at": "2026-01-01T00:00:00Z",
        "updated_at": "2026-01-01T00:00:00Z",
        "approved_at": None,
        "executed_at": None,
        "caused_by": None,
    }
    parsed = Action.model_validate(raw)
    assert parsed.kind == {"Custom": "my_workflow"}


def test_evidence_round_trips() -> None:
    from hydra import Evidence

    raw = {
        "id": "evd_x",
        "tenant_id": None,
        "source": {"System": {"name": "sensor"}},
        "payload": {"kind": "obs", "data": {"k": 1}},
        "reliability": 0.95,
        "observed_at": "2026-01-01T00:00:00Z",
        "recorded_at": "2026-01-01T00:00:00Z",
        "caused_by": None,
    }
    parsed = Evidence.model_validate(raw)
    assert parsed.payload.kind == "obs"
    assert parsed.payload.data == {"k": 1}
    assert parsed.reliability == 0.95


def test_outcome_round_trips() -> None:
    from hydra import Outcome

    raw = {
        "id": "oc_x",
        "tenant_id": None,
        "action_id": "act_x",
        "kind": "Success",
        "observed_events": ["evt_a"],
        "updated_claims": [],
        "produced_evidence": [],
        "impact": {},
        "observed_at": "2026-01-01T00:00:00Z",
        "recorded_at": "2026-01-01T00:00:00Z",
        "recorded_by": "actor_agent",
        "caused_by": None,
    }
    parsed = Outcome.model_validate(raw)
    assert parsed.kind == "Success"
    assert parsed.observed_events == ["evt_a"]


def test_ingest_response_round_trips() -> None:
    from hydra import IngestResponse

    raw = {
        "cascade_id": "csc_x",
        "event_ids": ["evt_a", "evt_b"],
        "event_count": 2,
        "idempotent_hit": False,
    }
    parsed = IngestResponse.model_validate(raw)
    assert parsed.cascade_id == "csc_x"
    assert parsed.event_ids == ["evt_a", "evt_b"]
    assert parsed.event_count == 2
    assert parsed.idempotent_hit is False
    # Idempotent-hit path: cascade_id may be present (re-used) and
    # idempotent_hit=true.
    raw2 = {
        "cascade_id": "csc_orig",
        "event_ids": ["evt_x"],
        "event_count": 1,
        "idempotent_hit": True,
    }
    parsed2 = IngestResponse.model_validate(raw2)
    assert parsed2.idempotent_hit is True


def test_confidence_clamps_at_pydantic_validation() -> None:
    """`Confidence = Annotated[float, Field(ge=0.0, le=1.0)]` —
    Pydantic rejects out-of-range values rather than clamping
    silently. Catches bad client code early."""
    from pydantic import ValidationError

    from hydra import Claim

    raw_bad = {
        "id": "claim_x",
        "tenant_id": None,
        "kind": "Fact",
        "subject": {"Node": "n"},
        "predicate": "p",
        "object": {"Value": 1},
        "confidence": 1.5,  # out of range
        "status": "Proposed",
        "evidence_for": [],
        "evidence_against": [],
        "valid_from": "2026-01-01T00:00:00Z",
        "valid_until": None,
        "created_by": "actor_x",
        "created_at": "2026-01-01T00:00:00Z",
        "updated_at": "2026-01-01T00:00:00Z",
        "caused_by": None,
    }
    with pytest.raises(ValidationError):
        Claim.model_validate(raw_bad)
