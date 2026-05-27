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
