"""Sync-side method coverage for `HydraSync`.

Pattern: one happy-path test per method group, plus the load-bearing
semantic tests (404 → HydraNotFoundError, validate-200-on-invalid,
peer_lag null-vs-data, etc.). The async versions of these tests live
in test_ingest.py / test_query.py / test_lineage.py / test_diagnostics.py
/ test_schemas.py / test_replication.py and prove the per-method
plumbing in detail. This file is the proof that the sync mirror
delegates correctly to the same wire-format contract.

If a future patch adds a new method to `Hydra`, it should add a
matching sync test here so the parity is enforced by CI.
"""

from __future__ import annotations

from typing import Any

import httpx
import pytest
import respx

from hydra import (
    ClaimObject,
    ClaimSubject,
    EvidenceSource,
    FieldSchema,
    HydraNotFoundError,
    HydraSync,
    HydraValidationError,
    ValueTypeOf,
)

# Reuse the existing async test fixtures verbatim so the sync mirror
# is exercised against the same wire shapes.
from tests.test_diagnostics import (
    ANOMALY_RESPONSE_OK,
    COUNTERFACTUAL_FULL_RESPONSE,
    COVERAGE_RESPONSE_OK,
    EVOLUTION_RESPONSE_NO_LOGS,
)
from tests.test_lineage import LINEAGE_FIXTURE
from tests.test_replication import PEER_FIXTURE, STATUS_FIXTURE
from tests.test_schemas import ENTITY_SCHEMA_FIXTURE


NODE_FIXTURE: dict[str, Any] = {
    "node": {
        "meta": {
            "id": "node_x",
            "type_id": "test",
            "created_at": "2026-01-01T00:00:00Z",
            "updated_at": "2026-01-01T00:00:00Z",
            "version": 1,
            "alive": True,
        },
        "properties": {"hello": "world"},
    }
}


# === Ingest ===


def test_sync_ingest_signal(
    hy_sync: HydraSync, respx_mock: respx.MockRouter
) -> None:
    respx_mock.post("https://hydra.test/ingest").mock(
        return_value=httpx.Response(
            200,
            json={
                "cascade_id": "csc_a",
                "event_ids": ["evt_1"],
                "event_count": 1,
                "idempotent_hit": False,
            },
        )
    )
    resp = hy_sync.ingest_signal(name="cloudtrail/X", source="node_x")
    assert resp.event_ids == ["evt_1"]
    assert resp.cascade_id == "csc_a"
    assert resp.idempotent_hit is False


def test_sync_ingest_signal_sends_idempotency_key(
    hy_sync: HydraSync, respx_mock: respx.MockRouter
) -> None:
    route = respx_mock.post("https://hydra.test/ingest").mock(
        return_value=httpx.Response(
            200,
            json={"event_ids": [], "event_count": 0, "idempotent_hit": True},
        )
    )
    hy_sync.ingest_signal(
        name="X", source="node_x", idempotency_key="dedup_001"
    )
    assert route.calls.last.request.headers["Idempotency-Key"] == "dedup_001"


def test_sync_propose_claim_builds_event_kind(
    hy_sync: HydraSync, respx_mock: respx.MockRouter
) -> None:
    """Verify the body shape — `ClaimProposed` event wrapping a Claim
    with the externally-tagged subject + object."""
    route = respx_mock.post("https://hydra.test/ingest").mock(
        return_value=httpx.Response(
            200,
            json={"event_ids": ["evt_1"], "event_count": 1, "idempotent_hit": False},
        )
    )
    hy_sync.propose_claim(
        claim_id="claim_001",
        subject=ClaimSubject.dataset("orders_daily"),
        predicate="is_stale",
        object=ClaimObject.value(True),
        created_by="actor_x",
        kind="AnomalyFinding",
        confidence=0.9,
    )
    import json

    body = json.loads(route.calls.last.request.content)
    inner = body["event_kind"]["ClaimProposed"]["claim"]
    assert inner["id"] == "claim_001"
    assert inner["subject"] == {"Dataset": "orders_daily"}
    assert inner["object"] == {"Value": True}
    assert inner["kind"] == "AnomalyFinding"


def test_sync_add_evidence(
    hy_sync: HydraSync, respx_mock: respx.MockRouter
) -> None:
    respx_mock.post("https://hydra.test/ingest").mock(
        return_value=httpx.Response(
            200,
            json={"event_ids": ["evt_1"], "event_count": 1, "idempotent_hit": False},
        )
    )
    resp = hy_sync.add_evidence(
        evidence_id="evd_001",
        source=EvidenceSource.warehouse(system="snowflake", table="orders"),
        payload_kind="row_count",
        payload_data={"count": 1500},
        reliability=0.85,
    )
    assert resp.event_count == 1


def test_sync_propose_action(
    hy_sync: HydraSync, respx_mock: respx.MockRouter
) -> None:
    respx_mock.post("https://hydra.test/ingest").mock(
        return_value=httpx.Response(
            200,
            json={"event_ids": ["evt_1"], "event_count": 1, "idempotent_hit": False},
        )
    )
    resp = hy_sync.propose_action(
        action_id="act_001",
        kind="Backfill",
        targets=[{"Dataset": "orders_daily"}],
        proposed_by="actor_x",
    )
    assert resp.event_count == 1


# === Query ===


def test_sync_get_node(
    hy_sync: HydraSync, respx_mock: respx.MockRouter
) -> None:
    respx_mock.get("https://hydra.test/query/nodes/node_x").mock(
        return_value=httpx.Response(200, json=NODE_FIXTURE)
    )
    node = hy_sync.get_node("node_x")
    assert node.meta.id == "node_x"
    assert node.properties == {"hello": "world"}


def test_sync_get_node_404_raises_not_found(
    hy_sync: HydraSync, respx_mock: respx.MockRouter
) -> None:
    """Critical — error mapping reaches the sync surface unchanged."""
    respx_mock.get("https://hydra.test/query/nodes/missing").mock(
        return_value=httpx.Response(404, json={"error": "node not found"})
    )
    with pytest.raises(HydraNotFoundError):
        hy_sync.get_node("missing")


def test_sync_list_claims_by_status(
    hy_sync: HydraSync, respx_mock: respx.MockRouter
) -> None:
    respx_mock.get("https://hydra.test/query/claims/status/Verified").mock(
        return_value=httpx.Response(200, json={"claims": []})
    )
    claims = hy_sync.list_claims(status="Verified")
    assert claims == []


def test_sync_list_claims_rejects_both_filters(
    hy_sync: HydraSync,
) -> None:
    """Both clients raise ValueError for the same misconfiguration."""
    with pytest.raises(ValueError):
        hy_sync.list_claims(status="Verified", kind="Fact")


# === Lineage ===


def test_sync_lineage(
    hy_sync: HydraSync, respx_mock: respx.MockRouter
) -> None:
    respx_mock.get("https://hydra.test/lineage/evt_seed").mock(
        return_value=httpx.Response(200, json=LINEAGE_FIXTURE)
    )
    lin = hy_sync.lineage("evt_seed", depth=10)
    assert lin.seed_event_id == "evt_seed"
    assert lin.depth == 10


# === Diagnostics namespace ===


def test_sync_diagnostics_anomaly(
    hy_sync: HydraSync, respx_mock: respx.MockRouter
) -> None:
    respx_mock.get("https://hydra.test/diagnostics/anomaly").mock(
        return_value=httpx.Response(200, json=ANOMALY_RESPONSE_OK)
    )
    resp = hy_sync.diagnostics.anomaly()
    assert resp.anomaly_count == 1


def test_sync_diagnostics_coverage(
    hy_sync: HydraSync, respx_mock: respx.MockRouter
) -> None:
    respx_mock.get("https://hydra.test/diagnostics/coverage").mock(
        return_value=httpx.Response(200, json=COVERAGE_RESPONSE_OK)
    )
    resp = hy_sync.diagnostics.coverage()
    assert resp.model_count == 1


def test_sync_diagnostics_counterfactual(
    hy_sync: HydraSync, respx_mock: respx.MockRouter
) -> None:
    respx_mock.get("https://hydra.test/diagnostics/counterfactual/evt_abc").mock(
        return_value=httpx.Response(200, json=COUNTERFACTUAL_FULL_RESPONSE)
    )
    resp = hy_sync.diagnostics.counterfactual("evt_abc", include_diff=True)
    assert resp.diff is not None


def test_sync_diagnostics_evolution(
    hy_sync: HydraSync, respx_mock: respx.MockRouter
) -> None:
    respx_mock.get("https://hydra.test/diagnostics/evolution").mock(
        return_value=httpx.Response(200, json=EVOLUTION_RESPONSE_NO_LOGS)
    )
    resp = hy_sync.diagnostics.evolution()
    assert resp.subscription_count >= 0
    # Pin the Patch-3 semantic: fire_log/miss_log are None when caller
    # didn't request include_logs. Sync side honors it identically.
    if resp.metrics:
        assert resp.metrics[0].fire_log is None
        assert resp.metrics[0].miss_log is None


# === Schemas namespace ===


def test_sync_schemas_get_entity(
    hy_sync: HydraSync, respx_mock: respx.MockRouter
) -> None:
    respx_mock.get("https://hydra.test/schemas/entity/type_invoice").mock(
        return_value=httpx.Response(200, json=ENTITY_SCHEMA_FIXTURE)
    )
    schema = hy_sync.schemas.get_entity("type_invoice")
    assert schema.type_id == "type_invoice"


def test_sync_schemas_list_active(
    hy_sync: HydraSync, respx_mock: respx.MockRouter
) -> None:
    respx_mock.get("https://hydra.test/schemas/active").mock(
        return_value=httpx.Response(
            200, json={"schemas": [{"EntityType": ENTITY_SCHEMA_FIXTURE}]}
        )
    )
    schemas = hy_sync.schemas.list_active()
    assert len(schemas) == 1
    assert "EntityType" in schemas[0]


def test_sync_schemas_register_entity_sends_tenant(
    hy_sync: HydraSync, respx_mock: respx.MockRouter
) -> None:
    route = respx_mock.post("https://hydra.test/schemas/entity").mock(
        return_value=httpx.Response(201, json={"schema_id": "sch_new"})
    )
    sid = hy_sync.schemas.register_entity(
        type_id="type_x",
        name="X",
        fields=[FieldSchema(name="amount", value_type="Float", required=True)],
    )
    assert sid == "sch_new"
    assert route.calls.last.request.headers["X-Hydra-Tenant"] == "tenant_test"


def test_sync_schemas_register_with_recursive_value_type(
    hy_sync: HydraSync, respx_mock: respx.MockRouter
) -> None:
    """Sync side handles `ValueTypeOf.list_of(ValueTypeOf.custom(...))`
    exactly the same as async — wire shape is data, not flow control."""
    route = respx_mock.post("https://hydra.test/schemas/claim-predicate").mock(
        return_value=httpx.Response(201, json={"schema_id": "sch_pred"})
    )
    hy_sync.schemas.register_claim_predicate(
        predicate="references",
        object_type=ValueTypeOf.list_of(ValueTypeOf.custom("type_invoice")),
    )
    import json

    body = json.loads(route.calls.last.request.content)
    assert body["object_type"] == {"List": {"Custom": "type_invoice"}}


def test_sync_schemas_disable_handles_204(
    hy_sync: HydraSync, respx_mock: respx.MockRouter
) -> None:
    respx_mock.post("https://hydra.test/schemas/sch_x/disable").mock(
        return_value=httpx.Response(204)
    )
    result = hy_sync.schemas.disable("sch_x", reason="superseded")
    assert result is None


def test_sync_schemas_archive_handles_204(
    hy_sync: HydraSync, respx_mock: respx.MockRouter
) -> None:
    respx_mock.post("https://hydra.test/schemas/sch_x/archive").mock(
        return_value=httpx.Response(204)
    )
    result = hy_sync.schemas.archive("sch_x")
    assert result is None


def test_sync_schemas_validate_action_does_not_raise_on_invalid(
    hy_sync: HydraSync, respx_mock: respx.MockRouter
) -> None:
    """**Critical sync semantic** — validate returns ValidationResponse,
    never raises on `valid: False`. Pin this so a future patch doesn't
    add an `if not valid: raise` shortcut to the sync class."""
    respx_mock.post("https://hydra.test/schemas/validate/action").mock(
        return_value=httpx.Response(
            200,
            json={
                "valid": False,
                "schema_id": "sch_act",
                "errors": [
                    {"schema_id": "sch_act", "path": "amount", "message": "wrong type"}
                ],
            },
        )
    )
    report = hy_sync.schemas.validate_action({"kind": "X"})
    assert report.valid is False
    assert len(report.errors) == 1
    assert report.errors[0].path == "amount"


def test_sync_schemas_validate_edge_update_404_raises(
    hy_sync: HydraSync, respx_mock: respx.MockRouter
) -> None:
    """`validate_edge_update` is the only validator that 404s. Verify
    the sync path raises the same typed exception."""
    respx_mock.post("https://hydra.test/schemas/validate/edge-update").mock(
        return_value=httpx.Response(404, json={"error": "edge not found"})
    )
    with pytest.raises(HydraNotFoundError):
        hy_sync.schemas.validate_edge_update(
            edge_id="edge_missing", changes={"v": 1}
        )


# === Replication namespace ===


def test_sync_replication_status(
    hy_sync: HydraSync, respx_mock: respx.MockRouter
) -> None:
    respx_mock.get("https://hydra.test/replication/status").mock(
        return_value=httpx.Response(200, json=STATUS_FIXTURE)
    )
    status = hy_sync.replication.status()
    assert status.role == "Leader"
    assert len(status.peers) == 1


def test_sync_replication_peers(
    hy_sync: HydraSync, respx_mock: respx.MockRouter
) -> None:
    respx_mock.get("https://hydra.test/replication/peers").mock(
        return_value=httpx.Response(200, json={"peers": [PEER_FIXTURE]})
    )
    peers = hy_sync.replication.peers()
    assert peers[0].role == "Follower"


def test_sync_replication_peer_404(
    hy_sync: HydraSync, respx_mock: respx.MockRouter
) -> None:
    respx_mock.get("https://hydra.test/replication/peers/missing").mock(
        return_value=httpx.Response(404, json={"error": "peer not found"})
    )
    with pytest.raises(HydraNotFoundError):
        hy_sync.replication.peer("missing")


def test_sync_replication_peer_lag_null(
    hy_sync: HydraSync, respx_mock: respx.MockRouter
) -> None:
    """**Critical sync semantic** — peer_lag never 404s; lag:None is
    the no-observation state. Same contract as async."""
    respx_mock.get("https://hydra.test/replication/peers/unseen/lag").mock(
        return_value=httpx.Response(
            200, json={"peer_id": "unseen", "lag": None}
        )
    )
    resp = hy_sync.replication.peer_lag("unseen")
    assert resp.lag is None


def test_sync_replication_role(
    hy_sync: HydraSync, respx_mock: respx.MockRouter
) -> None:
    respx_mock.get("https://hydra.test/replication/role").mock(
        return_value=httpx.Response(200, json={"role": "leader"})
    )
    role = hy_sync.replication.role()
    assert role == "leader"


def test_sync_replication_promotion_status_null(
    hy_sync: HydraSync, respx_mock: respx.MockRouter
) -> None:
    respx_mock.get("https://hydra.test/replication/promotion-status").mock(
        return_value=httpx.Response(
            200,
            json={
                "self_peer_id": "replica_self",
                "current_role": "follower",
                "last_promotion": None,
            },
        )
    )
    resp = hy_sync.replication.promotion_status()
    assert resp.last_promotion is None


# === Cross-cutting: tenant override on a namespaced method ===


def test_sync_namespace_tenant_override(
    hy_sync: HydraSync, respx_mock: respx.MockRouter
) -> None:
    """Per-call tenant on namespaced methods works the same on sync."""
    route = respx_mock.get("https://hydra.test/schemas/entity/type_x").mock(
        return_value=httpx.Response(200, json=ENTITY_SCHEMA_FIXTURE)
    )
    hy_sync.schemas.get_entity("type_x", tenant="tenant_other")
    assert route.calls.last.request.headers["X-Hydra-Tenant"] == "tenant_other"


# === Cross-cutting: error mapping returns the same exception types ===


def test_sync_400_on_register_raises_validation_error(
    hy_sync: HydraSync, respx_mock: respx.MockRouter
) -> None:
    respx_mock.post("https://hydra.test/schemas/entity").mock(
        return_value=httpx.Response(
            400, json={"error": "failed to register entity schema: dup"}
        )
    )
    with pytest.raises(HydraValidationError):
        hy_sync.schemas.register_entity(
            type_id="type_x", name="X", fields=[]
        )
