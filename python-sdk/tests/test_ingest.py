"""Tests for the 4 ingest helper methods.

Each helper constructs the right `EventKind` shape, wraps it in
`{"event_kind": ...}`, POSTs to `/ingest`, and parses the
`IngestResponse`.

Tests verify:
  - The POST body matches the engine's expected EventKind shape
  - Idempotency-Key header is set when provided, omitted when absent
  - Tenant header default + per-call override
  - 200 returns a parsed IngestResponse
  - 409 (follower) → HydraReadOnlyFollowerError
  - 400 (validation) → HydraValidationError with body preserved
"""

from __future__ import annotations

import json

import httpx
import pytest
import respx

from hydra import (
    ActionTarget,
    ClaimObject,
    ClaimSubject,
    EvidenceSource,
    Hydra,
    HydraReadOnlyFollowerError,
    HydraValidationError,
)


INGEST_OK = {
    "cascade_id": "csc_abc",
    "event_ids": ["evt_abc"],
    "event_count": 1,
    "idempotent_hit": False,
}


# === ingest_signal ===


@pytest.mark.asyncio
async def test_ingest_signal_builds_correct_event_kind(
    hy: Hydra, respx_mock: respx.MockRouter
) -> None:
    route = respx_mock.post("https://hydra.test/ingest").mock(
        return_value=httpx.Response(200, json=INGEST_OK)
    )
    resp = await hy.ingest_signal(
        name="cloudtrail/CreateBucket",
        source="node_aws_acct",
        payload={"region": "us-east-1"},
    )
    assert resp.cascade_id == "csc_abc"
    assert resp.event_ids == ["evt_abc"]
    body = json.loads(route.calls.last.request.content)
    assert body == {
        "event_kind": {
            "Signal": {
                "source": "node_aws_acct",
                "name": "cloudtrail/CreateBucket",
                "payload": {"region": "us-east-1"},
            }
        }
    }


@pytest.mark.asyncio
async def test_ingest_signal_payload_defaults_to_empty(
    hy: Hydra, respx_mock: respx.MockRouter
) -> None:
    route = respx_mock.post("https://hydra.test/ingest").mock(
        return_value=httpx.Response(200, json=INGEST_OK)
    )
    await hy.ingest_signal(name="x", source="node_y")
    body = json.loads(route.calls.last.request.content)
    assert body["event_kind"]["Signal"]["payload"] == {}


@pytest.mark.asyncio
async def test_ingest_signal_sets_idempotency_key_header_when_provided(
    hy: Hydra, respx_mock: respx.MockRouter
) -> None:
    route = respx_mock.post("https://hydra.test/ingest").mock(
        return_value=httpx.Response(200, json=INGEST_OK)
    )
    await hy.ingest_signal(name="x", source="node_y", idempotency_key="op-12345")
    request = route.calls.last.request
    assert request.headers["Idempotency-Key"] == "op-12345"


@pytest.mark.asyncio
async def test_ingest_signal_omits_idempotency_key_header_when_absent(
    hy: Hydra, respx_mock: respx.MockRouter
) -> None:
    route = respx_mock.post("https://hydra.test/ingest").mock(
        return_value=httpx.Response(200, json=INGEST_OK)
    )
    await hy.ingest_signal(name="x", source="node_y")
    request = route.calls.last.request
    assert "Idempotency-Key" not in request.headers


@pytest.mark.asyncio
async def test_ingest_signal_tenant_override(
    hy: Hydra, respx_mock: respx.MockRouter
) -> None:
    route = respx_mock.post("https://hydra.test/ingest").mock(
        return_value=httpx.Response(200, json=INGEST_OK)
    )
    await hy.ingest_signal(name="x", source="node_y", tenant="tenant_other")
    request = route.calls.last.request
    assert request.headers["X-Hydra-Tenant"] == "tenant_other"


# === propose_claim ===


@pytest.mark.asyncio
async def test_propose_claim_builds_correct_event_kind(
    hy: Hydra, respx_mock: respx.MockRouter
) -> None:
    route = respx_mock.post("https://hydra.test/ingest").mock(
        return_value=httpx.Response(200, json=INGEST_OK)
    )
    await hy.propose_claim(
        claim_id="claim_anom_001",
        subject=ClaimSubject.dataset("revenue_daily"),
        predicate="is_stale",
        object=ClaimObject.value(True),
        created_by="actor_agent",
        kind="AnomalyFinding",
        confidence=0.91,
    )
    body = json.loads(route.calls.last.request.content)
    claim = body["event_kind"]["ClaimProposed"]["claim"]
    assert claim["id"] == "claim_anom_001"
    assert claim["subject"] == {"Dataset": "revenue_daily"}
    assert claim["predicate"] == "is_stale"
    assert claim["object"] == {"Value": True}
    assert claim["kind"] == "AnomalyFinding"
    assert claim["confidence"] == 0.91
    assert claim["status"] == "Proposed"
    assert claim["created_by"] == "actor_agent"
    # tenant_id mirrors the client's default unless overridden.
    assert claim["tenant_id"] == "tenant_test"


@pytest.mark.asyncio
async def test_propose_claim_default_kind_and_status(
    hy: Hydra, respx_mock: respx.MockRouter
) -> None:
    route = respx_mock.post("https://hydra.test/ingest").mock(
        return_value=httpx.Response(200, json=INGEST_OK)
    )
    await hy.propose_claim(
        claim_id="claim_x",
        subject=ClaimSubject.dataset("d"),
        predicate="p",
        object=ClaimObject.value(1),
        created_by="actor_y",
    )
    claim = json.loads(route.calls.last.request.content)["event_kind"]["ClaimProposed"][
        "claim"
    ]
    # Defaults per the method signature.
    assert claim["kind"] == "Inference"
    assert claim["status"] == "Proposed"
    assert claim["confidence"] == 1.0


# === add_evidence ===


@pytest.mark.asyncio
async def test_add_evidence_builds_correct_event_kind(
    hy: Hydra, respx_mock: respx.MockRouter
) -> None:
    route = respx_mock.post("https://hydra.test/ingest").mock(
        return_value=httpx.Response(200, json=INGEST_OK)
    )
    await hy.add_evidence(
        evidence_id="evd_001",
        source=EvidenceSource.warehouse(system="snowflake", table="orders"),
        payload_kind="row_count_delta",
        payload_data={"delta": -42},
        reliability=0.8,
    )
    evidence = json.loads(route.calls.last.request.content)["event_kind"][
        "EvidenceAdded"
    ]["evidence"]
    assert evidence["id"] == "evd_001"
    assert evidence["source"] == {
        "Warehouse": {
            "system": "snowflake",
            "database": None,
            "schema": None,
            "table": "orders",
        }
    }
    assert evidence["payload"] == {"kind": "row_count_delta", "data": {"delta": -42}}
    assert evidence["reliability"] == 0.8


# === propose_action ===


@pytest.mark.asyncio
async def test_propose_action_with_simple_kind(
    hy: Hydra, respx_mock: respx.MockRouter
) -> None:
    route = respx_mock.post("https://hydra.test/ingest").mock(
        return_value=httpx.Response(200, json=INGEST_OK)
    )
    await hy.propose_action(
        action_id="act_001",
        kind="Quarantine",
        targets=[ActionTarget.dataset("d1"), ActionTarget.node("node_x")],
        proposed_by="actor_agent",
        related_claims=["claim_a"],
        payload={"reason": "stale"},
    )
    action = json.loads(route.calls.last.request.content)["event_kind"][
        "ActionProposed"
    ]["action"]
    assert action["id"] == "act_001"
    assert action["kind"] == "Quarantine"
    assert action["targets"] == [{"Dataset": "d1"}, {"Node": "node_x"}]
    assert action["status"] == "Proposed"
    assert action["proposed_by"] == "actor_agent"
    assert action["related_claims"] == ["claim_a"]
    assert action["payload"] == {"reason": "stale"}


@pytest.mark.asyncio
async def test_propose_action_with_custom_kind(
    hy: Hydra, respx_mock: respx.MockRouter
) -> None:
    """`ActionKind::Custom(String)` serializes as
    `{"Custom": "my_thing"}`. The SDK accepts this shape directly
    since `kind` is typed as `str | dict[str, Any]`."""
    route = respx_mock.post("https://hydra.test/ingest").mock(
        return_value=httpx.Response(200, json=INGEST_OK)
    )
    await hy.propose_action(
        action_id="act_002",
        kind={"Custom": "my_special_workflow"},
        targets=[ActionTarget.system("s1")],
        proposed_by="actor_y",
    )
    action = json.loads(route.calls.last.request.content)["event_kind"][
        "ActionProposed"
    ]["action"]
    assert action["kind"] == {"Custom": "my_special_workflow"}


# === Error mapping ===


@pytest.mark.asyncio
async def test_ingest_409_raises_read_only_follower(
    hy: Hydra, respx_mock: respx.MockRouter
) -> None:
    """V2 P4H semantics — a follower returns 409 with the standard
    `{"error": "follower is read-only"}` body. Agents catch
    HydraReadOnlyFollowerError to know they hit a non-leader."""
    respx_mock.post("https://hydra.test/ingest").mock(
        return_value=httpx.Response(409, json={"error": "follower is read-only"})
    )
    with pytest.raises(HydraReadOnlyFollowerError) as exc_info:
        await hy.ingest_signal(name="x", source="node_y")
    assert exc_info.value.body == {"error": "follower is read-only"}


@pytest.mark.asyncio
async def test_ingest_400_raises_validation_error_with_body_preserved(
    hy: Hydra, respx_mock: respx.MockRouter
) -> None:
    """Engine 400s carry a structured error body — the SDK preserves
    it verbatim on `HydraValidationError.body` per Rule #8."""
    respx_mock.post("https://hydra.test/ingest").mock(
        return_value=httpx.Response(400, json={"error": "tenant header required"})
    )
    with pytest.raises(HydraValidationError) as exc_info:
        await hy.ingest_signal(name="x", source="node_y")
    assert exc_info.value.body == {"error": "tenant header required"}
