"""Tests for `hy.schemas.*` — schema register / read / lifecycle / validate.

Verifies:
  - Reads return typed models; lists return raw dicts (per design)
  - Registers send tenant header, return `schema_id` string
  - Lifecycle (disable/archive) handles 204 No Content
  - Validate methods never raise on `valid: False`
  - Validate-edge-update is the only validator that can 404
  - Per-call tenant override works on every method
"""

from __future__ import annotations

from typing import Any

import httpx
import pytest
import respx

from hydra import (
    EntityTypeSchema,
    FieldSchema,
    Hydra,
    HydraNotFoundError,
    ValidationResponse,
    ValueTypeOf,
)


# === Schema record fixtures (single-fetch responses) ===

ENTITY_SCHEMA_FIXTURE: dict[str, Any] = {
    "id": "sch_entity_001",
    "tenant_id": "tenant_test",
    "type_id": "type_invoice",
    "name": "Invoice",
    "status": "Active",
    "fields": [
        {
            "name": "amount",
            "value_type": "Float",
            "required": True,
            "default_value": None,
            "description": None,
            "metadata": {},
        },
        {
            "name": "currency",
            "value_type": "String",
            "required": True,
            "default_value": None,
            "description": None,
            "metadata": {},
        },
    ],
    "created_by": "actor_admin",
    "created_at": "2026-01-01T00:00:00Z",
    "updated_at": "2026-01-01T00:00:00Z",
    "metadata": {},
}


EDGE_SCHEMA_FIXTURE: dict[str, Any] = {
    "id": "sch_edge_001",
    "tenant_id": "tenant_test",
    "type_id": "type_depends_on",
    "name": "DependsOn",
    "status": "Active",
    "fields": [],
    "created_by": "actor_admin",
    "created_at": "2026-01-01T00:00:00Z",
    "updated_at": "2026-01-01T00:00:00Z",
    "metadata": {},
}


CLAIM_PREDICATE_SCHEMA_FIXTURE: dict[str, Any] = {
    "id": "sch_claim_001",
    "tenant_id": "tenant_test",
    "predicate": "is_stale",
    "status": "Active",
    "subject_type": "type_dataset",
    "object_type": "Bool",
    "allowed_claim_kinds": ["AnomalyFinding", "Inference"],
    "created_by": "actor_admin",
    "created_at": "2026-01-01T00:00:00Z",
    "updated_at": "2026-01-01T00:00:00Z",
    "metadata": {},
}


# === Reads ===


@pytest.mark.asyncio
async def test_get_entity_returns_typed_schema(
    hy: Hydra, respx_mock: respx.MockRouter
) -> None:
    respx_mock.get("https://hydra.test/schemas/entity/type_invoice").mock(
        return_value=httpx.Response(200, json=ENTITY_SCHEMA_FIXTURE)
    )
    schema = await hy.schemas.get_entity("type_invoice")
    assert isinstance(schema, EntityTypeSchema)
    assert schema.id == "sch_entity_001"
    assert schema.type_id == "type_invoice"
    assert schema.status == "Active"
    assert len(schema.fields) == 2
    assert schema.fields[0].name == "amount"
    assert schema.fields[0].value_type == "Float"


@pytest.mark.asyncio
async def test_get_entity_404_raises_not_found(
    hy: Hydra, respx_mock: respx.MockRouter
) -> None:
    respx_mock.get("https://hydra.test/schemas/entity/type_missing").mock(
        return_value=httpx.Response(404, json={"error": "entity schema not found"})
    )
    with pytest.raises(HydraNotFoundError):
        await hy.schemas.get_entity("type_missing")


@pytest.mark.asyncio
async def test_get_edge_returns_typed_schema(
    hy: Hydra, respx_mock: respx.MockRouter
) -> None:
    respx_mock.get("https://hydra.test/schemas/edge/type_depends_on").mock(
        return_value=httpx.Response(200, json=EDGE_SCHEMA_FIXTURE)
    )
    schema = await hy.schemas.get_edge("type_depends_on")
    assert schema.id == "sch_edge_001"
    assert schema.name == "DependsOn"


@pytest.mark.asyncio
async def test_get_claim_predicate_subject_type_optional(
    hy: Hydra, respx_mock: respx.MockRouter
) -> None:
    """`subject_type=None` is the "predicate accepts any entity type"
    case. Test that the SDK round-trips it cleanly."""
    no_subject = {**CLAIM_PREDICATE_SCHEMA_FIXTURE, "subject_type": None}
    respx_mock.get("https://hydra.test/schemas/claim/is_flagged").mock(
        return_value=httpx.Response(200, json=no_subject)
    )
    schema = await hy.schemas.get_claim_predicate("is_flagged")
    assert schema.subject_type is None
    assert schema.predicate == "is_stale"


@pytest.mark.asyncio
async def test_list_active_returns_raw_dicts(
    hy: Hydra, respx_mock: respx.MockRouter
) -> None:
    """List endpoints return `list[dict]`. The server's
    `SchemaDefinition` is externally-tagged, so each item is a
    single-key dict like `{"EntityType": {...}}`. Per Patch 4
    design, the SDK does not fake-type the union."""
    body = {
        "schemas": [
            {"EntityType": ENTITY_SCHEMA_FIXTURE},
            {"EdgeType": EDGE_SCHEMA_FIXTURE},
        ]
    }
    respx_mock.get("https://hydra.test/schemas/active").mock(
        return_value=httpx.Response(200, json=body)
    )
    schemas = await hy.schemas.list_active()
    assert isinstance(schemas, list)
    assert len(schemas) == 2
    # The external tag is the only way to discriminate entity vs edge.
    assert "EntityType" in schemas[0]
    assert "EdgeType" in schemas[1]
    assert schemas[0]["EntityType"]["type_id"] == "type_invoice"


@pytest.mark.asyncio
async def test_list_disabled_and_archived_routed(
    hy: Hydra, respx_mock: respx.MockRouter
) -> None:
    respx_mock.get("https://hydra.test/schemas/disabled").mock(
        return_value=httpx.Response(200, json={"schemas": []})
    )
    respx_mock.get("https://hydra.test/schemas/archived").mock(
        return_value=httpx.Response(200, json={"schemas": []})
    )
    assert await hy.schemas.list_disabled() == []
    assert await hy.schemas.list_archived() == []


# === Registers ===


@pytest.mark.asyncio
async def test_register_entity_returns_schema_id_and_sends_tenant(
    hy: Hydra, respx_mock: respx.MockRouter
) -> None:
    route = respx_mock.post("https://hydra.test/schemas/entity").mock(
        return_value=httpx.Response(201, json={"schema_id": "sch_new_001"})
    )
    schema_id = await hy.schemas.register_entity(
        type_id="type_invoice",
        name="Invoice",
        fields=[FieldSchema(name="amount", value_type="Float", required=True)],
    )
    assert schema_id == "sch_new_001"
    request = route.calls.last.request
    assert request.headers["X-Hydra-Tenant"] == "tenant_test"
    # Body shape: fields serialized as dicts.
    import json

    body = json.loads(request.content)
    assert body["type_id"] == "type_invoice"
    assert body["name"] == "Invoice"
    assert body["fields"][0]["name"] == "amount"
    assert body["fields"][0]["value_type"] == "Float"
    assert body["fields"][0]["required"] is True


@pytest.mark.asyncio
async def test_register_entity_accepts_field_dicts(
    hy: Hydra, respx_mock: respx.MockRouter
) -> None:
    """`fields=` may be either typed `FieldSchema` instances or
    pre-built dicts — both should serialize to the same wire shape."""
    route = respx_mock.post("https://hydra.test/schemas/entity").mock(
        return_value=httpx.Response(201, json={"schema_id": "sch_x"})
    )
    await hy.schemas.register_entity(
        type_id="type_x",
        name="X",
        fields=[
            {
                "name": "v",
                "value_type": "Int",
                "required": True,
                "default_value": None,
                "description": None,
                "metadata": {},
            }
        ],
    )
    import json

    body = json.loads(route.calls.last.request.content)
    assert body["fields"][0]["name"] == "v"


@pytest.mark.asyncio
async def test_register_edge_returns_schema_id(
    hy: Hydra, respx_mock: respx.MockRouter
) -> None:
    respx_mock.post("https://hydra.test/schemas/edge").mock(
        return_value=httpx.Response(201, json={"schema_id": "sch_edge_new"})
    )
    sid = await hy.schemas.register_edge(
        type_id="type_t", name="T", fields=[]
    )
    assert sid == "sch_edge_new"


@pytest.mark.asyncio
async def test_register_evidence_returns_schema_id(
    hy: Hydra, respx_mock: respx.MockRouter
) -> None:
    respx_mock.post("https://hydra.test/schemas/evidence").mock(
        return_value=httpx.Response(201, json={"schema_id": "sch_evd_new"})
    )
    sid = await hy.schemas.register_evidence(
        kind="bank_transaction",
        fields=[FieldSchema(name="amount", value_type="Float", required=True)],
    )
    assert sid == "sch_evd_new"


@pytest.mark.asyncio
async def test_register_claim_predicate_with_recursive_value_type(
    hy: Hydra, respx_mock: respx.MockRouter
) -> None:
    """`object_type` accepts a recursive ValueType built via
    `ValueTypeOf` helpers. Wire form must serialize the recursion
    exactly."""
    route = respx_mock.post("https://hydra.test/schemas/claim-predicate").mock(
        return_value=httpx.Response(201, json={"schema_id": "sch_pred_new"})
    )
    sid = await hy.schemas.register_claim_predicate(
        predicate="references",
        object_type=ValueTypeOf.list_of(ValueTypeOf.custom("type_invoice")),
        subject_type="type_dataset",
        allowed_claim_kinds=["Inference"],
    )
    assert sid == "sch_pred_new"
    import json

    body = json.loads(route.calls.last.request.content)
    assert body["predicate"] == "references"
    assert body["object_type"] == {"List": {"Custom": "type_invoice"}}
    assert body["subject_type"] == "type_dataset"


@pytest.mark.asyncio
async def test_register_claim_predicate_null_subject(
    hy: Hydra, respx_mock: respx.MockRouter
) -> None:
    """`subject_type=None` round-trips as JSON null."""
    route = respx_mock.post("https://hydra.test/schemas/claim-predicate").mock(
        return_value=httpx.Response(201, json={"schema_id": "sch_pred_null"})
    )
    await hy.schemas.register_claim_predicate(
        predicate="is_flagged", object_type="Bool"
    )
    import json

    body = json.loads(route.calls.last.request.content)
    assert body["subject_type"] is None


@pytest.mark.asyncio
async def test_register_action_and_policy_condition(
    hy: Hydra, respx_mock: respx.MockRouter
) -> None:
    respx_mock.post("https://hydra.test/schemas/action").mock(
        return_value=httpx.Response(201, json={"schema_id": "sch_act_new"})
    )
    respx_mock.post("https://hydra.test/schemas/policy-condition").mock(
        return_value=httpx.Response(201, json={"schema_id": "sch_pol_new"})
    )
    sid_a = await hy.schemas.register_action(
        action_kind="PostLedgerEntry", fields=[]
    )
    sid_p = await hy.schemas.register_policy_condition(
        policy_kind="AutoApproval", fields=[]
    )
    assert sid_a == "sch_act_new"
    assert sid_p == "sch_pol_new"


# === Lifecycle (204 No Content) ===


@pytest.mark.asyncio
async def test_disable_handles_204_no_content(
    hy: Hydra, respx_mock: respx.MockRouter
) -> None:
    """Disable returns 204 with empty body. The SDK should not
    explode trying to parse an empty body as JSON."""
    route = respx_mock.post("https://hydra.test/schemas/sch_x/disable").mock(
        return_value=httpx.Response(204)
    )
    result = await hy.schemas.disable("sch_x", reason="superseded")
    assert result is None
    import json

    body = json.loads(route.calls.last.request.content)
    assert body == {"reason": "superseded"}


@pytest.mark.asyncio
async def test_archive_handles_204_no_content(
    hy: Hydra, respx_mock: respx.MockRouter
) -> None:
    route = respx_mock.post("https://hydra.test/schemas/sch_x/archive").mock(
        return_value=httpx.Response(204)
    )
    result = await hy.schemas.archive("sch_x")
    assert result is None
    import json

    body = json.loads(route.calls.last.request.content)
    assert body == {"reason": None}


# === Validate ===

VALID_PAYLOAD_RESPONSE: dict[str, Any] = {
    "valid": True,
    "schema_id": "sch_action_001",
    "errors": [],
}

INVALID_PAYLOAD_RESPONSE: dict[str, Any] = {
    "valid": False,
    "schema_id": "sch_action_001",
    "errors": [
        {
            "schema_id": "sch_action_001",
            "path": "amount",
            "message": "expected Float, got String",
        }
    ],
}


@pytest.mark.asyncio
async def test_validate_action_returns_validation_response(
    hy: Hydra, respx_mock: respx.MockRouter
) -> None:
    respx_mock.post("https://hydra.test/schemas/validate/action").mock(
        return_value=httpx.Response(200, json=VALID_PAYLOAD_RESPONSE)
    )
    report = await hy.schemas.validate_action(
        {
            "id": "act_001",
            "tenant_id": None,
            "kind": "PostLedgerEntry",
            "status": "Proposed",
            "targets": [],
            "related_claims": [],
            "supporting_evidence": [],
            "proposed_by": "actor_x",
            "approved_by": None,
            "policy_id": None,
            "payload": {"amount": 100.0, "account": "Cash"},
            "created_at": "2026-01-01T00:00:00Z",
            "updated_at": "2026-01-01T00:00:00Z",
            "approved_at": None,
            "executed_at": None,
            "caused_by": None,
        }
    )
    assert isinstance(report, ValidationResponse)
    assert report.valid is True
    assert report.errors == []


@pytest.mark.asyncio
async def test_validate_action_does_NOT_raise_on_invalid(
    hy: Hydra, respx_mock: respx.MockRouter
) -> None:
    """The SDK returns a `ValidationResponse(valid=False, ...)` —
    validation failure is NOT a transport error. Pin this so a future
    patch doesn't mistakenly add an `if not valid: raise` shortcut."""
    respx_mock.post("https://hydra.test/schemas/validate/action").mock(
        return_value=httpx.Response(200, json=INVALID_PAYLOAD_RESPONSE)
    )
    report = await hy.schemas.validate_action({"kind": "X"})
    assert report.valid is False
    assert len(report.errors) == 1
    assert report.errors[0].path == "amount"
    assert "expected Float" in report.errors[0].message


@pytest.mark.asyncio
async def test_validate_action_schema_id_optional(
    hy: Hydra, respx_mock: respx.MockRouter
) -> None:
    """If no schema is registered for the payload's kind, server
    returns `valid: true` with `schema_id: null` (permissive)."""
    respx_mock.post("https://hydra.test/schemas/validate/action").mock(
        return_value=httpx.Response(
            200, json={"valid": True, "schema_id": None, "errors": []}
        )
    )
    report = await hy.schemas.validate_action({"kind": "Unknown"})
    assert report.valid is True
    assert report.schema_id is None


@pytest.mark.asyncio
async def test_validate_node_create_and_update(
    hy: Hydra, respx_mock: respx.MockRouter
) -> None:
    create_route = respx_mock.post("https://hydra.test/schemas/validate/node-create").mock(
        return_value=httpx.Response(200, json=VALID_PAYLOAD_RESPONSE)
    )
    update_route = respx_mock.post("https://hydra.test/schemas/validate/node-update").mock(
        return_value=httpx.Response(200, json=VALID_PAYLOAD_RESPONSE)
    )
    create_report = await hy.schemas.validate_node_create(
        type_id="type_invoice", properties={"amount": 100.0}
    )
    update_report = await hy.schemas.validate_node_update(
        type_id="type_invoice", changes={"amount": 200.0}
    )
    assert create_report.valid is True
    assert update_report.valid is True
    import json

    create_body = json.loads(create_route.calls.last.request.content)
    update_body = json.loads(update_route.calls.last.request.content)
    assert create_body == {"type_id": "type_invoice", "properties": {"amount": 100.0}}
    assert update_body == {"type_id": "type_invoice", "changes": {"amount": 200.0}}


@pytest.mark.asyncio
async def test_validate_edge_create_and_update(
    hy: Hydra, respx_mock: respx.MockRouter
) -> None:
    respx_mock.post("https://hydra.test/schemas/validate/edge-create").mock(
        return_value=httpx.Response(200, json=VALID_PAYLOAD_RESPONSE)
    )
    update_route = respx_mock.post(
        "https://hydra.test/schemas/validate/edge-update"
    ).mock(return_value=httpx.Response(200, json=VALID_PAYLOAD_RESPONSE))
    await hy.schemas.validate_edge_create(type_id="type_x", properties={})
    await hy.schemas.validate_edge_update(edge_id="edge_001", changes={"weight": 0.5})
    import json

    body = json.loads(update_route.calls.last.request.content)
    assert body == {"edge_id": "edge_001", "changes": {"weight": 0.5}}


@pytest.mark.asyncio
async def test_validate_edge_update_404_raises_not_found(
    hy: Hydra, respx_mock: respx.MockRouter
) -> None:
    """`validate_edge_update` is the only validator that can 404 —
    it needs a live edge in the graph to validate against."""
    respx_mock.post("https://hydra.test/schemas/validate/edge-update").mock(
        return_value=httpx.Response(404, json={"error": "edge not found: edge_x"})
    )
    with pytest.raises(HydraNotFoundError):
        await hy.schemas.validate_edge_update(edge_id="edge_x", changes={"v": 1})


# === Namespace + tenant override ===


@pytest.mark.asyncio
async def test_schemas_namespace_is_single_instance(hy: Hydra) -> None:
    """One `_Schemas` instance per Hydra client, stable across reads."""
    assert hy.schemas is hy.schemas


@pytest.mark.asyncio
async def test_schemas_tenant_override(
    hy: Hydra, respx_mock: respx.MockRouter
) -> None:
    """Rule #7 — per-call tenant on every method including the
    namespaced ones."""
    route = respx_mock.get("https://hydra.test/schemas/entity/type_x").mock(
        return_value=httpx.Response(200, json=ENTITY_SCHEMA_FIXTURE)
    )
    await hy.schemas.get_entity("type_x", tenant="tenant_other")
    assert route.calls.last.request.headers["X-Hydra-Tenant"] == "tenant_other"
