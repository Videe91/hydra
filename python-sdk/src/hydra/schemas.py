"""`hy.schemas.*` — schema register / read / lifecycle / validate.

Per Patch 4 design: thin namespace methods. Each method builds the
request body (or query params), calls `_http`, returns the typed
model. No business logic, no client-side validation.

**Validation methods never raise on `valid: False`** — they return
the full `ValidationResponse` and the caller branches on `.valid`.
Per Rule #8, the engine's verdict is reported verbatim; a "schema
mismatch" is not a transport error.

**List endpoints (`list_active`/`list_disabled`/`list_archived`)
return `list[dict[str, Any]]`.** The server's `Vec<SchemaDefinition>`
is an externally-tagged Rust enum; each list item is a single-key
dict like `{"EntityType": {...}}`, `{"EdgeType": {...}}`,
`{"ClaimPredicate": {...}}`. Entity and edge schemas share the same
inner field shape — the variant tag is the only way to tell them
apart, so we don't fake-type the union. Use the typed single-fetch
getters (`get_entity` etc.) when the variant is known.
"""

from __future__ import annotations

from typing import Any

from . import _paths
from ._http import HydraHttpClient, HydraHttpClientSync
from ._types import (
    Action,
    ActionPayloadSchema,
    Claim,
    ClaimPredicateSchema,
    EdgeId,
    EdgeTypeSchema,
    EntityTypeSchema,
    Evidence,
    EvidencePayloadSchema,
    FieldSchema,
    PolicyConditionSchema,
    SchemaId,
    TenantId,
    TypeId,
    ValidationResponse,
    ValueType,
)


class _Schemas:
    """Namespace for `/schemas/*` HTTP routes."""

    def __init__(
        self, http: HydraHttpClient, default_tenant: TenantId | None
    ) -> None:
        self._http = http
        # `default_tenant` is kept for symmetry with `_Diagnostics` /
        # `_Replication`; HydraHttpClient already applies the client-
        # default tenant when a per-call `tenant=` is omitted.
        self._default_tenant = default_tenant

    # ========================================================================
    # Reads
    # ========================================================================

    async def list_active(
        self, *, tenant: TenantId | None = None
    ) -> list[dict[str, Any]]:
        """List active schemas. See module docstring for the dict shape."""
        raw = await self._http.get(_paths.schemas_active_path(), tenant=tenant)
        return list(raw["schemas"])

    async def list_disabled(
        self, *, tenant: TenantId | None = None
    ) -> list[dict[str, Any]]:
        """List disabled schemas (active → disabled lifecycle state)."""
        raw = await self._http.get(_paths.schemas_disabled_path(), tenant=tenant)
        return list(raw["schemas"])

    async def list_archived(
        self, *, tenant: TenantId | None = None
    ) -> list[dict[str, Any]]:
        """List archived schemas (terminal lifecycle state)."""
        raw = await self._http.get(_paths.schemas_archived_path(), tenant=tenant)
        return list(raw["schemas"])

    async def get_entity(
        self, type_id: TypeId, *, tenant: TenantId | None = None
    ) -> EntityTypeSchema:
        """Get the entity (node) type schema for `type_id`. 404 → HydraNotFoundError."""
        raw = await self._http.get(_paths.schema_entity_path(type_id), tenant=tenant)
        return EntityTypeSchema.model_validate(raw)

    async def get_edge(
        self, type_id: TypeId, *, tenant: TenantId | None = None
    ) -> EdgeTypeSchema:
        """Get the edge (relationship) type schema for `type_id`. 404 → HydraNotFoundError."""
        raw = await self._http.get(_paths.schema_edge_path(type_id), tenant=tenant)
        return EdgeTypeSchema.model_validate(raw)

    async def get_evidence(
        self, kind: str, *, tenant: TenantId | None = None
    ) -> EvidencePayloadSchema:
        """Get the evidence payload schema for `kind`. 404 → HydraNotFoundError."""
        raw = await self._http.get(_paths.schema_evidence_path(kind), tenant=tenant)
        return EvidencePayloadSchema.model_validate(raw)

    async def get_claim_predicate(
        self, predicate: str, *, tenant: TenantId | None = None
    ) -> ClaimPredicateSchema:
        """Get the claim predicate schema for `predicate`. 404 → HydraNotFoundError."""
        raw = await self._http.get(
            _paths.schema_claim_predicate_path(predicate), tenant=tenant
        )
        return ClaimPredicateSchema.model_validate(raw)

    async def get_action(
        self, action_kind: str, *, tenant: TenantId | None = None
    ) -> ActionPayloadSchema:
        """Get the action payload schema for `action_kind`. 404 → HydraNotFoundError."""
        raw = await self._http.get(
            _paths.schema_action_path(action_kind), tenant=tenant
        )
        return ActionPayloadSchema.model_validate(raw)

    async def get_policy(
        self, policy_kind: str, *, tenant: TenantId | None = None
    ) -> PolicyConditionSchema:
        """Get the policy condition schema for `policy_kind`. 404 → HydraNotFoundError."""
        raw = await self._http.get(
            _paths.schema_policy_path(policy_kind), tenant=tenant
        )
        return PolicyConditionSchema.model_validate(raw)

    # ========================================================================
    # Registers (require X-Hydra-Tenant; return SchemaId)
    # ========================================================================

    async def register_entity(
        self,
        *,
        type_id: TypeId,
        name: str,
        fields: list[FieldSchema] | list[dict[str, Any]],
        tenant: TenantId | None = None,
    ) -> SchemaId:
        """Register an entity (node) type schema. Returns the new `schema_id`."""
        body = {
            "type_id": type_id,
            "name": name,
            "fields": _fields_as_dicts(fields),
        }
        raw = await self._http.post(
            _paths.schemas_register_entity_path(), json=body, tenant=tenant
        )
        return raw["schema_id"]

    async def register_edge(
        self,
        *,
        type_id: TypeId,
        name: str,
        fields: list[FieldSchema] | list[dict[str, Any]],
        tenant: TenantId | None = None,
    ) -> SchemaId:
        """Register an edge (relationship) type schema. Returns the new `schema_id`."""
        body = {
            "type_id": type_id,
            "name": name,
            "fields": _fields_as_dicts(fields),
        }
        raw = await self._http.post(
            _paths.schemas_register_edge_path(), json=body, tenant=tenant
        )
        return raw["schema_id"]

    async def register_evidence(
        self,
        *,
        kind: str,
        fields: list[FieldSchema] | list[dict[str, Any]],
        tenant: TenantId | None = None,
    ) -> SchemaId:
        """Register an evidence payload schema. Returns the new `schema_id`."""
        body = {"kind": kind, "fields": _fields_as_dicts(fields)}
        raw = await self._http.post(
            _paths.schemas_register_evidence_path(), json=body, tenant=tenant
        )
        return raw["schema_id"]

    async def register_claim_predicate(
        self,
        *,
        predicate: str,
        object_type: ValueType,
        subject_type: TypeId | None = None,
        allowed_claim_kinds: list[str] | None = None,
        tenant: TenantId | None = None,
    ) -> SchemaId:
        """Register a claim predicate schema. `subject_type=None` means the predicate accepts any entity type."""
        body: dict[str, Any] = {
            "predicate": predicate,
            "subject_type": subject_type,
            "object_type": object_type,
            "allowed_claim_kinds": allowed_claim_kinds or [],
        }
        raw = await self._http.post(
            _paths.schemas_register_claim_predicate_path(), json=body, tenant=tenant
        )
        return raw["schema_id"]

    async def register_action(
        self,
        *,
        action_kind: str,
        fields: list[FieldSchema] | list[dict[str, Any]],
        tenant: TenantId | None = None,
    ) -> SchemaId:
        """Register an action payload schema. Returns the new `schema_id`."""
        body = {"action_kind": action_kind, "fields": _fields_as_dicts(fields)}
        raw = await self._http.post(
            _paths.schemas_register_action_path(), json=body, tenant=tenant
        )
        return raw["schema_id"]

    async def register_policy_condition(
        self,
        *,
        policy_kind: str,
        fields: list[FieldSchema] | list[dict[str, Any]],
        tenant: TenantId | None = None,
    ) -> SchemaId:
        """Register a policy condition schema. Returns the new `schema_id`."""
        body = {"policy_kind": policy_kind, "fields": _fields_as_dicts(fields)}
        raw = await self._http.post(
            _paths.schemas_register_policy_condition_path(), json=body, tenant=tenant
        )
        return raw["schema_id"]

    # ========================================================================
    # Lifecycle (204 No Content)
    # ========================================================================

    async def disable(
        self,
        schema_id: SchemaId,
        *,
        reason: str | None = None,
        tenant: TenantId | None = None,
    ) -> None:
        """Move a schema to `Disabled` state. Disabled schemas are not used for validation but remain queryable."""
        await self._http.post(
            _paths.schema_disable_path(schema_id),
            json={"reason": reason},
            tenant=tenant,
        )

    async def archive(
        self,
        schema_id: SchemaId,
        *,
        reason: str | None = None,
        tenant: TenantId | None = None,
    ) -> None:
        """Move a schema to `Archived` state (terminal — schema is no longer enforced)."""
        await self._http.post(
            _paths.schema_archive_path(schema_id),
            json={"reason": reason},
            tenant=tenant,
        )

    # ========================================================================
    # Validate (always 200; never raises on valid=False)
    # ========================================================================

    async def validate_action(
        self, action: Action | dict[str, Any], *, tenant: TenantId | None = None
    ) -> ValidationResponse:
        """Preflight-validate an `Action` payload against its registered `ActionPayloadSchema`."""
        body = {"action": _model_or_dict(action)}
        raw = await self._http.post(
            _paths.schemas_validate_action_path(), json=body, tenant=tenant
        )
        return ValidationResponse.model_validate(raw)

    async def validate_evidence(
        self, evidence: Evidence | dict[str, Any], *, tenant: TenantId | None = None
    ) -> ValidationResponse:
        """Preflight-validate an `Evidence` payload against its registered `EvidencePayloadSchema`."""
        body = {"evidence": _model_or_dict(evidence)}
        raw = await self._http.post(
            _paths.schemas_validate_evidence_path(), json=body, tenant=tenant
        )
        return ValidationResponse.model_validate(raw)

    async def validate_claim(
        self, claim: Claim | dict[str, Any], *, tenant: TenantId | None = None
    ) -> ValidationResponse:
        """Preflight-validate a `Claim` against its registered `ClaimPredicateSchema`."""
        body = {"claim": _model_or_dict(claim)}
        raw = await self._http.post(
            _paths.schemas_validate_claim_path(), json=body, tenant=tenant
        )
        return ValidationResponse.model_validate(raw)

    async def validate_node_create(
        self,
        *,
        type_id: TypeId,
        properties: dict[str, Any],
        tenant: TenantId | None = None,
    ) -> ValidationResponse:
        """Preflight-validate a node-create payload against the `EntityTypeSchema` for `type_id`."""
        body = {"type_id": type_id, "properties": properties}
        raw = await self._http.post(
            _paths.schemas_validate_node_create_path(), json=body, tenant=tenant
        )
        return ValidationResponse.model_validate(raw)

    async def validate_node_update(
        self,
        *,
        type_id: TypeId,
        changes: dict[str, Any],
        tenant: TenantId | None = None,
    ) -> ValidationResponse:
        """Preflight-validate a node-update payload (partial field changes) against the `EntityTypeSchema`."""
        body = {"type_id": type_id, "changes": changes}
        raw = await self._http.post(
            _paths.schemas_validate_node_update_path(), json=body, tenant=tenant
        )
        return ValidationResponse.model_validate(raw)

    async def validate_edge_create(
        self,
        *,
        type_id: TypeId,
        properties: dict[str, Any],
        tenant: TenantId | None = None,
    ) -> ValidationResponse:
        """Preflight-validate an edge-create payload against the `EdgeTypeSchema` for `type_id`."""
        body = {"type_id": type_id, "properties": properties}
        raw = await self._http.post(
            _paths.schemas_validate_edge_create_path(), json=body, tenant=tenant
        )
        return ValidationResponse.model_validate(raw)

    async def validate_edge_update(
        self,
        *,
        edge_id: EdgeId,
        changes: dict[str, Any],
        tenant: TenantId | None = None,
    ) -> ValidationResponse:
        """Preflight-validate an edge-update payload. **Only validator that can raise `HydraNotFoundError`** (needs a live edge)."""
        body = {"edge_id": edge_id, "changes": changes}
        raw = await self._http.post(
            _paths.schemas_validate_edge_update_path(), json=body, tenant=tenant
        )
        return ValidationResponse.model_validate(raw)


def _fields_as_dicts(
    fields: list[FieldSchema] | list[dict[str, Any]],
) -> list[dict[str, Any]]:
    """Accept either typed `FieldSchema` instances or pre-built dicts.
    The HTTP layer wants the dict shape on the wire."""
    return [
        f.model_dump(mode="json") if isinstance(f, FieldSchema) else f for f in fields
    ]


def _model_or_dict(value: Any) -> Any:
    """Unwrap a Pydantic model to its dict shape, or pass a dict through."""
    if hasattr(value, "model_dump"):
        return value.model_dump(mode="json")
    return value


# === Patch 5: sync mirror ===
#
# Method-for-method parity with `_Schemas`. Reuses `_fields_as_dicts`
# and `_model_or_dict` so the serialization contract is shared.


class _SchemasSync:
    """Synchronous mirror of `_Schemas`. Access via `hy.schemas.<method>`
    on a `HydraSync` client."""

    def __init__(
        self, http: HydraHttpClientSync, default_tenant: TenantId | None
    ) -> None:
        self._http = http
        self._default_tenant = default_tenant

    # === Reads ===

    def list_active(
        self, *, tenant: TenantId | None = None
    ) -> list[dict[str, Any]]:
        """List active schemas. See module docstring for the dict shape."""
        raw = self._http.get(_paths.schemas_active_path(), tenant=tenant)
        return list(raw["schemas"])

    def list_disabled(
        self, *, tenant: TenantId | None = None
    ) -> list[dict[str, Any]]:
        """List disabled schemas (active → disabled lifecycle state)."""
        raw = self._http.get(_paths.schemas_disabled_path(), tenant=tenant)
        return list(raw["schemas"])

    def list_archived(
        self, *, tenant: TenantId | None = None
    ) -> list[dict[str, Any]]:
        """List archived schemas (terminal lifecycle state)."""
        raw = self._http.get(_paths.schemas_archived_path(), tenant=tenant)
        return list(raw["schemas"])

    def get_entity(
        self, type_id: TypeId, *, tenant: TenantId | None = None
    ) -> EntityTypeSchema:
        """Get the entity (node) type schema for `type_id`. 404 → HydraNotFoundError."""
        raw = self._http.get(_paths.schema_entity_path(type_id), tenant=tenant)
        return EntityTypeSchema.model_validate(raw)

    def get_edge(
        self, type_id: TypeId, *, tenant: TenantId | None = None
    ) -> EdgeTypeSchema:
        """Get the edge (relationship) type schema for `type_id`. 404 → HydraNotFoundError."""
        raw = self._http.get(_paths.schema_edge_path(type_id), tenant=tenant)
        return EdgeTypeSchema.model_validate(raw)

    def get_evidence(
        self, kind: str, *, tenant: TenantId | None = None
    ) -> EvidencePayloadSchema:
        """Get the evidence payload schema for `kind`. 404 → HydraNotFoundError."""
        raw = self._http.get(_paths.schema_evidence_path(kind), tenant=tenant)
        return EvidencePayloadSchema.model_validate(raw)

    def get_claim_predicate(
        self, predicate: str, *, tenant: TenantId | None = None
    ) -> ClaimPredicateSchema:
        """Get the claim predicate schema for `predicate`. 404 → HydraNotFoundError."""
        raw = self._http.get(
            _paths.schema_claim_predicate_path(predicate), tenant=tenant
        )
        return ClaimPredicateSchema.model_validate(raw)

    def get_action(
        self, action_kind: str, *, tenant: TenantId | None = None
    ) -> ActionPayloadSchema:
        """Get the action payload schema for `action_kind`. 404 → HydraNotFoundError."""
        raw = self._http.get(
            _paths.schema_action_path(action_kind), tenant=tenant
        )
        return ActionPayloadSchema.model_validate(raw)

    def get_policy(
        self, policy_kind: str, *, tenant: TenantId | None = None
    ) -> PolicyConditionSchema:
        """Get the policy condition schema for `policy_kind`. 404 → HydraNotFoundError."""
        raw = self._http.get(
            _paths.schema_policy_path(policy_kind), tenant=tenant
        )
        return PolicyConditionSchema.model_validate(raw)

    # === Registers ===

    def register_entity(
        self,
        *,
        type_id: TypeId,
        name: str,
        fields: list[FieldSchema] | list[dict[str, Any]],
        tenant: TenantId | None = None,
    ) -> SchemaId:
        """Register an entity (node) type schema. Returns the new `schema_id`."""
        body = {
            "type_id": type_id,
            "name": name,
            "fields": _fields_as_dicts(fields),
        }
        raw = self._http.post(
            _paths.schemas_register_entity_path(), json=body, tenant=tenant
        )
        return raw["schema_id"]

    def register_edge(
        self,
        *,
        type_id: TypeId,
        name: str,
        fields: list[FieldSchema] | list[dict[str, Any]],
        tenant: TenantId | None = None,
    ) -> SchemaId:
        """Register an edge (relationship) type schema. Returns the new `schema_id`."""
        body = {
            "type_id": type_id,
            "name": name,
            "fields": _fields_as_dicts(fields),
        }
        raw = self._http.post(
            _paths.schemas_register_edge_path(), json=body, tenant=tenant
        )
        return raw["schema_id"]

    def register_evidence(
        self,
        *,
        kind: str,
        fields: list[FieldSchema] | list[dict[str, Any]],
        tenant: TenantId | None = None,
    ) -> SchemaId:
        """Register an evidence payload schema. Returns the new `schema_id`."""
        body = {"kind": kind, "fields": _fields_as_dicts(fields)}
        raw = self._http.post(
            _paths.schemas_register_evidence_path(), json=body, tenant=tenant
        )
        return raw["schema_id"]

    def register_claim_predicate(
        self,
        *,
        predicate: str,
        object_type: ValueType,
        subject_type: TypeId | None = None,
        allowed_claim_kinds: list[str] | None = None,
        tenant: TenantId | None = None,
    ) -> SchemaId:
        """Register a claim predicate schema. `subject_type=None` means the predicate accepts any entity type."""
        body: dict[str, Any] = {
            "predicate": predicate,
            "subject_type": subject_type,
            "object_type": object_type,
            "allowed_claim_kinds": allowed_claim_kinds or [],
        }
        raw = self._http.post(
            _paths.schemas_register_claim_predicate_path(), json=body, tenant=tenant
        )
        return raw["schema_id"]

    def register_action(
        self,
        *,
        action_kind: str,
        fields: list[FieldSchema] | list[dict[str, Any]],
        tenant: TenantId | None = None,
    ) -> SchemaId:
        """Register an action payload schema. Returns the new `schema_id`."""
        body = {"action_kind": action_kind, "fields": _fields_as_dicts(fields)}
        raw = self._http.post(
            _paths.schemas_register_action_path(), json=body, tenant=tenant
        )
        return raw["schema_id"]

    def register_policy_condition(
        self,
        *,
        policy_kind: str,
        fields: list[FieldSchema] | list[dict[str, Any]],
        tenant: TenantId | None = None,
    ) -> SchemaId:
        """Register a policy condition schema. Returns the new `schema_id`."""
        body = {"policy_kind": policy_kind, "fields": _fields_as_dicts(fields)}
        raw = self._http.post(
            _paths.schemas_register_policy_condition_path(), json=body, tenant=tenant
        )
        return raw["schema_id"]

    # === Lifecycle (204 No Content) ===

    def disable(
        self,
        schema_id: SchemaId,
        *,
        reason: str | None = None,
        tenant: TenantId | None = None,
    ) -> None:
        """Move a schema to `Disabled` state. Disabled schemas are not used for validation but remain queryable."""
        self._http.post(
            _paths.schema_disable_path(schema_id),
            json={"reason": reason},
            tenant=tenant,
        )

    def archive(
        self,
        schema_id: SchemaId,
        *,
        reason: str | None = None,
        tenant: TenantId | None = None,
    ) -> None:
        """Move a schema to `Archived` state (terminal — schema is no longer enforced)."""
        self._http.post(
            _paths.schema_archive_path(schema_id),
            json={"reason": reason},
            tenant=tenant,
        )

    # === Validate (always 200; never raises on valid=False) ===

    def validate_action(
        self, action: Action | dict[str, Any], *, tenant: TenantId | None = None
    ) -> ValidationResponse:
        """Preflight-validate an `Action` payload against its registered `ActionPayloadSchema`."""
        body = {"action": _model_or_dict(action)}
        raw = self._http.post(
            _paths.schemas_validate_action_path(), json=body, tenant=tenant
        )
        return ValidationResponse.model_validate(raw)

    def validate_evidence(
        self, evidence: Evidence | dict[str, Any], *, tenant: TenantId | None = None
    ) -> ValidationResponse:
        """Preflight-validate an `Evidence` payload against its registered `EvidencePayloadSchema`."""
        body = {"evidence": _model_or_dict(evidence)}
        raw = self._http.post(
            _paths.schemas_validate_evidence_path(), json=body, tenant=tenant
        )
        return ValidationResponse.model_validate(raw)

    def validate_claim(
        self, claim: Claim | dict[str, Any], *, tenant: TenantId | None = None
    ) -> ValidationResponse:
        """Preflight-validate a `Claim` against its registered `ClaimPredicateSchema`."""
        body = {"claim": _model_or_dict(claim)}
        raw = self._http.post(
            _paths.schemas_validate_claim_path(), json=body, tenant=tenant
        )
        return ValidationResponse.model_validate(raw)

    def validate_node_create(
        self,
        *,
        type_id: TypeId,
        properties: dict[str, Any],
        tenant: TenantId | None = None,
    ) -> ValidationResponse:
        """Preflight-validate a node-create payload against the `EntityTypeSchema` for `type_id`."""
        body = {"type_id": type_id, "properties": properties}
        raw = self._http.post(
            _paths.schemas_validate_node_create_path(), json=body, tenant=tenant
        )
        return ValidationResponse.model_validate(raw)

    def validate_node_update(
        self,
        *,
        type_id: TypeId,
        changes: dict[str, Any],
        tenant: TenantId | None = None,
    ) -> ValidationResponse:
        """Preflight-validate a node-update payload (partial field changes) against the `EntityTypeSchema`."""
        body = {"type_id": type_id, "changes": changes}
        raw = self._http.post(
            _paths.schemas_validate_node_update_path(), json=body, tenant=tenant
        )
        return ValidationResponse.model_validate(raw)

    def validate_edge_create(
        self,
        *,
        type_id: TypeId,
        properties: dict[str, Any],
        tenant: TenantId | None = None,
    ) -> ValidationResponse:
        """Preflight-validate an edge-create payload against the `EdgeTypeSchema` for `type_id`."""
        body = {"type_id": type_id, "properties": properties}
        raw = self._http.post(
            _paths.schemas_validate_edge_create_path(), json=body, tenant=tenant
        )
        return ValidationResponse.model_validate(raw)

    def validate_edge_update(
        self,
        *,
        edge_id: EdgeId,
        changes: dict[str, Any],
        tenant: TenantId | None = None,
    ) -> ValidationResponse:
        """Preflight-validate an edge-update payload. **Only validator that can raise `HydraNotFoundError`** (needs a live edge)."""
        body = {"edge_id": edge_id, "changes": changes}
        raw = self._http.post(
            _paths.schemas_validate_edge_update_path(), json=body, tenant=tenant
        )
        return ValidationResponse.model_validate(raw)
