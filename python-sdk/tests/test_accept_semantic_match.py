"""Tests for the Patch 42 Accept Semantic Match SDK method:

  - `Hydra.accept_semantic_identity_match(*, candidate_entity_id,
       alias, added_by, tenant=None)`

The HTTP-layer contracts (trust-gated alias attach, strict tenant
scoping, 404-on-unknown-or-wrong-tenant indistinguishable, 400
on gate failure / cross-entity conflict / invalid alias / empty
actor, idempotent re-accept returns same shape) are pinned at
the Rust HTTP boundary in
`crates/hydra-net/src/http/identity.rs`. These tests focus on the
SDK wire round-trip — request body shape, tenant header
propagation, response unwrapping (`{entity: ...}` → typed
`IdentityEntity`), error mapping (400 → ValidationError, 404 →
NotFoundError), and sync parity.
"""

from __future__ import annotations

from typing import Any

import httpx
import pytest
import respx

from hydra import (
    Hydra,
    HydraNotFoundError,
    HydraSync,
    HydraValidationError,
    IdentityAlias,
    IdentityEntity,
)


# === Fixture ===

ATTACHED_ALIAS: dict[str, Any] = {
    "source": "snowflake",
    "namespace": "finance",
    "external_id": "P42_NEW",
    "label": "x.p41_a",
    "normalized": "x.p41_a",
}

# Wrapped `{entity: IdentityEntity}` response shape. Mirrors P41
# engine output post-accept: candidate entity with the new alias
# appended.
ENTITY_RESPONSE: dict[str, Any] = {
    "entity": {
        "id": "ide_p42_candidate",
        "tenant_id": "tenant_default",
        "kind": "Dataset",
        "canonical_key": "x.p41_a",
        "display_name": "x.p41_a",
        "aliases": [
            {
                "source": "snowflake",
                "namespace": "analytics",
                "external_id": "X_P41_A",
                "label": "x.p41_a",
                "normalized": "x.p41_a",
            },
            {
                "source": "dbt",
                "namespace": "models",
                "external_id": "X_P41_A",
                "label": "x.p41_a",
                "normalized": "x.p41_a",
            },
            {
                "source": "looker",
                "namespace": "finance",
                "external_id": "X_P41_A",
                "label": "x.p41_a",
                "normalized": "x.p41_a",
            },
            ATTACHED_ALIAS,
        ],
        "confidence": 0.95,
        "metadata": {},
        "created_by": "actor_ops",
        "created_at": "2026-06-02T12:00:00Z",
        "updated_at": "2026-06-02T12:00:05Z",
        "caused_by": None,
    },
}


# === accept_semantic_identity_match ===


@pytest.mark.asyncio
async def test_accept_semantic_identity_match_returns_typed_entity(
    hy: Hydra, respx_mock: respx.MockRouter
) -> None:
    """Happy path — POST `{candidate_entity_id, alias, added_by}`
    returns the wrapped `{entity}` body, unwrapped to a typed
    `IdentityEntity` with the new alias appended."""
    route = respx_mock.post(
        "https://hydra.test/identity/matches/accept"
    ).mock(return_value=httpx.Response(200, json=ENTITY_RESPONSE))

    alias = IdentityAlias.model_validate(ATTACHED_ALIAS)
    entity = await hy.accept_semantic_identity_match(
        candidate_entity_id="ide_p42_candidate",
        alias=alias,
        added_by="actor_ops",
    )
    assert isinstance(entity, IdentityEntity)
    assert entity.id == "ide_p42_candidate"
    # Attached alias present in the returned entity.
    assert any(
        a.source == "snowflake"
        and a.namespace == "finance"
        and a.normalized == "x.p41_a"
        for a in entity.aliases
    )
    # Tenant header propagated automatically.
    assert "X-Hydra-Tenant" in route.calls.last.request.headers
    # Body shape pinned.
    import json as _json
    sent = _json.loads(route.calls.last.request.content)
    assert sent["candidate_entity_id"] == "ide_p42_candidate"
    assert sent["added_by"] == "actor_ops"
    assert sent["alias"]["source"] == "snowflake"
    assert sent["alias"]["namespace"] == "finance"


@pytest.mark.asyncio
async def test_accept_semantic_identity_match_tenant_override(
    hy: Hydra, respx_mock: respx.MockRouter
) -> None:
    """Per-call `tenant=` overrides the default header — required
    for cross-tenant operator workflows (operator with access to
    multiple tenants accepting matches in tenant B from a session
    configured for tenant A)."""
    route = respx_mock.post(
        "https://hydra.test/identity/matches/accept"
    ).mock(return_value=httpx.Response(200, json=ENTITY_RESPONSE))

    alias = IdentityAlias.model_validate(ATTACHED_ALIAS)
    await hy.accept_semantic_identity_match(
        candidate_entity_id="ide_p42_candidate",
        alias=alias,
        added_by="actor_ops",
        tenant="tenant_other",
    )
    assert (
        route.calls.last.request.headers["X-Hydra-Tenant"]
        == "tenant_other"
    )


@pytest.mark.asyncio
async def test_accept_semantic_identity_match_unknown_candidate_raises_not_found(
    hy: Hydra, respx_mock: respx.MockRouter
) -> None:
    """Unknown candidate / wrong-tenant candidate both surface as
    server 404 with `"unknown identity entity: {id}"` → SDK maps
    to `HydraNotFoundError`."""
    respx_mock.post(
        "https://hydra.test/identity/matches/accept"
    ).mock(
        return_value=httpx.Response(
            404,
            json={"error": "unknown identity entity: ide_ghost"},
        )
    )
    alias = IdentityAlias.model_validate(ATTACHED_ALIAS)
    with pytest.raises(HydraNotFoundError):
        await hy.accept_semantic_identity_match(
            candidate_entity_id="ide_ghost",
            alias=alias,
            added_by="actor_ops",
        )


@pytest.mark.asyncio
async def test_accept_semantic_identity_match_gate_failure_raises_validation(
    hy: Hydra, respx_mock: respx.MockRouter
) -> None:
    """Trust gate failure (match below Strong / entity below
    High / source below High) surfaces as server 400 with
    `"accept rejected: ... trust below High"` → SDK maps to
    `HydraValidationError`. Same mapping covers invalid alias,
    empty actor, and cross-entity conflict."""
    respx_mock.post(
        "https://hydra.test/identity/matches/accept"
    ).mock(
        return_value=httpx.Response(
            400,
            json={
                "error": (
                    "accept rejected: source trust below High "
                    "(score=0.600, level=Medium)"
                )
            },
        )
    )
    alias = IdentityAlias.model_validate(ATTACHED_ALIAS)
    with pytest.raises(HydraValidationError):
        await hy.accept_semantic_identity_match(
            candidate_entity_id="ide_low_source",
            alias=alias,
            added_by="actor_ops",
        )


def test_accept_semantic_identity_match_sync_mirror(
    hy_sync: HydraSync, respx_mock: respx.MockRouter
) -> None:
    """Sync mirror returns the same typed envelope as the async
    client. Locks signature + behavioral parity."""
    respx_mock.post(
        "https://hydra.test/identity/matches/accept"
    ).mock(return_value=httpx.Response(200, json=ENTITY_RESPONSE))

    alias = IdentityAlias.model_validate(ATTACHED_ALIAS)
    entity = hy_sync.accept_semantic_identity_match(
        candidate_entity_id="ide_p42_candidate",
        alias=alias,
        added_by="actor_ops",
    )
    assert isinstance(entity, IdentityEntity)
    assert entity.id == "ide_p42_candidate"
    # The attached alias survives the round-trip.
    assert any(
        a.source == "snowflake" and a.namespace == "finance"
        for a in entity.aliases
    )
