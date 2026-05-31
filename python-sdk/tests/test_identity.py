"""Tests for the Identity Graph SDK surface (Patch 31).

Covers the four async methods + sync mirrors:

  - `Hydra.create_identity_entity(entity, *, tenant=None)`
  - `Hydra.identity_entity(entity_id, *, tenant=None)`
  - `Hydra.identity_entities(*, kind=None, after=None, limit=None, tenant=None)`
  - `Hydra.suggest_identity_matches(*, source, normalized, namespace=None,
        kind=None, limit=10, tenant=None)`

The HTTP-layer contracts (strict tenant scoping, anti-smuggling,
unknown-kind-returns-empty, duplicate-alias-400) are pinned at
the Rust HTTP boundary in `crates/hydra-net/src/http/identity.rs`.
These tests focus on the SDK wire round-trip — typed envelope
parsing, kwarg-to-URL-param mapping, tenant header propagation,
error mapping, and sync parity.
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
    SemanticIdentityMatchAssessment,
)


# === Fixtures ===

ENTITY_BODY: dict[str, Any] = {
    "id": "ide_revenue_daily",
    "tenant_id": "tenant_test",
    "kind": "Dataset",
    "canonical_key": "dataset/revenue_daily",
    "display_name": "Revenue (daily)",
    "aliases": [
        {
            "source": "snowflake",
            "namespace": "analytics",
            "external_id": "ANALYTICS.REVENUE_DAILY",
            "label": "ANALYTICS.REVENUE_DAILY",
            "normalized": "analytics.revenue_daily",
        }
    ],
    "confidence": 1.0,
    "metadata": {},
    "created_by": "actor_ops",
    "created_at": "2026-05-31T12:00:00Z",
    "updated_at": "2026-05-31T12:00:00Z",
    "caused_by": None,
}

MATCH_ASSESSMENT_BODY: dict[str, Any] = {
    "query_alias": {
        "source": "snowflake",
        "namespace": "analytics",
        "external_id": None,
        "label": "analytics.revenue_daily",
        "normalized": "analytics.revenue_daily",
    },
    "candidates": [
        {
            "entity_id": "ide_revenue_daily",
            "score": 0.95,
            "level": "Strong",
            "factors": [
                {
                    "kind": "exact_alias_match",
                    "weight": 0.85,
                    "applied": True,
                    "detail": "alias matches existing entity",
                },
                {
                    "kind": "same_kind",
                    "weight": 0.10,
                    "applied": False,
                    "detail": "no kind context on query alias (v0)",
                },
            ],
        }
    ],
    "assessed_at": "2026-05-31T12:00:00Z",
}


# === create_identity_entity ===


@pytest.mark.asyncio
async def test_create_identity_entity_returns_typed_entity(
    hy: Hydra, respx_mock: respx.MockRouter
) -> None:
    route = respx_mock.post(
        "https://hydra.test/identity/entities"
    ).mock(return_value=httpx.Response(200, json={"entity": ENTITY_BODY}))

    entity = IdentityEntity.model_validate(ENTITY_BODY)
    result = await hy.create_identity_entity(entity)

    assert isinstance(result, IdentityEntity)
    assert result.id == "ide_revenue_daily"
    assert result.kind == "Dataset"
    assert len(result.aliases) == 1
    # Body shape: {"entity": {...}}
    sent_body = route.calls.last.request.read()
    assert b'"entity"' in sent_body


@pytest.mark.asyncio
async def test_create_identity_entity_tenant_override_propagates(
    hy: Hydra, respx_mock: respx.MockRouter
) -> None:
    """Per-call `tenant=` overrides the client default and lands
    as `X-Hydra-Tenant`."""
    route = respx_mock.post(
        "https://hydra.test/identity/entities"
    ).mock(return_value=httpx.Response(200, json={"entity": ENTITY_BODY}))

    entity = IdentityEntity.model_validate(ENTITY_BODY)
    await hy.create_identity_entity(entity, tenant="tenant_other")

    assert (
        route.calls.last.request.headers["X-Hydra-Tenant"]
        == "tenant_other"
    )


@pytest.mark.asyncio
async def test_create_identity_entity_duplicate_raises_validation(
    hy: Hydra, respx_mock: respx.MockRouter
) -> None:
    """Duplicate alias / canonical_key returns 400 → SDK
    `HydraValidationError`."""
    respx_mock.post(
        "https://hydra.test/identity/entities"
    ).mock(
        return_value=httpx.Response(
            400,
            json={"error": "duplicate alias key 'tenant_test|...'"},
        )
    )

    entity = IdentityEntity.model_validate(ENTITY_BODY)
    with pytest.raises(HydraValidationError):
        await hy.create_identity_entity(entity)


# === identity_entity ===


@pytest.mark.asyncio
async def test_identity_entity_returns_typed_entity(
    hy: Hydra, respx_mock: respx.MockRouter
) -> None:
    respx_mock.get(
        "https://hydra.test/identity/entities/ide_revenue_daily"
    ).mock(return_value=httpx.Response(200, json={"entity": ENTITY_BODY}))

    entity = await hy.identity_entity("ide_revenue_daily")
    assert isinstance(entity, IdentityEntity)
    assert entity.id == "ide_revenue_daily"
    assert entity.canonical_key == "dataset/revenue_daily"


@pytest.mark.asyncio
async def test_identity_entity_unknown_raises_not_found(
    hy: Hydra, respx_mock: respx.MockRouter
) -> None:
    """404 → `HydraNotFoundError`. Unknown id, wrong tenant, AND
    `None`-tenanted system entity all surface identically (the
    strict isolation contract from P29)."""
    respx_mock.get(
        "https://hydra.test/identity/entities/ide_ghost"
    ).mock(
        return_value=httpx.Response(
            404,
            json={"error": "identity entity not found: ide_ghost"},
        )
    )

    with pytest.raises(HydraNotFoundError):
        await hy.identity_entity("ide_ghost")


# === identity_entities (list) ===


@pytest.mark.asyncio
async def test_identity_entities_paginated_unfiltered(
    hy: Hydra, respx_mock: respx.MockRouter
) -> None:
    respx_mock.get("https://hydra.test/identity/entities").mock(
        return_value=httpx.Response(
            200,
            json={
                "entities": [ENTITY_BODY],
                "next_cursor": None,
            },
        )
    )

    entities = await hy.identity_entities()
    assert len(entities) == 1
    assert isinstance(entities[0], IdentityEntity)
    assert entities[0].kind == "Dataset"


@pytest.mark.asyncio
async def test_identity_entities_filter_by_kind_propagates(
    hy: Hydra, respx_mock: respx.MockRouter
) -> None:
    route = respx_mock.get(
        "https://hydra.test/identity/entities",
        params={"kind": "dataset"},
    ).mock(
        return_value=httpx.Response(200, json={"entities": [ENTITY_BODY]})
    )

    entities = await hy.identity_entities(kind="dataset")
    assert len(entities) == 1
    assert (
        route.calls.last.request.url.params["kind"] == "dataset"
    )


# === suggest_identity_matches ===


@pytest.mark.asyncio
async def test_suggest_identity_matches_returns_typed_assessment(
    hy: Hydra, respx_mock: respx.MockRouter
) -> None:
    """Happy path — returns `SemanticIdentityMatchAssessment`
    with typed candidates. `MatchLevel` parses as the string
    `"Strong"` (NOT Python None — even when level is `"None"`)."""
    respx_mock.get(
        "https://hydra.test/identity/matches",
        params={
            "source": "snowflake",
            "normalized": "analytics.revenue_daily",
            "namespace": "analytics",
            "limit": "10",
        },
    ).mock(
        return_value=httpx.Response(
            200,
            json={"assessment": MATCH_ASSESSMENT_BODY},
        )
    )

    assessment = await hy.suggest_identity_matches(
        source="snowflake",
        normalized="analytics.revenue_daily",
        namespace="analytics",
    )
    assert isinstance(assessment, SemanticIdentityMatchAssessment)
    assert len(assessment.candidates) == 1
    top = assessment.candidates[0]
    assert top.entity_id == "ide_revenue_daily"
    assert top.level == "Strong"  # STRING literal, not Python None
    # All factors preserved (applied + unapplied — explainability).
    assert len(top.factors) == 2
    assert any(not f.applied for f in top.factors)


@pytest.mark.asyncio
async def test_suggest_identity_matches_url_params_propagate(
    hy: Hydra, respx_mock: respx.MockRouter
) -> None:
    """All kwargs land as URL query params on the GET request."""
    route = respx_mock.get(
        "https://hydra.test/identity/matches",
        params={
            "source": "looker",
            "normalized": "revenue.daily.dashboard",
            "namespace": "finance",
            "kind": "dashboard",
            "limit": "5",
        },
    ).mock(
        return_value=httpx.Response(
            200,
            json={"assessment": MATCH_ASSESSMENT_BODY},
        )
    )

    await hy.suggest_identity_matches(
        source="looker",
        normalized="revenue.daily.dashboard",
        namespace="finance",
        kind="dashboard",
        limit=5,
    )
    sent = route.calls.last.request.url.params
    assert sent["source"] == "looker"
    assert sent["namespace"] == "finance"
    assert sent["kind"] == "dashboard"
    assert sent["limit"] == "5"


@pytest.mark.asyncio
async def test_suggest_identity_matches_match_level_none_is_string(
    hy: Hydra, respx_mock: respx.MockRouter
) -> None:
    """Wrinkle E pin — `MatchLevel.None` is the STRING `"None"`,
    NOT Python None. A candidate with level `"None"` parses
    cleanly through Pydantic and `level == "None"` is the
    operator-facing check."""
    body = {
        **MATCH_ASSESSMENT_BODY,
        "candidates": [
            {
                **MATCH_ASSESSMENT_BODY["candidates"][0],
                "score": 0.05,
                "level": "None",
            }
        ],
    }
    respx_mock.get(
        "https://hydra.test/identity/matches",
        params={
            "source": "snowflake",
            "normalized": "totally_unrelated",
            "limit": "10",
        },
    ).mock(return_value=httpx.Response(200, json={"assessment": body}))

    assessment = await hy.suggest_identity_matches(
        source="snowflake",
        normalized="totally_unrelated",
    )
    top = assessment.candidates[0]
    assert top.level == "None"
    assert top.level is not None  # Python None would be falsy


# === Sync mirrors ===


def test_identity_entity_sync_mirror(
    hy_sync: HydraSync, respx_mock: respx.MockRouter
) -> None:
    respx_mock.get(
        "https://hydra.test/identity/entities/ide_revenue_daily"
    ).mock(return_value=httpx.Response(200, json={"entity": ENTITY_BODY}))

    entity = hy_sync.identity_entity("ide_revenue_daily")
    assert isinstance(entity, IdentityEntity)
    assert entity.id == "ide_revenue_daily"


def test_suggest_identity_matches_sync_mirror(
    hy_sync: HydraSync, respx_mock: respx.MockRouter
) -> None:
    """Sync parity for the matcher — operator dashboards and
    notebooks both rely on this."""
    respx_mock.get(
        "https://hydra.test/identity/matches",
        params={
            "source": "snowflake",
            "normalized": "analytics.revenue_daily",
            "limit": "10",
        },
    ).mock(
        return_value=httpx.Response(
            200,
            json={"assessment": MATCH_ASSESSMENT_BODY},
        )
    )

    assessment = hy_sync.suggest_identity_matches(
        source="snowflake",
        normalized="analytics.revenue_daily",
    )
    assert isinstance(assessment, SemanticIdentityMatchAssessment)
    assert assessment.candidates[0].level == "Strong"
