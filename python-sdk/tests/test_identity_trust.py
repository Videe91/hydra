"""Tests for the Patch 34 identity trust SDK methods:

  - `Hydra.assess_identity_entity_trust(entity_id, *, tenant=None)`
  - `Hydra.assess_identity_match_trust(*, source, normalized,
        candidate_entity_id, namespace=None, kind=None, tenant=None)`

The HTTP-layer contracts (strict tenant scoping, 404
indistinguishable from missing, both axes preserved,
missing-required-param → 400) are pinned at the Rust HTTP
boundary in `crates/hydra-net/src/http/trust.rs`. These tests
focus on the SDK wire round-trip — typed envelope parsing,
URL param mapping, tenant header propagation, error mapping,
the carry-forward `MatchLevel "None"` string gotcha, and
sync parity.
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
    IdentityEntityTrustAssessment,
    IdentityMatchTrustAssessment,
)


# === Fixtures ===

ENTITY_TRUST_BODY: dict[str, Any] = {
    "entity_id": "ide_revenue_daily",
    "score": 0.85,
    "level": "High",
    "explanation": "Identity record verdict High (score 0.85)",
    "factors": [
        {
            "kind": "entity_confidence_high",
            "weight": 0.30,
            "applied": True,
            "detail": "confidence 0.95 (≥ 0.80)",
        },
        {
            "kind": "single_alias_only",
            "weight": -0.10,
            "applied": False,
            "detail": "3 aliases",
        },
    ],
    "assessed_at": "2026-05-31T12:00:00Z",
}

MATCH_TRUST_BODY: dict[str, Any] = {
    "query_alias": {
        "source": "snowflake",
        "namespace": "analytics",
        "external_id": None,
        "label": "analytics.revenue_daily",
        "normalized": "analytics.revenue_daily",
    },
    "candidate_entity_id": "ide_revenue_daily",
    "match_score": 0.95,
    "match_level": "Strong",
    "score": 0.90,
    "level": "High",
    "explanation": "Trust verdict High over Strong match",
    "factors": [
        {
            "kind": "exact_alias_match",
            "weight": 0.40,
            "applied": True,
            "detail": "alias appears verbatim on candidate",
        },
        {
            "kind": "alias_conflict_present",
            "weight": -0.35,
            "applied": False,
            "detail": "no conflicting alias resolution",
        },
    ],
    "assessed_at": "2026-05-31T12:00:00Z",
}


# === assess_identity_entity_trust ===


@pytest.mark.asyncio
async def test_assess_identity_entity_trust_returns_typed_assessment(
    hy: Hydra, respx_mock: respx.MockRouter
) -> None:
    route = respx_mock.get(
        "https://hydra.test/trust/identity/entities/ide_revenue_daily"
    ).mock(return_value=httpx.Response(200, json=ENTITY_TRUST_BODY))

    a = await hy.assess_identity_entity_trust("ide_revenue_daily")
    assert isinstance(a, IdentityEntityTrustAssessment)
    assert a.entity_id == "ide_revenue_daily"
    assert a.level == "High"
    assert abs(a.score - 0.85) < 1e-9
    # All factor records preserved — including applied=false.
    assert len(a.factors) == 2
    assert any(not f.applied for f in a.factors)
    # Tenant propagated automatically from the fixture default.
    assert "X-Hydra-Tenant" in route.calls.last.request.headers


@pytest.mark.asyncio
async def test_assess_identity_entity_trust_tenant_override_propagates(
    hy: Hydra, respx_mock: respx.MockRouter
) -> None:
    route = respx_mock.get(
        "https://hydra.test/trust/identity/entities/ide_revenue_daily"
    ).mock(return_value=httpx.Response(200, json=ENTITY_TRUST_BODY))

    await hy.assess_identity_entity_trust(
        "ide_revenue_daily", tenant="tenant_other"
    )
    assert (
        route.calls.last.request.headers["X-Hydra-Tenant"]
        == "tenant_other"
    )


@pytest.mark.asyncio
async def test_assess_identity_entity_trust_unknown_raises_not_found(
    hy: Hydra, respx_mock: respx.MockRouter
) -> None:
    """404 → `HydraNotFoundError`. Unknown id, wrong tenant,
    AND `None`-tenanted entity all surface identically — strict
    isolation contract carries forward from P29 / P31."""
    respx_mock.get(
        "https://hydra.test/trust/identity/entities/ide_ghost"
    ).mock(
        return_value=httpx.Response(
            404,
            json={"error": "unknown identity entity: ide_ghost"},
        )
    )
    with pytest.raises(HydraNotFoundError):
        await hy.assess_identity_entity_trust("ide_ghost")


def test_assess_identity_entity_trust_sync_mirror(
    hy_sync: HydraSync, respx_mock: respx.MockRouter
) -> None:
    respx_mock.get(
        "https://hydra.test/trust/identity/entities/ide_revenue_daily"
    ).mock(return_value=httpx.Response(200, json=ENTITY_TRUST_BODY))

    a = hy_sync.assess_identity_entity_trust("ide_revenue_daily")
    assert isinstance(a, IdentityEntityTrustAssessment)
    assert a.level == "High"


# === assess_identity_match_trust ===


@pytest.mark.asyncio
async def test_assess_identity_match_trust_returns_typed_assessment(
    hy: Hydra, respx_mock: respx.MockRouter
) -> None:
    respx_mock.get(
        "https://hydra.test/trust/identity/matches",
        params={
            "source": "snowflake",
            "normalized": "analytics.revenue_daily",
            "candidate_entity_id": "ide_revenue_daily",
            "namespace": "analytics",
        },
    ).mock(return_value=httpx.Response(200, json=MATCH_TRUST_BODY))

    a = await hy.assess_identity_match_trust(
        source="snowflake",
        normalized="analytics.revenue_daily",
        candidate_entity_id="ide_revenue_daily",
        namespace="analytics",
    )
    assert isinstance(a, IdentityMatchTrustAssessment)
    # Both axes preserved on the wire.
    assert a.match_level == "Strong"
    assert a.level == "High"
    assert abs(a.match_score - 0.95) < 1e-9
    assert abs(a.score - 0.90) < 1e-9
    # Factor list includes applied + unapplied records.
    assert len(a.factors) == 2
    assert any(f.applied for f in a.factors)
    assert any(not f.applied for f in a.factors)


@pytest.mark.asyncio
async def test_assess_identity_match_trust_url_params_propagate(
    hy: Hydra, respx_mock: respx.MockRouter
) -> None:
    """All kwargs (required + optional) land as URL query
    params on the GET request."""
    route = respx_mock.get(
        "https://hydra.test/trust/identity/matches",
        params={
            "source": "looker",
            "normalized": "revenue.daily.dashboard",
            "candidate_entity_id": "ide_revenue_daily",
            "namespace": "finance",
            "kind": "dashboard",
        },
    ).mock(return_value=httpx.Response(200, json=MATCH_TRUST_BODY))

    await hy.assess_identity_match_trust(
        source="looker",
        normalized="revenue.daily.dashboard",
        candidate_entity_id="ide_revenue_daily",
        namespace="finance",
        kind="dashboard",
    )
    sent = route.calls.last.request.url.params
    assert sent["source"] == "looker"
    assert sent["normalized"] == "revenue.daily.dashboard"
    assert sent["candidate_entity_id"] == "ide_revenue_daily"
    assert sent["namespace"] == "finance"
    assert sent["kind"] == "dashboard"


@pytest.mark.asyncio
async def test_assess_identity_match_trust_match_level_none_is_string(
    hy: Hydra, respx_mock: respx.MockRouter
) -> None:
    """Wrinkle E carry-forward pin from P31. `MatchLevel.None`
    is a STRING literal `"None"` on the wire — NOT Python's
    `None`. A candidate whose semantic match scored below the
    Weak threshold has `match_level="None"`, but `level` (P32
    trust verdict, TrustLevel) may still be populated based on
    other factors (e.g., exact alias match dominates even with
    weak semantic)."""
    body = {
        **MATCH_TRUST_BODY,
        "match_score": 0.10,
        "match_level": "None",
        "score": 0.40,
        "level": "Low",
    }
    respx_mock.get(
        "https://hydra.test/trust/identity/matches",
        params={
            "source": "snowflake",
            "normalized": "totally_unrelated",
            "candidate_entity_id": "ide_revenue_daily",
        },
    ).mock(return_value=httpx.Response(200, json=body))

    a = await hy.assess_identity_match_trust(
        source="snowflake",
        normalized="totally_unrelated",
        candidate_entity_id="ide_revenue_daily",
    )
    # `match_level` is the STRING "None", not Python None.
    assert a.match_level == "None"
    assert a.match_level is not None  # Python None would be falsy
    # P32 trust verdict can be populated independently.
    assert a.level == "Low"


@pytest.mark.asyncio
async def test_assess_identity_match_trust_unknown_raises_not_found(
    hy: Hydra, respx_mock: respx.MockRouter
) -> None:
    respx_mock.get(
        "https://hydra.test/trust/identity/matches",
        params={
            "source": "snowflake",
            "normalized": "x",
            "candidate_entity_id": "ide_ghost",
        },
    ).mock(
        return_value=httpx.Response(
            404,
            json={"error": "unknown identity entity: ide_ghost"},
        )
    )
    with pytest.raises(HydraNotFoundError):
        await hy.assess_identity_match_trust(
            source="snowflake",
            normalized="x",
            candidate_entity_id="ide_ghost",
        )


@pytest.mark.asyncio
async def test_assess_identity_match_trust_missing_param_raises_validation(
    hy: Hydra, respx_mock: respx.MockRouter
) -> None:
    """Server returns 400 when a required query param is
    absent. SDK maps to `HydraValidationError`. The SDK itself
    can't easily enforce required kwargs (Python enforces at
    call site via keyword-only `*,` syntax), but if the server
    rejects we surface it cleanly."""
    respx_mock.get(
        "https://hydra.test/trust/identity/matches"
    ).mock(
        return_value=httpx.Response(
            400,
            json={
                "error": "missing field `candidate_entity_id`"
            },
        )
    )
    # Simulate a malformed call by passing empty values that
    # the server would reject. (Python prevents omitting the
    # kwargs entirely at the function signature level.)
    with pytest.raises(HydraValidationError):
        await hy.assess_identity_match_trust(
            source="",
            normalized="x",
            candidate_entity_id="ide_x",
        )


def test_assess_identity_match_trust_sync_mirror(
    hy_sync: HydraSync, respx_mock: respx.MockRouter
) -> None:
    respx_mock.get(
        "https://hydra.test/trust/identity/matches",
        params={
            "source": "snowflake",
            "normalized": "analytics.revenue_daily",
            "candidate_entity_id": "ide_revenue_daily",
        },
    ).mock(return_value=httpx.Response(200, json=MATCH_TRUST_BODY))

    a = hy_sync.assess_identity_match_trust(
        source="snowflake",
        normalized="analytics.revenue_daily",
        candidate_entity_id="ide_revenue_daily",
    )
    assert isinstance(a, IdentityMatchTrustAssessment)
    # Both axes round-trip via sync client too.
    assert a.match_level == "Strong"
    assert a.level == "High"
