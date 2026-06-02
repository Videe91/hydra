"""Tests for the Patch 40 IdentityLink trust SDK method:

  - `Hydra.assess_identity_link_trust(link_id, *, tenant=None)`

The HTTP-layer contracts (strict tenant scoping, 404 indistinguishable
from missing, endpoint-entity miss → 404 not 500, broader substring
match, route precedence pin asserting read:trust) are pinned at the
Rust HTTP boundary in `crates/hydra-net/src/http/trust.rs`. These
tests focus on the SDK wire round-trip — typed envelope parsing,
URL-encoding via `_seg()`, tenant header propagation, error mapping,
strategic-warning carry-forward, 11-factor explainability lock, and
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
    HydraServerError,
    HydraSync,
    HydraValidationError,
    IdentityLinkTrustAssessment,
)


# === Fixture ===
#
# Mirrors the engine's IdentityLinkTrustAssessment output for a
# happy-path link: confidence_high + both endpoints high-trust +
# refs present + built-in kind. 11 factor records — applied AND
# unapplied — locked by the engine explainability contract.
LINK_TRUST_BODY: dict[str, Any] = {
    "link_id": "idl_revenue_link",
    "score": 0.80,
    "level": "High",
    "explanation": (
        "Link verdict High (score 0.80) — 5 positive factor(s) and 0 "
        "penalty factor(s) applied out of 5 total. v1 measures "
        "STRUCTURAL trust (confidence, endpoint entity-trust, supporting "
        "refs, kind well-formedness); v1 does NOT validate SEMANTIC "
        "correctness — kind compatibility lands in P41+. Auto-actions "
        "must compose with separate gates."
    ),
    "factors": [
        {
            "kind": "link_confidence_high",
            "weight": 0.25,
            "applied": True,
            "detail": "link confidence 0.95 (≥ 0.80)",
        },
        {
            "kind": "link_confidence_medium",
            "weight": 0.10,
            "applied": False,
            "detail": "link confidence 0.95 (0.50–0.80)",
        },
        {
            "kind": "link_confidence_low",
            "weight": -0.20,
            "applied": False,
            "detail": "link confidence 0.95 (< 0.50)",
        },
        {
            "kind": "from_entity_trust_high",
            "weight": 0.15,
            "applied": True,
            "detail": "from entity P33 trust 0.85 (High)",
        },
        {
            "kind": "from_entity_trust_low",
            "weight": -0.15,
            "applied": False,
            "detail": "from entity P33 trust 0.85 (≤ 0.40)",
        },
        {
            "kind": "to_entity_trust_high",
            "weight": 0.15,
            "applied": True,
            "detail": "to entity P33 trust 0.85 (High)",
        },
        {
            "kind": "to_entity_trust_low",
            "weight": -0.15,
            "applied": False,
            "detail": "to entity P33 trust 0.85 (≤ 0.40)",
        },
        {
            "kind": "supporting_references_present",
            "weight": 0.15,
            "applied": True,
            "detail": "2 supporting reference(s) (evidence/claim/cell ids)",
        },
        {
            "kind": "no_supporting_references",
            "weight": -0.05,
            "applied": False,
            "detail": "2 supporting reference(s) present",
        },
        {
            "kind": "built_in_kind",
            "weight": 0.10,
            "applied": True,
            "detail": "kind 'depends_on' is a built-in variant",
        },
        {
            "kind": "custom_kind",
            "weight": -0.05,
            "applied": False,
            "detail": "kind 'depends_on' is built-in",
        },
    ],
    "assessed_at": "2026-06-01T12:00:00Z",
}


# === assess_identity_link_trust ===


@pytest.mark.asyncio
async def test_assess_identity_link_trust_parses_typed_body(
    hy: Hydra, respx_mock: respx.MockRouter
) -> None:
    """Happy path — GET /trust/identity/links/{id} round-trips
    through to a typed Pydantic `IdentityLinkTrustAssessment`
    with all 6 P39 fields preserved."""
    respx_mock.get(
        "https://hydra.test/trust/identity/links/idl_revenue_link"
    ).mock(return_value=httpx.Response(200, json=LINK_TRUST_BODY))

    a = await hy.assess_identity_link_trust("idl_revenue_link")
    assert isinstance(a, IdentityLinkTrustAssessment)
    assert a.link_id == "idl_revenue_link"
    assert a.level == "High"
    assert abs(a.score - 0.80) < 1e-9
    assert "STRUCTURAL" in a.explanation
    assert len(a.factors) == 11
    assert a.assessed_at == "2026-06-01T12:00:00Z"


@pytest.mark.asyncio
async def test_assess_identity_link_trust_propagates_tenant_header(
    hy: Hydra, respx_mock: respx.MockRouter
) -> None:
    """Default tenant from fixture flows through as
    `X-Hydra-Tenant`."""
    route = respx_mock.get(
        "https://hydra.test/trust/identity/links/idl_x"
    ).mock(return_value=httpx.Response(200, json=LINK_TRUST_BODY))

    await hy.assess_identity_link_trust("idl_x")
    assert "X-Hydra-Tenant" in route.calls.last.request.headers


@pytest.mark.asyncio
async def test_assess_identity_link_trust_override_tenant_kwarg(
    hy: Hydra, respx_mock: respx.MockRouter
) -> None:
    """Per-call `tenant=` overrides the default header."""
    route = respx_mock.get(
        "https://hydra.test/trust/identity/links/idl_x"
    ).mock(return_value=httpx.Response(200, json=LINK_TRUST_BODY))

    await hy.assess_identity_link_trust("idl_x", tenant="tenant_other")
    assert (
        route.calls.last.request.headers["X-Hydra-Tenant"]
        == "tenant_other"
    )


@pytest.mark.asyncio
async def test_assess_identity_link_trust_404_raises_not_found(
    hy: Hydra, respx_mock: respx.MockRouter
) -> None:
    """Unknown link / wrong-tenant link / `None`-tenanted link /
    endpoint-entity miss during the P33 walk all surface as
    404 → `HydraNotFoundError`. The HTTP handler uses the
    broader `"unknown identity"` substring match — the SDK
    just maps 404 to NotFound regardless of the engine's
    error string."""
    respx_mock.get(
        "https://hydra.test/trust/identity/links/idl_ghost"
    ).mock(
        return_value=httpx.Response(
            404,
            json={"error": "unknown identity link: idl_ghost"},
        )
    )
    with pytest.raises(HydraNotFoundError):
        await hy.assess_identity_link_trust("idl_ghost")


@pytest.mark.asyncio
async def test_assess_identity_link_trust_400_raises_validation(
    hy: Hydra, respx_mock: respx.MockRouter
) -> None:
    """Server 400 (missing tenant header etc) → SDK maps to
    `HydraValidationError`."""
    respx_mock.get(
        "https://hydra.test/trust/identity/links/idl_x"
    ).mock(
        return_value=httpx.Response(
            400,
            json={"error": "missing X-Hydra-Tenant header"},
        )
    )
    with pytest.raises(HydraValidationError):
        await hy.assess_identity_link_trust("idl_x")


@pytest.mark.asyncio
async def test_assess_identity_link_trust_500_raises_server(
    hy: Hydra, respx_mock: respx.MockRouter
) -> None:
    """Server 500 (unexpected engine error) → SDK maps to
    `HydraServerError`."""
    respx_mock.get(
        "https://hydra.test/trust/identity/links/idl_x"
    ).mock(
        return_value=httpx.Response(
            500,
            json={"error": "identity link trust assessment failed: ..."},
        )
    )
    with pytest.raises(HydraServerError):
        await hy.assess_identity_link_trust("idl_x")


@pytest.mark.asyncio
async def test_assess_identity_link_trust_url_encodes_link_id(
    hy: Hydra, respx_mock: respx.MockRouter
) -> None:
    """Path helper passes `link_id` through `_seg()` which
    URL-encodes special chars. In practice IdentityLinkId is
    ULID-alphanumeric (no encoding needed), but pin the
    behavior so future id-format changes don't silently break."""
    # URL with a literal space; _seg(value, safe="") percent-encodes
    # the space → %20.
    route = respx_mock.get(
        "https://hydra.test/trust/identity/links/idl%20x"
    ).mock(return_value=httpx.Response(200, json=LINK_TRUST_BODY))

    await hy.assess_identity_link_trust("idl x")
    # respx matched the URL → _seg() encoded the space correctly.
    assert route.called


@pytest.mark.asyncio
async def test_assess_identity_link_trust_explanation_carries_strategic_warning(
    hy: Hydra, respx_mock: respx.MockRouter
) -> None:
    """Engine bakes the structural-not-semantic warning into the
    `explanation` field. Wire test asserts BOTH substrings —
    locks the contract from drifting silently."""
    respx_mock.get(
        "https://hydra.test/trust/identity/links/idl_x"
    ).mock(return_value=httpx.Response(200, json=LINK_TRUST_BODY))

    a = await hy.assess_identity_link_trust("idl_x")
    assert "STRUCTURAL" in a.explanation
    assert "SEMANTIC" in a.explanation


@pytest.mark.asyncio
async def test_assess_identity_link_trust_factors_include_unapplied(
    hy: Hydra, respx_mock: respx.MockRouter
) -> None:
    """Explainability contract — at least one factor record has
    `applied: False`. Pin so a future "filter applied=true only"
    refactor breaks the wire test loudly."""
    respx_mock.get(
        "https://hydra.test/trust/identity/links/idl_x"
    ).mock(return_value=httpx.Response(200, json=LINK_TRUST_BODY))

    a = await hy.assess_identity_link_trust("idl_x")
    assert any(not f.applied for f in a.factors)


@pytest.mark.asyncio
async def test_assess_identity_link_trust_factors_length_is_eleven(
    hy: Hydra, respx_mock: respx.MockRouter
) -> None:
    """11-factor explainability lock. P39 emits exactly 11 factor
    records on every assessment; the SDK must not filter or
    drop any."""
    respx_mock.get(
        "https://hydra.test/trust/identity/links/idl_x"
    ).mock(return_value=httpx.Response(200, json=LINK_TRUST_BODY))

    a = await hy.assess_identity_link_trust("idl_x")
    assert len(a.factors) == 11


def test_assess_identity_link_trust_sync_parity(
    hy_sync: HydraSync, respx_mock: respx.MockRouter
) -> None:
    """Sync mirror returns the same typed envelope as the async
    client."""
    respx_mock.get(
        "https://hydra.test/trust/identity/links/idl_x"
    ).mock(return_value=httpx.Response(200, json=LINK_TRUST_BODY))

    a = hy_sync.assess_identity_link_trust("idl_x")
    assert isinstance(a, IdentityLinkTrustAssessment)
    assert a.level == "High"
    assert len(a.factors) == 11


def test_identity_link_trust_assessment_forbids_extra_fields() -> None:
    """Pydantic `ConfigDict(extra="forbid")` rejects unknown
    fields — locks the wire contract from accidental drift."""
    import pydantic

    bad = {**LINK_TRUST_BODY, "rogue_field": "should fail"}
    with pytest.raises(pydantic.ValidationError):
        IdentityLinkTrustAssessment.model_validate(bad)
