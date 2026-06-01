"""Tests for the Patch 36 source trust SDK method:

  - `Hydra.assess_source_trust(source, *, tenant=None)`

The HTTP-layer contracts (empty + sentinel sources → 400,
unknown-but-valid source → 200 with `level="Unknown"`,
None-tenanted source data invisible to tenanted probe via 200
empty verdict NOT 404, route lives under `/trust/identity/*`)
are pinned at the Rust HTTP boundary in
`crates/hydra-net/src/http/trust.rs`. These tests focus on the
SDK wire round-trip — typed envelope parsing, URL-encoding via
`_seg()`, tenant header propagation, error mapping, and sync
parity.
"""

from __future__ import annotations

from typing import Any

import httpx
import pytest
import respx

from hydra import (
    Hydra,
    HydraSync,
    HydraValidationError,
    SourceTrustAssessment,
)


# === Fixture ===

SOURCE_TRUST_BODY: dict[str, Any] = {
    "source": "snowflake",
    "score": 0.80,
    "level": "High",
    "explanation": "Source verdict High (score 0.80) — 6 positive "
    "factor(s) and 0 penalty factor(s) applied out of 6 total. "
    "v1 measures identity-claim trust, NOT operational health "
    "(freshness, heartbeat, SLA, schema drift not yet considered).",
    "factors": [
        {
            "kind": "source_has_identity_aliases",
            "weight": 0.20,
            "applied": True,
            "detail": "5 entities reference source 'snowflake'",
        },
        {
            "kind": "low_trust_entities_from_source",
            "weight": -0.20,
            "applied": False,
            "detail": "mean entity trust 0.78 (> 0.40)",
        },
    ],
    "related_entity_ids": [
        "ide_dash0",
        "ide_d0",
        "ide_d1",
        "ide_d2",
        "ide_t0",
    ],
    "entity_sample_size": 5,
    "evidence_sample_size": 2,
    "assessed_at": "2026-06-01T12:00:00Z",
}


# === assess_source_trust ===


@pytest.mark.asyncio
async def test_assess_source_trust_returns_typed_assessment(
    hy: Hydra, respx_mock: respx.MockRouter
) -> None:
    """Happy path — `GET /trust/identity/sources/snowflake`
    round-trips through to a typed Pydantic `SourceTrustAssessment`.
    Pin that:
      - the response is parsed via `model_validate` (not raw dict)
      - all P35 + P36 fields preserve through serde
      - `related_entity_ids` (P36 Adaptation A1) is on the wire
      - `entity_sample_size` + `evidence_sample_size` carry forward
      - factor list keeps `applied=false` records (explainability)
      - tenant header propagates automatically from fixture default
    """
    route = respx_mock.get(
        "https://hydra.test/trust/identity/sources/snowflake"
    ).mock(return_value=httpx.Response(200, json=SOURCE_TRUST_BODY))

    a = await hy.assess_source_trust("snowflake")
    assert isinstance(a, SourceTrustAssessment)
    assert a.source == "snowflake"
    assert a.level == "High"
    assert abs(a.score - 0.80) < 1e-9
    # Patch 36 Adaptation A1 — related_entity_ids preserved.
    assert a.related_entity_ids == [
        "ide_dash0",
        "ide_d0",
        "ide_d1",
        "ide_d2",
        "ide_t0",
    ]
    # Cap-transparency sizes preserved.
    assert a.entity_sample_size == 5
    assert a.evidence_sample_size == 2
    # Factor list preserved — including applied=false.
    assert len(a.factors) == 2
    assert any(not f.applied for f in a.factors)
    # Tenant header propagated.
    assert "X-Hydra-Tenant" in route.calls.last.request.headers


@pytest.mark.asyncio
async def test_assess_source_trust_tenant_override_propagates(
    hy: Hydra, respx_mock: respx.MockRouter
) -> None:
    """Per-call `tenant=` kwarg overrides the default header."""
    route = respx_mock.get(
        "https://hydra.test/trust/identity/sources/snowflake"
    ).mock(return_value=httpx.Response(200, json=SOURCE_TRUST_BODY))

    await hy.assess_source_trust("snowflake", tenant="tenant_other")
    assert (
        route.calls.last.request.headers["X-Hydra-Tenant"]
        == "tenant_other"
    )


@pytest.mark.asyncio
async def test_assess_source_trust_unknown_source_returns_low_not_not_found(
    hy: Hydra, respx_mock: respx.MockRouter
) -> None:
    """Wrinkle E pin (carries from P35). A well-formed but unseen
    source is a legitimate 200 verdict with `level="Unknown"`,
    NOT a 404. The SDK must NOT raise `HydraNotFoundError` —
    the response is a normal typed assessment with empty sample
    sizes. Critical contract distinction vs P34's entity-trust
    surface (where unknown id → 404)."""
    empty_body = {
        "source": "neverseen",
        "score": 0.0,
        "level": "Unknown",
        "explanation": "Source verdict Unknown (score 0.00) — no "
        "aliases from source 'neverseen' observed in tenant scope, "
        "no evidence records mapped. v1 measures identity-claim "
        "trust, NOT operational health.",
        "factors": [
            {
                "kind": "source_has_identity_aliases",
                "weight": 0.20,
                "applied": False,
                "detail": "no aliases from source 'neverseen' observed",
            },
        ],
        "related_entity_ids": [],
        "entity_sample_size": 0,
        "evidence_sample_size": 0,
        "assessed_at": "2026-06-01T12:00:00Z",
    }
    respx_mock.get(
        "https://hydra.test/trust/identity/sources/neverseen"
    ).mock(return_value=httpx.Response(200, json=empty_body))

    # No exception — typed assessment returned.
    a = await hy.assess_source_trust("neverseen")
    assert isinstance(a, SourceTrustAssessment)
    assert a.source == "neverseen"
    assert a.level == "Unknown"
    assert a.score == 0.0
    assert a.entity_sample_size == 0
    assert a.evidence_sample_size == 0
    assert a.related_entity_ids == []


@pytest.mark.asyncio
async def test_assess_source_trust_validation_error_on_empty_source(
    hy: Hydra, respx_mock: respx.MockRouter
) -> None:
    """SDK does NOT pre-validate the source (Wrinkle H1 — server
    is the source of truth). An empty source produces a path of
    `/trust/identity/sources/` which axum routes as 404. For the
    sentinel `__system__` case, the HTTP handler returns 400
    which the SDK maps to `HydraValidationError`. Pin the 400
    path explicitly — it's the contract operators rely on for
    structured error handling."""
    respx_mock.get(
        "https://hydra.test/trust/identity/sources/__system__"
    ).mock(
        return_value=httpx.Response(
            400,
            json={"error": "source '__system__' is a reserved sentinel"},
        )
    )
    with pytest.raises(HydraValidationError):
        await hy.assess_source_trust("__system__")


@pytest.mark.asyncio
async def test_assess_source_trust_url_encoded_source(
    hy: Hydra, respx_mock: respx.MockRouter
) -> None:
    """Adaptation C pin — sources containing URL-special chars
    round-trip through `_seg()` (which calls
    `urllib.parse.quote(value, safe="")`). Pin both a slash-
    containing source AND a dotted source.
    """
    # Slash → %2F
    respx_mock.get(
        "https://hydra.test/trust/identity/sources/snowflake%2Feast"
    ).mock(
        return_value=httpx.Response(
            200,
            json={**SOURCE_TRUST_BODY, "source": "snowflake/east"},
        )
    )
    a = await hy.assess_source_trust("snowflake/east")
    assert a.source == "snowflake/east"

    # Dotted source — passes through as-is (`.` is path-safe).
    respx_mock.get(
        "https://hydra.test/trust/identity/sources/github.com"
    ).mock(
        return_value=httpx.Response(
            200,
            json={**SOURCE_TRUST_BODY, "source": "github.com"},
        )
    )
    b = await hy.assess_source_trust("github.com")
    assert b.source == "github.com"


def test_assess_source_trust_sync_mirror(
    hy_sync: HydraSync, respx_mock: respx.MockRouter
) -> None:
    """Sync parity — `HydraSync.assess_source_trust` returns the
    same typed envelope as the async client. Mirrors the P34
    sync-mirror test pattern."""
    respx_mock.get(
        "https://hydra.test/trust/identity/sources/snowflake"
    ).mock(return_value=httpx.Response(200, json=SOURCE_TRUST_BODY))

    a = hy_sync.assess_source_trust("snowflake")
    assert isinstance(a, SourceTrustAssessment)
    assert a.level == "High"
    assert a.related_entity_ids == [
        "ide_dash0",
        "ide_d0",
        "ide_d1",
        "ide_d2",
        "ide_t0",
    ]
