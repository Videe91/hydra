"""Tests for the Patch 50 Correlation Discover SDK methods:

  - `Hydra.discover_correlation_candidates(seed, *, window_secs, limit, tenant=None)`
  - `HydraSync.discover_correlation_candidates(seed, *, window_secs, limit, tenant=None)`

HTTP-layer contracts (request body shape, OVERWRITE-not-validate
tenant rule, response envelope, error mapping, cross-tenant
seed → empty results, sort DESC ordering) are pinned at the Rust
HTTP boundary in `crates/hydra-net/src/http/correlations.rs`.
These tests focus on the SDK wire round-trip — request body
shape, tenant header propagation, response unwrapping
(`{candidates: [...]}` → `list[CorrelationCandidate]`), error
mapping (400 → `HydraValidationError`, 404 →
`HydraNotFoundError`), and sync parity.

Reuses the candidate fixture shape from `test_correlation_anchor.py`.
The mocked response is `{candidates: [BODY, BODY]}` — two
candidates so the SDK can verify list unwrapping.
"""

from __future__ import annotations

from typing import Any

import httpx
import pytest
import respx

from hydra import (
    CorrelationCandidate,
    CorrelationSignalRef,
    Hydra,
    HydraNotFoundError,
    HydraSync,
    HydraValidationError,
)


# === Fixtures ===

_REASON_KIND_PAIRS = [
    ("SameIdentityEntity", "same_identity_entity", 0.25),
    ("TrustedIdentityLink", "trusted_identity_link", 0.20),
    ("SameSource", "same_source", 0.10),
    ("SourceTrustHigh", "source_trust_high", 0.10),
    ("EntityTrustHigh", "entity_trust_high", 0.15),
    ("CellTrustHigh", "cell_trust_high", 0.15),
    ("TimeProximity", "time_proximity", 0.10),
    ("SemanticSimilarity", "semantic_similarity", 0.0),
    ("ClaimPredicateSimilarity", "claim_predicate_similarity", 0.10),
    ("Contradiction", "contradiction", -0.30),
    ("OperatorConfirmed", "operator_confirmed", 0.0),
]


def _make_reasons(applied: bool) -> list[dict[str, Any]]:
    return [
        {
            "kind": reason_kind,
            "weight": weight,
            "applied": applied,
            "detail": "p50 fixture stub",
        }
        for reason_kind, _, weight in _REASON_KIND_PAIRS
    ]


def _make_factors(applied: bool) -> list[dict[str, Any]]:
    return [
        {
            "kind": factor_kind,
            "weight": weight,
            "applied": applied,
            "detail": "p50 fixture stub",
        }
        for _, factor_kind, weight in _REASON_KIND_PAIRS
    ]


def _candidate_body(
    score: float, level: str, strength: str
) -> dict[str, Any]:
    return {
        "tenant_id": "tenant_test",
        "signals": [
            {
                "kind": "External",
                "id": "ext_a",
                "tenant_id": "tenant_test",
                "observed_at": None,
                "entity_ids": [],
                "cell_ids": [],
                "claim_ids": [],
                "evidence_ids": [],
                "metadata": {},
            },
            {
                "kind": "External",
                "id": "ext_b",
                "tenant_id": "tenant_test",
                "observed_at": None,
                "entity_ids": [],
                "cell_ids": [],
                "claim_ids": [],
                "evidence_ids": [],
                "metadata": {},
            },
        ],
        "entity_ids": [],
        "cell_ids": [],
        "time_window_start": None,
        "time_window_end": None,
        "reasons": _make_reasons(score >= 0.20),
        "trust": {
            "correlation_id": None,
            "score": score,
            "level": level,
            "strength": strength,
            "explanation": f"p50 fixture verdict — {level}/{strength}",
            "factors": _make_factors(score >= 0.20),
            "assessed_at": "2026-06-02T12:00:00Z",
        },
        "created_at": "2026-06-02T12:00:00Z",
    }


# Two-candidate response — wire-form `{candidates: [...]}`. Two
# distinct scores so the SDK can verify list ordering survives
# the round-trip.
DISCOVER_RESPONSE: dict[str, Any] = {
    "candidates": [
        _candidate_body(0.85, "High", "Strong"),
        _candidate_body(0.55, "Medium", "Possible"),
    ]
}


def _seed() -> CorrelationSignalRef:
    return CorrelationSignalRef.model_validate(
        {
            "kind": "IdentityEntity",
            "id": "ide_seed",
            "tenant_id": "tenant_test",
            "observed_at": "2026-06-02T12:00:00Z",
            "entity_ids": ["ide_seed"],
            "cell_ids": [],
            "claim_ids": [],
            "evidence_ids": [],
            "metadata": {},
        }
    )


# === Tests ===


@pytest.mark.asyncio
async def test_discover_correlation_candidates_returns_typed_candidates(
    hy: Hydra, respx_mock: respx.MockRouter
) -> None:
    """Happy path — POST `{seed, window_secs, limit}` returns
    the wrapped `{candidates: [...]}` body, unwrapped to a
    `list[CorrelationCandidate]`. Body shape + tenant header
    propagation pinned."""
    route = respx_mock.post(
        "https://hydra.test/correlations/discover"
    ).mock(
        return_value=httpx.Response(200, json=DISCOVER_RESPONSE)
    )

    seed = _seed()
    result = await hy.discover_correlation_candidates(
        seed, window_secs=900, limit=10
    )
    assert isinstance(result, list)
    assert len(result) == 2
    assert all(isinstance(c, CorrelationCandidate) for c in result)
    # Scores survive the round-trip in order.
    assert result[0].trust.score == 0.85
    assert result[1].trust.score == 0.55

    # Tenant header propagated automatically.
    assert "X-Hydra-Tenant" in route.calls.last.request.headers
    # Body shape pinned.
    import json as _json
    sent = _json.loads(route.calls.last.request.content)
    assert "seed" in sent
    assert "window_secs" in sent
    assert "limit" in sent
    assert sent["window_secs"] == 900
    assert sent["limit"] == 10
    assert sent["seed"]["id"] == "ide_seed"


@pytest.mark.asyncio
async def test_discover_correlation_candidates_tenant_override(
    hy: Hydra, respx_mock: respx.MockRouter
) -> None:
    """Per-call `tenant=` overrides the default header — required
    for cross-tenant operator workflows."""
    route = respx_mock.post(
        "https://hydra.test/correlations/discover"
    ).mock(
        return_value=httpx.Response(200, json=DISCOVER_RESPONSE)
    )

    await hy.discover_correlation_candidates(
        _seed(), window_secs=900, limit=10, tenant="tenant_other"
    )
    assert (
        route.calls.last.request.headers["X-Hydra-Tenant"]
        == "tenant_other"
    )


@pytest.mark.asyncio
async def test_discover_correlation_candidates_validation_error_on_zero_limit(
    hy: Hydra, respx_mock: respx.MockRouter
) -> None:
    """Server returns 400 `{"error": "limit must be > 0"}` →
    SDK maps to `HydraValidationError`. Same mapping covers
    `window_secs == 0`, missing tenant, invalid seed kind."""
    respx_mock.post(
        "https://hydra.test/correlations/discover"
    ).mock(
        return_value=httpx.Response(
            400,
            json={"error": "limit must be > 0"},
        )
    )
    with pytest.raises(HydraValidationError):
        await hy.discover_correlation_candidates(
            _seed(), window_secs=900, limit=0
        )


@pytest.mark.asyncio
async def test_discover_correlation_candidates_not_found_on_unknown_ref_mocked(
    hy: Hydra, respx_mock: respx.MockRouter
) -> None:
    """Forward-compat pin: the wire's 404 arm is currently
    UNREACHABLE from real P49 engine behavior (per-pair lookup
    misses silently swallow → 200 + empty candidates). But the
    SDK still maps 404 → `HydraNotFoundError` for future engine
    paths that may surface unknown-ref errors directly. This
    test pins the mapping using a MOCKED 404 — it does NOT
    pretend the real engine returns 404 in v1."""
    respx_mock.post(
        "https://hydra.test/correlations/discover"
    ).mock(
        return_value=httpx.Response(
            404,
            json={
                "error": (
                    "(forward-compat) unknown identity entity: "
                    "ide_ghost"
                )
            },
        )
    )
    with pytest.raises(HydraNotFoundError):
        await hy.discover_correlation_candidates(
            _seed(), window_secs=900, limit=10
        )


def test_discover_correlation_candidates_sync_mirror(
    hy_sync: HydraSync, respx_mock: respx.MockRouter
) -> None:
    """Sync mirror returns the same typed envelope as the async
    client. Locks signature + behavioral parity."""
    respx_mock.post(
        "https://hydra.test/correlations/discover"
    ).mock(
        return_value=httpx.Response(200, json=DISCOVER_RESPONSE)
    )
    result = hy_sync.discover_correlation_candidates(
        _seed(), window_secs=900, limit=10
    )
    assert isinstance(result, list)
    assert len(result) == 2
    assert all(isinstance(c, CorrelationCandidate) for c in result)
    assert result[0].trust.score == 0.85
    assert result[1].trust.score == 0.55
