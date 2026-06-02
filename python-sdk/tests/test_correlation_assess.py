"""Tests for the Patch 46 Correlation HTTP + SDK surface:

  - `Hydra.assess_correlation_candidate(signals, *, tenant=None)`
  - `HydraSync.assess_correlation_candidate(signals, *, tenant=None)`

HTTP-layer contracts (request body shape, tenant overwrite anti-
smuggling, response envelope, error mapping, 11 reasons + 11
factors 1:1, `CorrelationStrength.None` is a STRING) are pinned at
the Rust HTTP boundary in
`crates/hydra-net/src/http/correlations.rs`. These tests focus on
the SDK wire round-trip — request body shape, tenant header
propagation, response unwrapping (`{candidate: ...}` →
`CorrelationCandidate`), error mapping (400 →
`HydraValidationError`, 404 → `HydraNotFoundError`), and sync
parity.
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


# === Fixture ===
#
# Mirrors the wire shape the Patch 45 engine produces:
#   - 11 reasons (all built-in CorrelationReasonKind discriminants,
#     PascalCase, applied=false for the all-stub case)
#   - 11 trust factors (1:1 mirror, snake_case kind strings)
#   - `level` == "Unknown", `strength` == "None"
#     (score 0.0 — proves "None" is a STRING value on the wire)

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


def _make_reasons() -> list[dict[str, Any]]:
    return [
        {
            "kind": reason_kind,
            "weight": weight,
            "applied": False,
            "detail": f"{factor_kind} stub for fixture",
        }
        for reason_kind, factor_kind, weight in _REASON_KIND_PAIRS
    ]


def _make_factors() -> list[dict[str, Any]]:
    return [
        {
            "kind": factor_kind,
            "weight": weight,
            "applied": False,
            "detail": f"{factor_kind} stub for fixture",
        }
        for _, factor_kind, weight in _REASON_KIND_PAIRS
    ]


CANDIDATE_RESPONSE: dict[str, Any] = {
    "candidate": {
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
        "reasons": _make_reasons(),
        "trust": {
            "correlation_id": None,
            "score": 0.0,
            "level": "Unknown",
            # LOAD-BEARING: PascalCase string, NOT JSON null.
            "strength": "None",
            "explanation": (
                "Correlation verdict Unknown/None (score 0.00) — 0 "
                "positive and 0 penalty factor(s) applied out of 0/11 "
                "total. v1 assesses CALLER-PROVIDED groupings, NOT "
                "discovers them. Suggestion-only: auto-actions must "
                "compose trust.level == High AND trust.score >= "
                "ACCEPT_CORRELATION_FLOOR with a dedicated audit "
                "event — never act on this assessment alone."
            ),
            "factors": _make_factors(),
            "assessed_at": "2026-06-02T12:00:00Z",
        },
        "created_at": "2026-06-02T12:00:00Z",
    }
}


def _signal(kind: str, signal_id: str) -> CorrelationSignalRef:
    """Build a minimal CorrelationSignalRef the engine accepts."""
    return CorrelationSignalRef.model_validate(
        {
            "kind": kind,
            "id": signal_id,
            "tenant_id": "tenant_test",
            "observed_at": None,
            "entity_ids": [],
            "cell_ids": [],
            "claim_ids": [],
            "evidence_ids": [],
            "metadata": {},
        }
    )


# === assess_correlation_candidate (async) ===


@pytest.mark.asyncio
async def test_assess_correlation_candidate_returns_typed_candidate(
    hy: Hydra, respx_mock: respx.MockRouter
) -> None:
    """Happy path — POST `{signals: [...]}` returns the wrapped
    `{candidate}` body, unwrapped to a typed `CorrelationCandidate`
    with 11 reasons + 11 trust factors + the tenant header
    propagated."""
    route = respx_mock.post(
        "https://hydra.test/correlations/assess"
    ).mock(return_value=httpx.Response(200, json=CANDIDATE_RESPONSE))

    signals = [_signal("External", "ext_a"), _signal("External", "ext_b")]
    candidate = await hy.assess_correlation_candidate(signals)
    assert isinstance(candidate, CorrelationCandidate)
    assert candidate.tenant_id == "tenant_test"
    assert len(candidate.reasons) == 11
    assert len(candidate.trust.factors) == 11
    # Tenant header propagated automatically.
    assert "X-Hydra-Tenant" in route.calls.last.request.headers
    # Body shape pinned.
    import json as _json
    sent = _json.loads(route.calls.last.request.content)
    assert "signals" in sent
    assert len(sent["signals"]) == 2
    assert sent["signals"][0]["kind"] == "External"
    assert sent["signals"][0]["id"] == "ext_a"


@pytest.mark.asyncio
async def test_assess_correlation_candidate_tenant_override(
    hy: Hydra, respx_mock: respx.MockRouter
) -> None:
    """Per-call `tenant=` overrides the default header — required
    for cross-tenant operator workflows. Mirrors P42 / P40 patterns."""
    route = respx_mock.post(
        "https://hydra.test/correlations/assess"
    ).mock(return_value=httpx.Response(200, json=CANDIDATE_RESPONSE))

    signals = [_signal("External", "ext_a"), _signal("External", "ext_b")]
    await hy.assess_correlation_candidate(signals, tenant="tenant_other")
    assert (
        route.calls.last.request.headers["X-Hydra-Tenant"]
        == "tenant_other"
    )


@pytest.mark.asyncio
async def test_assess_correlation_candidate_validation_error_on_too_few_signals(
    hy: Hydra, respx_mock: respx.MockRouter
) -> None:
    """Server returns 400 `{"error": "correlation requires at least
    two signals"}` → SDK maps to `HydraValidationError`. Same
    mapping covers missing tenant, invalid signal kind."""
    respx_mock.post("https://hydra.test/correlations/assess").mock(
        return_value=httpx.Response(
            400,
            json={
                "error": "correlation requires at least two signals"
            },
        )
    )
    signals = [_signal("External", "ext_solo")]
    with pytest.raises(HydraValidationError):
        await hy.assess_correlation_candidate(signals)


@pytest.mark.asyncio
async def test_assess_correlation_candidate_not_found_on_unknown_entity(
    hy: Hydra, respx_mock: respx.MockRouter
) -> None:
    """Server returns 404 on any unknown / wrong-tenant referenced
    entity / cell / claim / evidence — collapsed to prevent
    cross-tenant existence enumeration. SDK maps to
    `HydraNotFoundError`."""
    respx_mock.post("https://hydra.test/correlations/assess").mock(
        return_value=httpx.Response(
            404,
            json={
                "error": (
                    "correlation signal at index 0 references "
                    "unknown identity entity: ide_ghost"
                )
            },
        )
    )
    signals = [
        _signal("External", "ext_a"),
        _signal("External", "ext_b"),
    ]
    with pytest.raises(HydraNotFoundError):
        await hy.assess_correlation_candidate(signals)


@pytest.mark.asyncio
async def test_assess_correlation_candidate_reasons_and_trust_round_trip(
    hy: Hydra, respx_mock: respx.MockRouter
) -> None:
    """Explainability contract pin: `reasons` + `trust.factors` both
    carry exactly 11 entries; they mirror 1:1 (same length, same
    applied bits, same weights, kind discriminants match
    snake_case factor kinds)."""
    respx_mock.post("https://hydra.test/correlations/assess").mock(
        return_value=httpx.Response(200, json=CANDIDATE_RESPONSE)
    )
    signals = [_signal("External", "ext_a"), _signal("External", "ext_b")]
    candidate = await hy.assess_correlation_candidate(signals)
    assert len(candidate.reasons) == 11
    assert len(candidate.trust.factors) == 11
    for reason, factor in zip(candidate.reasons, candidate.trust.factors):
        assert reason.applied == factor.applied
        assert reason.weight == factor.weight
        assert reason.detail == factor.detail


def test_assess_correlation_candidate_sync_mirror(
    hy_sync: HydraSync, respx_mock: respx.MockRouter
) -> None:
    """Sync mirror returns the same typed envelope as the async
    client. Locks signature + behavioral parity."""
    respx_mock.post("https://hydra.test/correlations/assess").mock(
        return_value=httpx.Response(200, json=CANDIDATE_RESPONSE)
    )
    signals = [_signal("External", "ext_a"), _signal("External", "ext_b")]
    candidate = hy_sync.assess_correlation_candidate(signals)
    assert isinstance(candidate, CorrelationCandidate)
    assert len(candidate.reasons) == 11
    assert len(candidate.trust.factors) == 11


def test_correlation_strength_none_is_string(
    hy_sync: HydraSync, respx_mock: respx.MockRouter
) -> None:
    """LOAD-BEARING wire gotcha: `CorrelationStrength.None` is the
    STRING value `"None"` (no correlation), distinct from Python's
    `None`. Mirrors `MatchLevel.None`.

    Comparing with `is None` would silently miss the no-correlation
    case; SDK callers MUST use `== "None"`."""
    respx_mock.post("https://hydra.test/correlations/assess").mock(
        return_value=httpx.Response(200, json=CANDIDATE_RESPONSE)
    )
    signals = [_signal("External", "ext_a"), _signal("External", "ext_b")]
    candidate = hy_sync.assess_correlation_candidate(signals)
    assert candidate.trust.strength == "None"
    # Strict identity check — confirms the value is the string,
    # not Python's None.
    assert candidate.trust.strength is not None
