"""Tests for the Patch 48 Correlation Anchor SDK methods:

  - `Hydra.anchor_correlation_candidate(candidate, *, actor, tenant=None)`
  - `HydraSync.anchor_correlation_candidate(candidate, *, actor, tenant=None)`

HTTP-layer contracts (request body shape, VALIDATE-don't-overwrite
tenant rule, response envelope, error mapping, no-dedup) are pinned
at the Rust HTTP boundary in
`crates/hydra-net/src/http/correlations.rs`. These tests focus on
the SDK wire round-trip — request body shape, tenant header
propagation, response unwrapping (`{cell: ...}` → typed
`CausalCell`), error mapping (400 → `HydraValidationError`), and
sync parity.

Reuses `CorrelationCandidate` fixture shape from
`test_correlation_assess.py`, overriding trust to High / Strong /
0.95 so the request body shape mirrors a real post-assess
candidate. The mocked response is a deterministic Incident
`CausalCell` body — the SDK has no engine to drive, so we shape
the wire response directly.
"""

from __future__ import annotations

from typing import Any

import httpx
import pytest
import respx

from hydra import (
    CausalCell,
    CorrelationCandidate,
    Hydra,
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


def _make_reasons() -> list[dict[str, Any]]:
    return [
        {
            "kind": reason_kind,
            "weight": weight,
            "applied": True,
            "detail": "p48 fixture stub",
        }
        for reason_kind, _, weight in _REASON_KIND_PAIRS
    ]


def _make_factors() -> list[dict[str, Any]]:
    return [
        {
            "kind": factor_kind,
            "weight": weight,
            "applied": True,
            "detail": "p48 fixture stub",
        }
        for _, factor_kind, weight in _REASON_KIND_PAIRS
    ]


# A High/Strong candidate body (post-assess shape). Reused as the
# input to `anchor_correlation_candidate`.
CANDIDATE_BODY: dict[str, Any] = {
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
        "score": 0.95,
        "level": "High",
        "strength": "Strong",
        "explanation": "p48 fixture verdict — High/Strong",
        "factors": _make_factors(),
        "assessed_at": "2026-06-02T12:00:00Z",
    },
    "created_at": "2026-06-02T12:00:00Z",
}

# Mirror of the cell P47 engine produces — Incident, no
# source_events/action_ids/outcome_ids/observation_run_ids,
# trust_score preserved from candidate, caused_by None.
INCIDENT_CELL_BODY: dict[str, Any] = {
    "id": "cell_p48_incident",
    "tenant_id": "tenant_test",
    "kind": "Incident",
    "subject": "correlation.2_signals",
    "source_events": [],
    "evidence_ids": [],
    "claim_ids": [],
    "action_ids": [],
    "outcome_ids": [],
    "observation_run_ids": [],
    "child_cell_ids": [],
    "trust_score": 0.95,
    "summary": (
        "correlation anchor: 2 signals, 0 entities, 0 cells, "
        "strength=Strong, trust=0.95"
    ),
    "created_by": "actor_ops",
    "created_at": "2026-06-02T12:00:05Z",
    "caused_by": None,
}


# === Tests ===


@pytest.mark.asyncio
async def test_anchor_correlation_candidate_returns_typed_cell(
    hy: Hydra, respx_mock: respx.MockRouter
) -> None:
    """Happy path — POST `{candidate, actor}` returns the
    `{cell}` envelope, unwrapped to a typed `CausalCell`
    with `kind == "Incident"` and `trust_score` preserved."""
    route = respx_mock.post(
        "https://hydra.test/correlations/anchor"
    ).mock(
        return_value=httpx.Response(200, json={"cell": INCIDENT_CELL_BODY})
    )

    candidate = CorrelationCandidate.model_validate(CANDIDATE_BODY)
    cell = await hy.anchor_correlation_candidate(
        candidate, actor="actor_ops"
    )
    assert isinstance(cell, CausalCell)
    assert cell.kind == "Incident"
    assert cell.trust_score == 0.95
    assert cell.subject == "correlation.2_signals"

    # Body shape: `{candidate, actor}`. Tenant header set.
    assert "X-Hydra-Tenant" in route.calls.last.request.headers
    import json as _json
    sent = _json.loads(route.calls.last.request.content)
    assert "candidate" in sent
    assert "actor" in sent
    assert sent["actor"] == "actor_ops"
    # Candidate body round-trips through model_dump.
    assert sent["candidate"]["trust"]["level"] == "High"
    assert sent["candidate"]["trust"]["strength"] == "Strong"


@pytest.mark.asyncio
async def test_anchor_correlation_candidate_tenant_override(
    hy: Hydra, respx_mock: respx.MockRouter
) -> None:
    """Per-call `tenant=` overrides the default header — required
    for cross-tenant operator workflows. Mirrors P42/P46 pattern."""
    route = respx_mock.post(
        "https://hydra.test/correlations/anchor"
    ).mock(
        return_value=httpx.Response(200, json={"cell": INCIDENT_CELL_BODY})
    )

    candidate = CorrelationCandidate.model_validate(CANDIDATE_BODY)
    await hy.anchor_correlation_candidate(
        candidate, actor="actor_ops", tenant="tenant_other"
    )
    assert (
        route.calls.last.request.headers["X-Hydra-Tenant"]
        == "tenant_other"
    )


@pytest.mark.asyncio
async def test_anchor_correlation_candidate_low_trust_raises_validation(
    hy: Hydra, respx_mock: respx.MockRouter
) -> None:
    """Server returns 400 with `"anchor rejected: trust below
    High/Strong ..."` → SDK maps to `HydraValidationError`. Same
    mapping covers tenant mismatch, signal mismatch, empty actor,
    too-few-signals (every P47 rejection is caller-fixable; no
    404 path because the engine performs no store lookups)."""
    respx_mock.post(
        "https://hydra.test/correlations/anchor"
    ).mock(
        return_value=httpx.Response(
            400,
            json={
                "error": (
                    "anchor rejected: trust below High/Strong "
                    "(score=0.300, level=Low, strength=Weak)"
                )
            },
        )
    )
    candidate = CorrelationCandidate.model_validate(CANDIDATE_BODY)
    with pytest.raises(HydraValidationError):
        await hy.anchor_correlation_candidate(candidate, actor="actor_ops")


def test_anchor_correlation_candidate_sync_mirror(
    hy_sync: HydraSync, respx_mock: respx.MockRouter
) -> None:
    """Sync mirror returns the same typed envelope as the async
    client. Locks signature + behavioral parity."""
    respx_mock.post(
        "https://hydra.test/correlations/anchor"
    ).mock(
        return_value=httpx.Response(200, json={"cell": INCIDENT_CELL_BODY})
    )
    candidate = CorrelationCandidate.model_validate(CANDIDATE_BODY)
    cell = hy_sync.anchor_correlation_candidate(candidate, actor="actor_ops")
    assert isinstance(cell, CausalCell)
    assert cell.kind == "Incident"
    assert cell.trust_score == 0.95
