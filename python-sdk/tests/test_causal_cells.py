"""Tests for `Hydra.causal_cell(...)` and `Hydra.causal_cells(...)`
(Patch 25 — CausalCell Read/Query HTTP + Python SDK).

Verifies:
  - `causal_cell` hits `GET /causal-cells/{cell_id}` and returns a
    typed `CausalCell`
  - `causal_cells` (no filter) hits `GET /causal-cells` and parses
    the paginated `{cells, next_cursor?}` shape into a typed list
  - `causal_cells(kind=...)` propagates `?kind=` and parses the
    unpaginated `{cells}` shape
  - `kind` accepts both `"reflex"` (str) and the externally-tagged
    `{"Custom": "label"}` dict form
  - Per-call tenant override propagates as `X-Hydra-Tenant`
  - Sync mirrors return the same typed envelopes
  - 404 → `HydraNotFoundError` (unknown cell, wrong tenant, AND
    `None`-tenanted system cell all surface identically by design)
  - 400 (missing tenant OR unknown cursor) → `HydraValidationError`
"""

from __future__ import annotations

from typing import Any

import httpx
import pytest
import respx

from hydra import (
    CausalCell,
    Hydra,
    HydraNotFoundError,
    HydraSync,
    HydraValidationError,
)


# === Fixtures ===

REFLEX_CELL_BODY: dict[str, Any] = {
    "id": "cell_reflex_one",
    "tenant_id": "tenant_test",
    "kind": "Reflex",
    "subject": "hydra.commit-rate",
    "source_events": ["evt_1"],
    "evidence_ids": ["ev_1"],
    "claim_ids": ["claim_1"],
    "action_ids": ["act_1"],
    "outcome_ids": ["out_1"],
    "observation_run_ids": ["mmrun_1"],
    "child_cell_ids": [],
    "trust_score": 0.85,
    "summary": "commit-rate reflex chain",
    "created_by": "actor_test",
    "created_at": "2026-05-30T12:00:00Z",
    "caused_by": "evt_1",
}

HEALTH_CELL_BODY: dict[str, Any] = {
    **REFLEX_CELL_BODY,
    "id": "cell_health_one",
    "kind": "Health",
    "subject": "hydra.health",
    "child_cell_ids": ["cell_reflex_one"],
}

CUSTOM_CELL_BODY: dict[str, Any] = {
    **REFLEX_CELL_BODY,
    "id": "cell_custom_one",
    "kind": {"Custom": "invoice_anomaly"},
    "subject": "invoice.42",
}


# === Async tests ===


@pytest.mark.asyncio
async def test_causal_cell_returns_typed_cell(
    hy: Hydra, respx_mock: respx.MockRouter
) -> None:
    route = respx_mock.get(
        "https://hydra.test/causal-cells/cell_reflex_one"
    ).mock(
        return_value=httpx.Response(
            200, json={"cell": REFLEX_CELL_BODY}
        )
    )

    cell = await hy.causal_cell("cell_reflex_one")

    assert isinstance(cell, CausalCell)
    assert cell.id == "cell_reflex_one"
    assert cell.kind == "Reflex"
    assert cell.subject == "hydra.commit-rate"
    assert cell.trust_score == 0.85
    assert cell.claim_ids == ["claim_1"]
    # Tenant propagated automatically from the fixture's default.
    assert "X-Hydra-Tenant" in route.calls.last.request.headers


@pytest.mark.asyncio
async def test_causal_cell_custom_kind_round_trips(
    hy: Hydra, respx_mock: respx.MockRouter
) -> None:
    """Pin: a `Custom("invoice_anomaly")` cell on the wire arrives
    as `{"Custom": "invoice_anomaly"}` and round-trips through
    Pydantic intact. Dashboards key off `kind` to render cell
    chips; the union form must survive validation."""
    respx_mock.get(
        "https://hydra.test/causal-cells/cell_custom_one"
    ).mock(
        return_value=httpx.Response(
            200, json={"cell": CUSTOM_CELL_BODY}
        )
    )

    cell = await hy.causal_cell("cell_custom_one")

    assert cell.kind == {"Custom": "invoice_anomaly"}


@pytest.mark.asyncio
async def test_causal_cells_paginated_unfiltered(
    hy: Hydra, respx_mock: respx.MockRouter
) -> None:
    """`causal_cells()` with no filter hits `/causal-cells` and
    parses the paginated `{cells, next_cursor}` shape into a
    typed list."""
    respx_mock.get("https://hydra.test/causal-cells").mock(
        return_value=httpx.Response(
            200,
            json={
                "cells": [REFLEX_CELL_BODY, HEALTH_CELL_BODY],
                "next_cursor": "cell_health_one",
            },
        )
    )

    cells = await hy.causal_cells()

    assert len(cells) == 2
    assert all(isinstance(c, CausalCell) for c in cells)
    assert cells[0].kind == "Reflex"
    assert cells[1].kind == "Health"


@pytest.mark.asyncio
async def test_causal_cells_filter_by_string_kind(
    hy: Hydra, respx_mock: respx.MockRouter
) -> None:
    """`kind="reflex"` propagates as `?kind=reflex` and parses the
    unpaginated `{cells}` filtered shape."""
    route = respx_mock.get(
        "https://hydra.test/causal-cells",
        params={"kind": "reflex"},
    ).mock(
        return_value=httpx.Response(
            200, json={"cells": [REFLEX_CELL_BODY]}
        )
    )

    cells = await hy.causal_cells(kind="reflex")

    assert len(cells) == 1
    assert cells[0].kind == "Reflex"
    assert route.calls.last.request.url.params["kind"] == "reflex"


@pytest.mark.asyncio
async def test_causal_cells_filter_by_custom_kind_dict(
    hy: Hydra, respx_mock: respx.MockRouter
) -> None:
    """Passing the externally-tagged `{"Custom": "invoice_anomaly"}`
    dict form unwraps the label client-side and sends
    `?kind=invoice_anomaly`. Pin the unwrap behavior so callers
    can mirror the Rust enum shape in either direction."""
    route = respx_mock.get(
        "https://hydra.test/causal-cells",
        params={"kind": "invoice_anomaly"},
    ).mock(
        return_value=httpx.Response(
            200, json={"cells": [CUSTOM_CELL_BODY]}
        )
    )

    cells = await hy.causal_cells(kind={"Custom": "invoice_anomaly"})

    assert len(cells) == 1
    assert cells[0].kind == {"Custom": "invoice_anomaly"}
    assert (
        route.calls.last.request.url.params["kind"]
        == "invoice_anomaly"
    )


@pytest.mark.asyncio
async def test_causal_cells_pagination_params_propagate(
    hy: Hydra, respx_mock: respx.MockRouter
) -> None:
    """`limit` and `after` round-trip as URL query params on the
    unfiltered branch."""
    route = respx_mock.get(
        "https://hydra.test/causal-cells",
        params={"limit": "5", "after": "cell_reflex_one"},
    ).mock(
        return_value=httpx.Response(
            200,
            json={"cells": [HEALTH_CELL_BODY], "next_cursor": None},
        )
    )

    cells = await hy.causal_cells(limit=5, after="cell_reflex_one")

    assert len(cells) == 1
    sent_params = route.calls.last.request.url.params
    assert sent_params["limit"] == "5"
    assert sent_params["after"] == "cell_reflex_one"


@pytest.mark.asyncio
async def test_causal_cell_tenant_override_propagates(
    hy: Hydra, respx_mock: respx.MockRouter
) -> None:
    """Per-call `tenant=` overrides the client default and lands
    as `X-Hydra-Tenant`."""
    route = respx_mock.get(
        "https://hydra.test/causal-cells/cell_reflex_one"
    ).mock(
        return_value=httpx.Response(
            200, json={"cell": REFLEX_CELL_BODY}
        )
    )

    await hy.causal_cell("cell_reflex_one", tenant="tenant_other")

    assert (
        route.calls.last.request.headers["X-Hydra-Tenant"]
        == "tenant_other"
    )


@pytest.mark.asyncio
async def test_causal_cell_unknown_raises_not_found(
    hy: Hydra, respx_mock: respx.MockRouter
) -> None:
    """404 → `HydraNotFoundError`. Unknown cell, wrong tenant, AND
    `None`-tenanted system cells all surface identically by
    design (strict tenant isolation — no cross-tenant probing)."""
    respx_mock.get(
        "https://hydra.test/causal-cells/cell_ghost"
    ).mock(
        return_value=httpx.Response(
            404,
            json={"error": "causal cell not found: cell_ghost"},
        )
    )

    with pytest.raises(HydraNotFoundError):
        await hy.causal_cell("cell_ghost")


@pytest.mark.asyncio
async def test_causal_cells_bad_cursor_raises_validation(
    hy: Hydra, respx_mock: respx.MockRouter
) -> None:
    """An unknown `?after=` cursor is a client bug, not a silent
    empty page. The server returns 400; the SDK maps it to
    `HydraValidationError`."""
    respx_mock.get(
        "https://hydra.test/causal-cells",
        params={"after": "cell_does_not_exist"},
    ).mock(
        return_value=httpx.Response(
            400,
            json={"error": "unknown causal cell cursor: cell_does_not_exist"},
        )
    )

    with pytest.raises(HydraValidationError):
        await hy.causal_cells(after="cell_does_not_exist")


# === Sync mirrors ===


def test_causal_cell_sync_mirror(
    hy_sync: HydraSync, respx_mock: respx.MockRouter
) -> None:
    respx_mock.get(
        "https://hydra.test/causal-cells/cell_reflex_one"
    ).mock(
        return_value=httpx.Response(
            200, json={"cell": REFLEX_CELL_BODY}
        )
    )

    cell = hy_sync.causal_cell("cell_reflex_one")

    assert isinstance(cell, CausalCell)
    assert cell.id == "cell_reflex_one"
    assert cell.kind == "Reflex"


def test_causal_cells_sync_mirror_filter_by_kind(
    hy_sync: HydraSync, respx_mock: respx.MockRouter
) -> None:
    """Sync parity for the filtered branch — operator dashboards
    and Jupyter notebooks both rely on this."""
    respx_mock.get(
        "https://hydra.test/causal-cells",
        params={"kind": "health"},
    ).mock(
        return_value=httpx.Response(
            200, json={"cells": [HEALTH_CELL_BODY]}
        )
    )

    cells = hy_sync.causal_cells(kind="health")

    assert len(cells) == 1
    assert cells[0].kind == "Health"
    assert cells[0].child_cell_ids == ["cell_reflex_one"]
