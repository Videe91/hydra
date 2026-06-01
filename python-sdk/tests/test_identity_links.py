"""Tests for the Patch 38 IdentityLink SDK methods:

  - `Hydra.create_identity_link(link, *, tenant=None)`
  - `Hydra.identity_link(link_id, *, tenant=None)`
  - `Hydra.identity_links(*, from_entity_id, to_entity_id, kind,
        after, limit, tenant)`
  - `Hydra.identity_links_for_entity(entity_id, *, kind, after,
        limit, tenant)`

HTTP-layer contracts (tenant scoping, anti-smuggling, 404
unification, route ordering, kind PascalCase-vs-snake-case URL
wart) are pinned at the Rust HTTP boundary in
`crates/hydra-net/src/http/identity.rs`. These tests focus on the
SDK wire round-trip — typed envelope parsing, URL param
propagation, kind dict-vs-string extraction, the
`_link_kind_param` helper, tenant header propagation, error
mapping, and sync parity.
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
    IdentityLink,
)
from hydra.client import _link_kind_param


# === Fixtures ===

LINK_BODY: dict[str, Any] = {
    "id": "idl_revenue_link",
    "tenant_id": "tenant_default",
    "kind": "DependsOn",
    "from_entity_id": "ide_dbt_model",
    "to_entity_id": "ide_snowflake_table",
    "confidence": 0.9,
    "evidence_ids": [],
    "claim_ids": [],
    "cell_ids": [],
    "metadata": {},
    "created_by": "actor_ops",
    "created_at": "2026-06-01T12:00:00Z",
    "caused_by": None,
}


# === _link_kind_param helper unit tests ===


def test_link_kind_param_none_returns_none() -> None:
    """`kind=None` short-circuits to `None`."""
    assert _link_kind_param(None) is None


def test_link_kind_param_string_passes_through() -> None:
    """String input passes through verbatim. **Wart**: caller
    passing `"DownstreamOf"` (PascalCase) ends up filtering for
    `Custom("DownstreamOf")` server-side — documented wart."""
    assert _link_kind_param("downstream_of") == "downstream_of"
    assert _link_kind_param("DownstreamOf") == "DownstreamOf"


def test_link_kind_param_dict_extracts_custom_label() -> None:
    """Dict form `{"Custom": "uses_metric"}` unwraps to the inner
    label. Wire form for Custom kinds round-trips through `?kind=`
    as the bare label."""
    assert _link_kind_param({"Custom": "uses_metric"}) == "uses_metric"


# === create_identity_link ===


@pytest.mark.asyncio
async def test_create_identity_link_returns_typed_link(
    hy: Hydra, respx_mock: respx.MockRouter
) -> None:
    """Happy path — POST returns the typed `IdentityLink` with
    all P37 fields preserved (including the P38 polish defaults
    on empty collections)."""
    route = respx_mock.post(
        "https://hydra.test/identity/links"
    ).mock(return_value=httpx.Response(200, json={"link": LINK_BODY}))

    link = IdentityLink.model_validate(LINK_BODY)
    stored = await hy.create_identity_link(link)
    assert isinstance(stored, IdentityLink)
    assert stored.id == "idl_revenue_link"
    assert stored.kind == "DependsOn"
    assert stored.from_entity_id == "ide_dbt_model"
    assert stored.to_entity_id == "ide_snowflake_table"
    # Tenant header propagated.
    assert "X-Hydra-Tenant" in route.calls.last.request.headers


@pytest.mark.asyncio
async def test_create_identity_link_tenant_override_propagates(
    hy: Hydra, respx_mock: respx.MockRouter
) -> None:
    """Per-call `tenant=` overrides default header."""
    route = respx_mock.post(
        "https://hydra.test/identity/links"
    ).mock(return_value=httpx.Response(200, json={"link": LINK_BODY}))

    link = IdentityLink.model_validate(LINK_BODY)
    await hy.create_identity_link(link, tenant="tenant_other")
    assert (
        route.calls.last.request.headers["X-Hydra-Tenant"]
        == "tenant_other"
    )


@pytest.mark.asyncio
async def test_create_identity_link_400_maps_to_validation_error(
    hy: Hydra, respx_mock: respx.MockRouter
) -> None:
    """Server returns 400 for self-link / duplicate / invalid
    kind; SDK maps to `HydraValidationError`."""
    respx_mock.post(
        "https://hydra.test/identity/links"
    ).mock(
        return_value=httpx.Response(
            400,
            json={"error": "self-link rejected: from == to == ide_a"},
        )
    )
    link = IdentityLink.model_validate({**LINK_BODY, "to_entity_id": "ide_dbt_model"})
    with pytest.raises(HydraValidationError):
        await hy.create_identity_link(link)


@pytest.mark.asyncio
async def test_create_identity_link_404_maps_to_not_found_error(
    hy: Hydra, respx_mock: respx.MockRouter
) -> None:
    """Server returns 404 for unknown from/to entity (unified
    P37 error); SDK maps to `HydraNotFoundError`."""
    respx_mock.post(
        "https://hydra.test/identity/links"
    ).mock(
        return_value=httpx.Response(
            404,
            json={"error": "unknown identity entity: ide_ghost"},
        )
    )
    link = IdentityLink.model_validate({**LINK_BODY, "from_entity_id": "ide_ghost"})
    with pytest.raises(HydraNotFoundError):
        await hy.create_identity_link(link)


# === identity_link ===


@pytest.mark.asyncio
async def test_identity_link_returns_typed_link(
    hy: Hydra, respx_mock: respx.MockRouter
) -> None:
    respx_mock.get(
        "https://hydra.test/identity/links/idl_revenue_link"
    ).mock(return_value=httpx.Response(200, json={"link": LINK_BODY}))

    link = await hy.identity_link("idl_revenue_link")
    assert isinstance(link, IdentityLink)
    assert link.kind == "DependsOn"


@pytest.mark.asyncio
async def test_identity_link_unknown_raises_not_found(
    hy: Hydra, respx_mock: respx.MockRouter
) -> None:
    """Wrong-tenant / unknown / `None`-tenanted link all surface
    as 404 → `HydraNotFoundError`."""
    respx_mock.get(
        "https://hydra.test/identity/links/idl_ghost"
    ).mock(
        return_value=httpx.Response(
            404,
            json={"error": "identity link not found: idl_ghost"},
        )
    )
    with pytest.raises(HydraNotFoundError):
        await hy.identity_link("idl_ghost")


# === identity_links (list with filters + pagination) ===


@pytest.mark.asyncio
async def test_identity_links_filter_params_propagate(
    hy: Hydra, respx_mock: respx.MockRouter
) -> None:
    """All filter kwargs land in URL query params."""
    route = respx_mock.get(
        "https://hydra.test/identity/links",
        params={
            "from_entity_id": "ide_a",
            "to_entity_id": "ide_b",
            "kind": "depends_on",
            "after": "idl_x",
            "limit": "10",
        },
    ).mock(
        return_value=httpx.Response(
            200,
            json={"links": [LINK_BODY], "next_cursor": None},
        )
    )

    links, cursor = await hy.identity_links(
        from_entity_id="ide_a",
        to_entity_id="ide_b",
        kind="depends_on",
        after="idl_x",
        limit=10,
    )
    assert len(links) == 1
    assert cursor is None
    sent = route.calls.last.request.url.params
    assert sent["from_entity_id"] == "ide_a"
    assert sent["to_entity_id"] == "ide_b"
    assert sent["kind"] == "depends_on"
    assert sent["after"] == "idl_x"
    assert sent["limit"] == "10"


@pytest.mark.asyncio
async def test_identity_links_kind_dict_extracts_custom(
    hy: Hydra, respx_mock: respx.MockRouter
) -> None:
    """`kind={"Custom": "uses_metric"}` → `?kind=uses_metric` on
    the wire — pinned via `_link_kind_param` helper."""
    route = respx_mock.get(
        "https://hydra.test/identity/links",
        params={"kind": "uses_metric"},
    ).mock(
        return_value=httpx.Response(
            200,
            json={"links": [], "next_cursor": None},
        )
    )
    await hy.identity_links(kind={"Custom": "uses_metric"})
    sent = route.calls.last.request.url.params
    assert sent["kind"] == "uses_metric"


@pytest.mark.asyncio
async def test_identity_links_returns_next_cursor_tuple(
    hy: Hydra, respx_mock: respx.MockRouter
) -> None:
    """Paginated response returns `(links, next_cursor)`. Pin the
    tuple shape so future refactor doesn't switch to a dict
    silently."""
    respx_mock.get(
        "https://hydra.test/identity/links"
    ).mock(
        return_value=httpx.Response(
            200,
            json={"links": [LINK_BODY], "next_cursor": "idl_revenue_link"},
        )
    )
    links, cursor = await hy.identity_links()
    assert len(links) == 1
    assert cursor == "idl_revenue_link"


# === identity_links_for_entity ===


@pytest.mark.asyncio
async def test_identity_links_for_entity_returns_links(
    hy: Hydra, respx_mock: respx.MockRouter
) -> None:
    """Entity-scoped union route returns incoming + outgoing
    links for the entity. Tenant probe happens server-side; SDK
    just round-trips the response."""
    route = respx_mock.get(
        "https://hydra.test/identity/entities/ide_dbt_model/links"
    ).mock(
        return_value=httpx.Response(
            200,
            json={"links": [LINK_BODY], "next_cursor": None},
        )
    )
    links, cursor = await hy.identity_links_for_entity("ide_dbt_model")
    assert len(links) == 1
    assert cursor is None
    assert "X-Hydra-Tenant" in route.calls.last.request.headers


@pytest.mark.asyncio
async def test_identity_links_for_entity_unknown_entity_raises_not_found(
    hy: Hydra, respx_mock: respx.MockRouter
) -> None:
    """Server probes entity ownership first; missing → 404 →
    `HydraNotFoundError`. Pins the existence-enumeration block."""
    respx_mock.get(
        "https://hydra.test/identity/entities/ide_ghost/links"
    ).mock(
        return_value=httpx.Response(
            404,
            json={"error": "identity entity not found: ide_ghost"},
        )
    )
    with pytest.raises(HydraNotFoundError):
        await hy.identity_links_for_entity("ide_ghost")


# === Sync mirror smoke ===


def test_create_identity_link_sync_mirror(
    hy_sync: HydraSync, respx_mock: respx.MockRouter
) -> None:
    """Sync parity — `HydraSync.create_identity_link` returns the
    same typed envelope. One sync test pins overall mirror
    behavior (other 3 sync methods follow the same pattern)."""
    respx_mock.post(
        "https://hydra.test/identity/links"
    ).mock(return_value=httpx.Response(200, json={"link": LINK_BODY}))

    link = IdentityLink.model_validate(LINK_BODY)
    stored = hy_sync.create_identity_link(link)
    assert isinstance(stored, IdentityLink)
    assert stored.kind == "DependsOn"
