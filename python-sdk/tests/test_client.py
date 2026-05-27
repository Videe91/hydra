"""Tests for the public `Hydra` client — construction, context
manager, tenant flow, token redaction.

Tests for the individual ingest / query methods live in
test_ingest.py and test_query.py.
"""

from __future__ import annotations

import httpx
import pytest
import respx

from hydra import Hydra


def test_construct_with_minimal_args() -> None:
    hy = Hydra("http://localhost:8080")
    assert hy.base_url == "http://localhost:8080"
    assert hy.tenant is None


def test_construct_with_all_args() -> None:
    hy = Hydra(
        "http://localhost:8080/",  # trailing slash stripped
        token="secret",
        tenant="tenant_x",
        verify=True,
        timeout=5.0,
    )
    assert hy.base_url == "http://localhost:8080"
    assert hy.tenant == "tenant_x"


def test_repr_redacts_bearer_token() -> None:
    """Critical security property — bearer tokens MUST NOT leak via
    `repr(hy)`, `str(hy)`, or `print(hy)`. Catches the case where a
    traceback containing locals would otherwise expose the auth
    secret in logs."""
    hy = Hydra(
        "http://localhost:8080",
        token="super-secret-bearer-do-not-leak",
        tenant="tenant_x",
    )
    rendered = repr(hy)
    assert "super-secret" not in rendered
    assert "<set>" in rendered  # the redacted marker
    # `str(hy)` defaults to `repr(hy)` — both must be safe.
    assert "super-secret" not in str(hy)


def test_repr_shows_token_unset_when_absent() -> None:
    hy = Hydra("http://localhost:8080")
    assert "<unset>" in repr(hy)


@pytest.mark.asyncio
async def test_async_context_manager_closes() -> None:
    """Verifies `async with Hydra(...) as hy:` closes the underlying
    httpx client on exit. We can't observe the close directly without
    instrumenting httpx; this test just runs through the protocol
    and ensures no exception."""
    async with Hydra("http://localhost:8080") as hy:
        assert hy.base_url == "http://localhost:8080"
    # No assertion needed — if aclose() raised, the test would fail.


@pytest.mark.asyncio
async def test_aclose_can_be_called_directly() -> None:
    hy = Hydra("http://localhost:8080")
    await hy.aclose()


@pytest.mark.asyncio
async def test_tenant_default_propagates_to_get(
    hy: Hydra, respx_mock: respx.MockRouter
) -> None:
    """The client's configured `tenant` lands as the `X-Hydra-Tenant`
    header on every request that doesn't override it."""
    route = respx_mock.get("https://hydra.test/query/nodes/node_x").mock(
        return_value=httpx.Response(
            200,
            json={
                "node": {
                    "meta": {
                        "id": "node_x",
                        "type_id": "test",
                        "created_at": "2026-01-01T00:00:00Z",
                        "updated_at": "2026-01-01T00:00:00Z",
                        "version": 1,
                        "alive": True,
                        "tenant_id": "tenant_test",
                    },
                    "properties": {},
                }
            },
        )
    )
    await hy.get_node("node_x")
    request = route.calls.last.request
    assert request.headers["X-Hydra-Tenant"] == "tenant_test"


@pytest.mark.asyncio
async def test_tenant_per_call_override_wins(
    hy: Hydra, respx_mock: respx.MockRouter
) -> None:
    """Rule #7: tenant override always available on every endpoint.
    Per-call `tenant=` MUST beat the client default."""
    route = respx_mock.get("https://hydra.test/query/nodes/node_x").mock(
        return_value=httpx.Response(
            200,
            json={
                "node": {
                    "meta": {
                        "id": "node_x",
                        "type_id": "test",
                        "created_at": "2026-01-01T00:00:00Z",
                        "updated_at": "2026-01-01T00:00:00Z",
                        "version": 1,
                        "alive": True,
                    },
                    "properties": {},
                }
            },
        )
    )
    await hy.get_node("node_x", tenant="tenant_override")
    request = route.calls.last.request
    assert request.headers["X-Hydra-Tenant"] == "tenant_override"
