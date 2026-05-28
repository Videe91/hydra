"""Test fixtures.

Uses respx (HTTP mocking for httpx) so tests don't need a running
Hydra server. Integration tests against a live engine are deferred
to a later patch.

Both async (`Hydra` / `HydraHttpClient`) and sync (`HydraSync` /
`HydraHttpClientSync`) variants are exposed as fixtures so Patch 5
sync tests can share the same respx mock as their async counterparts.
"""

from __future__ import annotations

import httpx
import pytest
import respx

from hydra import Hydra, HydraSync
from hydra._http import HydraHttpClient, HydraHttpClientSync


@pytest.fixture
def respx_mock() -> respx.MockRouter:
    """Per-test respx mock. `assert_all_called=False` so individual
    tests don't have to register every route they happen to hit."""
    with respx.mock(assert_all_called=False) as router:
        yield router


@pytest.fixture
def http_client(respx_mock: respx.MockRouter) -> HydraHttpClient:
    """Internal async HTTP client wired through respx."""
    transport = httpx.MockTransport(handler=respx_mock.handler)
    async_client = httpx.AsyncClient(
        base_url="https://hydra.test",
        transport=transport,
    )
    return HydraHttpClient(
        base_url="https://hydra.test",
        token="test-token",
        tenant="tenant_test",
        client=async_client,
    )


@pytest.fixture
def http_client_sync(respx_mock: respx.MockRouter) -> HydraHttpClientSync:
    """Internal sync HTTP client wired through respx. Patch 5."""
    transport = httpx.MockTransport(handler=respx_mock.handler)
    sync_client = httpx.Client(
        base_url="https://hydra.test",
        transport=transport,
    )
    return HydraHttpClientSync(
        base_url="https://hydra.test",
        token="test-token",
        tenant="tenant_test",
        client=sync_client,
    )


@pytest.fixture
def hy(respx_mock: respx.MockRouter) -> Hydra:
    """Public async Hydra client wired through respx."""
    transport = httpx.MockTransport(handler=respx_mock.handler)
    async_client = httpx.AsyncClient(
        base_url="https://hydra.test",
        transport=transport,
    )
    return Hydra(
        base_url="https://hydra.test",
        token="test-token",
        tenant="tenant_test",
        client=async_client,
    )


@pytest.fixture
def hy_sync(respx_mock: respx.MockRouter) -> HydraSync:
    """Public sync HydraSync client wired through respx. Patch 5."""
    transport = httpx.MockTransport(handler=respx_mock.handler)
    sync_client = httpx.Client(
        base_url="https://hydra.test",
        transport=transport,
    )
    return HydraSync(
        base_url="https://hydra.test",
        token="test-token",
        tenant="tenant_test",
        client=sync_client,
    )
