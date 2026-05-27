"""Test fixtures.

Patch 1 uses respx (HTTP mocking for httpx) so we don't need a
running Hydra server. Integration tests against a live engine are
deferred to a later patch.
"""

from __future__ import annotations

import httpx
import pytest
import respx

from hydra._http import HydraHttpClient


@pytest.fixture
def respx_mock() -> respx.MockRouter:
    """Per-test respx mock. Default `assert_all_called=False` so
    individual tests don't have to register every route they happen
    to hit indirectly."""
    with respx.mock(assert_all_called=False) as router:
        yield router


@pytest.fixture
def http_client(respx_mock: respx.MockRouter) -> HydraHttpClient:
    """Async client wired through respx. Base URL is consistent so
    tests can register routes against `https://hydra.test/...`.
    """
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
