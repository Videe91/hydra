"""Test fixtures.

Uses respx (HTTP mocking for httpx) so tests don't need a running
Hydra server. Integration tests against a live engine are deferred
to a later patch.
"""

from __future__ import annotations

import httpx
import pytest
import respx

from hydra import Hydra
from hydra._http import HydraHttpClient


@pytest.fixture
def respx_mock() -> respx.MockRouter:
    """Per-test respx mock. `assert_all_called=False` so individual
    tests don't have to register every route they happen to hit."""
    with respx.mock(assert_all_called=False) as router:
        yield router


@pytest.fixture
def http_client(respx_mock: respx.MockRouter) -> HydraHttpClient:
    """Internal HTTP client wired through respx. Used by Patch 1
    `_http.py` tests."""
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
def hy(respx_mock: respx.MockRouter) -> Hydra:
    """Public Hydra client wired through respx. The main fixture for
    Patch 2 client / ingest / query tests."""
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
