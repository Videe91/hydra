"""Tests for HydraHttpClient — auth, tenant, error mapping.

Uses respx to mock httpx without a running Hydra server.

Coverage:
  - 200 success returns parsed JSON
  - Authorization Bearer header is sent
  - X-Hydra-Tenant header is sent (client default + per-call override)
  - 400 → HydraValidationError with body preserved
  - 401, 403 → HydraAuthError
  - 404 → HydraNotFoundError
  - 409 → HydraReadOnlyFollowerError
  - 429 → HydraRateLimitedError
  - 500, 503 → HydraServerError
  - Connection failure → HydraConnectionError
  - Plain-text body (Prometheus metrics endpoint) → returns str
  - Empty response body → returns None
"""

from __future__ import annotations

import httpx
import pytest
import respx

from hydra._http import HydraHttpClient
from hydra.errors import (
    HydraAuthError,
    HydraConnectionError,
    HydraError,
    HydraNotFoundError,
    HydraRateLimitedError,
    HydraReadOnlyFollowerError,
    HydraServerError,
    HydraValidationError,
)


@pytest.mark.asyncio
async def test_get_returns_parsed_json_on_200(
    http_client: HydraHttpClient, respx_mock: respx.MockRouter
) -> None:
    respx_mock.get("https://hydra.test/events/evt_x").mock(
        return_value=httpx.Response(200, json={"id": "evt_x", "kind": "signal"})
    )
    result = await http_client.get("/events/evt_x")
    assert result == {"id": "evt_x", "kind": "signal"}


@pytest.mark.asyncio
async def test_authorization_bearer_header_is_sent(
    http_client: HydraHttpClient, respx_mock: respx.MockRouter
) -> None:
    route = respx_mock.get("https://hydra.test/events/evt_x").mock(
        return_value=httpx.Response(200, json={})
    )
    await http_client.get("/events/evt_x")
    request = route.calls.last.request
    assert request.headers["Authorization"] == "Bearer test-token"


@pytest.mark.asyncio
async def test_tenant_header_uses_client_default(
    http_client: HydraHttpClient, respx_mock: respx.MockRouter
) -> None:
    route = respx_mock.get("https://hydra.test/events/evt_x").mock(
        return_value=httpx.Response(200, json={})
    )
    await http_client.get("/events/evt_x")
    request = route.calls.last.request
    assert request.headers["X-Hydra-Tenant"] == "tenant_test"


@pytest.mark.asyncio
async def test_tenant_header_per_call_override(
    http_client: HydraHttpClient, respx_mock: respx.MockRouter
) -> None:
    """Design rule #7: tenant override always available on every endpoint."""
    route = respx_mock.get("https://hydra.test/events/evt_x").mock(
        return_value=httpx.Response(200, json={})
    )
    await http_client.get("/events/evt_x", tenant="tenant_other")
    request = route.calls.last.request
    assert request.headers["X-Hydra-Tenant"] == "tenant_other"


@pytest.mark.asyncio
async def test_no_tenant_header_when_unset() -> None:
    """When no tenant default and no per-call override, the header is absent."""
    respx_router = respx.MockRouter(assert_all_called=False)
    transport = httpx.MockTransport(handler=respx_router.handler)
    async_client = httpx.AsyncClient(base_url="https://hydra.test", transport=transport)
    client = HydraHttpClient(
        base_url="https://hydra.test",
        token="t",
        tenant=None,
        client=async_client,
    )
    route = respx_router.get("https://hydra.test/x").mock(
        return_value=httpx.Response(200, json={})
    )
    await client.get("/x")
    request = route.calls.last.request
    assert "X-Hydra-Tenant" not in request.headers


@pytest.mark.asyncio
async def test_400_raises_validation_error_with_body_preserved(
    http_client: HydraHttpClient, respx_mock: respx.MockRouter
) -> None:
    body = {"error": "missing required field 'kind'"}
    respx_mock.post("https://hydra.test/ingest").mock(
        return_value=httpx.Response(400, json=body)
    )
    with pytest.raises(HydraValidationError) as exc_info:
        await http_client.post("/ingest", json={"bogus": True})
    err = exc_info.value
    assert err.status_code == 400
    assert err.body == body
    assert err.url == "https://hydra.test/ingest"


@pytest.mark.asyncio
async def test_401_raises_auth_error(
    http_client: HydraHttpClient, respx_mock: respx.MockRouter
) -> None:
    respx_mock.get("https://hydra.test/events").mock(
        return_value=httpx.Response(401, json={"error": "unauthorized"})
    )
    with pytest.raises(HydraAuthError) as exc_info:
        await http_client.get("/events")
    assert exc_info.value.status_code == 401


@pytest.mark.asyncio
async def test_403_raises_auth_error(
    http_client: HydraHttpClient, respx_mock: respx.MockRouter
) -> None:
    respx_mock.get("https://hydra.test/events").mock(
        return_value=httpx.Response(403, json={"error": "insufficient scope"})
    )
    with pytest.raises(HydraAuthError) as exc_info:
        await http_client.get("/events")
    assert exc_info.value.status_code == 403


@pytest.mark.asyncio
async def test_404_raises_not_found(
    http_client: HydraHttpClient, respx_mock: respx.MockRouter
) -> None:
    respx_mock.get("https://hydra.test/events/missing").mock(
        return_value=httpx.Response(404, json={"error": "event not found: missing"})
    )
    with pytest.raises(HydraNotFoundError) as exc_info:
        await http_client.get("/events/missing")
    assert exc_info.value.status_code == 404
    assert "event not found" in str(exc_info.value)


@pytest.mark.asyncio
async def test_409_raises_read_only_follower(
    http_client: HydraHttpClient, respx_mock: respx.MockRouter
) -> None:
    """V2 P4H semantics — follower returns 409 with the standard
    `{"error": "follower is read-only"}` body. Agents catching
    this know to retry against the leader."""
    respx_mock.post("https://hydra.test/ingest").mock(
        return_value=httpx.Response(409, json={"error": "follower is read-only"})
    )
    with pytest.raises(HydraReadOnlyFollowerError) as exc_info:
        await http_client.post("/ingest", json={})
    assert exc_info.value.status_code == 409
    assert exc_info.value.body == {"error": "follower is read-only"}


@pytest.mark.asyncio
async def test_429_raises_rate_limited(
    http_client: HydraHttpClient, respx_mock: respx.MockRouter
) -> None:
    respx_mock.get("https://hydra.test/events").mock(
        return_value=httpx.Response(429, headers={"Retry-After": "5"}, json={"error": "slow down"})
    )
    with pytest.raises(HydraRateLimitedError) as exc_info:
        await http_client.get("/events")
    assert exc_info.value.status_code == 429


@pytest.mark.asyncio
async def test_500_raises_server_error(
    http_client: HydraHttpClient, respx_mock: respx.MockRouter
) -> None:
    respx_mock.get("https://hydra.test/events").mock(
        return_value=httpx.Response(500, text="internal error")
    )
    with pytest.raises(HydraServerError) as exc_info:
        await http_client.get("/events")
    assert exc_info.value.status_code == 500
    assert exc_info.value.body == "internal error"  # non-JSON body preserved as text


@pytest.mark.asyncio
async def test_503_raises_server_error(
    http_client: HydraHttpClient, respx_mock: respx.MockRouter
) -> None:
    respx_mock.get("https://hydra.test/events").mock(
        return_value=httpx.Response(503, json={"error": "shutting down"})
    )
    with pytest.raises(HydraServerError) as exc_info:
        await http_client.get("/events")
    assert exc_info.value.status_code == 503


@pytest.mark.asyncio
async def test_connection_failure_raises_connection_error() -> None:
    """Transport-level failures (DNS, TLS, connect refused, timeout)
    surface as HydraConnectionError. status_code is None."""

    def handler(request: httpx.Request) -> httpx.Response:
        raise httpx.ConnectError("connection refused", request=request)

    transport = httpx.MockTransport(handler)
    async_client = httpx.AsyncClient(base_url="https://hydra.test", transport=transport)
    client = HydraHttpClient(
        base_url="https://hydra.test",
        token="t",
        client=async_client,
    )
    with pytest.raises(HydraConnectionError) as exc_info:
        await client.get("/events")
    assert exc_info.value.status_code is None
    # Original httpx exception preserved as __cause__.
    assert isinstance(exc_info.value.__cause__, httpx.ConnectError)


@pytest.mark.asyncio
async def test_plain_text_body_returned_as_string(
    http_client: HydraHttpClient, respx_mock: respx.MockRouter
) -> None:
    """The /metrics endpoint returns Prometheus text — the client
    must hand it back as a str without trying to JSON-parse it."""
    respx_mock.get("https://hydra.test/metrics").mock(
        return_value=httpx.Response(
            200,
            text="# TYPE hydra_replication_lag_commits gauge\nhydra_replication_lag_commits 3\n",
            headers={"content-type": "text/plain; version=0.0.4"},
        )
    )
    result = await http_client.get("/metrics")
    assert isinstance(result, str)
    assert "hydra_replication_lag_commits" in result


@pytest.mark.asyncio
async def test_empty_response_body_returns_none(
    http_client: HydraHttpClient, respx_mock: respx.MockRouter
) -> None:
    respx_mock.post("https://hydra.test/internal/empty").mock(
        return_value=httpx.Response(200, content=b"")
    )
    result = await http_client.post("/internal/empty", json={})
    assert result is None


@pytest.mark.asyncio
async def test_base_hydra_error_catchable_for_all_errors(
    http_client: HydraHttpClient, respx_mock: respx.MockRouter
) -> None:
    """Sanity: any typed error can be caught via the base class."""
    respx_mock.get("https://hydra.test/x").mock(return_value=httpx.Response(409, json={}))
    with pytest.raises(HydraError):
        await http_client.get("/x")
