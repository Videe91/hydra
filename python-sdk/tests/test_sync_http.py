"""Tests for `HydraHttpClientSync` — auth, tenant, error mapping.

Mirrors `test_http.py` but uses `httpx.Client` instead of
`httpx.AsyncClient`. Both clients route through the same shared
`_raise_for_error` / `_parse_success` helpers, so this file is the
proof that the sync side of the shared logic stays wired correctly.
"""

from __future__ import annotations

import httpx
import pytest
import respx

from hydra._http import HydraHttpClientSync
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


def test_sync_get_returns_parsed_json_on_200(
    http_client_sync: HydraHttpClientSync, respx_mock: respx.MockRouter
) -> None:
    respx_mock.get("https://hydra.test/events/evt_x").mock(
        return_value=httpx.Response(200, json={"id": "evt_x", "kind": "signal"})
    )
    result = http_client_sync.get("/events/evt_x")
    assert result == {"id": "evt_x", "kind": "signal"}


def test_sync_authorization_bearer_header_is_sent(
    http_client_sync: HydraHttpClientSync, respx_mock: respx.MockRouter
) -> None:
    route = respx_mock.get("https://hydra.test/events/evt_x").mock(
        return_value=httpx.Response(200, json={})
    )
    http_client_sync.get("/events/evt_x")
    assert route.calls.last.request.headers["Authorization"] == "Bearer test-token"


def test_sync_tenant_header_default_then_override(
    http_client_sync: HydraHttpClientSync, respx_mock: respx.MockRouter
) -> None:
    route = respx_mock.get("https://hydra.test/events/evt_x").mock(
        return_value=httpx.Response(200, json={})
    )
    http_client_sync.get("/events/evt_x")
    assert route.calls.last.request.headers["X-Hydra-Tenant"] == "tenant_test"

    http_client_sync.get("/events/evt_x", tenant="tenant_other")
    assert route.calls.last.request.headers["X-Hydra-Tenant"] == "tenant_other"


def test_sync_400_raises_validation_error(
    http_client_sync: HydraHttpClientSync, respx_mock: respx.MockRouter
) -> None:
    respx_mock.get("https://hydra.test/events/evt_x").mock(
        return_value=httpx.Response(400, json={"error": "bad request"})
    )
    with pytest.raises(HydraValidationError) as exc_info:
        http_client_sync.get("/events/evt_x")
    assert exc_info.value.status_code == 400
    assert exc_info.value.body == {"error": "bad request"}


@pytest.mark.parametrize("status", [401, 403])
def test_sync_401_403_raise_auth_error(
    http_client_sync: HydraHttpClientSync,
    respx_mock: respx.MockRouter,
    status: int,
) -> None:
    respx_mock.get("https://hydra.test/events/evt_x").mock(
        return_value=httpx.Response(status, json={"error": "no"})
    )
    with pytest.raises(HydraAuthError):
        http_client_sync.get("/events/evt_x")


def test_sync_404_raises_not_found_error(
    http_client_sync: HydraHttpClientSync, respx_mock: respx.MockRouter
) -> None:
    respx_mock.get("https://hydra.test/events/evt_x").mock(
        return_value=httpx.Response(404, json={"error": "not found"})
    )
    with pytest.raises(HydraNotFoundError):
        http_client_sync.get("/events/evt_x")


def test_sync_409_raises_readonly_follower_error(
    http_client_sync: HydraHttpClientSync, respx_mock: respx.MockRouter
) -> None:
    respx_mock.post("https://hydra.test/ingest").mock(
        return_value=httpx.Response(409, json={"error": "follower is read-only"})
    )
    with pytest.raises(HydraReadOnlyFollowerError):
        http_client_sync.post("/ingest", json={})


def test_sync_429_raises_rate_limited_error(
    http_client_sync: HydraHttpClientSync, respx_mock: respx.MockRouter
) -> None:
    respx_mock.get("https://hydra.test/events/evt_x").mock(
        return_value=httpx.Response(429)
    )
    with pytest.raises(HydraRateLimitedError):
        http_client_sync.get("/events/evt_x")


@pytest.mark.parametrize("status", [500, 502, 503])
def test_sync_5xx_raises_server_error(
    http_client_sync: HydraHttpClientSync,
    respx_mock: respx.MockRouter,
    status: int,
) -> None:
    respx_mock.get("https://hydra.test/events/evt_x").mock(
        return_value=httpx.Response(status, json={"error": "boom"})
    )
    with pytest.raises(HydraServerError):
        http_client_sync.get("/events/evt_x")


def test_sync_unmapped_status_falls_back_to_base_class(
    http_client_sync: HydraHttpClientSync, respx_mock: respx.MockRouter
) -> None:
    """418 is unmapped — should raise the base `HydraError` rather than
    silently passing through."""
    respx_mock.get("https://hydra.test/events/evt_x").mock(
        return_value=httpx.Response(418, json={"error": "tea"})
    )
    with pytest.raises(HydraError):
        http_client_sync.get("/events/evt_x")


def test_sync_transport_error_raises_hydra_connection_error() -> None:
    """Build a sync client over a MockTransport that always raises
    ConnectError, and verify the SDK wraps it in HydraConnectionError
    with the underlying exception attached via `__cause__`."""

    def raises(request: httpx.Request) -> httpx.Response:
        raise httpx.ConnectError("simulated down", request=request)

    transport = httpx.MockTransport(raises)
    client = httpx.Client(base_url="https://hydra.test", transport=transport)
    http_client = HydraHttpClientSync(
        base_url="https://hydra.test",
        token="t",
        tenant="tnt",
        client=client,
    )
    with pytest.raises(HydraConnectionError) as exc_info:
        http_client.get("/events/evt_x")
    assert isinstance(exc_info.value.__cause__, httpx.ConnectError)


def test_sync_text_content_type_returns_string(
    http_client_sync: HydraHttpClientSync, respx_mock: respx.MockRouter
) -> None:
    """Prometheus-style text responses come back as a str, not JSON."""
    respx_mock.get("https://hydra.test/metrics").mock(
        return_value=httpx.Response(
            200,
            text="# HELP hydra_up 1\nhydra_up 1\n",
            headers={"content-type": "text/plain"},
        )
    )
    result = http_client_sync.get("/metrics")
    assert isinstance(result, str)
    assert "hydra_up" in result


def test_sync_empty_body_returns_none(
    http_client_sync: HydraHttpClientSync, respx_mock: respx.MockRouter
) -> None:
    """Lifecycle routes (`/schemas/:id/disable`) return 204 with empty
    body. The SDK should not try to parse `b""` as JSON."""
    respx_mock.post("https://hydra.test/schemas/sch_x/disable").mock(
        return_value=httpx.Response(204)
    )
    result = http_client_sync.post(
        "/schemas/sch_x/disable", json={"reason": "rotated"}
    )
    assert result is None


def test_sync_post_sends_idempotency_extra_header(
    http_client_sync: HydraHttpClientSync, respx_mock: respx.MockRouter
) -> None:
    """`extra_headers=` adds per-call headers (used for
    `Idempotency-Key`)."""
    route = respx_mock.post("https://hydra.test/ingest").mock(
        return_value=httpx.Response(
            200,
            json={
                "event_ids": [],
                "event_count": 0,
                "idempotent_hit": True,
            },
        )
    )
    http_client_sync.post(
        "/ingest",
        json={},
        extra_headers={"Idempotency-Key": "key_001"},
    )
    assert route.calls.last.request.headers["Idempotency-Key"] == "key_001"
