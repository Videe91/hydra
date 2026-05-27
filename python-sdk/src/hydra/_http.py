"""Internal HTTP client wrapper.

NOT part of the public API. Design rule #9: no raw HTTP escape hatch.
This module is consumed by the (future) public `Hydra` class and by
internal helpers; it does not appear in `hydra.__init__` exports.

Responsibilities:
  - Wrap httpx.AsyncClient with Hydra-specific defaults (auth header,
    tenant header, base URL, timeout).
  - Map HTTP status codes to the typed exception hierarchy (design
    rule #12).
  - Preserve the raw response body verbatim on errors (design rule
    #8) — `HydraError.body` carries Hydra's JSON or the raw bytes
    if non-JSON.

NOT in scope here:
  - Retries (design rule #5: no hidden retries in v0).
  - Caching (design rule #6: no local caching).
  - Method-specific helpers (those live in the public method
    modules — ingest.py, query.py, etc.).
"""

from __future__ import annotations

from typing import Any

import httpx

from .errors import (
    HydraAuthError,
    HydraConnectionError,
    HydraError,
    HydraNotFoundError,
    HydraRateLimitedError,
    HydraReadOnlyFollowerError,
    HydraServerError,
    HydraValidationError,
)


DEFAULT_TIMEOUT_SECONDS = 10.0
TENANT_HEADER = "X-Hydra-Tenant"


class HydraHttpClient:
    """Async HTTP client wrapper. Internal."""

    def __init__(
        self,
        base_url: str,
        *,
        token: str | None = None,
        tenant: str | None = None,
        verify: bool = True,
        timeout: float = DEFAULT_TIMEOUT_SECONDS,
        client: httpx.AsyncClient | None = None,
    ) -> None:
        self.base_url = base_url.rstrip("/")
        self._token = token
        self._default_tenant = tenant
        # Allow a caller-supplied client (tests use respx-instrumented
        # clients; advanced users may want custom transport).
        self._client = client or httpx.AsyncClient(
            base_url=self.base_url,
            verify=verify,
            timeout=timeout,
        )
        self._owns_client = client is None

    async def aclose(self) -> None:
        if self._owns_client:
            await self._client.aclose()

    def _headers(self, tenant: str | None) -> dict[str, str]:
        headers: dict[str, str] = {}
        if self._token:
            headers["Authorization"] = f"Bearer {self._token}"
        # Tenant resolution: per-call override > client default > absent.
        # Design rule #7: tenant override always available on every endpoint.
        effective_tenant = tenant if tenant is not None else self._default_tenant
        if effective_tenant is not None:
            headers[TENANT_HEADER] = effective_tenant
        return headers

    async def get(
        self,
        path: str,
        *,
        params: dict[str, Any] | None = None,
        tenant: str | None = None,
    ) -> Any:
        return await self._request("GET", path, params=params, tenant=tenant)

    async def post(
        self,
        path: str,
        *,
        json: Any | None = None,
        params: dict[str, Any] | None = None,
        tenant: str | None = None,
        extra_headers: dict[str, str] | None = None,
    ) -> Any:
        return await self._request(
            "POST",
            path,
            params=params,
            tenant=tenant,
            json=json,
            extra_headers=extra_headers,
        )

    async def _request(
        self,
        method: str,
        path: str,
        *,
        params: dict[str, Any] | None = None,
        tenant: str | None = None,
        json: Any | None = None,
        extra_headers: dict[str, str] | None = None,
    ) -> Any:
        headers = self._headers(tenant)
        if extra_headers:
            headers.update(extra_headers)

        url = path if path.startswith("http") else path
        try:
            response = await self._client.request(
                method,
                url,
                params=params,
                json=json,
                headers=headers,
            )
        except httpx.TransportError as exc:
            # Network / TLS / DNS / timeout — Hydra never returned anything.
            raise HydraConnectionError(
                f"{method} {self.base_url}{path}: {exc}",
                url=f"{self.base_url}{path}",
            ) from exc

        if response.is_success:
            # 2xx — parse JSON if present; some endpoints return text
            # (Prometheus metrics). The public method layer decides
            # what to do with each body; here we just return the raw
            # parsed value or text.
            if not response.content:
                return None
            content_type = response.headers.get("content-type", "")
            if "application/json" in content_type:
                return response.json()
            return response.text

        # Error path — map status to the typed exception hierarchy.
        # Preserve the body verbatim (design rule #8).
        body: Any | None
        try:
            body = response.json()
        except (ValueError, httpx.DecodingError):
            body = response.text or None

        status = response.status_code
        message = _format_message(method, response.url, status, body)
        full_url = str(response.url)

        if status == 400:
            raise HydraValidationError(message, status_code=status, body=body, url=full_url)
        if status in (401, 403):
            raise HydraAuthError(message, status_code=status, body=body, url=full_url)
        if status == 404:
            raise HydraNotFoundError(message, status_code=status, body=body, url=full_url)
        if status == 409:
            raise HydraReadOnlyFollowerError(
                message, status_code=status, body=body, url=full_url
            )
        if status == 429:
            raise HydraRateLimitedError(message, status_code=status, body=body, url=full_url)
        if 500 <= status < 600:
            raise HydraServerError(message, status_code=status, body=body, url=full_url)

        # Anything else (e.g. 3xx that httpx didn't follow, unusual 4xx)
        # falls back to the base class. Unknown-but-mapped status codes
        # should land here so callers can still catch `HydraError`.
        raise HydraError(message, status_code=status, body=body, url=full_url)


def _format_message(method: str, url: httpx.URL, status: int, body: Any) -> str:
    """Compose a concise error string. The full body lives on the
    exception's `.body` attribute; this string is what users see when
    they str() the exception.
    """
    error_hint: str | None = None
    if isinstance(body, dict) and "error" in body:
        # Hydra's standard error shape: {"error": "..."}
        value = body["error"]
        if isinstance(value, str):
            error_hint = value
    if error_hint is not None:
        return f"{method} {url} -> {status}: {error_hint}"
    return f"{method} {url} -> {status}"
