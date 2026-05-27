"""Exception hierarchy for the Hydra SDK.

Design rule #8: server errors are preserved verbatim. Every exception
carries the raw HTTP status code, the response body (if JSON), and the
request URL. No re-wrapping, no message reformatting, no field
renaming.

Design rule #12: errors are typed, not stringly-typed. Callers write
`except HydraReadOnlyFollowerError:` and have it fire on exactly that
case. A new error category gets its own exception class.

The hierarchy maps to HTTP status codes:
  HydraError                       (base)
    HydraConnectionError           (network / TLS / DNS — no status)
    HydraAuthError                 (401, 403)
    HydraValidationError           (400)
    HydraNotFoundError             (404)
    HydraReadOnlyFollowerError     (409 from the role middleware)
    HydraRateLimitedError          (429)
    HydraServerError               (5xx)
"""

from __future__ import annotations

from typing import Any


class HydraError(Exception):
    """Base for every Hydra SDK error.

    `status_code` and `body` are None for transport-level failures
    (connection refused, DNS, TLS handshake) — anything that happens
    before Hydra returns a response. `url` is always populated when
    the SDK had a target to call.
    """

    def __init__(
        self,
        message: str,
        *,
        status_code: int | None = None,
        body: Any | None = None,
        url: str | None = None,
    ) -> None:
        super().__init__(message)
        self.status_code = status_code
        self.body = body
        self.url = url

    def __repr__(self) -> str:
        return (
            f"{type(self).__name__}("
            f"message={super().__str__()!r}, "
            f"status_code={self.status_code!r}, "
            f"url={self.url!r})"
        )


class HydraConnectionError(HydraError):
    """Transport-level failure — TCP / TLS / DNS / timeout.

    `status_code` is always None here: Hydra never returned anything.
    The underlying httpx exception is preserved as `__cause__`.
    """


class HydraAuthError(HydraError):
    """Authentication or authorization failed — HTTP 401 or 403.

    401 means the bearer token is missing or invalid. 403 means the
    token is valid but lacks the required scope for this route.
    """


class HydraValidationError(HydraError):
    """Server rejected the request body or query parameters — HTTP 400.

    The `body` field carries Hydra's error JSON, which typically has
    a `"error"` key with a human-readable message.
    """


class HydraNotFoundError(HydraError):
    """Resource not found — HTTP 404.

    Raised for unknown event_id on /lineage/, unknown peer_id on
    replication routes, etc.
    """


class HydraReadOnlyFollowerError(HydraError):
    """Hit a follower with a mutating request — HTTP 409.

    Per V2 P4H + polish #5/#6: a node in `RuntimeRole::Follower`
    rejects ingest, schema register, and other mutating routes with
    409 + `{"error": "follower is read-only"}`. Agents catching this
    know to retry against the current leader (look up via
    `/replication/role` or `/replication/status`).
    """


class HydraRateLimitedError(HydraError):
    """Rate limit hit — HTTP 429.

    Hydra's `RateLimitMode::PerIp` sends `Retry-After` headers; the
    raw response body is preserved in `body`.
    """


class HydraServerError(HydraError):
    """Hydra server-side error — HTTP 5xx.

    Includes panics, unhandled engine errors, etc. The body is
    preserved when JSON.
    """
