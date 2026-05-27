"""Tests for the exception hierarchy.

Verifies the design contract:
  - All exceptions inherit from HydraError so callers can catch the base.
  - status_code, body, url are preserved verbatim.
  - Each typed exception is distinguishable.
"""

from __future__ import annotations

import pytest

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


def test_all_exceptions_inherit_from_hydra_error() -> None:
    """Design rule #12: callers catch typed exceptions; HydraError is
    the base for the catch-all path."""
    for cls in (
        HydraConnectionError,
        HydraAuthError,
        HydraValidationError,
        HydraNotFoundError,
        HydraReadOnlyFollowerError,
        HydraRateLimitedError,
        HydraServerError,
    ):
        assert issubclass(cls, HydraError), f"{cls.__name__} must inherit HydraError"


def test_status_code_body_url_preserved() -> None:
    """Design rule #8: server errors preserved verbatim."""
    body = {"error": "follower is read-only"}
    err = HydraReadOnlyFollowerError(
        "POST /ingest -> 409: follower is read-only",
        status_code=409,
        body=body,
        url="https://hydra.test/ingest",
    )
    assert err.status_code == 409
    assert err.body == body
    assert err.url == "https://hydra.test/ingest"
    # The base Exception message is preserved.
    assert "follower is read-only" in str(err)


def test_connection_error_has_no_status_code() -> None:
    """Transport-level failures: status_code is None because Hydra
    never returned anything."""
    err = HydraConnectionError("connection refused", url="https://hydra.test/ingest")
    assert err.status_code is None
    assert err.body is None
    assert err.url == "https://hydra.test/ingest"


def test_repr_includes_status_and_url() -> None:
    err = HydraNotFoundError(
        "GET /events/evt_x -> 404",
        status_code=404,
        body={"error": "event not found"},
        url="https://hydra.test/events/evt_x",
    )
    rendered = repr(err)
    assert "HydraNotFoundError" in rendered
    assert "404" in rendered
    assert "https://hydra.test/events/evt_x" in rendered


def test_each_typed_error_is_distinguishable() -> None:
    """Callers can write `except HydraReadOnlyFollowerError:` and
    have it fire on exactly that case — not on HydraAuthError, etc."""
    err = HydraReadOnlyFollowerError("test", status_code=409)
    with pytest.raises(HydraReadOnlyFollowerError):
        raise err
    # And it's still a HydraError for catch-all paths.
    with pytest.raises(HydraError):
        raise err
    # But NOT a HydraAuthError.
    assert not isinstance(err, HydraAuthError)
    assert not isinstance(err, HydraNotFoundError)
