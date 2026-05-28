"""Tests for the public `HydraSync` client — construction, context
manager, tenant flow, token redaction.

Sync counterpart of `test_client.py`. Sync-specific tests
(`with hy:` instead of `async with`, `close()` vs `aclose()`) live
here. Per-method behavior is covered in `test_sync_methods.py`.
"""

from __future__ import annotations

import httpx
import respx

from hydra import HydraSync


def test_sync_construct_with_minimal_args() -> None:
    hy = HydraSync("http://localhost:8080")
    assert hy.base_url == "http://localhost:8080"
    assert hy.tenant is None


def test_sync_construct_strips_trailing_slash() -> None:
    hy = HydraSync(
        "http://localhost:8080/",
        token="secret",
        tenant="tenant_x",
        verify=True,
        timeout=5.0,
    )
    assert hy.base_url == "http://localhost:8080"
    assert hy.tenant == "tenant_x"


def test_sync_repr_redacts_bearer_token() -> None:
    """The same security property as `Hydra.__repr__` — bearer tokens
    MUST NOT leak via `repr(hy)`, `str(hy)`, or `print(hy)`."""
    hy = HydraSync(
        "http://localhost:8080",
        token="super-secret-bearer-do-not-leak",
        tenant="tenant_x",
    )
    rendered = repr(hy)
    assert "super-secret" not in rendered
    assert "<set>" in rendered
    assert "HydraSync" in rendered  # the class name should show
    assert "super-secret" not in str(hy)


def test_sync_repr_shows_token_unset_when_absent() -> None:
    hy = HydraSync("http://localhost:8080")
    assert "<unset>" in repr(hy)


def test_sync_context_manager_closes() -> None:
    """`with HydraSync(...) as hy:` exits cleanly, calling close()."""
    with HydraSync("http://localhost:8080") as hy:
        assert hy.base_url == "http://localhost:8080"
    # If close() raised, this test would fail.


def test_sync_close_can_be_called_directly() -> None:
    hy = HydraSync("http://localhost:8080")
    hy.close()


def test_sync_namespaces_are_single_instance() -> None:
    """Each namespace instance is captured once at __init__ time; the
    same object is returned on every attribute access."""
    hy = HydraSync("http://localhost:8080")
    assert hy.diagnostics is hy.diagnostics
    assert hy.schemas is hy.schemas
    assert hy.replication is hy.replication


def test_sync_tenant_default_propagates_to_get(
    hy_sync: HydraSync, respx_mock: respx.MockRouter
) -> None:
    """Client `tenant` lands as `X-Hydra-Tenant` on every request that
    doesn't override it (Rule #7 — sync side)."""
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
    hy_sync.get_node("node_x")
    assert route.calls.last.request.headers["X-Hydra-Tenant"] == "tenant_test"


def test_sync_tenant_per_call_override_wins(
    hy_sync: HydraSync, respx_mock: respx.MockRouter
) -> None:
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
    hy_sync.get_node("node_x", tenant="tenant_override")
    assert route.calls.last.request.headers["X-Hydra-Tenant"] == "tenant_override"


def test_sync_hydra_async_and_sync_can_coexist() -> None:
    """Both clients pointed at the same engine should not interfere —
    they hold independent httpx clients and namespace instances."""
    from hydra import Hydra

    async_hy = Hydra("http://localhost:8080", tenant="t")
    sync_hy = HydraSync("http://localhost:8080", tenant="t")
    assert async_hy.base_url == sync_hy.base_url
    # Different namespace classes (async _Schemas vs sync _SchemasSync)
    # even though they ride on the same shared schemas.py file.
    assert type(async_hy.schemas).__name__ == "_Schemas"
    assert type(sync_hy.schemas).__name__ == "_SchemasSync"
