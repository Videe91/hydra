"""Tests for `hy.replication.*` — read-only operator introspection.

Six methods (status / peers / peer / peer_lag / role / promotion_status).
The puller-internal routes (`/replication/commits`,
`/replication/snapshot/*`) are intentionally NOT exposed in the SDK
and have no corresponding methods to test.

Three semantic boundaries pinned here:
  - `peer` 404s on unknown id
  - `peer_lag` NEVER 404s — `lag: None` is the intentional "no data" state
  - `promotion_status.last_promotion: None` (never promoted) vs populated
"""

from __future__ import annotations

from typing import Any

import httpx
import pytest
import respx

from hydra import (
    Hydra,
    HydraNotFoundError,
    ReplicationLag,
    ReplicationPeer,
)


# === Fixtures ===

PEER_FIXTURE: dict[str, Any] = {
    "id": "replica_b",
    "tenant_id": None,
    "role": "Follower",
    "status": "Online",
    "endpoint": "https://b.hydra.test",
    "mode": "CommitLogStreaming",
    "last_offset": {
        "sequence": 42,
        "commit_id": "commit_xyz",
        "commit_hash": "hash_xyz",
    },
    "last_lag": {
        "leader_sequence": 50,
        "follower_sequence": 42,
        "lag_commits": 8,
        "observed_at": "2026-01-01T00:00:00Z",
    },
    "registered_by": "actor_admin",
    "registered_at": "2026-01-01T00:00:00Z",
    "updated_at": "2026-01-01T00:00:01Z",
    "metadata": {},
}


STATUS_FIXTURE: dict[str, Any] = {
    "role": "Leader",
    "head_sequence": 50,
    "head_commit_id": "commit_head",
    "peers": [PEER_FIXTURE],
}


# === status ===


@pytest.mark.asyncio
async def test_status_returns_typed_response(
    hy: Hydra, respx_mock: respx.MockRouter
) -> None:
    respx_mock.get("https://hydra.test/replication/status").mock(
        return_value=httpx.Response(200, json=STATUS_FIXTURE)
    )
    status = await hy.replication.status()
    assert status.role == "Leader"
    assert status.head_sequence == 50
    assert status.head_commit_id == "commit_head"
    assert len(status.peers) == 1
    assert status.peers[0].id == "replica_b"


@pytest.mark.asyncio
async def test_status_empty_cluster_round_trip(
    hy: Hydra, respx_mock: respx.MockRouter
) -> None:
    """Fresh leader: empty peers, head_sequence=0, head_commit_id null."""
    respx_mock.get("https://hydra.test/replication/status").mock(
        return_value=httpx.Response(
            200,
            json={
                "role": "Leader",
                "head_sequence": 0,
                "head_commit_id": None,
                "peers": [],
            },
        )
    )
    status = await hy.replication.status()
    assert status.head_commit_id is None
    assert status.peers == []


# === peers / peer ===


@pytest.mark.asyncio
async def test_peers_returns_list_of_typed_peers(
    hy: Hydra, respx_mock: respx.MockRouter
) -> None:
    respx_mock.get("https://hydra.test/replication/peers").mock(
        return_value=httpx.Response(200, json={"peers": [PEER_FIXTURE]})
    )
    peers = await hy.replication.peers()
    assert len(peers) == 1
    assert isinstance(peers[0], ReplicationPeer)
    assert peers[0].role == "Follower"
    assert peers[0].mode == "CommitLogStreaming"
    assert peers[0].last_offset is not None
    assert peers[0].last_offset.sequence == 42


@pytest.mark.asyncio
async def test_peer_single_lookup(
    hy: Hydra, respx_mock: respx.MockRouter
) -> None:
    respx_mock.get("https://hydra.test/replication/peers/replica_b").mock(
        return_value=httpx.Response(200, json={"peer": PEER_FIXTURE})
    )
    peer = await hy.replication.peer("replica_b")
    assert peer.id == "replica_b"
    assert peer.status == "Online"


@pytest.mark.asyncio
async def test_peer_404_raises_not_found(
    hy: Hydra, respx_mock: respx.MockRouter
) -> None:
    respx_mock.get("https://hydra.test/replication/peers/missing").mock(
        return_value=httpx.Response(404, json={"error": "peer not found"})
    )
    with pytest.raises(HydraNotFoundError):
        await hy.replication.peer("missing")


# === peer_lag — never 404s, null = no observation ===


@pytest.mark.asyncio
async def test_peer_lag_returns_typed_lag(
    hy: Hydra, respx_mock: respx.MockRouter
) -> None:
    respx_mock.get("https://hydra.test/replication/peers/replica_b/lag").mock(
        return_value=httpx.Response(
            200,
            json={
                "peer_id": "replica_b",
                "lag": {
                    "leader_sequence": 50,
                    "follower_sequence": 42,
                    "lag_commits": 8,
                    "observed_at": "2026-01-01T00:00:00Z",
                },
            },
        )
    )
    resp = await hy.replication.peer_lag("replica_b")
    assert resp.peer_id == "replica_b"
    assert isinstance(resp.lag, ReplicationLag)
    assert resp.lag.lag_commits == 8


@pytest.mark.asyncio
async def test_peer_lag_null_means_no_observation(
    hy: Hydra, respx_mock: respx.MockRouter
) -> None:
    """**Critical semantic** — unknown peer or no observation yet
    both surface as `lag: None`, NOT a 404. Operators polling this
    route get a stable 200 contract."""
    respx_mock.get("https://hydra.test/replication/peers/replica_unseen/lag").mock(
        return_value=httpx.Response(
            200, json={"peer_id": "replica_unseen", "lag": None}
        )
    )
    resp = await hy.replication.peer_lag("replica_unseen")
    assert resp.peer_id == "replica_unseen"
    assert resp.lag is None


# === role ===


@pytest.mark.asyncio
async def test_role_returns_lowercase_runtime_role(
    hy: Hydra, respx_mock: respx.MockRouter
) -> None:
    """`/replication/role` returns the lowercase RuntimeRole literal,
    distinct from the PascalCase ReplicationRole on peers."""
    respx_mock.get("https://hydra.test/replication/role").mock(
        return_value=httpx.Response(200, json={"role": "leader"})
    )
    role = await hy.replication.role()
    assert role == "leader"


@pytest.mark.asyncio
async def test_role_follower(
    hy: Hydra, respx_mock: respx.MockRouter
) -> None:
    respx_mock.get("https://hydra.test/replication/role").mock(
        return_value=httpx.Response(200, json={"role": "follower"})
    )
    role = await hy.replication.role()
    assert role == "follower"


# === promotion_status ===


@pytest.mark.asyncio
async def test_promotion_status_never_promoted_returns_none(
    hy: Hydra, respx_mock: respx.MockRouter
) -> None:
    """**Critical semantic** — `last_promotion: None` means this node
    has never been promoted. Distinct from a promoted-then-demoted
    node (which would have `last_promotion: {...}` AND
    `current_role: "follower"`)."""
    respx_mock.get("https://hydra.test/replication/promotion-status").mock(
        return_value=httpx.Response(
            200,
            json={
                "self_peer_id": "replica_self",
                "current_role": "follower",
                "last_promotion": None,
            },
        )
    )
    resp = await hy.replication.promotion_status()
    assert resp.self_peer_id == "replica_self"
    assert resp.current_role == "follower"
    assert resp.last_promotion is None


@pytest.mark.asyncio
async def test_promotion_status_after_promotion(
    hy: Hydra, respx_mock: respx.MockRouter
) -> None:
    respx_mock.get("https://hydra.test/replication/promotion-status").mock(
        return_value=httpx.Response(
            200,
            json={
                "self_peer_id": "replica_self",
                "current_role": "leader",
                "last_promotion": {
                    "promoted_at": "2026-01-01T00:00:00Z",
                    "promotion_sequence": 7,
                    "promoted_by": "actor_oncall",
                    "reason": "leader unreachable",
                },
            },
        )
    )
    resp = await hy.replication.promotion_status()
    assert resp.current_role == "leader"
    assert resp.last_promotion is not None
    assert resp.last_promotion.promotion_sequence == 7
    assert resp.last_promotion.promoted_by == "actor_oncall"
    assert resp.last_promotion.reason == "leader unreachable"


# === Namespace + tenant override ===


def test_replication_namespace_is_single_instance(hy: Hydra) -> None:
    assert hy.replication is hy.replication


@pytest.mark.asyncio
async def test_replication_tenant_override(
    hy: Hydra, respx_mock: respx.MockRouter
) -> None:
    """Rule #7 — per-call tenant override applies to replication
    reads too, even though the engine layer doesn't enforce tenant
    isolation on the replication control plane."""
    route = respx_mock.get("https://hydra.test/replication/status").mock(
        return_value=httpx.Response(
            200,
            json={
                "role": "Leader",
                "head_sequence": 0,
                "head_commit_id": None,
                "peers": [],
            },
        )
    )
    await hy.replication.status(tenant="tenant_other")
    assert route.calls.last.request.headers["X-Hydra-Tenant"] == "tenant_other"
