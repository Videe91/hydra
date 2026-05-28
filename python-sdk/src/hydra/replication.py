"""`hy.replication.*` — read-only replication introspection.

The SDK exposes the **operator-facing** read routes only. Three
internal-protocol routes used by the puller worker are intentionally
NOT exposed:

  GET /replication/commits          — pull-protocol page fetch
  GET /replication/snapshot/latest  — bootstrap decision
  GET /replication/snapshot/:id     — full SnapshotBody download

Those are part of the leader→follower wire protocol, not an
operator UX. Wrapping them would invite mis-use and ship a giant
`SnapshotBody` model the SDK has no other reason to carry.

Write routes (`POST /replication/role`, `POST /replication/promote`,
`POST /replication/apply`) are out of scope for Patch 4 — they may
land later under an explicit "admin" namespace.
"""

from __future__ import annotations

from . import _paths
from ._http import HydraHttpClient, HydraHttpClientSync
from ._types import (
    ReplicaId,
    ReplicationLagResponse,
    ReplicationPeer,
    ReplicationPromotionStatusResponse,
    ReplicationRoleGetResponse,
    ReplicationStatusResponse,
    RuntimeRole,
    TenantId,
)


class _Replication:
    """Namespace for read-only `/replication/*` HTTP routes."""

    def __init__(
        self, http: HydraHttpClient, default_tenant: TenantId | None
    ) -> None:
        self._http = http
        self._default_tenant = default_tenant

    async def status(
        self, *, tenant: TenantId | None = None
    ) -> ReplicationStatusResponse:
        """Return the cluster-wide replication snapshot: role, head sequence/commit, and the full peer list."""
        raw = await self._http.get(_paths.replication_status_path(), tenant=tenant)
        return ReplicationStatusResponse.model_validate(raw)

    async def peers(
        self, *, tenant: TenantId | None = None
    ) -> list[ReplicationPeer]:
        """List every registered replication peer."""
        raw = await self._http.get(_paths.replication_peers_path(), tenant=tenant)
        return [ReplicationPeer.model_validate(p) for p in raw["peers"]]

    async def peer(
        self, peer_id: ReplicaId, *, tenant: TenantId | None = None
    ) -> ReplicationPeer:
        """Get a single replication peer by id. 404 → HydraNotFoundError."""
        raw = await self._http.get(
            _paths.replication_peer_path(peer_id), tenant=tenant
        )
        return ReplicationPeer.model_validate(raw["peer"])

    async def peer_lag(
        self, peer_id: ReplicaId, *, tenant: TenantId | None = None
    ) -> ReplicationLagResponse:
        """Return the latest observed lag for `peer_id`. **Never 404s** — unknown peer or no observation yet both surface as `lag: None`."""
        raw = await self._http.get(
            _paths.replication_peer_lag_path(peer_id), tenant=tenant
        )
        return ReplicationLagResponse.model_validate(raw)

    async def role(self, *, tenant: TenantId | None = None) -> RuntimeRole:
        """Return this node's current runtime role (`"leader"` or `"follower"`)."""
        raw = await self._http.get(_paths.replication_role_path(), tenant=tenant)
        parsed = ReplicationRoleGetResponse.model_validate(raw)
        return parsed.role

    async def promotion_status(
        self, *, tenant: TenantId | None = None
    ) -> ReplicationPromotionStatusResponse:
        """Return durable promotion history for this node. `last_promotion=None` means this node was never promoted; `current_role` is the live engine role (may diverge after demotion)."""
        raw = await self._http.get(
            _paths.replication_promotion_status_path(), tenant=tenant
        )
        return ReplicationPromotionStatusResponse.model_validate(raw)


# === Patch 5: sync mirror ===
#
# Method-for-method parity with `_Replication`. Same signatures, same
# semantics (`peer_lag` never 404s, etc.).


class _ReplicationSync:
    """Synchronous mirror of `_Replication`. Access via
    `hy.replication.<method>` on a `HydraSync` client."""

    def __init__(
        self, http: HydraHttpClientSync, default_tenant: TenantId | None
    ) -> None:
        self._http = http
        self._default_tenant = default_tenant

    def status(
        self, *, tenant: TenantId | None = None
    ) -> ReplicationStatusResponse:
        """Return the cluster-wide replication snapshot: role, head sequence/commit, and the full peer list."""
        raw = self._http.get(_paths.replication_status_path(), tenant=tenant)
        return ReplicationStatusResponse.model_validate(raw)

    def peers(
        self, *, tenant: TenantId | None = None
    ) -> list[ReplicationPeer]:
        """List every registered replication peer."""
        raw = self._http.get(_paths.replication_peers_path(), tenant=tenant)
        return [ReplicationPeer.model_validate(p) for p in raw["peers"]]

    def peer(
        self, peer_id: ReplicaId, *, tenant: TenantId | None = None
    ) -> ReplicationPeer:
        """Get a single replication peer by id. 404 → HydraNotFoundError."""
        raw = self._http.get(_paths.replication_peer_path(peer_id), tenant=tenant)
        return ReplicationPeer.model_validate(raw["peer"])

    def peer_lag(
        self, peer_id: ReplicaId, *, tenant: TenantId | None = None
    ) -> ReplicationLagResponse:
        """Return the latest observed lag for `peer_id`. **Never 404s** — unknown peer or no observation yet both surface as `lag: None`."""
        raw = self._http.get(
            _paths.replication_peer_lag_path(peer_id), tenant=tenant
        )
        return ReplicationLagResponse.model_validate(raw)

    def role(self, *, tenant: TenantId | None = None) -> RuntimeRole:
        """Return this node's current runtime role (`"leader"` or `"follower"`)."""
        raw = self._http.get(_paths.replication_role_path(), tenant=tenant)
        parsed = ReplicationRoleGetResponse.model_validate(raw)
        return parsed.role

    def promotion_status(
        self, *, tenant: TenantId | None = None
    ) -> ReplicationPromotionStatusResponse:
        """Return durable promotion history for this node. `last_promotion=None` means this node was never promoted; `current_role` is the live engine role (may diverge after demotion)."""
        raw = self._http.get(
            _paths.replication_promotion_status_path(), tenant=tenant
        )
        return ReplicationPromotionStatusResponse.model_validate(raw)
