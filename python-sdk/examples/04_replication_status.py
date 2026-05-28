"""Example 04 — poll replication status, peer lag, promotion history.

A small operator dashboard. Shows what `hy.replication.*` exposes and
the wire semantics that matter when running Hydra in a leader/follower
deployment.

Key semantics demonstrated:

  - `peer_lag(...)` NEVER 404s. `lag is None` means "no observation
    yet OR unknown peer_id" — a stable polling contract. Operators
    can poll this on a timer without worrying about HTTP error paths.

  - `promotion_status().last_promotion is None` means this node has
    never been promoted. A non-None `last_promotion` with
    `current_role == "follower"` means the node was promoted then
    demoted — the durable audit trail survives role changes.

Requires a Hydra engine reachable at http://localhost:8080. Works on
single-node deployments (the status response will just have an empty
peer list).

Run:

    python examples/04_replication_status.py
"""

from __future__ import annotations

import os

from hydra import HydraSync

BASE_URL = os.environ.get("HYDRA_BASE_URL", "http://localhost:8080")
TOKEN = os.environ.get("HYDRA_TOKEN")
TENANT = os.environ.get("HYDRA_TENANT", "tenant_default")


def main() -> None:
    with HydraSync(BASE_URL, token=TOKEN, tenant=TENANT) as hy:
        # === Cluster-wide snapshot ===
        status = hy.replication.status()
        print(f"role:              {status.role}")
        print(f"head_sequence:     {status.head_sequence}")
        print(f"head_commit_id:    {status.head_commit_id}")
        print(f"peers registered:  {len(status.peers)}")

        # === Per-peer lag ===
        if not status.peers:
            print("\nNo peers — single-node deployment. Skipping per-peer lag.")
        else:
            print("\nPer-peer lag:")
            for peer in status.peers:
                lag_resp = hy.replication.peer_lag(peer.id)
                if lag_resp.lag is None:
                    # The route returned 200 with lag:null — either the
                    # puller hasn't pulled yet OR the peer_id is unknown
                    # to the in-memory replication store. Both are
                    # legitimate "no data" states for operator polling.
                    print(f"  {peer.id:<24} no observation yet")
                else:
                    print(
                        f"  {peer.id:<24} "
                        f"lag={lag_resp.lag.lag_commits:>4} commits "
                        f"(follower={lag_resp.lag.follower_sequence}, "
                        f"leader={lag_resp.lag.leader_sequence}, "
                        f"observed_at={lag_resp.lag.observed_at})"
                    )

        # === Runtime role (lowercase RuntimeRole, distinct from the
        #     PascalCase ReplicationRole on peer records). ===
        runtime_role = hy.replication.role()
        print(f"\nRuntime role:      {runtime_role}")

        # === Promotion audit ===
        promo = hy.replication.promotion_status()
        print(f"self_peer_id:      {promo.self_peer_id}")
        print(f"current_role:      {promo.current_role}")
        if promo.last_promotion is None:
            print("last_promotion:    (this node has never been promoted)")
        else:
            lp = promo.last_promotion
            print(f"last_promotion:    sequence={lp.promotion_sequence}")
            print(f"                   promoted_at={lp.promoted_at}")
            print(f"                   promoted_by={lp.promoted_by}")
            print(f"                   reason={lp.reason}")
            if promo.current_role == "follower":
                # current_role lives, last_promotion is durable. After
                # promote-then-demote, the audit is preserved.
                print(
                    "                   (this node was promoted then "
                    "demoted — audit history survives role changes)"
                )


if __name__ == "__main__":
    main()
