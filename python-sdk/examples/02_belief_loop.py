"""Example 02 — the full epistemic loop.

Walks through Hydra's four-verb loop:

    observe → support → propose → act

Concretely:
  1. Add `Evidence` (something concrete the agent observed).
  2. Propose a `Claim` supported by that evidence.
  3. Propose an `Action` related to that claim.
  4. Query Hydra to confirm the loop landed.

This is the kind of loop a real agent runs every time it acts on the
world: belief is grounded in evidence, action is grounded in belief,
and every step is recorded for later explanation.

Requires a Hydra engine reachable at http://localhost:8080.

Run:

    python examples/02_belief_loop.py
"""

from __future__ import annotations

import os
import uuid

from hydra import (
    ActionTarget,
    ClaimObject,
    ClaimSubject,
    EvidenceSource,
    HydraSync,
)

BASE_URL = os.environ.get("HYDRA_BASE_URL", "http://localhost:8080")
TOKEN = os.environ.get("HYDRA_TOKEN")
TENANT = os.environ.get("HYDRA_TENANT", "tenant_default")


def _id(prefix: str) -> str:
    """Mint a unique-ish id. Real callers should use ULIDs or whatever
    matches their ID convention."""
    return f"{prefix}_{uuid.uuid4().hex[:10]}"


def main() -> None:
    with HydraSync(BASE_URL, token=TOKEN, tenant=TENANT) as hy:
        evidence_id = _id("evd")
        claim_id = _id("claim")
        action_id = _id("act")

        # 1. Add evidence: a warehouse query that returned an
        #    anomalously low row count.
        hy.add_evidence(
            evidence_id=evidence_id,
            source=EvidenceSource.warehouse(
                system="snowflake", table="orders_daily"
            ),
            payload_kind="row_count_delta",
            payload_data={"delta": -127, "baseline": 1500},
            reliability=0.93,
        )
        print(f"1. Added evidence {evidence_id}")

        # 2. Propose a claim: "the `orders_daily` dataset is stale,"
        #    supported by the evidence we just added.
        hy.propose_claim(
            claim_id=claim_id,
            subject=ClaimSubject.dataset("orders_daily"),
            predicate="is_stale",
            object=ClaimObject.value(True),
            created_by="actor_anomaly_agent",
            kind="AnomalyFinding",
            confidence=0.87,
            evidence_for=[evidence_id],
        )
        print(f"2. Proposed claim {claim_id} (confidence=0.87)")

        # 3. Propose an action: backfill the stale dataset. The action
        #    is linked to the supporting claim and evidence so the full
        #    causal chain is queryable.
        hy.propose_action(
            action_id=action_id,
            kind="Backfill",
            targets=[ActionTarget.dataset("orders_daily")],
            proposed_by="actor_anomaly_agent",
            related_claims=[claim_id],
            supporting_evidence=[evidence_id],
            payload={"backfill_window_hours": 24},
        )
        print(f"3. Proposed action {action_id} (Backfill)")

        # 4. Confirm by reading back. The claim should report the
        #    evidence it leans on.
        claim = hy.get_claim(claim_id)
        print(
            f"\n4. Read back claim {claim.id}: "
            f"{claim.predicate}={claim.object.get('Value')} "
            f"({claim.status}, confidence={claim.confidence:.2f})"
        )
        print(f"   evidence_for: {claim.evidence_for}")

        # Bonus: list every claim supported by this evidence record.
        # Useful when correlating multiple beliefs grounded in the same
        # observation.
        supported = hy.list_claims_for_evidence(evidence_id)
        print(
            f"   Total claims supported by {evidence_id}: {len(supported)}"
        )


if __name__ == "__main__":
    main()
