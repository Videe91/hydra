"""Demo Agent 1 — Data Quality Incident Watcher.

This is the first demo agent in the Hydra examples. It proves that
Hydra is a *living database*, not just an event log.

It runs the full agentic loop end-to-end against a real Hydra
instance:

    observe → evidence → claim → action → explain

Storyline
---------

Snowflake reports that `orders.customer_id` suddenly has 38% nulls
(vs. a 2% baseline). The agent:

  1. Observes the spike as a `warehouse.null_spike` Signal.
  2. Records the metric reading as Evidence (reliability 0.94).
  3. Proposes the Claim that the `orders` table has a data-quality
     incident (confidence 0.91, kind AnomalyFinding).
  4. Proposes a Quarantine Action against the dataset.
  5. Asks Hydra to explain the chain via `hy.lineage(signal_event_id)`.

The "aha" is step 5: a single call returns the evidence + claim +
action that originated from the signal, plus a server-rendered
`explanation_summary` sentence. Hydra remembered the causal chain
across four independent ingest calls because the agent threaded the
seed event id back through each record via the SDK's `caused_by`
parameter.

Bonus pass
----------

After the loop, the agent calls `hy.diagnostics.{anomaly, coverage,
counterfactual}` to show that Hydra surfaces operational insight
about its own state — the database introspects itself.

Run
---

Requires a Hydra engine reachable at http://localhost:8080 with
ingest + lineage + diagnostics enabled.

    python data_quality_watcher.py

If your engine listens elsewhere, set env vars:

    HYDRA_BASE_URL=http://hydra.internal:8080 \
    HYDRA_TOKEN=... \
    HYDRA_TENANT=tenant_demo \
    python data_quality_watcher.py
"""

from __future__ import annotations

import json
import os
import pathlib
import sys

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

# Stable IDs let the demo be re-run idempotently against the same
# Hydra. Real agents would mint ULIDs/UUIDs.
SIGNAL_IDEMPOTENCY_KEY = "incident-orders-customer-id-null-spike"
EVIDENCE_ID = "evd_orders_customer_id_null_spike"
CLAIM_ID = "claim_orders_customer_id_corrupted"
ACTION_ID = "act_quarantine_orders"

AGENT_ACTOR = "agent_data_quality_watcher"


def load_incident() -> dict:
    """Load the sample incident from the sibling JSON file."""
    here = pathlib.Path(__file__).parent
    with (here / "sample_incident.json").open() as f:
        return json.load(f)


def main() -> None:
    incident = load_incident()

    print("Hydra Data Quality Watcher")
    print(f"  base_url = {BASE_URL}")
    print(f"  tenant   = {TENANT}")
    print()

    with HydraSync(BASE_URL, token=TOKEN, tenant=TENANT) as hy:
        # ────────────────────────────────────────────────────────────
        # 1. Observe — a Signal is the most lightweight thing the
        #    agent can hand to Hydra. "Something happened. Here's
        #    the payload."
        # ────────────────────────────────────────────────────────────
        signal_resp = hy.ingest_signal(
            name="warehouse.null_spike",
            source="node_snowflake_prod_orders",
            payload=incident,
            idempotency_key=SIGNAL_IDEMPOTENCY_KEY,
        )
        seed_event_id = signal_resp.event_ids[0]
        print("Observed:")
        print(
            f"  warehouse.null_spike on "
            f"snowflake.prod.{incident['dataset']}.{incident['column']}"
        )
        print(f"  seed event id: {seed_event_id}")
        print()

        # ────────────────────────────────────────────────────────────
        # 2. Evidence — "Here is the concrete data underpinning the
        #    observation." reliability=0.94 says "the snowflake
        #    metric is accurate but not infallible." caused_by ties
        #    this back to the signal so lineage can find it.
        # ────────────────────────────────────────────────────────────
        hy.add_evidence(
            evidence_id=EVIDENCE_ID,
            source=EvidenceSource.system("snowflake"),
            payload_kind="metric_observation",
            payload_data=incident,
            reliability=0.94,
            caused_by=seed_event_id,
        )
        print("Evidence:")
        print(f"  {EVIDENCE_ID}")
        print("  reliability: 0.94")
        print()

        # ────────────────────────────────────────────────────────────
        # 3. Claim — the belief layer. The agent moves from "I saw
        #    this number" to "I believe this means the orders table
        #    has a data-quality incident." Confidence 0.91 reflects
        #    that the spike is consistent with the failure mode but
        #    isn't direct proof of corruption.
        # ────────────────────────────────────────────────────────────
        hy.propose_claim(
            claim_id=CLAIM_ID,
            subject=ClaimSubject.dataset(incident["dataset"]),
            predicate="has_data_quality_incident",
            object=ClaimObject.value(
                {"column": incident["column"], "reason": "null_spike"}
            ),
            created_by=AGENT_ACTOR,
            kind="AnomalyFinding",
            confidence=0.91,
            evidence_for=[EVIDENCE_ID],
            caused_by=seed_event_id,
        )
        print("Claim:")
        print(f"  {CLAIM_ID}")
        print("  confidence: 0.91")
        print()

        # ────────────────────────────────────────────────────────────
        # 4. Action — propose remediation. Quarantine is reversible
        #    and conservative; a real agent might escalate via an
        #    ApprovalRequest before promoting this beyond Proposed.
        # ────────────────────────────────────────────────────────────
        hy.propose_action(
            action_id=ACTION_ID,
            kind="Quarantine",
            targets=[ActionTarget.dataset(incident["dataset"])],
            proposed_by=AGENT_ACTOR,
            related_claims=[CLAIM_ID],
            supporting_evidence=[EVIDENCE_ID],
            payload={
                "reason": (
                    f"{incident['column']} null rate jumped from "
                    f"{incident['baseline']:.0%} to {incident['value']:.0%}"
                ),
                "suggested_owner": "data-platform-oncall",
            },
            caused_by=seed_event_id,
        )
        print("Action proposed:")
        print(f"  {ACTION_ID}")
        print("  kind: Quarantine")
        print()

        # ────────────────────────────────────────────────────────────
        # 5. Explain — the "aha" moment. ONE lineage call returns
        #    the evidence, claim, and action that descended from the
        #    seed signal, plus a server-rendered prose summary. No
        #    extra bookkeeping by the agent — Hydra remembered.
        # ────────────────────────────────────────────────────────────
        lineage = hy.lineage(seed_event_id, depth=10)
        print("Explanation:")
        print(f"  {lineage.explanation_summary}")
        print()
        print("Causal chain:")
        print(f"  events:    {len(lineage.events)}")
        print(f"  evidence:  {len(lineage.evidence)}")
        print(f"  claims:    {len(lineage.claims)}")
        print(f"  actions:   {len(lineage.actions)}")
        print()

        # ────────────────────────────────────────────────────────────
        # Bonus — Hydra introspects itself. Each diagnostic endpoint
        # is read-only and tolerates being called against a fresh
        # engine (returns empty / "no observation" rather than 404).
        # ────────────────────────────────────────────────────────────
        try:
            anomaly = hy.diagnostics.anomaly()
            coverage = hy.diagnostics.coverage()
            counterfactual = hy.diagnostics.counterfactual(
                seed_event_id, include_diff=False
            )
            print("Diagnostics:")
            print(f"  anomalies: {anomaly.anomaly_count}")
            print(
                f"  coverage:  {coverage.report_count} model(s) "
                f"({'complete' if coverage.report_count == 0 else 'see report'})"
            )
            print(
                f"  counterfactual magnitude: {counterfactual.magnitude:.1f}"
            )
        except Exception as exc:  # noqa: BLE001 — diagnostics are bonus
            print(f"Diagnostics: skipped ({exc.__class__.__name__})")


if __name__ == "__main__":
    try:
        main()
    except Exception as exc:  # noqa: BLE001
        print(f"\nDemo failed: {exc.__class__.__name__}: {exc}", file=sys.stderr)
        print(
            "\nIs Hydra running and reachable at "
            f"{BASE_URL}? Set HYDRA_BASE_URL / HYDRA_TOKEN / HYDRA_TENANT "
            "in your environment to point elsewhere.",
            file=sys.stderr,
        )
        sys.exit(1)
