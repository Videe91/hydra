"""Example 01 — ingest a signal, then ask Hydra to explain it.

Demonstrates:
  - Constructing a `HydraSync` client and using it as a context manager
  - Ingesting a `Signal` event with a structured payload
  - Capturing the `event_id` from the `IngestResponse`
  - Calling `hy.lineage(event_id)` to retrieve the causal context
  - Reading the server-rendered `explanation_summary`

Requires a Hydra engine reachable at http://localhost:8080. Adjust
`BASE_URL` if your engine listens elsewhere. If auth is enabled, set
`HYDRA_TOKEN` in your environment.

Run:

    python examples/01_ingest_and_lineage.py
"""

from __future__ import annotations

import os

from hydra import HydraSync

BASE_URL = os.environ.get("HYDRA_BASE_URL", "http://localhost:8080")
TOKEN = os.environ.get("HYDRA_TOKEN")
TENANT = os.environ.get("HYDRA_TENANT", "tenant_default")


def main() -> None:
    with HydraSync(BASE_URL, token=TOKEN, tenant=TENANT) as hy:
        # Ingest one signal: a CloudTrail-style observation about a
        # bucket creation, emitted by a sensor node.
        resp = hy.ingest_signal(
            name="cloudtrail/CreateBucket",
            source="node_aws_sensor",
            payload={
                "bucket_name": "my-app-uploads",
                "region": "us-east-1",
                "account_id": "123456789012",
            },
        )
        print(f"Ingested {resp.event_count} event(s); ids: {resp.event_ids}")

        if not resp.event_ids:
            print("No event ids returned (engine may have de-duped). Exiting.")
            return

        seed_event_id = resp.event_ids[0]

        # Ask for the lineage of the new event. With nothing else
        # ingested yet the answer is small: just the seed event, no
        # ancestors or descendants. As more events flow through Hydra,
        # this same call returns increasingly rich causal context.
        lin = hy.lineage(seed_event_id, depth=10)

        print(f"\nLineage of {seed_event_id}:")
        print(f"  Events in causal context: {len(lin.events)}")
        print(f"  Ancestors:                {lin.ancestors}")
        print(f"  Descendants:              {lin.descendants}")
        print(f"  Truncated:                {lin.truncated}")
        print(f"\nExplanation: {lin.explanation_summary}")


if __name__ == "__main__":
    main()
