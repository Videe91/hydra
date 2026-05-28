"""Demo Agent 1 — Live edition.

The upgrade from `data_quality_watcher.py` (run-once) to a watcher
that *tails* Hydra and reacts to every new `warehouse.null_spike`
signal as it lands. This is the moment Hydra becomes visibly alive:

    something happens → agent sees it → agent records why → agent
    proposes belief → agent proposes action → Hydra explains the chain

Compared to the run-once version, this script:

  - Uses the async `Hydra` client (the sync `HydraSync` doesn't have
    `subscribe_commits` yet — sync mirror is deferred to a later
    patch).
  - Calls `async for item in hy.subscribe_commits(...)` and branches
    on `item.type`.
  - Reacts to commits whose events contain a `Signal` named
    `warehouse.null_spike` — but NOT signals the agent itself
    emitted (no feedback loop on the agent's own ingest events).
  - Derives deterministic evidence/claim/action ids from the seed
    event id, so reconnecting and replaying the same commit twice is
    idempotent.

Requires a Hydra engine reachable at http://localhost:8080 with the
`/commits/stream` endpoint mounted (Patch 6 or later).

    python data_quality_watcher_live.py

Ctrl-C to exit. Set `HYDRA_BASE_URL` / `HYDRA_TOKEN` / `HYDRA_TENANT`
in the env to point at a different engine.

To produce signals to react to, run from another terminal:

    python data_quality_watcher.py   # the run-once script

Each invocation will land a new commit, the live watcher will see
it within milliseconds.
"""

from __future__ import annotations

import asyncio
import os
import signal
import sys
from typing import Any

from hydra import (
    ActionTarget,
    ClaimObject,
    ClaimSubject,
    EvidenceSource,
    Hydra,
)

BASE_URL = os.environ.get("HYDRA_BASE_URL", "http://localhost:8080")
TOKEN = os.environ.get("HYDRA_TOKEN")
TENANT = os.environ.get("HYDRA_TENANT", "tenant_default")

AGENT_ACTOR = "agent_data_quality_watcher_live"

# Source NodeId the run-once script uses. We react to signals from
# anyone EXCEPT this agent itself (preventing a feedback loop on
# ingest events the live watcher emits when it adds evidence /
# proposes claims / proposes actions).
WATCHED_SIGNAL_NAME = "warehouse.null_spike"


def _signal_payload(event: Any) -> dict[str, Any] | None:
    """Extract the payload from a Signal EventKind. Returns None for
    non-Signal events, or events whose kind isn't shaped like our
    expected dict-tagged-union."""
    kind = event.kind
    if not isinstance(kind, dict):
        return None
    signal = kind.get("Signal")
    if not isinstance(signal, dict):
        return None
    return signal


def _is_our_own_event(event: Any) -> bool:
    """Skip events the agent itself emits — otherwise reacting to a
    null_spike causes us to ingest evidence/claim/action, which
    triggers our own subscription, which would loop."""
    # The agent's ingest helpers don't set source=AGENT_ACTOR on
    # signals (signals come FROM sensors, not agents). Our followup
    # commits are EvidenceAdded / ClaimProposed / ActionProposed
    # events — those don't have a `Signal` discriminator, so
    # `_signal_payload` already returns None and we skip them by
    # name match. Belt and braces: also skip any signal whose
    # source includes our actor id, in case future agents emit
    # signals.
    payload = _signal_payload(event)
    if payload is None:
        return False
    source = payload.get("source") or ""
    return AGENT_ACTOR in source


async def react_to_signal(hy: Hydra, seed_event_id: str, payload: dict[str, Any]) -> None:
    """Record evidence + claim + action for one observed null-spike
    signal, then print the resulting lineage summary."""
    inner_payload = payload.get("payload") or {}
    column = inner_payload.get("column", "unknown")
    dataset = inner_payload.get("dataset", "unknown")
    rate = inner_payload.get("value", 0.0)
    baseline = inner_payload.get("baseline", 0.0)

    # Deterministic IDs derived from the seed event id. Re-running
    # the watcher and re-observing the same commit is a no-op.
    evidence_id = f"evd_live_{seed_event_id}"
    claim_id = f"claim_live_{seed_event_id}"
    action_id = f"act_live_{seed_event_id}"

    await hy.add_evidence(
        evidence_id=evidence_id,
        source=EvidenceSource.system("snowflake"),
        payload_kind="metric_observation",
        payload_data=inner_payload,
        reliability=0.94,
        caused_by=seed_event_id,
    )
    await hy.propose_claim(
        claim_id=claim_id,
        subject=ClaimSubject.dataset(dataset),
        predicate="has_data_quality_incident",
        object=ClaimObject.value({"column": column, "reason": "null_spike"}),
        created_by=AGENT_ACTOR,
        kind="AnomalyFinding",
        confidence=0.91,
        evidence_for=[evidence_id],
        caused_by=seed_event_id,
    )
    await hy.propose_action(
        action_id=action_id,
        kind="Quarantine",
        targets=[ActionTarget.dataset(dataset)],
        proposed_by=AGENT_ACTOR,
        related_claims=[claim_id],
        supporting_evidence=[evidence_id],
        payload={
            "reason": (
                f"{column} null rate jumped from {baseline:.0%} "
                f"to {rate:.0%}"
            ),
            "suggested_owner": "data-platform-oncall",
        },
        caused_by=seed_event_id,
    )

    lineage = await hy.lineage(seed_event_id, depth=10)
    print(f"  → reacted: evd={evidence_id}, claim={claim_id}, action={action_id}")
    print(f"    lineage: {lineage.explanation_summary}")


async def watch_forever() -> None:
    print("Hydra Data Quality Watcher — LIVE")
    print(f"  base_url = {BASE_URL}")
    print(f"  tenant   = {TENANT}")
    print(f"  watching for Signal name = {WATCHED_SIGNAL_NAME!r}")
    print(f"  agent actor = {AGENT_ACTOR}")
    print("Ctrl-C to exit.\n")

    last_seen_sequence = 0
    async with Hydra(BASE_URL, token=TOKEN, tenant=TENANT) as hy:
        # Reconnect loop. `subscribe_commits` may terminate cleanly
        # (server close), via a CommitStreamError (slow consumer),
        # or via a network error. We resume from the last seen
        # sequence so the engine's catch-up replay covers the gap.
        while True:
            print(f"[stream] connecting after_sequence={last_seen_sequence}")
            try:
                async for item in hy.subscribe_commits(
                    after_sequence=last_seen_sequence
                ):
                    if item.type == "heartbeat":
                        # Heartbeats are bookkeeping; keep going.
                        continue
                    if item.type == "lag":
                        print(
                            f"[stream] lag: requested {item.requested_after_sequence}, "
                            f"starting at {item.starting_at_sequence}"
                        )
                        # Resume cursor from where the server is
                        # actually starting us, not where we asked.
                        last_seen_sequence = max(
                            last_seen_sequence, item.starting_at_sequence - 1
                        )
                        continue
                    if item.type == "error":
                        print(
                            f"[stream] error: {item.error}"
                            + (f" ({item.hint})" if item.hint else "")
                        )
                        # Iterator ends after error per the SDK
                        # contract; outer loop reconnects.
                        break
                    # item.type == "commit"
                    commit = item.commit
                    last_seen_sequence = commit.sequence
                    print(
                        f"[seq {commit.sequence}] {len(commit.events)} event(s)"
                    )
                    for event in commit.events:
                        payload = _signal_payload(event)
                        if payload is None:
                            continue
                        if payload.get("name") != WATCHED_SIGNAL_NAME:
                            continue
                        if _is_our_own_event(event):
                            continue
                        print(
                            f"  ! null-spike signal observed "
                            f"(source={payload.get('source')})"
                        )
                        await react_to_signal(hy, event.id, payload)
            except (KeyboardInterrupt, asyncio.CancelledError):
                raise
            except Exception as exc:  # noqa: BLE001
                print(
                    f"[stream] connection lost: "
                    f"{exc.__class__.__name__}: {exc}",
                    file=sys.stderr,
                )

            # Small delay before reconnecting so a hard-down engine
            # doesn't pin the CPU in a tight reconnect loop.
            await asyncio.sleep(2.0)


def _install_signal_handlers(loop: asyncio.AbstractEventLoop) -> None:
    """Make Ctrl-C exit cleanly rather than producing a noisy
    traceback. Unix-only; on Windows the default Ctrl-C handler is
    used."""
    if sys.platform == "win32":
        return
    for sig in (signal.SIGINT, signal.SIGTERM):
        loop.add_signal_handler(sig, lambda: asyncio.create_task(_shutdown()))


async def _shutdown() -> None:
    print("\n[stream] shutting down")
    raise asyncio.CancelledError()


def main() -> None:
    loop = asyncio.new_event_loop()
    asyncio.set_event_loop(loop)
    _install_signal_handlers(loop)
    try:
        loop.run_until_complete(watch_forever())
    except (KeyboardInterrupt, asyncio.CancelledError):
        pass
    finally:
        loop.close()


if __name__ == "__main__":
    main()
