"""Internal URL path construction helpers.

NOT part of the public API.

Centralizing path construction now (when there are 11 routes)
prevents drift as Patches 3 and 4 add diagnostic, lineage,
schema, and replication routes. Every public method that hits an
HTTP route calls one of these helpers; route changes in Hydra are
fixed in exactly one place.

Path-segment values get URL-encoded so IDs containing reserved
characters (slashes in `Dataset` names, etc.) don't break the
route match.
"""

from __future__ import annotations

from urllib.parse import quote


def _seg(value: str) -> str:
    """URL-encode a single path segment. Hydra IDs are ULID-shaped
    today and don't need encoding, but `Dataset` subject names can
    contain dots, slashes, and other reserved bytes."""
    return quote(value, safe="")


# === /ingest ===


def ingest_path() -> str:
    return "/ingest"


# === /query/* (single-get) ===


def query_node_path(node_id: str) -> str:
    return f"/query/nodes/{_seg(node_id)}"


def query_edge_path(edge_id: str) -> str:
    return f"/query/edges/{_seg(edge_id)}"


def query_claim_path(claim_id: str) -> str:
    return f"/query/claims/{_seg(claim_id)}"


def query_evidence_path(evidence_id: str) -> str:
    return f"/query/evidence/{_seg(evidence_id)}"


def query_action_path(action_id: str) -> str:
    return f"/query/actions/{_seg(action_id)}"


def query_outcome_path(outcome_id: str) -> str:
    return f"/query/outcomes/{_seg(outcome_id)}"


# === /events/* ===
#
# Note: there is no `/query/events/:event_id` route — the
# get-by-id lives at `/events/:event_id` under the events router
# (auth scope `read:audit` rather than `read:query`).


def event_path(event_id: str) -> str:
    return f"/events/{_seg(event_id)}"


# === /query/* (list with filter variants) ===


def query_claims_path() -> str:
    return "/query/claims"


def query_claims_by_status_path(status: str) -> str:
    return f"/query/claims/status/{_seg(status)}"


def query_claims_by_kind_path(kind: str) -> str:
    return f"/query/claims/kind/{_seg(kind)}"


def query_claims_for_subject_path() -> str:
    """Returns the path. Caller supplies `subject_kind` and
    `subject_value` as query params."""
    return "/query/claims-for-subject"


def query_claims_using_evidence_path(evidence_id: str) -> str:
    return f"/query/evidence/{_seg(evidence_id)}/claims"


def query_actions_path() -> str:
    return "/query/actions"


def query_actions_by_status_path(status: str) -> str:
    return f"/query/actions/status/{_seg(status)}"


def query_outcomes_for_action_path(action_id: str) -> str:
    return f"/query/actions/{_seg(action_id)}/outcomes"
