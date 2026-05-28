"""Tests for `hy.subscribe_commits()` and the SSE parser.

Two layers exercised here:

1. The manual SSE parser inside `_http._iter_sse_events`. Pure
   protocol shape; doesn't need a Hydra server. Pins the multi-line
   `data:` rule because the WHATWG spec allows it even though the
   current engine emits single-line data.

2. `Hydra.subscribe_commits()` end-to-end against a respx-mocked
   `/commits/stream` endpoint, including each of the four SSE event
   types: commit, heartbeat, lag, error.

End-to-end tests stream a fixed SSE payload through respx and assert
the typed stream items the SDK yields.
"""

from __future__ import annotations

import json

import httpx
import pytest
import respx

from hydra import (
    CommitBatchLite,
    CommitStreamCommit,
    CommitStreamError,
    CommitStreamHeartbeat,
    CommitStreamLag,
    Hydra,
)
from hydra._http import _iter_sse_events


# === Manual SSE parser — protocol shape ===


async def _aiter(lines: list[str]):
    """Wrap a static list of lines as an async iterator so the SSE
    parser sees the same shape it gets from `httpx.aiter_lines()`."""
    for line in lines:
        yield line


@pytest.mark.asyncio
async def test_sse_parser_yields_single_event() -> None:
    lines = [
        "event: commit",
        "data: {\"sequence\": 1}",
        "",
    ]
    events = [e async for e in _iter_sse_events(_aiter(lines))]
    assert events == [("commit", '{"sequence": 1}')]


@pytest.mark.asyncio
async def test_sse_parser_handles_multiple_events() -> None:
    lines = [
        "event: commit",
        "data: {\"sequence\": 1}",
        "",
        "event: heartbeat",
        "data: {\"head_sequence\": 1}",
        "",
        "event: commit",
        "data: {\"sequence\": 2}",
        "",
    ]
    events = [e async for e in _iter_sse_events(_aiter(lines))]
    assert events == [
        ("commit", '{"sequence": 1}'),
        ("heartbeat", '{"head_sequence": 1}'),
        ("commit", '{"sequence": 2}'),
    ]


@pytest.mark.asyncio
async def test_sse_parser_handles_multiline_data() -> None:
    """Per the WHATWG EventSource spec, multiple `data:` lines in one
    event are concatenated with `\\n`. Hydra's server currently emits
    single-line data, but agents may add line-broken JSON later — and
    the parser must already handle it correctly today."""
    lines = [
        "event: commit",
        "data: {",
        "data:   \"sequence\": 1,",
        "data:   \"detail\": \"multi-line payload\"",
        "data: }",
        "",
    ]
    events = [e async for e in _iter_sse_events(_aiter(lines))]
    assert len(events) == 1
    name, data = events[0]
    assert name == "commit"
    # The reconstructed data must be parseable JSON.
    parsed = json.loads(data)
    assert parsed == {"sequence": 1, "detail": "multi-line payload"}


@pytest.mark.asyncio
async def test_sse_parser_skips_comments_and_unknown_fields() -> None:
    lines = [
        ": this is a comment",
        "event: heartbeat",
        "id: 42",  # unknown field — silently dropped per spec
        "retry: 3000",  # unknown field
        "data: {\"head_sequence\": 7}",
        "",
    ]
    events = [e async for e in _iter_sse_events(_aiter(lines))]
    assert events == [("heartbeat", '{"head_sequence": 7}')]


@pytest.mark.asyncio
async def test_sse_parser_handles_crlf_line_endings() -> None:
    """httpx's aiter_lines strips `\\n` but not always `\\r`. The
    parser must tolerate `\\r` at the end of each line."""
    lines = [
        "event: commit\r",
        "data: {}\r",
        "\r",
    ]
    events = [e async for e in _iter_sse_events(_aiter(lines))]
    assert events == [("commit", "{}")]


@pytest.mark.asyncio
async def test_sse_parser_strips_only_one_leading_space() -> None:
    """Per the SSE spec one optional leading space after `:` is
    stripped. Subsequent whitespace is data."""
    lines = [
        "data:  two leading spaces",  # one leading space stripped → " two leading spaces"
        "",
    ]
    events = [e async for e in _iter_sse_events(_aiter(lines))]
    assert events == [("message", " two leading spaces")]


@pytest.mark.asyncio
async def test_sse_parser_dispatches_trailing_event_without_final_blank() -> None:
    """Lenient end-of-stream: if the server closes without a final
    blank line, surface the buffered event anyway. Real Python SSE
    clients (eg. httpx-sse) do the same."""
    lines = [
        "event: commit",
        "data: {\"sequence\": 1}",
        # NO blank line — connection closes mid-event
    ]
    events = [e async for e in _iter_sse_events(_aiter(lines))]
    assert events == [("commit", '{"sequence": 1}')]


# === End-to-end: hy.subscribe_commits() against a mocked stream ===


def _sse_payload(events: list[tuple[str, dict]]) -> str:
    """Serialize a list of (event_name, json_dict) pairs into wire
    SSE format."""
    parts = []
    for name, data in events:
        parts.append(f"event: {name}\n")
        parts.append(f"data: {json.dumps(data)}\n")
        parts.append("\n")
    return "".join(parts)


COMMIT_BATCH_FIXTURE = {
    "id": "commit_1",
    "sequence": 1,
    "previous_hash": None,
    "commit_hash": "hash_1",
    "events": [
        {
            "id": "evt_1",
            "timestamp": "2026-01-01T00:00:00Z",
            "kind": {
                "Signal": {
                    "source": "node_x",
                    "name": "warehouse.null_spike",
                    "payload": {},
                }
            },
            "caused_by": [],
            "cascade_id": "csc_1",
            "cascade_depth": 0,
            "cascade_breadth_index": 0,
            "tenant_id": None,
        }
    ],
    "event_records": [],
    "status": "Committed",
    "committed_by": None,
    "committed_at": "2026-01-01T00:00:00Z",
    "idempotency_key": None,
    "metadata": {},
}


@pytest.mark.asyncio
async def test_subscribe_commits_yields_parsed_batch(
    hy: Hydra, respx_mock: respx.MockRouter
) -> None:
    """Single commit event over the wire → typed `CommitStreamCommit`
    with a parsed `CommitBatchLite`. The `events` list is already
    `Event` instances; `raw` carries the full wire dict."""
    payload = _sse_payload([("commit", COMMIT_BATCH_FIXTURE)])
    respx_mock.get("https://hydra.test/commits/stream").mock(
        return_value=httpx.Response(
            200, text=payload, headers={"content-type": "text/event-stream"}
        )
    )

    items = []
    async for item in hy.subscribe_commits():
        items.append(item)
    assert len(items) == 1

    item = items[0]
    assert isinstance(item, CommitStreamCommit)
    assert item.type == "commit"
    assert item.commit.id == "commit_1"
    assert item.commit.sequence == 1
    assert len(item.commit.events) == 1
    assert item.commit.events[0].id == "evt_1"
    # raw preserves the full wire shape.
    assert item.commit.raw["status"] == "Committed"
    assert item.commit.raw["commit_hash"] == "hash_1"


@pytest.mark.asyncio
async def test_subscribe_commits_passes_after_sequence_query_param(
    hy: Hydra, respx_mock: respx.MockRouter
) -> None:
    """Caller resumes from a known sequence via `after_sequence=...`.
    The SDK must surface that as a `?after_sequence=N` query param."""
    payload = _sse_payload([])
    route = respx_mock.get("https://hydra.test/commits/stream").mock(
        return_value=httpx.Response(
            200, text=payload, headers={"content-type": "text/event-stream"}
        )
    )
    async for _ in hy.subscribe_commits(after_sequence=42):
        pass
    request = route.calls.last.request
    assert request.url.params.get("after_sequence") == "42"


@pytest.mark.asyncio
async def test_subscribe_commits_omits_after_sequence_when_zero(
    hy: Hydra, respx_mock: respx.MockRouter
) -> None:
    """`after_sequence=0` (default) means "from the start" — no query
    param needed. The engine treats absence the same as 0."""
    payload = _sse_payload([])
    route = respx_mock.get("https://hydra.test/commits/stream").mock(
        return_value=httpx.Response(
            200, text=payload, headers={"content-type": "text/event-stream"}
        )
    )
    async for _ in hy.subscribe_commits():
        pass
    request = route.calls.last.request
    assert "after_sequence" not in request.url.params


@pytest.mark.asyncio
async def test_subscribe_commits_surfaces_heartbeat(
    hy: Hydra, respx_mock: respx.MockRouter
) -> None:
    """Per the Patch 6 design, heartbeats are first-class items —
    NOT silently dropped. Agents that want the keepalive can use them
    for connection-health metrics; demos can ignore them."""
    payload = _sse_payload([("heartbeat", {"head_sequence": 7})])
    respx_mock.get("https://hydra.test/commits/stream").mock(
        return_value=httpx.Response(
            200, text=payload, headers={"content-type": "text/event-stream"}
        )
    )
    items = [it async for it in hy.subscribe_commits()]
    assert len(items) == 1
    assert isinstance(items[0], CommitStreamHeartbeat)
    assert items[0].head_sequence == 7


@pytest.mark.asyncio
async def test_subscribe_commits_surfaces_lag(
    hy: Hydra, respx_mock: respx.MockRouter
) -> None:
    """The lag event tells the caller their `after_sequence` was
    below what the engine could replay. Stream continues from
    `starting_at_sequence`; this test verifies the SDK exposes both
    numbers."""
    payload = _sse_payload(
        [
            (
                "lag",
                {
                    "requested_after_sequence": 5,
                    "starting_at_sequence": 100,
                },
            ),
            ("commit", COMMIT_BATCH_FIXTURE),
        ]
    )
    respx_mock.get("https://hydra.test/commits/stream").mock(
        return_value=httpx.Response(
            200, text=payload, headers={"content-type": "text/event-stream"}
        )
    )
    items = [it async for it in hy.subscribe_commits(after_sequence=5)]
    assert len(items) == 2
    assert isinstance(items[0], CommitStreamLag)
    assert items[0].requested_after_sequence == 5
    assert items[0].starting_at_sequence == 100
    # Stream continues — the commit AFTER the lag event is still emitted.
    assert isinstance(items[1], CommitStreamCommit)


@pytest.mark.asyncio
async def test_subscribe_commits_terminates_after_error(
    hy: Hydra, respx_mock: respx.MockRouter
) -> None:
    """`error` is terminal. Even if more events follow in the wire
    payload (unlikely — server closes on error), the SDK iterator
    must stop after yielding the error so callers handle it once."""
    payload = _sse_payload(
        [
            ("error", {"error": "subscriber lagged: 42 commits dropped", "hint": "reconnect"}),
            # This commit should NOT be yielded — iterator already
            # returned after the error.
            ("commit", COMMIT_BATCH_FIXTURE),
        ]
    )
    respx_mock.get("https://hydra.test/commits/stream").mock(
        return_value=httpx.Response(
            200, text=payload, headers={"content-type": "text/event-stream"}
        )
    )
    items = [it async for it in hy.subscribe_commits()]
    assert len(items) == 1
    assert isinstance(items[0], CommitStreamError)
    assert "lagged" in items[0].error
    assert items[0].hint == "reconnect"


@pytest.mark.asyncio
async def test_subscribe_commits_skips_unknown_event_types(
    hy: Hydra, respx_mock: respx.MockRouter
) -> None:
    """Forward compatibility: if the server adds new SSE event types
    in a future patch, an older SDK must not crash. Unknown event
    names are silently skipped — caller sees only what it knows
    about."""
    payload = _sse_payload(
        [
            ("future_event_kind", {"weird": "payload"}),
            ("commit", COMMIT_BATCH_FIXTURE),
        ]
    )
    respx_mock.get("https://hydra.test/commits/stream").mock(
        return_value=httpx.Response(
            200, text=payload, headers={"content-type": "text/event-stream"}
        )
    )
    items = [it async for it in hy.subscribe_commits()]
    assert len(items) == 1
    assert isinstance(items[0], CommitStreamCommit)


@pytest.mark.asyncio
async def test_subscribe_commits_sends_auth_and_tenant_headers(
    hy: Hydra, respx_mock: respx.MockRouter
) -> None:
    """The stream opens with the same auth + tenant header machinery
    as regular calls — bearer token + X-Hydra-Tenant default."""
    payload = _sse_payload([])
    route = respx_mock.get("https://hydra.test/commits/stream").mock(
        return_value=httpx.Response(
            200, text=payload, headers={"content-type": "text/event-stream"}
        )
    )
    async for _ in hy.subscribe_commits():
        pass
    request = route.calls.last.request
    assert request.headers["Authorization"] == "Bearer test-token"
    assert request.headers["X-Hydra-Tenant"] == "tenant_test"
    # SSE clients should announce themselves with this Accept header.
    assert request.headers["Accept"] == "text/event-stream"


@pytest.mark.asyncio
async def test_subscribe_commits_tenant_override(
    hy: Hydra, respx_mock: respx.MockRouter
) -> None:
    """Per-call `tenant=` overrides the client default (Rule #7)
    even on the streaming connection."""
    payload = _sse_payload([])
    route = respx_mock.get("https://hydra.test/commits/stream").mock(
        return_value=httpx.Response(
            200, text=payload, headers={"content-type": "text/event-stream"}
        )
    )
    async for _ in hy.subscribe_commits(tenant="tenant_other"):
        pass
    assert route.calls.last.request.headers["X-Hydra-Tenant"] == "tenant_other"


# === CommitBatchLite shape ===


def test_commit_batch_lite_from_wire_extracts_typed_fields() -> None:
    """`CommitBatchLite.from_wire(dict)` must populate the typed
    fields AND preserve the full wire dict in `raw`."""
    lite = CommitBatchLite.from_wire(COMMIT_BATCH_FIXTURE)
    assert lite.id == "commit_1"
    assert lite.sequence == 1
    assert lite.commit_hash == "hash_1"
    assert lite.previous_hash is None
    assert len(lite.events) == 1
    assert lite.events[0].id == "evt_1"
    # The wire-shape stash carries everything, including fields the
    # SDK doesn't yet type (status, event_records, metadata).
    assert lite.raw == COMMIT_BATCH_FIXTURE


def test_commit_batch_lite_handles_missing_optional_hashes() -> None:
    """First commit on a fresh ledger has `previous_hash: null`
    AND `commit_hash: null` is possible before the hash is computed.
    Both should round-trip as None without exploding."""
    payload = {
        **COMMIT_BATCH_FIXTURE,
        "previous_hash": None,
        "commit_hash": None,
    }
    lite = CommitBatchLite.from_wire(payload)
    assert lite.previous_hash is None
    assert lite.commit_hash is None
