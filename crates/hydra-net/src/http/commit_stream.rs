//! Living-database phase — `GET /commits/stream?after_sequence=N`.
//!
//! The endpoint that turns Hydra from a *queryable* living database
//! into a *reactive* one. Agents can tail the database via Server-Sent
//! Events instead of polling, and react to commits as they land.
//!
//! ## Event vocabulary
//!
//! ```text
//! event: commit
//! data: <CommitBatch JSON>
//!
//! event: heartbeat
//! data: {"head_sequence": <u64>}
//!
//! event: lag
//! data: {"requested_after_sequence": <u64>, "starting_at_sequence": <u64>}
//!
//! event: error
//! data: {"error": "<msg>", "hint": "<hint>"}
//! ```
//!
//! - `commit` — one per committed batch, in sequence order.
//! - `heartbeat` — emitted every 15s so clients know the connection
//!   is alive even during quiet windows.
//! - `lag` — emitted at most ONCE at the start of a connection if
//!   the caller's `after_sequence` is below what the in-memory
//!   ledger can replay. The stream still opens and continues from
//!   the earliest available sequence; the client decides whether to
//!   reconcile via `/replication/commits` paged catch-up.
//! - `error` — broadcast-lag (slow consumer) followed by connection
//!   close. The client should reconnect with `after_sequence=<last
//!   commit sequence it observed>`.
//!
//! ## Catch-up ordering
//!
//! Subtle and load-bearing. The handler subscribes to the broadcast
//! channel BEFORE reading the in-memory ledger, so any commit that
//! lands during replay is captured in the receiver buffer and
//! deduplicated by sequence number on the way out. Reversing this
//! order can drop commits in the gap between snapshot read and
//! subscribe.
//!
//! ## Backpressure
//!
//! The broadcast channel has a fixed capacity (256 batches). If a
//! subscriber lags past capacity, `recv()` returns
//! `RecvError::Lagged(n)`. The handler emits an `error` event
//! describing the lag and closes the connection — the client should
//! reconnect.
//!
//! ## Auth
//!
//! Mounted at `/commits/stream`. Matches `/commits` (paged) for
//! scope semantics: `read:audit`. Not tenant-filtered — the audit
//! view is cluster-wide and clients filter `event.tenant_id`
//! themselves if they need to.

use std::convert::Infallible;
use std::sync::Arc;
use std::time::Duration;

use axum::{
    extract::{Query, State},
    response::{
        sse::{Event as SseEvent, KeepAlive, Sse},
        IntoResponse,
    },
    routing::get,
    Router,
};
use hydra_core::CommitBatch;
use hydra_engine::commit_ledger::CommitObserver;
use serde::{Deserialize, Serialize};
use serde_json::json;
use tokio::sync::{broadcast, mpsc};
use tokio_stream::wrappers::ReceiverStream;

use crate::runtime::RuntimeHandle;

/// Capacity of the broadcast channel that fans every committed
/// batch out to live `/commits/stream` subscribers. Subscribers
/// that fall behind this many batches will receive
/// `RecvError::Lagged` and be disconnected with an `error` event;
/// they should reconnect with `after_sequence=<last seen>`.
pub const COMMIT_STREAM_CAPACITY: usize = 256;

/// Cadence at which `event: heartbeat` is emitted on every open
/// stream regardless of traffic. Lets clients distinguish an idle
/// engine from a dropped connection.
const HEARTBEAT_INTERVAL: Duration = Duration::from_secs(15);

/// Buffer size for the mpsc that the SSE handler uses to feed
/// `axum::response::Sse`. Large enough to absorb a catch-up replay
/// without backpressure dropping items, small enough to keep
/// memory bounded.
const SSE_CHANNEL_BUFFER: usize = 64;

/// Live fan-out for committed batches.
///
/// Implements `CommitObserver` so it can be attached to a `Hydra`
/// instance via `Hydra::set_commit_observer`. Every commit that
/// reaches the durable writer is then also published on this
/// broadcast channel for live subscribers.
///
/// `Arc`-shareable: the server holds one instance, attaches it to
/// the engine, AND keeps a clone for the HTTP router's state so
/// the stream handler can call `subscribe()` per connection.
#[derive(Clone)]
pub struct CommitBroadcaster {
    sender: broadcast::Sender<CommitBatch>,
}

impl CommitBroadcaster {
    /// Construct a broadcaster with the default capacity.
    pub fn new() -> Self {
        Self::with_capacity(COMMIT_STREAM_CAPACITY)
    }

    /// Construct with an explicit capacity. Production callers
    /// should use [`CommitBroadcaster::new`]; the explicit-capacity
    /// constructor exists for tests that exercise the lag path with
    /// small buffers.
    pub fn with_capacity(capacity: usize) -> Self {
        let (sender, _) = broadcast::channel(capacity);
        Self { sender }
    }

    /// Open a new live subscription. The receiver returns each
    /// future committed batch in sequence order; falling behind by
    /// the broadcaster's capacity yields `RecvError::Lagged`.
    pub fn subscribe(&self) -> broadcast::Receiver<CommitBatch> {
        self.sender.subscribe()
    }

    /// Current subscriber count. Useful for metrics and tests.
    pub fn subscriber_count(&self) -> usize {
        self.sender.receiver_count()
    }
}

impl Default for CommitBroadcaster {
    fn default() -> Self {
        Self::new()
    }
}

impl std::fmt::Debug for CommitBroadcaster {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("CommitBroadcaster")
            .field("subscribers", &self.sender.receiver_count())
            .field("capacity", &COMMIT_STREAM_CAPACITY)
            .finish()
    }
}

impl CommitObserver for CommitBroadcaster {
    fn observe_commit(&self, batch: &CommitBatch) {
        // `send` only errors when there are zero active receivers.
        // That is not a failure state; agents simply haven't tuned
        // in yet. Silently absorb the error per the
        // `CommitObserver` non-failability contract.
        let _ = self.sender.send(batch.clone());
    }
}

#[derive(Clone)]
pub struct CommitStreamHttpState {
    pub runtime: RuntimeHandle,
    pub broadcaster: Arc<CommitBroadcaster>,
}

impl CommitStreamHttpState {
    pub fn new(runtime: RuntimeHandle, broadcaster: Arc<CommitBroadcaster>) -> Self {
        Self { runtime, broadcaster }
    }
}

/// Build the commit-stream router. One route:
/// `GET /commits/stream?after_sequence=N` (auth scope `read:audit`).
pub fn commit_stream_router(
    runtime: RuntimeHandle,
    broadcaster: Arc<CommitBroadcaster>,
) -> Router {
    Router::new()
        .route("/commits/stream", get(handle_commit_stream))
        .with_state(CommitStreamHttpState::new(runtime, broadcaster))
}

#[derive(Debug, Clone, Deserialize, Default)]
pub struct CommitStreamQuery {
    /// Tail the stream from strictly after this sequence number.
    /// Default `0` — replay every committed batch the in-memory
    /// ledger still holds, then continue live.
    pub after_sequence: Option<u64>,
}

/// SSE handler for `GET /commits/stream`.
///
/// Subscribes to the broadcaster BEFORE snapshotting the in-memory
/// ledger so commits landing during replay are not dropped. Emits
/// catch-up batches (sequence > after_sequence) first, then drains
/// the broadcast receiver, deduplicating by sequence number. Emits
/// a heartbeat every `HEARTBEAT_INTERVAL`. Closes with an `error`
/// event on broadcast lag.
async fn handle_commit_stream(
    State(state): State<CommitStreamHttpState>,
    Query(query): Query<CommitStreamQuery>,
) -> impl IntoResponse {
    let after_sequence = query.after_sequence.unwrap_or(0);
    let broadcaster = state.broadcaster.clone();
    let runtime = state.runtime.clone();

    // Step 1 — subscribe BEFORE reading the ledger so anything that
    // lands during replay is buffered for dedup-and-emit.
    let mut live_rx = broadcaster.subscribe();

    // Snapshot the in-memory ledger. The lock is released as soon
    // as we collect; subsequent commits arrive via `live_rx`.
    let (replay_batches, current_head): (Vec<CommitBatch>, u64) = {
        let hydra = runtime.hydra();
        let hydra = hydra.read().await;
        let ledger_batches: Vec<CommitBatch> = hydra
            .commit_ledger()
            .batches_in_sequence()
            .into_iter()
            .filter(|batch| batch.sequence > after_sequence)
            .cloned()
            .collect();
        let head = hydra
            .latest_commit()
            .map(|record| record.sequence)
            .unwrap_or(0);
        (ledger_batches, head)
    };

    // Detect the lag-on-connect case. Two flavors:
    //
    //   1. Real gap — we have batches to replay but the earliest
    //      one is strictly ahead of `after_sequence + 1`. Means
    //      the in-memory ledger no longer holds the commits the
    //      caller asked for (compaction, or a fresh process that
    //      bootstrapped past them).
    //
    //   2. Caller ahead of engine — no replay available AND
    //      `after_sequence > current_head`. Operationally rare
    //      (cursor desync after a leader swap or restart), but
    //      worth surfacing so the client knows the next sequence
    //      it will see is not after_sequence + 1.
    //
    // In both cases the stream stays open; the client decides
    // whether to reconcile via `/replication/commits`.
    let lag_event: Option<SseEvent> = match replay_batches.first() {
        Some(first) if first.sequence > after_sequence + 1 => {
            Some(make_lag_event(after_sequence, first.sequence))
        }
        None if after_sequence > current_head && current_head > 0 => {
            Some(make_lag_event(after_sequence, current_head + 1))
        }
        _ => None,
    };

    // Bounded mpsc that feeds axum::Sse. The pipeline task writes
    // catch-up + live + heartbeat events here in order.
    let (tx, rx) = mpsc::channel::<Result<SseEvent, Infallible>>(SSE_CHANNEL_BUFFER);

    // Run the pump in a spawned task so axum can return the
    // response immediately and start flushing bytes to the client.
    tokio::spawn(async move {
        // Track the highest sequence we have emitted so far so we
        // can dedupe live broadcasts against replay.
        let mut last_sent_sequence: u64 = after_sequence;

        // Emit lag at most once, at the start.
        if let Some(event) = lag_event {
            if tx.send(Ok(event)).await.is_err() {
                return; // client disconnected
            }
        }

        // Catch-up replay.
        for batch in replay_batches {
            let seq = batch.sequence;
            if seq <= last_sent_sequence {
                continue; // already covered
            }
            let event = match make_commit_event(&batch) {
                Ok(event) => event,
                Err(error) => {
                    let _ = tx
                        .send(Ok(make_error_event(
                            &format!("commit serialization failed: {error}"),
                            None,
                        )))
                        .await;
                    return;
                }
            };
            if tx.send(Ok(event)).await.is_err() {
                return;
            }
            last_sent_sequence = seq;
        }

        // Live tail — interleave broadcast receives with periodic
        // heartbeats.
        let mut heartbeat_ticker = tokio::time::interval(HEARTBEAT_INTERVAL);
        // First tick fires immediately; skip it so the first
        // heartbeat lands HEARTBEAT_INTERVAL after replay completes
        // rather than overlapping with replay.
        heartbeat_ticker.tick().await;

        loop {
            tokio::select! {
                recv = live_rx.recv() => {
                    match recv {
                        Ok(batch) => {
                            if batch.sequence <= last_sent_sequence {
                                continue; // dedupe against replay
                            }
                            let seq = batch.sequence;
                            let event = match make_commit_event(&batch) {
                                Ok(event) => event,
                                Err(error) => {
                                    let _ = tx
                                        .send(Ok(make_error_event(
                                            &format!("commit serialization failed: {error}"),
                                            None,
                                        )))
                                        .await;
                                    return;
                                }
                            };
                            if tx.send(Ok(event)).await.is_err() {
                                return;
                            }
                            last_sent_sequence = seq;
                        }
                        Err(broadcast::error::RecvError::Lagged(skipped)) => {
                            let _ = tx
                                .send(Ok(make_error_event(
                                    &format!(
                                        "subscriber lagged: {skipped} commit(s) dropped from the broadcast buffer"
                                    ),
                                    Some(
                                        "reconnect with after_sequence equal to the last commit you observed",
                                    ),
                                )))
                                .await;
                            return;
                        }
                        Err(broadcast::error::RecvError::Closed) => {
                            // Broadcaster dropped — server is shutting down.
                            return;
                        }
                    }
                }
                _ = heartbeat_ticker.tick() => {
                    // Read the freshest head sequence so the
                    // heartbeat reflects the engine's actual
                    // position, not the last sequence we sent.
                    let head = {
                        let hydra = runtime.hydra();
                        let hydra = hydra.read().await;
                        hydra.latest_commit().map(|r| r.sequence).unwrap_or(0)
                    };
                    let event = make_heartbeat_event(head);
                    if tx.send(Ok(event)).await.is_err() {
                        return;
                    }
                }
            }
        }
    });

    let stream = ReceiverStream::new(rx);
    Sse::new(stream).keep_alive(KeepAlive::default())
}

fn make_commit_event(batch: &CommitBatch) -> Result<SseEvent, serde_json::Error> {
    let json = serde_json::to_string(batch)?;
    Ok(SseEvent::default().event("commit").data(json))
}

fn make_heartbeat_event(head_sequence: u64) -> SseEvent {
    let data = json!({ "head_sequence": head_sequence }).to_string();
    SseEvent::default().event("heartbeat").data(data)
}

fn make_lag_event(requested_after_sequence: u64, starting_at_sequence: u64) -> SseEvent {
    let data = json!({
        "requested_after_sequence": requested_after_sequence,
        "starting_at_sequence": starting_at_sequence,
    })
    .to_string();
    SseEvent::default().event("lag").data(data)
}

fn make_error_event(message: &str, hint: Option<&str>) -> SseEvent {
    let payload = match hint {
        Some(hint) => json!({ "error": message, "hint": hint }),
        None => json!({ "error": message }),
    };
    SseEvent::default().event("error").data(payload.to_string())
}

/// Tiny payload echoed by tests to verify SSE event-name semantics.
/// Keep public for `serde_json` round-trip tests in the integration
/// layer; not used at runtime.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct CommitStreamLagPayload {
    pub requested_after_sequence: u64,
    pub starting_at_sequence: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct CommitStreamHeartbeatPayload {
    pub head_sequence: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CommitStreamErrorPayload {
    pub error: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub hint: Option<String>,
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::runtime::RuntimeBuilder;
    use axum::body::Body;
    use axum::http::{Method, Request, StatusCode};
    use hydra_core::{EventKind, NodeId};
    use std::collections::HashMap;
    use std::time::Duration;
    use tower::ServiceExt;

    /// Helper — pump the SSE response body until we collect `expected`
    /// events or timeout. Returns the raw event tuples
    /// `(event_name, data_str)`.
    async fn collect_sse_events(
        response: axum::http::Response<Body>,
        expected: usize,
        timeout: Duration,
    ) -> Vec<(String, String)> {
        use tokio_stream::StreamExt;
        let mut events: Vec<(String, String)> = Vec::new();
        let mut current_event: Option<String> = None;
        let mut current_data: Vec<String> = Vec::new();
        let mut body = response.into_body().into_data_stream();
        let mut buffer = String::new();
        let deadline = tokio::time::Instant::now() + timeout;

        while events.len() < expected && tokio::time::Instant::now() < deadline {
            let remaining = deadline.saturating_duration_since(tokio::time::Instant::now());
            let chunk = match tokio::time::timeout(remaining, body.next()).await {
                Ok(Some(Ok(bytes))) => bytes,
                _ => break,
            };
            buffer.push_str(&String::from_utf8_lossy(&chunk));
            // Process every full line currently in the buffer.
            loop {
                let Some(newline_idx) = buffer.find('\n') else {
                    break;
                };
                let line: String = buffer.drain(..=newline_idx).collect();
                let line = line.trim_end_matches('\n').trim_end_matches('\r');
                if line.is_empty() {
                    if !current_data.is_empty() {
                        let event_name = current_event.take().unwrap_or_else(|| "message".to_string());
                        events.push((event_name, current_data.join("\n")));
                        current_data.clear();
                    } else {
                        current_event = None;
                    }
                } else if let Some(stripped) = line.strip_prefix("event:") {
                    current_event = Some(stripped.trim_start_matches(' ').to_string());
                } else if let Some(stripped) = line.strip_prefix("data:") {
                    current_data.push(stripped.trim_start_matches(' ').to_string());
                } // ignore comments + other field lines
            }
        }
        events
    }

    fn signal_event(name: &str) -> EventKind {
        EventKind::Signal {
            source: NodeId::from_str("test.commit_stream"),
            name: name.to_string(),
            payload: HashMap::new(),
        }
    }

    #[tokio::test]
    async fn broadcaster_implements_observer_and_fans_out() {
        let broadcaster = Arc::new(CommitBroadcaster::new());
        let mut rx = broadcaster.subscribe();

        // Fake a CommitBatch and call observe_commit directly.
        let batch = hydra_core::CommitBatch::new(vec![hydra_core::Event::trigger(signal_event("x"))])
            .with_sequence(1)
            .mark_committed(None);
        broadcaster.observe_commit(&batch);

        let received = rx.recv().await.unwrap();
        assert_eq!(received.sequence, 1);
    }

    #[tokio::test]
    async fn observe_commit_with_no_subscribers_does_not_panic() {
        // Per the CommitObserver contract: an observer must never
        // propagate failure to the engine. A broadcast with zero
        // receivers returns Err — we must swallow it.
        let broadcaster = CommitBroadcaster::new();
        let batch = hydra_core::CommitBatch::new(vec![hydra_core::Event::trigger(signal_event("x"))])
            .with_sequence(1)
            .mark_committed(None);
        broadcaster.observe_commit(&batch); // must not panic
        assert_eq!(broadcaster.subscriber_count(), 0);
    }

    #[tokio::test]
    async fn stream_emits_commit_event_per_ingest() {
        let (runtime, _processor) = RuntimeBuilder::new().build();
        let broadcaster = Arc::new(CommitBroadcaster::new());

        // Attach the broadcaster as the engine's commit observer
        // so ingest fires `observe_commit`.
        {
            let hydra = runtime.hydra();
            let mut hydra = hydra.write().await;
            hydra.set_commit_observer(broadcaster.clone() as Arc<dyn CommitObserver>);
        }

        let app = commit_stream_router(runtime.clone(), broadcaster.clone());

        // Drive an ingest BEFORE the request so we have a commit to
        // catch up on. Then more after to exercise the live path.
        {
            let hydra = runtime.hydra();
            let mut hydra = hydra.write().await;
            hydra.ingest(signal_event("first")).unwrap();
        }

        // Start the SSE request.
        let response = app
            .oneshot(
                Request::builder()
                    .method(Method::GET)
                    .uri("/commits/stream?after_sequence=0")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);

        // The catch-up will deliver the first commit synchronously.
        // The body stream stays open; collect with a tight timeout.
        let events = collect_sse_events(response, 1, Duration::from_millis(500)).await;
        assert_eq!(events.len(), 1);
        assert_eq!(events[0].0, "commit");
        // Body parses as JSON and carries sequence=1.
        let body: serde_json::Value = serde_json::from_str(&events[0].1).unwrap();
        assert_eq!(body["sequence"], serde_json::json!(1));
    }

    #[tokio::test]
    async fn stream_emits_lag_when_gap_too_large() {
        // Build a runtime, ingest 3 commits, then request
        // after_sequence=10 — which is beyond the head. The handler
        // should emit a lag event explaining the gap rather than
        // silently dropping us at head.
        let (runtime, _processor) = RuntimeBuilder::new().build();
        let broadcaster = Arc::new(CommitBroadcaster::new());
        {
            let hydra = runtime.hydra();
            let mut hydra = hydra.write().await;
            hydra.set_commit_observer(broadcaster.clone() as Arc<dyn CommitObserver>);
            for i in 0..3 {
                hydra.ingest(signal_event(&format!("e{i}"))).unwrap();
            }
        }
        let app = commit_stream_router(runtime.clone(), broadcaster);

        let response = app
            .oneshot(
                Request::builder()
                    .method(Method::GET)
                    .uri("/commits/stream?after_sequence=10")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();

        let events = collect_sse_events(response, 1, Duration::from_millis(500)).await;
        assert!(!events.is_empty());
        let (name, data) = &events[0];
        assert_eq!(name, "lag");
        let payload: CommitStreamLagPayload = serde_json::from_str(data).unwrap();
        assert_eq!(payload.requested_after_sequence, 10);
        // Engine head was 3; stream restarts at head+1.
        assert_eq!(payload.starting_at_sequence, 4);
    }

    #[tokio::test]
    async fn stream_replays_after_sequence_strictly_greater() {
        // Catch-up should ONLY include batches with sequence
        // strictly greater than after_sequence — never reissue the
        // batch the caller already saw.
        let (runtime, _processor) = RuntimeBuilder::new().build();
        let broadcaster = Arc::new(CommitBroadcaster::new());
        {
            let hydra = runtime.hydra();
            let mut hydra = hydra.write().await;
            hydra.set_commit_observer(broadcaster.clone() as Arc<dyn CommitObserver>);
            for i in 0..3 {
                hydra.ingest(signal_event(&format!("e{i}"))).unwrap();
            }
        }
        let app = commit_stream_router(runtime.clone(), broadcaster);

        let response = app
            .oneshot(
                Request::builder()
                    .method(Method::GET)
                    .uri("/commits/stream?after_sequence=1")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();

        // Expect commit events for sequences 2 and 3 — nothing for 1.
        let events = collect_sse_events(response, 2, Duration::from_millis(500)).await;
        assert_eq!(events.len(), 2);
        assert_eq!(events[0].0, "commit");
        let body_a: serde_json::Value = serde_json::from_str(&events[0].1).unwrap();
        let body_b: serde_json::Value = serde_json::from_str(&events[1].1).unwrap();
        assert_eq!(body_a["sequence"], serde_json::json!(2));
        assert_eq!(body_b["sequence"], serde_json::json!(3));
    }

    #[tokio::test]
    async fn stream_default_after_sequence_replays_everything() {
        // No `?after_sequence=` query param defaults to 0 → every
        // committed batch the in-memory ledger holds is replayed.
        let (runtime, _processor) = RuntimeBuilder::new().build();
        let broadcaster = Arc::new(CommitBroadcaster::new());
        {
            let hydra = runtime.hydra();
            let mut hydra = hydra.write().await;
            hydra.set_commit_observer(broadcaster.clone() as Arc<dyn CommitObserver>);
            for i in 0..2 {
                hydra.ingest(signal_event(&format!("seed-{i}"))).unwrap();
            }
        }
        let app = commit_stream_router(runtime.clone(), broadcaster);

        let response = app
            .oneshot(
                Request::builder()
                    .method(Method::GET)
                    .uri("/commits/stream")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();

        let events = collect_sse_events(response, 2, Duration::from_millis(500)).await;
        assert_eq!(events.len(), 2);
        assert_eq!(events[0].0, "commit");
        assert_eq!(events[1].0, "commit");
    }
}
