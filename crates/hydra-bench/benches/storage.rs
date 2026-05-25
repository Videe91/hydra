//! Storage baseline benchmarks (CommitLog hot paths).
//!
//! - **commit_log_append** — append N batches to a fresh on-disk log.
//!   Captures per-batch write + flush cost.
//! - **commit_log_load_all** — parse N batches off disk. The recovery
//!   read path uses the same call.
//! - **commit_log_compact** — `compact_through(cutoff)` rewrites the
//!   log dropping batches <= cutoff. Measures the cost of the atomic
//!   tempfile+rename rewrite at compaction sizes operators care about.
//!
//! Each benchmark uses `std::env::temp_dir() + (pid, nanos)` for
//! workdirs (matches the project's existing test convention; no
//! `tempfile` dep). Workdirs are cleaned up at the end of each
//! benchmark group.

use criterion::{
    criterion_group, criterion_main, BatchSize, BenchmarkId, Criterion, Throughput,
};
use hydra_core::{CommitBatch, EventKind, NodeId};
use hydra_engine::hydra::Hydra;
use hydra_storage::commit_log::CommitLog;
use std::collections::HashMap;
use std::path::PathBuf;
use std::sync::atomic::{AtomicU64, Ordering};

fn signal(index: usize) -> EventKind {
    EventKind::Signal {
        source: NodeId::from_str("bench.storage"),
        name: format!("signal_{index}"),
        payload: HashMap::new(),
    }
}

fn committed_batches(count: usize) -> Vec<CommitBatch> {
    let mut hydra = Hydra::new();
    for i in 0..count {
        hydra.ingest(signal(i)).unwrap();
    }
    hydra
        .commit_ledger()
        .batches_in_sequence()
        .into_iter()
        .cloned()
        .collect()
}

/// Returns a unique workdir under the system temp dir. Each call
/// returns a fresh path so concurrent bench iterations don't collide.
fn fresh_workdir(label: &str) -> PathBuf {
    static COUNTER: AtomicU64 = AtomicU64::new(0);
    let n = COUNTER.fetch_add(1, Ordering::Relaxed);
    let dir = std::env::temp_dir().join(format!(
        "hydra_bench_storage_{label}_{}_{}_{n}",
        std::process::id(),
        chrono::Utc::now().timestamp_nanos_opt().unwrap_or_default()
    ));
    std::fs::create_dir_all(&dir).unwrap();
    dir
}

fn bench_commit_log_append(c: &mut Criterion) {
    let mut group = c.benchmark_group("commit_log_append");
    // 100 / 1_000 — 10_000 would dominate by file-IO and not give
    // useful per-append numbers above what 1k already shows.
    for size in [100usize, 1_000] {
        let batches = committed_batches(size);
        group.throughput(Throughput::Elements(size as u64));
        group.bench_with_input(BenchmarkId::from_parameter(size), &batches, |b, batches| {
            b.iter_batched(
                || {
                    let dir = fresh_workdir("append");
                    let log = CommitLog::open(dir.join("commits.jsonl")).unwrap();
                    (dir, log, batches.clone())
                },
                |(dir, log, batches)| {
                    for batch in &batches {
                        log.append(batch).unwrap();
                    }
                    // Clean up inside the bench so we don't leak temp
                    // dirs; the cost shows up uniformly across
                    // iterations.
                    let _ = std::fs::remove_dir_all(&dir);
                },
                BatchSize::LargeInput,
            );
        });
    }
    group.finish();
}

fn bench_commit_log_load_all(c: &mut Criterion) {
    let mut group = c.benchmark_group("commit_log_load_all");
    for size in [1_000usize, 10_000] {
        // Build a real on-disk log once per size; reuse across
        // iterations because load_all doesn't mutate it.
        let dir = fresh_workdir("load_all");
        let log = CommitLog::open(dir.join("commits.jsonl")).unwrap();
        for batch in committed_batches(size) {
            log.append(&batch).unwrap();
        }
        group.throughput(Throughput::Elements(size as u64));
        group.bench_with_input(BenchmarkId::from_parameter(size), &log, |b, log| {
            b.iter(|| {
                let v = log.load_all().unwrap();
                v.len()
            });
        });
        let _ = std::fs::remove_dir_all(&dir);
    }
    group.finish();
}

fn bench_commit_log_compact(c: &mut Criterion) {
    let mut group = c.benchmark_group("commit_log_compact");
    for size in [1_000usize, 10_000] {
        let batches = committed_batches(size);
        // Cutoff = half the sequences — the realistic post-snapshot
        // compaction shape (drop everything up to the snapshot
        // sequence, retain the tail).
        let cutoff = (size / 2) as u64;
        group.bench_with_input(BenchmarkId::from_parameter(size), &size, |b, _| {
            b.iter_batched(
                || {
                    let dir = fresh_workdir("compact");
                    let log = CommitLog::open(dir.join("commits.jsonl")).unwrap();
                    for batch in &batches {
                        log.append(batch).unwrap();
                    }
                    (dir, log)
                },
                |(dir, log)| {
                    log.compact_through(cutoff).unwrap();
                    let _ = std::fs::remove_dir_all(&dir);
                },
                BatchSize::LargeInput,
            );
        });
    }
    group.finish();
}

criterion_group!(
    benches,
    bench_commit_log_append,
    bench_commit_log_load_all,
    bench_commit_log_compact,
);
criterion_main!(benches);
