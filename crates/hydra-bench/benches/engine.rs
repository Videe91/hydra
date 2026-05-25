//! Engine baseline benchmarks.
//!
//! Covers the four hottest pure-engine paths:
//!
//! - **ingest_signal** — Hydra::ingest of N independent Signal
//!   events. Measures the cascade + commit + epistemic dispatch
//!   overhead per event.
//! - **query_lists** — Hydra::events() / all_nodes() snapshots
//!   over a preloaded engine. Direct engine calls (sync) — no
//!   QueryService async overhead in this baseline.
//! - **snapshot** — Hydra::snapshot(actor) at various sizes. Captures
//!   the cost of materializing snapshot bodies from the projection +
//!   stores.
//! - **recover_from_commits** — fresh Hydra rebuilt from N committed
//!   batches. Pure ledger replay.
//!
//! Sizes are 100 / 1_000 / 10_000 except where the heavier ones
//! would dominate the bench wall-clock — see comments per group.

use criterion::{
    criterion_group, criterion_main, BatchSize, BenchmarkId, Criterion, Throughput,
};
use hydra_core::{
    ActorId, CommitBatch, EventKind, NodeId,
};
use hydra_engine::hydra::Hydra;
use std::collections::HashMap;

fn signal(index: usize) -> EventKind {
    EventKind::Signal {
        source: NodeId::from_str("bench.signal"),
        name: format!("signal_{index}"),
        payload: HashMap::new(),
    }
}

fn node_created(type_id: &str) -> EventKind {
    EventKind::NodeCreated {
        node_id: NodeId::new(),
        type_id: type_id.to_string(),
        properties: HashMap::new(),
    }
}

fn hydra_with_signals(count: usize) -> Hydra {
    let mut hydra = Hydra::new();
    for i in 0..count {
        hydra.ingest(signal(i)).unwrap();
    }
    hydra
}

fn hydra_with_nodes(count: usize) -> Hydra {
    let mut hydra = Hydra::new();
    for i in 0..count {
        hydra
            .ingest(node_created(if i % 2 == 0 { "ec2" } else { "vpc" }))
            .unwrap();
    }
    hydra
}

fn committed_batches(count: usize) -> Vec<CommitBatch> {
    let hydra = hydra_with_signals(count);
    hydra
        .commit_ledger()
        .batches_in_sequence()
        .into_iter()
        .cloned()
        .collect()
}

fn bench_ingest_signal(c: &mut Criterion) {
    let mut group = c.benchmark_group("ingest_signal");
    for size in [100usize, 1_000, 10_000] {
        group.throughput(Throughput::Elements(size as u64));
        group.bench_with_input(BenchmarkId::from_parameter(size), &size, |b, &size| {
            b.iter_batched(
                Hydra::new,
                |mut hydra| {
                    for i in 0..size {
                        hydra.ingest(signal(i)).unwrap();
                    }
                },
                BatchSize::SmallInput,
            );
        });
    }
    group.finish();
}

fn bench_query_events_list(c: &mut Criterion) {
    let mut group = c.benchmark_group("query_events_list");
    for size in [1_000usize, 10_000] {
        let hydra = hydra_with_signals(size);
        group.throughput(Throughput::Elements(size as u64));
        group.bench_with_input(BenchmarkId::from_parameter(size), &hydra, |b, hydra| {
            b.iter(|| {
                // `events()` returns Vec<&Event> — the alloc + ref
                // collect is the work we're measuring.
                let v = hydra.events();
                v.len()
            });
        });
    }
    group.finish();
}

fn bench_query_nodes_list(c: &mut Criterion) {
    let mut group = c.benchmark_group("query_nodes_list");
    for size in [1_000usize, 10_000] {
        let hydra = hydra_with_nodes(size);
        group.throughput(Throughput::Elements(size as u64));
        group.bench_with_input(BenchmarkId::from_parameter(size), &hydra, |b, hydra| {
            b.iter(|| {
                let v = hydra.all_nodes();
                v.len()
            });
        });
    }
    group.finish();
}

fn bench_snapshot(c: &mut Criterion) {
    let mut group = c.benchmark_group("snapshot");
    // Drop 10_000 here — snapshot materializes every store in the
    // engine and the cost of preloading 10k nodes per measurement
    // dwarfs the actual snapshot work. 1k gives a clean baseline;
    // larger numbers belong in a dedicated heavy-bench patch.
    for size in [100usize, 1_000] {
        group.bench_with_input(BenchmarkId::from_parameter(size), &size, |b, &size| {
            b.iter_batched(
                || hydra_with_nodes(size),
                |mut hydra| {
                    hydra
                        .snapshot(ActorId::from_str("actor_bench"))
                        .unwrap();
                },
                BatchSize::LargeInput,
            );
        });
    }
    group.finish();
}

fn bench_recover_from_commits(c: &mut Criterion) {
    let mut group = c.benchmark_group("recover_from_commits");
    for size in [1_000usize, 10_000] {
        let batches = committed_batches(size);
        group.throughput(Throughput::Elements(size as u64));
        group.bench_with_input(BenchmarkId::from_parameter(size), &batches, |b, batches| {
            b.iter_batched(
                || batches.clone(),
                |batches| {
                    let mut hydra = Hydra::new();
                    hydra.recover_from_commits(batches).unwrap();
                },
                BatchSize::LargeInput,
            );
        });
    }
    group.finish();
}

criterion_group!(
    benches,
    bench_ingest_signal,
    bench_query_events_list,
    bench_query_nodes_list,
    bench_snapshot,
    bench_recover_from_commits,
);
criterion_main!(benches);
