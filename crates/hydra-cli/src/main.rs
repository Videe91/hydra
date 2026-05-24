//! # hydra-cli
//!
//! Operator CLI for Hydra. This first version exposes a single command:
//!
//! ```text
//! hydra-cli compact <root>
//! ```
//!
//! which wraps
//! [`HydraRuntime::compact_commit_log_through_latest_snapshot`].
//!
//! Future commands (`inspect`, `snapshot`, `verify`, ...) land in their
//! own patches.

use clap::{Parser, Subcommand};
use hydra_sdk::HydraRuntime;
use std::path::PathBuf;

#[derive(Debug, Parser)]
#[command(name = "hydra-cli")]
#[command(about = "Hydra database operator CLI")]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Debug, Subcommand)]
enum Command {
    /// Compact the commit log through the latest snapshot.
    ///
    /// Drops every commit batch whose sequence is `<= latest snapshot
    /// sequence`. Recovery still works because the snapshot body covers
    /// state up to that sequence and the retained tail covers everything
    /// after.
    Compact {
        /// Hydra data root directory.
        root: PathBuf,
    },
    /// Inspect persistent Hydra state without mutating it.
    ///
    /// Prints commit count, snapshot count, latest snapshot sequence
    /// (if any), and the recovery path a subsequent `open_persistent`
    /// would take. Safe to run on a live root.
    Inspect {
        /// Hydra data root directory.
        root: PathBuf,
    },
    /// Take a durable snapshot of a persistent Hydra root.
    ///
    /// Opens the root, calls `Hydra::snapshot(actor)` (which writes the
    /// body through to disk before committing `SnapshotTaken`), and
    /// prints the resulting manifest's id + sequence + counts.
    Snapshot {
        /// Hydra data root directory.
        root: PathBuf,
        /// Actor ID to attribute the snapshot to. Required — snapshots
        /// must be auditable.
        #[arg(long)]
        actor: String,
    },
}

fn main() {
    if let Err(error) = run() {
        eprintln!("error: {error}");
        std::process::exit(1);
    }
}

fn run() -> hydra_core::error::Result<()> {
    let cli = Cli::parse();
    match cli.command {
        Command::Compact { root } => compact(root),
        Command::Inspect { root } => inspect(root),
        Command::Snapshot { root, actor } => snapshot(root, actor),
    }
}

fn compact(root: PathBuf) -> hydra_core::error::Result<()> {
    match HydraRuntime::compact_commit_log_through_latest_snapshot(&root)? {
        Some(report) => {
            println!(
                "compacted: cutoff={} removed={} retained={}",
                report.cutoff_sequence, report.removed_count, report.retained_count
            );
        }
        None => {
            println!("no snapshots - nothing to compact");
        }
    }
    Ok(())
}

fn inspect(root: PathBuf) -> hydra_core::error::Result<()> {
    let report = HydraRuntime::inspect_persistent_state(&root)?;
    println!("commits: {}", report.commit_count);
    println!("snapshots: {}", report.snapshot_count);
    match report.latest_snapshot_sequence {
        Some(sequence) => println!("latest_snapshot_sequence: {sequence}"),
        None => println!("latest_snapshot_sequence: none"),
    }
    println!("recommended_recovery: {:?}", report.recommended_recovery);
    Ok(())
}

fn snapshot(root: PathBuf, actor: String) -> hydra_core::error::Result<()> {
    let actor = hydra_core::ActorId::from_str(&actor);
    let manifest = HydraRuntime::snapshot_persistent_root(&root, actor)?;
    println!(
        "snapshot: id={} sequence={} events={} commits={}",
        manifest.id, manifest.sequence, manifest.total_events, manifest.total_commits
    );
    Ok(())
}
