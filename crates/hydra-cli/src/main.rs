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
