use hydra_core::{ActorId, EventKind, NodeId};
use hydra_sdk::HydraRuntime;
use std::collections::HashMap;
use std::path::PathBuf;
use std::process::Command;

fn actor() -> ActorId {
    ActorId::from_str("actor_hydra_cli_test")
}

fn signal(name: &str) -> EventKind {
    EventKind::Signal {
        source: NodeId::from_str("cli.compact"),
        name: name.to_string(),
        payload: HashMap::new(),
    }
}

fn temp_root(name: &str) -> PathBuf {
    std::env::temp_dir().join(format!(
        "hydra_cli_{name}_{}_{}",
        std::process::id(),
        chrono::Utc::now()
            .timestamp_nanos_opt()
            .unwrap_or_default()
    ))
}

fn cli_bin() -> PathBuf {
    PathBuf::from(env!("CARGO_BIN_EXE_hydra-cli"))
}

#[test]
fn compact_reports_no_snapshots() {
    let root = temp_root("no_snapshots");

    // Materialize the root + empty log/snapshots dir so the helper has
    // something to open. Without this, FileSnapshotStore::open + CommitLog::open
    // create the dirs on first call, but we want to exercise the helper
    // against a "real but empty" persistent root.
    {
        let (_, _) = HydraRuntime::open_persistent(&root, actor()).unwrap();
    }

    let output = Command::new(cli_bin())
        .arg("compact")
        .arg(&root)
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "stderr: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(
        stdout.contains("no snapshots - nothing to compact"),
        "unexpected stdout: {stdout}"
    );

    let _ = std::fs::remove_dir_all(&root);
}

#[test]
fn compact_compacts_persistent_root() {
    let root = temp_root("compacts");

    // Phase 1: ingest "before", snapshot, ingest "after_one" / "after_two".
    {
        let (mut hydra, _) = HydraRuntime::open_persistent(&root, actor()).unwrap();
        hydra.ingest(signal("before")).unwrap();
        hydra.snapshot(actor()).unwrap();
        hydra.ingest(signal("after_one")).unwrap();
        hydra.ingest(signal("after_two")).unwrap();
    }

    // Phase 2: run `hydra-cli compact <root>` as a subprocess.
    let output = Command::new(cli_bin())
        .arg("compact")
        .arg(&root)
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "stderr: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(stdout.contains("compacted:"), "unexpected stdout: {stdout}");
    assert!(stdout.contains("removed=1"), "unexpected stdout: {stdout}");
    assert!(stdout.contains("retained=3"), "unexpected stdout: {stdout}");

    // Phase 3: reopen and confirm recovery still works from the compacted
    // log + snapshot. Proves the CLI compaction is safe by construction.
    {
        let (hydra, report) = HydraRuntime::open_persistent(&root, actor()).unwrap();
        assert_eq!(
            report.mode,
            hydra_storage::recovery::RecoveryMode::SnapshotAndReplay
        );
        assert_eq!(report.replayed_commit_count, 3);
        let signal_count = hydra
            .events()
            .into_iter()
            .filter(|event| event.kind.kind_name() == "signal")
            .count();
        assert_eq!(signal_count, 3);
    }

    let _ = std::fs::remove_dir_all(&root);
}
