use hydra_core::{ActorId, EventKind, NodeId};
use hydra_sdk::HydraRuntime;
use std::collections::HashMap;
use std::path::PathBuf;
use std::process::Command;

fn actor() -> ActorId {
    ActorId::from_str("actor_hydra_cli_recoverability_test")
}

fn signal(name: &str) -> EventKind {
    EventKind::Signal {
        source: NodeId::from_str("cli.recoverability"),
        name: name.to_string(),
        payload: HashMap::new(),
    }
}

fn temp_root(name: &str) -> PathBuf {
    std::env::temp_dir().join(format!(
        "hydra_cli_recoverability_{name}_{}_{}",
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
fn verify_recoverability_reports_compacted_root_valid() {
    let root = temp_root("compacted");
    // Pre-populate: ingest, snapshot, ingest more.
    {
        let (mut hydra, _) = HydraRuntime::open_persistent(&root, actor()).unwrap();
        hydra.ingest(signal("before")).unwrap();
        hydra.snapshot(actor()).unwrap();
        hydra.ingest(signal("after_one")).unwrap();
        hydra.ingest(signal("after_two")).unwrap();
    }
    // Compact through the snapshot so the commit log starts at sequence N+1.
    HydraRuntime::compact_commit_log_through_latest_snapshot(&root)
        .unwrap()
        .unwrap();

    let output = Command::new(cli_bin())
        .arg("verify-recoverability")
        .arg(&root)
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "stderr: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(stdout.contains("valid: true"), "stdout: {stdout}");
    assert!(
        stdout.contains("snapshot_id: snap_"),
        "stdout: {stdout}"
    );
    assert!(
        stdout.contains("snapshot_sequence: 1"),
        "stdout: {stdout}"
    );
    // Tail: SnapshotTaken + after_one + after_two = 3.
    assert!(stdout.contains("tail_commits: 3"), "stdout: {stdout}");

    let _ = std::fs::remove_dir_all(&root);
}

#[test]
fn verify_recoverability_falls_back_without_snapshot() {
    let root = temp_root("no_snapshot");
    {
        let (mut hydra, _) = HydraRuntime::open_persistent(&root, actor()).unwrap();
        hydra.ingest(signal("one")).unwrap();
    }

    let output = Command::new(cli_bin())
        .arg("verify-recoverability")
        .arg(&root)
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "stderr: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(stdout.contains("valid: true"), "stdout: {stdout}");
    assert!(stdout.contains("snapshot_id: none"), "stdout: {stdout}");
    assert!(
        stdout.contains("snapshot_sequence: none"),
        "stdout: {stdout}"
    );
    assert!(stdout.contains("tail_commits: 0"), "stdout: {stdout}");
    // Fallback marker should be present in message: line.
    assert!(
        stdout.contains("no snapshots"),
        "expected fallback marker: {stdout}"
    );

    let _ = std::fs::remove_dir_all(&root);
}
