use hydra_core::{ActorId, EventKind, NodeId};
use hydra_sdk::HydraRuntime;
use std::collections::HashMap;
use std::path::PathBuf;
use std::process::Command;

fn actor() -> ActorId {
    ActorId::from_str("actor_hydra_cli_inspect_test")
}

fn signal(name: &str) -> EventKind {
    EventKind::Signal {
        source: NodeId::from_str("cli.inspect"),
        name: name.to_string(),
        payload: HashMap::new(),
    }
}

fn temp_root(name: &str) -> PathBuf {
    std::env::temp_dir().join(format!(
        "hydra_cli_inspect_{name}_{}_{}",
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
fn inspect_reports_empty_root() {
    let root = temp_root("empty");
    let output = Command::new(cli_bin())
        .arg("inspect")
        .arg(&root)
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "stderr: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(stdout.contains("commits: 0"), "stdout: {stdout}");
    assert!(stdout.contains("snapshots: 0"), "stdout: {stdout}");
    assert!(
        stdout.contains("latest_snapshot_sequence: none"),
        "stdout: {stdout}"
    );
    assert!(
        stdout.contains("recommended_recovery: Empty"),
        "stdout: {stdout}"
    );
    let _ = std::fs::remove_dir_all(&root);
}

#[test]
fn inspect_reports_snapshot_recovery_path() {
    let root = temp_root("snapshot");
    {
        let (mut hydra, _) = HydraRuntime::open_persistent(&root, actor()).unwrap();
        hydra.ingest(signal("before")).unwrap();
        hydra.snapshot(actor()).unwrap();
        hydra.ingest(signal("after")).unwrap();
    }

    let output = Command::new(cli_bin())
        .arg("inspect")
        .arg(&root)
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "stderr: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    let stdout = String::from_utf8_lossy(&output.stdout);
    // 1 "before" + SnapshotTaken + 1 "after" = 3 commits durable on disk.
    assert!(stdout.contains("commits: 3"), "stdout: {stdout}");
    assert!(stdout.contains("snapshots: 1"), "stdout: {stdout}");
    assert!(
        stdout.contains("latest_snapshot_sequence: 1"),
        "stdout: {stdout}"
    );
    assert!(
        stdout.contains("recommended_recovery: SnapshotAndReplay"),
        "stdout: {stdout}"
    );
    let _ = std::fs::remove_dir_all(&root);
}
