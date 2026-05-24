use hydra_core::{ActorId, EventKind, NodeId};
use hydra_engine::snapshot_store::SnapshotBackend;
use hydra_sdk::HydraRuntime;
use hydra_storage::snapshot::FileSnapshotStore;
use std::collections::HashMap;
use std::path::PathBuf;
use std::process::Command;

fn actor() -> ActorId {
    ActorId::from_str("actor_hydra_cli_snapshot_test")
}

fn signal(name: &str) -> EventKind {
    EventKind::Signal {
        source: NodeId::from_str("cli.snapshot"),
        name: name.to_string(),
        payload: HashMap::new(),
    }
}

fn temp_root(name: &str) -> PathBuf {
    std::env::temp_dir().join(format!(
        "hydra_cli_snapshot_{name}_{}_{}",
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
fn snapshot_command_creates_snapshot_on_disk() {
    let root = temp_root("creates");

    // Pre-populate with one ingested event.
    {
        let (mut hydra, _) = HydraRuntime::open_persistent(&root, actor()).unwrap();
        hydra.ingest(signal("before")).unwrap();
    }

    // Run the CLI snapshot command.
    let output = Command::new(cli_bin())
        .arg("snapshot")
        .arg(&root)
        .arg("--actor")
        .arg("actor_hydra_cli_snapshot_test")
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "stderr: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(stdout.contains("snapshot: id=snap_"), "stdout: {stdout}");
    assert!(stdout.contains("sequence=1"), "stdout: {stdout}");
    assert!(stdout.contains("events=1"), "stdout: {stdout}");
    assert!(stdout.contains("commits=1"), "stdout: {stdout}");

    // Verify the snapshot actually landed on disk by reopening the
    // backend independently.
    let snapshot_store = FileSnapshotStore::open(&root).unwrap();
    let manifests = snapshot_store.list_snapshot_manifests().unwrap();
    assert_eq!(manifests.len(), 1);
    assert_eq!(manifests[0].sequence, 1);

    let _ = std::fs::remove_dir_all(&root);
}

#[test]
fn snapshot_command_requires_actor_flag() {
    let root = temp_root("requires_actor");
    let output = Command::new(cli_bin())
        .arg("snapshot")
        .arg(&root)
        .output()
        .unwrap();
    assert!(!output.status.success(), "expected non-zero exit");
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains("--actor"),
        "stderr should mention --actor: {stderr}"
    );
    let _ = std::fs::remove_dir_all(&root);
}
