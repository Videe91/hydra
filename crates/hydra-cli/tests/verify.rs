use hydra_core::{ActorId, EventKind, NodeId};
use hydra_sdk::HydraRuntime;
use std::collections::HashMap;
use std::path::PathBuf;
use std::process::Command;

fn actor() -> ActorId {
    ActorId::from_str("actor_hydra_cli_verify_test")
}

fn signal(name: &str) -> EventKind {
    EventKind::Signal {
        source: NodeId::from_str("cli.verify"),
        name: name.to_string(),
        payload: HashMap::new(),
    }
}

fn temp_root(name: &str) -> PathBuf {
    std::env::temp_dir().join(format!(
        "hydra_cli_verify_{name}_{}_{}",
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
fn verify_reports_empty_root_valid() {
    let root = temp_root("empty");
    let output = Command::new(cli_bin())
        .arg("verify")
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
    assert!(stdout.contains("commits: 0"), "stdout: {stdout}");
    let _ = std::fs::remove_dir_all(&root);
}

#[test]
fn verify_reports_valid_persistent_root() {
    let root = temp_root("valid");
    {
        let (mut hydra, _) = HydraRuntime::open_persistent(&root, actor()).unwrap();
        hydra.ingest(signal("one")).unwrap();
        hydra.ingest(signal("two")).unwrap();
    }

    let output = Command::new(cli_bin())
        .arg("verify")
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
    assert!(stdout.contains("commits: 2"), "stdout: {stdout}");
    let _ = std::fs::remove_dir_all(&root);
}
