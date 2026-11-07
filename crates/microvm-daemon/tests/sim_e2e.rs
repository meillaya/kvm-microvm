//! Daemon end-to-end test over the simulation backend.
//!
//! Starts the real REST and gRPC servers through `microvm_daemon::start`,
//! drives the CLI client, and checks that shutdown removes both sockets.

use microvm_cli::{Cli, Command};
use microvm_daemon::config::DaemonConfig;
use microvm_daemon::start;
use std::path::{Path, PathBuf};

fn cli(socket: PathBuf, command: Command) -> Cli {
    Cli {
        socket,
        json: false,
        command,
    }
}

async fn run(socket: &Path, command: Command) -> String {
    let (code, output) = microvm_cli::execute(&cli(socket.to_path_buf(), command)).await;
    assert_eq!(
        code,
        microvm_cli::ExitCode::Success,
        "command failed: {output}"
    );
    output
}

fn token(output: &str) -> String {
    output
        .split_whitespace()
        .last()
        .expect("command output has a token")
        .to_string()
}

#[tokio::test]
async fn daemon_sim_lifecycle() {
    let tmp = tempfile::tempdir().unwrap();
    let rest = tmp.path().join("rest.sock");
    let grpc = tmp.path().join("grpc.sock");
    let config_path = tmp.path().join("microvmd.toml");
    let uid = unsafe { libc::getuid() };
    let gid = unsafe { libc::getgid() };
    let toml = format!(
        r#"
backend = "sim"
[server]
rest_socket = "{rest}"
grpc_socket = "{grpc}"
socket_mode = "0600"
socket_uid = {uid}
socket_gid = {gid}
allowed_uids = [{uid}]
tenant = "local"
role = "owner"
[paths]
state_dir = "{state}"
artifact_dir = "{artifacts}"
snapshot_dir = "{snapshots}"
socket_dir = "{sockets}"
chroot_dir = "{chroot}"
log_dir = "{logs}"
[runtime]
firecracker = "/bin/false"
use_jailer = false
"#,
        rest = rest.display(),
        grpc = grpc.display(),
        state = tmp.path().join("state").display(),
        artifacts = tmp.path().join("artifacts").display(),
        snapshots = tmp.path().join("snapshots").display(),
        sockets = tmp.path().join("sockets").display(),
        chroot = tmp.path().join("chroot").display(),
        logs = tmp.path().join("logs").display(),
    );
    std::fs::write(&config_path, toml).unwrap();
    let config = DaemonConfig::load(&config_path).unwrap();
    let handle = start(config).await.unwrap();

    let create = run(
        &rest,
        Command::Create {
            vcpu: 1,
            memory_mib: 128,
            disk_mib: 128,
            network_policy: "none".to_string(),
        },
    )
    .await;
    let vm_id = token(&create);
    run(
        &rest,
        Command::Status {
            vm_id: vm_id.clone(),
        },
    )
    .await;
    run(
        &rest,
        Command::Start {
            vm_id: vm_id.clone(),
        },
    )
    .await;
    let status = run(
        &rest,
        Command::Status {
            vm_id: vm_id.clone(),
        },
    )
    .await;
    assert!(status.contains("state=running"), "{status}");
    run(
        &rest,
        Command::Metrics {
            vm_id: vm_id.clone(),
        },
    )
    .await;
    let snapshot = run(
        &rest,
        Command::Snapshot {
            vm_id: vm_id.clone(),
        },
    )
    .await;
    let snapshot_id = token(&snapshot);
    run(
        &rest,
        Command::Stop {
            vm_id: vm_id.clone(),
        },
    )
    .await;
    let restored = run(&rest, Command::Restore { snapshot_id }).await;
    let restored_id = token(&restored);
    let list = run(&rest, Command::List).await;
    assert!(list.contains(&restored_id), "{list}");
    run(
        &rest,
        Command::Stop {
            vm_id: restored_id.clone(),
        },
    )
    .await;
    run(
        &rest,
        Command::Delete {
            vm_id: vm_id.clone(),
        },
    )
    .await;
    run(&rest, Command::Delete { vm_id: restored_id }).await;

    handle.shutdown().await;
    assert!(!rest.exists(), "REST socket removed");
    assert!(!grpc.exists(), "gRPC socket removed");
}
