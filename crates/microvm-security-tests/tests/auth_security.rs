//! Authentication / authorization adversarial suite.
//!
//! Drives the real peer-credential extraction
//! ([`microvm_rest::peer::get_peer_credentials`]) over a genuine Unix
//! socketpair, the UID-mapping authenticators
//! ([`microvm_rest::peer::StaticAuthenticator`] /
//! [`microvm_rest::peer::RootOnlyAuthenticator`]), the tenant/role policy
//! ([`microvm_lifecycle::policy::authorize`]), and the Unix-socket ownership +
//! mode validation on both transports ([`microvm_rest::RestServer::validate_socket`]
//! and [`microvm_grpc::GrpcServer::validate_socket`]).
//!
//! Traps covered: a peer whose UID does not map to an authorized principal
//! (peer-credential denial), cross-tenant access, a role acting above its
//! permission, a wrong-owner control socket, and an insecure (world-accessible)
//! socket mode. Every probe observes a typed rejection: the authenticators
//! return `None`, the policy returns [`ErrorCode::PermissionDenied`], and the
//! socket validators return a structured socket-validation error.

mod common;

use common::{assert_no_bypass, run_battery, Probe};
use microvm_errors::ErrorCode;
use microvm_lifecycle::policy::{authorize, Operation};
use microvm_rest::peer::{
    get_peer_credentials, PeerAuthenticator as RestPeerAuth, PeerCredentials,
    RootOnlyAuthenticator, StaticAuthenticator,
};
use microvm_types::{Principal, Role, TenantId};
use std::os::unix::fs::MetadataExt;
use std::os::unix::net::{UnixListener, UnixStream};
use std::path::Path;
use tempfile::TempDir;

fn tenant(id: &str) -> TenantId {
    TenantId::new(id).unwrap()
}
fn principal(t: &str, role: Role) -> Principal {
    Principal::new(tenant(t), role)
}

/// The current process UID/GID, read from a socket file this process owns
/// (avoids any direct `getuid` FFI in the test body).
fn current_ids() -> (u32, u32) {
    let tmp = TempDir::new().unwrap();
    let path = tmp.path().join("id.sock");
    let listener = UnixListener::bind(&path).unwrap();
    let meta = std::fs::metadata(&path).unwrap();
    let ids = (meta.uid(), meta.gid());
    drop(listener);
    ids
}

// -- Peer-credential extraction ---------------------------------------------

#[test]
fn peer_credentials_extracted_from_real_unix_socket() {
    let (a, _b) = UnixStream::pair().unwrap();
    let creds = get_peer_credentials(&a).unwrap();
    let (uid, gid) = current_ids();
    // A socketpair's peer is this very process.
    assert_eq!(creds.pid, std::process::id() as i32);
    assert_eq!(creds.uid, uid);
    assert_eq!(creds.gid, gid);
}

#[test]
fn static_authenticator_denies_wrong_uid() {
    let (uid, _gid) = current_ids();
    let auth = StaticAuthenticator::new(uid, principal("tenant-a", Role::Owner));
    let ok = PeerCredentials {
        pid: 1,
        uid,
        gid: uid,
    };
    assert!(auth.authenticate(&ok).is_some(), "matching uid is accepted");
    // A different UID (another tenant's process) is denied -> None.
    let foreign = PeerCredentials {
        pid: 1,
        uid: uid.wrapping_add(1),
        gid: uid,
    };
    assert!(auth.authenticate(&foreign).is_none(), "wrong uid is denied");
}

#[test]
fn root_only_authenticator_denies_non_root() {
    let auth = RootOnlyAuthenticator::new(principal("tenant-a", Role::Owner));
    let root = PeerCredentials {
        pid: 1,
        uid: 0,
        gid: 0,
    };
    assert!(auth.authenticate(&root).is_some());
    let non_root = PeerCredentials {
        pid: 1,
        uid: 1000,
        gid: 1000,
    };
    assert!(auth.authenticate(&non_root).is_none(), "non-root is denied");
}

/// End-to-end peer-credential denial: a peer whose UID does not map to any
/// authorized principal is rejected before any authorization decision.
#[test]
fn peer_credential_to_principal_denial_is_end_to_end() {
    let (uid, _gid) = current_ids();
    // The daemon only authorizes a DIFFERENT service UID, not this process.
    let auth = StaticAuthenticator::new(uid.wrapping_add(1), principal("tenant-a", Role::Owner));
    let (_a, _b) = UnixStream::pair().unwrap();
    let creds = get_peer_credentials(&_a).unwrap(); // this process's real creds
    assert!(
        auth.authenticate(&creds).is_none(),
        "a peer whose UID is not the authorized service UID must be denied"
    );
}

// -- Tenant / role authorization --------------------------------------------

#[test]
fn cross_tenant_access_is_denied() {
    let p = principal("tenant-a", Role::Owner);
    let err = authorize(&p, &tenant("tenant-b"), Operation::Status).unwrap_err();
    assert_eq!(err.code, ErrorCode::PermissionDenied);
    assert_eq!(
        err.context.get("principal_tenant").map(String::as_str),
        Some("tenant-a")
    );
    assert_eq!(
        err.context.get("resource_owner").map(String::as_str),
        Some("tenant-b")
    );
}

#[test]
fn same_tenant_owner_is_allowed() {
    let p = principal("tenant-a", Role::Owner);
    assert!(authorize(&p, &tenant("tenant-a"), Operation::Create).is_ok());
    assert!(authorize(&p, &tenant("tenant-a"), Operation::Stop).is_ok());
}

#[test]
fn role_escalation_is_denied() {
    let owner = tenant("tenant-a");
    // Viewer cannot mutate.
    let viewer = principal("tenant-a", Role::Viewer);
    for op in [
        Operation::Create,
        Operation::Start,
        Operation::Stop,
        Operation::Snapshot,
    ] {
        let err = authorize(&viewer, &owner, op).unwrap_err();
        assert_eq!(err.code, ErrorCode::PermissionDenied, "viewer {op}");
    }
    // Operator cannot create/snapshot/restore.
    let operator = principal("tenant-a", Role::Operator);
    for op in [Operation::Create, Operation::Snapshot, Operation::Restore] {
        let err = authorize(&operator, &owner, op).unwrap_err();
        assert_eq!(err.code, ErrorCode::PermissionDenied, "operator {op}");
    }
    // Operator CAN start/stop; Viewer CAN read status/metrics.
    assert!(authorize(&operator, &owner, Operation::Start).is_ok());
    assert!(authorize(&operator, &owner, Operation::Stop).is_ok());
    assert!(authorize(&viewer, &owner, Operation::Status).is_ok());
    assert!(authorize(&viewer, &owner, Operation::Metrics).is_ok());
}

// -- Socket ownership + mode validation -------------------------------------

/// Bind a real Unix socket and return (tempdir guard, path, owner uid).
fn bind_socket() -> (TempDir, std::path::PathBuf, u32) {
    let tmp = TempDir::new().unwrap();
    let path = tmp.path().join("api.sock");
    let listener = UnixListener::bind(&path).unwrap();
    let uid = std::fs::metadata(&path).unwrap().uid();
    std::mem::forget(listener); // keep the socket file alive for validation
    (tmp, path, uid)
}

fn set_mode(path: &Path, mode: u32) {
    use std::os::unix::fs::PermissionsExt;
    std::fs::set_permissions(path, std::fs::Permissions::from_mode(mode)).unwrap();
}

#[test]
fn rest_socket_mode_0660_accepted_insecure_rejected() {
    let (_tmp, path, _uid) = bind_socket();
    set_mode(&path, 0o660);
    let cfg = microvm_rest::SocketConfig::with_path(&path).with_mode(0o660);
    assert!(rest_validate(&path, &cfg).is_ok(), "0660 is accepted");
    for insecure in [0o777u32, 0o666, 0o644, 0o600] {
        set_mode(&path, insecure);
        assert!(
            rest_validate(&path, &cfg).is_err(),
            "insecure mode {insecure:04o} must be rejected"
        );
    }
}

#[test]
fn grpc_socket_mode_0660_accepted_insecure_rejected() {
    let (_tmp, path, _uid) = bind_socket();
    set_mode(&path, 0o660);
    let cfg = microvm_grpc::SocketConfig::with_path(&path).with_mode(0o660);
    assert!(grpc_validate(&path, &cfg).is_ok(), "0660 is accepted");
    for insecure in [0o777u32, 0o666, 0o644] {
        set_mode(&path, insecure);
        assert!(
            grpc_validate(&path, &cfg).is_err(),
            "insecure mode {insecure:04o} must be rejected"
        );
    }
}

#[test]
fn wrong_owner_socket_is_rejected_by_both_transports() {
    let (_tmp, path, uid) = bind_socket();
    set_mode(&path, 0o660);
    let foreign = uid.wrapping_add(1);
    // REST: expecting a different owner UID must fail.
    let rest_cfg = microvm_rest::SocketConfig::with_path(&path)
        .with_mode(0o660)
        .with_uid(foreign);
    assert!(rest_validate(&path, &rest_cfg).is_err(), "wrong owner uid");
    // gRPC: same.
    let grpc_cfg = microvm_grpc::SocketConfig::with_path(&path)
        .with_mode(0o660)
        .with_uid(foreign);
    assert!(grpc_validate(&path, &grpc_cfg).is_err(), "wrong owner uid");
    // Control: the actual owner is accepted.
    let ok_cfg = microvm_rest::SocketConfig::with_path(&path)
        .with_mode(0o660)
        .with_uid(uid);
    assert!(rest_validate(&path, &ok_cfg).is_ok());
}

#[test]
fn non_socket_file_is_rejected() {
    let tmp = TempDir::new().unwrap();
    let path = tmp.path().join("not-a-socket");
    std::fs::write(&path, b"x").unwrap();
    set_mode(&path, 0o660);
    let cfg = microvm_rest::SocketConfig::with_path(&path).with_mode(0o660);
    assert!(
        rest_validate(&path, &cfg).is_err(),
        "a regular file is not a socket"
    );
}

// Thin wrappers so the battery can record the validators' typed outcome as a
// `Result<(), MicrovmError>`-shaped probe. The validators return `ServerError`;
// we map any rejection to `PermissionDenied` (the security meaning of an
// ownership/mode failure) for the probe recorder.
fn rest_validate(path: &Path, cfg: &microvm_rest::SocketConfig) -> Result<(), ErrorCode> {
    microvm_rest::RestServer::validate_socket(path, cfg).map_err(|_| ErrorCode::PermissionDenied)
}
fn grpc_validate(path: &Path, cfg: &microvm_grpc::SocketConfig) -> Result<(), ErrorCode> {
    microvm_grpc::GrpcServer::validate_socket(path, cfg).map_err(|_| ErrorCode::PermissionDenied)
}

// -- Consolidated battery ---------------------------------------------------

#[test]
fn auth_security_battery_emits_evidence_and_detects_no_bypass() {
    let (uid, _gid) = current_ids();

    // Peer-credential denial probes: model "authenticator returns None" as a
    // rejection by converting Option<Principal> -> Result<(), ErrorCode>.
    let auth = StaticAuthenticator::new(uid, principal("tenant-a", Role::Owner));
    let foreign = PeerCredentials {
        pid: 1,
        uid: uid.wrapping_add(1),
        gid: uid,
    };
    let peer_denied: Result<(), ErrorCode> = auth
        .authenticate(&foreign)
        .map(|_| ())
        .ok_or(ErrorCode::PermissionDenied);
    let root_auth = RootOnlyAuthenticator::new(principal("tenant-a", Role::Owner));
    let non_root = PeerCredentials {
        pid: 1,
        uid: 1000,
        gid: 1000,
    };
    let root_denied: Result<(), ErrorCode> = root_auth
        .authenticate(&non_root)
        .map(|_| ())
        .ok_or(ErrorCode::PermissionDenied);

    // Socket ownership/mode probes.
    let (_tmp, path, sock_uid) = bind_socket();
    set_mode(&path, 0o666);
    let insecure_cfg = microvm_rest::SocketConfig::with_path(&path).with_mode(0o660);
    let insecure_probe = rest_validate(&path, &insecure_cfg);
    set_mode(&path, 0o660);
    let wrong_owner_cfg = microvm_rest::SocketConfig::with_path(&path)
        .with_mode(0o660)
        .with_uid(sock_uid.wrapping_add(1));
    let wrong_owner_probe = rest_validate(&path, &wrong_owner_cfg);
    let grpc_wrong_owner = microvm_grpc::SocketConfig::with_path(&path)
        .with_mode(0o660)
        .with_uid(sock_uid.wrapping_add(1));
    let grpc_wrong_owner_probe = grpc_validate(&path, &grpc_wrong_owner);

    let viewer = principal("tenant-a", Role::Viewer);
    let operator = principal("tenant-a", Role::Operator);

    let probes = vec![
        Probe::from_result(
            "peer_cred_wrong_uid_denied",
            "auth:peer_credential_denial",
            ErrorCode::PermissionDenied,
            peer_denied,
        ),
        Probe::from_result(
            "root_only_non_root_denied",
            "auth:peer_credential_denial",
            ErrorCode::PermissionDenied,
            root_denied,
        ),
        Probe::from_result(
            "cross_tenant_denied",
            "auth:cross_tenant",
            ErrorCode::PermissionDenied,
            authorize(
                &principal("tenant-a", Role::Owner),
                &tenant("tenant-b"),
                Operation::Status,
            ),
        ),
        Probe::from_result(
            "viewer_create_denied",
            "auth:role_escalation",
            ErrorCode::PermissionDenied,
            authorize(&viewer, &tenant("tenant-a"), Operation::Create),
        ),
        Probe::from_result(
            "viewer_start_denied",
            "auth:role_escalation",
            ErrorCode::PermissionDenied,
            authorize(&viewer, &tenant("tenant-a"), Operation::Start),
        ),
        Probe::from_result(
            "operator_create_denied",
            "auth:role_escalation",
            ErrorCode::PermissionDenied,
            authorize(&operator, &tenant("tenant-a"), Operation::Create),
        ),
        Probe::from_result(
            "operator_snapshot_denied",
            "auth:role_escalation",
            ErrorCode::PermissionDenied,
            authorize(&operator, &tenant("tenant-a"), Operation::Snapshot),
        ),
        Probe::from_result(
            "insecure_socket_mode",
            "auth:insecure_socket",
            ErrorCode::PermissionDenied,
            insecure_probe,
        ),
        Probe::from_result(
            "wrong_owner_socket_rest",
            "auth:wrong_owner_socket",
            ErrorCode::PermissionDenied,
            wrong_owner_probe,
        ),
        Probe::from_result(
            "wrong_owner_socket_grpc",
            "auth:wrong_owner_socket",
            ErrorCode::PermissionDenied,
            grpc_wrong_owner_probe,
        ),
    ];

    let evidence = run_battery("auth_security", probes);
    assert_no_bypass(&evidence);
    assert!(evidence.summary.total >= 10);

    // Controls: legitimate access works (so the denials are discriminating).
    assert!(authorize(
        &principal("tenant-a", Role::Owner),
        &tenant("tenant-a"),
        Operation::Create
    )
    .is_ok());
    assert!(auth
        .authenticate(&PeerCredentials {
            pid: 1,
            uid,
            gid: uid
        })
        .is_some());
}
