//! Integration tests: REST/gRPC contract parity and transport constraints.
//!
//! These tests load the actual `api/openapi.yaml` and
//! `api/microvm/v1/service.proto` files from the repository root and
//! validate:
//!
//! 1. OpenAPI spec is valid YAML with required fields.
//! 2. Proto file has valid proto3 syntax.
//! 3. Every OpenAPI operation has a matching proto RPC (and vice versa).
//! 4. Neither file contains TCP transport addresses.

use microvm_transport_contract::{check_parity, scan_for_tcp_patterns, OpenApiDoc, ProtoDoc};
use std::path::PathBuf;

/// Locate the repository root by walking up from the crate directory.
fn repo_root() -> PathBuf {
    let manifest = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    // crates/microvm-transport-contract -> repo root is two levels up.
    manifest
        .parent()
        .expect("crate parent")
        .parent()
        .expect("repo root")
        .to_path_buf()
}

fn openapi_path() -> PathBuf {
    repo_root().join("api/openapi.yaml")
}

fn proto_path() -> PathBuf {
    repo_root().join("api/microvm/v1/service.proto")
}

// ---------------------------------------------------------------------------
// OpenAPI validity
// ---------------------------------------------------------------------------

#[test]
fn openapi_is_valid_yaml_with_required_fields() {
    let doc = OpenApiDoc::from_file(&openapi_path())
        .expect("openapi.yaml must exist and parse as valid YAML");

    let errors = doc.validate();
    assert!(
        errors.is_ok(),
        "OpenAPI validation failed: {:?}",
        errors.unwrap_err()
    );
}

#[test]
fn openapi_has_all_expected_operations() {
    let doc = OpenApiDoc::from_file(&openapi_path()).unwrap();
    let ops = doc.operations();

    let expected_ids = [
        "createVm",
        "getVmStatus",
        "startVm",
        "stopVm",
        "snapshotVm",
        "getVmMetrics",
        "restoreVm",
    ];

    let actual_ids: Vec<&str> = ops.iter().map(|(_, _, id)| *id).collect();

    for expected in &expected_ids {
        assert!(
            actual_ids.contains(expected),
            "missing OpenAPI operation '{}'; found: {:?}",
            expected,
            actual_ids
        );
    }

    assert_eq!(
        ops.len(),
        expected_ids.len(),
        "unexpected extra operations: {:?}",
        actual_ids
    );
}

#[test]
fn openapi_server_uses_unix_socket() {
    let doc = OpenApiDoc::from_file(&openapi_path()).unwrap();
    assert!(
        !doc.servers.is_empty(),
        "OpenAPI must define at least one server"
    );
    for server in &doc.servers {
        assert!(
            server.url.starts_with("unix://"),
            "server URL must use unix:// scheme, got '{}'",
            server.url
        );
    }
}

// ---------------------------------------------------------------------------
// Proto validity
// ---------------------------------------------------------------------------

#[test]
fn proto_has_valid_proto3_syntax() {
    let doc = ProtoDoc::from_file(&proto_path())
        .expect("service.proto must exist and parse as valid proto3");

    assert_eq!(doc.syntax, "proto3");
    assert_eq!(doc.package, "microvm.v1");
}

#[test]
fn proto_has_microvm_service_with_all_rpcs() {
    let doc = ProtoDoc::from_file(&proto_path()).unwrap();

    assert_eq!(doc.services.len(), 1, "expected exactly one service");
    let svc = &doc.services[0];
    assert_eq!(svc.name, "MicrovmService");

    let expected_rpcs = [
        "CreateVm",
        "StartVm",
        "StopVm",
        "SnapshotVm",
        "RestoreVm",
        "GetVmStatus",
        "GetVmMetrics",
    ];

    for expected in &expected_rpcs {
        assert!(
            svc.rpcs.contains(&expected.to_string()),
            "missing proto RPC '{}'; found: {:?}",
            expected,
            svc.rpcs
        );
    }

    assert_eq!(
        svc.rpcs.len(),
        expected_rpcs.len(),
        "unexpected extra RPCs: {:?}",
        svc.rpcs
    );
}

#[test]
fn proto_has_expected_messages() {
    let doc = ProtoDoc::from_file(&proto_path()).unwrap();

    let expected_messages = [
        "ResourceSpec",
        "ErrorResponse",
        "CreateVmRequest",
        "CreateVmResponse",
        "StartVmRequest",
        "StartVmResponse",
        "StopVmRequest",
        "StopVmResponse",
        "SnapshotVmRequest",
        "SnapshotVmResponse",
        "RestoreVmRequest",
        "RestoreVmResponse",
        "GetVmStatusRequest",
        "GetVmStatusResponse",
        "GetVmMetricsRequest",
        "GetVmMetricsResponse",
    ];

    for expected in &expected_messages {
        assert!(
            doc.messages.contains(&expected.to_string()),
            "missing proto message '{}'; found: {:?}",
            expected,
            doc.messages
        );
    }
}

#[test]
fn proto_has_expected_enums() {
    let doc = ProtoDoc::from_file(&proto_path()).unwrap();

    assert!(
        doc.enums.contains(&"VmState".to_string()),
        "missing VmState enum"
    );
    assert!(
        doc.enums.contains(&"NetworkPolicy".to_string()),
        "missing NetworkPolicy enum"
    );
}

// ---------------------------------------------------------------------------
// Parity
// ---------------------------------------------------------------------------

#[test]
fn every_openapi_operation_has_matching_proto_rpc() {
    let openapi = OpenApiDoc::from_file(&openapi_path()).unwrap();
    let proto = ProtoDoc::from_file(&proto_path()).unwrap();

    let mismatches = check_parity(&openapi, &proto);
    assert!(
        mismatches.is_empty(),
        "REST/gRPC parity violations:\n{}",
        mismatches.join("\n")
    );
}

// ---------------------------------------------------------------------------
// Static transport scan
// ---------------------------------------------------------------------------

#[test]
fn openapi_contains_no_tcp_addresses() {
    let content = std::fs::read_to_string(openapi_path()).unwrap();
    let violations = scan_for_tcp_patterns(&content);
    assert!(
        violations.is_empty(),
        "OpenAPI spec contains forbidden TCP patterns:\n{:#?}",
        violations
    );
}

#[test]
fn proto_contains_no_tcp_addresses() {
    let content = std::fs::read_to_string(proto_path()).unwrap();
    let violations = scan_for_tcp_patterns(&content);
    assert!(
        violations.is_empty(),
        "Proto file contains forbidden TCP patterns:\n{:#?}",
        violations
    );
}

#[test]
fn scan_rejects_forbidden_patterns_in_synthetic_content() {
    // Positive control: verify the scanner actually catches violations.
    let bad_content = r#"
    server:
      url: "http://0.0.0.0:8080"
    fallback:
      url: "http://127.0.0.1:9090"
    transport: "tcp://localhost:5000"
    ipv6_any: "[::]:8080"
    ipv6_loop: "::1:9090"
    named: "localhost:3000"
    "#;

    let violations = scan_for_tcp_patterns(bad_content);
    assert!(
        violations.len() >= 6,
        "scanner must catch all forbidden patterns, got {} violations: {:?}",
        violations.len(),
        violations
    );
}
