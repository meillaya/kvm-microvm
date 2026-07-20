//! Deterministic HTTP-function handler tests (plan todo 28, requirement 1).
//!
//! The single static Rust HTTP function is a pure request->response map with a
//! pinned local rootfs. No VM, socket, or clock is involved.

use microvm_artifacts::Digest;
use microvm_demo::{HttpFunction, HttpRequest, HttpResponse, Method, Rootfs};

fn function() -> HttpFunction {
    let rootfs = Rootfs::new("hello-http-rootfs", Digest::from_bytes([7; 32])).unwrap();
    HttpFunction::new("hello-http", rootfs).unwrap()
}

#[test]
fn readiness_probe_returns_200_ok() {
    let f = function();
    let req = HttpRequest::health();
    let resp = f.handle(&req);
    assert_eq!(resp, HttpResponse::new(200, "ok"));
    assert!(f.is_ready(&req, &resp));
}

#[test]
fn invocation_is_deterministic() {
    let f = function();
    let req = HttpRequest::invoke();
    let a = f.handle(&req);
    let b = f.handle(&req);
    assert_eq!(a, b);
    assert_eq!(a.body, "Hello from hello-http!");
}

#[test]
fn post_invocation_echoes_input_without_external_state() {
    let f = function();
    let resp = f.handle(&HttpRequest::new(Method::Post, "/", "input"));
    assert_eq!(resp.status, 200);
    assert_eq!(resp.body, "input");
}

#[test]
fn only_one_function_no_routing_to_others() {
    let f = function();
    // Any non-rooted path is 404: there is no second function to route to.
    assert_eq!(
        f.handle(&HttpRequest::new(Method::Get, "/other", ""))
            .status,
        404
    );
    assert_eq!(
        f.handle(&HttpRequest::new(Method::Post, "/health", "x"))
            .status,
        404
    );
}

#[test]
fn rootfs_is_pinned_and_local() {
    let f = function();
    assert_eq!(f.rootfs.name, "hello-http-rootfs");
    assert_eq!(f.rootfs.sha256, Digest::from_bytes([7; 32]));
}
