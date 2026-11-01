//! The minimal static Rust HTTP function and its pinned local rootfs
//! (plan todo 28, requirement 1).
//!
//! The demo serves exactly one HTTP function. There is no multi-function
//! routing, no autoscaling, no persistent external data, and no second language
//! runtime: the function is a fixed Rust handler compiled into a pinned,
//! content-addressed local rootfs image. The rootfs is identified by its SHA-256
//! digest ([`Rootfs::sha256`]); the demo never pulls, mounts, or fetches it from
//! a remote source.
//!
//! # Determinism
//! [`HttpFunction::handle`] is a pure function of the request: the same request
//! always yields the same response. This keeps the handler fully testable with
//! no VM, no socket, and no clock.

use microvm_artifacts::Digest;
use microvm_errors::{ErrorCode, MicrovmError};
use serde::{Deserialize, Serialize};

/// The HTTP method of a request. The demo supports the two methods a minimal
/// function needs: `GET` (readiness/invocation) and `POST` (invocation body).
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "UPPERCASE")]
pub enum Method {
    /// `GET`.
    Get,
    /// `POST`.
    Post,
}

impl Method {
    /// Stable uppercase token.
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Get => "GET",
            Self::Post => "POST",
        }
    }
}

/// A minimal HTTP/1.1-style request delivered to the function.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct HttpRequest {
    /// Request method.
    pub method: Method,
    /// Request path (e.g. `/`, `/health`).
    pub path: String,
    /// Request body (empty for `GET`).
    pub body: String,
}

impl HttpRequest {
    /// Build a request.
    pub fn new(method: Method, path: impl Into<String>, body: impl Into<String>) -> Self {
        Self {
            method,
            path: path.into(),
            body: body.into(),
        }
    }

    /// The readiness probe request: `GET /health`.
    pub fn health() -> Self {
        Self::new(Method::Get, "/health", "")
    }

    /// The canonical invocation request: `GET /`.
    pub fn invoke() -> Self {
        Self::new(Method::Get, "/", "")
    }
}

/// A minimal HTTP response produced by the function.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct HttpResponse {
    /// HTTP status code (e.g. `200`, `404`).
    pub status: u16,
    /// Response body.
    pub body: String,
}

impl HttpResponse {
    /// Build a response.
    pub fn new(status: u16, body: impl Into<String>) -> Self {
        Self {
            status,
            body: body.into(),
        }
    }

    /// True when the status is a `2xx` success.
    pub fn is_success(&self) -> bool {
        (200..300).contains(&self.status)
    }
}

/// A pinned, content-addressed local rootfs image holding the function binary.
///
/// The rootfs is local-only and digest-addressed: [`Rootfs::sha256`] is the
/// orchestrator's own content hash of the image bytes. The demo never resolves
/// it from a registry or remote URI.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Rootfs {
    /// Stable rootfs name (e.g. `hello-http-rootfs`).
    pub name: String,
    /// SHA-256 of the rootfs image bytes.
    pub sha256: Digest,
}

impl Rootfs {
    /// Build a rootfs reference.
    ///
    /// # Errors
    /// Returns [`ErrorCode::InvalidResourceSpec`] when `name` is empty.
    pub fn new(name: impl Into<String>, sha256: Digest) -> Result<Self, MicrovmError> {
        let name = name.into();
        if name.is_empty() {
            return Err(MicrovmError::new(
                ErrorCode::InvalidResourceSpec,
                "rootfs name must not be empty",
            )
            .with_context("field", "name"));
        }
        Ok(Self { name, sha256 })
    }
}

/// The single minimal static Rust HTTP function the demo serves.
///
/// The handler is fixed (static) and pure: it maps a request to a response with
/// no external state. Readiness is signalled by `GET /health` returning `200`.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct HttpFunction {
    /// Stable function name (e.g. `hello-http`).
    pub name: String,
    /// The pinned local rootfs the function is packaged in.
    pub rootfs: Rootfs,
}

impl HttpFunction {
    /// Build a function.
    ///
    /// # Errors
    /// Returns [`ErrorCode::InvalidResourceSpec`] when `name` is empty.
    pub fn new(name: impl Into<String>, rootfs: Rootfs) -> Result<Self, MicrovmError> {
        let name = name.into();
        if name.is_empty() {
            return Err(MicrovmError::new(
                ErrorCode::InvalidResourceSpec,
                "function name must not be empty",
            )
            .with_context("field", "name"));
        }
        Ok(Self { name, rootfs })
    }

    /// The pure request handler.
    ///
    /// Routes:
    /// - `GET /health` -> `200 ok` (service-readiness signal).
    /// - `GET /`       -> `200 Hello from <name>!` (canonical invocation).
    /// - `POST /`      -> `200` echoing the request body (invocation with input).
    /// - anything else -> `404 not found`.
    pub fn handle(&self, req: &HttpRequest) -> HttpResponse {
        match (req.method, req.path.as_str()) {
            (Method::Get, "/health") => HttpResponse::new(200, "ok"),
            (Method::Get, "/") => HttpResponse::new(200, format!("Hello from {}!", self.name)),
            (Method::Post, "/") => HttpResponse::new(200, req.body.clone()),
            _ => HttpResponse::new(404, "not found"),
        }
    }

    /// True when `response` is a successful readiness signal for `GET /health`.
    pub fn is_ready(&self, req: &HttpRequest, response: &HttpResponse) -> bool {
        req.path == "/health" && response.is_success()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn rootfs() -> Rootfs {
        Rootfs::new("hello-http-rootfs", Digest::from_bytes([7; 32])).unwrap()
    }

    fn function() -> HttpFunction {
        HttpFunction::new("hello-http", rootfs()).unwrap()
    }

    #[test]
    fn health_route_is_readiness_signal() {
        let f = function();
        let req = HttpRequest::health();
        let resp = f.handle(&req);
        assert_eq!(resp.status, 200);
        assert_eq!(resp.body, "ok");
        assert!(f.is_ready(&req, &resp));
    }

    #[test]
    fn invoke_route_greets_with_function_name() {
        let f = function();
        let resp = f.handle(&HttpRequest::invoke());
        assert_eq!(resp.status, 200);
        assert_eq!(resp.body, "Hello from hello-http!");
    }

    #[test]
    fn post_echoes_body() {
        let f = function();
        let req = HttpRequest::new(Method::Post, "/", "payload");
        let resp = f.handle(&req);
        assert_eq!(resp.status, 200);
        assert_eq!(resp.body, "payload");
    }

    #[test]
    fn unknown_route_is_404() {
        let f = function();
        let resp = f.handle(&HttpRequest::new(Method::Get, "/nope", ""));
        assert_eq!(resp.status, 404);
        assert!(!resp.is_success());
    }

    #[test]
    fn handler_is_pure_and_deterministic() {
        let f = function();
        let req = HttpRequest::invoke();
        assert_eq!(f.handle(&req), f.handle(&req));
    }

    #[test]
    fn readiness_is_false_for_non_health_route() {
        let f = function();
        let req = HttpRequest::invoke();
        let resp = f.handle(&req);
        assert!(!f.is_ready(&req, &resp));
    }

    #[test]
    fn empty_names_are_rejected() {
        assert!(Rootfs::new("", Digest::from_bytes([0; 32])).is_err());
        assert!(HttpFunction::new("", rootfs()).is_err());
    }

    #[test]
    fn rootfs_pins_content_hash() {
        let r = rootfs();
        assert_eq!(r.sha256, Digest::from_bytes([7; 32]));
    }
}
