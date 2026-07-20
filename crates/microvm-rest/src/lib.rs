//! REST/JSON API over a protected Unix domain socket for the
//! kvm-microvm-orchestrator platform.
//!
//! This crate implements the OpenAPI lifecycle routes exclusively over a
//! filesystem Unix socket. No TCP listener is created. Peer credentials
//! (`SO_PEERCRED`) are captured before authorization, and the socket file
//! is validated for mode `0660` and expected owner/group.
//!
//! # Architecture
//!
//! - [`config::SocketConfig`] — configurable socket path, mode, and ownership.
//! - [`peer::PeerCredentials`] — UID/GID extracted via `SO_PEERCRED`.
//! - [`peer::PeerAuthenticator`] — maps peer credentials to a [`Principal`].
//! - [`error`] — stable mapping from [`MicrovmError`] to HTTP status/body.
//! - [`router`] — route matching and request dispatch to the service.
//! - [`server::RestServer`] — Unix socket listener and HTTP/1.1 serving loop.
//!
//! # Security invariants
//!
//! - The socket is created with mode `0660` (owner+group read/write only).
//! - Peer UID/GID is captured via `SO_PEERCRED` before any authorization.
//! - No TCP address is ever bound.
//! - Business policy (quota, state machine, authorization) is delegated to
//!   the [`LifecycleService`](microvm_lifecycle::LifecycleService) backend.

pub mod config;
pub mod error;
pub mod peer;
pub mod router;
pub mod server;

pub use config::SocketConfig;
pub use error::{error_to_http_status, ErrorBody};
pub use peer::{PeerAuthenticator, PeerCredentials};
pub use server::RestServer;
