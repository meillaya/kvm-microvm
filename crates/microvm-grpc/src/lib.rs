//! gRPC API over a protected Unix domain socket for the
//! kvm-microvm-orchestrator platform.
//!
//! This crate implements the `microvm.v1` protobuf service (todo 8) exclusively
//! over a filesystem Unix socket, providing full parity with the REST/JSON
//! transport ([`microvm-rest`]). Both transports drive the *same*
//! transport-neutral [`LifecycleService`](microvm_lifecycle::LifecycleService)
//! backend: in production the composed
//! [`VmLifecycleService`](microvm_service::VmLifecycleService), so the same
//! request reaches the same service result regardless of transport.
//!
//! # Architecture
//!
//! - [`proto`]: generated `microvm.v1` stubs (from `api/microvm/v1/service.proto`).
//! - [`config::SocketConfig`]: configurable socket path, mode, and ownership.
//! - [`peer`]: `SO_PEERCRED` extraction, [`PeerAuthenticator`](peer::PeerAuthenticator)
//!   policy, and per-connection principal propagation into tonic.
//! - [`error`]: stable mapping from [`MicrovmError`](microvm_errors::MicrovmError)
//!   to gRPC status codes, with the REST-identical error body in the details.
//! - [`service::MicrovmGrpcService`]: the `MicrovmService` implementation.
//! - [`server::GrpcServer`]: Unix socket listener and tonic serving loop.
//!
//! # Security invariants
//!
//! - The socket is created with mode `0660` (owner+group read/write only).
//! - Peer UID/GID is captured via `SO_PEERCRED` before any authorization.
//! - No TCP address is ever bound; only [`tokio::net::UnixListener`].
//! - gRPC reflection is disabled (see [`server::REFLECTION_ENABLED`]).
//! - Business policy (quota, state machine, authorization) is delegated to the
//!   lifecycle service backend.

pub mod config;
pub mod error;
pub mod peer;
pub mod proto;
pub mod server;
pub mod service;

pub use config::SocketConfig;
pub use error::{error_code_to_grpc, microvm_error_to_status, ErrorBody};
pub use peer::{PeerAuthenticator, PeerCredentials};
pub use server::GrpcServer;
pub use service::MicrovmGrpcService;
