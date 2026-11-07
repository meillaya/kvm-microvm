//! Build-time gRPC code generation for the `microvm.v1` service.
//!
//! Compiles the canonical proto contract (`api/microvm/v1/service.proto`,
//! defined in the API contract) into Rust server/client stubs using `tonic-prost-build`
//! and the system `protoc`. The generated code is emitted into `OUT_DIR` and
//! included by `src/proto.rs`.

fn main() -> Result<(), Box<dyn std::error::Error>> {
    // The proto lives at the repository root under `api/`, two levels up from
    // this crate. It is the single source of truth shared with the REST/OpenAPI
    // contract; we never keep a private copy.
    let proto = "../../api/microvm/v1/service.proto";
    let include = "../../api";

    println!("cargo:rerun-if-changed={proto}");
    println!("cargo:rerun-if-changed=build.rs");

    tonic_prost_build::configure()
        .build_server(true)
        .build_client(true)
        .compile_protos(&[proto], &[include])?;

    Ok(())
}
