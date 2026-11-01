//! The `microvm run` constrained-import command.
//!
//! `run` is a constrained local import surface, not an OCI runtime.
//! It validates a local, digest-pinned OCI-like reference, imports it
//! through [`microvm_oci::OciImporter`] (verifying every layer hash and
//! refusing host mounts / capabilities / privileged / host-network
//! knobs), translates the result into a resource spec, then creates and
//! starts a microVM through the REST Unix socket.
//!
//! Remote and tag-only references are rejected with exit code 4
//! ([`ExitCode::LocalArtifactRequired`]) before any I/O, so
//! `microvm run --image nginx:latest` performs no network activity.

use crate::client::{Client, CreateVmRequest, NetworkPolicyArg};
use crate::error::CliError;
use microvm_oci::OciImporter;

/// The outcome of a successful `run`: the created and started VM id.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RunOutcome {
    /// The VM id created from the imported image.
    pub vm_id: String,
}

/// Execute the constrained `run` pipeline against `client`.
///
/// 1. Validate `image` as a local reference (rejects remote/tag-only
///    with [`ExitCode::LocalArtifactRequired`], no I/O).
/// 2. Import the local OCI-like layout, verifying every layer digest and
///    refusing forbidden runtime knobs.
/// 3. Create a VM from the imported resource spec.
/// 4. Start the VM.
pub async fn execute_run(client: &Client, image: &str) -> Result<RunOutcome, CliError> {
    // Step 1+2: validate the local reference and import. Both are local,
    // synchronous, and perform no network I/O. A remote/tag-only reference
    // fails here with local_artifact_required before any socket contact.
    let spec = import_local_image(image)?;

    // Step 3: create the VM from the imported resource spec.
    let network_policy = match spec.resources.network_policy() {
        microvm_types::NetworkPolicy::None => NetworkPolicyArg::None,
        microvm_types::NetworkPolicy::NatOnly => NetworkPolicyArg::NatOnly,
        microvm_types::NetworkPolicy::EgressAllowed => NetworkPolicyArg::EgressAllowed,
    };
    let create_req = CreateVmRequest {
        vcpu_count: spec.resources.vcpu_count(),
        memory_mib: spec.resources.memory_mib(),
        disk_mib: spec.resources.disk_mib(),
        network_policy,
    };
    let created = client.create_vm(&create_req).await?;

    // Step 4: start the VM.
    client.start_vm(&created.vm_id).await?;

    Ok(RunOutcome {
        vm_id: created.vm_id,
    })
}

/// Validate and import a local OCI-like image reference, returning the
/// typed microVM spec.
///
/// This is the local-only portion of `run`: it never touches the network
/// or the service socket. Remote and tag-only references are rejected
/// with [`ExitCode::LocalArtifactRequired`].
pub fn import_local_image(image: &str) -> Result<microvm_oci::MicroVmSpec, CliError> {
    let importer = OciImporter::open_reference(image).map_err(import_error_to_cli)?;
    let spec = importer.import().map_err(import_error_to_cli)?;
    Ok(spec)
}

/// Map a [`microvm_oci::ImportError`] to a [`CliError`], preserving the
/// stable error code (and thus exit code) and sanitizing the message.
fn import_error_to_cli(err: microvm_oci::ImportError) -> CliError {
    let microvm_err: microvm_errors::MicrovmError = err.into();
    CliError::from_microvm_error(&microvm_err)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::exit_code::ExitCode;

    #[test]
    fn run_rejects_remote_reference_without_io() {
        // nginx:latest is a tag-only reference; must fail with
        // local_artifact_required (exit 4) before any I/O.
        let err = import_local_image("nginx:latest").unwrap_err();
        assert_eq!(err.exit_code, ExitCode::LocalArtifactRequired);
    }

    #[test]
    fn run_rejects_https_reference_without_io() {
        let err = import_local_image("https://example.com/img").unwrap_err();
        assert_eq!(err.exit_code, ExitCode::LocalArtifactRequired);
    }

    #[test]
    fn run_rejects_docker_reference_without_io() {
        let err = import_local_image("docker://nginx:latest").unwrap_err();
        assert_eq!(err.exit_code, ExitCode::LocalArtifactRequired);
    }

    #[test]
    fn run_rejects_digest_registry_reference_without_io() {
        let reference =
            "repo/img@sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
        let err = import_local_image(reference).unwrap_err();
        assert_eq!(err.exit_code, ExitCode::LocalArtifactRequired);
    }

    #[test]
    fn run_missing_layout_is_not_found_or_general() {
        // A well-formed local path that does not exist fails after
        // reference validation (no remote rejection).
        let err = import_local_image("./nonexistent-layout-dir-xyz").unwrap_err();
        // The layout root is absent => not a local_artifact_required
        // (the reference itself is local); it is an artifact/internal error.
        assert_ne!(err.exit_code, ExitCode::LocalArtifactRequired);
    }
}
