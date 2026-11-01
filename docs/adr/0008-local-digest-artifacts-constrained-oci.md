# ADR-0008: Pinned local digest-addressed artifacts; constrained OCI import; no remote pulls

## Status

Accepted.

## Context

The owner selected reproducibility and a strong security contract. Treating
`nginx:latest` or a remote tag as a secure artifact source would undermine both:
tags are mutable and remote pulls introduce a network dependency and an
untrusted-input channel. The owner still wants an OCI-like entry point, but only
as a constrained local import format.

## Decision

- Artifacts are pinned, local, and digest-addressed. Image references must
  be a local path or `file://` URI to a digest-pinned OCI-like layout
  (`manifest.json` plus `blobs/sha256/<hex>`).
- The importer verifies the SHA-256 of the config blob and every layer, selects
  a supported platform (`linux/amd64` or `linux/arm64`), and translates the
  result into a typed microVM spec.
- Remote and tag-only references are rejected before any I/O: `https://`,
  `http://`, `docker://`, `oci://`, `registry://`, `s3://`, `ssh://`,
  `repo/img@sha256:…`, and `nginx:latest` all fail with
  `local_artifact_required`. The command performs no network I/O.
- The importer refuses images requesting host mounts, host
  network/PID/IPC sharing, privileged mode, capability additions, or arbitrary
  host process controls. Container process metadata (Cmd/Entrypoint/Env) is
  ignored, never applied to the host.

## Consequences

- Artifact provenance is reproducible and local; there is no remote client
  dependency and no mutable-tag risk.
- The OCI-like entry point is safe by construction: it cannot apply host-side
  container privileges.
- Reference classification is pure and fully tested without network access.

## Scope-out

No remote registry pulls. No tag-based `nginx:latest` behavior. No general OCI
runtime compatibility and no OCI runtime conformance claim. No host mounts,
host capabilities, privileged container flags, or host process controls.

## References

- [../architecture.md](../architecture.md#51-constrained-local-oci-like-import)
- [../security.md](../security.md#54-artifact-and-path-boundaries)
- [ADR-0012](0012-fail-closed-tcb.md)
