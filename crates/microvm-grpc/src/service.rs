//! gRPC service implementation backed by the transport-neutral lifecycle
//! service.
//!
//! [`MicrovmGrpcService`] implements the generated `MicrovmService` trait by
//! delegating every RPC to an `Arc<dyn LifecycleService>` — the same backend
//! contract the REST transport drives. In production this is the composed
//! [`VmLifecycleService`](microvm_service::VmLifecycleService); tests inject a
//! scripted mock. All business policy (state machine, quota, ownership) lives
//! in the backend; this layer only does transport concerns: principal
//! extraction, request validation, proto↔domain mapping, and error mapping.

use std::sync::Arc;

use microvm_lifecycle::{LifecycleService, VmState as DomainVmState};
use microvm_types::{
    NetworkPolicy as DomainNetworkPolicy, Principal, ResourceSpec, SnapshotId, VmId,
};
use tonic::{Request, Response, Status};

use crate::error::{
    authentication_failed_status, invalid_id_status, invalid_resource_spec_status,
    microvm_error_to_status,
};
use crate::peer::PeerConnectInfo;
use crate::proto::v1::microvm_service_server::MicrovmService;
use crate::proto::v1::{
    CreateVmRequest, CreateVmResponse, GetVmMetricsRequest, GetVmMetricsResponse,
    GetVmStatusRequest, GetVmStatusResponse, NetworkPolicy as ProtoNetworkPolicy,
    ResourceSpec as ProtoResourceSpec, RestoreVmRequest, RestoreVmResponse, SnapshotVmRequest,
    SnapshotVmResponse, StartVmRequest, StartVmResponse, StopVmRequest, StopVmResponse,
    VmState as ProtoVmState,
};

/// gRPC adapter exposing a [`LifecycleService`] as the `MicrovmService`.
#[derive(Clone)]
pub struct MicrovmGrpcService {
    service: Arc<dyn LifecycleService>,
}

impl MicrovmGrpcService {
    /// Wrap a lifecycle service backend.
    pub fn new(service: Arc<dyn LifecycleService>) -> Self {
        Self { service }
    }
}

/// Recover the authenticated principal from a request's connection info.
///
/// Returns a `PermissionDenied` status (with a `permission_denied` error body)
/// when the peer was not authenticated, mirroring the REST transport's `403`.
fn principal_from_request<T>(req: &Request<T>) -> Result<Principal, Status> {
    req.extensions()
        .get::<PeerConnectInfo>()
        .and_then(|info| info.principal.clone())
        .ok_or_else(authentication_failed_status)
}

// ---------------------------------------------------------------------------
// proto <-> domain mappings
// ---------------------------------------------------------------------------

/// Map a domain [`DomainVmState`] to its proto enum discriminant.
fn vm_state_to_proto(state: DomainVmState) -> i32 {
    match state {
        DomainVmState::Created => ProtoVmState::Created as i32,
        DomainVmState::Configured => ProtoVmState::Configured as i32,
        DomainVmState::Running => ProtoVmState::Running as i32,
        DomainVmState::Paused => ProtoVmState::Paused as i32,
        DomainVmState::Snapshotting => ProtoVmState::Snapshotting as i32,
        DomainVmState::Restoring => ProtoVmState::Restoring as i32,
        DomainVmState::Stopped => ProtoVmState::Stopped as i32,
        DomainVmState::Failed => ProtoVmState::Failed as i32,
    }
}

/// Map a proto network policy discriminant to the domain [`DomainNetworkPolicy`].
///
/// `Unspecified` (the proto3 default) and any unknown value map to the platform
/// default `None`, matching the REST transport's default-when-absent behavior.
fn network_policy_from_proto(value: i32) -> DomainNetworkPolicy {
    if value == ProtoNetworkPolicy::None as i32 {
        DomainNetworkPolicy::None
    } else if value == ProtoNetworkPolicy::NatOnly as i32 {
        DomainNetworkPolicy::NatOnly
    } else if value == ProtoNetworkPolicy::FullEgress as i32 {
        DomainNetworkPolicy::EgressAllowed
    } else {
        DomainNetworkPolicy::None
    }
}

/// Map a domain [`DomainNetworkPolicy`] to its proto enum discriminant.
fn network_policy_to_proto(policy: DomainNetworkPolicy) -> i32 {
    match policy {
        DomainNetworkPolicy::None => ProtoNetworkPolicy::None as i32,
        DomainNetworkPolicy::NatOnly => ProtoNetworkPolicy::NatOnly as i32,
        DomainNetworkPolicy::EgressAllowed => ProtoNetworkPolicy::FullEgress as i32,
    }
}

/// Map a domain [`ResourceSpec`] to the proto [`ProtoResourceSpec`] message.
fn resource_spec_to_proto(spec: &ResourceSpec) -> ProtoResourceSpec {
    ProtoResourceSpec {
        vcpu_count: spec.vcpu_count(),
        memory_mib: spec.memory_mib(),
        disk_mib: spec.disk_mib(),
        network_policy: network_policy_to_proto(spec.network_policy()),
    }
}

// ---------------------------------------------------------------------------
// MicrovmService implementation
// ---------------------------------------------------------------------------

#[tonic::async_trait]
impl MicrovmService for MicrovmGrpcService {
    async fn create_vm(
        &self,
        request: Request<CreateVmRequest>,
    ) -> Result<Response<CreateVmResponse>, Status> {
        let principal = principal_from_request(&request)?;
        let req = request.into_inner();

        let spec = ResourceSpec::new(
            req.vcpu_count,
            req.memory_mib,
            req.disk_mib,
            network_policy_from_proto(req.network_policy),
        )
        .map_err(|e| invalid_resource_spec_status(e.reason))?;

        match self.service.create(spec, principal).await {
            Ok(vm_id) => Ok(Response::new(CreateVmResponse {
                vm_id: vm_id.to_string(),
            })),
            Err(e) => Err(microvm_error_to_status(&e)),
        }
    }

    async fn start_vm(
        &self,
        request: Request<StartVmRequest>,
    ) -> Result<Response<StartVmResponse>, Status> {
        let principal = principal_from_request(&request)?;
        let vm_id = VmId::new(request.into_inner().vm_id)
            .map_err(|e| invalid_id_status(format!("invalid vm_id: {}", e.reason)))?;

        self.service
            .start(&vm_id, &principal)
            .await
            .map_err(|e| microvm_error_to_status(&e))?;
        Ok(Response::new(StartVmResponse {}))
    }

    async fn stop_vm(
        &self,
        request: Request<StopVmRequest>,
    ) -> Result<Response<StopVmResponse>, Status> {
        let principal = principal_from_request(&request)?;
        let vm_id = VmId::new(request.into_inner().vm_id)
            .map_err(|e| invalid_id_status(format!("invalid vm_id: {}", e.reason)))?;

        self.service
            .stop(&vm_id, &principal)
            .await
            .map_err(|e| microvm_error_to_status(&e))?;
        Ok(Response::new(StopVmResponse {}))
    }

    async fn snapshot_vm(
        &self,
        request: Request<SnapshotVmRequest>,
    ) -> Result<Response<SnapshotVmResponse>, Status> {
        let principal = principal_from_request(&request)?;
        let vm_id = VmId::new(request.into_inner().vm_id)
            .map_err(|e| invalid_id_status(format!("invalid vm_id: {}", e.reason)))?;

        match self.service.snapshot(&vm_id, &principal).await {
            Ok(snapshot_id) => Ok(Response::new(SnapshotVmResponse {
                snapshot_id: snapshot_id.to_string(),
            })),
            Err(e) => Err(microvm_error_to_status(&e)),
        }
    }

    async fn restore_vm(
        &self,
        request: Request<RestoreVmRequest>,
    ) -> Result<Response<RestoreVmResponse>, Status> {
        let principal = principal_from_request(&request)?;
        let snapshot_id = SnapshotId::new(request.into_inner().snapshot_id)
            .map_err(|e| invalid_id_status(format!("invalid snapshot_id: {}", e.reason)))?;

        match self.service.restore(&snapshot_id, &principal).await {
            Ok(vm_id) => Ok(Response::new(RestoreVmResponse {
                vm_id: vm_id.to_string(),
            })),
            Err(e) => Err(microvm_error_to_status(&e)),
        }
    }

    async fn get_vm_status(
        &self,
        request: Request<GetVmStatusRequest>,
    ) -> Result<Response<GetVmStatusResponse>, Status> {
        let principal = principal_from_request(&request)?;
        let vm_id = VmId::new(request.into_inner().vm_id)
            .map_err(|e| invalid_id_status(format!("invalid vm_id: {}", e.reason)))?;

        match self.service.status(&vm_id, &principal).await {
            Ok(status) => Ok(Response::new(GetVmStatusResponse {
                vm_id: status.vm_id.to_string(),
                state: vm_state_to_proto(status.state),
                created_at: status.created_at.to_rfc3339(),
                resource_spec: Some(resource_spec_to_proto(&status.resource_spec)),
            })),
            Err(e) => Err(microvm_error_to_status(&e)),
        }
    }

    async fn get_vm_metrics(
        &self,
        request: Request<GetVmMetricsRequest>,
    ) -> Result<Response<GetVmMetricsResponse>, Status> {
        let principal = principal_from_request(&request)?;
        let vm_id = VmId::new(request.into_inner().vm_id)
            .map_err(|e| invalid_id_status(format!("invalid vm_id: {}", e.reason)))?;

        match self.service.metrics(&vm_id, &principal).await {
            Ok(metrics) => Ok(Response::new(GetVmMetricsResponse {
                vm_id: metrics.vm_id.to_string(),
                state: vm_state_to_proto(metrics.state),
            })),
            Err(e) => Err(microvm_error_to_status(&e)),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn vm_state_mapping_is_total_and_stable() {
        for state in DomainVmState::all() {
            let proto = vm_state_to_proto(*state);
            // Round-trip through the proto enum name table.
            let name = ProtoVmState::try_from(proto).unwrap().as_str_name();
            assert!(name.starts_with("VM_STATE_"), "unexpected name {name}");
        }
        assert_eq!(
            vm_state_to_proto(DomainVmState::Running),
            ProtoVmState::Running as i32
        );
    }

    #[test]
    fn network_policy_round_trips() {
        for policy in [
            DomainNetworkPolicy::None,
            DomainNetworkPolicy::NatOnly,
            DomainNetworkPolicy::EgressAllowed,
        ] {
            let proto = network_policy_to_proto(policy);
            assert_eq!(network_policy_from_proto(proto), policy);
        }
    }

    #[test]
    fn network_policy_unspecified_defaults_to_none() {
        assert_eq!(
            network_policy_from_proto(ProtoNetworkPolicy::Unspecified as i32),
            DomainNetworkPolicy::None
        );
        // Unknown discriminants also fail closed to the default.
        assert_eq!(network_policy_from_proto(999), DomainNetworkPolicy::None);
    }

    #[test]
    fn full_egress_maps_to_domain_egress_allowed() {
        assert_eq!(
            network_policy_from_proto(ProtoNetworkPolicy::FullEgress as i32),
            DomainNetworkPolicy::EgressAllowed
        );
    }

    #[test]
    fn resource_spec_to_proto_preserves_fields() {
        let spec = ResourceSpec::new(2, 512, 1024, DomainNetworkPolicy::NatOnly).unwrap();
        let proto = resource_spec_to_proto(&spec);
        assert_eq!(proto.vcpu_count, 2);
        assert_eq!(proto.memory_mib, 512);
        assert_eq!(proto.disk_mib, 1024);
        assert_eq!(proto.network_policy, ProtoNetworkPolicy::NatOnly as i32);
    }

    #[test]
    fn principal_from_request_rejects_missing_connect_info() {
        let req = Request::new(());
        let status = principal_from_request(&req).unwrap_err();
        assert_eq!(status.code(), tonic::Code::PermissionDenied);
    }

    #[test]
    fn principal_from_request_rejects_unauthenticated_peer() {
        let mut req = Request::new(());
        req.extensions_mut().insert(PeerConnectInfo {
            creds: crate::peer::PeerCredentials {
                pid: 1,
                uid: 1000,
                gid: 1000,
            },
            principal: None,
        });
        let status = principal_from_request(&req).unwrap_err();
        assert_eq!(status.code(), tonic::Code::PermissionDenied);
    }
}
