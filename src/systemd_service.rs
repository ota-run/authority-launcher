//                █████
//               ░░███
//       ██████  ███████    ██████
//      ███░░███░░░███░    ░░░░░███
//     ░███ ░███  ░███      ███████
//     ░███ ░███  ░███ ███ ███░░███
//     ░░██████   ░░█████ ░░████████
//      ░░░░░░     ░░░░░   ░░░░░░░░
//
//   Copyright (C) 2026 — 2026, Ota. All Rights Reserved.
//
//   DO NOT ALTER OR REMOVE COPYRIGHT NOTICES OR THIS FILE HEADER.
//
//   Licensed under the Apache License, Version 2.0. See LICENSE for the full license text.
//   You may not use this file except in compliance with the License.
//   Unless required by applicable law or agreed to in writing, software distributed under the
//   License is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND,
//   either express or implied. See the License for the specific language governing permissions
//   and limitations under the License.
//
//   If you need additional information or have any questions, please email: os@ota.run

//! Linux socket-activation admission for the planned protected launcher service.
//!
//! This foundation deliberately stops before lease issuance or selected execution. It proves the
//! service can consume only the fixed listener, derive the connecting job principal through
//! `SO_PEERCRED`, durably prepare an exact stopped Ota child, attach and verify its transient
//! systemd scope, admit that child's exact bounded process-posture preface, and bridge one signed
//! V3 attestation and one exact signed authorization decision. Lease consumption remains disabled
//! and exact cleanup is still mandatory.

use std::env;
use std::io::{Read, Write};
use std::os::fd::{AsRawFd, FromRawFd, RawFd};
use std::os::unix::fs::{FileTypeExt, MetadataExt, PermissionsExt};
use std::os::unix::net::{UnixListener, UnixStream};
use std::path::Path;
use std::time::Duration;

use ota_authority_launcher::linux_observations::{
    ObservedSessionPeer, observe_connected_peer, reconcile_connected_peer,
    revalidate_connected_peer, verify_peer_executable_identity, verify_peer_process_status,
};
use ota_authority_protocol::{
    ATTESTATION_RESPONSE, AuthorizationDecision, LAUNCHER_TERMINAL, LauncherAttestationClaimsV3,
    LauncherAttestationSigningRequestV1, LauncherInvocationRequestV1, LauncherTerminalFrameV1,
    LauncherTerminalOutcomeV1, LauncherTerminalStageV1, LauncherWorkingDirectoryV1,
    MAX_FRAME_BYTES, SYSTEMD_LAUNCHER_SERVICE_PROTOCOL_V1, SYSTEMD_PROTECTED_LAUNCHER_ADAPTER_V1,
    SYSTEMD_PROTECTED_LAUNCHER_ATTESTATION_PROTOCOL_V3, SystemdProtectedLauncherInstanceEvidenceV1,
    decode_frame, encode_frame, launcher_attestation_claims_v3_identity,
    launcher_attestation_signing_request_v1_identity, launcher_invocation_request_identity,
    launcher_working_directory_identity, systemd_job_principal_profile_identity,
    systemd_job_principal_profile_v2, systemd_launcher_profile_identity,
    systemd_launcher_profile_v3, systemd_protected_launcher_instance_v3_foundation_identity,
    validate_launcher_invocation_request_v1, validate_launcher_terminal_frame_v1,
};
use thiserror::Error;

use crate::active_slot::{ActiveSlot, ActiveSlotError};
#[cfg(test)]
use crate::config::SessionPeer;
use crate::config::{
    SYSTEMD_AUTHORITY_LAUNCHER_CONFIG_PATH, SystemdLauncherServiceConfigV1,
    load_systemd_launcher_service_config, systemd_principal_mapping, verify_protected_directory,
};
use crate::installation_manifest::{
    ProtectedInstallationManifestV1, ProtectedInstallationRoleV1,
    load_protected_installation_manifest,
};
use crate::prepared_child::{
    PreparedChildBinding, PreparedChildError, prepare_stopped_child, recorded_child_is_live_exact,
    terminate_recorded_child,
};
use crate::systemd_runtime_observations::verify_systemd_runtime;
use crate::systemd_scope::{ScopeBoundary, SystemdScopeError, SystemdScopeManager};
use crate::target_directory::{TargetDirectoryError, open_repository_directory};

const SYSTEMD_LISTEN_FD: RawFd = 3;
const ACTIVE_SLOT_DIRECTORY: &str = "/var/lib/ota/authority-launcher/active";
const REQUEST_TIMEOUT: Duration = Duration::from_secs(5);
#[cfg(feature = "systemd-pressure-faults")]
const PRESSURE_EXIT_AFTER_SCOPE_MARKER: &str =
    "/run/ota/authority-launcher-pressure-exit-after-scope";
#[cfg(feature = "systemd-pressure-faults")]
const PRESSURE_EXIT_AFTER_SCOPE_CODE: i32 = 86;
#[cfg(feature = "systemd-pressure-faults")]
const PRESSURE_EXIT_AFTER_DECISION_MARKER: &str =
    "/run/ota/authority-launcher-pressure-exit-after-decision";
#[cfg(feature = "systemd-pressure-faults")]
const PRESSURE_EXIT_AFTER_DECISION_CODE: i32 = 87;

#[derive(Debug, Error)]
pub(crate) enum SystemdServiceError {
    #[error("the systemd launcher service must run as root")]
    RootRequired,
    #[error("the systemd launcher listener is unavailable or invalid")]
    ListenerUnavailable,
    #[error("the systemd launcher request is invalid")]
    InvalidRequest,
    #[error("the systemd launcher request peer is not mapped by protected configuration")]
    PeerUnmapped,
    #[error("the systemd launcher request peer posture is unavailable")]
    PeerPostureUnavailable,
    #[error("the systemd launcher repository path is outside protected allowed roots")]
    RepositoryOutsideAllowedRoots,
    #[error(
        "the systemd launcher repository is unavailable to the configured execution principal: {0}"
    )]
    RepositoryUnavailableToExecutionPrincipal(#[source] TargetDirectoryError),
    #[error("the systemd launcher active-slot boundary is unavailable")]
    ActiveSlotUnavailable,
    #[error("the systemd launcher could not prepare the protected Ota child")]
    ChildPreparationFailed,
    #[error("the systemd launcher could not confirm terminal child cleanup")]
    ChildCleanupFailed,
    #[error("the systemd launcher transient scope boundary is unavailable")]
    ScopeUnavailable,
    #[error("the systemd launcher protected broker proxy is unavailable")]
    BrokerProxyUnavailable,
    #[error("the protected launcher installation identity is unavailable or mismatched")]
    InstallationIdentityUnavailable,
    #[error("the protected launcher effective runtime profile is unavailable or mismatched")]
    RuntimeProfileUnavailable,
    #[error("the systemd launcher protocol bridge refused before authorization")]
    PreAuthorizationProtocolRefused,
    #[error("the systemd launcher authorization decision was refused or unavailable")]
    AuthorizationDecisionRefused,
    #[error("the systemd launcher could not confirm terminal scope cleanup")]
    ScopeCleanupFailed,
    #[error("the systemd launcher admission foundation does not yet execute governed work")]
    ExecutionNotEnabled,
}

pub(crate) fn serve_once() -> Result<u8, SystemdServiceError> {
    if unsafe { libc::geteuid() } != 0 {
        return Err(SystemdServiceError::RootRequired);
    }
    let loaded = load_systemd_launcher_service_config(SYSTEMD_AUTHORITY_LAUNCHER_CONFIG_PATH)
        .map_err(|_| SystemdServiceError::ListenerUnavailable)?;
    let config = &loaded.config;
    let launcher_executable = std::env::current_exe()
        .map_err(|_| SystemdServiceError::InstallationIdentityUnavailable)?;
    let installation = load_protected_installation_manifest(config, &launcher_executable)
        .map_err(|_| SystemdServiceError::InstallationIdentityUnavailable)?;
    let listener =
        inherited_systemd_listener(config.socket_path.as_path(), config.socket_group_gid)?;
    reconcile_active_slots(
        Path::new(ACTIVE_SLOT_DIRECTORY),
        0,
        Path::new("/"),
        Duration::from_secs(config.maximum_terminal_wait_seconds),
    )?;
    let (mut stream, _) = listener
        .accept()
        .map_err(|_| SystemdServiceError::ListenerUnavailable)?;
    stream
        .set_read_timeout(Some(REQUEST_TIMEOUT))
        .map_err(|_| SystemdServiceError::ListenerUnavailable)?;
    stream
        .set_write_timeout(Some(REQUEST_TIMEOUT))
        .map_err(|_| SystemdServiceError::ListenerUnavailable)?;

    let peer =
        observe_connected_peer(&stream).map_err(|_| SystemdServiceError::PeerPostureUnavailable)?;
    let request = receive_request(&mut stream, config.maximum_request_bytes)?;
    let mapping = select_mapping(config, &request, &peer)?;
    reconcile_connected_peer(&peer, mapping.job_peer.uid, mapping.job_peer.gid)
        .map_err(|_| SystemdServiceError::PeerPostureUnavailable)?;
    verify_peer_process_status(&peer).map_err(|_| SystemdServiceError::PeerPostureUnavailable)?;
    validate_requested_command(&request)?;

    // A random service-minted ID prevents the client from selecting a terminal carrier. The
    // service creates it before target-principal preparation so every admitted request receives
    // terminal refusal evidence even when directory opening is unavailable.
    let invocation_id = fresh_invocation_id()?;
    let repository = match open_repository_directory(
        config,
        &mapping.execution,
        request.repository_path.as_str(),
    ) {
        Ok(repository) => repository,
        Err(error) => {
            write_terminal(
                &mut stream,
                invocation_id.as_str(),
                LauncherTerminalOutcomeV1::Refused,
                Some(2),
                Some(LauncherTerminalStageV1::RequestRefusedBeforeBoundary),
            )?;
            return Err(map_target_directory_error(error));
        }
    };

    let child_boundary = prepare_disabled_child_boundary(
        config,
        &installation,
        &loaded.ota_binary,
        &repository,
        mapping,
        &request,
        invocation_id.as_str(),
        &stream,
        &peer,
        Path::new(ACTIVE_SLOT_DIRECTORY),
        0,
        Path::new("/"),
    );

    match child_boundary {
        Ok((_prepared_child, decision)) => {
            // Lease issuance and execution remain disabled. Refusal is emitted only after the
            // prepared child was killed, reaped, and removed from the durable active-slot store.
            write_terminal(
                &mut stream,
                invocation_id.as_str(),
                LauncherTerminalOutcomeV1::Refused,
                Some(2),
                Some(match decision {
                    AuthorizationDecision::Allowed => {
                        LauncherTerminalStageV1::AuthorizationDecisionVerifiedBeforeLeaseBoundaryRemoved
                    }
                    AuthorizationDecision::Denied | AuthorizationDecision::Pending => {
                        LauncherTerminalStageV1::AuthorityRefusedBoundaryRemoved
                    }
                }),
            )?;
            Err(SystemdServiceError::ExecutionNotEnabled)
        }
        Err(
            error @ (SystemdServiceError::PreAuthorizationProtocolRefused
            | SystemdServiceError::RuntimeProfileUnavailable),
        ) => {
            write_terminal(
                &mut stream,
                invocation_id.as_str(),
                LauncherTerminalOutcomeV1::Refused,
                Some(2),
                Some(LauncherTerminalStageV1::PreAuthorizationProtocolRefusedBoundaryRemoved),
            )?;
            Err(error)
        }
        Err(
            error @ (SystemdServiceError::BrokerProxyUnavailable
            | SystemdServiceError::AuthorizationDecisionRefused),
        ) => {
            write_terminal(
                &mut stream,
                invocation_id.as_str(),
                LauncherTerminalOutcomeV1::Refused,
                Some(2),
                Some(LauncherTerminalStageV1::PreAuthorizationProtocolRefusedBoundaryRemoved),
            )?;
            Err(error)
        }
        Err(error) => {
            write_terminal(
                &mut stream,
                invocation_id.as_str(),
                LauncherTerminalOutcomeV1::Failed,
                Some(1),
                Some(LauncherTerminalStageV1::BoundaryFailed),
            )?;
            Err(error)
        }
    }
}

#[allow(clippy::too_many_arguments)]
fn prepare_disabled_child_boundary(
    config: &SystemdLauncherServiceConfigV1,
    installation: &ProtectedInstallationManifestV1,
    ota_binary: &std::fs::File,
    repository: &crate::target_directory::OpenedRepositoryDirectory,
    mapping: &crate::config::SystemdPrincipalMappingV1,
    request: &LauncherInvocationRequestV1,
    invocation_id: &str,
    client_stream: &UnixStream,
    peer: &ObservedSessionPeer,
    active_slot_directory: &Path,
    active_slot_owner_uid: u32,
    active_slot_trusted_root: &Path,
) -> Result<
    (
        ota_authority_protocol::LauncherChildProcessV1,
        AuthorizationDecision,
    ),
    SystemdServiceError,
> {
    let scope_manager = SystemdScopeManager::connect().map_err(map_systemd_scope_error)?;
    prepare_disabled_child_boundary_with_scope(
        config,
        ota_binary,
        repository,
        mapping,
        request,
        invocation_id,
        active_slot_directory,
        active_slot_owner_uid,
        active_slot_trusted_root,
        &scope_manager,
        |child, principal_mapping, scope, active_slot| {
            let posture = child
                .resume_and_receive_process_posture(
                    principal_mapping.identity.as_str(),
                    Duration::from_secs(config.maximum_startup_seconds),
                )
                .map_err(|error| pressure_prepared_child_failure("process_posture", error))?;
            let child_record = child.record.clone();
            let (authorization, request_identity) = child
                .continue_to_v3_authorization_request(
                    &posture,
                    Duration::from_secs(config.maximum_startup_seconds),
                    |challenge| {
                        let runtime_identity = verify_systemd_runtime(config, installation, scope)
                            .map_err(|_| pressure_bridge_failure("systemd_runtime"))?;
                        let mut evidence =
                            crate::closed_profile_observations::collect_live_closed_profile_evidence(
                                config,
                                installation,
                                mapping,
                                client_stream,
                                peer,
                                &child_record,
                                scope,
                                &posture,
                                runtime_identity.as_str(),
                            )
                            .map_err(|_| pressure_bridge_failure("closed_profile"))?;
                        produce_attestation(
                            config,
                            installation,
                            principal_mapping,
                            &child_record,
                            scope,
                            &posture,
                            challenge,
                            &mut evidence,
                        )
                        .map_err(|_| pressure_bridge_failure("attestation_producer"))
                    },
                )
                .map_err(|error| pressure_prepared_child_failure("v3_session", error))?;
            let mut proxy = ProtectedBrokerProxy::connect(
                config,
                Duration::from_secs(config.maximum_terminal_wait_seconds),
            )?;
            proxy.run_revalidated(|stream| {
                child
                    .relay_v3_authorization_decisions(
                        &authorization,
                        &request_identity,
                        stream,
                        Duration::from_secs(config.maximum_terminal_wait_seconds),
                        |evidence| {
                            active_slot
                                .record_authorization_decision(evidence.clone())
                                .map_err(|_| {
                                    PreparedChildError::AuthorizationDecisionBridgeUnavailable
                                })?;
                            pressure_exit_after_authorization_decision_recorded().map_err(|_| {
                                PreparedChildError::AuthorizationDecisionBridgeUnavailable
                            })
                        },
                    )
                    .map_err(map_prepared_child_error)
            })
        },
    )
}

fn pressure_bridge_failure(stage: &'static str) -> PreparedChildError {
    #[cfg(feature = "systemd-pressure-faults")]
    eprintln!("ota-authority-launcher: bounded pressure bridge failure stage={stage}");
    #[cfg(not(feature = "systemd-pressure-faults"))]
    let _ = stage;
    PreparedChildError::AttestationBridgeUnavailable
}

fn pressure_prepared_child_failure(
    stage: &'static str,
    error: PreparedChildError,
) -> SystemdServiceError {
    #[cfg(feature = "systemd-pressure-faults")]
    eprintln!("ota-authority-launcher: bounded pressure child failure stage={stage} error={error}");
    #[cfg(not(feature = "systemd-pressure-faults"))]
    let _ = stage;
    map_prepared_child_error(error)
}

#[allow(clippy::too_many_arguments)]
fn produce_attestation(
    config: &SystemdLauncherServiceConfigV1,
    installation: &ProtectedInstallationManifestV1,
    principal_mapping: &ota_authority_protocol::LauncherPrincipalMappingV1,
    child: &ota_authority_protocol::LauncherChildProcessV1,
    scope: &ota_authority_protocol::LauncherSystemdScopeV1,
    posture: &ota_authority_protocol::OtaProcessPostureV1,
    challenge: &ota_authority_protocol::BrokerChallenge,
    evidence: &mut crate::closed_profile_observations::LiveClosedProfileEvidence,
) -> Result<ota_authority_protocol::SignedLauncherAttestationV3, SystemdServiceError> {
    let claim_config = config
        .attestation_claims
        .as_ref()
        .ok_or(SystemdServiceError::RuntimeProfileUnavailable)?;
    let producer = ota_authority_launcher::attestation_client::load_producer_binding()
        .map_err(|_| SystemdServiceError::RuntimeProfileUnavailable)?;
    let launcher_profile_identity =
        systemd_launcher_profile_identity(&systemd_launcher_profile_v3())
            .map_err(|_| SystemdServiceError::RuntimeProfileUnavailable)?;
    let launcher_executable_identity = installation
        .singular_identity(ProtectedInstallationRoleV1::LauncherExecutable)
        .map_err(|_| SystemdServiceError::RuntimeProfileUnavailable)?;
    if producer.launcher_service_binding_identity != config.service_unit_identity
        || producer.launcher_configuration_identity != config.identity
        || producer.launcher_profile_identity != launcher_profile_identity
        || producer.launcher_executable_identity != launcher_executable_identity
        || producer.verifier_key_set_identity != config.attestor_key_set_identity
    {
        return Err(SystemdServiceError::RuntimeProfileUnavailable);
    }

    let job_profile_identity =
        systemd_job_principal_profile_identity(&systemd_job_principal_profile_v2())
            .map_err(|_| SystemdServiceError::RuntimeProfileUnavailable)?;
    let mut instance = SystemdProtectedLauncherInstanceEvidenceV1 {
        schema_version: 1,
        identity: String::new(),
        adapter: SYSTEMD_PROTECTED_LAUNCHER_ADAPTER_V1.into(),
        principal_mapping: principal_mapping.clone(),
        process_posture: posture.clone(),
        systemd_launcher_profile_identity: launcher_profile_identity.clone(),
        systemd_job_principal_profile_identity: job_profile_identity,
        launcher_session_binding_identity: config.identity.clone(),
        systemd_invocation_identity: scope.identity.clone(),
        working_directory_identity: child.working_directory_identity.clone(),
        child_process_identity: child.identity.clone(),
    };
    instance.identity = systemd_protected_launcher_instance_v3_foundation_identity(&instance)
        .map_err(|_| SystemdServiceError::RuntimeProfileUnavailable)?;
    let complete =
        ota_authority_launcher::observation_collector::collect_closed_profile(instance, evidence)
            .map_err(|_| SystemdServiceError::RuntimeProfileUnavailable)?;
    let claims = LauncherAttestationClaimsV3 {
        message_kind: ATTESTATION_RESPONSE.into(),
        attestation_protocol_version: SYSTEMD_PROTECTED_LAUNCHER_ATTESTATION_PROTOCOL_V3.into(),
        binding_identity: challenge.binding_identity.clone(),
        challenge_nonce_commitment: challenge.nonce_commitment.clone(),
        invocation_id: child.invocation_id.clone(),
        work_unit_identity: challenge.work_unit_identity.clone(),
        semantic_scope_identity: challenge.semantic_scope_identity.clone(),
        runner_principal: principal_mapping.identity.clone(),
        channel_delivery: String::from("launcher_session_fd"),
        authenticated_origin: claim_config.authenticated_origin.clone(),
        authority_mounts: claim_config.authority_mounts.clone(),
        systemd_protected_launcher: complete,
        issuer: producer.issuer.clone(),
        audience: producer.audience.clone(),
    };
    let claims_identity = launcher_attestation_claims_v3_identity(&claims)
        .map_err(|_| SystemdServiceError::RuntimeProfileUnavailable)?;
    let mut request = LauncherAttestationSigningRequestV1 {
        schema_version: 1,
        message_kind: ota_authority_protocol::LAUNCHER_ATTESTATION_SIGNING_REQUEST.into(),
        request_identity: String::new(),
        challenge: challenge.clone(),
        claims_identity,
        claims,
        launcher_service_binding_identity: config.service_unit_identity.clone(),
        launcher_configuration_identity: config.identity.clone(),
        launcher_executable_identity: launcher_executable_identity.to_owned(),
        launcher_profile_identity,
        producer_binding_identity: producer.identity.clone(),
        producer_audience: producer.audience.clone(),
        requested_maximum_validity_seconds: claim_config.requested_maximum_validity_seconds,
    };
    request.request_identity = launcher_attestation_signing_request_v1_identity(&request)
        .map_err(|_| SystemdServiceError::RuntimeProfileUnavailable)?;
    let response =
        ota_authority_launcher::attestation_client::request_attestation(&producer, &request)
            .map_err(|_| SystemdServiceError::RuntimeProfileUnavailable)?;
    Ok(response.attestation)
}

struct ProtectedBrokerProxy {
    stream: UnixStream,
    peer: ObservedSessionPeer,
    executable_identity: String,
}

impl ProtectedBrokerProxy {
    fn connect(
        config: &SystemdLauncherServiceConfigV1,
        timeout: Duration,
    ) -> Result<Self, SystemdServiceError> {
        let path = config.broker_proxy_socket.as_path();
        let parent = path
            .parent()
            .ok_or(SystemdServiceError::BrokerProxyUnavailable)?;
        verify_protected_directory(parent, 0, Path::new("/"))
            .map_err(|_| SystemdServiceError::BrokerProxyUnavailable)?;
        let metadata = std::fs::symlink_metadata(path)
            .map_err(|_| SystemdServiceError::BrokerProxyUnavailable)?;
        if !metadata.file_type().is_socket()
            || metadata.uid() != config.broker_proxy_peer.uid
            || metadata.gid() != config.broker_proxy_peer.gid
            || metadata.permissions().mode() & 0o7777 != 0o600
        {
            return Err(SystemdServiceError::BrokerProxyUnavailable);
        }
        let stream =
            UnixStream::connect(path).map_err(|_| SystemdServiceError::BrokerProxyUnavailable)?;
        stream
            .set_read_timeout(Some(timeout))
            .and_then(|()| stream.set_write_timeout(Some(timeout)))
            .map_err(|_| SystemdServiceError::BrokerProxyUnavailable)?;
        let peer = observe_connected_peer(&stream)
            .map_err(|_| SystemdServiceError::BrokerProxyUnavailable)?;
        reconcile_connected_peer(
            &peer,
            config.broker_proxy_peer.uid,
            config.broker_proxy_peer.gid,
        )
        .map_err(|_| SystemdServiceError::BrokerProxyUnavailable)?;
        verify_peer_executable_identity(&peer, &config.broker_proxy_executable_identity)
            .map_err(|_| SystemdServiceError::BrokerProxyUnavailable)?;
        let proxy = Self {
            stream,
            peer,
            executable_identity: config.broker_proxy_executable_identity.clone(),
        };
        proxy.revalidate()?;
        Ok(proxy)
    }

    fn revalidate(&self) -> Result<(), SystemdServiceError> {
        revalidate_connected_peer(&self.stream, &self.peer)
            .and_then(|()| verify_peer_executable_identity(&self.peer, &self.executable_identity))
            .map_err(|_| SystemdServiceError::BrokerProxyUnavailable)
    }

    fn run_revalidated<T>(
        &mut self,
        operation: impl FnOnce(&mut UnixStream) -> Result<T, SystemdServiceError>,
    ) -> Result<T, SystemdServiceError> {
        self.revalidate()?;
        let result = operation(&mut self.stream);
        self.revalidate()?;
        result
    }
}

#[allow(clippy::too_many_arguments)]
fn prepare_disabled_child_boundary_with_scope<F>(
    config: &SystemdLauncherServiceConfigV1,
    ota_binary: &std::fs::File,
    repository: &crate::target_directory::OpenedRepositoryDirectory,
    mapping: &crate::config::SystemdPrincipalMappingV1,
    request: &LauncherInvocationRequestV1,
    invocation_id: &str,
    active_slot_directory: &Path,
    active_slot_owner_uid: u32,
    active_slot_trusted_root: &Path,
    scope_manager: &impl ScopeBoundary,
    posture_gate: F,
) -> Result<
    (
        ota_authority_protocol::LauncherChildProcessV1,
        AuthorizationDecision,
    ),
    SystemdServiceError,
>
where
    F: FnOnce(
        &mut crate::prepared_child::PreparedChild,
        &ota_authority_protocol::LauncherPrincipalMappingV1,
        &ota_authority_protocol::LauncherSystemdScopeV1,
        &mut ActiveSlot,
    ) -> Result<AuthorizationDecision, SystemdServiceError>,
{
    let request_identity = launcher_invocation_request_identity(request)
        .map_err(|_| SystemdServiceError::InvalidRequest)?;
    let principal_mapping = systemd_principal_mapping(config, mapping)
        .map_err(|_| SystemdServiceError::ActiveSlotUnavailable)?;
    let mut working_directory = LauncherWorkingDirectoryV1 {
        schema_version: 1,
        identity: String::new(),
        logical_path: request.repository_path.clone(),
        device: repository.device,
        inode: repository.inode,
    };
    working_directory.identity = launcher_working_directory_identity(&working_directory)
        .map_err(|_| SystemdServiceError::ActiveSlotUnavailable)?;
    let mut active_slot = ActiveSlot::begin(
        active_slot_directory,
        active_slot_owner_uid,
        active_slot_trusted_root,
        invocation_id,
        principal_mapping.identity.as_str(),
        request_identity.as_str(),
        working_directory.clone(),
    )
    .map_err(map_active_slot_error)?;
    let mut child = match prepare_stopped_child(
        config,
        ota_binary,
        repository,
        &mapping.execution,
        &PreparedChildBinding {
            invocation_id,
            request_identity: request_identity.as_str(),
            principal_mapping_identity: principal_mapping.identity.as_str(),
            working_directory_identity: working_directory.identity.as_str(),
        },
        request.ota_arguments.as_slice(),
    ) {
        Ok(child) => child,
        Err(error) => return Err(preparation_failure(active_slot, error)),
    };
    if active_slot.record_child(child.record.clone()).is_err() {
        child
            .terminate_and_reap()
            .map_err(|_| SystemdServiceError::ChildCleanupFailed)?;
        active_slot
            .finalize()
            .map_err(|_| SystemdServiceError::ChildCleanupFailed)?;
        return Err(SystemdServiceError::ActiveSlotUnavailable);
    }
    let scope = match scope_manager.attach_stopped_child(
        invocation_id,
        request_identity.as_str(),
        &child.record,
        Duration::from_secs(config.maximum_startup_seconds),
    ) {
        Ok(scope) => scope,
        Err(error) => {
            child
                .terminate_and_reap()
                .map_err(|_| SystemdServiceError::ChildCleanupFailed)?;
            if error == SystemdScopeError::CleanupFailed {
                return Err(SystemdServiceError::ScopeCleanupFailed);
            }
            active_slot
                .finalize()
                .map_err(|_| SystemdServiceError::ChildCleanupFailed)?;
            return Err(map_systemd_scope_error(error));
        }
    };
    if active_slot.record_scope(scope.clone()).is_err() {
        scope_manager
            .stop_and_confirm_empty(
                &scope,
                &child.record,
                Duration::from_secs(config.maximum_terminal_wait_seconds),
            )
            .map_err(|_| SystemdServiceError::ScopeCleanupFailed)?;
        child
            .terminate_and_reap()
            .map_err(|_| SystemdServiceError::ChildCleanupFailed)?;
        active_slot
            .finalize()
            .map_err(|_| SystemdServiceError::ChildCleanupFailed)?;
        return Err(SystemdServiceError::ActiveSlotUnavailable);
    }
    if let Err(error) = pressure_exit_after_scope_recorded() {
        scope_manager
            .stop_and_confirm_empty(
                &scope,
                &child.record,
                Duration::from_secs(config.maximum_terminal_wait_seconds),
            )
            .map_err(|_| SystemdServiceError::ScopeCleanupFailed)?;
        child
            .terminate_and_reap()
            .map_err(|_| SystemdServiceError::ChildCleanupFailed)?;
        active_slot
            .finalize()
            .map_err(|_| SystemdServiceError::ChildCleanupFailed)?;
        return Err(error);
    }
    let posture_result = posture_gate(&mut child, &principal_mapping, &scope, &mut active_slot);
    let child_record = child.record.clone();
    scope_manager
        .stop_and_confirm_empty(
            &scope,
            &child.record,
            Duration::from_secs(config.maximum_terminal_wait_seconds),
        )
        .map_err(|_| SystemdServiceError::ScopeCleanupFailed)?;
    child
        .terminate_and_reap()
        .map_err(|_| SystemdServiceError::ChildCleanupFailed)?;
    active_slot
        .finalize()
        .map_err(|_| SystemdServiceError::ChildCleanupFailed)?;
    let decision = posture_result?;
    Ok((child_record, decision))
}

#[cfg(feature = "systemd-pressure-faults")]
fn pressure_exit_after_scope_recorded() -> Result<(), SystemdServiceError> {
    if !consume_pressure_exit_marker(
        Path::new(PRESSURE_EXIT_AFTER_SCOPE_MARKER),
        Path::new("/"),
        0,
    )? {
        return Ok(());
    }

    // The pressure-only build exits without unwinding after the root-owned one-shot marker is
    // durably consumed. The active-slot journal, stopped child, and exact scope must then be
    // reconciled by the next socket activation before another request is accepted.
    unsafe { libc::_exit(PRESSURE_EXIT_AFTER_SCOPE_CODE) }
}

#[cfg(not(feature = "systemd-pressure-faults"))]
fn pressure_exit_after_scope_recorded() -> Result<(), SystemdServiceError> {
    Ok(())
}

#[cfg(feature = "systemd-pressure-faults")]
fn pressure_exit_after_authorization_decision_recorded() -> Result<(), SystemdServiceError> {
    if !consume_pressure_exit_marker(
        Path::new(PRESSURE_EXIT_AFTER_DECISION_MARKER),
        Path::new("/"),
        0,
    )? {
        return Ok(());
    }

    // The durable decision envelope must survive this abrupt exit so startup recovery can prove
    // cleanup-only reconciliation without resuming the child or requesting a lease.
    unsafe { libc::_exit(PRESSURE_EXIT_AFTER_DECISION_CODE) }
}

#[cfg(not(feature = "systemd-pressure-faults"))]
fn pressure_exit_after_authorization_decision_recorded() -> Result<(), SystemdServiceError> {
    Ok(())
}

#[cfg(feature = "systemd-pressure-faults")]
fn consume_pressure_exit_marker(
    path: &Path,
    trusted_root: &Path,
    expected_owner_uid: u32,
) -> Result<bool, SystemdServiceError> {
    let metadata = match std::fs::symlink_metadata(path) {
        Ok(metadata) => metadata,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(false),
        Err(_) => return Err(SystemdServiceError::ActiveSlotUnavailable),
    };
    let parent = path
        .parent()
        .ok_or(SystemdServiceError::ActiveSlotUnavailable)?;
    verify_protected_directory(parent, expected_owner_uid, trusted_root)
        .map_err(|_| SystemdServiceError::ActiveSlotUnavailable)?;
    if !metadata.file_type().is_file()
        || metadata.uid() != expected_owner_uid
        || metadata.permissions().mode() & 0o777 != 0o600
        || metadata.nlink() != 1
    {
        return Err(SystemdServiceError::ActiveSlotUnavailable);
    }
    std::fs::remove_file(path).map_err(|_| SystemdServiceError::ActiveSlotUnavailable)?;
    std::fs::File::open(parent)
        .and_then(|directory| directory.sync_all())
        .map_err(|_| SystemdServiceError::ActiveSlotUnavailable)?;
    Ok(true)
}

fn map_systemd_scope_error(error: SystemdScopeError) -> SystemdServiceError {
    match error {
        SystemdScopeError::CleanupFailed => SystemdServiceError::ScopeCleanupFailed,
        _ => SystemdServiceError::ScopeUnavailable,
    }
}

fn map_active_slot_error(_error: ActiveSlotError) -> SystemdServiceError {
    SystemdServiceError::ActiveSlotUnavailable
}

fn map_prepared_child_error(error: PreparedChildError) -> SystemdServiceError {
    match error {
        PreparedChildError::CleanupFailed => SystemdServiceError::ChildCleanupFailed,
        PreparedChildError::AttestationBridgeUnavailable
        | PreparedChildError::AuthorizationAdmissionMismatch => {
            SystemdServiceError::PreAuthorizationProtocolRefused
        }
        PreparedChildError::AuthorizationDecisionBridgeUnavailable => {
            SystemdServiceError::AuthorizationDecisionRefused
        }
        _ => SystemdServiceError::ChildPreparationFailed,
    }
}

fn preparation_failure(active_slot: ActiveSlot, error: PreparedChildError) -> SystemdServiceError {
    if error == PreparedChildError::CleanupFailed {
        return SystemdServiceError::ChildCleanupFailed;
    }
    if active_slot.finalize().is_err() {
        return SystemdServiceError::ChildCleanupFailed;
    }
    map_prepared_child_error(error)
}

fn reconcile_active_slots(
    active_slot_directory: &Path,
    active_slot_owner_uid: u32,
    active_slot_trusted_root: &Path,
    cleanup_timeout: Duration,
) -> Result<(), SystemdServiceError> {
    let slots = ActiveSlot::load_all(
        active_slot_directory,
        active_slot_owner_uid,
        active_slot_trusted_root,
    )
    .map_err(map_active_slot_error)?;
    if slots.is_empty() {
        return Ok(());
    }
    let scope_manager =
        SystemdScopeManager::connect().map_err(|_| SystemdServiceError::ScopeCleanupFailed)?;
    reconcile_loaded_slots(slots, &scope_manager, cleanup_timeout)
}

fn reconcile_loaded_slots(
    slots: Vec<ActiveSlot>,
    scope_manager: &impl ScopeBoundary,
    cleanup_timeout: Duration,
) -> Result<(), SystemdServiceError> {
    let mut failure = None;
    for slot in slots {
        let Some(child) = slot.child() else {
            if failure.is_none() {
                failure = Some(SystemdServiceError::ActiveSlotUnavailable);
            }
            continue;
        };
        if let Some(scope) = slot.scope() {
            match scope_manager.stop_and_confirm_empty(scope, child, cleanup_timeout) {
                Ok(()) => {}
                Err(SystemdScopeError::ScopeAbsent) => {
                    match recorded_child_is_live_exact(child) {
                        Ok(false) => {
                            if slot.finalize().is_err() {
                                failure = Some(SystemdServiceError::ChildCleanupFailed);
                            }
                            continue;
                        }
                        Ok(true) => {
                            let _ = terminate_recorded_child(child, cleanup_timeout);
                        }
                        Err(_) => {}
                    }
                    failure = Some(SystemdServiceError::ScopeCleanupFailed);
                    continue;
                }
                Err(_) => {
                    failure = Some(SystemdServiceError::ScopeCleanupFailed);
                    continue;
                }
            }
        } else if scope_manager
            .recover_unrecorded_scope(
                child.invocation_id.as_str(),
                child.request_identity.as_str(),
                child,
                cleanup_timeout,
            )
            .is_err()
        {
            failure = Some(SystemdServiceError::ScopeCleanupFailed);
            continue;
        }
        if terminate_recorded_child(child, cleanup_timeout).is_err() {
            failure = Some(SystemdServiceError::ChildCleanupFailed);
            continue;
        }
        if slot.finalize().is_err() {
            failure = Some(SystemdServiceError::ChildCleanupFailed);
        }
    }
    if let Some(error) = failure {
        return Err(error);
    }
    Ok(())
}

fn validate_requested_command(
    request: &LauncherInvocationRequestV1,
) -> Result<(), SystemdServiceError> {
    crate::validate_ota_args(&request.ota_arguments)
        .map_err(|_| SystemdServiceError::InvalidRequest)
}

fn map_target_directory_error(error: TargetDirectoryError) -> SystemdServiceError {
    match error {
        TargetDirectoryError::OutsideAllowedRoots => {
            SystemdServiceError::RepositoryOutsideAllowedRoots
        }
        _ => SystemdServiceError::RepositoryUnavailableToExecutionPrincipal(error),
    }
}

fn inherited_systemd_listener(
    expected_path: &Path,
    expected_group_gid: u32,
) -> Result<UnixListener, SystemdServiceError> {
    let expected_pid = unsafe { libc::getpid() }.to_string();
    if env::var("LISTEN_PID").ok().as_deref() != Some(expected_pid.as_str())
        || env::var("LISTEN_FDS").ok().as_deref() != Some("1")
    {
        return Err(SystemdServiceError::ListenerUnavailable);
    }
    set_cloexec(SYSTEMD_LISTEN_FD)?;
    verify_listener_socket(SYSTEMD_LISTEN_FD)?;
    // SAFETY: the descriptor was verified as a listening AF_UNIX stream and ownership transfers
    // once to the returned listener.
    let listener = unsafe { UnixListener::from_raw_fd(SYSTEMD_LISTEN_FD) };
    if listener
        .local_addr()
        .ok()
        .and_then(|address| address.as_pathname().map(Path::to_path_buf))
        != Some(expected_path.to_path_buf())
    {
        return Err(SystemdServiceError::ListenerUnavailable);
    }
    verify_listener_path(&listener, expected_path, expected_group_gid)?;
    Ok(listener)
}

fn verify_listener_path(
    listener: &UnixListener,
    expected_path: &Path,
    expected_group_gid: u32,
) -> Result<(), SystemdServiceError> {
    verify_protected_directory(
        expected_path
            .parent()
            .ok_or(SystemdServiceError::ListenerUnavailable)?,
        0,
        Path::new("/"),
    )
    .map_err(|_| SystemdServiceError::ListenerUnavailable)?;
    let metadata = std::fs::symlink_metadata(expected_path)
        .map_err(|_| SystemdServiceError::ListenerUnavailable)?;
    let mut opened: libc::stat = unsafe { std::mem::zeroed() };
    if unsafe { libc::fstat(listener.as_raw_fd(), &mut opened) } != 0 {
        return Err(SystemdServiceError::ListenerUnavailable);
    }
    if !metadata.file_type().is_socket()
        || metadata.uid() != 0
        || metadata.gid() != expected_group_gid
        || metadata.mode() & 0o7777 != 0o660
        || opened.st_mode & libc::S_IFMT != libc::S_IFSOCK
        || opened.st_uid != 0
    {
        return Err(SystemdServiceError::ListenerUnavailable);
    }
    Ok(())
}

fn receive_request(
    stream: &mut UnixStream,
    maximum_request_bytes: usize,
) -> Result<LauncherInvocationRequestV1, SystemdServiceError> {
    let mut header = [0_u8; 4];
    stream
        .read_exact(&mut header)
        .map_err(|_| SystemdServiceError::InvalidRequest)?;
    let length = u32::from_be_bytes(header) as usize;
    if length == 0 || length > maximum_request_bytes || length > MAX_FRAME_BYTES {
        return Err(SystemdServiceError::InvalidRequest);
    }
    let mut frame = Vec::with_capacity(4 + length);
    frame.extend_from_slice(&header);
    frame.resize(4 + length, 0);
    stream
        .read_exact(&mut frame[4..])
        .map_err(|_| SystemdServiceError::InvalidRequest)?;
    let payload = decode_frame(&frame).map_err(|_| SystemdServiceError::InvalidRequest)?;
    let request =
        serde_json::from_slice(payload).map_err(|_| SystemdServiceError::InvalidRequest)?;
    validate_launcher_invocation_request_v1(&request)
        .map_err(|_| SystemdServiceError::InvalidRequest)?;
    Ok(request)
}

fn select_mapping<'a>(
    config: &'a SystemdLauncherServiceConfigV1,
    request: &LauncherInvocationRequestV1,
    peer: &ObservedSessionPeer,
) -> Result<&'a crate::config::SystemdPrincipalMappingV1, SystemdServiceError> {
    config
        .mappings
        .iter()
        .find(|mapping| {
            mapping.authority_id == request.authority_id
                && mapping.job_peer.uid == peer.uid
                && mapping.job_peer.gid == peer.gid
        })
        .ok_or(SystemdServiceError::PeerUnmapped)
}

fn write_terminal(
    stream: &mut UnixStream,
    invocation_id: &str,
    outcome: LauncherTerminalOutcomeV1,
    exit_code: Option<i32>,
    stage: Option<LauncherTerminalStageV1>,
) -> Result<(), SystemdServiceError> {
    let terminal = LauncherTerminalFrameV1 {
        message_kind: LAUNCHER_TERMINAL.into(),
        protocol_version: SYSTEMD_LAUNCHER_SERVICE_PROTOCOL_V1.into(),
        invocation_id: invocation_id.into(),
        outcome,
        exit_code,
        stage,
    };
    validate_launcher_terminal_frame_v1(&terminal)
        .map_err(|_| SystemdServiceError::InvalidRequest)?;
    let payload = serde_json::to_vec(&terminal).map_err(|_| SystemdServiceError::InvalidRequest)?;
    let frame =
        encode_frame(payload.as_slice()).map_err(|_| SystemdServiceError::InvalidRequest)?;
    stream
        .write_all(&frame)
        .map_err(|_| SystemdServiceError::InvalidRequest)
}

fn fresh_invocation_id() -> Result<String, SystemdServiceError> {
    let mut random = [0_u8; 16];
    getrandom::getrandom(&mut random).map_err(|_| SystemdServiceError::InvalidRequest)?;
    let mut identity = String::from("invocation-");
    for byte in random {
        use std::fmt::Write as _;
        write!(&mut identity, "{byte:02x}").expect("writing to String cannot fail");
    }
    Ok(identity)
}

fn set_cloexec(descriptor: RawFd) -> Result<(), SystemdServiceError> {
    // SAFETY: `fcntl` only reads and updates flags on the supplied descriptor.
    let flags = unsafe { libc::fcntl(descriptor, libc::F_GETFD) };
    if flags < 0 || unsafe { libc::fcntl(descriptor, libc::F_SETFD, flags | libc::FD_CLOEXEC) } < 0
    {
        return Err(SystemdServiceError::ListenerUnavailable);
    }
    Ok(())
}

fn verify_listener_socket(descriptor: RawFd) -> Result<(), SystemdServiceError> {
    let mut socket_type = 0_i32;
    let mut length = std::mem::size_of::<i32>() as libc::socklen_t;
    // SAFETY: `socket_type` is a valid writable buffer for `SO_TYPE`.
    let result = unsafe {
        libc::getsockopt(
            descriptor,
            libc::SOL_SOCKET,
            libc::SO_TYPE,
            (&mut socket_type as *mut i32).cast(),
            &mut length,
        )
    };
    if result != 0
        || socket_type != libc::SOCK_STREAM
        || length != std::mem::size_of::<i32>() as libc::socklen_t
    {
        return Err(SystemdServiceError::ListenerUnavailable);
    }
    let mut accepts_connections = 0_i32;
    let mut length = std::mem::size_of::<i32>() as libc::socklen_t;
    // SAFETY: `accepts_connections` is a valid writable buffer for `SO_ACCEPTCONN`.
    let result = unsafe {
        libc::getsockopt(
            descriptor,
            libc::SOL_SOCKET,
            libc::SO_ACCEPTCONN,
            (&mut accepts_connections as *mut i32).cast(),
            &mut length,
        )
    };
    if result != 0
        || accepts_connections != 1
        || length != std::mem::size_of::<i32>() as libc::socklen_t
    {
        return Err(SystemdServiceError::ListenerUnavailable);
    }
    let mut address: libc::sockaddr_storage = unsafe { std::mem::zeroed() };
    let mut address_length = std::mem::size_of::<libc::sockaddr_storage>() as libc::socklen_t;
    // SAFETY: `address` is a correctly sized writable address buffer for `getsockname`.
    let result = unsafe {
        libc::getsockname(
            descriptor,
            (&mut address as *mut libc::sockaddr_storage).cast(),
            &mut address_length,
        )
    };
    if result != 0 || address.ss_family as libc::c_int != libc::AF_UNIX {
        return Err(SystemdServiceError::ListenerUnavailable);
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use std::cell::{Cell, RefCell};
    use std::collections::BTreeMap;
    use std::fs;
    use std::os::unix::ffi::OsStrExt;
    use std::os::unix::fs::{MetadataExt, PermissionsExt};
    use std::path::PathBuf;

    use tempfile::tempdir;

    use super::*;

    #[test]
    fn protected_broker_proxy_refuses_peer_exit_during_bridge() {
        let temporary = tempdir().expect("temporary broker socket directory");
        let socket_path = temporary.path().join("broker.sock");
        let listener = UnixListener::bind(&socket_path).expect("broker listener");

        let peer_pid = unsafe { libc::fork() };
        assert!(peer_pid >= 0, "fork must succeed");
        if peer_pid == 0 {
            drop(listener);
            let result = UnixStream::connect(&socket_path).and_then(|mut stream| {
                stream.write_all(b"ready")?;
                unsafe { libc::pause() };
                Ok(())
            });
            unsafe { libc::_exit(if result.is_ok() { 0 } else { 90 }) };
        }

        let (mut stream, _) = listener.accept().expect("accepted broker peer");
        let mut ready = [0_u8; 5];
        stream.read_exact(&mut ready).expect("broker peer ready");
        assert_eq!(&ready, b"ready");
        let peer = observe_connected_peer(&stream).expect("guarded broker peer");
        let mut executable = std::fs::File::open("/proc/self/exe").expect("test executable");
        let executable_identity =
            crate::config::sha256_file_identity(&mut executable).expect("executable identity");
        let mut proxy = ProtectedBrokerProxy {
            stream,
            peer,
            executable_identity,
        };

        let result = proxy.run_revalidated(|_| {
            unsafe {
                libc::kill(peer_pid, libc::SIGKILL);
                libc::waitpid(peer_pid, std::ptr::null_mut(), 0);
            }
            Ok(())
        });

        assert!(matches!(
            result,
            Err(SystemdServiceError::BrokerProxyUnavailable)
        ));
    }

    #[cfg(feature = "systemd-pressure-faults")]
    #[test]
    fn pressure_crash_marker_enforces_protected_one_shot_identity() {
        let temporary = tempdir().expect("temporary pressure root");
        let owner_uid = unsafe { libc::geteuid() };
        fs::set_permissions(temporary.path(), fs::Permissions::from_mode(0o700))
            .expect("protected pressure root");
        let pressure = temporary.path().join("pressure");
        fs::create_dir(&pressure).expect("pressure directory");
        fs::set_permissions(&pressure, fs::Permissions::from_mode(0o700))
            .expect("protected pressure directory");
        let marker = pressure.join("exit-after-scope");

        fs::write(&marker, b"1").expect("pressure marker");
        fs::set_permissions(&marker, fs::Permissions::from_mode(0o644))
            .expect("unprotected marker permissions");
        assert!(matches!(
            consume_pressure_exit_marker(&marker, temporary.path(), owner_uid),
            Err(SystemdServiceError::ActiveSlotUnavailable)
        ));

        fs::set_permissions(&marker, fs::Permissions::from_mode(0o600))
            .expect("protected marker permissions");
        let hardlink = pressure.join("hardlink");
        fs::hard_link(&marker, &hardlink).expect("hardlink marker");
        assert!(matches!(
            consume_pressure_exit_marker(&marker, temporary.path(), owner_uid),
            Err(SystemdServiceError::ActiveSlotUnavailable)
        ));
        fs::remove_file(&hardlink).expect("remove hardlink");

        assert!(matches!(
            consume_pressure_exit_marker(&marker, temporary.path(), owner_uid.wrapping_add(1)),
            Err(SystemdServiceError::ActiveSlotUnavailable)
        ));

        fs::remove_file(&marker).expect("remove regular marker");
        let symlink_target = pressure.join("target");
        fs::write(&symlink_target, b"1").expect("symlink target");
        fs::set_permissions(&symlink_target, fs::Permissions::from_mode(0o600))
            .expect("symlink target permissions");
        std::os::unix::fs::symlink(&symlink_target, &marker).expect("symlink marker");
        assert!(matches!(
            consume_pressure_exit_marker(&marker, temporary.path(), owner_uid),
            Err(SystemdServiceError::ActiveSlotUnavailable)
        ));
        fs::remove_file(&marker).expect("remove symlink marker");

        fs::write(&marker, b"1").expect("replacement pressure marker");
        fs::set_permissions(&marker, fs::Permissions::from_mode(0o600))
            .expect("replacement marker permissions");
        fs::set_permissions(&pressure, fs::Permissions::from_mode(0o720))
            .expect("writable pressure directory");
        assert!(matches!(
            consume_pressure_exit_marker(&marker, temporary.path(), owner_uid),
            Err(SystemdServiceError::ActiveSlotUnavailable)
        ));
        fs::set_permissions(&pressure, fs::Permissions::from_mode(0o700))
            .expect("restore pressure directory");

        assert!(
            consume_pressure_exit_marker(&marker, temporary.path(), owner_uid)
                .expect("consume protected marker")
        );
        assert!(!marker.exists());
        assert!(
            !consume_pressure_exit_marker(&marker, temporary.path(), owner_uid)
                .expect("marker is one shot")
        );
    }

    #[derive(Default)]
    struct RecordingScopeBoundary {
        attached: RefCell<Vec<ota_authority_protocol::LauncherSystemdScopeV1>>,
        stopped: RefCell<Vec<String>>,
    }

    struct UncertainScopeBoundary;
    struct AbsentScopeBoundary;

    impl ScopeBoundary for AbsentScopeBoundary {
        fn attach_stopped_child(
            &self,
            _invocation_id: &str,
            _request_identity: &str,
            _child: &ota_authority_protocol::LauncherChildProcessV1,
            _timeout: Duration,
        ) -> Result<ota_authority_protocol::LauncherSystemdScopeV1, SystemdScopeError> {
            Err(SystemdScopeError::ScopeAbsent)
        }

        fn stop_and_confirm_empty(
            &self,
            _expected: &ota_authority_protocol::LauncherSystemdScopeV1,
            _child: &ota_authority_protocol::LauncherChildProcessV1,
            _timeout: Duration,
        ) -> Result<(), SystemdScopeError> {
            Err(SystemdScopeError::ScopeAbsent)
        }

        fn recover_unrecorded_scope(
            &self,
            _invocation_id: &str,
            _request_identity: &str,
            _child: &ota_authority_protocol::LauncherChildProcessV1,
            _timeout: Duration,
        ) -> Result<(), SystemdScopeError> {
            Ok(())
        }
    }

    impl ScopeBoundary for UncertainScopeBoundary {
        fn attach_stopped_child(
            &self,
            _invocation_id: &str,
            _request_identity: &str,
            _child: &ota_authority_protocol::LauncherChildProcessV1,
            _timeout: Duration,
        ) -> Result<ota_authority_protocol::LauncherSystemdScopeV1, SystemdScopeError> {
            Err(SystemdScopeError::CleanupFailed)
        }

        fn stop_and_confirm_empty(
            &self,
            _expected: &ota_authority_protocol::LauncherSystemdScopeV1,
            _child: &ota_authority_protocol::LauncherChildProcessV1,
            _timeout: Duration,
        ) -> Result<(), SystemdScopeError> {
            Err(SystemdScopeError::CleanupFailed)
        }

        fn recover_unrecorded_scope(
            &self,
            _invocation_id: &str,
            _request_identity: &str,
            _child: &ota_authority_protocol::LauncherChildProcessV1,
            _timeout: Duration,
        ) -> Result<(), SystemdScopeError> {
            Err(SystemdScopeError::CleanupFailed)
        }
    }

    impl ScopeBoundary for RecordingScopeBoundary {
        fn attach_stopped_child(
            &self,
            invocation_id: &str,
            request_identity: &str,
            child: &ota_authority_protocol::LauncherChildProcessV1,
            _timeout: Duration,
        ) -> Result<ota_authority_protocol::LauncherSystemdScopeV1, SystemdScopeError> {
            let digest = request_identity
                .strip_prefix("sha256:")
                .ok_or(SystemdScopeError::ScopeMismatch)?;
            let unit_name = format!("ota-authority-invocation-{digest}.scope");
            let mut scope = ota_authority_protocol::LauncherSystemdScopeV1 {
                schema_version: 1,
                identity: String::new(),
                invocation_id: invocation_id.into(),
                request_identity: request_identity.into(),
                child_identity: child.identity.clone(),
                child_pid: child.pid,
                unit_name: unit_name.clone(),
                unit_object_path: format!("/org/freedesktop/systemd1/unit/{unit_name}"),
                slice: crate::systemd_scope::INVOCATION_SLICE.into(),
                control_group: format!("/ota-authority-invocations.slice/{unit_name}"),
                delegate: false,
                kill_mode: String::from("control-group"),
                collect_mode: String::from("inactive-or-failed"),
            };
            scope.identity = ota_authority_protocol::launcher_systemd_scope_identity(&scope)
                .map_err(|_| SystemdScopeError::ScopeMismatch)?;
            self.attached.borrow_mut().push(scope.clone());
            Ok(scope)
        }

        fn stop_and_confirm_empty(
            &self,
            expected: &ota_authority_protocol::LauncherSystemdScopeV1,
            _child: &ota_authority_protocol::LauncherChildProcessV1,
            _timeout: Duration,
        ) -> Result<(), SystemdScopeError> {
            self.stopped.borrow_mut().push(expected.identity.clone());
            Ok(())
        }

        fn recover_unrecorded_scope(
            &self,
            _invocation_id: &str,
            _request_identity: &str,
            _child: &ota_authority_protocol::LauncherChildProcessV1,
            _timeout: Duration,
        ) -> Result<(), SystemdScopeError> {
            Ok(())
        }
    }

    #[test]
    fn unsupported_command_refuses_during_systemd_request_admission() {
        let request = LauncherInvocationRequestV1 {
            message_kind: ota_authority_protocol::LAUNCHER_INVOCATION_REQUEST.into(),
            protocol_version: SYSTEMD_LAUNCHER_SERVICE_PROTOCOL_V1.into(),
            authority_id: "release".into(),
            ota_arguments: vec!["self-update".into()],
            repository_path: "/srv/repositories/project".into(),
        };
        assert!(matches!(
            validate_requested_command(&request),
            Err(SystemdServiceError::InvalidRequest)
        ));
    }

    #[test]
    fn bridge_errors_remain_pre_authorization_protocol_refusals_after_cleanup() {
        assert!(matches!(
            map_prepared_child_error(PreparedChildError::AttestationBridgeUnavailable),
            SystemdServiceError::PreAuthorizationProtocolRefused
        ));
        assert!(matches!(
            map_prepared_child_error(PreparedChildError::AuthorizationAdmissionMismatch),
            SystemdServiceError::PreAuthorizationProtocolRefused
        ));
    }

    #[test]
    fn listener_path_requires_exact_metadata_and_protected_parent_chain() {
        if unsafe { libc::geteuid() } != 0 {
            return;
        }
        let directory = PathBuf::from(format!("/run/ota-listener-test-{}", std::process::id()));
        let _ = fs::remove_dir_all(&directory);
        fs::create_dir(&directory).expect("protected listener directory");
        fs::set_permissions(&directory, fs::Permissions::from_mode(0o755))
            .expect("directory permissions");
        let path = directory.join("launcher.sock");
        let listener = UnixListener::bind(&path).expect("listener");
        let path_c = std::ffi::CString::new(path.as_os_str().as_bytes()).expect("path");
        assert_eq!(unsafe { libc::chown(path_c.as_ptr(), 0, 1001) }, 0);
        fs::set_permissions(&path, fs::Permissions::from_mode(0o660)).expect("permissions");
        assert!(verify_listener_path(&listener, &path, 1001).is_ok());

        fs::set_permissions(&directory, fs::Permissions::from_mode(0o777))
            .expect("writable directory permissions");
        assert!(verify_listener_path(&listener, &path, 1001).is_err());
        drop(listener);
        fs::remove_file(&path).expect("remove listener socket");
        fs::remove_dir(&directory).expect("remove listener directory");
    }

    #[test]
    fn listener_verification_rejects_a_connected_unix_stream() {
        let (stream, _peer) = UnixStream::pair().expect("socket pair");
        assert!(verify_listener_socket(stream.as_raw_fd()).is_err());
    }

    #[test]
    fn disabled_service_journals_stopped_child_and_confirms_cleanup() {
        if unsafe { libc::geteuid() } != 0 {
            return;
        }
        let temporary = tempdir().expect("temporary directory");
        let active = temporary.path().join("active");
        let repository_path = temporary.path().join("repository");
        fs::create_dir(&active).expect("active directory");
        fs::create_dir(&repository_path).expect("repository directory");
        fs::set_permissions(&active, fs::Permissions::from_mode(0o700))
            .expect("active permissions");
        let repository_file = std::fs::File::open(&repository_path).expect("repository descriptor");
        let repository_metadata = repository_file.metadata().expect("repository metadata");
        let repository = crate::target_directory::OpenedRepositoryDirectory {
            descriptor: repository_file.into(),
            device: repository_metadata.dev(),
            inode: repository_metadata.ino(),
        };
        let identity = |character: char| format!("sha256:{}", character.to_string().repeat(64));
        let config = SystemdLauncherServiceConfigV1 {
            schema_version: 1,
            identity: identity('a'),
            adapter: ota_authority_protocol::SYSTEMD_PROTECTED_LAUNCHER_ADAPTER_V1.into(),
            socket_path: PathBuf::from("/run/ota/authority-launcher.sock"),
            socket_group_gid: 1001,
            ota_binary: PathBuf::from("/bin/true"),
            environment: BTreeMap::from([(String::from("PATH"), String::from("/usr/bin"))]),
            allowed_repository_roots: vec![temporary.path().into()],
            mappings: vec![crate::config::SystemdPrincipalMappingV1 {
                authority_id: String::from("release"),
                job_peer: SessionPeer {
                    uid: 1001,
                    gid: 1001,
                },
                execution: crate::config::RunAs {
                    uid: 65_534,
                    gid: 65_534,
                },
                closed_profile: None,
            }],
            broker_proxy_socket: PathBuf::from("/run/ota/broker-proxy.sock"),
            broker_proxy_peer: SessionPeer { uid: 0, gid: 0 },
            service_unit_identity: identity('b'),
            socket_unit_identity: identity('c'),
            ota_binary_identity: identity('d'),
            broker_proxy_identity: identity('e'),
            broker_proxy_executable_identity: identity('1'),
            attestor_key_set_identity: identity('f'),
            attestation_claims: None,
            maximum_request_bytes: 4096,
            maximum_active_sessions: 1,
            maximum_startup_seconds: 5,
            maximum_terminal_wait_seconds: 30,
        };
        let request = LauncherInvocationRequestV1 {
            message_kind: ota_authority_protocol::LAUNCHER_INVOCATION_REQUEST.into(),
            protocol_version: SYSTEMD_LAUNCHER_SERVICE_PROTOCOL_V1.into(),
            authority_id: String::from("release"),
            ota_arguments: vec![String::from("run"), String::from("verify")],
            repository_path: repository_path.to_string_lossy().into_owned(),
        };
        let executable = std::fs::File::open("/bin/true").expect("test executable");
        let scope_boundary = RecordingScopeBoundary::default();
        let posture_gate_ran_after_scope = Cell::new(false);
        let (child, decision) = prepare_disabled_child_boundary_with_scope(
            &config,
            &executable,
            &repository,
            &config.mappings[0],
            &request,
            "invocation-test",
            &active,
            0,
            temporary.path(),
            &scope_boundary,
            |_child, _principal_mapping, _scope, _active_slot| {
                let journal_path = fs::read_dir(&active)
                    .expect("active directory")
                    .next()
                    .expect("durable active slot")
                    .expect("active-slot entry")
                    .path();
                let journal: serde_json::Value = serde_json::from_slice(
                    &fs::read(journal_path).expect("read durable active slot"),
                )
                .expect("active-slot JSON");
                posture_gate_ran_after_scope.set(
                    scope_boundary.attached.borrow().len() == 1
                        && journal.get("stage").and_then(serde_json::Value::as_str)
                            == Some("scope_attached"),
                );
                Ok(AuthorizationDecision::Allowed)
            },
        )
        .expect("prepare and clean child boundary");
        assert_eq!(decision, AuthorizationDecision::Allowed);
        assert!(posture_gate_ran_after_scope.get());
        assert_eq!(scope_boundary.attached.borrow().len(), 1);
        assert_eq!(scope_boundary.stopped.borrow().len(), 1);
        assert!(!PathBuf::from(format!("/proc/{}", child.pid)).exists());
        assert_eq!(fs::read_dir(&active).expect("active directory").count(), 0);

        let refused_scope = RecordingScopeBoundary::default();
        let refused_pid = Cell::new(0_u32);
        assert!(matches!(
            prepare_disabled_child_boundary_with_scope(
                &config,
                &executable,
                &repository,
                &config.mappings[0],
                &request,
                "invocation-authority-refusal",
                &active,
                0,
                temporary.path(),
                &refused_scope,
                |child, _principal_mapping, _scope, _active_slot| {
                    refused_pid.set(child.record.pid);
                    Err(SystemdServiceError::PreAuthorizationProtocolRefused)
                },
            ),
            Err(SystemdServiceError::PreAuthorizationProtocolRefused)
        ));
        assert_eq!(refused_scope.attached.borrow().len(), 1);
        assert_eq!(refused_scope.stopped.borrow().len(), 1);
        assert!(!PathBuf::from(format!("/proc/{}", refused_pid.get())).exists());
        assert_eq!(fs::read_dir(&active).expect("active directory").count(), 0);

        assert!(matches!(
            prepare_disabled_child_boundary_with_scope(
                &config,
                &executable,
                &repository,
                &config.mappings[0],
                &request,
                "invocation-uncertain-scope",
                &active,
                0,
                temporary.path(),
                &UncertainScopeBoundary,
                |_child, _principal_mapping, _scope, _active_slot| {
                    Ok(AuthorizationDecision::Allowed)
                },
            ),
            Err(SystemdServiceError::ScopeCleanupFailed)
        ));
        let mut uncertain =
            ActiveSlot::load_all(&active, 0, temporary.path()).expect("load uncertain scope slot");
        assert_eq!(uncertain.len(), 1);
        assert!(uncertain[0].child().is_some());
        assert!(uncertain[0].scope().is_none());
        uncertain
            .pop()
            .expect("uncertain scope slot")
            .finalize()
            .expect("uncertain scope test cleanup");

        let principal =
            systemd_principal_mapping(&config, &config.mappings[0]).expect("principal mapping");
        let mut working = LauncherWorkingDirectoryV1 {
            schema_version: 1,
            identity: String::new(),
            logical_path: request.repository_path.clone(),
            device: repository.device,
            inode: repository.inode,
        };
        working.identity =
            launcher_working_directory_identity(&working).expect("working-directory identity");
        let request_identity =
            launcher_invocation_request_identity(&request).expect("request identity");
        let intent = ActiveSlot::begin(
            &active,
            0,
            temporary.path(),
            "invocation-intent-only",
            principal.identity.as_str(),
            request_identity.as_str(),
            working.clone(),
        )
        .expect("intent-only slot");
        assert!(matches!(
            preparation_failure(intent, PreparedChildError::CleanupFailed),
            SystemdServiceError::ChildCleanupFailed
        ));
        let recoverable_mapping = identity('8');
        let recoverable_request = identity('7');
        let mut recoverable = ActiveSlot::begin(
            &active,
            0,
            temporary.path(),
            "invocation-recoverable",
            recoverable_mapping.as_str(),
            recoverable_request.as_str(),
            working.clone(),
        )
        .expect("recoverable slot");
        let mut absent_child = ota_authority_protocol::LauncherChildProcessV1 {
            schema_version: 1,
            identity: String::new(),
            invocation_id: String::from("invocation-recoverable"),
            request_identity: recoverable_request,
            pid: u32::MAX,
            process_start_time_identity: identity('6'),
            ota_binary_identity: config.ota_binary_identity.clone(),
            principal_mapping_identity: recoverable_mapping,
            working_directory_identity: working.identity.clone(),
        };
        absent_child.identity =
            ota_authority_protocol::launcher_child_process_identity(&absent_child)
                .expect("absent child identity");
        recoverable
            .record_child(absent_child)
            .expect("record recoverable child");
        drop(recoverable);
        let loaded =
            ActiveSlot::load_all(&active, 0, temporary.path()).expect("load recoverable slots");
        assert!(matches!(
            reconcile_loaded_slots(loaded, &AbsentScopeBoundary, Duration::from_secs(1)),
            Err(SystemdServiceError::ActiveSlotUnavailable)
        ));
        let mut retained_intent =
            ActiveSlot::load_all(&active, 0, temporary.path()).expect("load retained intent");
        assert_eq!(retained_intent.len(), 1);
        retained_intent
            .pop()
            .expect("retained intent")
            .finalize()
            .expect("intent test cleanup");

        let absent_mapping = identity('5');
        let absent_request = identity('4');
        let mut scope_removed = ActiveSlot::begin(
            &active,
            0,
            temporary.path(),
            "invocation-scope-removed",
            absent_mapping.as_str(),
            absent_request.as_str(),
            working.clone(),
        )
        .expect("scope-removed slot");
        let mut absent_after_scope = ota_authority_protocol::LauncherChildProcessV1 {
            schema_version: 1,
            identity: String::new(),
            invocation_id: String::from("invocation-scope-removed"),
            request_identity: absent_request.clone(),
            pid: u32::MAX - 1,
            process_start_time_identity: identity('3'),
            ota_binary_identity: config.ota_binary_identity.clone(),
            principal_mapping_identity: absent_mapping,
            working_directory_identity: working.identity.clone(),
        };
        absent_after_scope.identity =
            ota_authority_protocol::launcher_child_process_identity(&absent_after_scope)
                .expect("scope-removed child identity");
        scope_removed
            .record_child(absent_after_scope.clone())
            .expect("record scope-removed child");
        let scope_factory = RecordingScopeBoundary::default();
        let removed_scope = scope_factory
            .attach_stopped_child(
                "invocation-scope-removed",
                absent_request.as_str(),
                &absent_after_scope,
                Duration::from_secs(1),
            )
            .expect("scope-removed scope");
        scope_removed
            .record_scope(removed_scope)
            .expect("record removed scope");
        drop(scope_removed);
        let removed_slots =
            ActiveSlot::load_all(&active, 0, temporary.path()).expect("load removed scope slot");
        reconcile_loaded_slots(removed_slots, &AbsentScopeBoundary, Duration::from_secs(1))
            .expect("scope and child absence is terminal");
        assert_eq!(fs::read_dir(&active).expect("active directory").count(), 0);

        let mut stale = ActiveSlot::begin(
            &active,
            0,
            temporary.path(),
            "invocation-stale",
            principal.identity.as_str(),
            request_identity.as_str(),
            working.clone(),
        )
        .expect("stale slot");
        let mut mismatched_child = ota_authority_protocol::LauncherChildProcessV1 {
            schema_version: 1,
            identity: String::new(),
            invocation_id: String::from("invocation-stale"),
            request_identity,
            pid: std::process::id(),
            process_start_time_identity: identity('9'),
            ota_binary_identity: config.ota_binary_identity.clone(),
            principal_mapping_identity: principal.identity,
            working_directory_identity: working.identity,
        };
        mismatched_child.identity =
            ota_authority_protocol::launcher_child_process_identity(&mismatched_child)
                .expect("mismatched child identity");
        stale
            .record_child(mismatched_child)
            .expect("record mismatched child");
        drop(stale);
        let stale_slots =
            ActiveSlot::load_all(&active, 0, temporary.path()).expect("load stale child slot");
        assert!(matches!(
            reconcile_loaded_slots(stale_slots, &AbsentScopeBoundary, Duration::from_secs(1)),
            Err(SystemdServiceError::ChildCleanupFailed)
        ));
        let mut retained =
            ActiveSlot::load_all(&active, 0, temporary.path()).expect("load retained mismatch");
        assert_eq!(retained.len(), 1);
        retained
            .pop()
            .expect("retained slot")
            .finalize()
            .expect("test cleanup");
    }
}
