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

//! Pressure-only protected-launcher capability derivation.
//!
//! This module observes authority files and process-bound descriptors owned by the launcher. It
//! does not load repository configuration, request an OIDC token, contact a provider, or deliver
//! secret bytes. Core consumption is a separate reviewed boundary.

#[cfg(target_os = "linux")]
use ota_authority_protocol::{
    LauncherChildProcessV1, LauncherInvocationRequestV1, LauncherPrincipalMappingV1,
    LauncherSystemdScopeV1, OtaProcessPostureV1, PROTECTED_AUTHORITY_SNAPSHOT,
    PROTECTED_AUTHORITY_SNAPSHOT_RESPONSE, PROTECTED_LAUNCHER_CAPABILITY,
    ProtectedAuthoritySnapshotPayloadV1, ProtectedAuthoritySnapshotRequestV1,
    ProtectedAuthoritySnapshotResponseV1, ProtectedLauncherAuthorityContextV1,
    ProtectedLauncherCapabilityEvidenceV1, ProtectedLauncherCapabilityV1,
    ProtectedLauncherDescriptorRoleV1, ProtectedLauncherDescriptorV1,
    ProtectedSecretDeliveryBindingBundleV1, ProtectedSecretDeliveryVerifierStoreV1,
    SYSTEMD_LAUNCHER_SERVICE_PROTOCOL_V1, SystemdProtectedLauncherInstanceEvidenceV2,
    launcher_invocation_request_identity, protected_authority_snapshot_payload_v1_identity,
    protected_authority_snapshot_response_v1_identity,
    protected_launcher_authority_context_v1_identity, protected_launcher_boot_v1_identity,
    protected_launcher_capability_v1_identity, protected_launcher_cgroup_v1_identity,
    protected_launcher_invocation_nonce_v1_identity,
    protected_secret_delivery_binding_bundle_signature_message_v1,
    reconcile_protected_authority_snapshot_request_v1,
    reconcile_protected_authority_snapshot_response_v1,
    reconcile_protected_secret_delivery_authority_bundle_v1,
    validate_protected_launcher_capability_v1,
};
#[cfg(target_os = "linux")]
use thiserror::Error;

#[cfg(target_os = "linux")]
use ota_authority_protocol::{
    MAX_PROTECTED_LAUNCHER_STORE_BYTES_V1, ProtectedLauncherDescriptorAccessV1,
    ProtectedLauncherDescriptorKindV1, protected_launcher_descriptor_v1_identity,
    protected_launcher_store_content_identity_v1,
};
#[cfg(target_os = "linux")]
use std::ffi::CString;
#[cfg(target_os = "linux")]
use std::fs::File;
#[cfg(target_os = "linux")]
use std::io;
#[cfg(target_os = "linux")]
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd, RawFd};
#[cfg(target_os = "linux")]
use std::os::unix::fs::{FileExt, MetadataExt};
#[cfg(target_os = "linux")]
use std::os::unix::net::UnixStream;
#[cfg(target_os = "linux")]
use std::path::{Component, Path};

#[cfg(target_os = "linux")]
use base64::Engine;
#[cfg(target_os = "linux")]
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
#[cfg(target_os = "linux")]
use ed25519_dalek::{Signature, VerifyingKey};
#[cfg(target_os = "linux")]
use time::OffsetDateTime;

#[cfg(target_os = "linux")]
use crate::installation_manifest::RetainedProtectedLauncherAuthorityInstallationV1;

#[cfg(target_os = "linux")]
const PROC_BOOT_ID_PATH: &[u8] = b"sys/kernel/random/boot_id";

#[cfg(target_os = "linux")]
pub const SECRET_DELIVERY_AUTHORITY_DIRECTORY: &str = "/etc/ota/secret-delivery";
#[cfg(target_os = "linux")]
pub const SECRET_DELIVERY_VERIFIER_STORE: &str = "verifiers-v1.json";
#[cfg(target_os = "linux")]
pub const SECRET_DELIVERY_BINDING_STORE: &str = "bindings-v1.json";

#[cfg(target_os = "linux")]
struct RetainedProtectedLauncherBootV1 {
    file: File,
    device: u64,
    inode: u64,
    mode: u32,
    value: String,
    identity: String,
}

#[cfg(target_os = "linux")]
impl RetainedProtectedLauncherBootV1 {
    pub(crate) fn from_manager_file(file: File) -> Result<Self, ProtectedLauncherCapabilityError> {
        verify_procfs_root(file.as_raw_fd())?;
        let descriptor_flags = unsafe { libc::fcntl(file.as_raw_fd(), libc::F_GETFL) };
        if descriptor_flags < 0 || descriptor_flags & libc::O_ACCMODE != libc::O_RDONLY {
            return Err(ProtectedLauncherCapabilityError::Unprotected);
        }
        let (device, inode, mode, value, identity) = observe_boot_file(&file)?;
        Ok(Self {
            file,
            device,
            inode,
            mode,
            value,
            identity,
        })
    }

    #[cfg(test)]
    fn observe_fixture() -> Result<Self, ProtectedLauncherCapabilityError> {
        let proc_root = open_root(Path::new("/proc"), 0, 0)?;
        verify_procfs_root(proc_root.as_raw_fd())?;
        let descriptor = openat2_beneath(
            proc_root.as_raw_fd(),
            PROC_BOOT_ID_PATH,
            libc::O_RDONLY | libc::O_CLOEXEC | libc::O_NOFOLLOW | libc::O_NONBLOCK,
        )?;
        let file = File::from(descriptor);
        Self::from_manager_file(file)
    }

    fn reobserve(&self) -> Result<&str, ProtectedLauncherCapabilityError> {
        let (device, inode, mode, value, identity) = observe_boot_file(&self.file)?;
        if device != self.device
            || inode != self.inode
            || mode != self.mode
            || value != self.value
            || identity != self.identity
        {
            return Err(ProtectedLauncherCapabilityError::ReconciliationFailed);
        }
        Ok(self.identity.as_str())
    }
}

#[cfg(target_os = "linux")]
pub(crate) struct RetainedProtectedLauncherAuthorityContextV1 {
    authority: RetainedProtectedLauncherAuthoritySourceV1,
    authority_identity: String,
    invocation_nonce: [u8; 32],
    invocation_nonce_identity: String,
    boot: RetainedProtectedLauncherBootV1,
}

#[cfg(target_os = "linux")]
enum RetainedProtectedLauncherAuthoritySourceV1 {
    Installation(Box<RetainedProtectedLauncherAuthorityInstallationV1>),
    #[cfg(test)]
    Fixture(Box<ProtectedLauncherAuthorityContextV1>),
}

#[cfg(target_os = "linux")]
impl RetainedProtectedLauncherAuthorityContextV1 {
    pub(crate) fn acquire(
        authority: RetainedProtectedLauncherAuthorityInstallationV1,
        boot_file: File,
    ) -> Result<Self, ProtectedLauncherCapabilityError> {
        let authority_identity = authority
            .reconcile()
            .map_err(|_| ProtectedLauncherCapabilityError::Unprotected)?
            .identity
            .clone();
        let mut invocation_nonce = [0_u8; 32];
        getrandom::getrandom(&mut invocation_nonce)
            .map_err(|_| ProtectedLauncherCapabilityError::Unavailable)?;
        if invocation_nonce.iter().all(|byte| *byte == 0) {
            return Err(ProtectedLauncherCapabilityError::Unavailable);
        }
        let invocation_nonce_identity =
            protected_launcher_invocation_nonce_v1_identity(&invocation_nonce)
                .map_err(|_| ProtectedLauncherCapabilityError::Unprotected)?;
        Ok(Self {
            authority: RetainedProtectedLauncherAuthoritySourceV1::Installation(Box::new(
                authority,
            )),
            authority_identity,
            invocation_nonce,
            invocation_nonce_identity,
            boot: RetainedProtectedLauncherBootV1::from_manager_file(boot_file)?,
        })
    }

    fn reconcile(
        &self,
    ) -> Result<(&ProtectedLauncherAuthorityContextV1, &str, &str), ProtectedLauncherCapabilityError>
    {
        let authority = match &self.authority {
            RetainedProtectedLauncherAuthoritySourceV1::Installation(authority) => authority
                .reconcile()
                .map_err(|_| ProtectedLauncherCapabilityError::ReconciliationFailed)?,
            #[cfg(test)]
            RetainedProtectedLauncherAuthoritySourceV1::Fixture(authority) => authority.as_ref(),
        };
        if protected_launcher_authority_context_v1_identity(authority)
            .map_err(|_| ProtectedLauncherCapabilityError::ReconciliationFailed)?
            != authority.identity
            || authority.identity != self.authority_identity
            || protected_launcher_invocation_nonce_v1_identity(&self.invocation_nonce)
                .map_err(|_| ProtectedLauncherCapabilityError::ReconciliationFailed)?
                != self.invocation_nonce_identity
        {
            return Err(ProtectedLauncherCapabilityError::ReconciliationFailed);
        }
        Ok((
            authority,
            self.invocation_nonce_identity.as_str(),
            self.boot.reobserve()?,
        ))
    }

    #[cfg(test)]
    fn for_test(
        authority: ProtectedLauncherAuthorityContextV1,
        invocation_nonce: [u8; 32],
    ) -> Result<Self, ProtectedLauncherCapabilityError> {
        let authority_identity = authority.identity.clone();
        Ok(Self {
            authority: RetainedProtectedLauncherAuthoritySourceV1::Fixture(Box::new(authority)),
            authority_identity,
            invocation_nonce,
            invocation_nonce_identity: protected_launcher_invocation_nonce_v1_identity(
                &invocation_nonce,
            )
            .map_err(|_| ProtectedLauncherCapabilityError::Unprotected)?,
            boot: RetainedProtectedLauncherBootV1::observe_fixture()?,
        })
    }

    #[cfg(test)]
    fn fixture_authority_mut(&mut self) -> &mut ProtectedLauncherAuthorityContextV1 {
        match &mut self.authority {
            RetainedProtectedLauncherAuthoritySourceV1::Fixture(authority) => authority.as_mut(),
            RetainedProtectedLauncherAuthoritySourceV1::Installation(_) => {
                panic!("test fixture authority required")
            }
        }
    }
}

#[cfg(target_os = "linux")]
#[derive(Debug, Error, PartialEq, Eq)]
pub enum ProtectedLauncherCapabilityError {
    #[error("protected launcher authority state is unavailable")]
    Unavailable,
    #[error("protected launcher authority state is not protected")]
    Unprotected,
    #[error("protected launcher capability reconciliation failed")]
    ReconciliationFailed,
}

/// Non-descriptor truth retained by the protected launcher transaction.
///
/// Descriptor and store-byte evidence is deliberately excluded: callers cannot construct that
/// evidence. It is read from retained descriptors immediately before reconciliation.
#[cfg(target_os = "linux")]
pub(crate) struct ProtectedLauncherCapabilityContextV1<'a> {
    pub request: &'a LauncherInvocationRequestV1,
    pub child: &'a LauncherChildProcessV1,
    pub scope: &'a LauncherSystemdScopeV1,
    pub principal_mapping: &'a LauncherPrincipalMappingV1,
    pub process_posture: &'a OtaProcessPostureV1,
    pub launcher_instance: &'a SystemdProtectedLauncherInstanceEvidenceV2,
    pub launcher_executable_identity: &'a str,
    pub launcher_configuration_identity: &'a str,
    pub launcher_service_binding_identity: &'a str,
    pub launcher_profile_identity: &'a str,
    pub service_uid: u32,
    pub service_gid: u32,
    pub authority: &'a RetainedProtectedLauncherAuthorityContextV1,
}

#[cfg(target_os = "linux")]
pub(crate) struct RetainedProtectedLauncherObservationV1 {
    stores: ProtectedAuthorityStoresV1,
    cgroup: RetainedInvocationCgroupV1,
    session: UnixStream,
    session_descriptor: ProtectedLauncherDescriptorV1,
}

#[cfg(target_os = "linux")]
type ReobservedProtectedLauncherState<'a> =
    ([ProtectedLauncherDescriptorV1; 4], &'a [u8], &'a [u8]);

#[cfg(target_os = "linux")]
impl RetainedProtectedLauncherObservationV1 {
    pub(crate) fn observe(
        stores: ProtectedAuthorityStoresV1,
        cgroup: RetainedInvocationCgroupV1,
        session: UnixStream,
    ) -> Result<Self, ProtectedLauncherCapabilityError> {
        let session_descriptor = observe_launcher_session_descriptor_v1(&session)?;
        Ok(Self {
            stores,
            cgroup,
            session,
            session_descriptor,
        })
    }

    fn reobserve(
        &mut self,
        scope: &LauncherSystemdScopeV1,
    ) -> Result<ReobservedProtectedLauncherState<'_>, ProtectedLauncherCapabilityError> {
        self.stores.revalidate()?;
        self.cgroup.revalidate(scope)?;
        let session_descriptor = observe_launcher_session_descriptor_v1(&self.session)?;
        if session_descriptor != self.session_descriptor {
            return Err(ProtectedLauncherCapabilityError::ReconciliationFailed);
        }
        self.session_descriptor = session_descriptor;
        Ok((
            [
                self.session_descriptor.clone(),
                self.stores.descriptors()[0].clone(),
                self.stores.descriptors()[1].clone(),
                self.cgroup.descriptor().clone(),
            ],
            self.stores.verifier_store_bytes(),
            self.stores.binding_store_bytes(),
        ))
    }
}

#[cfg(target_os = "linux")]
pub(crate) fn derive_protected_launcher_capability_v1(
    input: &ProtectedLauncherCapabilityContextV1<'_>,
    observation: &mut RetainedProtectedLauncherObservationV1,
) -> Result<ProtectedLauncherCapabilityV1, ProtectedLauncherCapabilityError> {
    let (authority, invocation_nonce_identity, boot_identity) = input.authority.reconcile()?;
    let runner_administrator_identity = authority.runner_administrator.identity.as_str();
    let implementation_subject = &authority.implementation_subject;
    let implementation_subject_identity = implementation_subject.identity.as_str();
    if implementation_subject.launcher_artifact_identity != input.launcher_executable_identity
        || implementation_subject.ota_artifact_identity != input.child.ota_binary_identity
        || implementation_subject.launcher_profile_identity != input.launcher_profile_identity
    {
        return Err(ProtectedLauncherCapabilityError::ReconciliationFailed);
    }
    let (descriptors, verifier_store_bytes, binding_store_bytes) =
        observation.reobserve(input.scope)?;
    let cgroup_descriptor = descriptors
        .iter()
        .find(|descriptor| descriptor.role == ProtectedLauncherDescriptorRoleV1::InvocationCgroup)
        .ok_or(ProtectedLauncherCapabilityError::ReconciliationFailed)?;
    let cgroup_identity = protected_launcher_cgroup_v1_identity(input.scope, cgroup_descriptor)
        .map_err(|_| ProtectedLauncherCapabilityError::ReconciliationFailed)?;
    let request_identity = launcher_invocation_request_identity(input.request)
        .map_err(|_| ProtectedLauncherCapabilityError::ReconciliationFailed)?;
    let mut capability = ProtectedLauncherCapabilityV1 {
        schema_version: 1,
        identity: String::new(),
        message_kind: PROTECTED_LAUNCHER_CAPABILITY.into(),
        protocol_version: SYSTEMD_LAUNCHER_SERVICE_PROTOCOL_V1.into(),
        launcher_request_identity: request_identity,
        launcher_executable_identity: input.launcher_executable_identity.into(),
        launcher_configuration_identity: input.launcher_configuration_identity.into(),
        launcher_service_binding_identity: input.launcher_service_binding_identity.into(),
        launcher_profile_identity: input.launcher_profile_identity.into(),
        runner_administrator_identity: runner_administrator_identity.into(),
        service_uid: input.service_uid,
        service_gid: input.service_gid,
        invocation_nonce_identity: invocation_nonce_identity.into(),
        boot_identity: boot_identity.into(),
        protected_launcher_instance_identity: input.launcher_instance.identity.clone(),
        systemd_invocation_identity: input.scope.identity.clone(),
        systemd_scope_identity: input.scope.identity.clone(),
        cgroup_identity,
        child_process_identity: input.child.identity.clone(),
        principal_mapping_identity: input.principal_mapping.identity.clone(),
        process_posture_identity: input.process_posture.identity.clone(),
        implementation_subject_identity: implementation_subject_identity.into(),
        descriptors: descriptors.to_vec(),
    };
    capability.identity = protected_launcher_capability_v1_identity(&capability)
        .map_err(|_| ProtectedLauncherCapabilityError::ReconciliationFailed)?;
    let evidence = ProtectedLauncherCapabilityEvidenceV1 {
        request: input.request,
        child: input.child,
        scope: input.scope,
        principal_mapping: input.principal_mapping,
        process_posture: input.process_posture,
        launcher_instance: input.launcher_instance,
        launcher_executable_identity: input.launcher_executable_identity,
        launcher_configuration_identity: input.launcher_configuration_identity,
        launcher_service_binding_identity: input.launcher_service_binding_identity,
        launcher_profile_identity: input.launcher_profile_identity,
        runner_administrator_identity,
        service_uid: input.service_uid,
        service_gid: input.service_gid,
        invocation_nonce_identity,
        boot_identity,
        implementation_subject_identity,
        observed_descriptors: descriptors.as_slice(),
        verifier_store_bytes,
        binding_store_bytes,
    };
    validate_protected_launcher_capability_v1(&capability, &evidence)
        .map_err(|_| ProtectedLauncherCapabilityError::ReconciliationFailed)?;
    Ok(capability)
}

#[cfg(target_os = "linux")]
pub struct ProtectedAuthorityStoresV1 {
    verifier_store: File,
    binding_store: File,
    verifier_store_bytes: Vec<u8>,
    binding_store_bytes: Vec<u8>,
    descriptors: [ProtectedLauncherDescriptorV1; 2],
}

/// Reconciled authority input retained by the protected Launcher. It is not an admission,
/// provider credential, or transport message; a later same-session route must bind it to Core's
/// candidate before any provider transaction can begin.
#[cfg(target_os = "linux")]
pub(crate) struct VerifiedSecretDeliveryAuthorityBundleV1 {
    pub(crate) verifier_store_descriptor: ProtectedLauncherDescriptorV1,
    pub(crate) binding_store_descriptor: ProtectedLauncherDescriptorV1,
    pub(crate) verifier_store_bytes: Vec<u8>,
    pub(crate) binding_store_bytes: Vec<u8>,
    pub(crate) verifier_store: ProtectedSecretDeliveryVerifierStoreV1,
    pub(crate) binding_bundle: ProtectedSecretDeliveryBindingBundleV1,
    pub(crate) binding_payload: Vec<u8>,
}

#[cfg(target_os = "linux")]
impl ProtectedAuthorityStoresV1 {
    pub fn open() -> Result<Self, ProtectedLauncherCapabilityError> {
        Self::open_beneath(Path::new("/"), Path::new("etc/ota/secret-delivery"), 0, 0)
    }

    pub(crate) fn try_clone(&self) -> Result<Self, ProtectedLauncherCapabilityError> {
        Ok(Self {
            verifier_store: self
                .verifier_store
                .try_clone()
                .map_err(|_| ProtectedLauncherCapabilityError::Unavailable)?,
            binding_store: self
                .binding_store
                .try_clone()
                .map_err(|_| ProtectedLauncherCapabilityError::Unavailable)?,
            verifier_store_bytes: self.verifier_store_bytes.clone(),
            binding_store_bytes: self.binding_store_bytes.clone(),
            descriptors: self.descriptors.clone(),
        })
    }

    pub fn descriptors(&self) -> &[ProtectedLauncherDescriptorV1; 2] {
        &self.descriptors
    }

    pub fn verifier_store_bytes(&self) -> &[u8] {
        self.verifier_store_bytes.as_slice()
    }

    pub fn binding_store_bytes(&self) -> &[u8] {
        self.binding_store_bytes.as_slice()
    }

    pub fn revalidate(&self) -> Result<(), ProtectedLauncherCapabilityError> {
        revalidate_store(
            &self.verifier_store,
            &self.descriptors[0],
            self.verifier_store_bytes.as_slice(),
        )?;
        revalidate_store(
            &self.binding_store,
            &self.descriptors[1],
            self.binding_store_bytes.as_slice(),
        )
    }

    /// Revalidates the retained root-owned descriptors, then verifies one current authority
    /// bundle. The clock is Launcher-owned; only tests may inject a timestamp.
    pub(crate) fn verify_secret_delivery_authority_bundle_v1(
        &self,
    ) -> Result<VerifiedSecretDeliveryAuthorityBundleV1, ProtectedLauncherCapabilityError> {
        let observed_at_unix_seconds = u64::try_from(OffsetDateTime::now_utc().unix_timestamp())
            .map_err(|_| ProtectedLauncherCapabilityError::Unavailable)?;
        self.verify_secret_delivery_authority_bundle_inner_v1(observed_at_unix_seconds)
    }

    #[cfg(test)]
    fn verify_secret_delivery_authority_bundle_at_v1(
        &self,
        observed_at_unix_seconds: u64,
    ) -> Result<VerifiedSecretDeliveryAuthorityBundleV1, ProtectedLauncherCapabilityError> {
        self.verify_secret_delivery_authority_bundle_inner_v1(observed_at_unix_seconds)
    }

    fn verify_secret_delivery_authority_bundle_inner_v1(
        &self,
        observed_at_unix_seconds: u64,
    ) -> Result<VerifiedSecretDeliveryAuthorityBundleV1, ProtectedLauncherCapabilityError> {
        self.revalidate()?;
        let store: ProtectedSecretDeliveryVerifierStoreV1 =
            serde_json::from_slice(self.verifier_store_bytes())
                .map_err(|_| ProtectedLauncherCapabilityError::Unprotected)?;
        let bundle: ProtectedSecretDeliveryBindingBundleV1 =
            serde_json::from_slice(self.binding_store_bytes())
                .map_err(|_| ProtectedLauncherCapabilityError::Unprotected)?;
        reconcile_protected_secret_delivery_authority_bundle_v1(
            &store,
            &bundle,
            observed_at_unix_seconds,
        )
        .map_err(|_| ProtectedLauncherCapabilityError::ReconciliationFailed)?;

        let verifier = store
            .verifiers
            .first()
            .ok_or(ProtectedLauncherCapabilityError::ReconciliationFailed)?;
        let public_key = URL_SAFE_NO_PAD
            .decode(&verifier.public_key)
            .map_err(|_| ProtectedLauncherCapabilityError::ReconciliationFailed)?;
        let public_key: [u8; 32] = public_key
            .try_into()
            .map_err(|_| ProtectedLauncherCapabilityError::ReconciliationFailed)?;
        let verifying_key = VerifyingKey::from_bytes(&public_key)
            .map_err(|_| ProtectedLauncherCapabilityError::ReconciliationFailed)?;
        let signature = URL_SAFE_NO_PAD
            .decode(&bundle.signature)
            .map_err(|_| ProtectedLauncherCapabilityError::ReconciliationFailed)?;
        let signature = Signature::from_slice(&signature)
            .map_err(|_| ProtectedLauncherCapabilityError::ReconciliationFailed)?;
        let signature_message =
            protected_secret_delivery_binding_bundle_signature_message_v1(bundle.identity.as_str())
                .map_err(|_| ProtectedLauncherCapabilityError::ReconciliationFailed)?;
        verifying_key
            .verify_strict(&signature_message, &signature)
            .map_err(|_| ProtectedLauncherCapabilityError::ReconciliationFailed)?;
        let payload =
            ota_authority_protocol::protected_secret_delivery_binding_bundle_payload_bytes_v1(
                &bundle,
            )
            .map_err(|_| ProtectedLauncherCapabilityError::ReconciliationFailed)?;
        Ok(VerifiedSecretDeliveryAuthorityBundleV1 {
            verifier_store_descriptor: self.descriptors[0].clone(),
            binding_store_descriptor: self.descriptors[1].clone(),
            verifier_store_bytes: self.verifier_store_bytes.clone(),
            binding_store_bytes: self.binding_store_bytes.clone(),
            verifier_store: store,
            binding_bundle: bundle,
            binding_payload: payload,
        })
    }

    /// Builds one private snapshot only after the retained stores, exact request, and signed
    /// authority bundle have been revalidated together.
    pub(crate) fn respond_to_authority_snapshot_v1(
        &self,
        request: &ProtectedAuthoritySnapshotRequestV1,
        startup_continuation: &ota_authority_protocol::LauncherStartupContinuationV1,
    ) -> Result<ProtectedAuthoritySnapshotResponseV1, ProtectedLauncherCapabilityError> {
        let observed_at_unix_seconds = u64::try_from(OffsetDateTime::now_utc().unix_timestamp())
            .map_err(|_| ProtectedLauncherCapabilityError::Unavailable)?;
        reconcile_protected_authority_snapshot_request_v1(
            request,
            startup_continuation,
            observed_at_unix_seconds,
        )
        .map_err(|_| ProtectedLauncherCapabilityError::ReconciliationFailed)?;
        let verified =
            self.verify_secret_delivery_authority_bundle_inner_v1(observed_at_unix_seconds)?;
        let payload = ProtectedAuthoritySnapshotPayloadV1 {
            schema_version: 1,
            record_kind: PROTECTED_AUTHORITY_SNAPSHOT.into(),
            request_identity: request.identity.clone(),
            launcher_request_identity: request.launcher_request_identity.clone(),
            startup_continuation_identity: request.startup_continuation_identity.clone(),
            session_identity: request.session_identity.clone(),
            contract_identity: request.contract_identity.clone(),
            selected_execution_graph_identity: request.selected_execution_graph_identity.clone(),
            verifier_store_descriptor: verified.verifier_store_descriptor,
            binding_store_descriptor: verified.binding_store_descriptor,
            verifier_store: verified.verifier_store,
            binding_bundle: verified.binding_bundle,
            verifier_store_bytes: URL_SAFE_NO_PAD.encode(verified.verifier_store_bytes),
            binding_store_bytes: URL_SAFE_NO_PAD.encode(verified.binding_store_bytes),
        };
        let protected_snapshot_identity =
            protected_authority_snapshot_payload_v1_identity(&payload)
                .map_err(|_| ProtectedLauncherCapabilityError::ReconciliationFailed)?;
        let mut response = ProtectedAuthoritySnapshotResponseV1 {
            schema_version: 1,
            message_kind: PROTECTED_AUTHORITY_SNAPSHOT_RESPONSE.into(),
            identity: String::new(),
            request_identity: request.identity.clone(),
            payload,
            protected_snapshot_identity,
        };
        response.identity = protected_authority_snapshot_response_v1_identity(&response)
            .map_err(|_| ProtectedLauncherCapabilityError::ReconciliationFailed)?;
        reconcile_protected_authority_snapshot_response_v1(
            request,
            &response,
            startup_continuation,
            observed_at_unix_seconds,
        )
        .map_err(|_| ProtectedLauncherCapabilityError::ReconciliationFailed)?;
        Ok(response)
    }

    fn open_beneath(
        root: &Path,
        authority_directory: &Path,
        expected_uid: u32,
        expected_gid: u32,
    ) -> Result<Self, ProtectedLauncherCapabilityError> {
        let root = open_root(root, expected_uid, expected_gid)?;
        let authority = open_protected_directory_chain(
            root.as_raw_fd(),
            authority_directory,
            expected_uid,
            expected_gid,
            true,
        )?;
        let (verifier_store, verifier_store_bytes, verifier_descriptor) = open_store(
            authority.as_raw_fd(),
            SECRET_DELIVERY_VERIFIER_STORE,
            ProtectedLauncherDescriptorRoleV1::VerifierStore,
            expected_uid,
            expected_gid,
        )?;
        let (binding_store, binding_store_bytes, binding_descriptor) = open_store(
            authority.as_raw_fd(),
            SECRET_DELIVERY_BINDING_STORE,
            ProtectedLauncherDescriptorRoleV1::BindingStore,
            expected_uid,
            expected_gid,
        )?;
        if verifier_descriptor.device == binding_descriptor.device
            && verifier_descriptor.inode == binding_descriptor.inode
        {
            return Err(ProtectedLauncherCapabilityError::Unprotected);
        }
        Ok(Self {
            verifier_store,
            binding_store,
            verifier_store_bytes,
            binding_store_bytes,
            descriptors: [verifier_descriptor, binding_descriptor],
        })
    }
}

#[cfg(target_os = "linux")]
fn observe_launcher_session_descriptor_v1(
    session: &UnixStream,
) -> Result<ProtectedLauncherDescriptorV1, ProtectedLauncherCapabilityError> {
    observe_raw_descriptor_v1(
        session.as_raw_fd(),
        ProtectedLauncherDescriptorRoleV1::LauncherSessionSocket,
        None,
    )
}

#[cfg(target_os = "linux")]
fn observe_store_descriptor_v1(
    file: &File,
    role: ProtectedLauncherDescriptorRoleV1,
    content_identity: String,
) -> Result<ProtectedLauncherDescriptorV1, ProtectedLauncherCapabilityError> {
    if !matches!(
        role,
        ProtectedLauncherDescriptorRoleV1::VerifierStore
            | ProtectedLauncherDescriptorRoleV1::BindingStore
    ) {
        return Err(ProtectedLauncherCapabilityError::Unprotected);
    }
    observe_raw_descriptor_v1(file.as_raw_fd(), role, Some(content_identity))
}

#[cfg(target_os = "linux")]
fn observe_cgroup_descriptor_v1(
    directory: &File,
) -> Result<ProtectedLauncherDescriptorV1, ProtectedLauncherCapabilityError> {
    observe_raw_descriptor_v1(
        directory.as_raw_fd(),
        ProtectedLauncherDescriptorRoleV1::InvocationCgroup,
        None,
    )
}

#[cfg(target_os = "linux")]
pub struct RetainedInvocationCgroupV1 {
    directory: File,
    descriptor: ProtectedLauncherDescriptorV1,
    scope_identity: String,
}

#[cfg(target_os = "linux")]
impl RetainedInvocationCgroupV1 {
    pub fn open(scope: &LauncherSystemdScopeV1) -> Result<Self, ProtectedLauncherCapabilityError> {
        if !is_canonical_cgroup_path(scope.control_group.as_str()) {
            return Err(ProtectedLauncherCapabilityError::Unprotected);
        }
        let relative = scope
            .control_group
            .strip_prefix('/')
            .ok_or(ProtectedLauncherCapabilityError::Unprotected)?;
        let root = open_root(Path::new("/sys/fs/cgroup"), 0, 0)?;
        verify_cgroup2_root(root.as_raw_fd())?;
        let directory =
            open_protected_directory_chain(root.as_raw_fd(), Path::new(relative), 0, 0, false)?;
        let directory = File::from(directory);
        let descriptor = observe_cgroup_descriptor_v1(&directory)?;
        protected_launcher_cgroup_v1_identity(scope, &descriptor)
            .map_err(|_| ProtectedLauncherCapabilityError::ReconciliationFailed)?;
        Ok(Self {
            directory,
            descriptor,
            scope_identity: scope.identity.clone(),
        })
    }

    pub fn descriptor(&self) -> &ProtectedLauncherDescriptorV1 {
        &self.descriptor
    }

    pub fn revalidate(
        &self,
        scope: &LauncherSystemdScopeV1,
    ) -> Result<(), ProtectedLauncherCapabilityError> {
        if self.scope_identity != scope.identity {
            return Err(ProtectedLauncherCapabilityError::ReconciliationFailed);
        }
        let observed = observe_cgroup_descriptor_v1(&self.directory)?;
        if observed != self.descriptor {
            return Err(ProtectedLauncherCapabilityError::ReconciliationFailed);
        }
        protected_launcher_cgroup_v1_identity(scope, &observed)
            .map_err(|_| ProtectedLauncherCapabilityError::ReconciliationFailed)?;
        Ok(())
    }
}

#[cfg(target_os = "linux")]
fn is_canonical_cgroup_path(value: &str) -> bool {
    value.starts_with('/')
        && value != "/"
        && !value.starts_with("//")
        && !value.ends_with('/')
        && value
            .split('/')
            .skip(1)
            .all(|component| !component.is_empty() && component != "." && component != "..")
}

#[cfg(target_os = "linux")]
fn observe_raw_descriptor_v1(
    descriptor: RawFd,
    role: ProtectedLauncherDescriptorRoleV1,
    content_identity: Option<String>,
) -> Result<ProtectedLauncherDescriptorV1, ProtectedLauncherCapabilityError> {
    let mut stat = std::mem::MaybeUninit::<libc::stat>::uninit();
    if unsafe { libc::fstat(descriptor, stat.as_mut_ptr()) } != 0 {
        return Err(ProtectedLauncherCapabilityError::Unavailable);
    }
    let metadata = unsafe { stat.assume_init() };
    let flags = unsafe { libc::fcntl(descriptor, libc::F_GETFL) };
    if flags < 0 {
        return Err(ProtectedLauncherCapabilityError::Unavailable);
    }
    let (kind, access) = match role {
        ProtectedLauncherDescriptorRoleV1::LauncherSessionSocket => {
            if metadata.st_mode & libc::S_IFMT != libc::S_IFSOCK
                || socket_option_int(descriptor, libc::SO_DOMAIN)? != libc::AF_UNIX
                || socket_option_int(descriptor, libc::SO_TYPE)? != libc::SOCK_STREAM
                || flags & libc::O_ACCMODE != libc::O_RDWR
            {
                return Err(ProtectedLauncherCapabilityError::Unprotected);
            }
            (
                ProtectedLauncherDescriptorKindV1::UnixStreamSocket,
                ProtectedLauncherDescriptorAccessV1::ReadWrite,
            )
        }
        ProtectedLauncherDescriptorRoleV1::VerifierStore
        | ProtectedLauncherDescriptorRoleV1::BindingStore => {
            if metadata.st_mode & libc::S_IFMT != libc::S_IFREG
                || flags & libc::O_ACCMODE != libc::O_RDONLY
            {
                return Err(ProtectedLauncherCapabilityError::Unprotected);
            }
            (
                ProtectedLauncherDescriptorKindV1::RegularFile,
                ProtectedLauncherDescriptorAccessV1::ReadOnly,
            )
        }
        ProtectedLauncherDescriptorRoleV1::InvocationCgroup => {
            if metadata.st_mode & libc::S_IFMT != libc::S_IFDIR || flags & libc::O_PATH == 0 {
                return Err(ProtectedLauncherCapabilityError::Unprotected);
            }
            (
                ProtectedLauncherDescriptorKindV1::Directory,
                ProtectedLauncherDescriptorAccessV1::ReadOnly,
            )
        }
    };
    let mut descriptor = ProtectedLauncherDescriptorV1 {
        schema_version: 1,
        identity: String::new(),
        role,
        kind,
        access,
        device: metadata.st_dev,
        inode: metadata.st_ino,
        owner_uid: metadata.st_uid,
        owner_gid: metadata.st_gid,
        mode: metadata.st_mode & 0o7777,
        size: metadata.st_size as u64,
        content_identity,
    };
    descriptor.identity = protected_launcher_descriptor_v1_identity(&descriptor)
        .map_err(|_| ProtectedLauncherCapabilityError::Unprotected)?;
    Ok(descriptor)
}

#[cfg(target_os = "linux")]
fn socket_option_int(
    descriptor: RawFd,
    option: libc::c_int,
) -> Result<libc::c_int, ProtectedLauncherCapabilityError> {
    let mut value = 0;
    let mut length = std::mem::size_of_val(&value) as libc::socklen_t;
    if unsafe {
        libc::getsockopt(
            descriptor,
            libc::SOL_SOCKET,
            option,
            (&mut value as *mut libc::c_int).cast(),
            &mut length,
        )
    } != 0
        || length as usize != std::mem::size_of_val(&value)
    {
        return Err(ProtectedLauncherCapabilityError::Unprotected);
    }
    Ok(value)
}

#[cfg(target_os = "linux")]
pub(crate) fn open_root(
    path: &Path,
    expected_uid: u32,
    expected_gid: u32,
) -> Result<OwnedFd, ProtectedLauncherCapabilityError> {
    let path = CString::new(path.as_os_str().as_encoded_bytes())
        .map_err(|_| ProtectedLauncherCapabilityError::Unprotected)?;
    let descriptor = unsafe {
        libc::open(
            path.as_ptr(),
            libc::O_PATH | libc::O_DIRECTORY | libc::O_CLOEXEC | libc::O_NOFOLLOW,
        )
    };
    if descriptor < 0 {
        return Err(ProtectedLauncherCapabilityError::Unavailable);
    }
    let descriptor = unsafe { OwnedFd::from_raw_fd(descriptor) };
    verify_directory_descriptor(descriptor.as_raw_fd(), expected_uid, expected_gid, false)?;
    Ok(descriptor)
}

#[cfg(target_os = "linux")]
fn canonical_relative_components(
    path: &Path,
) -> Result<Vec<Component<'_>>, ProtectedLauncherCapabilityError> {
    let encoded = path.as_os_str().as_encoded_bytes();
    if encoded.is_empty()
        || encoded.first() == Some(&b'/')
        || encoded.last() == Some(&b'/')
        || encoded
            .split(|byte| *byte == b'/')
            .any(|component| component.is_empty() || component == b"." || component == b"..")
    {
        return Err(ProtectedLauncherCapabilityError::Unprotected);
    }
    let components = path.components().collect::<Vec<_>>();
    if components.is_empty()
        || components
            .iter()
            .any(|component| !matches!(component, Component::Normal(_)))
    {
        return Err(ProtectedLauncherCapabilityError::Unprotected);
    }
    Ok(components)
}

#[cfg(target_os = "linux")]
pub(crate) fn open_protected_directory_chain(
    root: RawFd,
    path: &Path,
    expected_uid: u32,
    expected_gid: u32,
    final_private_mode: bool,
) -> Result<OwnedFd, ProtectedLauncherCapabilityError> {
    let components = canonical_relative_components(path)?;
    let mut parent = duplicate_fd(root)?;
    for (index, component) in components.iter().enumerate() {
        let Component::Normal(name) = component else {
            return Err(ProtectedLauncherCapabilityError::Unprotected);
        };
        let next = openat2_beneath(
            parent.as_raw_fd(),
            name.as_encoded_bytes(),
            libc::O_PATH | libc::O_DIRECTORY | libc::O_CLOEXEC,
        )?;
        verify_directory_descriptor(
            next.as_raw_fd(),
            expected_uid,
            expected_gid,
            final_private_mode && index + 1 == components.len(),
        )?;
        parent = next;
    }
    Ok(parent)
}

#[cfg(target_os = "linux")]
pub(crate) fn open_protected_directory_chain_allowing_mounts(
    root: RawFd,
    path: &Path,
    expected_uid: u32,
    expected_gid: u32,
    final_private_mode: bool,
) -> Result<OwnedFd, ProtectedLauncherCapabilityError> {
    let components = canonical_relative_components(path)?;
    let mut parent = duplicate_fd(root)?;
    for (index, component) in components.iter().enumerate() {
        let Component::Normal(name) = component else {
            return Err(ProtectedLauncherCapabilityError::Unprotected);
        };
        let next = openat2_beneath_with_mode_and_resolution(
            parent.as_raw_fd(),
            name.as_encoded_bytes(),
            libc::O_PATH | libc::O_DIRECTORY | libc::O_CLOEXEC,
            0,
            false,
        )?;
        verify_directory_descriptor(
            next.as_raw_fd(),
            expected_uid,
            expected_gid,
            final_private_mode && index + 1 == components.len(),
        )?;
        parent = next;
    }
    Ok(parent)
}

#[cfg(target_os = "linux")]
fn open_store(
    authority_directory: RawFd,
    name: &str,
    role: ProtectedLauncherDescriptorRoleV1,
    expected_uid: u32,
    expected_gid: u32,
) -> Result<(File, Vec<u8>, ProtectedLauncherDescriptorV1), ProtectedLauncherCapabilityError> {
    let descriptor = openat2_beneath(
        authority_directory,
        name.as_bytes(),
        libc::O_RDONLY | libc::O_CLOEXEC | libc::O_NOFOLLOW | libc::O_NONBLOCK,
    )?;
    let file = File::from(descriptor);
    let metadata = file
        .metadata()
        .map_err(|_| ProtectedLauncherCapabilityError::Unavailable)?;
    if !metadata.is_file()
        || metadata.uid() != expected_uid
        || metadata.gid() != expected_gid
        || metadata.mode() & 0o7777 != 0o400
        || metadata.size() == 0
        || metadata.size() > MAX_PROTECTED_LAUNCHER_STORE_BYTES_V1 as u64
    {
        return Err(ProtectedLauncherCapabilityError::Unprotected);
    }
    let bytes = read_exact_descriptor(&file, metadata.size() as usize)?;
    let content_identity = protected_launcher_store_content_identity_v1(role, bytes.as_slice())
        .map_err(|_| ProtectedLauncherCapabilityError::Unprotected)?;
    let descriptor = observe_store_descriptor_v1(&file, role, content_identity)?;
    revalidate_store(&file, &descriptor, bytes.as_slice())?;
    Ok((file, bytes, descriptor))
}

#[cfg(target_os = "linux")]
fn revalidate_store(
    file: &File,
    expected: &ProtectedLauncherDescriptorV1,
    expected_bytes: &[u8],
) -> Result<(), ProtectedLauncherCapabilityError> {
    let content_identity =
        protected_launcher_store_content_identity_v1(expected.role, expected_bytes)
            .map_err(|_| ProtectedLauncherCapabilityError::ReconciliationFailed)?;
    let observed = observe_store_descriptor_v1(file, expected.role, content_identity)?;
    if &observed != expected
        || read_exact_descriptor(file, expected_bytes.len())?.as_slice() != expected_bytes
    {
        return Err(ProtectedLauncherCapabilityError::ReconciliationFailed);
    }
    Ok(())
}

#[cfg(target_os = "linux")]
fn read_exact_descriptor(
    file: &File,
    expected_size: usize,
) -> Result<Vec<u8>, ProtectedLauncherCapabilityError> {
    if expected_size == 0 || expected_size > MAX_PROTECTED_LAUNCHER_STORE_BYTES_V1 {
        return Err(ProtectedLauncherCapabilityError::Unprotected);
    }
    let mut bytes = vec![0_u8; expected_size];
    let mut offset = 0;
    while offset < bytes.len() {
        let count = file
            .read_at(&mut bytes[offset..], offset as u64)
            .map_err(|_| ProtectedLauncherCapabilityError::Unavailable)?;
        if count == 0 {
            return Err(ProtectedLauncherCapabilityError::ReconciliationFailed);
        }
        offset += count;
    }
    let mut extra = [0_u8; 1];
    if file
        .read_at(&mut extra, expected_size as u64)
        .map_err(|_| ProtectedLauncherCapabilityError::Unavailable)?
        != 0
    {
        return Err(ProtectedLauncherCapabilityError::ReconciliationFailed);
    }
    Ok(bytes)
}

#[cfg(target_os = "linux")]
fn verify_directory_descriptor(
    descriptor: RawFd,
    expected_uid: u32,
    expected_gid: u32,
    exact_private_mode: bool,
) -> Result<(), ProtectedLauncherCapabilityError> {
    let mut stat = std::mem::MaybeUninit::<libc::stat>::uninit();
    if unsafe { libc::fstat(descriptor, stat.as_mut_ptr()) } != 0 {
        return Err(ProtectedLauncherCapabilityError::Unavailable);
    }
    let stat = unsafe { stat.assume_init() };
    let mode = stat.st_mode & 0o7777;
    if stat.st_mode & libc::S_IFMT != libc::S_IFDIR
        || stat.st_uid != expected_uid
        || stat.st_gid != expected_gid
        || if exact_private_mode {
            mode != 0o700
        } else {
            mode & 0o022 != 0
        }
    {
        return Err(ProtectedLauncherCapabilityError::Unprotected);
    }
    Ok(())
}

#[cfg(target_os = "linux")]
fn verify_procfs_root(descriptor: RawFd) -> Result<(), ProtectedLauncherCapabilityError> {
    let mut stat = std::mem::MaybeUninit::<libc::statfs>::uninit();
    if unsafe { libc::fstatfs(descriptor, stat.as_mut_ptr()) } != 0 {
        return Err(ProtectedLauncherCapabilityError::Unavailable);
    }
    let stat = unsafe { stat.assume_init() };
    if stat.f_type as libc::c_long != libc::PROC_SUPER_MAGIC as libc::c_long {
        return Err(ProtectedLauncherCapabilityError::Unprotected);
    }
    Ok(())
}

#[cfg(target_os = "linux")]
fn observe_boot_file(
    file: &File,
) -> Result<(u64, u64, u32, String, String), ProtectedLauncherCapabilityError> {
    let metadata = file
        .metadata()
        .map_err(|_| ProtectedLauncherCapabilityError::Unavailable)?;
    let mode = metadata.mode() & 0o7777;
    if !metadata.is_file() || metadata.uid() != 0 || mode & 0o022 != 0 {
        return Err(ProtectedLauncherCapabilityError::Unprotected);
    }
    let mut bytes = [0_u8; 38];
    let count = file
        .read_at(&mut bytes, 0)
        .map_err(|_| ProtectedLauncherCapabilityError::Unavailable)?;
    let value = std::str::from_utf8(&bytes[..count])
        .ok()
        .and_then(|value| value.strip_suffix('\n').or(Some(value)))
        .filter(|value| value.len() == 36)
        .ok_or(ProtectedLauncherCapabilityError::Unprotected)?
        .to_owned();
    let identity = protected_launcher_boot_v1_identity(&value)
        .map_err(|_| ProtectedLauncherCapabilityError::Unprotected)?;
    Ok((metadata.dev(), metadata.ino(), mode, value, identity))
}

#[cfg(target_os = "linux")]
fn verify_cgroup2_root(descriptor: RawFd) -> Result<(), ProtectedLauncherCapabilityError> {
    let mut stat = std::mem::MaybeUninit::<libc::statfs>::uninit();
    if unsafe { libc::fstatfs(descriptor, stat.as_mut_ptr()) } != 0 {
        return Err(ProtectedLauncherCapabilityError::Unavailable);
    }
    let stat = unsafe { stat.assume_init() };
    if stat.f_type as libc::c_long != libc::CGROUP2_SUPER_MAGIC as libc::c_long {
        return Err(ProtectedLauncherCapabilityError::Unprotected);
    }
    Ok(())
}

#[cfg(target_os = "linux")]
fn duplicate_fd(descriptor: RawFd) -> Result<OwnedFd, ProtectedLauncherCapabilityError> {
    let duplicate = unsafe { libc::fcntl(descriptor, libc::F_DUPFD_CLOEXEC, 3) };
    if duplicate < 0 {
        return Err(ProtectedLauncherCapabilityError::Unavailable);
    }
    Ok(unsafe { OwnedFd::from_raw_fd(duplicate) })
}

#[cfg(target_os = "linux")]
#[repr(C)]
struct OpenHow {
    flags: u64,
    mode: u64,
    resolve: u64,
}

#[cfg(target_os = "linux")]
pub(crate) fn openat2_beneath(
    parent: RawFd,
    name: &[u8],
    flags: i32,
) -> Result<OwnedFd, ProtectedLauncherCapabilityError> {
    openat2_beneath_with_mode(parent, name, flags, 0)
}

pub(crate) fn openat2_beneath_with_mode(
    parent: RawFd,
    name: &[u8],
    flags: i32,
    mode: u64,
) -> Result<OwnedFd, ProtectedLauncherCapabilityError> {
    openat2_beneath_with_mode_and_resolution(parent, name, flags, mode, true)
}

#[cfg(target_os = "linux")]
fn openat2_beneath_with_mode_and_resolution(
    parent: RawFd,
    name: &[u8],
    flags: i32,
    mode: u64,
    prohibit_mount_transition: bool,
) -> Result<OwnedFd, ProtectedLauncherCapabilityError> {
    const RESOLVE_NO_XDEV: u64 = 0x01;
    const RESOLVE_NO_MAGICLINKS: u64 = 0x02;
    const RESOLVE_NO_SYMLINKS: u64 = 0x04;
    const RESOLVE_BENEATH: u64 = 0x08;
    let name = CString::new(name).map_err(|_| ProtectedLauncherCapabilityError::Unprotected)?;
    let how = OpenHow {
        flags: flags as u64,
        mode,
        resolve: (if prohibit_mount_transition {
            RESOLVE_NO_XDEV
        } else {
            0
        }) | RESOLVE_NO_MAGICLINKS
            | RESOLVE_NO_SYMLINKS
            | RESOLVE_BENEATH,
    };
    let descriptor = unsafe {
        libc::syscall(
            libc::SYS_openat2,
            parent,
            name.as_ptr(),
            &how,
            std::mem::size_of::<OpenHow>(),
        )
    };
    if descriptor < 0 {
        let error = io::Error::last_os_error();
        return Err(match error.raw_os_error() {
            Some(libc::ENOENT) | Some(libc::ENOSYS) => {
                ProtectedLauncherCapabilityError::Unavailable
            }
            _ => ProtectedLauncherCapabilityError::Unprotected,
        });
    }
    Ok(unsafe { OwnedFd::from_raw_fd(descriptor as RawFd) })
}

#[cfg(all(test, target_os = "linux"))]
mod linux_tests {
    use std::fs;
    use std::os::fd::{AsRawFd, FromRawFd};
    use std::os::unix::fs::{MetadataExt, PermissionsExt};
    use std::os::unix::net::{UnixDatagram, UnixStream};
    use std::time::{Duration, Instant};

    use base64::Engine;
    use base64::engine::general_purpose::URL_SAFE_NO_PAD;
    use ed25519_dalek::{Signer, SigningKey};
    use ota_authority_protocol::*;
    use tempfile::tempdir;

    use super::*;

    #[test]
    fn protected_mount_chain_accepts_only_canonical_components() {
        let root = tempdir().expect("mount-chain root");
        fs::set_permissions(root.path(), fs::Permissions::from_mode(0o700)).expect("root mode");
        let boundary = root.path().join("state");
        fs::create_dir(&boundary).expect("boundary directory");
        fs::set_permissions(&boundary, fs::Permissions::from_mode(0o700)).expect("boundary mode");
        let replay = boundary.join("replay");
        fs::create_dir(&replay).expect("replay directory");
        fs::set_permissions(&replay, fs::Permissions::from_mode(0o700)).expect("replay mode");
        let metadata = root.path().metadata().expect("root metadata");
        let root = open_root(root.path(), metadata.uid(), metadata.gid()).expect("retained root");
        open_protected_directory_chain_allowing_mounts(
            root.as_raw_fd(),
            Path::new("state/replay"),
            metadata.uid(),
            metadata.gid(),
            true,
        )
        .expect("canonical mount chain");
        for alias in [
            "",
            ".",
            "..",
            "state//replay",
            "state/./replay",
            "state/../replay",
            "state/replay/",
            "/state/replay",
        ] {
            assert!(
                open_protected_directory_chain_allowing_mounts(
                    root.as_raw_fd(),
                    Path::new(alias),
                    metadata.uid(),
                    metadata.gid(),
                    true,
                )
                .is_err(),
                "mount-chain alias must refuse: {alias:?}",
            );
        }
    }

    fn create_store_tree() -> tempfile::TempDir {
        let root = tempdir().expect("root");
        fs::set_permissions(root.path(), fs::Permissions::from_mode(0o700)).expect("root mode");
        let authority = root.path().join("authority");
        fs::create_dir(&authority).expect("authority");
        fs::set_permissions(&authority, fs::Permissions::from_mode(0o700)).expect("authority mode");
        for (name, bytes) in [
            (
                SECRET_DELIVERY_VERIFIER_STORE,
                b"{\"verifiers\":[]}".as_slice(),
            ),
            (
                SECRET_DELIVERY_BINDING_STORE,
                b"{\"bindings\":[]}".as_slice(),
            ),
        ] {
            let path = authority.join(name);
            fs::write(&path, bytes).expect("store");
            fs::set_permissions(path, fs::Permissions::from_mode(0o400)).expect("store mode");
        }
        root
    }

    fn create_signed_authority_bundle_store_tree() -> (
        tempfile::TempDir,
        ProtectedSecretDeliveryVerifierStoreV1,
        ProtectedSecretDeliveryBindingBundleV1,
        Vec<u8>,
    ) {
        let root = create_store_tree();
        let authority = root.path().join("authority");
        let signing_key = SigningKey::from_bytes(&[9; 32]);
        let public_key = URL_SAFE_NO_PAD.encode(signing_key.verifying_key().to_bytes());
        let mut verifier = ProtectedSecretDeliveryBindingBundleVerifierV1 {
            schema_version: 1,
            record_kind: PROTECTED_SECRET_DELIVERY_BINDING_BUNDLE_VERIFIER.into(),
            identity: String::new(),
            public_key: public_key.clone(),
            key_identity: protected_secret_delivery_binding_bundle_key_identity_v1(&public_key)
                .expect("key identity"),
            key_usage: PROTECTED_SECRET_DELIVERY_BINDING_BUNDLE_KEY_USAGE_V1.into(),
            signature_domain: std::str::from_utf8(
                PROTECTED_SECRET_DELIVERY_BINDING_BUNDLE_SIGNATURE_DOMAIN_V1,
            )
            .expect("signature domain")
            .into(),
        };
        verifier.identity =
            protected_secret_delivery_binding_bundle_verifier_v1_identity(&verifier)
                .expect("verifier identity");
        let payload = br#"{"schema_version":1,"bindings":[]}"#.to_vec();
        let mut bundle = ProtectedSecretDeliveryBindingBundleV1 {
            schema_version: 1,
            record_kind: PROTECTED_SECRET_DELIVERY_BINDING_BUNDLE.into(),
            identity: String::new(),
            authority_id: "ota-secret-delivery".into(),
            generation: 1,
            issued_at_unix_seconds: 1_788_800_000,
            expires_at_unix_seconds: 1_788_803_600,
            verifier_identity: verifier.identity.clone(),
            payload: URL_SAFE_NO_PAD.encode(&payload),
            payload_identity: protected_secret_delivery_binding_bundle_payload_v1_identity(
                &payload,
            )
            .expect("payload identity"),
            signature: "A".repeat(86),
        };
        bundle.identity =
            protected_secret_delivery_binding_bundle_v1_identity(&bundle).expect("bundle identity");
        sign_authority_bundle(&mut bundle, &signing_key);
        let mut store = ProtectedSecretDeliveryVerifierStoreV1 {
            schema_version: 1,
            record_kind: PROTECTED_SECRET_DELIVERY_VERIFIER_STORE.into(),
            identity: String::new(),
            authority_id: bundle.authority_id.clone(),
            generation: 1,
            not_before_unix_seconds: bundle.issued_at_unix_seconds,
            not_after_unix_seconds: bundle.expires_at_unix_seconds,
            verifiers: vec![verifier],
            active_binding_bundle_identity: bundle.identity.clone(),
            active_binding_bundle_generation: bundle.generation,
        };
        store.identity =
            protected_secret_delivery_verifier_store_v1_identity(&store).expect("store identity");
        write_authority_bundle_records(&authority, &store, &bundle);
        (root, store, bundle, payload)
    }

    fn sign_authority_bundle(
        bundle: &mut ProtectedSecretDeliveryBindingBundleV1,
        signing_key: &SigningKey,
    ) {
        bundle.identity =
            protected_secret_delivery_binding_bundle_v1_identity(bundle).expect("bundle identity");
        bundle.signature = URL_SAFE_NO_PAD.encode(
            signing_key
                .sign(
                    &protected_secret_delivery_binding_bundle_signature_message_v1(
                        bundle.identity.as_str(),
                    )
                    .expect("signature message"),
                )
                .to_bytes(),
        );
    }

    fn write_authority_bundle_records(
        authority: &Path,
        store: &ProtectedSecretDeliveryVerifierStoreV1,
        bundle: &ProtectedSecretDeliveryBindingBundleV1,
    ) {
        for (name, bytes) in [
            (
                SECRET_DELIVERY_VERIFIER_STORE,
                serde_jcs::to_vec(&store).expect("store JSON"),
            ),
            (
                SECRET_DELIVERY_BINDING_STORE,
                serde_jcs::to_vec(&bundle).expect("bundle JSON"),
            ),
        ] {
            let path = authority.join(name);
            fs::set_permissions(&path, fs::Permissions::from_mode(0o600)).expect("write mode");
            fs::write(&path, bytes).expect("authority record");
            fs::set_permissions(path, fs::Permissions::from_mode(0o400)).expect("protected mode");
        }
    }

    #[test]
    fn retained_authority_bundle_verifies_signature_and_descriptor_bytes() {
        let (root, _store, bundle, payload) = create_signed_authority_bundle_store_tree();
        let metadata = root.path().metadata().expect("root metadata");
        let stores = ProtectedAuthorityStoresV1::open_beneath(
            root.path(),
            Path::new("authority"),
            metadata.uid(),
            metadata.gid(),
        )
        .expect("retained stores");
        let verified = stores
            .verify_secret_delivery_authority_bundle_at_v1(bundle.issued_at_unix_seconds)
            .expect("current signed bundle");
        assert_eq!(verified.binding_bundle.identity, bundle.identity);
        assert_eq!(verified.binding_payload, payload);
        assert_eq!(
            verified.binding_bundle.payload_identity,
            bundle.payload_identity
        );
        assert_eq!(
            verified
                .verifier_store_descriptor
                .content_identity
                .as_deref(),
            Some(
                protected_launcher_store_content_identity_v1(
                    ProtectedLauncherDescriptorRoleV1::VerifierStore,
                    verified.verifier_store_bytes.as_slice(),
                )
                .expect("verifier content identity")
                .as_str()
            )
        );
        assert_eq!(
            verified
                .binding_store_descriptor
                .content_identity
                .as_deref(),
            Some(
                protected_launcher_store_content_identity_v1(
                    ProtectedLauncherDescriptorRoleV1::BindingStore,
                    verified.binding_store_bytes.as_slice(),
                )
                .expect("binding content identity")
                .as_str()
            )
        );

        let binding_path = root
            .path()
            .join("authority")
            .join(SECRET_DELIVERY_BINDING_STORE);
        let mut bytes = fs::read(&binding_path).expect("binding bytes");
        let index = bytes
            .iter()
            .position(|byte| *byte == b'a')
            .expect("mutable byte");
        bytes[index] = b'b';
        fs::set_permissions(&binding_path, fs::Permissions::from_mode(0o600)).expect("write mode");
        fs::write(&binding_path, bytes).expect("same-length drift");
        fs::set_permissions(&binding_path, fs::Permissions::from_mode(0o400))
            .expect("protected mode");
        assert!(matches!(
            stores.verify_secret_delivery_authority_bundle_at_v1(bundle.issued_at_unix_seconds),
            Err(ProtectedLauncherCapabilityError::ReconciliationFailed)
        ));
    }

    #[test]
    fn retained_authority_bundle_refuses_structurally_valid_wrong_signature() {
        let (root, _store, bundle, _) = create_signed_authority_bundle_store_tree();
        let binding_path = root
            .path()
            .join("authority")
            .join(SECRET_DELIVERY_BINDING_STORE);
        let mut invalid = bundle;
        invalid.signature = "A".repeat(86);
        fs::set_permissions(&binding_path, fs::Permissions::from_mode(0o600)).expect("write mode");
        fs::write(
            &binding_path,
            serde_jcs::to_vec(&invalid).expect("invalid bundle JSON"),
        )
        .expect("invalid bundle");
        fs::set_permissions(&binding_path, fs::Permissions::from_mode(0o400))
            .expect("protected mode");
        let metadata = root.path().metadata().expect("root metadata");
        let stores = ProtectedAuthorityStoresV1::open_beneath(
            root.path(),
            Path::new("authority"),
            metadata.uid(),
            metadata.gid(),
        )
        .expect("retained stores");
        assert!(matches!(
            stores.verify_secret_delivery_authority_bundle_at_v1(invalid.issued_at_unix_seconds),
            Err(ProtectedLauncherCapabilityError::ReconciliationFailed)
        ));
    }

    #[test]
    fn retained_authority_bundle_refuses_weak_keys_and_protocol_substitutions() {
        let verify_mutation = |mutate: &dyn Fn(
            &mut ProtectedSecretDeliveryVerifierStoreV1,
            &mut ProtectedSecretDeliveryBindingBundleV1,
        ),
                               after_signing: &dyn Fn(
            &mut ProtectedSecretDeliveryVerifierStoreV1,
            &ProtectedSecretDeliveryBindingBundleV1,
        ),
                               observed_at: u64| {
            let (root, mut store, mut bundle, _) = create_signed_authority_bundle_store_tree();
            mutate(&mut store, &mut bundle);
            let signing_key = SigningKey::from_bytes(&[9; 32]);
            sign_authority_bundle(&mut bundle, &signing_key);
            store.active_binding_bundle_identity = bundle.identity.clone();
            after_signing(&mut store, &bundle);
            store.identity = protected_secret_delivery_verifier_store_v1_identity(&store)
                .expect("mutated store identity");
            write_authority_bundle_records(&root.path().join("authority"), &store, &bundle);
            let metadata = root.path().metadata().expect("root metadata");
            let stores = ProtectedAuthorityStoresV1::open_beneath(
                root.path(),
                Path::new("authority"),
                metadata.uid(),
                metadata.gid(),
            )
            .expect("retained stores");
            stores.verify_secret_delivery_authority_bundle_at_v1(observed_at)
        };
        const OBSERVED_AT: u64 = 1_788_800_001;

        assert!(matches!(
            verify_mutation(
                &|_store, bundle| {
                    bundle.authority_id = "other-authority".into();
                },
                &|_, _| {},
                OBSERVED_AT,
            ),
            Err(ProtectedLauncherCapabilityError::ReconciliationFailed)
        ));
        assert!(matches!(
            verify_mutation(
                &|_store, bundle| {
                    bundle.generation = 2;
                },
                &|_, _| {},
                OBSERVED_AT,
            ),
            Err(ProtectedLauncherCapabilityError::ReconciliationFailed)
        ));
        assert!(matches!(
            verify_mutation(
                &|_, _| {},
                &|store, _bundle| {
                    store.active_binding_bundle_identity = format!("sha256:{}", "f".repeat(64));
                },
                OBSERVED_AT,
            ),
            Err(ProtectedLauncherCapabilityError::ReconciliationFailed)
        ));
        assert!(matches!(
            verify_mutation(
                &|_store, bundle| {
                    bundle.verifier_identity = format!("sha256:{}", "e".repeat(64));
                },
                &|_, _| {},
                OBSERVED_AT,
            ),
            Err(ProtectedLauncherCapabilityError::ReconciliationFailed)
        ));
        assert!(matches!(
            verify_mutation(
                &|store, bundle| {
                    store.not_before_unix_seconds = OBSERVED_AT + 1;
                    bundle.issued_at_unix_seconds = store.not_before_unix_seconds;
                    bundle.expires_at_unix_seconds = store.not_after_unix_seconds;
                },
                &|_, _| {},
                OBSERVED_AT,
            ),
            Err(ProtectedLauncherCapabilityError::ReconciliationFailed)
        ));
        assert!(matches!(
            verify_mutation(
                &|store, bundle| {
                    store.not_after_unix_seconds = OBSERVED_AT;
                    bundle.expires_at_unix_seconds = OBSERVED_AT;
                },
                &|_, _| {},
                OBSERVED_AT + 1,
            ),
            Err(ProtectedLauncherCapabilityError::ReconciliationFailed)
        ));

        let (root, mut store, mut bundle, _) = create_signed_authority_bundle_store_tree();
        let weak_public_key = URL_SAFE_NO_PAD.encode([
            1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
            0, 0, 0,
        ]);
        let verifier = &mut store.verifiers[0];
        verifier.public_key = weak_public_key.clone();
        verifier.key_identity =
            protected_secret_delivery_binding_bundle_key_identity_v1(weak_public_key.as_str())
                .expect("weak key identity");
        verifier.identity = protected_secret_delivery_binding_bundle_verifier_v1_identity(verifier)
            .expect("weak verifier identity");
        bundle.verifier_identity = verifier.identity.clone();
        bundle.identity = protected_secret_delivery_binding_bundle_v1_identity(&bundle)
            .expect("weak bundle identity");
        bundle.signature = URL_SAFE_NO_PAD.encode([
            1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
            0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
            0, 0, 0, 0, 0, 0,
        ]);
        store.active_binding_bundle_identity = bundle.identity.clone();
        store.identity = protected_secret_delivery_verifier_store_v1_identity(&store)
            .expect("weak store identity");
        write_authority_bundle_records(&root.path().join("authority"), &store, &bundle);
        let metadata = root.path().metadata().expect("root metadata");
        let stores = ProtectedAuthorityStoresV1::open_beneath(
            root.path(),
            Path::new("authority"),
            metadata.uid(),
            metadata.gid(),
        )
        .expect("weak retained stores");
        assert!(matches!(
            stores.verify_secret_delivery_authority_bundle_at_v1(OBSERVED_AT),
            Err(ProtectedLauncherCapabilityError::ReconciliationFailed)
        ));

        let (root, _store, bundle, _) = create_signed_authority_bundle_store_tree();
        let binding_path = root
            .path()
            .join("authority")
            .join(SECRET_DELIVERY_BINDING_STORE);
        fs::set_permissions(&binding_path, fs::Permissions::from_mode(0o600)).expect("write mode");
        fs::write(&binding_path, b"{").expect("malformed bundle");
        fs::set_permissions(&binding_path, fs::Permissions::from_mode(0o400))
            .expect("protected mode");
        let metadata = root.path().metadata().expect("root metadata");
        let stores = ProtectedAuthorityStoresV1::open_beneath(
            root.path(),
            Path::new("authority"),
            metadata.uid(),
            metadata.gid(),
        )
        .expect("retained malformed stores");
        assert!(matches!(
            stores.verify_secret_delivery_authority_bundle_at_v1(bundle.issued_at_unix_seconds),
            Err(ProtectedLauncherCapabilityError::Unprotected)
        ));
    }

    #[test]
    fn authority_stores_are_opened_beneath_retained_descriptors() {
        let root = create_store_tree();
        let metadata = root.path().metadata().expect("metadata");
        let stores = ProtectedAuthorityStoresV1::open_beneath(
            root.path(),
            Path::new("authority"),
            metadata.uid(),
            metadata.gid(),
        )
        .expect("protected stores");
        assert_eq!(stores.descriptors().len(), 2);
        stores.revalidate().expect("retained stores");
    }

    #[test]
    fn authority_store_aliases_and_writable_directories_refuse() {
        let root = create_store_tree();
        let metadata = root.path().metadata().expect("metadata");
        let authority = root.path().join("authority");
        fs::remove_file(authority.join(SECRET_DELIVERY_BINDING_STORE)).expect("remove store");
        std::os::unix::fs::symlink(
            authority.join(SECRET_DELIVERY_VERIFIER_STORE),
            authority.join(SECRET_DELIVERY_BINDING_STORE),
        )
        .expect("alias");
        assert!(
            ProtectedAuthorityStoresV1::open_beneath(
                root.path(),
                Path::new("authority"),
                metadata.uid(),
                metadata.gid(),
            )
            .is_err()
        );

        fs::remove_file(authority.join(SECRET_DELIVERY_BINDING_STORE)).expect("remove alias");
        fs::write(
            authority.join(SECRET_DELIVERY_BINDING_STORE),
            b"{\"bindings\":[]}",
        )
        .expect("restore store");
        fs::set_permissions(
            authority.join(SECRET_DELIVERY_BINDING_STORE),
            fs::Permissions::from_mode(0o400),
        )
        .expect("store mode");
        fs::set_permissions(&authority, fs::Permissions::from_mode(0o720))
            .expect("writable authority");
        assert!(
            ProtectedAuthorityStoresV1::open_beneath(
                root.path(),
                Path::new("authority"),
                metadata.uid(),
                metadata.gid(),
            )
            .is_err()
        );

        fs::set_permissions(&authority, fs::Permissions::from_mode(0o700))
            .expect("restore authority mode");
        fs::remove_file(authority.join(SECRET_DELIVERY_BINDING_STORE)).expect("remove store");
        fs::hard_link(
            authority.join(SECRET_DELIVERY_VERIFIER_STORE),
            authority.join(SECRET_DELIVERY_BINDING_STORE),
        )
        .expect("hardlink alias");
        assert!(
            ProtectedAuthorityStoresV1::open_beneath(
                root.path(),
                Path::new("authority"),
                metadata.uid(),
                metadata.gid(),
            )
            .is_err()
        );
    }

    #[test]
    fn descriptor_roles_are_observed_from_kernel_state() {
        let (session, _peer) = UnixStream::pair().expect("stream pair");
        assert!(observe_launcher_session_descriptor_v1(&session).is_ok());

        let datagram = UnixDatagram::unbound().expect("datagram");
        assert!(
            observe_raw_descriptor_v1(
                datagram.as_raw_fd(),
                ProtectedLauncherDescriptorRoleV1::LauncherSessionSocket,
                None,
            )
            .is_err()
        );

        let tcp = unsafe { libc::socket(libc::AF_INET, libc::SOCK_STREAM | libc::SOCK_CLOEXEC, 0) };
        assert!(tcp >= 0, "TCP socket");
        let tcp = unsafe { std::os::fd::OwnedFd::from_raw_fd(tcp) };
        assert!(
            observe_raw_descriptor_v1(
                tcp.as_raw_fd(),
                ProtectedLauncherDescriptorRoleV1::LauncherSessionSocket,
                None,
            )
            .is_err()
        );

        let root = create_store_tree();
        let store = fs::File::options()
            .read(true)
            .write(true)
            .open(
                root.path()
                    .join("authority")
                    .join(SECRET_DELIVERY_VERIFIER_STORE),
            )
            .expect("read-write store");
        assert!(
            observe_store_descriptor_v1(
                &store,
                ProtectedLauncherDescriptorRoleV1::VerifierStore,
                protected_launcher_store_content_identity_v1(
                    ProtectedLauncherDescriptorRoleV1::VerifierStore,
                    b"{\"verifiers\":[]}",
                )
                .expect("content identity"),
            )
            .is_err()
        );
    }

    #[test]
    fn fifo_store_refuses_without_blocking() {
        let root = create_store_tree();
        let metadata = root.path().metadata().expect("metadata");
        let fifo = root
            .path()
            .join("authority")
            .join(SECRET_DELIVERY_BINDING_STORE);
        fs::remove_file(&fifo).expect("remove store");
        let path = CString::new(fifo.as_os_str().as_encoded_bytes()).expect("FIFO path");
        assert_eq!(
            unsafe { libc::mkfifo(path.as_ptr(), 0o400) },
            0,
            "create FIFO"
        );

        let started = Instant::now();
        assert!(
            ProtectedAuthorityStoresV1::open_beneath(
                root.path(),
                Path::new("authority"),
                metadata.uid(),
                metadata.gid(),
            )
            .is_err()
        );
        assert!(
            started.elapsed() < Duration::from_secs(1),
            "FIFO open must be bounded"
        );
    }
}

#[cfg(all(
    test,
    target_os = "linux",
    feature = "secret-delivery-pressure",
    feature = "protected-attestor"
))]
mod privileged_linux_tests {
    use std::fs;
    use std::os::unix::fs::PermissionsExt;
    use std::os::unix::net::UnixStream;

    use base64::Engine;
    use base64::engine::general_purpose::URL_SAFE_NO_PAD;
    use ed25519_dalek::SigningKey;
    use ota_authority_protocol::*;

    use super::*;
    use crate::attestation_client::verify_capability_observation_signature_response;
    use crate::attestor::AttestationIssuer;
    use crate::protected_capability_observation::{
        ProtectedCapabilityObservationError, ProtectedCapabilityObservationReplayStoreV1,
        derive_and_sign_capability_observation_for_test_v1,
        derive_secret_delivery_transaction_binding_for_test_v1,
    };

    struct CapabilityFixture {
        request: LauncherInvocationRequestV1,
        child: LauncherChildProcessV1,
        scope: LauncherSystemdScopeV1,
        principal_mapping: LauncherPrincipalMappingV1,
        process_posture: OtaProcessPostureV1,
        launcher_instance: SystemdProtectedLauncherInstanceEvidenceV2,
        launcher_executable_identity: String,
        launcher_configuration_identity: String,
        launcher_service_binding_identity: String,
        launcher_profile_identity: String,
        authority: RetainedProtectedLauncherAuthorityContextV1,
    }

    impl CapabilityFixture {
        fn context(&self) -> ProtectedLauncherCapabilityContextV1<'_> {
            ProtectedLauncherCapabilityContextV1 {
                request: &self.request,
                child: &self.child,
                scope: &self.scope,
                principal_mapping: &self.principal_mapping,
                process_posture: &self.process_posture,
                launcher_instance: &self.launcher_instance,
                launcher_executable_identity: self.launcher_executable_identity.as_str(),
                launcher_configuration_identity: self.launcher_configuration_identity.as_str(),
                launcher_service_binding_identity: self.launcher_service_binding_identity.as_str(),
                launcher_profile_identity: self.launcher_profile_identity.as_str(),
                service_uid: 0,
                service_gid: 0,
                authority: &self.authority,
            }
        }
    }

    fn identity(value: char) -> String {
        format!("sha256:{}", value.to_string().repeat(64))
    }

    fn principal(uid: u32, gid: u32) -> UnixPrincipalIdentity {
        UnixPrincipalIdentity {
            real_uid: uid,
            effective_uid: uid,
            saved_uid: uid,
            filesystem_uid: uid,
            real_gid: gid,
            effective_gid: gid,
            saved_gid: gid,
            filesystem_gid: gid,
        }
    }

    fn current_control_group() -> String {
        const EXPECTED_CONTROL_GROUP: &str = "/ota.slice/ota-authority.slice/ota-authority-invocations.slice/ota-authority-invocation-0123456789abcdef.scope";
        let cgroup = fs::read_to_string("/proc/self/cgroup").expect("current cgroup");
        let observed = cgroup
            .lines()
            .find_map(|line| line.strip_prefix("0::"))
            .expect("unified cgroup-v2 path");
        assert_eq!(
            observed, EXPECTED_CONTROL_GROUP,
            "test must run inside the exact requested systemd slice and scope",
        );
        observed.to_owned()
    }

    fn fixture() -> CapabilityFixture {
        assert_eq!(unsafe { libc::geteuid() }, 0, "test requires root");
        let request = LauncherInvocationRequestV1 {
            message_kind: LAUNCHER_INVOCATION_REQUEST.into(),
            protocol_version: SYSTEMD_LAUNCHER_SERVICE_PROTOCOL_V1.into(),
            authority_id: "secret-delivery".into(),
            ota_arguments: vec!["run".into(), "publish".into()],
            repository_path: "/srv/ota/repository".into(),
        };
        let request_identity =
            launcher_invocation_request_identity(&request).expect("request identity");
        let launcher_configuration_identity = identity('3');
        let job_profile = systemd_job_principal_profile_v2();
        let job_profile_identity =
            systemd_job_principal_profile_identity(&job_profile).expect("job profile identity");
        let mut principal_mapping = LauncherPrincipalMappingV1 {
            schema_version: 1,
            identity: String::new(),
            job_peer: principal(1001, 1001),
            execution: principal(1002, 1002),
            job_principal_profile_identity: job_profile_identity.clone(),
            launcher_session_binding_identity: launcher_configuration_identity.clone(),
        };
        principal_mapping.identity = launcher_principal_mapping_identity(&principal_mapping)
            .expect("principal mapping identity");
        let mut working_directory = LauncherWorkingDirectoryV1 {
            schema_version: 1,
            identity: String::new(),
            logical_path: request.repository_path.clone(),
            device: 31,
            inode: 3100,
        };
        working_directory.identity =
            launcher_working_directory_identity(&working_directory).expect("working identity");
        let mut child = LauncherChildProcessV1 {
            schema_version: 1,
            identity: String::new(),
            invocation_id: "secret-delivery-1".into(),
            request_identity: request_identity.clone(),
            pid: std::process::id(),
            process_start_time_identity: identity('7'),
            ota_binary_identity: identity('2'),
            principal_mapping_identity: principal_mapping.identity.clone(),
            working_directory_identity: working_directory.identity,
        };
        child.identity = launcher_child_process_identity(&child).expect("child identity");
        let unit_name = "ota-authority-invocation-0123456789abcdef.scope";
        let mut scope = LauncherSystemdScopeV1 {
            schema_version: 1,
            identity: String::new(),
            invocation_id: child.invocation_id.clone(),
            request_identity,
            child_identity: child.identity.clone(),
            child_pid: child.pid,
            unit_name: unit_name.into(),
            unit_object_path: format!("/org/freedesktop/systemd1/unit/{unit_name}"),
            slice: "ota-authority-invocations.slice".into(),
            control_group: current_control_group(),
            delegate: false,
            kill_mode: "control-group".into(),
            collect_mode: "inactive-or-failed".into(),
        };
        scope.identity = launcher_systemd_scope_identity(&scope).expect("scope identity");
        let mut process_posture = OtaProcessPostureV1 {
            schema_version: 1,
            identity: String::new(),
            message_kind: OTA_PROCESS_POSTURE.into(),
            pid: child.pid,
            process_start_time_identity: child.process_start_time_identity.clone(),
            ota_binary_identity: child.ota_binary_identity.clone(),
            no_new_privs: true,
            dumpable: 0,
            ptracer_clear_applied: true,
            principal_mapping_identity: principal_mapping.identity.clone(),
        };
        process_posture.identity =
            ota_process_posture_identity(&process_posture).expect("process posture identity");
        let launcher_profile = systemd_launcher_profile_v4();
        let launcher_profile_identity = systemd_launcher_profile_identity(&launcher_profile)
            .expect("launcher profile identity");
        let mut foundation = SystemdProtectedLauncherInstanceEvidenceV1 {
            schema_version: 1,
            identity: String::new(),
            adapter: SYSTEMD_PROTECTED_LAUNCHER_ADAPTER_V1.into(),
            principal_mapping: principal_mapping.clone(),
            process_posture: process_posture.clone(),
            systemd_launcher_profile_identity: launcher_profile_identity.clone(),
            systemd_job_principal_profile_identity: job_profile_identity,
            launcher_session_binding_identity: launcher_configuration_identity.clone(),
            systemd_invocation_identity: scope.identity.clone(),
            working_directory_identity: child.working_directory_identity.clone(),
            child_process_identity: child.identity.clone(),
        };
        foundation.identity =
            systemd_protected_launcher_instance_v3_foundation_identity(&foundation)
                .expect("foundation identity");
        let mut launcher_instance = SystemdProtectedLauncherInstanceEvidenceV2 {
            schema_version: 3,
            identity: String::new(),
            instance_v1: foundation,
            launcher_observations: launcher_profile
                .evidence_sources
                .into_iter()
                .map(|source| SystemdLauncherObservation {
                    source,
                    state: RuntimeBoundaryObservationState::Verified,
                    reason_code: "verified_by_systemd_protected_launcher".into(),
                    evidence_identity: Some(identity('8')),
                })
                .collect(),
            job_principal_observations: job_profile
                .requirements
                .into_iter()
                .map(|required| SystemdJobPrincipalObservation {
                    requirement: required.requirement,
                    evidence_methods: required.evidence_methods,
                    state: RuntimeBoundaryObservationState::Verified,
                    reason_code: "verified_by_systemd_protected_launcher".into(),
                    evidence_identity: Some(identity('9')),
                })
                .collect(),
        };
        launcher_instance.identity =
            systemd_protected_launcher_instance_v2_identity(&launcher_instance)
                .expect("launcher instance identity");
        let mut runner_administrator = RunnerAdministratorAuthorityV1 {
            schema_version: 1,
            record_kind: RUNNER_ADMINISTRATOR_AUTHORITY.into(),
            identity: String::new(),
            authority_id: String::from("secret-delivery"),
            authority_instance_id: URL_SAFE_NO_PAD.encode([6_u8; 32]),
            administration_scope: String::from("protected_self_hosted_runner"),
        };
        runner_administrator.identity =
            runner_administrator_authority_v1_identity(&runner_administrator)
                .expect("runner administrator identity");
        let mut implementation_subject = ProtectedLauncherImplementationSubjectV1 {
            schema_version: 1,
            record_kind: PROTECTED_LAUNCHER_IMPLEMENTATION_SUBJECT.into(),
            identity: String::new(),
            launcher_source_repository: String::from(
                "https://github.com/ota-run/authority-launcher",
            ),
            launcher_source_revision: "1".repeat(40),
            core_source_repository: String::from("https://github.com/ota-run/ota"),
            core_source_revision: "2".repeat(40),
            protocol_source_repository: String::from(
                "https://github.com/ota-run/authority-protocol",
            ),
            protocol_source_revision: "3".repeat(40),
            launcher_build_identity: identity('a'),
            core_build_identity: identity('b'),
            launcher_artifact_identity: identity('1'),
            ota_artifact_identity: child.ota_binary_identity.clone(),
            protocol_version: SYSTEMD_LAUNCHER_SERVICE_PROTOCOL_V1.into(),
            minimum_core_version: String::from("1.6.28"),
            maximum_exclusive_core_version: String::from("1.7.0"),
            launcher_profile_identity: launcher_profile_identity.clone(),
            target: ProtectedLauncherImplementationTargetV1 {
                environment: String::from("self_hosted"),
                os: String::from("linux"),
                architecture: String::from("x86_64"),
                execution_mode: String::from("native"),
                launcher_class: String::from("systemd_protected_launcher_v4"),
            },
        };
        implementation_subject.identity =
            protected_launcher_implementation_subject_v1_identity(&implementation_subject)
                .expect("implementation subject identity");
        let mut authority = ProtectedLauncherAuthorityContextV1 {
            schema_version: 1,
            record_kind: PROTECTED_LAUNCHER_AUTHORITY_CONTEXT.into(),
            identity: String::new(),
            runner_administrator,
            implementation_subject,
        };
        authority.identity = protected_launcher_authority_context_v1_identity(&authority)
            .expect("authority context identity");
        let invocation_nonce = [10_u8; 32];
        let retained_authority =
            RetainedProtectedLauncherAuthorityContextV1::for_test(authority, invocation_nonce)
                .expect("retained authority context");
        CapabilityFixture {
            request,
            child,
            scope,
            principal_mapping,
            process_posture,
            launcher_instance,
            launcher_executable_identity: identity('1'),
            launcher_configuration_identity,
            launcher_service_binding_identity: identity('4'),
            launcher_profile_identity,
            authority: retained_authority,
        }
    }

    fn observation(scope: &LauncherSystemdScopeV1) -> RetainedProtectedLauncherObservationV1 {
        let stores = ProtectedAuthorityStoresV1::open().expect("protected stores");
        let cgroup = RetainedInvocationCgroupV1::open(scope).expect("invocation cgroup");
        let (session, _peer) = UnixStream::pair().expect("session pair");
        RetainedProtectedLauncherObservationV1::observe(stores, cgroup, session)
            .expect("retained observation")
    }

    fn observation_request(
        nonce: &[u8; 32],
        attempt: &str,
        expected_launcher_request_identity: &str,
    ) -> ProtectedLauncherCapabilityObservationRequestV1 {
        let mut challenge = ProtectedLauncherCapabilityObservationChallengeV1 {
            schema_version: 1,
            message_kind: PROTECTED_LAUNCHER_CAPABILITY_OBSERVATION_CHALLENGE.into(),
            identity: String::new(),
            workflow_run_id: "34153231585".into(),
            workflow_run_attempt: attempt.into(),
            workflow_reference: "ota-run/ota/.github/workflows/secret-delivery-oidc-endpoint-evidence.yml@refs/heads/1.6.28-implementation".into(),
            nonce_commitment: protected_launcher_capability_observation_nonce_commitment_v1(nonce)
                .expect("nonce commitment"),
            issued_at_unix_seconds: 1_788_800_000,
            expires_at_unix_seconds: 1_788_800_300,
        };
        challenge.identity =
            protected_launcher_capability_observation_challenge_v1_identity(&challenge)
                .expect("challenge identity");
        let mut request = ProtectedLauncherCapabilityObservationRequestV1 {
            schema_version: 1,
            message_kind: PROTECTED_LAUNCHER_CAPABILITY_OBSERVATION_REQUEST.into(),
            identity: String::new(),
            challenge,
            nonce: URL_SAFE_NO_PAD.encode(nonce),
            runner_version: "2.337.0".into(),
            expected_launcher_request_identity: expected_launcher_request_identity.into(),
        };
        request.identity = protected_launcher_capability_observation_request_v1_identity(&request)
            .expect("request identity");
        request
    }

    fn projection_verifier(
        signing_key: &SigningKey,
    ) -> ProtectedLauncherCapabilityProjectionVerifierV1 {
        let public_key = URL_SAFE_NO_PAD.encode(signing_key.verifying_key().to_bytes());
        let mut verifier = ProtectedLauncherCapabilityProjectionVerifierV1 {
            schema_version: 1,
            record_kind: PROTECTED_LAUNCHER_CAPABILITY_PROJECTION_VERIFIER.into(),
            identity: String::new(),
            public_key: public_key.clone(),
            key_identity: protected_launcher_capability_projection_key_identity_v1(&public_key)
                .expect("key identity"),
            key_usage: PROTECTED_LAUNCHER_CAPABILITY_OBSERVATION_PROJECTION_KEY_USAGE_V1.into(),
            signature_domain: std::str::from_utf8(
                PROTECTED_LAUNCHER_CAPABILITY_OBSERVATION_SIGNATURE_DOMAIN_V1,
            )
            .expect("signature domain")
            .into(),
        };
        verifier.identity =
            protected_launcher_capability_projection_verifier_v1_identity(&verifier)
                .expect("verifier identity");
        verifier
    }

    #[test]
    #[ignore = "requires root-owned stores and a real transient systemd cgroup-v2 scope"]
    fn retained_observation_derives_and_rejects_live_substitution() {
        let mut fixture = fixture();
        let mut retained = observation(&fixture.scope);
        let capability = derive_protected_launcher_capability_v1(&fixture.context(), &mut retained)
            .expect("live capability");

        fixture.authority.invocation_nonce[0] ^= 1;
        assert!(
            derive_protected_launcher_capability_v1(&fixture.context(), &mut retained).is_err()
        );
        fixture.authority.invocation_nonce[0] ^= 1;

        let original_authority = fixture.authority.fixture_authority_mut().clone();
        let authority = fixture.authority.fixture_authority_mut();
        authority.runner_administrator.authority_instance_id = URL_SAFE_NO_PAD.encode([11_u8; 32]);
        authority.runner_administrator.identity =
            runner_administrator_authority_v1_identity(&authority.runner_administrator)
                .expect("substituted administrator identity");
        authority.identity = protected_launcher_authority_context_v1_identity(authority)
            .expect("substituted authority context identity");
        assert!(
            derive_protected_launcher_capability_v1(&fixture.context(), &mut retained).is_err()
        );
        *fixture.authority.fixture_authority_mut() = original_authority.clone();

        let authority = fixture.authority.fixture_authority_mut();
        authority.implementation_subject.core_source_revision = "4".repeat(40);
        authority.implementation_subject.identity =
            protected_launcher_implementation_subject_v1_identity(
                &authority.implementation_subject,
            )
            .expect("substituted implementation identity");
        authority.identity = protected_launcher_authority_context_v1_identity(authority)
            .expect("substituted subject context identity");
        assert!(
            derive_protected_launcher_capability_v1(&fixture.context(), &mut retained).is_err()
        );
        *fixture.authority.fixture_authority_mut() = original_authority;

        let original_boot_identity = fixture.authority.boot.identity.clone();
        fixture.authority.boot.identity = identity('f');
        assert!(
            derive_protected_launcher_capability_v1(&fixture.context(), &mut retained).is_err()
        );
        fixture.authority.boot.identity = original_boot_identity;
        derive_protected_launcher_capability_v1(&fixture.context(), &mut retained)
            .expect("restored authority observations");

        let verifier_path =
            Path::new(SECRET_DELIVERY_AUTHORITY_DIRECTORY).join(SECRET_DELIVERY_VERIFIER_STORE);
        let original = fs::read(&verifier_path).expect("verifier bytes");
        fs::set_permissions(&verifier_path, fs::Permissions::from_mode(0o600)).expect("drift mode");
        assert!(
            derive_protected_launcher_capability_v1(&fixture.context(), &mut retained).is_err()
        );
        fs::set_permissions(&verifier_path, fs::Permissions::from_mode(0o400))
            .expect("restore mode");
        let mut changed = original.clone();
        changed[0] ^= 1;
        assert_eq!(changed.len(), original.len());
        fs::write(&verifier_path, &changed).expect("same-length drift bytes");
        assert!(
            derive_protected_launcher_capability_v1(&fixture.context(), &mut retained).is_err()
        );
        fs::write(&verifier_path, &original).expect("restore bytes");
        derive_protected_launcher_capability_v1(&fixture.context(), &mut retained)
            .expect("restored live capability");

        let mut substituted_session = observation(&fixture.scope);
        let (replacement, _replacement_peer) = UnixStream::pair().expect("replacement session");
        substituted_session.session = replacement;
        assert!(
            derive_protected_launcher_capability_v1(&fixture.context(), &mut substituted_session,)
                .is_err()
        );

        let mut substituted_cgroup = observation(&fixture.scope);
        let mut other_scope = fixture.scope.clone();
        other_scope.child_pid += 1;
        other_scope.identity =
            launcher_systemd_scope_identity(&other_scope).expect("substituted scope identity");
        substituted_cgroup.cgroup =
            RetainedInvocationCgroupV1::open(&other_scope).expect("substituted cgroup");
        assert!(
            derive_protected_launcher_capability_v1(&fixture.context(), &mut substituted_cgroup,)
                .is_err()
        );

        let replay_directory = tempfile::tempdir_in("/root").expect("protected replay directory");
        fs::set_permissions(replay_directory.path(), fs::Permissions::from_mode(0o700))
            .expect("replay directory mode");
        let replay = ProtectedCapabilityObservationReplayStoreV1::open_for_test(
            replay_directory.path(),
            0,
            0,
        )
        .expect("replay store");
        let signing_key = SigningKey::from_bytes(&[7_u8; 32]);
        let issuer = AttestationIssuer::for_capability_observation_test(signing_key.clone());
        let binding = issuer.capability_observation_binding_for_test();
        let verifier = projection_verifier(&signing_key);
        let request_identity = launcher_invocation_request_identity(&fixture.request)
            .expect("launcher request identity");
        let mismatched_request = observation_request(&[6_u8; 32], "4", &identity('f'));
        assert!(matches!(
            derive_and_sign_capability_observation_for_test_v1(
                &replay,
                &mismatched_request,
                mismatched_request.challenge.issued_at_unix_seconds,
                &binding,
                &verifier,
                &fixture.context(),
                &mut retained,
                |_, _, _| unreachable!("mismatched invocation must refuse before signing"),
            ),
            Err(ProtectedCapabilityObservationError::InvalidChallenge)
        ));
        let request = observation_request(&[7_u8; 32], "1", &request_identity);
        let response = derive_and_sign_capability_observation_for_test_v1(
            &replay,
            &request,
            request.challenge.issued_at_unix_seconds,
            &binding,
            &verifier,
            &fixture.context(),
            &mut retained,
            |_, verifier, signing_request| {
                let response = issuer
                    .issue_capability_observation_for_test(signing_request, verifier)
                    .map_err(|_| ProtectedCapabilityObservationError::SignerAuthorityUnavailable)?;
                verify_capability_observation_signature_response(
                    verifier,
                    signing_request,
                    &response,
                )
                .map_err(|_| ProtectedCapabilityObservationError::SignerAuthorityUnavailable)?;
                Ok(response)
            },
        )
        .expect("complete protected observation transaction");
        assert_eq!(response.request_identity, request.identity);
        assert_eq!(
            response.projection.payload.challenge_identity,
            request.challenge.identity
        );
        let response_json = serde_json::to_string(&response).expect("response JSON");
        assert!(!response_json.contains(&request.nonce));
        assert!(!response_json.contains(&capability.identity));

        let mut startup_continuation = LauncherStartupContinuationV1 {
            schema_version: 1,
            identity: String::new(),
            message_kind: LAUNCHER_STARTUP_CONTINUATION.into(),
            invocation_id: fixture.child.invocation_id.clone(),
            launcher_request_identity: request_identity.clone(),
            child_process_identity: fixture.child.identity.clone(),
            working_directory_identity: fixture.child.working_directory_identity.clone(),
            process_posture_identity: fixture.process_posture.identity.clone(),
            principal_mapping_identity: fixture.principal_mapping.identity.clone(),
        };
        startup_continuation.identity =
            launcher_startup_continuation_identity(&startup_continuation)
                .expect("startup continuation identity");
        let transaction_observation = observation_request(&[10_u8; 32], "4", &request_identity);
        let mut transaction_request = ProtectedLauncherSecretDeliveryTransactionBindingRequestV1 {
            schema_version: 1,
            message_kind: PROTECTED_LAUNCHER_SECRET_DELIVERY_TRANSACTION_BINDING_REQUEST.into(),
            identity: String::new(),
            launcher_request_identity: request_identity.clone(),
            observation: transaction_observation,
            secret_transaction_candidate_identity: identity('c'),
            startup_continuation_identity: startup_continuation.identity.clone(),
            session_identity: protected_launcher_secret_delivery_transaction_session_v1_identity(
                startup_continuation.identity.as_str(),
            )
            .expect("transaction session identity"),
        };
        transaction_request.identity =
            protected_launcher_secret_delivery_transaction_binding_request_v1_identity(
                &transaction_request,
            )
            .expect("transaction request identity");
        let transaction_response = derive_secret_delivery_transaction_binding_for_test_v1(
            &replay,
            &transaction_request,
            &startup_continuation,
            &identity('d'),
            transaction_request
                .observation
                .challenge
                .issued_at_unix_seconds,
            &binding,
            &verifier,
            &fixture.context(),
            &mut retained,
            |_, verifier, signing_request| {
                let response = issuer
                    .issue_capability_observation_for_test(signing_request, verifier)
                    .map_err(|_| ProtectedCapabilityObservationError::SignerAuthorityUnavailable)?;
                verify_capability_observation_signature_response(
                    verifier,
                    signing_request,
                    &response,
                )
                .map_err(|_| ProtectedCapabilityObservationError::SignerAuthorityUnavailable)?;
                Ok(response)
            },
        )
        .expect("same-execution secret-delivery transaction binding");
        assert_eq!(
            transaction_response.binding.startup_continuation_identity,
            startup_continuation.identity
        );
        assert_eq!(
            transaction_response.binding.protected_capability_identity,
            capability.identity
        );
        let public_projection_json = serde_json::to_string(&transaction_response.projection)
            .expect("public projection JSON");
        assert!(!public_projection_json.contains(&capability.identity));
        assert!(
            !public_projection_json
                .contains(&transaction_request.secret_transaction_candidate_identity)
        );

        let substituted_observation = observation_request(&[11_u8; 32], "5", &request_identity);
        let mut substituted_request = transaction_request.clone();
        substituted_request.observation = substituted_observation;
        substituted_request.startup_continuation_identity = identity('e');
        substituted_request.session_identity =
            protected_launcher_secret_delivery_transaction_session_v1_identity(
                substituted_request.startup_continuation_identity.as_str(),
            )
            .expect("substituted transaction session identity");
        substituted_request.identity =
            protected_launcher_secret_delivery_transaction_binding_request_v1_identity(
                &substituted_request,
            )
            .expect("substituted transaction request identity");
        assert!(matches!(
            derive_secret_delivery_transaction_binding_for_test_v1(
                &replay,
                &substituted_request,
                &startup_continuation,
                &identity('d'),
                substituted_request
                    .observation
                    .challenge
                    .issued_at_unix_seconds,
                &binding,
                &verifier,
                &fixture.context(),
                &mut retained,
                |_, verifier, signing_request| {
                    issuer
                        .issue_capability_observation_for_test(signing_request, verifier)
                        .map_err(|_| {
                            ProtectedCapabilityObservationError::SignerAuthorityUnavailable
                        })
                },
            ),
            Err(ProtectedCapabilityObservationError::ProjectionInvalid)
        ));
        substituted_request.startup_continuation_identity = startup_continuation.identity.clone();
        substituted_request.session_identity =
            protected_launcher_secret_delivery_transaction_session_v1_identity(
                startup_continuation.identity.as_str(),
            )
            .expect("restored transaction session identity");
        substituted_request.identity =
            protected_launcher_secret_delivery_transaction_binding_request_v1_identity(
                &substituted_request,
            )
            .expect("restored transaction request identity");
        derive_secret_delivery_transaction_binding_for_test_v1(
            &replay,
            &substituted_request,
            &startup_continuation,
            &identity('d'),
            substituted_request
                .observation
                .challenge
                .issued_at_unix_seconds,
            &binding,
            &verifier,
            &fixture.context(),
            &mut retained,
            |_, verifier, signing_request| {
                issuer
                    .issue_capability_observation_for_test(signing_request, verifier)
                    .map_err(|_| ProtectedCapabilityObservationError::SignerAuthorityUnavailable)
            },
        )
        .expect("preflight refusal must not consume replay state");
        assert!(matches!(
            derive_and_sign_capability_observation_for_test_v1(
                &replay,
                &request,
                request.challenge.issued_at_unix_seconds,
                &binding,
                &verifier,
                &fixture.context(),
                &mut retained,
                |_, verifier, signing_request| {
                    issuer
                        .issue_capability_observation_for_test(signing_request, verifier)
                        .map_err(|_| {
                            ProtectedCapabilityObservationError::SignerAuthorityUnavailable
                        })
                },
            ),
            Err(ProtectedCapabilityObservationError::ReplayDetected)
        ));

        let wrong_key = SigningKey::from_bytes(&[8_u8; 32]);
        let wrong_verifier = projection_verifier(&wrong_key);
        let substituted_signer_request = observation_request(&[8_u8; 32], "2", &request_identity);
        assert!(matches!(
            derive_and_sign_capability_observation_for_test_v1(
                &replay,
                &substituted_signer_request,
                substituted_signer_request.challenge.issued_at_unix_seconds,
                &binding,
                &wrong_verifier,
                &fixture.context(),
                &mut retained,
                |_, verifier, signing_request| {
                    issuer
                        .issue_capability_observation_for_test(signing_request, verifier)
                        .map_err(|_| {
                            ProtectedCapabilityObservationError::SignerAuthorityUnavailable
                        })
                },
            ),
            Err(ProtectedCapabilityObservationError::SignerAuthorityUnavailable)
        ));
        assert!(matches!(
            derive_and_sign_capability_observation_for_test_v1(
                &replay,
                &substituted_signer_request,
                substituted_signer_request.challenge.issued_at_unix_seconds,
                &binding,
                &verifier,
                &fixture.context(),
                &mut retained,
                |_, verifier, signing_request| {
                    issuer
                        .issue_capability_observation_for_test(signing_request, verifier)
                        .map_err(|_| {
                            ProtectedCapabilityObservationError::SignerAuthorityUnavailable
                        })
                },
            ),
            Err(ProtectedCapabilityObservationError::ReplayDetected)
        ));

        let expired_request = observation_request(&[9_u8; 32], "3", &request_identity);
        assert!(matches!(
            derive_and_sign_capability_observation_for_test_v1(
                &replay,
                &expired_request,
                expired_request.challenge.expires_at_unix_seconds + 1,
                &binding,
                &verifier,
                &fixture.context(),
                &mut retained,
                |_, verifier, signing_request| {
                    issuer
                        .issue_capability_observation_for_test(signing_request, verifier)
                        .map_err(|_| {
                            ProtectedCapabilityObservationError::SignerAuthorityUnavailable
                        })
                },
            ),
            Err(ProtectedCapabilityObservationError::InvalidChallenge)
        ));
    }
}
