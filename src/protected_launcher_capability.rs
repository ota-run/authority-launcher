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
    LauncherSystemdScopeV1, OtaProcessPostureV1, PROTECTED_LAUNCHER_CAPABILITY,
    ProtectedLauncherCapabilityEvidenceV1, ProtectedLauncherCapabilityV1,
    ProtectedLauncherDescriptorRoleV1, ProtectedLauncherDescriptorV1,
    SYSTEMD_LAUNCHER_SERVICE_PROTOCOL_V1, SystemdProtectedLauncherInstanceEvidenceV2,
    launcher_invocation_request_identity, protected_launcher_capability_v1_identity,
    protected_launcher_cgroup_v1_identity, validate_protected_launcher_capability_v1,
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
pub const SECRET_DELIVERY_AUTHORITY_DIRECTORY: &str = "/etc/ota/secret-delivery";
#[cfg(target_os = "linux")]
pub const SECRET_DELIVERY_VERIFIER_STORE: &str = "verifiers-v1.json";
#[cfg(target_os = "linux")]
pub const SECRET_DELIVERY_BINDING_STORE: &str = "bindings-v1.json";

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
    pub runner_administrator_identity: &'a str,
    pub service_uid: u32,
    pub service_gid: u32,
    pub invocation_nonce_identity: &'a str,
    pub boot_identity: &'a str,
    pub implementation_subject_identity: &'a str,
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
        runner_administrator_identity: input.runner_administrator_identity.into(),
        service_uid: input.service_uid,
        service_gid: input.service_gid,
        invocation_nonce_identity: input.invocation_nonce_identity.into(),
        boot_identity: input.boot_identity.into(),
        protected_launcher_instance_identity: input.launcher_instance.identity.clone(),
        systemd_invocation_identity: input.scope.identity.clone(),
        systemd_scope_identity: input.scope.identity.clone(),
        cgroup_identity,
        child_process_identity: input.child.identity.clone(),
        principal_mapping_identity: input.principal_mapping.identity.clone(),
        process_posture_identity: input.process_posture.identity.clone(),
        implementation_subject_identity: input.implementation_subject_identity.into(),
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
        runner_administrator_identity: input.runner_administrator_identity,
        service_uid: input.service_uid,
        service_gid: input.service_gid,
        invocation_nonce_identity: input.invocation_nonce_identity,
        boot_identity: input.boot_identity,
        implementation_subject_identity: input.implementation_subject_identity,
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

#[cfg(target_os = "linux")]
impl ProtectedAuthorityStoresV1 {
    pub fn open() -> Result<Self, ProtectedLauncherCapabilityError> {
        Self::open_beneath(Path::new("/"), Path::new("etc/ota/secret-delivery"), 0, 0)
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
pub(crate) fn open_protected_directory_chain(
    root: RawFd,
    path: &Path,
    expected_uid: u32,
    expected_gid: u32,
    final_private_mode: bool,
) -> Result<OwnedFd, ProtectedLauncherCapabilityError> {
    let components = path.components().collect::<Vec<_>>();
    if components.is_empty()
        || components
            .iter()
            .any(|component| !matches!(component, Component::Normal(_)))
    {
        return Err(ProtectedLauncherCapabilityError::Unprotected);
    }
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
    const RESOLVE_NO_XDEV: u64 = 0x01;
    const RESOLVE_NO_MAGICLINKS: u64 = 0x02;
    const RESOLVE_NO_SYMLINKS: u64 = 0x04;
    const RESOLVE_BENEATH: u64 = 0x08;
    let name = CString::new(name).map_err(|_| ProtectedLauncherCapabilityError::Unprotected)?;
    let how = OpenHow {
        flags: flags as u64,
        mode,
        resolve: RESOLVE_NO_XDEV | RESOLVE_NO_MAGICLINKS | RESOLVE_NO_SYMLINKS | RESOLVE_BENEATH,
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

    use tempfile::tempdir;

    use super::*;

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
    };

    struct CapabilityFixture {
        request: LauncherInvocationRequestV1,
        child: LauncherChildProcessV1,
        scope: LauncherSystemdScopeV1,
        principal_mapping: LauncherPrincipalMappingV1,
        process_posture: OtaProcessPostureV1,
        launcher_instance: SystemdProtectedLauncherInstanceEvidenceV2,
        launcher_configuration_identity: String,
        launcher_service_binding_identity: String,
        launcher_profile_identity: String,
        runner_administrator_identity: String,
        invocation_nonce_identity: String,
        boot_identity: String,
        implementation_subject_identity: String,
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
                launcher_executable_identity: self.child.ota_binary_identity.as_str(),
                launcher_configuration_identity: self.launcher_configuration_identity.as_str(),
                launcher_service_binding_identity: self.launcher_service_binding_identity.as_str(),
                launcher_profile_identity: self.launcher_profile_identity.as_str(),
                runner_administrator_identity: self.runner_administrator_identity.as_str(),
                service_uid: 0,
                service_gid: 0,
                invocation_nonce_identity: self.invocation_nonce_identity.as_str(),
                boot_identity: self.boot_identity.as_str(),
                implementation_subject_identity: self.implementation_subject_identity.as_str(),
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
        let launcher_profile = systemd_launcher_profile_v3();
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
        CapabilityFixture {
            request,
            child,
            scope,
            principal_mapping,
            process_posture,
            launcher_instance,
            launcher_configuration_identity,
            launcher_service_binding_identity: identity('4'),
            launcher_profile_identity,
            runner_administrator_identity: identity('6'),
            invocation_nonce_identity: identity('a'),
            boot_identity: identity('b'),
            implementation_subject_identity: identity('c'),
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
        let fixture = fixture();
        let mut retained = observation(&fixture.scope);
        let capability = derive_protected_launcher_capability_v1(&fixture.context(), &mut retained)
            .expect("live capability");

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
