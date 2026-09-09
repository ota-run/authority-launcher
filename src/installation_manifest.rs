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

//! Protected installation identity for the systemd launcher and separated attestation producer.
//!
//! The manifest is administrator-owned state at one fixed path. It contains public content
//! identities only, never producer credentials or private key material.

use std::collections::{BTreeMap, BTreeSet};
use std::fs::File;
use std::io::Seek;
use std::os::unix::fs::MetadataExt;
use std::path::{Path, PathBuf};

use ota_authority_protocol::{
    ProtectedLauncherAuthorityContextV1, ProtectedLauncherCapabilityProjectionVerifierV1,
    message_identity, protected_launcher_authority_context_v1_identity,
    protected_launcher_implementation_subject_v1_identity,
    runner_administrator_authority_v1_identity, systemd_job_principal_profile_identity,
    systemd_job_principal_profile_v2, systemd_launcher_profile_identity,
    systemd_launcher_profile_v3, validate_protected_launcher_capability_projection_verifier_v1,
};
use serde::{Deserialize, Serialize};
use thiserror::Error;

use crate::config::{
    ConfigError, SystemdLauncherServiceConfigV1, open_protected_executable, open_protected_file,
    sha256_file_identity,
};

pub(crate) const SYSTEMD_INSTALLATION_MANIFEST_PATH: &str =
    "/etc/ota/authority-launcher-installation.json";
pub(crate) const CAPABILITY_PROJECTION_VERIFIER_PATH: &str =
    "/usr/share/ota/authority-launcher/capability-projection-verifier-v1.json";
pub(crate) const PROTECTED_LAUNCHER_AUTHORITY_CONTEXT_PATH: &str =
    "/etc/ota/protected-launcher-authority-context-v1.json";
pub(crate) const CAPABILITY_OBSERVATION_REPLAY_DIRECTORY: &str =
    "/var/lib/ota/authority-launcher/capability-observation-replay";
const INSTALLATION_MANIFEST_IDENTITY_DOMAIN_V1: &str =
    "ota.authority-launcher.installation-manifest.v1\0";
const HISTORY_INSTALLATION_IDENTITY_DOMAIN_V1: &str =
    "ota.authority-launcher.history-installation.v1\0";
const BROKER_PROXY_INSTALLATION_IDENTITY_DOMAIN_V1: &str =
    "ota.authority-launcher.broker-proxy-installation.v1\0";
pub(crate) const PROTECTED_LAUNCHER_BUILD_IDENTITY_DOMAIN_V1: &[u8] =
    b"ota.authority-launcher.installed-build.v1\0";

#[derive(Debug, Error, PartialEq, Eq)]
pub(crate) enum InstallationManifestError {
    #[error("the protected installation manifest is unavailable")]
    Unavailable,
    #[error("the protected installation manifest is malformed")]
    Malformed,
    #[error("the protected installation manifest does not match the installed boundary")]
    Mismatch,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq, PartialOrd, Ord)]
#[serde(rename_all = "snake_case")]
pub(crate) enum ProtectedInstallationRoleV1 {
    LauncherExecutable,
    OtaExecutable,
    LauncherConfiguration,
    LauncherServiceUnit,
    LauncherServiceDropIn,
    LauncherSocketUnit,
    LauncherSocketDropIn,
    BrokerProxyExecutable,
    BrokerProxyServiceUnit,
    BrokerProxySocketUnit,
    AttestorExecutable,
    AttestorConfiguration,
    AttestorVerifierSet,
    CapabilityProjectionVerifier,
    ProtectedLauncherAuthorityContext,
    AttestorServiceUnit,
    AttestorServiceDropIn,
    AttestorSocketUnit,
    AttestorSocketDropIn,
    SystemctlExecutable,
    SudoExecutable,
    PkcheckExecutable,
    PolkitRule,
    NonLoginShellExecutable,
    JobRunnerExecutable,
    ProductionClientExecutable,
    JobRunnerServiceUnit,
    JobRunnerServiceDropIn,
    HistoryClientExecutable,
    HistoryBinding,
    HistoryServiceUnit,
    HistorySocketUnit,
}

pub(crate) fn protected_launcher_installed_build_identity(
    owner: &str,
    source_repository: &str,
    source_revision: &str,
    artifact_identity: &str,
) -> Result<String, InstallationManifestError> {
    message_identity(
        PROTECTED_LAUNCHER_BUILD_IDENTITY_DOMAIN_V1,
        &(owner, source_repository, source_revision, artifact_identity),
    )
    .map_err(|_| InstallationManifestError::Malformed)
}

#[allow(dead_code)] // Retained by the inactive protected observation service foundation.
struct RetainedProtectedInstallationFileV1 {
    file: File,
    path: PathBuf,
    trusted_root: PathBuf,
    expected_owner_uid: u32,
    executable: bool,
    identity: String,
    device: u64,
    inode: u64,
    mode: u32,
    size: u64,
}

#[allow(dead_code)]
impl RetainedProtectedInstallationFileV1 {
    fn open(
        path: &Path,
        expected_owner_uid: u32,
        trusted_root: &Path,
        executable: bool,
    ) -> Result<Self, InstallationManifestError> {
        let file = if executable {
            open_protected_executable(path, expected_owner_uid, trusted_root)
        } else {
            open_protected_file(path, expected_owner_uid, trusted_root)
        }
        .map_err(map_config_error)?;
        let retained = Self {
            file,
            path: path.to_path_buf(),
            trusted_root: trusted_root.to_path_buf(),
            expected_owner_uid,
            executable,
            identity: String::new(),
            device: 0,
            inode: 0,
            mode: 0,
            size: 0,
        };
        let (identity, device, inode, mode, size) = retained.observe_descriptor()?;
        Ok(Self {
            identity,
            device,
            inode,
            mode,
            size,
            ..retained
        })
    }

    fn observe_descriptor(
        &self,
    ) -> Result<(String, u64, u64, u32, u64), InstallationManifestError> {
        let mut file = self
            .file
            .try_clone()
            .map_err(|_| InstallationManifestError::Unavailable)?;
        file.rewind()
            .map_err(|_| InstallationManifestError::Unavailable)?;
        let identity = sha256_file_identity(&mut file).map_err(map_config_error)?;
        let metadata = self
            .file
            .metadata()
            .map_err(|_| InstallationManifestError::Unavailable)?;
        Ok((
            identity,
            metadata.dev(),
            metadata.ino(),
            metadata.mode() & 0o7777,
            metadata.size(),
        ))
    }

    fn reconcile(&self) -> Result<(), InstallationManifestError> {
        let expected = (
            self.identity.clone(),
            self.device,
            self.inode,
            self.mode,
            self.size,
        );
        if self.observe_descriptor()? != expected {
            return Err(InstallationManifestError::Mismatch);
        }
        let reopened = Self::open(
            &self.path,
            self.expected_owner_uid,
            &self.trusted_root,
            self.executable,
        )?;
        if reopened.observe_descriptor()? != expected {
            return Err(InstallationManifestError::Mismatch);
        }
        Ok(())
    }

    fn read_json<T: for<'de> Deserialize<'de>>(&self) -> Result<T, InstallationManifestError> {
        let mut file = self
            .file
            .try_clone()
            .map_err(|_| InstallationManifestError::Unavailable)?;
        file.rewind()
            .map_err(|_| InstallationManifestError::Unavailable)?;
        serde_json::from_reader(file).map_err(|_| InstallationManifestError::Malformed)
    }
}

#[allow(dead_code)] // Retained by the inactive protected observation service foundation.
pub(crate) struct RetainedProtectedLauncherAuthorityInstallationV1 {
    context: ProtectedLauncherAuthorityContextV1,
    manifest_identity: String,
    manifest: RetainedProtectedInstallationFileV1,
    context_file: RetainedProtectedInstallationFileV1,
    launcher: RetainedProtectedInstallationFileV1,
    ota: RetainedProtectedInstallationFileV1,
}

#[allow(dead_code)]
impl RetainedProtectedLauncherAuthorityInstallationV1 {
    pub(crate) fn reconcile(
        &self,
    ) -> Result<&ProtectedLauncherAuthorityContextV1, InstallationManifestError> {
        self.manifest.reconcile()?;
        self.context_file.reconcile()?;
        self.launcher.reconcile()?;
        self.ota.reconcile()?;
        let manifest: ProtectedInstallationManifestV1 = self.manifest.read_json()?;
        let context: ProtectedLauncherAuthorityContextV1 = self.context_file.read_json()?;
        if manifest.identity != self.manifest_identity || context != self.context {
            return Err(InstallationManifestError::Mismatch);
        }
        if self.context_file.identity
            != manifest
                .singular_identity(ProtectedInstallationRoleV1::ProtectedLauncherAuthorityContext)?
            || self.launcher.identity
                != manifest.singular_identity(ProtectedInstallationRoleV1::LauncherExecutable)?
            || self.ota.identity
                != manifest.singular_identity(ProtectedInstallationRoleV1::OtaExecutable)?
        {
            return Err(InstallationManifestError::Mismatch);
        }
        validate_authority_context_against_installation(
            &context,
            &manifest,
            &self.context_file.path,
        )?;
        Ok(&self.context)
    }
}

#[allow(dead_code)] // Used by the future protected observation service route.
pub(crate) fn load_protected_launcher_authority_context(
    config: &SystemdLauncherServiceConfigV1,
    launcher_executable: &Path,
) -> Result<RetainedProtectedLauncherAuthorityInstallationV1, InstallationManifestError> {
    load_protected_launcher_authority_context_at(
        Path::new(SYSTEMD_INSTALLATION_MANIFEST_PATH),
        Path::new(PROTECTED_LAUNCHER_AUTHORITY_CONTEXT_PATH),
        Path::new(crate::config::SYSTEMD_AUTHORITY_LAUNCHER_CONFIG_PATH),
        launcher_executable,
        config,
        0,
        Path::new("/"),
    )
}

#[allow(clippy::too_many_arguments)]
fn load_protected_launcher_authority_context_at(
    manifest_path: &Path,
    context_path: &Path,
    config_path: &Path,
    launcher_executable: &Path,
    config: &SystemdLauncherServiceConfigV1,
    expected_owner_uid: u32,
    trusted_root: &Path,
) -> Result<RetainedProtectedLauncherAuthorityInstallationV1, InstallationManifestError> {
    let manifest = load_protected_installation_manifest_at(
        manifest_path,
        config_path,
        launcher_executable,
        config,
        expected_owner_uid,
        trusted_root,
    )?;
    let retained_manifest = RetainedProtectedInstallationFileV1::open(
        manifest_path,
        expected_owner_uid,
        trusted_root,
        false,
    )?;
    let context_file = RetainedProtectedInstallationFileV1::open(
        context_path,
        expected_owner_uid,
        trusted_root,
        false,
    )?;
    let launcher = RetainedProtectedInstallationFileV1::open(
        launcher_executable,
        expected_owner_uid,
        trusted_root,
        true,
    )?;
    let ota = RetainedProtectedInstallationFileV1::open(
        &config.ota_binary,
        expected_owner_uid,
        trusted_root,
        true,
    )?;
    let context: ProtectedLauncherAuthorityContextV1 = context_file.read_json()?;
    if context_file.identity
        != manifest
            .singular_identity(ProtectedInstallationRoleV1::ProtectedLauncherAuthorityContext)?
        || launcher.identity
            != manifest.singular_identity(ProtectedInstallationRoleV1::LauncherExecutable)?
        || ota.identity != manifest.singular_identity(ProtectedInstallationRoleV1::OtaExecutable)?
    {
        return Err(InstallationManifestError::Mismatch);
    }
    validate_authority_context_against_installation(&context, &manifest, context_path)?;
    let retained = RetainedProtectedLauncherAuthorityInstallationV1 {
        context,
        manifest_identity: manifest.identity.clone(),
        manifest: retained_manifest,
        context_file,
        launcher,
        ota,
    };
    Ok(retained)
}

fn validate_authority_context_against_installation(
    context: &ProtectedLauncherAuthorityContextV1,
    manifest: &ProtectedInstallationManifestV1,
    context_path: &Path,
) -> Result<(), InstallationManifestError> {
    require_exact_singular_path(
        manifest,
        ProtectedInstallationRoleV1::ProtectedLauncherAuthorityContext,
        context_path,
    )?;
    let subject = &context.implementation_subject;
    if runner_administrator_authority_v1_identity(&context.runner_administrator)
        .map_err(|_| InstallationManifestError::Malformed)?
        != context.runner_administrator.identity
        || protected_launcher_implementation_subject_v1_identity(subject)
            .map_err(|_| InstallationManifestError::Malformed)?
            != subject.identity
        || protected_launcher_authority_context_v1_identity(context)
            .map_err(|_| InstallationManifestError::Malformed)?
            != context.identity
        || subject.launcher_artifact_identity
            != manifest.singular_identity(ProtectedInstallationRoleV1::LauncherExecutable)?
        || subject.ota_artifact_identity
            != manifest.singular_identity(ProtectedInstallationRoleV1::OtaExecutable)?
        || subject.launcher_profile_identity != manifest.launcher_profile_identity
        || subject.launcher_build_identity
            != protected_launcher_installed_build_identity(
                "launcher",
                &subject.launcher_source_repository,
                &subject.launcher_source_revision,
                &subject.launcher_artifact_identity,
            )?
        || subject.core_build_identity
            != protected_launcher_installed_build_identity(
                "core",
                &subject.core_source_repository,
                &subject.core_source_revision,
                &subject.ota_artifact_identity,
            )?
        || option_env!("OTA_LAUNCHER_BUILD_COMMIT")
            != Some(subject.launcher_source_revision.as_str())
        || option_env!("OTA_PROTOCOL_BUILD_REVISION")
            != Some(subject.protocol_source_revision.as_str())
    {
        return Err(InstallationManifestError::Mismatch);
    }
    Ok(())
}

#[allow(dead_code)] // Used by the library-owned protected observation service path.
pub(crate) fn load_capability_projection_verifier()
-> Result<ProtectedLauncherCapabilityProjectionVerifierV1, InstallationManifestError> {
    load_capability_projection_verifier_at(
        Path::new(SYSTEMD_INSTALLATION_MANIFEST_PATH),
        Path::new(CAPABILITY_PROJECTION_VERIFIER_PATH),
        0,
        Path::new("/"),
    )
}

#[allow(dead_code)]
fn load_capability_projection_verifier_at(
    manifest_path: &Path,
    verifier_path: &Path,
    expected_owner_uid: u32,
    trusted_root: &Path,
) -> Result<ProtectedLauncherCapabilityProjectionVerifierV1, InstallationManifestError> {
    let manifest_file = open_protected_file(manifest_path, expected_owner_uid, trusted_root)
        .map_err(map_config_error)?;
    let manifest: ProtectedInstallationManifestV1 =
        serde_json::from_reader(manifest_file).map_err(|_| InstallationManifestError::Malformed)?;
    if manifest.schema_version != 1
        || manifest.identity != protected_installation_manifest_identity(&manifest)?
    {
        return Err(InstallationManifestError::Mismatch);
    }
    require_exact_singular_path(
        &manifest,
        ProtectedInstallationRoleV1::CapabilityProjectionVerifier,
        verifier_path,
    )?;

    let mut verifier_file = open_protected_file(verifier_path, expected_owner_uid, trusted_root)
        .map_err(map_config_error)?;
    let verifier_file_identity =
        sha256_file_identity(&mut verifier_file).map_err(map_config_error)?;
    if manifest.singular_identity(ProtectedInstallationRoleV1::CapabilityProjectionVerifier)?
        != verifier_file_identity
    {
        return Err(InstallationManifestError::Mismatch);
    }
    verifier_file
        .rewind()
        .map_err(|_| InstallationManifestError::Unavailable)?;
    let verifier: ProtectedLauncherCapabilityProjectionVerifierV1 =
        serde_json::from_reader(verifier_file).map_err(|_| InstallationManifestError::Malformed)?;
    validate_protected_launcher_capability_projection_verifier_v1(&verifier)
        .map_err(|_| InstallationManifestError::Malformed)?;
    Ok(verifier)
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub(crate) struct ProtectedInstallationFileV1 {
    pub role: ProtectedInstallationRoleV1,
    pub path: PathBuf,
    pub identity: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub(crate) struct ProtectedInstallationManifestV1 {
    pub schema_version: u32,
    pub identity: String,
    pub launcher_configuration_identity: String,
    pub launcher_profile_identity: String,
    pub job_principal_profile_identity: String,
    pub files: Vec<ProtectedInstallationFileV1>,
}

pub(crate) fn resolve_optional_protected_executable_alias(
    alias: &Path,
    expected_owner_uid: u32,
    trusted_root: &Path,
) -> Result<Option<PathBuf>, InstallationManifestError> {
    match alias.symlink_metadata() {
        Ok(_) => {}
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(_) => return Err(InstallationManifestError::Unavailable),
    }
    let target = alias
        .canonicalize()
        .map_err(|_| InstallationManifestError::Unavailable)?;
    let file =
        open_protected_file(&target, expected_owner_uid, trusted_root).map_err(map_config_error)?;
    let metadata = file
        .metadata()
        .map_err(|_| InstallationManifestError::Unavailable)?;
    if metadata.mode() & 0o111 == 0 || metadata.nlink() != 1 {
        return Err(InstallationManifestError::Mismatch);
    }
    Ok(Some(target))
}

impl ProtectedInstallationManifestV1 {
    pub(crate) fn singular_path(
        &self,
        role: ProtectedInstallationRoleV1,
    ) -> Result<&Path, InstallationManifestError> {
        let mut entries = self.files.iter().filter(|entry| entry.role == role);
        let path = entries
            .next()
            .map(|entry| entry.path.as_path())
            .ok_or(InstallationManifestError::Malformed)?;
        if entries.next().is_some() {
            return Err(InstallationManifestError::Malformed);
        }
        Ok(path)
    }

    pub(crate) fn paths(&self, role: ProtectedInstallationRoleV1) -> Vec<&Path> {
        self.files
            .iter()
            .filter(|entry| entry.role == role)
            .map(|entry| entry.path.as_path())
            .collect()
    }

    pub(crate) fn optional_singular_path(
        &self,
        role: ProtectedInstallationRoleV1,
    ) -> Result<Option<&Path>, InstallationManifestError> {
        let mut entries = self.files.iter().filter(|entry| entry.role == role);
        let path = entries.next().map(|entry| entry.path.as_path());
        if entries.next().is_some() {
            return Err(InstallationManifestError::Malformed);
        }
        Ok(path)
    }

    pub(crate) fn singular_identity(
        &self,
        role: ProtectedInstallationRoleV1,
    ) -> Result<&str, InstallationManifestError> {
        let mut entries = self.files.iter().filter(|entry| entry.role == role);
        let identity = entries
            .next()
            .map(|entry| entry.identity.as_str())
            .ok_or(InstallationManifestError::Malformed)?;
        if entries.next().is_some() {
            return Err(InstallationManifestError::Malformed);
        }
        Ok(identity)
    }
}

pub(crate) fn protected_installation_manifest_identity(
    manifest: &ProtectedInstallationManifestV1,
) -> Result<String, InstallationManifestError> {
    let mut canonical = manifest.clone();
    canonical.identity.clear();
    message_identity(
        INSTALLATION_MANIFEST_IDENTITY_DOMAIN_V1.as_bytes(),
        &canonical,
    )
    .map_err(|_| InstallationManifestError::Malformed)
}

pub(crate) fn protected_history_installation_identity(
    manifest: &ProtectedInstallationManifestV1,
) -> Result<String, InstallationManifestError> {
    let mut canonical = manifest.clone();
    canonical.identity.clear();
    canonical
        .files
        .retain(|entry| entry.role != ProtectedInstallationRoleV1::HistoryBinding);
    message_identity(
        HISTORY_INSTALLATION_IDENTITY_DOMAIN_V1.as_bytes(),
        &canonical,
    )
    .map_err(|_| InstallationManifestError::Malformed)
}

pub(crate) fn broker_proxy_installation_identity(
    service_unit_identity: &str,
    socket_unit_identity: &str,
) -> Result<String, InstallationManifestError> {
    message_identity(
        BROKER_PROXY_INSTALLATION_IDENTITY_DOMAIN_V1.as_bytes(),
        &(service_unit_identity, socket_unit_identity),
    )
    .map_err(|_| InstallationManifestError::Malformed)
}

pub(crate) fn load_protected_installation_manifest(
    config: &SystemdLauncherServiceConfigV1,
    launcher_executable: &Path,
) -> Result<ProtectedInstallationManifestV1, InstallationManifestError> {
    load_protected_installation_manifest_at(
        Path::new(SYSTEMD_INSTALLATION_MANIFEST_PATH),
        Path::new(crate::config::SYSTEMD_AUTHORITY_LAUNCHER_CONFIG_PATH),
        launcher_executable,
        config,
        0,
        Path::new("/"),
    )
}

#[allow(clippy::too_many_arguments)]
pub(crate) fn verify_protected_history_installation(
    expected_manifest_identity: &str,
    launcher_executable: &Path,
    history_binding_path: &Path,
    history_client_path: &Path,
    history_client_identity: &str,
    history_service_unit_identity: &str,
    history_socket_unit_identity: &str,
) -> Result<(), InstallationManifestError> {
    let manifest_file = open_protected_file(
        Path::new(SYSTEMD_INSTALLATION_MANIFEST_PATH),
        0,
        Path::new("/"),
    )
    .map_err(map_config_error)?;
    let manifest: ProtectedInstallationManifestV1 =
        serde_json::from_reader(manifest_file).map_err(|_| InstallationManifestError::Malformed)?;
    if protected_installation_manifest_identity(&manifest)? != manifest.identity
        || protected_history_installation_identity(&manifest)? != expected_manifest_identity
    {
        return Err(InstallationManifestError::Mismatch);
    }
    let mut observed = BTreeMap::new();
    for entry in &manifest.files {
        let mut file =
            open_protected_file(&entry.path, 0, Path::new("/")).map_err(map_config_error)?;
        if sha256_file_identity(&mut file).map_err(map_config_error)? != entry.identity
            || observed
                .insert((entry.role, entry.path.clone()), ())
                .is_some()
        {
            return Err(InstallationManifestError::Mismatch);
        }
    }
    require_exact_singular_path(
        &manifest,
        ProtectedInstallationRoleV1::LauncherExecutable,
        launcher_executable,
    )?;
    require_exact_singular_path(
        &manifest,
        ProtectedInstallationRoleV1::HistoryBinding,
        history_binding_path,
    )?;
    require_exact_singular_path(
        &manifest,
        ProtectedInstallationRoleV1::HistoryClientExecutable,
        history_client_path,
    )?;
    if manifest.singular_identity(ProtectedInstallationRoleV1::HistoryClientExecutable)?
        != history_client_identity
        || manifest.singular_identity(ProtectedInstallationRoleV1::HistoryServiceUnit)?
            != history_service_unit_identity
        || manifest.singular_identity(ProtectedInstallationRoleV1::HistorySocketUnit)?
            != history_socket_unit_identity
    {
        return Err(InstallationManifestError::Mismatch);
    }
    Ok(())
}

fn load_protected_installation_manifest_at(
    manifest_path: &Path,
    config_path: &Path,
    launcher_executable: &Path,
    config: &SystemdLauncherServiceConfigV1,
    expected_owner_uid: u32,
    trusted_root: &Path,
) -> Result<ProtectedInstallationManifestV1, InstallationManifestError> {
    let manifest_file = open_protected_file(manifest_path, expected_owner_uid, trusted_root)
        .map_err(map_config_error)?;
    let manifest: ProtectedInstallationManifestV1 =
        serde_json::from_reader(manifest_file).map_err(|_| InstallationManifestError::Malformed)?;
    validate_manifest_shape(&manifest, config)?;

    let mut observed = BTreeMap::new();
    for entry in &manifest.files {
        let mut file = open_protected_file(&entry.path, expected_owner_uid, trusted_root)
            .map_err(map_config_error)?;
        let identity = sha256_file_identity(&mut file).map_err(map_config_error)?;
        if identity != entry.identity
            || observed
                .insert((entry.role, entry.path.clone()), ())
                .is_some()
        {
            return Err(InstallationManifestError::Mismatch);
        }
    }
    require_exact_singular_path(
        &manifest,
        ProtectedInstallationRoleV1::LauncherConfiguration,
        config_path,
    )?;
    require_exact_singular_path(
        &manifest,
        ProtectedInstallationRoleV1::LauncherExecutable,
        launcher_executable,
    )?;
    require_exact_singular_path(
        &manifest,
        ProtectedInstallationRoleV1::OtaExecutable,
        &config.ota_binary,
    )?;
    if manifest.singular_identity(ProtectedInstallationRoleV1::LauncherServiceUnit)?
        != config.service_unit_identity
        || manifest.singular_identity(ProtectedInstallationRoleV1::LauncherSocketUnit)?
            != config.socket_unit_identity
        || manifest.singular_identity(ProtectedInstallationRoleV1::OtaExecutable)?
            != config.ota_binary_identity
        || manifest.singular_identity(ProtectedInstallationRoleV1::AttestorVerifierSet)?
            != config.attestor_key_set_identity
        || manifest.singular_identity(ProtectedInstallationRoleV1::BrokerProxyExecutable)?
            != config.broker_proxy_executable_identity
        || broker_proxy_installation_identity(
            manifest.singular_identity(ProtectedInstallationRoleV1::BrokerProxyServiceUnit)?,
            manifest.singular_identity(ProtectedInstallationRoleV1::BrokerProxySocketUnit)?,
        )? != config.broker_proxy_identity
    {
        return Err(InstallationManifestError::Mismatch);
    }
    for mapping in &config.mappings {
        let Some(profile) = mapping.closed_profile.as_ref() else {
            continue;
        };
        require_role_path(
            &manifest,
            ProtectedInstallationRoleV1::JobRunnerServiceUnit,
            profile.runner_service_fragment_path.as_path(),
        )?;
        for path in &profile.runner_service_drop_in_paths {
            require_role_path(
                &manifest,
                ProtectedInstallationRoleV1::JobRunnerServiceDropIn,
                path.as_path(),
            )?;
        }
        require_exact_singular_path(
            &manifest,
            ProtectedInstallationRoleV1::NonLoginShellExecutable,
            profile.non_login_shell.as_path(),
        )?;
        manifest.singular_path(ProtectedInstallationRoleV1::JobRunnerExecutable)?;
    }

    Ok(manifest)
}

fn validate_manifest_shape(
    manifest: &ProtectedInstallationManifestV1,
    config: &SystemdLauncherServiceConfigV1,
) -> Result<(), InstallationManifestError> {
    if manifest.schema_version != 1
        || manifest.identity != protected_installation_manifest_identity(manifest)?
        || manifest.launcher_configuration_identity != config.identity
        || manifest.launcher_profile_identity
            != systemd_launcher_profile_identity(&systemd_launcher_profile_v3())
                .map_err(|_| InstallationManifestError::Malformed)?
        || manifest.job_principal_profile_identity
            != systemd_job_principal_profile_identity(&systemd_job_principal_profile_v2())
                .map_err(|_| InstallationManifestError::Malformed)?
        || manifest.files.is_empty()
    {
        return Err(InstallationManifestError::Mismatch);
    }

    let mut prior: Option<(ProtectedInstallationRoleV1, &Path)> = None;
    let mut roles = BTreeSet::new();
    for entry in &manifest.files {
        if !entry.path.is_absolute()
            || !is_sha256_identity(&entry.identity)
            || prior
                .as_ref()
                .is_some_and(|(role, path)| (*role, *path) >= (entry.role, entry.path.as_path()))
        {
            return Err(InstallationManifestError::Malformed);
        }
        prior = Some((entry.role, entry.path.as_path()));
        roles.insert(entry.role);
    }

    for required in [
        ProtectedInstallationRoleV1::LauncherExecutable,
        ProtectedInstallationRoleV1::OtaExecutable,
        ProtectedInstallationRoleV1::LauncherConfiguration,
        ProtectedInstallationRoleV1::LauncherServiceUnit,
        ProtectedInstallationRoleV1::LauncherSocketUnit,
        ProtectedInstallationRoleV1::BrokerProxyExecutable,
        ProtectedInstallationRoleV1::BrokerProxyServiceUnit,
        ProtectedInstallationRoleV1::BrokerProxySocketUnit,
        ProtectedInstallationRoleV1::AttestorExecutable,
        ProtectedInstallationRoleV1::AttestorConfiguration,
        ProtectedInstallationRoleV1::AttestorVerifierSet,
        ProtectedInstallationRoleV1::ProtectedLauncherAuthorityContext,
        ProtectedInstallationRoleV1::AttestorServiceUnit,
        ProtectedInstallationRoleV1::AttestorSocketUnit,
        ProtectedInstallationRoleV1::SystemctlExecutable,
        ProtectedInstallationRoleV1::PkcheckExecutable,
    ] {
        if !roles.contains(&required)
            || manifest
                .files
                .iter()
                .filter(|entry| entry.role == required)
                .count()
                != 1
        {
            return Err(InstallationManifestError::Malformed);
        }
    }
    if config
        .mappings
        .iter()
        .any(|mapping| mapping.closed_profile.is_some())
    {
        for required in [
            ProtectedInstallationRoleV1::PolkitRule,
            ProtectedInstallationRoleV1::NonLoginShellExecutable,
            ProtectedInstallationRoleV1::JobRunnerExecutable,
            ProtectedInstallationRoleV1::ProductionClientExecutable,
            ProtectedInstallationRoleV1::JobRunnerServiceUnit,
        ] {
            if !roles.contains(&required)
                || manifest
                    .files
                    .iter()
                    .filter(|entry| entry.role == required)
                    .count()
                    != 1
            {
                return Err(InstallationManifestError::Malformed);
            }
        }
    }
    let history_roles = [
        ProtectedInstallationRoleV1::HistoryClientExecutable,
        ProtectedInstallationRoleV1::HistoryBinding,
        ProtectedInstallationRoleV1::HistoryServiceUnit,
        ProtectedInstallationRoleV1::HistorySocketUnit,
    ];
    let history_count = history_roles
        .iter()
        .filter(|role| roles.contains(role))
        .count();
    if history_count != 0
        && (history_count != history_roles.len()
            || history_roles.iter().any(|role| {
                manifest
                    .files
                    .iter()
                    .filter(|entry| entry.role == *role)
                    .count()
                    != 1
            }))
    {
        return Err(InstallationManifestError::Malformed);
    }
    Ok(())
}

fn require_exact_singular_path(
    manifest: &ProtectedInstallationManifestV1,
    role: ProtectedInstallationRoleV1,
    expected: &Path,
) -> Result<(), InstallationManifestError> {
    if manifest.singular_path(role)? != expected {
        return Err(InstallationManifestError::Mismatch);
    }
    Ok(())
}

fn require_role_path(
    manifest: &ProtectedInstallationManifestV1,
    role: ProtectedInstallationRoleV1,
    expected: &Path,
) -> Result<(), InstallationManifestError> {
    if !manifest
        .files
        .iter()
        .any(|entry| entry.role == role && entry.path == expected)
    {
        return Err(InstallationManifestError::Mismatch);
    }
    Ok(())
}

fn is_sha256_identity(value: &str) -> bool {
    value.strip_prefix("sha256:").is_some_and(|digest| {
        digest.len() == 64
            && digest
                .bytes()
                .all(|byte| byte.is_ascii_hexdigit() && !byte.is_ascii_uppercase())
    })
}

fn map_config_error(error: ConfigError) -> InstallationManifestError {
    match error {
        ConfigError::Malformed | ConfigError::Unsupported => InstallationManifestError::Malformed,
        ConfigError::Unavailable | ConfigError::AuthorityUnavailable => {
            InstallationManifestError::Unavailable
        }
        ConfigError::Unprotected => InstallationManifestError::Mismatch,
    }
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeMap;
    use std::fs;
    use std::os::unix::fs::PermissionsExt;

    use base64::Engine;
    use base64::engine::general_purpose::URL_SAFE_NO_PAD;
    use ed25519_dalek::SigningKey;
    use ota_authority_protocol::{
        PROTECTED_LAUNCHER_AUTHORITY_CONTEXT,
        PROTECTED_LAUNCHER_CAPABILITY_OBSERVATION_PROJECTION_KEY_USAGE_V1,
        PROTECTED_LAUNCHER_CAPABILITY_OBSERVATION_SIGNATURE_DOMAIN_V1,
        PROTECTED_LAUNCHER_CAPABILITY_PROJECTION_VERIFIER,
        PROTECTED_LAUNCHER_IMPLEMENTATION_SUBJECT, ProtectedLauncherAuthorityContextV1,
        ProtectedLauncherImplementationSubjectV1, ProtectedLauncherImplementationTargetV1,
        RUNNER_ADMINISTRATOR_AUTHORITY, RunnerAdministratorAuthorityV1,
        protected_launcher_authority_context_v1_identity,
        protected_launcher_capability_projection_key_identity_v1,
        protected_launcher_capability_projection_verifier_v1_identity,
        protected_launcher_implementation_subject_v1_identity,
        runner_administrator_authority_v1_identity,
    };
    use tempfile::tempdir;

    use super::*;
    use crate::config::{
        RunAs, SessionPeer, SystemdPrincipalMappingV1, systemd_launcher_service_config_identity,
    };

    #[test]
    fn capability_projection_verifier_is_bound_to_protected_installation() {
        let root = tempdir().expect("temporary protected root");
        fs::set_permissions(root.path(), fs::Permissions::from_mode(0o700))
            .expect("protected root permissions");
        let owner = unsafe { libc::geteuid() };
        let signing_key = SigningKey::from_bytes(&[7_u8; 32]);
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
        let verifier_path = root.path().join("capability-verifier.json");
        fs::write(
            &verifier_path,
            serde_json::to_vec(&verifier).expect("serialized verifier"),
        )
        .expect("verifier file");
        fs::set_permissions(&verifier_path, fs::Permissions::from_mode(0o600))
            .expect("verifier permissions");
        let mut verifier_file =
            open_protected_file(&verifier_path, owner, root.path()).expect("protected verifier");
        let verifier_file_identity =
            sha256_file_identity(&mut verifier_file).expect("verifier file identity");
        let mut manifest = ProtectedInstallationManifestV1 {
            schema_version: 1,
            identity: String::new(),
            launcher_configuration_identity: format!("sha256:{}", "1".repeat(64)),
            launcher_profile_identity: format!("sha256:{}", "2".repeat(64)),
            job_principal_profile_identity: format!("sha256:{}", "3".repeat(64)),
            files: vec![ProtectedInstallationFileV1 {
                role: ProtectedInstallationRoleV1::CapabilityProjectionVerifier,
                path: verifier_path.clone(),
                identity: verifier_file_identity,
            }],
        };
        manifest.identity =
            protected_installation_manifest_identity(&manifest).expect("manifest identity");
        let manifest_path = root.path().join("installation.json");
        fs::write(
            &manifest_path,
            serde_json::to_vec(&manifest).expect("serialized manifest"),
        )
        .expect("manifest file");
        fs::set_permissions(&manifest_path, fs::Permissions::from_mode(0o600))
            .expect("manifest permissions");

        assert_eq!(
            load_capability_projection_verifier_at(
                &manifest_path,
                &verifier_path,
                owner,
                root.path(),
            )
            .expect("bound verifier"),
            verifier
        );

        fs::write(&verifier_path, b"{}").expect("substitute verifier");
        assert_eq!(
            load_capability_projection_verifier_at(
                &manifest_path,
                &verifier_path,
                owner,
                root.path(),
            ),
            Err(InstallationManifestError::Mismatch)
        );
    }

    #[test]
    fn history_installation_projection_breaks_the_binding_manifest_hash_cycle() {
        let mut manifest = ProtectedInstallationManifestV1 {
            schema_version: 1,
            identity: String::new(),
            launcher_configuration_identity: format!("sha256:{}", "1".repeat(64)),
            launcher_profile_identity: format!("sha256:{}", "2".repeat(64)),
            job_principal_profile_identity: format!("sha256:{}", "3".repeat(64)),
            files: vec![
                ProtectedInstallationFileV1 {
                    role: ProtectedInstallationRoleV1::LauncherExecutable,
                    path: PathBuf::from("/usr/lib/ota-authority/bin/ota-authority-launcher"),
                    identity: format!("sha256:{}", "4".repeat(64)),
                },
                ProtectedInstallationFileV1 {
                    role: ProtectedInstallationRoleV1::HistoryBinding,
                    path: PathBuf::from("/etc/ota/authority-history.json"),
                    identity: format!("sha256:{}", "5".repeat(64)),
                },
            ],
        };
        let projected =
            protected_history_installation_identity(&manifest).expect("history projection");
        manifest.files[1].identity = format!("sha256:{}", "6".repeat(64));
        assert_eq!(
            protected_history_installation_identity(&manifest).expect("changed binding projection"),
            projected
        );
        manifest.files[0].identity = format!("sha256:{}", "7".repeat(64));
        assert_ne!(
            protected_history_installation_identity(&manifest)
                .expect("changed launcher projection"),
            projected
        );
    }

    #[test]
    fn manifest_binds_every_required_protected_file_and_refuses_substitution() {
        let root = tempdir().expect("temporary protected root");
        fs::set_permissions(root.path(), fs::Permissions::from_mode(0o700))
            .expect("protected root permissions");
        let owner = unsafe { libc::geteuid() };
        let config_path = root.path().join("launcher.json");
        let launcher_path = root.path().join("launcher");
        let ota_path = root.path().join("ota");
        let mut config = systemd_config(ota_path.clone());

        let roles = [
            (
                ProtectedInstallationRoleV1::LauncherExecutable,
                launcher_path.clone(),
            ),
            (ProtectedInstallationRoleV1::OtaExecutable, ota_path),
            (
                ProtectedInstallationRoleV1::LauncherConfiguration,
                config_path.clone(),
            ),
            (
                ProtectedInstallationRoleV1::LauncherServiceUnit,
                root.path().join("launcher.service"),
            ),
            (
                ProtectedInstallationRoleV1::LauncherSocketUnit,
                root.path().join("launcher.socket"),
            ),
            (
                ProtectedInstallationRoleV1::BrokerProxyExecutable,
                root.path().join("broker-proxy"),
            ),
            (
                ProtectedInstallationRoleV1::BrokerProxyServiceUnit,
                root.path().join("broker-proxy.service"),
            ),
            (
                ProtectedInstallationRoleV1::BrokerProxySocketUnit,
                root.path().join("broker-proxy.socket"),
            ),
            (
                ProtectedInstallationRoleV1::AttestorExecutable,
                root.path().join("attestor"),
            ),
            (
                ProtectedInstallationRoleV1::AttestorConfiguration,
                root.path().join("attestor.json"),
            ),
            (
                ProtectedInstallationRoleV1::AttestorVerifierSet,
                root.path().join("attestor-verifiers.json"),
            ),
            (
                ProtectedInstallationRoleV1::ProtectedLauncherAuthorityContext,
                root.path()
                    .join("protected-launcher-authority-context-v1.json"),
            ),
            (
                ProtectedInstallationRoleV1::AttestorServiceUnit,
                root.path().join("attestor.service"),
            ),
            (
                ProtectedInstallationRoleV1::AttestorSocketUnit,
                root.path().join("attestor.socket"),
            ),
            (
                ProtectedInstallationRoleV1::SystemctlExecutable,
                root.path().join("systemctl"),
            ),
            (
                ProtectedInstallationRoleV1::SudoExecutable,
                root.path().join("sudo"),
            ),
            (
                ProtectedInstallationRoleV1::PkcheckExecutable,
                root.path().join("pkcheck"),
            ),
        ];
        for (role, path) in &roles {
            if path != &config_path {
                fs::write(path, path.as_os_str().as_encoded_bytes()).expect("protected file");
                let mode = if matches!(
                    role,
                    ProtectedInstallationRoleV1::LauncherExecutable
                        | ProtectedInstallationRoleV1::OtaExecutable
                ) {
                    0o700
                } else {
                    0o600
                };
                fs::set_permissions(path, fs::Permissions::from_mode(mode))
                    .expect("protected file permissions");
            }
        }
        let file_identity = |path: &Path| {
            let mut file = open_protected_file(path, owner, root.path())
                .expect("open protected fixture artifact");
            sha256_file_identity(&mut file).expect("fixture artifact identity")
        };
        let launcher_artifact_identity = file_identity(&launcher_path);
        let ota_artifact_identity = file_identity(
            roles
                .iter()
                .find(|(role, _)| *role == ProtectedInstallationRoleV1::OtaExecutable)
                .expect("Ota fixture role")
                .1
                .as_path(),
        );
        let launcher_source_revision = env!("OTA_LAUNCHER_BUILD_COMMIT").to_owned();
        let protocol_source_revision = env!("OTA_PROTOCOL_BUILD_REVISION").to_owned();
        let core_source_revision = "2".repeat(40);
        let launcher_profile_identity =
            systemd_launcher_profile_identity(&systemd_launcher_profile_v3())
                .expect("launcher profile identity");
        let mut administrator = RunnerAdministratorAuthorityV1 {
            schema_version: 1,
            record_kind: RUNNER_ADMINISTRATOR_AUTHORITY.into(),
            identity: String::new(),
            authority_id: String::from("release"),
            authority_instance_id: URL_SAFE_NO_PAD.encode([9_u8; 32]),
            administration_scope: String::from("protected_self_hosted_runner"),
        };
        administrator.identity = runner_administrator_authority_v1_identity(&administrator)
            .expect("administrator identity");
        let mut subject = ProtectedLauncherImplementationSubjectV1 {
            schema_version: 1,
            record_kind: PROTECTED_LAUNCHER_IMPLEMENTATION_SUBJECT.into(),
            identity: String::new(),
            launcher_source_repository: String::from(
                "https://github.com/ota-run/authority-launcher",
            ),
            launcher_source_revision,
            core_source_repository: String::from("https://github.com/ota-run/ota"),
            core_source_revision,
            protocol_source_repository: String::from(
                "https://github.com/ota-run/authority-protocol",
            ),
            protocol_source_revision,
            launcher_build_identity: protected_launcher_installed_build_identity(
                "launcher",
                "https://github.com/ota-run/authority-launcher",
                env!("OTA_LAUNCHER_BUILD_COMMIT"),
                &launcher_artifact_identity,
            )
            .expect("Launcher build identity"),
            core_build_identity: protected_launcher_installed_build_identity(
                "core",
                "https://github.com/ota-run/ota",
                &"2".repeat(40),
                &ota_artifact_identity,
            )
            .expect("Core build identity"),
            launcher_artifact_identity,
            ota_artifact_identity,
            protocol_version: ota_authority_protocol::SYSTEMD_LAUNCHER_SERVICE_PROTOCOL_V1.into(),
            minimum_core_version: String::from("1.6.28"),
            maximum_exclusive_core_version: String::from("1.7.0"),
            launcher_profile_identity,
            target: ProtectedLauncherImplementationTargetV1 {
                environment: String::from("self_hosted"),
                os: String::from("linux"),
                architecture: String::from("x86_64"),
                execution_mode: String::from("native"),
                launcher_class: String::from("systemd_protected_launcher_v3"),
            },
        };
        subject.identity = protected_launcher_implementation_subject_v1_identity(&subject)
            .expect("subject identity");
        let mut authority_context = ProtectedLauncherAuthorityContextV1 {
            schema_version: 1,
            record_kind: PROTECTED_LAUNCHER_AUTHORITY_CONTEXT.into(),
            identity: String::new(),
            runner_administrator: administrator,
            implementation_subject: subject,
        };
        authority_context.identity =
            protected_launcher_authority_context_v1_identity(&authority_context)
                .expect("authority context identity");
        let authority_context_path = roles
            .iter()
            .find(|(role, _)| {
                *role == ProtectedInstallationRoleV1::ProtectedLauncherAuthorityContext
            })
            .expect("authority context fixture role")
            .1
            .clone();
        fs::write(
            &authority_context_path,
            serde_json::to_vec(&authority_context).expect("serialized authority context"),
        )
        .expect("authority context file");
        fs::set_permissions(&authority_context_path, fs::Permissions::from_mode(0o600))
            .expect("authority context permissions");
        let role_identity = |role| {
            let path = roles
                .iter()
                .find(|(candidate, _)| *candidate == role)
                .expect("fixture role")
                .1
                .as_path();
            let mut file =
                open_protected_file(path, owner, root.path()).expect("open protected fixture role");
            sha256_file_identity(&mut file).expect("fixture role identity")
        };
        config.service_unit_identity =
            role_identity(ProtectedInstallationRoleV1::LauncherServiceUnit);
        config.socket_unit_identity =
            role_identity(ProtectedInstallationRoleV1::LauncherSocketUnit);
        config.ota_binary_identity = role_identity(ProtectedInstallationRoleV1::OtaExecutable);
        config.attestor_key_set_identity =
            role_identity(ProtectedInstallationRoleV1::AttestorVerifierSet);
        config.broker_proxy_executable_identity =
            role_identity(ProtectedInstallationRoleV1::BrokerProxyExecutable);
        config.broker_proxy_identity = broker_proxy_installation_identity(
            role_identity(ProtectedInstallationRoleV1::BrokerProxyServiceUnit).as_str(),
            role_identity(ProtectedInstallationRoleV1::BrokerProxySocketUnit).as_str(),
        )
        .expect("broker proxy identity");
        config.identity =
            systemd_launcher_service_config_identity(&config).expect("config identity");
        fs::write(
            &config_path,
            serde_json::to_vec(&config).expect("serialized config"),
        )
        .expect("launcher config");
        fs::set_permissions(&config_path, fs::Permissions::from_mode(0o600))
            .expect("launcher config permissions");

        let mut manifest = ProtectedInstallationManifestV1 {
            schema_version: 1,
            identity: String::new(),
            launcher_configuration_identity: config.identity.clone(),
            launcher_profile_identity: systemd_launcher_profile_identity(
                &systemd_launcher_profile_v3(),
            )
            .expect("launcher profile identity"),
            job_principal_profile_identity: systemd_job_principal_profile_identity(
                &systemd_job_principal_profile_v2(),
            )
            .expect("job profile identity"),
            files: roles
                .into_iter()
                .map(|(role, path)| {
                    let mut file = open_protected_file(&path, owner, root.path())
                        .expect("open protected fixture");
                    ProtectedInstallationFileV1 {
                        role,
                        path,
                        identity: sha256_file_identity(&mut file).expect("file identity"),
                    }
                })
                .collect(),
        };
        manifest.identity =
            protected_installation_manifest_identity(&manifest).expect("manifest identity");
        let manifest_path = root.path().join("installation.json");
        fs::write(
            &manifest_path,
            serde_json::to_vec(&manifest).expect("serialized manifest"),
        )
        .expect("installation manifest");
        fs::set_permissions(&manifest_path, fs::Permissions::from_mode(0o600))
            .expect("manifest permissions");

        let loaded = load_protected_installation_manifest_at(
            &manifest_path,
            &config_path,
            &launcher_path,
            &config,
            owner,
            root.path(),
        )
        .expect("verified protected installation");
        assert_eq!(loaded.identity, manifest.identity);
        let retained_authority = load_protected_launcher_authority_context_at(
            &manifest_path,
            &authority_context_path,
            &config_path,
            &launcher_path,
            &config,
            owner,
            root.path(),
        )
        .expect("verified authority context");
        assert_eq!(
            retained_authority
                .reconcile()
                .expect("reconciled authority context"),
            &authority_context,
        );

        let original_manifest = manifest.clone();
        let mut substituted_context = authority_context.clone();
        substituted_context
            .implementation_subject
            .ota_artifact_identity = identity('f');
        substituted_context.implementation_subject.identity =
            protected_launcher_implementation_subject_v1_identity(
                &substituted_context.implementation_subject,
            )
            .expect("substituted subject identity");
        substituted_context.identity =
            protected_launcher_authority_context_v1_identity(&substituted_context)
                .expect("substituted context identity");
        fs::write(
            &authority_context_path,
            serde_json::to_vec(&substituted_context).expect("serialized substituted context"),
        )
        .expect("substituted context file");
        manifest
            .files
            .iter_mut()
            .find(|entry| {
                entry.role == ProtectedInstallationRoleV1::ProtectedLauncherAuthorityContext
            })
            .expect("authority context manifest entry")
            .identity = file_identity(&authority_context_path);
        manifest.identity = protected_installation_manifest_identity(&manifest)
            .expect("substituted manifest identity");
        fs::write(
            &manifest_path,
            serde_json::to_vec(&manifest).expect("serialized substituted manifest"),
        )
        .expect("substituted manifest file");
        assert_eq!(
            retained_authority.reconcile(),
            Err(InstallationManifestError::Mismatch),
        );
        fs::write(
            &authority_context_path,
            serde_json::to_vec(&authority_context).expect("serialized restored context"),
        )
        .expect("restored context file");
        fs::write(
            &manifest_path,
            serde_json::to_vec(&original_manifest).expect("serialized restored manifest"),
        )
        .expect("restored manifest file");
        retained_authority
            .reconcile()
            .expect("restored authority installation");

        let original_launcher = fs::read(&launcher_path).expect("launcher fixture bytes");
        let mut substituted_launcher = original_launcher.clone();
        substituted_launcher[0] ^= 1;
        fs::write(&launcher_path, &substituted_launcher).expect("substituted launcher bytes");
        assert_eq!(
            retained_authority.reconcile(),
            Err(InstallationManifestError::Mismatch),
        );
        fs::write(&launcher_path, &original_launcher).expect("restored launcher bytes");
        retained_authority
            .reconcile()
            .expect("restored launcher installation");

        let ota_path = original_manifest
            .singular_path(ProtectedInstallationRoleV1::OtaExecutable)
            .expect("Ota fixture path");
        let original_ota = fs::read(ota_path).expect("Ota fixture bytes");
        let mut substituted_ota = original_ota.clone();
        substituted_ota[0] ^= 1;
        fs::write(ota_path, &substituted_ota).expect("substituted Ota bytes");
        assert_eq!(
            retained_authority.reconcile(),
            Err(InstallationManifestError::Mismatch),
        );
        fs::write(ota_path, &original_ota).expect("restored Ota bytes");
        retained_authority
            .reconcile()
            .expect("restored Ota installation");

        fs::set_permissions(&authority_context_path, fs::Permissions::from_mode(0o640))
            .expect("context metadata substitution");
        assert_eq!(
            retained_authority.reconcile(),
            Err(InstallationManifestError::Mismatch),
        );
        fs::set_permissions(&authority_context_path, fs::Permissions::from_mode(0o600))
            .expect("context metadata restoration");
        retained_authority
            .reconcile()
            .expect("restored context metadata");

        let attestor_path = original_manifest
            .files
            .iter()
            .find(|entry| entry.role == ProtectedInstallationRoleV1::AttestorExecutable)
            .expect("attestor entry")
            .path
            .clone();
        fs::write(attestor_path, b"substituted").expect("substituted attestor");
        assert_eq!(
            load_protected_installation_manifest_at(
                &manifest_path,
                &config_path,
                &launcher_path,
                &config,
                owner,
                root.path(),
            ),
            Err(InstallationManifestError::Mismatch)
        );
    }

    fn systemd_config(ota_binary: PathBuf) -> SystemdLauncherServiceConfigV1 {
        SystemdLauncherServiceConfigV1 {
            schema_version: 1,
            identity: String::new(),
            adapter: ota_authority_protocol::SYSTEMD_PROTECTED_LAUNCHER_ADAPTER_V1.into(),
            socket_path: PathBuf::from("/run/ota/authority-launcher.sock"),
            socket_group_gid: 1001,
            ota_binary,
            environment: BTreeMap::new(),
            allowed_repository_roots: vec![PathBuf::from("/srv/repos")],
            mappings: vec![SystemdPrincipalMappingV1 {
                authority_id: String::from("release"),
                job_peer: SessionPeer {
                    uid: 1001,
                    gid: 1001,
                },
                execution: RunAs {
                    uid: 2001,
                    gid: 2001,
                },
                closed_profile: None,
            }],
            broker_proxy_socket: PathBuf::from("/run/ota/broker-proxy.sock"),
            broker_proxy_peer: SessionPeer { uid: 0, gid: 0 },
            service_unit_identity: identity('1'),
            socket_unit_identity: identity('2'),
            ota_binary_identity: identity('3'),
            broker_proxy_identity: identity('4'),
            broker_proxy_executable_identity: identity('6'),
            attestor_key_set_identity: identity('5'),
            attestation_claims: None,
            maximum_request_bytes: 4096,
            maximum_active_sessions: 1,
            maximum_startup_seconds: 30,
            maximum_terminal_wait_seconds: 300,
        }
    }

    fn identity(value: char) -> String {
        format!("sha256:{}", value.to_string().repeat(64))
    }
}
