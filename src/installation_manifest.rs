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
use std::path::{Path, PathBuf};

use ota_authority_protocol::{
    message_identity, systemd_job_principal_profile_identity, systemd_job_principal_profile_v2,
    systemd_launcher_profile_identity, systemd_launcher_profile_v3,
};
use serde::{Deserialize, Serialize};
use thiserror::Error;

use crate::config::{
    ConfigError, SystemdLauncherServiceConfigV1, open_protected_file, sha256_file_identity,
};

pub(crate) const SYSTEMD_INSTALLATION_MANIFEST_PATH: &str =
    "/etc/ota/authority-launcher-installation.json";
const INSTALLATION_MANIFEST_IDENTITY_DOMAIN_V1: &str =
    "ota.authority-launcher.installation-manifest.v1\0";
const BROKER_PROXY_INSTALLATION_IDENTITY_DOMAIN_V1: &str =
    "ota.authority-launcher.broker-proxy-installation.v1\0";

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
    BrokerProxyServiceUnit,
    BrokerProxySocketUnit,
    AttestorExecutable,
    AttestorConfiguration,
    AttestorVerifierSet,
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
    JobRunnerServiceUnit,
    JobRunnerServiceDropIn,
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
        ProtectedInstallationRoleV1::BrokerProxyServiceUnit,
        ProtectedInstallationRoleV1::BrokerProxySocketUnit,
        ProtectedInstallationRoleV1::AttestorExecutable,
        ProtectedInstallationRoleV1::AttestorConfiguration,
        ProtectedInstallationRoleV1::AttestorVerifierSet,
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

    use tempfile::tempdir;

    use super::*;
    use crate::config::{
        RunAs, SessionPeer, SystemdPrincipalMappingV1, systemd_launcher_service_config_identity,
    };

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
        for (_, path) in &roles {
            if path != &config_path {
                fs::write(path, path.as_os_str().as_encoded_bytes()).expect("protected file");
                fs::set_permissions(path, fs::Permissions::from_mode(0o600))
                    .expect("protected file permissions");
            }
        }
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

        let attestor_path = manifest
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
