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

use std::collections::{BTreeMap, BTreeSet};
use std::fs::{File, OpenOptions};
use std::io::BufReader;
#[cfg(target_os = "linux")]
use std::io::Read;
use std::os::unix::fs::{MetadataExt, OpenOptionsExt};
use std::path::{Path, PathBuf};

#[cfg(any(test, target_os = "linux"))]
use ota_authority_protocol::{
    LauncherPrincipalMappingV1, MAX_FRAME_BYTES,
    SYSTEMD_LAUNCHER_SERVICE_CONFIGURATION_IDENTITY_DOMAIN_V1,
    SYSTEMD_PROTECTED_LAUNCHER_ADAPTER_V1, UnixPrincipalIdentity,
    launcher_principal_mapping_identity, message_identity, systemd_job_principal_profile_identity,
    systemd_job_principal_profile_v2,
};
use serde::{Deserialize, Serialize};
#[cfg(target_os = "linux")]
use sha2::{Digest, Sha256};
use thiserror::Error;

pub(crate) const AUTHORITY_LAUNCHER_CONFIG_PATH: &str = "/etc/ota/authority-launcher.json";
#[cfg(target_os = "linux")]
pub(crate) const SYSTEMD_AUTHORITY_LAUNCHER_CONFIG_PATH: &str =
    "/etc/ota/authority-launcher-systemd.json";
pub(crate) const CROSSING_BROKER_STORE_PATH: &str = "/etc/ota/crossing-brokers.json";

#[derive(Debug, Error)]
pub(crate) enum ConfigError {
    #[error("protected launcher configuration is unavailable")]
    Unavailable,
    #[error("protected launcher configuration is malformed")]
    Malformed,
    #[error("protected launcher configuration failed filesystem verification")]
    Unprotected,
    #[error("protected launcher configuration contains an unsupported value")]
    Unsupported,
    #[error("the requested authority has no unique protected launcher session")]
    AuthorityUnavailable,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct LauncherConfig {
    pub schema_version: u32,
    pub ota_binary: PathBuf,
    pub run_as: RunAs,
    pub environment: BTreeMap<String, String>,
    pub sessions: Vec<LauncherSessionBinding>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub(crate) struct RunAs {
    pub uid: u32,
    pub gid: u32,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct LauncherSessionBinding {
    pub authority_id: String,
    pub broker_session_descriptor: i32,
    pub expected_peer: SessionPeer,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub(crate) struct SessionPeer {
    pub uid: u32,
    pub gid: u32,
}

/// Administrator-owned configuration for the Linux systemd service branch.
///
/// This does not reinterpret the legacy inherited-descriptor configuration. The identity is
/// derived with the `identity` field cleared, then must match the V3 broker binding's
/// `launcher_session_binding_identity` before Core admits a crossing.
#[cfg(any(test, target_os = "linux"))]
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub(crate) struct SystemdLauncherServiceConfigV1 {
    pub schema_version: u32,
    pub identity: String,
    pub adapter: String,
    pub socket_path: PathBuf,
    pub socket_group_gid: u32,
    pub ota_binary: PathBuf,
    pub environment: BTreeMap<String, String>,
    pub allowed_repository_roots: Vec<PathBuf>,
    pub mappings: Vec<SystemdPrincipalMappingV1>,
    pub broker_proxy_socket: PathBuf,
    pub broker_proxy_peer: SessionPeer,
    pub service_unit_identity: String,
    pub socket_unit_identity: String,
    pub ota_binary_identity: String,
    pub broker_proxy_identity: String,
    pub attestor_key_set_identity: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub attestation_claims: Option<SystemdAttestationClaimsConfigV1>,
    pub maximum_request_bytes: usize,
    pub maximum_active_sessions: u32,
    pub maximum_startup_seconds: u64,
    pub maximum_terminal_wait_seconds: u64,
}

#[cfg(any(test, target_os = "linux"))]
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub(crate) struct SystemdPrincipalMappingV1 {
    pub authority_id: String,
    pub job_peer: SessionPeer,
    pub execution: RunAs,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub closed_profile: Option<SystemdJobPrincipalClosedProfileV1>,
}

#[cfg(any(test, target_os = "linux"))]
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub(crate) struct SystemdJobPrincipalClosedProfileV1 {
    pub runner_service_unit: String,
    pub runner_service_fragment_path: PathBuf,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub runner_service_drop_in_paths: Vec<PathBuf>,
    pub non_login_shell: PathBuf,
    pub host_control_sockets: Vec<PathBuf>,
}

#[cfg(any(test, target_os = "linux"))]
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub(crate) struct SystemdAttestationClaimsConfigV1 {
    pub authenticated_origin: String,
    pub authority_mounts: Vec<String>,
    pub requested_maximum_validity_seconds: u64,
}

impl LauncherConfig {
    pub(crate) fn session(
        &self,
        authority_id: &str,
    ) -> Result<&LauncherSessionBinding, ConfigError> {
        let mut matches = self
            .sessions
            .iter()
            .filter(|session| session.authority_id == authority_id);
        let selected = matches.next().ok_or(ConfigError::AuthorityUnavailable)?;
        if matches.next().is_some() {
            return Err(ConfigError::AuthorityUnavailable);
        }
        Ok(selected)
    }
}

#[derive(Debug, Deserialize)]
struct CoreBrokerStore {
    schema_version: u32,
    bindings: Vec<CoreBrokerBinding>,
}

#[derive(Debug, Deserialize)]
struct CoreBrokerBinding {
    authority_id: String,
    credential_delivery: CoreCredentialDelivery,
}

#[derive(Debug, Deserialize)]
struct CoreCredentialDelivery {
    kind: String,
    descriptor: i32,
}

#[derive(Debug, Clone, Copy)]
pub(crate) struct CoreBindingSelection {
    pub ota_session_descriptor: i32,
}

pub(crate) fn load_launcher_config(path: &str) -> Result<LauncherConfig, ConfigError> {
    let path = Path::new(path);
    let file = open_protected_file(path, 0, Path::new("/"))?;
    let config: LauncherConfig =
        serde_json::from_reader(BufReader::new(file)).map_err(|_| ConfigError::Malformed)?;
    validate_launcher_config(&config)?;
    verify_protected_executable(config.ota_binary.as_path(), 0, Path::new("/"))?;
    Ok(config)
}

#[cfg(target_os = "linux")]
pub(crate) fn load_systemd_launcher_service_config(
    path: &str,
) -> Result<LoadedSystemdLauncherServiceConfigV1, ConfigError> {
    let path = Path::new(path);
    let file = open_protected_file(path, 0, Path::new("/"))?;
    let config: SystemdLauncherServiceConfigV1 =
        serde_json::from_reader(BufReader::new(file)).map_err(|_| ConfigError::Malformed)?;
    validate_systemd_launcher_service_config(&config)?;
    let mut ota_binary = open_protected_executable(config.ota_binary.as_path(), 0, Path::new("/"))?;
    if sha256_file_identity(&mut ota_binary)? != config.ota_binary_identity {
        return Err(ConfigError::Unprotected);
    }
    Ok(LoadedSystemdLauncherServiceConfigV1 { config, ota_binary })
}

#[cfg(target_os = "linux")]
pub(crate) struct LoadedSystemdLauncherServiceConfigV1 {
    pub config: SystemdLauncherServiceConfigV1,
    /// The exact protected executable whose identity was verified during configuration loading.
    pub ota_binary: File,
}

#[cfg(any(test, target_os = "linux"))]
pub(crate) fn systemd_launcher_service_config_identity(
    config: &SystemdLauncherServiceConfigV1,
) -> Result<String, ConfigError> {
    let mut canonical = config.clone();
    canonical.identity.clear();
    message_identity(
        SYSTEMD_LAUNCHER_SERVICE_CONFIGURATION_IDENTITY_DOMAIN_V1,
        &canonical,
    )
    .map_err(|_| ConfigError::Malformed)
}

#[cfg(any(test, target_os = "linux"))]
pub(crate) fn systemd_principal_mapping(
    config: &SystemdLauncherServiceConfigV1,
    mapping: &SystemdPrincipalMappingV1,
) -> Result<LauncherPrincipalMappingV1, ConfigError> {
    let principal = |uid: u32, gid: u32| UnixPrincipalIdentity {
        real_uid: uid,
        effective_uid: uid,
        saved_uid: uid,
        filesystem_uid: uid,
        real_gid: gid,
        effective_gid: gid,
        saved_gid: gid,
        filesystem_gid: gid,
    };
    let mut canonical = LauncherPrincipalMappingV1 {
        schema_version: 1,
        identity: String::new(),
        job_peer: principal(mapping.job_peer.uid, mapping.job_peer.gid),
        execution: principal(mapping.execution.uid, mapping.execution.gid),
        job_principal_profile_identity: systemd_job_principal_profile_identity(
            &systemd_job_principal_profile_v2(),
        )
        .map_err(|_| ConfigError::Malformed)?,
        launcher_session_binding_identity: config.identity.clone(),
    };
    canonical.identity =
        launcher_principal_mapping_identity(&canonical).map_err(|_| ConfigError::Malformed)?;
    Ok(canonical)
}

pub(crate) fn load_core_binding(
    path: &str,
    authority_id: &str,
) -> Result<CoreBindingSelection, ConfigError> {
    let file = open_protected_file(Path::new(path), 0, Path::new("/"))?;
    let store: CoreBrokerStore =
        serde_json::from_reader(BufReader::new(file)).map_err(|_| ConfigError::Malformed)?;
    if store.schema_version != 1 {
        return Err(ConfigError::Unsupported);
    }
    let mut matches = store
        .bindings
        .iter()
        .filter(|binding| binding.authority_id == authority_id);
    let selected = matches.next().ok_or(ConfigError::AuthorityUnavailable)?;
    if matches.next().is_some()
        || selected.credential_delivery.kind != "launcher_session_fd"
        || selected.credential_delivery.descriptor < 3
    {
        return Err(ConfigError::AuthorityUnavailable);
    }
    Ok(CoreBindingSelection {
        ota_session_descriptor: selected.credential_delivery.descriptor,
    })
}

fn validate_launcher_config(config: &LauncherConfig) -> Result<(), ConfigError> {
    if config.schema_version != 1
        || !config.ota_binary.is_absolute()
        || config.run_as.uid == 0
        || config.run_as.gid == 0
        || config.environment.keys().any(|name| {
            name.is_empty()
                || name.len() > 128
                || !name
                    .bytes()
                    .all(|byte| byte.is_ascii_alphanumeric() || byte == b'_')
        })
        || config.sessions.is_empty()
    {
        return Err(ConfigError::Unsupported);
    }
    let mut authorities = BTreeSet::new();
    let mut descriptors = BTreeSet::new();
    for session in &config.sessions {
        if session.authority_id.is_empty()
            || session.authority_id.len() > 128
            || !session
                .authority_id
                .bytes()
                .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.'))
            || session.broker_session_descriptor < 3
            || !authorities.insert(session.authority_id.as_str())
            || !descriptors.insert(session.broker_session_descriptor)
        {
            return Err(ConfigError::Unsupported);
        }
    }
    Ok(())
}

#[cfg(any(test, target_os = "linux"))]
fn validate_systemd_launcher_service_config(
    config: &SystemdLauncherServiceConfigV1,
) -> Result<(), ConfigError> {
    if config.schema_version != 1
        || config.adapter != SYSTEMD_PROTECTED_LAUNCHER_ADAPTER_V1
        || config.socket_path != Path::new("/run/ota/authority-launcher.sock")
        || config.socket_group_gid == 0
        || !config.ota_binary.is_absolute()
        || !config.broker_proxy_socket.is_absolute()
        || config.broker_proxy_socket == config.socket_path
        || config.allowed_repository_roots.is_empty()
        || config.mappings.is_empty()
        || config.maximum_request_bytes == 0
        || config.maximum_request_bytes > MAX_FRAME_BYTES
        || config.maximum_active_sessions == 0
        || config.maximum_active_sessions > 16
        || config.maximum_startup_seconds == 0
        || config.maximum_startup_seconds > 600
        || config.maximum_terminal_wait_seconds == 0
        || config.maximum_terminal_wait_seconds > 3600
        || !is_sha256_identity(config.service_unit_identity.as_str())
        || !is_sha256_identity(config.socket_unit_identity.as_str())
        || !is_sha256_identity(config.ota_binary_identity.as_str())
        || !is_sha256_identity(config.broker_proxy_identity.as_str())
        || !is_sha256_identity(config.attestor_key_set_identity.as_str())
        || config.broker_proxy_peer.uid != 0
        || config.broker_proxy_peer.gid != 0
        || config.environment.len() > 64
        || config.environment.iter().any(|(name, value)| {
            !is_environment_name(name.as_str())
                || matches!(
                    name.as_str(),
                    "OTA_LAUNCHER_PRINCIPAL_MAPPING_IDENTITY" | "OTA_SYSTEMD_LAUNCHER_STARTUP_GATE"
                )
                || value.len() > 4096
                || value.contains('\0')
        })
        || config.attestation_claims.as_ref().is_some_and(|claims| {
            !is_bounded_public_value(claims.authenticated_origin.as_str())
                || claims.authority_mounts.is_empty()
                || claims.authority_mounts.len() > 16
                || claims
                    .authority_mounts
                    .iter()
                    .any(|value| !is_bounded_identifier(value.as_str()))
                || claims.requested_maximum_validity_seconds == 0
                || claims.requested_maximum_validity_seconds > 600
        })
    {
        return Err(ConfigError::Unsupported);
    }

    let mut roots = BTreeSet::new();
    for root in &config.allowed_repository_roots {
        if !root.is_absolute()
            || root == Path::new("/")
            || root.components().any(|component| {
                matches!(
                    component,
                    std::path::Component::CurDir | std::path::Component::ParentDir
                )
            })
            || !roots.insert(root.as_path())
        {
            return Err(ConfigError::Unsupported);
        }
    }
    if config
        .allowed_repository_roots
        .iter()
        .enumerate()
        .any(|(index, root)| {
            config
                .allowed_repository_roots
                .iter()
                .skip(index + 1)
                .any(|other| root.starts_with(other) || other.starts_with(root))
        })
    {
        return Err(ConfigError::Unsupported);
    }

    let mut authorities = BTreeSet::new();
    let mut job_peers = BTreeSet::new();
    let mut executions = BTreeSet::new();
    for mapping in &config.mappings {
        if !is_bounded_identifier(mapping.authority_id.as_str())
            || mapping.job_peer.uid == 0
            || mapping.job_peer.gid == 0
            || mapping.job_peer.gid != config.socket_group_gid
            || mapping.execution.uid == 0
            || mapping.execution.gid == 0
            || (mapping.job_peer.uid == mapping.execution.uid
                && mapping.job_peer.gid == mapping.execution.gid)
            || !authorities.insert(mapping.authority_id.as_str())
            || !job_peers.insert((mapping.job_peer.uid, mapping.job_peer.gid))
            || !executions.insert((mapping.execution.uid, mapping.execution.gid))
        {
            return Err(ConfigError::Unsupported);
        }
        if let Some(profile) = mapping.closed_profile.as_ref()
            && (!profile.runner_service_unit.ends_with(".service")
                || !is_bounded_identifier(profile.runner_service_unit.as_str())
                || !profile.runner_service_fragment_path.is_absolute()
                || !profile.non_login_shell.is_absolute()
                || profile.host_control_sockets.is_empty()
                || !unique_absolute_paths(profile.runner_service_drop_in_paths.as_slice())
                || !unique_absolute_paths(profile.host_control_sockets.as_slice()))
        {
            return Err(ConfigError::Unsupported);
        }
    }

    if config.identity != systemd_launcher_service_config_identity(config)? {
        return Err(ConfigError::Unprotected);
    }
    Ok(())
}

#[cfg(any(test, target_os = "linux"))]
fn unique_absolute_paths(paths: &[PathBuf]) -> bool {
    let mut seen = BTreeSet::new();
    paths.iter().all(|path| {
        path.is_absolute()
            && !path.components().any(|component| {
                matches!(
                    component,
                    std::path::Component::CurDir | std::path::Component::ParentDir
                )
            })
            && seen.insert(path.as_path())
    })
}

#[cfg(any(test, target_os = "linux"))]
fn is_bounded_identifier(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 128
        && value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.'))
}

#[cfg(any(test, target_os = "linux"))]
fn is_bounded_public_value(value: &str) -> bool {
    !value.is_empty() && value.len() <= 512 && !value.chars().any(char::is_control)
}

#[cfg(any(test, target_os = "linux"))]
fn is_environment_name(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 128
        && value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || byte == b'_')
}

#[cfg(any(test, target_os = "linux"))]
fn is_sha256_identity(value: &str) -> bool {
    value.len() == 71
        && value.starts_with("sha256:")
        && value.as_bytes()[7..]
            .iter()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(byte))
}

#[cfg(target_os = "linux")]
pub(crate) fn sha256_file_identity(file: &mut File) -> Result<String, ConfigError> {
    let mut digest = Sha256::new();
    let mut buffer = [0_u8; 16 * 1024];
    loop {
        let count = file
            .read(&mut buffer)
            .map_err(|_| ConfigError::Unavailable)?;
        if count == 0 {
            break;
        }
        digest.update(&buffer[..count]);
    }
    Ok(format!("sha256:{:x}", digest.finalize()))
}

#[cfg(target_os = "linux")]
fn open_protected_executable(
    path: &Path,
    expected_uid: u32,
    trusted_root: &Path,
) -> Result<File, ConfigError> {
    verify_protected_path(
        path,
        expected_uid,
        trusted_root,
        ProtectedPathKind::Executable,
    )?;
    let file = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_CLOEXEC | libc::O_NOFOLLOW)
        .open(path)
        .map_err(|_| ConfigError::Unavailable)?;
    let opened = file.metadata().map_err(|_| ConfigError::Unavailable)?;
    let observed = path.metadata().map_err(|_| ConfigError::Unavailable)?;
    if opened.dev() != observed.dev()
        || opened.ino() != observed.ino()
        || !opened.is_file()
        || opened.uid() != expected_uid
        || opened.mode() & 0o022 != 0
        || opened.mode() & 0o111 == 0
        || opened.mode() & 0o6000 != 0
    {
        return Err(ConfigError::Unprotected);
    }
    Ok(file)
}

pub(crate) fn open_protected_file(
    path: &Path,
    expected_uid: u32,
    trusted_root: &Path,
) -> Result<File, ConfigError> {
    verify_protected_path(path, expected_uid, trusted_root, ProtectedPathKind::File)?;
    let file = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_CLOEXEC | libc::O_NOFOLLOW)
        .open(path)
        .map_err(|_| ConfigError::Unavailable)?;
    let opened = file.metadata().map_err(|_| ConfigError::Unavailable)?;
    let observed = path.metadata().map_err(|_| ConfigError::Unavailable)?;
    if opened.dev() != observed.dev() || opened.ino() != observed.ino() {
        return Err(ConfigError::Unprotected);
    }
    Ok(file)
}

fn verify_protected_executable(
    path: &Path,
    expected_uid: u32,
    trusted_root: &Path,
) -> Result<(), ConfigError> {
    verify_protected_path(
        path,
        expected_uid,
        trusted_root,
        ProtectedPathKind::Executable,
    )
}

#[cfg(target_os = "linux")]
pub(crate) fn verify_protected_directory(
    path: &Path,
    expected_uid: u32,
    trusted_root: &Path,
) -> Result<(), ConfigError> {
    verify_protected_path(
        path,
        expected_uid,
        trusted_root,
        ProtectedPathKind::Directory,
    )
}

#[derive(Clone, Copy)]
#[cfg_attr(not(target_os = "linux"), allow(dead_code))]
enum ProtectedPathKind {
    File,
    Executable,
    Directory,
}

fn verify_protected_path(
    path: &Path,
    expected_uid: u32,
    trusted_root: &Path,
    kind: ProtectedPathKind,
) -> Result<(), ConfigError> {
    if !path.is_absolute() || !trusted_root.is_absolute() || !path.starts_with(trusted_root) {
        return Err(ConfigError::Unprotected);
    }
    let mut current = Some(path);
    while let Some(candidate) = current {
        let metadata = candidate
            .symlink_metadata()
            .map_err(|_| ConfigError::Unavailable)?;
        if metadata.file_type().is_symlink()
            || metadata.uid() != expected_uid
            || metadata.mode() & 0o022 != 0
        {
            return Err(ConfigError::Unprotected);
        }
        if candidate == path {
            let valid = match kind {
                ProtectedPathKind::File => metadata.is_file(),
                ProtectedPathKind::Executable => {
                    metadata.is_file()
                        && metadata.mode() & 0o111 != 0
                        && metadata.mode() & 0o6000 == 0
                }
                ProtectedPathKind::Directory => metadata.is_dir(),
            };
            if !valid {
                return Err(ConfigError::Unprotected);
            }
        } else if !metadata.is_dir() {
            return Err(ConfigError::Unprotected);
        }
        if candidate == trusted_root {
            return Ok(());
        }
        current = candidate.parent();
    }
    Err(ConfigError::Unprotected)
}

#[cfg(test)]
mod tests {
    use std::fs;
    use std::os::unix::fs::PermissionsExt;

    use tempfile::tempdir;

    use super::*;

    #[test]
    fn launcher_config_rejects_duplicate_authority_and_root_target() {
        let config = LauncherConfig {
            schema_version: 1,
            ota_binary: PathBuf::from("/usr/local/bin/ota"),
            run_as: RunAs { uid: 0, gid: 1000 },
            environment: BTreeMap::new(),
            sessions: vec![LauncherSessionBinding {
                authority_id: String::from("release"),
                broker_session_descriptor: 4,
                expected_peer: SessionPeer { uid: 0, gid: 0 },
            }],
        };
        assert!(validate_launcher_config(&config).is_err());

        let config = LauncherConfig {
            run_as: RunAs {
                uid: 1000,
                gid: 1000,
            },
            sessions: vec![
                LauncherSessionBinding {
                    authority_id: String::from("release"),
                    broker_session_descriptor: 4,
                    expected_peer: SessionPeer { uid: 0, gid: 0 },
                },
                LauncherSessionBinding {
                    authority_id: String::from("release"),
                    broker_session_descriptor: 5,
                    expected_peer: SessionPeer { uid: 0, gid: 0 },
                },
            ],
            ..config
        };
        assert!(validate_launcher_config(&config).is_err());
    }

    #[test]
    fn protected_file_verifier_rejects_symlink_and_writable_parent() {
        let root = tempdir().expect("temp root");
        fs::set_permissions(root.path(), fs::Permissions::from_mode(0o700))
            .expect("trusted root permissions");
        let uid = unsafe { libc::geteuid() };
        let protected = root.path().join("protected");
        fs::create_dir(&protected).expect("protected directory");
        fs::set_permissions(&protected, fs::Permissions::from_mode(0o700))
            .expect("protected permissions");
        let file = protected.join("config.json");
        fs::write(&file, b"{}").expect("protected file");
        fs::set_permissions(&file, fs::Permissions::from_mode(0o600)).expect("file permissions");
        assert!(verify_protected_path(&file, uid, root.path(), ProtectedPathKind::File).is_ok());

        let alias = protected.join("alias.json");
        std::os::unix::fs::symlink(&file, &alias).expect("symlink");
        assert!(verify_protected_path(&alias, uid, root.path(), ProtectedPathKind::File).is_err());

        fs::set_permissions(&protected, fs::Permissions::from_mode(0o722))
            .expect("writable permissions");
        assert!(verify_protected_path(&file, uid, root.path(), ProtectedPathKind::File).is_err());

        let directory = root.path().join("state");
        fs::create_dir(&directory).expect("state directory");
        fs::set_permissions(&directory, fs::Permissions::from_mode(0o700))
            .expect("state permissions");
        assert!(
            verify_protected_path(&directory, uid, root.path(), ProtectedPathKind::Directory,)
                .is_ok()
        );
    }

    #[test]
    fn protected_executable_rejects_privilege_bits() {
        let root = tempdir().expect("temp root");
        let uid = unsafe { libc::geteuid() };
        let executable = root.path().join("ota");
        fs::write(&executable, b"binary").expect("executable");
        fs::set_permissions(&executable, fs::Permissions::from_mode(0o4755))
            .expect("setuid permissions");
        assert!(verify_protected_executable(&executable, uid, root.path()).is_err());
    }

    fn identity(value: char) -> String {
        format!("sha256:{}", value.to_string().repeat(64))
    }

    fn systemd_service_config() -> SystemdLauncherServiceConfigV1 {
        let mut config = SystemdLauncherServiceConfigV1 {
            schema_version: 1,
            identity: String::new(),
            adapter: String::from(SYSTEMD_PROTECTED_LAUNCHER_ADAPTER_V1),
            socket_path: PathBuf::from("/run/ota/authority-launcher.sock"),
            socket_group_gid: 1001,
            ota_binary: PathBuf::from("/opt/ota/bin/ota"),
            environment: BTreeMap::from([(String::from("HOME"), String::from("/var/empty"))]),
            allowed_repository_roots: vec![PathBuf::from("/srv/ota-repositories")],
            mappings: vec![
                SystemdPrincipalMappingV1 {
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
                },
                SystemdPrincipalMappingV1 {
                    authority_id: String::from("publish"),
                    job_peer: SessionPeer {
                        uid: 1002,
                        gid: 1001,
                    },
                    execution: RunAs {
                        uid: 2002,
                        gid: 2002,
                    },
                    closed_profile: None,
                },
            ],
            broker_proxy_socket: PathBuf::from("/run/ota/broker-proxy.sock"),
            broker_proxy_peer: SessionPeer { uid: 0, gid: 0 },
            service_unit_identity: identity('a'),
            socket_unit_identity: identity('b'),
            ota_binary_identity: identity('c'),
            broker_proxy_identity: identity('d'),
            attestor_key_set_identity: identity('e'),
            attestation_claims: None,
            maximum_request_bytes: 4096,
            maximum_active_sessions: 2,
            maximum_startup_seconds: 30,
            maximum_terminal_wait_seconds: 300,
        };
        config.identity = systemd_launcher_service_config_identity(&config).expect("identity");
        config
    }

    #[test]
    fn systemd_service_config_requires_exact_identity_and_one_to_one_mappings() {
        let config = systemd_service_config();
        assert!(validate_systemd_launcher_service_config(&config).is_ok());
        let mapping =
            systemd_principal_mapping(&config, &config.mappings[0]).expect("principal mapping");
        assert_eq!(mapping.launcher_session_binding_identity, config.identity);
        assert_eq!(mapping.job_peer.real_uid, config.mappings[0].job_peer.uid);
        assert_eq!(mapping.execution.real_uid, config.mappings[0].execution.uid);

        let mut changed_root = config.clone();
        changed_root
            .allowed_repository_roots
            .push(PathBuf::from("/srv/other-repositories"));
        assert!(matches!(
            validate_systemd_launcher_service_config(&changed_root),
            Err(ConfigError::Unprotected)
        ));

        let mut shared_execution = config.clone();
        shared_execution.mappings[1].execution = shared_execution.mappings[0].execution.clone();
        shared_execution.identity =
            systemd_launcher_service_config_identity(&shared_execution).expect("identity");
        assert!(matches!(
            validate_systemd_launcher_service_config(&shared_execution),
            Err(ConfigError::Unsupported)
        ));

        let mut root_escape = config.clone();
        root_escape.allowed_repository_roots = vec![PathBuf::from("/srv/../etc")];
        root_escape.identity =
            systemd_launcher_service_config_identity(&root_escape).expect("identity");
        assert!(matches!(
            validate_systemd_launcher_service_config(&root_escape),
            Err(ConfigError::Unsupported)
        ));

        let mut reserved_environment = config.clone();
        reserved_environment.environment.insert(
            String::from("OTA_LAUNCHER_PRINCIPAL_MAPPING_IDENTITY"),
            identity('f'),
        );
        reserved_environment.identity =
            systemd_launcher_service_config_identity(&reserved_environment).expect("identity");
        assert!(matches!(
            validate_systemd_launcher_service_config(&reserved_environment),
            Err(ConfigError::Unsupported)
        ));

        let mut reserved_gate = config.clone();
        reserved_gate.environment.insert(
            String::from("OTA_SYSTEMD_LAUNCHER_STARTUP_GATE"),
            String::from("disabled"),
        );
        reserved_gate.identity =
            systemd_launcher_service_config_identity(&reserved_gate).expect("identity");
        assert!(matches!(
            validate_systemd_launcher_service_config(&reserved_gate),
            Err(ConfigError::Unsupported)
        ));

        let mut overlapping_roots = config.clone();
        overlapping_roots.allowed_repository_roots = vec![
            PathBuf::from("/srv/repositories"),
            PathBuf::from("/srv/repositories/team"),
        ];
        overlapping_roots.identity =
            systemd_launcher_service_config_identity(&overlapping_roots).expect("identity");
        assert!(matches!(
            validate_systemd_launcher_service_config(&overlapping_roots),
            Err(ConfigError::Unsupported)
        ));

        let mut uppercase_identity = config.clone();
        uppercase_identity.ota_binary_identity = identity('A');
        uppercase_identity.identity =
            systemd_launcher_service_config_identity(&uppercase_identity).expect("identity");
        assert!(matches!(
            validate_systemd_launcher_service_config(&uppercase_identity),
            Err(ConfigError::Unsupported)
        ));
    }

    #[test]
    fn systemd_closed_profile_and_attestation_claims_are_identity_bound() {
        let mut config = systemd_service_config();
        config.mappings[0].closed_profile = Some(SystemdJobPrincipalClosedProfileV1 {
            runner_service_unit: String::from("ota-pressure-runner.service"),
            runner_service_fragment_path: PathBuf::from(
                "/etc/systemd/system/ota-pressure-runner.service",
            ),
            runner_service_drop_in_paths: vec![PathBuf::from(
                "/etc/systemd/system/ota-pressure-runner.service.d/10-hardening.conf",
            )],
            non_login_shell: PathBuf::from("/usr/sbin/nologin"),
            host_control_sockets: vec![PathBuf::from("/run/docker.sock")],
        });
        config.attestation_claims = Some(SystemdAttestationClaimsConfigV1 {
            authenticated_origin: String::from("local-systemd-pressure"),
            authority_mounts: vec![String::from("authority-store")],
            requested_maximum_validity_seconds: 30,
        });
        config.identity = systemd_launcher_service_config_identity(&config).expect("identity");
        assert!(validate_systemd_launcher_service_config(&config).is_ok());

        let mut changed = config.clone();
        changed
            .attestation_claims
            .as_mut()
            .expect("attestation claims")
            .requested_maximum_validity_seconds = 31;
        assert!(matches!(
            validate_systemd_launcher_service_config(&changed),
            Err(ConfigError::Unprotected)
        ));

        let mut incomplete = config;
        incomplete.mappings[0]
            .closed_profile
            .as_mut()
            .expect("closed profile")
            .host_control_sockets
            .clear();
        incomplete.identity =
            systemd_launcher_service_config_identity(&incomplete).expect("identity");
        assert!(matches!(
            validate_systemd_launcher_service_config(&incomplete),
            Err(ConfigError::Unsupported)
        ));
    }
}
