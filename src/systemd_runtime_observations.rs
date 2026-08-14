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

//! Exact effective-systemd reconciliation for the protected launcher boundary.

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};

use ota_authority_protocol::{
    LauncherSystemdScopeV1, SYSTEMD_ATTESTOR_SOCKET_PATH_V1, message_identity,
};
use serde::Serialize;
use thiserror::Error;

use crate::config::SystemdLauncherServiceConfigV1;
use crate::installation_manifest::{ProtectedInstallationManifestV1, ProtectedInstallationRoleV1};

const LAUNCHER_SERVICE_UNIT: &str = "ota-authority-launcher.service";
const LAUNCHER_SOCKET_UNIT: &str = "ota-authority-launcher.socket";
const INVOCATION_SLICE: &str = "ota-authority-invocations.slice";
const SYSTEMD_RUNTIME_EVIDENCE_DOMAIN_V1: &str =
    "ota.authority-launcher.systemd-runtime-evidence.v1\0";
const MAX_SYSTEMCTL_OUTPUT: usize = 64 * 1024;

#[derive(Debug, Error, PartialEq, Eq)]
pub(crate) enum SystemdRuntimeObservationError {
    #[error("effective systemd runtime properties are unavailable")]
    Unavailable,
    #[error("effective systemd runtime properties do not match the closed profile")]
    Mismatch,
}

#[derive(Debug, Serialize)]
struct SystemdRuntimeEvidenceV1 {
    schema_version: u32,
    launcher_configuration_identity: String,
    installation_manifest_identity: String,
    service: BTreeMap<String, String>,
    socket: BTreeMap<String, String>,
    slice: BTreeMap<String, String>,
    invocation_scope: BTreeMap<String, String>,
}

pub(crate) fn verify_systemd_runtime(
    config: &SystemdLauncherServiceConfigV1,
    installation: &ProtectedInstallationManifestV1,
    scope: &LauncherSystemdScopeV1,
) -> Result<String, SystemdRuntimeObservationError> {
    let systemctl = installation
        .singular_path(ProtectedInstallationRoleV1::SystemctlExecutable)
        .map_err(|_| SystemdRuntimeObservationError::Unavailable)?;
    let service = show_properties(
        systemctl,
        LAUNCHER_SERVICE_UNIT,
        &[
            "Id",
            "ActiveState",
            "MainPID",
            "ControlGroup",
            "FragmentPath",
            "DropInPaths",
            "User",
            "Group",
            "UMask",
            "NoNewPrivileges",
            "RestrictSUIDSGID",
            "LockPersonality",
            "MemoryDenyWriteExecute",
            "RestrictRealtime",
            "PrivateTmp",
            "PrivateDevices",
            "ProtectSystem",
            "ProtectHome",
            "ProtectKernelTunables",
            "ProtectKernelModules",
            "ProtectKernelLogs",
            "ProtectClock",
            "ProtectControlGroups",
            "ProtectProc",
            "ProcSubset",
            "RestrictNamespaces",
            "SystemCallArchitectures",
            "CapabilityBoundingSet",
            "AmbientCapabilities",
            "SupplementaryGroups",
            "RestrictAddressFamilies",
            "KillMode",
            "ReadOnlyPaths",
            "ReadWritePaths",
        ],
    )?;
    verify_service_properties(config, installation, &service)?;

    let socket = show_properties(
        systemctl,
        LAUNCHER_SOCKET_UNIT,
        &[
            "Id",
            "ActiveState",
            "FragmentPath",
            "DropInPaths",
            "Accept",
            "Listen",
            "SocketUser",
            "SocketGroup",
            "SocketMode",
            "RemoveOnStop",
            "Triggers",
        ],
    )?;
    verify_socket_properties(config, installation, &socket)?;

    let slice = show_properties(
        systemctl,
        INVOCATION_SLICE,
        &["Id", "ActiveState", "ControlGroup"],
    )?;
    require(&slice, "Id", INVOCATION_SLICE)?;
    require(&slice, "ActiveState", "active")?;
    if value(&slice, "ControlGroup")?.is_empty() {
        return Err(SystemdRuntimeObservationError::Mismatch);
    }
    if scope.slice != INVOCATION_SLICE
        || scope.delegate
        || scope.kill_mode != "control-group"
        || scope.collect_mode != "inactive-or-failed"
    {
        return Err(SystemdRuntimeObservationError::Mismatch);
    }
    let invocation_scope = show_properties(
        systemctl,
        scope.unit_name.as_str(),
        &[
            "Id",
            "ActiveState",
            "ControlGroup",
            "Slice",
            "Delegate",
            "KillMode",
            "CollectMode",
        ],
    )?;
    for (name, expected) in [
        ("Id", scope.unit_name.as_str()),
        ("ActiveState", "active"),
        ("ControlGroup", scope.control_group.as_str()),
        ("Slice", scope.slice.as_str()),
        ("Delegate", "no"),
        ("KillMode", scope.kill_mode.as_str()),
        ("CollectMode", scope.collect_mode.as_str()),
    ] {
        require(&invocation_scope, name, expected)?;
    }

    message_identity(
        SYSTEMD_RUNTIME_EVIDENCE_DOMAIN_V1.as_bytes(),
        &SystemdRuntimeEvidenceV1 {
            schema_version: 1,
            launcher_configuration_identity: config.identity.clone(),
            installation_manifest_identity: installation.identity.clone(),
            service,
            socket,
            slice,
            invocation_scope,
        },
    )
    .map_err(|_| SystemdRuntimeObservationError::Mismatch)
}

pub(crate) fn show_properties(
    systemctl: &Path,
    unit: &str,
    properties: &[&str],
) -> Result<BTreeMap<String, String>, SystemdRuntimeObservationError> {
    let mut command = Command::new(systemctl);
    command
        .env_clear()
        .env("LC_ALL", "C")
        .arg("show")
        .arg(unit)
        .arg("--no-pager")
        .stdin(Stdio::null())
        .stderr(Stdio::null());
    for property in properties {
        command.arg(format!("--property={property}"));
    }
    let output = command
        .output()
        .map_err(|_| SystemdRuntimeObservationError::Unavailable)?;
    if !output.status.success()
        || output.stdout.is_empty()
        || output.stdout.len() > MAX_SYSTEMCTL_OUTPUT
    {
        return Err(SystemdRuntimeObservationError::Unavailable);
    }
    parse_properties(&output.stdout, properties)
}

fn parse_properties(
    output: &[u8],
    required: &[&str],
) -> Result<BTreeMap<String, String>, SystemdRuntimeObservationError> {
    let text = std::str::from_utf8(output).map_err(|_| SystemdRuntimeObservationError::Mismatch)?;
    let mut values = BTreeMap::new();
    for line in text.lines() {
        let (name, value) = line
            .split_once('=')
            .ok_or(SystemdRuntimeObservationError::Mismatch)?;
        if name.is_empty() || values.insert(name.into(), value.into()).is_some() {
            return Err(SystemdRuntimeObservationError::Mismatch);
        }
    }
    if values.len() != required.len() || required.iter().any(|name| !values.contains_key(*name)) {
        return Err(SystemdRuntimeObservationError::Mismatch);
    }
    Ok(values)
}

fn verify_service_properties(
    config: &SystemdLauncherServiceConfigV1,
    installation: &ProtectedInstallationManifestV1,
    values: &BTreeMap<String, String>,
) -> Result<(), SystemdRuntimeObservationError> {
    for (name, expected) in [
        ("Id", LAUNCHER_SERVICE_UNIT),
        ("ActiveState", "active"),
        ("User", "root"),
        ("Group", "root"),
        ("UMask", "0077"),
        ("NoNewPrivileges", "yes"),
        ("RestrictSUIDSGID", "no"),
        ("LockPersonality", "yes"),
        ("MemoryDenyWriteExecute", "no"),
        ("RestrictRealtime", "yes"),
        ("PrivateTmp", "yes"),
        ("PrivateDevices", "yes"),
        ("ProtectSystem", "strict"),
        ("ProtectHome", "read-only"),
        ("ProtectKernelTunables", "yes"),
        ("ProtectKernelModules", "yes"),
        ("ProtectKernelLogs", "yes"),
        ("ProtectClock", "yes"),
        ("ProtectControlGroups", "yes"),
        ("ProtectProc", "invisible"),
        ("ProcSubset", "pid"),
        ("RestrictNamespaces", "yes"),
        ("SystemCallArchitectures", "native"),
        ("AmbientCapabilities", "cap_setuid"),
        ("SupplementaryGroups", ""),
        ("KillMode", "control-group"),
    ] {
        require(values, name, expected)?;
    }
    let main_pid = value(values, "MainPID")?
        .parse::<u32>()
        .map_err(|_| SystemdRuntimeObservationError::Mismatch)?;
    if main_pid != std::process::id() || value(values, "ControlGroup")?.is_empty() {
        return Err(SystemdRuntimeObservationError::Mismatch);
    }
    require_path(
        values,
        "FragmentPath",
        installation
            .singular_path(ProtectedInstallationRoleV1::LauncherServiceUnit)
            .map_err(|_| SystemdRuntimeObservationError::Mismatch)?,
    )?;
    require_path_set(
        values,
        "DropInPaths",
        installation.paths(ProtectedInstallationRoleV1::LauncherServiceDropIn),
    )?;
    require_token_set(
        values,
        "CapabilityBoundingSet",
        &[
            "cap_dac_override",
            "cap_kill",
            "cap_setgid",
            "cap_setuid",
            "cap_sys_ptrace",
        ],
    )?;
    require_token_set(
        values,
        "RestrictAddressFamilies",
        &["AF_INET", "AF_INET6", "AF_UNIX"],
    )?;
    let mut writable = vec![
        Path::new("/run/ota/authority-launcher"),
        Path::new("/var/lib/ota/authority-launcher"),
    ];
    if installation
        .optional_singular_path(ProtectedInstallationRoleV1::HistoryBinding)
        .map_err(|_| SystemdRuntimeObservationError::Mismatch)?
        .is_some()
    {
        writable.extend([
            Path::new(crate::protected_history::HISTORY_BLOB_ROOT),
            Path::new(crate::protected_history::HISTORY_CATALOG_ROOT),
        ]);
    }
    writable.extend(config.allowed_repository_roots.iter().map(PathBuf::as_path));
    require_path_set(values, "ReadWritePaths", writable)?;
    let mut read_only = vec![Path::new("/etc/ota")];
    read_only.extend(installation.files.iter().map(|entry| entry.path.as_path()));
    read_only.push(Path::new("/run/systemd/system"));
    read_only.push(config.broker_proxy_socket.as_path());
    read_only.push(Path::new(SYSTEMD_ATTESTOR_SOCKET_PATH_V1));
    require_path_set(values, "ReadOnlyPaths", read_only)?;
    Ok(())
}

fn verify_socket_properties(
    config: &SystemdLauncherServiceConfigV1,
    installation: &ProtectedInstallationManifestV1,
    values: &BTreeMap<String, String>,
) -> Result<(), SystemdRuntimeObservationError> {
    for (name, expected) in [
        ("Id", LAUNCHER_SOCKET_UNIT),
        ("ActiveState", "active"),
        ("Accept", "no"),
        ("SocketUser", "root"),
        ("SocketMode", "0660"),
        ("RemoveOnStop", "yes"),
        ("Triggers", LAUNCHER_SERVICE_UNIT),
    ] {
        require(values, name, expected)?;
    }
    require_path(
        values,
        "FragmentPath",
        installation
            .singular_path(ProtectedInstallationRoleV1::LauncherSocketUnit)
            .map_err(|_| SystemdRuntimeObservationError::Mismatch)?,
    )?;
    require_path_set(
        values,
        "DropInPaths",
        installation.paths(ProtectedInstallationRoleV1::LauncherSocketDropIn),
    )?;
    let socket_group = group_name(config.socket_group_gid)?;
    require(values, "SocketGroup", socket_group.as_str())?;
    if !value(values, "Listen")?.contains(config.socket_path.to_string_lossy().as_ref()) {
        return Err(SystemdRuntimeObservationError::Mismatch);
    }
    Ok(())
}

fn group_name(gid: u32) -> Result<String, SystemdRuntimeObservationError> {
    let mut buffer = vec![0_u8; 16 * 1024];
    let mut group = std::mem::MaybeUninit::<libc::group>::uninit();
    let mut result = std::ptr::null_mut();
    let status = unsafe {
        libc::getgrgid_r(
            gid,
            group.as_mut_ptr(),
            buffer.as_mut_ptr().cast(),
            buffer.len(),
            &mut result,
        )
    };
    if status != 0 || result.is_null() {
        return Err(SystemdRuntimeObservationError::Unavailable);
    }
    let group = unsafe { group.assume_init() };
    if group.gr_name.is_null() {
        return Err(SystemdRuntimeObservationError::Mismatch);
    }
    let name = unsafe { std::ffi::CStr::from_ptr(group.gr_name) }
        .to_str()
        .map_err(|_| SystemdRuntimeObservationError::Mismatch)?;
    if name.is_empty() {
        return Err(SystemdRuntimeObservationError::Mismatch);
    }
    Ok(name.to_owned())
}

fn require(
    values: &BTreeMap<String, String>,
    name: &str,
    expected: &str,
) -> Result<(), SystemdRuntimeObservationError> {
    if value(values, name)? != expected {
        pressure_property_mismatch(name);
        return Err(SystemdRuntimeObservationError::Mismatch);
    }
    Ok(())
}

pub(crate) fn value<'a>(
    values: &'a BTreeMap<String, String>,
    name: &str,
) -> Result<&'a str, SystemdRuntimeObservationError> {
    values
        .get(name)
        .map(String::as_str)
        .ok_or(SystemdRuntimeObservationError::Mismatch)
}

fn require_path(
    values: &BTreeMap<String, String>,
    name: &str,
    expected: &Path,
) -> Result<(), SystemdRuntimeObservationError> {
    require(values, name, expected.to_string_lossy().as_ref())
}

pub(crate) fn require_path_set(
    values: &BTreeMap<String, String>,
    name: &str,
    expected: Vec<&Path>,
) -> Result<(), SystemdRuntimeObservationError> {
    let observed = value(values, name)?
        .split_whitespace()
        .map(str::to_owned)
        .collect::<std::collections::BTreeSet<_>>();
    let expected = expected
        .into_iter()
        .map(|path| path.to_string_lossy().into_owned())
        .collect::<std::collections::BTreeSet<_>>();
    if observed != expected {
        pressure_property_mismatch(name);
        return Err(SystemdRuntimeObservationError::Mismatch);
    }
    Ok(())
}

fn require_token_set(
    values: &BTreeMap<String, String>,
    name: &str,
    expected: &[&str],
) -> Result<(), SystemdRuntimeObservationError> {
    let observed = value(values, name)?
        .split_whitespace()
        .collect::<std::collections::BTreeSet<_>>();
    let expected = expected
        .iter()
        .copied()
        .collect::<std::collections::BTreeSet<_>>();
    if observed != expected {
        pressure_property_mismatch(name);
        return Err(SystemdRuntimeObservationError::Mismatch);
    }
    Ok(())
}

#[cfg(feature = "systemd-pressure-faults")]
fn pressure_property_mismatch(name: &str) {
    eprintln!("ota-authority-launcher: bounded pressure systemd property mismatch name={name}");
}

#[cfg(not(feature = "systemd-pressure-faults"))]
fn pressure_property_mismatch(_name: &str) {}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn property_parser_requires_the_exact_non_duplicated_set() {
        let required = ["Id", "ActiveState"];
        let parsed = parse_properties(b"Id=unit.service\nActiveState=active\n", &required)
            .expect("exact properties");
        assert_eq!(value(&parsed, "Id").expect("id"), "unit.service");
        assert!(parse_properties(b"Id=a\nId=b\nActiveState=active\n", &required).is_err());
        assert!(parse_properties(b"Id=a\n", &required).is_err());
        assert!(parse_properties(b"Id=a\nActiveState=active\nExtra=x\n", &required).is_err());
    }

    #[test]
    fn socket_runtime_requires_the_manager_observed_service_trigger() {
        let mut values = BTreeMap::from([
            ("Id".into(), LAUNCHER_SOCKET_UNIT.into()),
            ("ActiveState".into(), "active".into()),
            ("Accept".into(), "no".into()),
            ("SocketUser".into(), "root".into()),
            ("SocketMode".into(), "0660".into()),
            ("RemoveOnStop".into(), "yes".into()),
            ("Triggers".into(), LAUNCHER_SERVICE_UNIT.into()),
        ]);
        for (name, expected) in [
            ("Id", LAUNCHER_SOCKET_UNIT),
            ("ActiveState", "active"),
            ("Accept", "no"),
            ("SocketUser", "root"),
            ("SocketMode", "0660"),
            ("RemoveOnStop", "yes"),
            ("Triggers", LAUNCHER_SERVICE_UNIT),
        ] {
            require(&values, name, expected).expect("matching socket property");
        }
        values.insert("Triggers".into(), "other.service".into());
        assert!(require(&values, "Triggers", LAUNCHER_SERVICE_UNIT).is_err());
    }

    #[test]
    fn capabilities_use_systemd_manager_output_spelling() {
        let values = BTreeMap::from([(
            "CapabilityBoundingSet".into(),
            "cap_dac_override cap_kill cap_setgid cap_setuid cap_sys_ptrace".into(),
        )]);
        require_token_set(
            &values,
            "CapabilityBoundingSet",
            &[
                "cap_dac_override",
                "cap_kill",
                "cap_setgid",
                "cap_setuid",
                "cap_sys_ptrace",
            ],
        )
        .expect("exact manager capability set");
        assert!(
            require_token_set(
                &values,
                "CapabilityBoundingSet",
                &["cap_kill", "cap_setuid", "cap_sys_ptrace"],
            )
            .is_err()
        );
    }
}
