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

//! Live, fail-closed observations for the closed systemd job-principal profile.

use std::collections::{BTreeMap, BTreeSet};
use std::ffi::{CStr, CString};
use std::fs;
use std::io::Read;
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd};
use std::os::unix::ffi::OsStrExt;
use std::os::unix::fs::{FileTypeExt, MetadataExt};
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};

use ota_authority_protocol::{
    LauncherChildProcessV1, LauncherSystemdScopeV1, OtaProcessPostureV1,
    SystemdJobPrincipalRequirement, SystemdLauncherEvidenceSource, message_identity,
};
use serde::Serialize;
use thiserror::Error;

use crate::config::{
    RunAs, SystemdJobPrincipalClosedProfileV1, SystemdLauncherServiceConfigV1,
    SystemdPrincipalMappingV1,
};
use crate::installation_manifest::{ProtectedInstallationManifestV1, ProtectedInstallationRoleV1};
use crate::systemd_runtime_observations::{show_properties, value};
use ota_authority_launcher::linux_observations::{
    ObservedSessionPeer, revalidate_connected_peer, verify_peer_process_status,
};
use ota_authority_launcher::observation_collector::{
    ClosedProfileProbe, ObservationCollectionError,
};

const EVIDENCE_DOMAIN_V1: &str = "ota.authority-launcher.closed-profile-evidence.v1\0";
const MAX_POLICY_OUTPUT: usize = 64 * 1024;
const CANONICAL_SUDO_PATH: &str = "/usr/bin/sudo";
pub(crate) const SYSTEMD_ACTIONS: [&str; 4] = [
    "org.freedesktop.systemd1.manage-units",
    "org.freedesktop.systemd1.manage-unit-files",
    "org.freedesktop.systemd1.reload-daemon",
    "org.freedesktop.systemd1.set-environment",
];

#[derive(Debug, Error, PartialEq, Eq)]
pub(crate) enum ClosedProfileObservationError {
    #[error("a required closed-profile observation is unavailable")]
    Unavailable,
    #[error("a required closed-profile observation does not match protected configuration")]
    Mismatch,
}

#[derive(Debug)]
pub(crate) struct LiveClosedProfileEvidence {
    launcher: BTreeMap<&'static str, String>,
    job: BTreeMap<&'static str, String>,
}

impl LiveClosedProfileEvidence {
    pub(crate) fn launcher_identity(
        &self,
        source: SystemdLauncherEvidenceSource,
    ) -> Result<String, ClosedProfileObservationError> {
        self.launcher
            .get(launcher_key(source))
            .cloned()
            .ok_or(ClosedProfileObservationError::Unavailable)
    }

    pub(crate) fn job_identity(
        &self,
        requirement: SystemdJobPrincipalRequirement,
    ) -> Result<String, ClosedProfileObservationError> {
        self.job
            .get(job_key(requirement))
            .cloned()
            .ok_or(ClosedProfileObservationError::Unavailable)
    }
}

impl ClosedProfileProbe for LiveClosedProfileEvidence {
    fn verify_launcher_source(
        &mut self,
        source: SystemdLauncherEvidenceSource,
    ) -> Result<String, ObservationCollectionError> {
        self.launcher_identity(source)
            .map_err(|_| ObservationCollectionError::LauncherObservationUnavailable)
    }

    fn verify_job_principal_requirement(
        &mut self,
        requirement: &ota_authority_protocol::SystemdJobPrincipalRequirementDefinition,
    ) -> Result<String, ObservationCollectionError> {
        self.job_identity(requirement.requirement)
            .map_err(|_| ObservationCollectionError::JobPrincipalObservationUnavailable)
    }
}

#[allow(clippy::too_many_arguments)]
pub(crate) fn collect_live_closed_profile_evidence(
    config: &SystemdLauncherServiceConfigV1,
    installation: &ProtectedInstallationManifestV1,
    mapping: &SystemdPrincipalMappingV1,
    peer_stream: &std::os::unix::net::UnixStream,
    peer: &ObservedSessionPeer,
    child: &LauncherChildProcessV1,
    scope: &LauncherSystemdScopeV1,
    posture: &OtaProcessPostureV1,
    systemd_runtime_identity: &str,
) -> Result<LiveClosedProfileEvidence, ClosedProfileObservationError> {
    let closed = mapping
        .closed_profile
        .as_ref()
        .ok_or(ClosedProfileObservationError::Unavailable)?;
    revalidate_connected_peer(peer_stream, peer)
        .map_err(|_| ClosedProfileObservationError::Unavailable)?;
    verify_peer_process_status(peer).map_err(|_| ClosedProfileObservationError::Mismatch)?;

    let peer_identity = identity("peer", &(peer.pid, peer.uid, peer.gid))?;
    let account_identity = pressure_observation("accounts", verify_accounts(mapping, closed))?;
    let runner_identity = pressure_observation(
        "runner_service",
        verify_runner_service(installation, closed, peer.pid),
    )?;
    let containment_identity = pressure_observation(
        "process_containment",
        verify_process_containment(mapping, closed, child, scope),
    )?;
    let sudo_identity =
        pressure_observation("sudo_policy", verify_sudo_policy(installation, mapping))?;
    let policy_identity = pressure_observation(
        "systemd_policy",
        verify_systemd_policy(installation, mapping, peer, child),
    )?;
    let target_identity = pressure_observation(
        "target_access",
        verify_target_access(config, installation, mapping, closed, child.pid),
    )?;
    let descriptor_identity = pressure_observation(
        "child_descriptors",
        verify_child_descriptors(config, installation, child.pid),
    )?;
    let socket_identity = pressure_observation(
        "protected_socket_posture",
        verify_protected_socket_posture(config, closed),
    )?;
    let process_access_identity =
        pressure_observation("process_access", verify_process_access(mapping, child.pid))?;
    revalidate_connected_peer(peer_stream, peer)
        .map_err(|_| ClosedProfileObservationError::Unavailable)?;

    let mut launcher = BTreeMap::new();
    launcher.insert("protected_file_identity", installation.identity.clone());
    launcher.insert(
        "systemd_manager_property",
        systemd_runtime_identity.to_owned(),
    );
    launcher.insert("socket_peer_credentials", peer_identity.clone());
    launcher.insert(
        "proc_process_status",
        identity(
            "process-status",
            &(peer_identity.clone(), child.identity.clone()),
        )?,
    );
    launcher.insert("proc_descriptor_inspection", descriptor_identity);
    launcher.insert("protected_socket_identity", socket_identity);
    launcher.insert("target_principal_access_probe", target_identity.clone());
    launcher.insert("ota_process_posture", posture.identity.clone());

    let mut job = BTreeMap::new();
    job.insert(
        "distinct_one_to_one_principals",
        identity(
            "principal-mapping",
            &(config.identity.clone(), account_identity.clone()),
        )?,
    );
    job.insert(
        "peer_identity_matches_protected_mapping",
        identity(
            "peer-mapping",
            &(config.identity.clone(), peer_identity.clone()),
        )?,
    );
    for requirement in [
        "peer_no_new_privileges",
        "peer_capabilities_empty",
        "peer_supplementary_groups_limited_to_primary",
    ] {
        job.insert(requirement, peer_identity.clone());
    }
    job.insert("runner_service_identity_bound", runner_identity);
    job.insert("all_principal_processes_contained", containment_identity);
    job.insert("accounts_locked", account_identity.clone());
    job.insert("non_login_shells", account_identity);
    job.insert("sudo_policy_denied", sudo_identity);
    job.insert("systemd_policy_denied", policy_identity.clone());
    job.insert(
        "polkit_policy_denied",
        identity("polkit-policy", &policy_identity)?,
    );
    for requirement in [
        "protected_paths_write_denied",
        "host_control_sockets_denied",
        "execution_launcher_socket_denied",
    ] {
        job.insert(requirement, target_identity.clone());
    }
    job.insert(
        "ota_process_non_dumpable",
        identity(
            "non-dumpable",
            &(posture.identity.clone(), process_access_identity.clone()),
        )?,
    );
    job.insert(
        "ota_ptracer_cleared",
        identity(
            "ptracer-cleared",
            &(posture.identity.clone(), process_access_identity.clone()),
        )?,
    );
    job.insert("ota_process_inspection_denied", process_access_identity);
    Ok(LiveClosedProfileEvidence { launcher, job })
}

#[cfg(feature = "systemd-pressure-faults")]
fn pressure_observation<T>(
    name: &str,
    result: Result<T, ClosedProfileObservationError>,
) -> Result<T, ClosedProfileObservationError> {
    if result.is_err() {
        eprintln!("ota-authority-launcher: bounded pressure observation mismatch name={name}");
    }
    result
}

#[cfg(not(feature = "systemd-pressure-faults"))]
fn pressure_observation<T>(
    _name: &str,
    result: Result<T, ClosedProfileObservationError>,
) -> Result<T, ClosedProfileObservationError> {
    result
}

fn verify_runner_service(
    installation: &ProtectedInstallationManifestV1,
    closed: &SystemdJobPrincipalClosedProfileV1,
    peer_pid: u32,
) -> Result<String, ClosedProfileObservationError> {
    let systemctl = installation
        .singular_path(ProtectedInstallationRoleV1::SystemctlExecutable)
        .map_err(|_| ClosedProfileObservationError::Unavailable)?;
    let properties = show_properties(
        systemctl,
        closed.runner_service_unit.as_str(),
        &[
            "Id",
            "ActiveState",
            "ControlGroup",
            "FragmentPath",
            "DropInPaths",
            "NoNewPrivileges",
        ],
    )
    .map_err(|_| ClosedProfileObservationError::Unavailable)?;
    pressure_condition(
        "runner_service.id",
        value(&properties, "Id").ok() == Some(closed.runner_service_unit.as_str()),
    )?;
    pressure_condition(
        "runner_service.state",
        runner_service_state_is_executing(value(&properties, "ActiveState").ok()),
    )?;
    pressure_condition(
        "runner_service.no_new_privileges",
        value(&properties, "NoNewPrivileges").ok() == Some("yes"),
    )?;
    pressure_condition(
        "runner_service.fragment",
        value(&properties, "FragmentPath").ok()
            == Some(
                closed
                    .runner_service_fragment_path
                    .to_string_lossy()
                    .as_ref(),
            ),
    )?;
    pressure_condition(
        "runner_service.drop_ins",
        token_paths(
            value(&properties, "DropInPaths")
                .map_err(|_| ClosedProfileObservationError::Unavailable)?,
        )? == closed
            .runner_service_drop_in_paths
            .iter()
            .map(|path| path.to_string_lossy().into_owned())
            .collect::<BTreeSet<_>>(),
    )?;
    let control_group = value(&properties, "ControlGroup")
        .map_err(|_| ClosedProfileObservationError::Unavailable)?;
    pressure_condition(
        "runner_service.control_group_present",
        !control_group.is_empty(),
    )?;
    pressure_condition(
        "runner_service.peer_control_group",
        process_cgroup(peer_pid)? == control_group,
    )?;
    identity("runner-service", &properties)
}

fn runner_service_state_is_executing(state: Option<&str>) -> bool {
    matches!(state, Some("active" | "activating"))
}

fn pressure_condition(name: &str, condition: bool) -> Result<(), ClosedProfileObservationError> {
    if !condition {
        #[cfg(feature = "systemd-pressure-faults")]
        eprintln!("ota-authority-launcher: bounded pressure condition mismatch name={name}");
        return Err(ClosedProfileObservationError::Mismatch);
    }
    Ok(())
}

fn verify_process_containment(
    mapping: &SystemdPrincipalMappingV1,
    closed: &SystemdJobPrincipalClosedProfileV1,
    child: &LauncherChildProcessV1,
    scope: &LauncherSystemdScopeV1,
) -> Result<String, ClosedProfileObservationError> {
    let mut observed = Vec::new();
    for entry in fs::read_dir("/proc").map_err(|_| ClosedProfileObservationError::Unavailable)? {
        let entry = entry.map_err(|_| ClosedProfileObservationError::Unavailable)?;
        let Some(pid) = entry
            .file_name()
            .to_str()
            .and_then(|value| value.parse::<u32>().ok())
        else {
            continue;
        };
        let uid = process_real_uid(pid)?;
        if uid != mapping.job_peer.uid && uid != mapping.execution.uid {
            continue;
        }
        let cgroup = process_cgroup(pid)?;
        if (uid == mapping.job_peer.uid
            && !cgroup.ends_with(format!("/{}", closed.runner_service_unit).as_str()))
            || (uid == mapping.execution.uid && cgroup != scope.control_group)
        {
            return Err(ClosedProfileObservationError::Mismatch);
        }
        observed.push((pid, uid, cgroup));
    }
    observed.sort();
    if !observed
        .iter()
        .any(|(pid, uid, _)| *pid == child.pid && *uid == mapping.execution.uid)
    {
        return Err(ClosedProfileObservationError::Mismatch);
    }
    identity("process-containment", &observed)
}

#[derive(Debug, Serialize)]
struct AccountPosture {
    name: String,
    uid: u32,
    gid: u32,
    shell: String,
    locked: bool,
    supplementary_groups: Vec<u32>,
}

fn verify_accounts(
    mapping: &SystemdPrincipalMappingV1,
    closed: &SystemdJobPrincipalClosedProfileV1,
) -> Result<String, ClosedProfileObservationError> {
    let job = account_posture(
        mapping.job_peer.uid,
        mapping.job_peer.gid,
        &closed.non_login_shell,
    )?;
    let execution = account_posture(
        mapping.execution.uid,
        mapping.execution.gid,
        &closed.non_login_shell,
    )?;
    if job.name == execution.name || job.uid == execution.uid || job.gid == execution.gid {
        return Err(ClosedProfileObservationError::Mismatch);
    }
    identity("accounts", &(job, execution))
}

fn account_posture(
    uid: u32,
    gid: u32,
    expected_shell: &Path,
) -> Result<AccountPosture, ClosedProfileObservationError> {
    let (name, observed_gid, shell) = passwd_entry(uid)?;
    if observed_gid != gid || shell.as_bytes() != expected_shell.as_os_str().as_bytes() {
        return Err(ClosedProfileObservationError::Mismatch);
    }
    let locked = shadow_locked(name.as_str())?;
    let supplementary_groups = supplementary_groups(name.as_str(), gid)?;
    if !locked || !supplementary_groups.is_empty() {
        return Err(ClosedProfileObservationError::Mismatch);
    }
    Ok(AccountPosture {
        name,
        uid,
        gid,
        shell,
        locked,
        supplementary_groups,
    })
}

fn passwd_entry(uid: u32) -> Result<(String, u32, String), ClosedProfileObservationError> {
    let mut record = std::mem::MaybeUninit::<libc::passwd>::uninit();
    let mut result = std::ptr::null_mut();
    let mut buffer = vec![0_u8; 16 * 1024];
    let status = unsafe {
        libc::getpwuid_r(
            uid,
            record.as_mut_ptr(),
            buffer.as_mut_ptr().cast(),
            buffer.len(),
            &mut result,
        )
    };
    if status != 0 || result.is_null() {
        return Err(ClosedProfileObservationError::Unavailable);
    }
    let record = unsafe { record.assume_init() };
    Ok((
        c_string(record.pw_name)?,
        record.pw_gid,
        c_string(record.pw_shell)?,
    ))
}

fn shadow_locked(name: &str) -> Result<bool, ClosedProfileObservationError> {
    let name = CString::new(name).map_err(|_| ClosedProfileObservationError::Mismatch)?;
    let mut record = std::mem::MaybeUninit::<libc::spwd>::uninit();
    let mut result = std::ptr::null_mut();
    let mut buffer = vec![0_u8; 16 * 1024];
    let status = unsafe {
        libc::getspnam_r(
            name.as_ptr(),
            record.as_mut_ptr(),
            buffer.as_mut_ptr().cast(),
            buffer.len(),
            &mut result,
        )
    };
    if status != 0 || result.is_null() {
        return Err(ClosedProfileObservationError::Unavailable);
    }
    let password = c_string(unsafe { record.assume_init() }.sp_pwdp)?;
    Ok(password.starts_with('!') || password.starts_with('*'))
}

fn supplementary_groups(
    name: &str,
    primary_gid: u32,
) -> Result<Vec<u32>, ClosedProfileObservationError> {
    let name = CString::new(name).map_err(|_| ClosedProfileObservationError::Mismatch)?;
    let mut count = 0_i32;
    unsafe { libc::getgrouplist(name.as_ptr(), primary_gid, std::ptr::null_mut(), &mut count) };
    if count <= 0 || count > 1024 {
        return Err(ClosedProfileObservationError::Unavailable);
    }
    let mut groups = vec![0_u32; count as usize];
    if unsafe { libc::getgrouplist(name.as_ptr(), primary_gid, groups.as_mut_ptr(), &mut count) }
        < 0
    {
        return Err(ClosedProfileObservationError::Unavailable);
    }
    groups.truncate(count as usize);
    groups.sort_unstable();
    groups.dedup();
    groups.retain(|value| *value != primary_gid);
    Ok(groups)
}

fn verify_sudo_policy(
    installation: &ProtectedInstallationManifestV1,
    mapping: &SystemdPrincipalMappingV1,
) -> Result<String, ClosedProfileObservationError> {
    let configured = installation
        .optional_singular_path(ProtectedInstallationRoleV1::SudoExecutable)
        .map_err(|_| ClosedProfileObservationError::Mismatch)?;
    let canonical = Path::new(CANONICAL_SUDO_PATH);
    let exists = canonical
        .try_exists()
        .map_err(|_| ClosedProfileObservationError::Unavailable)?;
    match (configured, exists) {
        (None, false) => identity("sudo-absent", &CANONICAL_SUDO_PATH),
        (Some(path), true) if path == canonical => {
            let mut outcomes = Vec::new();
            for uid in [mapping.job_peer.uid, mapping.execution.uid] {
                let (name, _, _) = passwd_entry(uid)?;
                let output = bounded_command(path, &["-n", "-l", "-U", name.as_str()])?;
                if !sudo_listing_denies_user(&output, name.as_str()) {
                    return Err(ClosedProfileObservationError::Mismatch);
                }
                outcomes.push((name, output.status.code()));
            }
            identity("sudo-policy", &outcomes)
        }
        _ => Err(ClosedProfileObservationError::Mismatch),
    }
}

fn sudo_listing_denies_user(output: &std::process::Output, name: &str) -> bool {
    if !matches!(output.status.code(), Some(0 | 1)) {
        return false;
    }
    let text = String::from_utf8_lossy(&output.stdout).to_string()
        + String::from_utf8_lossy(&output.stderr).as_ref();
    let mut lines = text.lines().filter(|line| !line.trim().is_empty());
    let Some(line) = lines.next() else {
        return false;
    };
    let prefix = format!("User {name} is not allowed to run sudo on ");
    line.starts_with(prefix.as_str())
        && line.strip_prefix(prefix.as_str()).is_some_and(|host| {
            host.strip_suffix('.')
                .is_some_and(|host| !host.is_empty() && !host.chars().any(char::is_whitespace))
        })
        && lines.next().is_none()
}

fn verify_systemd_policy(
    installation: &ProtectedInstallationManifestV1,
    mapping: &SystemdPrincipalMappingV1,
    peer: &ObservedSessionPeer,
    child: &LauncherChildProcessV1,
) -> Result<String, ClosedProfileObservationError> {
    installation
        .singular_path(ProtectedInstallationRoleV1::PolkitRule)
        .map_err(|_| ClosedProfileObservationError::Unavailable)?;
    let pkcheck = installation
        .singular_path(ProtectedInstallationRoleV1::PkcheckExecutable)
        .map_err(|_| ClosedProfileObservationError::Unavailable)?;
    let mut outcomes = Vec::new();
    for (_principal, pid, uid) in [
        ("job", peer.pid, peer.uid),
        ("execution", child.pid, mapping.execution.uid),
    ] {
        let start = process_start_ticks(pid)?;
        let process = format!("{pid},{start},{uid}");
        for action in SYSTEMD_ACTIONS {
            let output = bounded_command(
                pkcheck,
                &["--action-id", action, "--process", process.as_str()],
            )?;
            if output.status.code() != Some(1) {
                #[cfg(feature = "systemd-pressure-faults")]
                eprintln!(
                    "ota-authority-launcher: bounded pressure Polkit mismatch principal={_principal} action={action} status={:?}",
                    output.status.code()
                );
                return Err(ClosedProfileObservationError::Mismatch);
            }
            outcomes.push((pid, action));
        }
    }
    identity("systemd-policy", &outcomes)
}

fn verify_target_access(
    config: &SystemdLauncherServiceConfigV1,
    installation: &ProtectedInstallationManifestV1,
    mapping: &SystemdPrincipalMappingV1,
    closed: &SystemdJobPrincipalClosedProfileV1,
    ota_pid: u32,
) -> Result<String, ClosedProfileObservationError> {
    let mut protected = vec![
        PathBuf::from("/etc/ota"),
        PathBuf::from("/var/lib/ota"),
        PathBuf::from("/run/ota/authority-launcher"),
    ];
    protected.extend(installation.files.iter().map(|entry| entry.path.clone()));
    protected.sort();
    protected.dedup();
    let job = run_access_probe(
        "job",
        &RunAs {
            uid: mapping.job_peer.uid,
            gid: mapping.job_peer.gid,
        },
        &protected,
        &closed.host_control_sockets,
        &[],
        ota_pid,
    )?;
    let execution = run_access_probe(
        "execution",
        &mapping.execution,
        &protected,
        &closed.host_control_sockets,
        &[
            (config.socket_path.clone(), libc::SOCK_STREAM),
            (config.broker_proxy_socket.clone(), libc::SOCK_STREAM),
            (
                PathBuf::from(ota_authority_protocol::SYSTEMD_ATTESTOR_SOCKET_PATH_V1),
                libc::SOCK_SEQPACKET,
            ),
        ],
        ota_pid,
    )?;
    identity("target-access", &(job, execution))
}

#[derive(Debug, Serialize)]
struct AccessProbeResult {
    uid: u32,
    gid: u32,
    paths_checked: usize,
    sockets_checked: usize,
}

fn run_access_probe(
    _principal_label: &str,
    principal: &RunAs,
    protected_paths: &[PathBuf],
    host_sockets: &[PathBuf],
    denied_sockets: &[(PathBuf, i32)],
    ota_pid: u32,
) -> Result<AccessProbeResult, ClosedProfileObservationError> {
    let target_descriptor = observed_process_descriptor(ota_pid)?;
    let mut descriptors = [0_i32; 2];
    if unsafe { libc::pipe2(descriptors.as_mut_ptr(), libc::O_CLOEXEC) } != 0 {
        return Err(ClosedProfileObservationError::Unavailable);
    }
    let read_fd = unsafe { OwnedFd::from_raw_fd(descriptors[0]) };
    let write_fd = unsafe { OwnedFd::from_raw_fd(descriptors[1]) };
    let pid = unsafe { libc::fork() };
    if pid < 0 {
        return Err(ClosedProfileObservationError::Unavailable);
    }
    if pid == 0 {
        drop(read_fd);
        let mut failures = 0_u8;
        if !drop_to(principal) {
            failures |= 1;
        } else {
            if protected_paths
                .iter()
                .any(|path| unsafe { libc::access(path_cstring(path).as_ptr(), libc::W_OK) } == 0)
            {
                failures |= 1 << 1;
            }
            if host_sockets.iter().any(|path| {
                can_connect(path, libc::SOCK_STREAM) || can_connect(path, libc::SOCK_SEQPACKET)
            }) {
                failures |= 1 << 2;
            }
            if denied_sockets
                .iter()
                .any(|(path, socket_type)| can_connect(path, *socket_type))
            {
                failures |= 1 << 3;
            }
            let process_failures = process_access_failures(ota_pid, target_descriptor);
            if process_failures != 0 {
                #[cfg(feature = "systemd-pressure-faults")]
                eprintln!(
                    "ota-authority-launcher: bounded pressure process-access mismatch primitives={}",
                    process_access_failure_categories(process_failures).join(",")
                );
                failures |= 1 << 4;
            }
        }
        let _ = unsafe { libc::write(write_fd.as_raw_fd(), (&failures as *const u8).cast(), 1) };
        unsafe { libc::_exit(if failures == 0 { 0 } else { 1 }) }
    }
    drop(write_fd);
    let mut byte = [0_u8; 1];
    let mut reader = fs::File::from(read_fd);
    reader
        .read_exact(&mut byte)
        .map_err(|_| ClosedProfileObservationError::Unavailable)?;
    let mut status = 0;
    if unsafe { libc::waitpid(pid, &mut status, 0) } != pid
        || !libc::WIFEXITED(status)
        || libc::WEXITSTATUS(status) != 0
        || byte[0] != 0
    {
        #[cfg(feature = "systemd-pressure-faults")]
        eprintln!(
            "ota-authority-launcher: bounded pressure access mismatch principal={_principal_label} categories={}",
            access_failure_categories(byte[0]).join(",")
        );
        return Err(ClosedProfileObservationError::Mismatch);
    }
    Ok(AccessProbeResult {
        uid: principal.uid,
        gid: principal.gid,
        paths_checked: protected_paths.len(),
        sockets_checked: host_sockets.len() + denied_sockets.len(),
    })
}

fn verify_process_access(
    mapping: &SystemdPrincipalMappingV1,
    ota_pid: u32,
) -> Result<String, ClosedProfileObservationError> {
    let job = run_access_probe(
        "job_process",
        &RunAs {
            uid: mapping.job_peer.uid,
            gid: mapping.job_peer.gid,
        },
        &[],
        &[],
        &[],
        ota_pid,
    )?;
    let execution = run_access_probe(
        "execution_process",
        &mapping.execution,
        &[],
        &[],
        &[],
        ota_pid,
    )?;
    identity("process-access", &(job, execution))
}

#[cfg(feature = "systemd-pressure-faults")]
fn access_failure_categories(value: u8) -> Vec<&'static str> {
    [
        (1, "identity_transition"),
        (1 << 1, "protected_path_write"),
        (1 << 2, "host_control_socket"),
        (1 << 3, "protected_launcher_socket"),
        (1 << 4, "ota_process_access"),
    ]
    .into_iter()
    .filter_map(|(bit, name)| (value & bit != 0).then_some(name))
    .collect()
}

#[cfg(feature = "systemd-pressure-faults")]
fn process_access_failure_categories(value: u8) -> Vec<&'static str> {
    [
        (1, "proc_fd"),
        (1 << 1, "proc_mem"),
        (1 << 2, "ptrace"),
        (1 << 3, "process_vm_readv"),
        (1 << 4, "pidfd_getfd"),
    ]
    .into_iter()
    .filter_map(|(bit, name)| (value & bit != 0).then_some(name))
    .collect()
}

fn observed_process_descriptor(pid: u32) -> Result<i32, ClosedProfileObservationError> {
    let directory = fs::read_dir(format!("/proc/{pid}/fd"))
        .map_err(|_| ClosedProfileObservationError::Unavailable)?;
    let mut descriptors = directory
        .map(|entry| {
            entry
                .map_err(|_| ClosedProfileObservationError::Unavailable)?
                .file_name()
                .to_str()
                .and_then(|value| value.parse::<i32>().ok())
                .ok_or(ClosedProfileObservationError::Mismatch)
        })
        .collect::<Result<Vec<_>, _>>()?;
    descriptors.sort_unstable();
    descriptors
        .into_iter()
        .next()
        .ok_or(ClosedProfileObservationError::Unavailable)
}

fn process_access_failures(pid: u32, target_descriptor: i32) -> u8 {
    let mut failures = 0_u8;
    for (bit, _name, path) in [
        (1, "proc_fd", format!("/proc/{pid}/fd")),
        (1 << 1, "proc_mem", format!("/proc/{pid}/mem")),
    ] {
        let Ok(path) = CString::new(path) else {
            failures |= bit;
            continue;
        };
        let descriptor = unsafe { libc::open(path.as_ptr(), libc::O_RDONLY | libc::O_CLOEXEC) };
        if descriptor >= 0 {
            unsafe { libc::close(descriptor) };
            #[cfg(feature = "systemd-pressure-faults")]
            eprintln!(
                "ota-authority-launcher: bounded pressure process-access primitive={_name} outcome=opened"
            );
            failures |= bit;
        } else {
            let error = std::io::Error::last_os_error().raw_os_error();
            if !proc_access_denied_errno(error) {
                #[cfg(feature = "systemd-pressure-faults")]
                eprintln!(
                    "ota-authority-launcher: bounded pressure process-access primitive={_name} errno={:?}",
                    error
                );
                failures |= bit;
            }
        }
    }
    if unsafe { libc::ptrace(libc::PTRACE_ATTACH, pid, 0, 0) } == 0 {
        let mut status = 0;
        unsafe {
            libc::waitpid(pid as i32, &mut status, 0);
            libc::ptrace(libc::PTRACE_DETACH, pid, 0, 0);
        }
        failures |= 1 << 2;
    } else if !permission_errno() {
        failures |= 1 << 2;
    }
    let mut local = 0_u8;
    let local_iov = libc::iovec {
        iov_base: (&mut local as *mut u8).cast(),
        iov_len: 1,
    };
    let remote_iov = libc::iovec {
        iov_base: std::ptr::dangling_mut::<libc::c_void>(),
        iov_len: 1,
    };
    if unsafe { libc::process_vm_readv(pid as i32, &local_iov, 1, &remote_iov, 1, 0) } >= 0
        || !permission_errno()
    {
        failures |= 1 << 3;
    }
    let pidfd = unsafe { libc::syscall(libc::SYS_pidfd_open, pid, 0) as i32 };
    if pidfd < 0 {
        if !permission_errno() {
            failures |= 1 << 4;
        }
        return failures;
    }
    let duplicated =
        unsafe { libc::syscall(libc::SYS_pidfd_getfd, pidfd, target_descriptor, 0) as i32 };
    let getfd_error = std::io::Error::last_os_error().raw_os_error();
    unsafe { libc::close(pidfd) };
    if duplicated >= 0 {
        unsafe { libc::close(duplicated) };
        failures |= 1 << 4;
    } else if !permission_errno_value(getfd_error) {
        failures |= 1 << 4;
    }
    failures
}

fn verify_child_descriptors(
    config: &SystemdLauncherServiceConfigV1,
    installation: &ProtectedInstallationManifestV1,
    pid: u32,
) -> Result<String, ClosedProfileObservationError> {
    let forbidden_paths = installation
        .files
        .iter()
        .map(|entry| entry.path.to_string_lossy().into_owned())
        .chain([
            config.broker_proxy_socket.to_string_lossy().into_owned(),
            ota_authority_protocol::SYSTEMD_ATTESTOR_SOCKET_PATH_V1.to_owned(),
        ])
        .collect::<BTreeSet<_>>();
    let forbidden_socket_inodes = forbidden_paths
        .iter()
        .filter_map(|path| fs::symlink_metadata(path).ok())
        .filter(|metadata| metadata.file_type().is_socket())
        .map(|metadata| metadata.ino())
        .collect::<BTreeSet<_>>();
    let mut observed = Vec::new();
    for entry in fs::read_dir(format!("/proc/{pid}/fd"))
        .map_err(|_| ClosedProfileObservationError::Unavailable)?
    {
        let entry = entry.map_err(|_| ClosedProfileObservationError::Unavailable)?;
        let target =
            fs::read_link(entry.path()).map_err(|_| ClosedProfileObservationError::Unavailable)?;
        let rendered = target.to_string_lossy().into_owned();
        if forbidden_paths.contains(&rendered) {
            return Err(ClosedProfileObservationError::Mismatch);
        }
        if let Some(inode) = rendered
            .strip_prefix("socket:[")
            .and_then(|value| value.strip_suffix(']'))
            .and_then(|value| value.parse::<u64>().ok())
            && forbidden_socket_inodes.contains(&inode)
        {
            return Err(ClosedProfileObservationError::Mismatch);
        }
        observed.push(rendered);
    }
    observed.sort();
    identity("child-descriptors", &observed)
}

#[derive(Debug, Serialize)]
struct ProtectedSocketPosture {
    path: String,
    device: u64,
    inode: u64,
    uid: u32,
    gid: u32,
    mode: u32,
}

fn verify_protected_socket_posture(
    config: &SystemdLauncherServiceConfigV1,
    closed: &SystemdJobPrincipalClosedProfileV1,
) -> Result<String, ClosedProfileObservationError> {
    let mut sockets = vec![
        protected_socket_posture(
            config.socket_path.as_path(),
            0,
            config.socket_group_gid,
            0o660,
        )?,
        protected_socket_posture(config.broker_proxy_socket.as_path(), 0, 0, 0o600)?,
        protected_socket_posture(
            Path::new(ota_authority_protocol::SYSTEMD_ATTESTOR_SOCKET_PATH_V1),
            0,
            0,
            0o600,
        )?,
    ];
    for host in &closed.host_control_sockets {
        if host
            .try_exists()
            .map_err(|_| ClosedProfileObservationError::Unavailable)?
        {
            let metadata = fs::symlink_metadata(host)
                .map_err(|_| ClosedProfileObservationError::Unavailable)?;
            if !metadata.file_type().is_socket() {
                return Err(ClosedProfileObservationError::Mismatch);
            }
            sockets.push(ProtectedSocketPosture {
                path: host.to_string_lossy().into_owned(),
                device: metadata.dev(),
                inode: metadata.ino(),
                uid: metadata.uid(),
                gid: metadata.gid(),
                mode: metadata.mode() & 0o7777,
            });
        }
    }
    identity("protected-sockets", &sockets)
}

fn protected_socket_posture(
    path: &Path,
    expected_uid: u32,
    expected_gid: u32,
    expected_mode: u32,
) -> Result<ProtectedSocketPosture, ClosedProfileObservationError> {
    let metadata =
        fs::symlink_metadata(path).map_err(|_| ClosedProfileObservationError::Unavailable)?;
    if !metadata.file_type().is_socket()
        || metadata.uid() != expected_uid
        || metadata.gid() != expected_gid
        || metadata.mode() & 0o7777 != expected_mode
    {
        return Err(ClosedProfileObservationError::Mismatch);
    }
    Ok(ProtectedSocketPosture {
        path: path.to_string_lossy().into_owned(),
        device: metadata.dev(),
        inode: metadata.ino(),
        uid: metadata.uid(),
        gid: metadata.gid(),
        mode: metadata.mode() & 0o7777,
    })
}

fn process_real_uid(pid: u32) -> Result<u32, ClosedProfileObservationError> {
    let status = fs::read_to_string(format!("/proc/{pid}/status"))
        .map_err(|_| ClosedProfileObservationError::Unavailable)?;
    let line = status
        .lines()
        .find(|line| line.starts_with("Uid:"))
        .ok_or(ClosedProfileObservationError::Mismatch)?;
    line.split_whitespace()
        .nth(1)
        .ok_or(ClosedProfileObservationError::Mismatch)?
        .parse()
        .map_err(|_| ClosedProfileObservationError::Mismatch)
}

fn process_cgroup(pid: u32) -> Result<String, ClosedProfileObservationError> {
    let content = fs::read_to_string(format!("/proc/{pid}/cgroup"))
        .map_err(|_| ClosedProfileObservationError::Unavailable)?;
    let mut unified = content.lines().filter_map(|line| line.strip_prefix("0::"));
    let value = unified
        .next()
        .ok_or(ClosedProfileObservationError::Mismatch)?;
    if unified.next().is_some() || !value.starts_with('/') {
        return Err(ClosedProfileObservationError::Mismatch);
    }
    Ok(value.to_owned())
}

fn process_start_ticks(pid: u32) -> Result<u64, ClosedProfileObservationError> {
    let stat = fs::read_to_string(format!("/proc/{pid}/stat"))
        .map_err(|_| ClosedProfileObservationError::Unavailable)?;
    let (_, suffix) = stat
        .rsplit_once(") ")
        .ok_or(ClosedProfileObservationError::Mismatch)?;
    suffix
        .split_whitespace()
        .nth(19)
        .ok_or(ClosedProfileObservationError::Mismatch)?
        .parse()
        .map_err(|_| ClosedProfileObservationError::Mismatch)
}

fn bounded_command(
    executable: &Path,
    arguments: &[&str],
) -> Result<std::process::Output, ClosedProfileObservationError> {
    let output = Command::new(executable)
        .args(arguments)
        .env_clear()
        .env("LC_ALL", "C")
        .stdin(Stdio::null())
        .output()
        .map_err(|_| ClosedProfileObservationError::Unavailable)?;
    if output.stdout.len() + output.stderr.len() > MAX_POLICY_OUTPUT {
        return Err(ClosedProfileObservationError::Mismatch);
    }
    Ok(output)
}

fn drop_to(principal: &RunAs) -> bool {
    let transitioned = unsafe {
        libc::syscall(
            libc::SYS_setgroups,
            0_usize,
            std::ptr::null::<libc::gid_t>(),
        ) == 0
            && libc::syscall(
                libc::SYS_setresgid,
                principal.gid,
                principal.gid,
                principal.gid,
            ) == 0
            && libc::syscall(
                libc::SYS_setresuid,
                principal.uid,
                principal.uid,
                principal.uid,
            ) == 0
    };
    transitioned
        && clear_process_capabilities()
        && unsafe { libc::prctl(libc::PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) == 0 }
        && dropped_process_status_matches(principal)
}

#[repr(C)]
struct CapabilityHeader {
    version: u32,
    pid: i32,
}

#[derive(Clone, Copy)]
#[repr(C)]
struct CapabilityData {
    effective: u32,
    permitted: u32,
    inheritable: u32,
}

fn clear_process_capabilities() -> bool {
    const LINUX_CAPABILITY_VERSION_3: u32 = 0x2008_0522;
    let header = CapabilityHeader {
        version: LINUX_CAPABILITY_VERSION_3,
        pid: 0,
    };
    let data = [CapabilityData {
        effective: 0,
        permitted: 0,
        inheritable: 0,
    }; 2];
    unsafe {
        libc::syscall(libc::SYS_capset, &header, data.as_ptr()) == 0
            && libc::prctl(
                libc::PR_CAP_AMBIENT,
                libc::PR_CAP_AMBIENT_CLEAR_ALL,
                0,
                0,
                0,
            ) == 0
    }
}

fn dropped_process_status_matches(principal: &RunAs) -> bool {
    let Ok(status) = fs::read_to_string("/proc/self/status") else {
        return false;
    };
    let field = |name: &str| {
        status
            .lines()
            .find_map(|line| line.strip_prefix(name).map(str::trim))
    };
    let ids_match = |name: &str, expected: u32| {
        field(name).is_some_and(|value| {
            let observed = value
                .split_whitespace()
                .map(str::parse::<u32>)
                .collect::<Result<Vec<_>, _>>();
            observed
                .is_ok_and(|values| values.len() == 4 && values.iter().all(|id| *id == expected))
        })
    };
    ids_match("Uid:", principal.uid)
        && ids_match("Gid:", principal.gid)
        && field("Groups:").is_some_and(str::is_empty)
        && ["CapInh:", "CapPrm:", "CapEff:", "CapAmb:"]
            .iter()
            .all(|name| {
                field(name).is_some_and(|value| {
                    u64::from_str_radix(value, 16).is_ok_and(|capabilities| capabilities == 0)
                })
            })
        && field("NoNewPrivs:") == Some("1")
}

fn can_connect(path: &Path, socket_type: i32) -> bool {
    let descriptor = unsafe { libc::socket(libc::AF_UNIX, socket_type | libc::SOCK_CLOEXEC, 0) };
    if descriptor < 0 {
        return true;
    }
    let bytes = path.as_os_str().as_bytes();
    if bytes.is_empty() || bytes.len() >= 108 {
        unsafe { libc::close(descriptor) };
        return true;
    }
    let mut address: libc::sockaddr_un = unsafe { std::mem::zeroed() };
    address.sun_family = libc::AF_UNIX as libc::sa_family_t;
    for (index, byte) in bytes.iter().enumerate() {
        address.sun_path[index] = *byte as libc::c_char;
    }
    let length = (std::mem::size_of::<libc::sa_family_t>() + bytes.len() + 1) as libc::socklen_t;
    let connected = unsafe {
        libc::connect(
            descriptor,
            (&address as *const libc::sockaddr_un).cast(),
            length,
        ) == 0
    };
    unsafe { libc::close(descriptor) };
    connected
}

fn permission_errno() -> bool {
    permission_errno_value(std::io::Error::last_os_error().raw_os_error())
}

fn permission_errno_value(value: Option<i32>) -> bool {
    matches!(value, Some(libc::EPERM) | Some(libc::EACCES))
}

fn proc_access_denied_errno(value: Option<i32>) -> bool {
    permission_errno_value(value) || value == Some(libc::ENOENT)
}

fn path_cstring(path: &Path) -> CString {
    CString::new(path.as_os_str().as_bytes()).expect("validated absolute path")
}

fn c_string(pointer: *const libc::c_char) -> Result<String, ClosedProfileObservationError> {
    if pointer.is_null() {
        return Err(ClosedProfileObservationError::Mismatch);
    }
    unsafe { CStr::from_ptr(pointer) }
        .to_str()
        .map(str::to_owned)
        .map_err(|_| ClosedProfileObservationError::Mismatch)
}

fn token_paths(value: &str) -> Result<BTreeSet<String>, ClosedProfileObservationError> {
    Ok(value.split_whitespace().map(str::to_owned).collect())
}

fn identity<T: Serialize>(
    label: &'static str,
    value: &T,
) -> Result<String, ClosedProfileObservationError> {
    #[derive(Serialize)]
    struct Evidence<'a, T> {
        label: &'a str,
        value: &'a T,
    }
    message_identity(EVIDENCE_DOMAIN_V1.as_bytes(), &Evidence { label, value })
        .map_err(|_| ClosedProfileObservationError::Mismatch)
}

fn launcher_key(source: SystemdLauncherEvidenceSource) -> &'static str {
    match source {
        SystemdLauncherEvidenceSource::ProtectedFileIdentity => "protected_file_identity",
        SystemdLauncherEvidenceSource::SystemdManagerProperty => "systemd_manager_property",
        SystemdLauncherEvidenceSource::SocketPeerCredentials => "socket_peer_credentials",
        SystemdLauncherEvidenceSource::ProcProcessStatus => "proc_process_status",
        SystemdLauncherEvidenceSource::ProcDescriptorInspection => "proc_descriptor_inspection",
        SystemdLauncherEvidenceSource::ProcUnixSocketInspection => "proc_unix_socket_inspection",
        SystemdLauncherEvidenceSource::ProtectedSocketIdentity => "protected_socket_identity",
        SystemdLauncherEvidenceSource::TargetPrincipalAccessProbe => {
            "target_principal_access_probe"
        }
        SystemdLauncherEvidenceSource::OtaProcessPosture => "ota_process_posture",
    }
}

fn job_key(requirement: SystemdJobPrincipalRequirement) -> &'static str {
    match requirement {
        SystemdJobPrincipalRequirement::DistinctOneToOnePrincipals => {
            "distinct_one_to_one_principals"
        }
        SystemdJobPrincipalRequirement::PeerIdentityMatchesProtectedMapping => {
            "peer_identity_matches_protected_mapping"
        }
        SystemdJobPrincipalRequirement::PeerNoNewPrivileges => "peer_no_new_privileges",
        SystemdJobPrincipalRequirement::PeerCapabilitiesEmpty => "peer_capabilities_empty",
        SystemdJobPrincipalRequirement::PeerSupplementaryGroupsEmpty => {
            "peer_supplementary_groups_empty"
        }
        SystemdJobPrincipalRequirement::PeerSupplementaryGroupsLimitedToPrimary => {
            "peer_supplementary_groups_limited_to_primary"
        }
        SystemdJobPrincipalRequirement::RunnerServiceIdentityBound => {
            "runner_service_identity_bound"
        }
        SystemdJobPrincipalRequirement::AllPrincipalProcessesContained => {
            "all_principal_processes_contained"
        }
        SystemdJobPrincipalRequirement::AccountsLocked => "accounts_locked",
        SystemdJobPrincipalRequirement::NonLoginShells => "non_login_shells",
        SystemdJobPrincipalRequirement::SudoPolicyDenied => "sudo_policy_denied",
        SystemdJobPrincipalRequirement::SystemdPolicyDenied => "systemd_policy_denied",
        SystemdJobPrincipalRequirement::PolkitPolicyDenied => "polkit_policy_denied",
        SystemdJobPrincipalRequirement::ProtectedPathsWriteDenied => "protected_paths_write_denied",
        SystemdJobPrincipalRequirement::HostControlSocketsDenied => "host_control_sockets_denied",
        SystemdJobPrincipalRequirement::ExecutionLauncherSocketDenied => {
            "execution_launcher_socket_denied"
        }
        SystemdJobPrincipalRequirement::OtaProcessNonDumpable => "ota_process_non_dumpable",
        SystemdJobPrincipalRequirement::OtaPtracerCleared => "ota_ptracer_cleared",
        SystemdJobPrincipalRequirement::OtaProcessInspectionDenied => {
            "ota_process_inspection_denied"
        }
    }
}

#[cfg(test)]
mod tests {
    use std::os::unix::fs::PermissionsExt;
    use std::os::unix::process::ExitStatusExt;

    use tempfile::tempdir;

    use super::*;

    #[test]
    fn process_stat_parser_uses_the_kernel_start_time_field_after_comm() {
        let stat =
            "42 (name with ) paren) S 1 2 3 4 5 6 7 8 9 10 11 12 13 14 15 16 17 18 424242 20";
        let (_, suffix) = stat.rsplit_once(") ").expect("stat suffix");
        assert_eq!(suffix.split_whitespace().nth(19), Some("424242"));
    }

    #[test]
    fn process_access_probe_selects_an_observed_target_descriptor() {
        let descriptor =
            observed_process_descriptor(std::process::id()).expect("current process descriptor");
        assert!(descriptor >= 0);
        assert!(Path::new(format!("/proc/self/fd/{descriptor}").as_str()).exists());
    }

    #[test]
    fn evidence_identity_is_domain_and_label_bound() {
        assert_ne!(identity("one", &42).unwrap(), identity("two", &42).unwrap());
    }

    #[test]
    fn permission_refusal_accepts_only_access_denial_errors() {
        assert!(permission_errno_value(Some(libc::EPERM)));
        assert!(permission_errno_value(Some(libc::EACCES)));
        assert!(!permission_errno_value(Some(libc::ENOENT)));
        assert!(!permission_errno_value(None));
        assert!(proc_access_denied_errno(Some(libc::ENOENT)));
        assert!(!proc_access_denied_errno(Some(libc::ESRCH)));
    }

    #[test]
    fn runner_service_accepts_active_or_activating_only() {
        assert!(runner_service_state_is_executing(Some("active")));
        assert!(runner_service_state_is_executing(Some("activating")));
        assert!(!runner_service_state_is_executing(Some("deactivating")));
        assert!(!runner_service_state_is_executing(Some("failed")));
        assert!(!runner_service_state_is_executing(None));
    }

    #[test]
    fn sudo_listing_requires_one_canonical_denial_line() {
        let denied = std::process::Output {
            status: std::process::ExitStatus::from_raw(0),
            stdout: b"User ota-job is not allowed to run sudo on runner.\n".to_vec(),
            stderr: Vec::new(),
        };
        assert!(sudo_listing_denies_user(&denied, "ota-job"));

        let mut additional_entry = denied.clone();
        additional_entry
            .stdout
            .extend_from_slice(b"(ALL) NOPASSWD: ALL\n");
        assert!(!sudo_listing_denies_user(&additional_entry, "ota-job"));

        let mut wrong_user = denied;
        wrong_user.stdout = b"User other is not allowed to run sudo on runner.\n".to_vec();
        assert!(!sudo_listing_denies_user(&wrong_user, "ota-job"));
    }

    #[test]
    fn protected_socket_posture_binds_type_owner_group_mode_and_inode() {
        let temporary = tempdir().expect("temporary socket directory");
        let path = temporary.path().join("protected.sock");
        let listener = std::os::unix::net::UnixListener::bind(&path).expect("protected socket");
        fs::set_permissions(&path, fs::Permissions::from_mode(0o600)).expect("socket permissions");
        let posture = protected_socket_posture(
            &path,
            unsafe { libc::geteuid() },
            unsafe { libc::getegid() },
            0o600,
        )
        .expect("matching protected socket");
        assert_eq!(posture.inode, fs::symlink_metadata(&path).unwrap().ino());

        fs::remove_file(&path).expect("remove original socket");
        fs::write(&path, b"not a socket").expect("replacement file");
        fs::set_permissions(&path, fs::Permissions::from_mode(0o600)).expect("file permissions");
        assert!(matches!(
            protected_socket_posture(
                &path,
                unsafe { libc::geteuid() },
                unsafe { libc::getegid() },
                0o600,
            ),
            Err(ClosedProfileObservationError::Mismatch)
        ));
        drop(listener);
    }
}
