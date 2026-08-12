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

//! Root-manager ownership for one stopped Ota child.

use std::fs;
use std::os::unix::fs::{FileTypeExt, MetadataExt, PermissionsExt};
use std::path::{Path, PathBuf};
use std::thread;
use std::time::{Duration, Instant};

use ota_authority_protocol::{
    LauncherChildProcessV1, LauncherSystemdScopeV1, launcher_systemd_scope_identity,
};
use thiserror::Error;
use zbus::blocking::{Connection, Proxy, connection::Builder};
use zbus::zvariant::{OwnedObjectPath, Value};

use crate::prepared_child::recorded_child_is_live_exact;

pub(crate) const INVOCATION_SLICE: &str = "ota-authority-invocations.slice";
const SYSTEMD_SERVICE: &str = "org.freedesktop.systemd1";
const SYSTEM_BUS_ADDRESS: &str = "unix:path=/run/dbus/system_bus_socket";
const SYSTEM_BUS_SOCKET: &str = "/run/dbus/system_bus_socket";
const DBUS_SERVICE: &str = "org.freedesktop.DBus";
const DBUS_PATH: &str = "/org/freedesktop/DBus";
const DBUS_INTERFACE: &str = "org.freedesktop.DBus";
const SYSTEMD_MANAGER_PATH: &str = "/org/freedesktop/systemd1";
const SYSTEMD_MANAGER_INTERFACE: &str = "org.freedesktop.systemd1.Manager";
const SYSTEMD_UNIT_INTERFACE: &str = "org.freedesktop.systemd1.Unit";
const SYSTEMD_SCOPE_INTERFACE: &str = "org.freedesktop.systemd1.Scope";
const POLL_INTERVAL: Duration = Duration::from_millis(20);

#[derive(Debug, Error, PartialEq, Eq)]
pub(crate) enum SystemdScopeError {
    #[error("the root systemd manager is unavailable")]
    ManagerUnavailable,
    #[error("the transient systemd scope could not be created")]
    CreationFailed,
    #[error("the transient systemd scope does not match the stopped child")]
    ScopeMismatch,
    #[error("the transient systemd scope is absent")]
    ScopeAbsent,
    #[error("the transient systemd scope could not be confirmed empty")]
    CleanupFailed,
}

pub(crate) struct SystemdScopeManager {
    connection: Connection,
}

pub(crate) trait ScopeBoundary {
    fn attach_stopped_child(
        &self,
        invocation_id: &str,
        request_identity: &str,
        child: &LauncherChildProcessV1,
        timeout: Duration,
    ) -> Result<LauncherSystemdScopeV1, SystemdScopeError>;

    fn stop_and_confirm_empty(
        &self,
        expected: &LauncherSystemdScopeV1,
        child: &LauncherChildProcessV1,
        timeout: Duration,
    ) -> Result<(), SystemdScopeError>;

    fn recover_unrecorded_scope(
        &self,
        invocation_id: &str,
        request_identity: &str,
        child: &LauncherChildProcessV1,
        timeout: Duration,
    ) -> Result<(), SystemdScopeError>;
}

impl SystemdScopeManager {
    pub(crate) fn connect() -> Result<Self, SystemdScopeError> {
        verify_system_bus_socket()?;
        let connection = Builder::address(SYSTEM_BUS_ADDRESS)
            .and_then(Builder::build)
            .map_err(|_| SystemdScopeError::ManagerUnavailable)?;
        let bus = Proxy::new(&connection, DBUS_SERVICE, DBUS_PATH, DBUS_INTERFACE)
            .map_err(|_| SystemdScopeError::ManagerUnavailable)?;
        let manager_pid: u32 = bus
            .call("GetConnectionUnixProcessID", &(SYSTEMD_SERVICE,))
            .map_err(|_| SystemdScopeError::ManagerUnavailable)?;
        if manager_pid != 1 {
            return Err(SystemdScopeError::ManagerUnavailable);
        }
        Ok(Self { connection })
    }

    fn attach_stopped_child_inner(
        &self,
        invocation_id: &str,
        request_identity: &str,
        child: &LauncherChildProcessV1,
        timeout: Duration,
    ) -> Result<LauncherSystemdScopeV1, SystemdScopeError> {
        let unit_name = scope_unit_name(request_identity)?;
        let manager = self.manager_proxy()?;
        let properties = vec![
            (
                "Description",
                Value::from("Ota governed authority invocation"),
            ),
            ("PIDs", Value::from(vec![child.pid])),
            ("Slice", Value::from(INVOCATION_SLICE)),
            ("Delegate", Value::from(false)),
            ("KillMode", Value::from("control-group")),
            ("CollectMode", Value::from("inactive-or-failed")),
        ];
        let auxiliary: Vec<(&str, Vec<(&str, Value<'_>)>)> = Vec::new();
        let started: Result<OwnedObjectPath, zbus::Error> = manager.call(
            "StartTransientUnit",
            &(unit_name.as_str(), "fail", properties, auxiliary),
        );
        if let Err(error) = started {
            #[cfg(test)]
            eprintln!("StartTransientUnit failed: {error:?}");
            if !start_error_requires_reconciliation(&error) {
                return Err(SystemdScopeError::CreationFailed);
            }
            return match self.recover_unrecorded_scope(
                invocation_id,
                request_identity,
                child,
                timeout,
            ) {
                Ok(()) => Err(SystemdScopeError::CreationFailed),
                Err(_) => Err(SystemdScopeError::CleanupFailed),
            };
        }
        let observed = self.observe_scope(
            invocation_id,
            request_identity,
            child,
            unit_name.as_str(),
            timeout,
        );
        if observed.is_err() {
            return match self.recover_unrecorded_scope(
                invocation_id,
                request_identity,
                child,
                timeout,
            ) {
                Ok(()) => Err(SystemdScopeError::ScopeMismatch),
                Err(_) => Err(SystemdScopeError::CleanupFailed),
            };
        }
        observed
    }

    pub(crate) fn verify_scope(
        &self,
        expected: &LauncherSystemdScopeV1,
        child: &LauncherChildProcessV1,
    ) -> Result<(), SystemdScopeError> {
        verify_recorded_scope_binding(expected, child)?;
        let observed = self.observe_existing_scope(expected.unit_name.as_str())?;
        if !recorded_child_is_live_exact(child).map_err(|_| SystemdScopeError::ScopeMismatch)? {
            return Err(SystemdScopeError::ScopeMismatch);
        }
        if !observed_scope_matches(expected, &observed)
            || !cgroup_contains_exact_pid(observed.control_group.as_str(), expected.child_pid)
        {
            return Err(SystemdScopeError::ScopeMismatch);
        }
        Ok(())
    }

    pub(crate) fn recover_unrecorded_scope(
        &self,
        invocation_id: &str,
        request_identity: &str,
        child: &LauncherChildProcessV1,
        timeout: Duration,
    ) -> Result<(), SystemdScopeError> {
        let unit_name = scope_unit_name(request_identity)?;
        let observed = match self.observe_existing_scope(unit_name.as_str()) {
            Ok(observed) => observed,
            Err(SystemdScopeError::ScopeAbsent) => return Ok(()),
            Err(error) => return Err(error),
        };
        if !cgroup_contains_exact_pid(observed.control_group.as_str(), child.pid) {
            return Err(SystemdScopeError::ScopeMismatch);
        }
        let mut scope = LauncherSystemdScopeV1 {
            schema_version: 1,
            identity: String::new(),
            invocation_id: invocation_id.into(),
            request_identity: request_identity.into(),
            child_identity: child.identity.clone(),
            child_pid: child.pid,
            unit_name,
            unit_object_path: observed.unit_object_path,
            slice: observed.slice,
            control_group: observed.control_group,
            delegate: observed.delegate,
            kill_mode: observed.kill_mode,
            collect_mode: observed.collect_mode,
        };
        scope.identity = launcher_systemd_scope_identity(&scope)
            .map_err(|_| SystemdScopeError::ScopeMismatch)?;
        self.stop_and_confirm_empty_inner(&scope, child, timeout)
    }

    fn stop_and_confirm_empty_inner(
        &self,
        expected: &LauncherSystemdScopeV1,
        child: &LauncherChildProcessV1,
        timeout: Duration,
    ) -> Result<(), SystemdScopeError> {
        verify_recorded_scope_binding(expected, child)?;
        if self.scope_is_terminal(expected.unit_name.as_str(), expected.control_group.as_str()) {
            return Ok(());
        }
        let child_is_live =
            recorded_child_is_live_exact(child).map_err(|_| SystemdScopeError::ScopeMismatch)?;
        if child_is_live {
            self.verify_scope(expected, child)?;
        } else {
            let observed = match cleanup_observation(
                expected,
                self.observe_existing_scope(expected.unit_name.as_str()),
            )? {
                Some(observed) => observed,
                None => return Ok(()),
            };
            if !observed_scope_matches(expected, &observed)
                || !cgroup_is_empty_or_absent(observed.control_group.as_str())
            {
                return Err(SystemdScopeError::ScopeMismatch);
            }
        }
        self.stop_unit_by_name(
            expected.unit_name.as_str(),
            expected.control_group.as_str(),
            timeout,
        )
    }

    fn stop_unit_by_name(
        &self,
        unit_name: &str,
        expected_control_group: &str,
        timeout: Duration,
    ) -> Result<(), SystemdScopeError> {
        let manager = self.manager_proxy()?;
        let killed: Result<(), zbus::Error> =
            manager.call("KillUnit", &(unit_name, "all", libc::SIGKILL));
        if killed.is_err() {
            return if self.scope_is_terminal(unit_name, expected_control_group) {
                Ok(())
            } else {
                Err(SystemdScopeError::CleanupFailed)
            };
        }
        let stopped: Result<OwnedObjectPath, zbus::Error> =
            manager.call("StopUnit", &(unit_name, "replace"));
        if stopped.is_err() && self.scope_is_terminal(unit_name, expected_control_group) {
            return Ok(());
        }
        stopped.map_err(|_| SystemdScopeError::CleanupFailed)?;
        let deadline = Instant::now() + timeout;
        loop {
            match self.observe_existing_scope(unit_name) {
                Ok(_) => {}
                Err(SystemdScopeError::ScopeAbsent)
                    if cgroup_is_empty_or_absent(expected_control_group) =>
                {
                    return Ok(());
                }
                Err(_) => {}
            }
            if Instant::now() >= deadline {
                return Err(SystemdScopeError::CleanupFailed);
            }
            thread::sleep(POLL_INTERVAL);
        }
    }

    fn scope_is_terminal(&self, unit_name: &str, expected_control_group: &str) -> bool {
        matches!(
            self.observe_existing_scope(unit_name),
            Err(SystemdScopeError::ScopeAbsent)
        ) && cgroup_is_empty_or_absent(expected_control_group)
    }

    fn observe_scope(
        &self,
        invocation_id: &str,
        request_identity: &str,
        child: &LauncherChildProcessV1,
        unit_name: &str,
        timeout: Duration,
    ) -> Result<LauncherSystemdScopeV1, SystemdScopeError> {
        let deadline = Instant::now() + timeout;
        loop {
            if let Ok(observed) = self.observe_existing_scope(unit_name)
                && cgroup_contains_exact_pid(observed.control_group.as_str(), child.pid)
            {
                let mut scope = LauncherSystemdScopeV1 {
                    schema_version: 1,
                    identity: String::new(),
                    invocation_id: invocation_id.into(),
                    request_identity: request_identity.into(),
                    child_identity: child.identity.clone(),
                    child_pid: child.pid,
                    unit_name: unit_name.into(),
                    unit_object_path: observed.unit_object_path,
                    slice: observed.slice,
                    control_group: observed.control_group,
                    delegate: observed.delegate,
                    kill_mode: observed.kill_mode,
                    collect_mode: observed.collect_mode,
                };
                scope.identity = launcher_systemd_scope_identity(&scope)
                    .map_err(|_| SystemdScopeError::ScopeMismatch)?;
                return Ok(scope);
            }
            if Instant::now() >= deadline {
                return Err(SystemdScopeError::ScopeMismatch);
            }
            thread::sleep(POLL_INTERVAL);
        }
    }

    fn observe_existing_scope(&self, unit_name: &str) -> Result<ObservedScope, SystemdScopeError> {
        let manager = self.manager_proxy()?;
        let path: OwnedObjectPath =
            manager
                .call("GetUnit", &(unit_name,))
                .map_err(|error| match error {
                    zbus::Error::MethodError(name, _, _)
                        if name.as_str() == "org.freedesktop.systemd1.NoSuchUnit" =>
                    {
                        SystemdScopeError::ScopeAbsent
                    }
                    _ => SystemdScopeError::ManagerUnavailable,
                })?;
        let unit = Proxy::new(
            &self.connection,
            SYSTEMD_SERVICE,
            path.as_str(),
            SYSTEMD_UNIT_INTERFACE,
        )
        .map_err(|_| SystemdScopeError::ManagerUnavailable)?;
        let scope = Proxy::new(
            &self.connection,
            SYSTEMD_SERVICE,
            path.as_str(),
            SYSTEMD_SCOPE_INTERFACE,
        )
        .map_err(|_| SystemdScopeError::ManagerUnavailable)?;
        let id: String = unit
            .get_property("Id")
            .map_err(|_| SystemdScopeError::ScopeMismatch)?;
        if id != unit_name {
            return Err(SystemdScopeError::ScopeMismatch);
        }
        let active_state: String = unit
            .get_property("ActiveState")
            .map_err(|_| SystemdScopeError::ScopeMismatch)?;
        if active_state != "active" {
            return Err(SystemdScopeError::ScopeMismatch);
        }
        let observed = ObservedScope {
            unit_object_path: path.to_string(),
            slice: scope
                .get_property("Slice")
                .map_err(|_| SystemdScopeError::ScopeMismatch)?,
            control_group: scope
                .get_property("ControlGroup")
                .map_err(|_| SystemdScopeError::ScopeMismatch)?,
            delegate: scope
                .get_property("Delegate")
                .map_err(|_| SystemdScopeError::ScopeMismatch)?,
            kill_mode: scope
                .get_property("KillMode")
                .map_err(|_| SystemdScopeError::ScopeMismatch)?,
            collect_mode: unit
                .get_property("CollectMode")
                .map_err(|_| SystemdScopeError::ScopeMismatch)?,
        };
        #[cfg(test)]
        eprintln!(
            "observed scope {} slice={} cgroup={} delegate={} kill={} collect={}",
            unit_name,
            observed.slice,
            observed.control_group,
            observed.delegate,
            observed.kill_mode,
            observed.collect_mode
        );
        Ok(observed)
    }

    fn manager_proxy(&self) -> Result<Proxy<'_>, SystemdScopeError> {
        Proxy::new(
            &self.connection,
            SYSTEMD_SERVICE,
            SYSTEMD_MANAGER_PATH,
            SYSTEMD_MANAGER_INTERFACE,
        )
        .map_err(|_| SystemdScopeError::ManagerUnavailable)
    }
}

impl ScopeBoundary for SystemdScopeManager {
    fn attach_stopped_child(
        &self,
        invocation_id: &str,
        request_identity: &str,
        child: &LauncherChildProcessV1,
        timeout: Duration,
    ) -> Result<LauncherSystemdScopeV1, SystemdScopeError> {
        self.attach_stopped_child_inner(invocation_id, request_identity, child, timeout)
    }

    fn stop_and_confirm_empty(
        &self,
        expected: &LauncherSystemdScopeV1,
        child: &LauncherChildProcessV1,
        timeout: Duration,
    ) -> Result<(), SystemdScopeError> {
        self.stop_and_confirm_empty_inner(expected, child, timeout)
    }

    fn recover_unrecorded_scope(
        &self,
        invocation_id: &str,
        request_identity: &str,
        child: &LauncherChildProcessV1,
        timeout: Duration,
    ) -> Result<(), SystemdScopeError> {
        SystemdScopeManager::recover_unrecorded_scope(
            self,
            invocation_id,
            request_identity,
            child,
            timeout,
        )
    }
}

struct ObservedScope {
    unit_object_path: String,
    slice: String,
    control_group: String,
    delegate: bool,
    kill_mode: String,
    collect_mode: String,
}

fn cleanup_observation(
    expected: &LauncherSystemdScopeV1,
    observed: Result<ObservedScope, SystemdScopeError>,
) -> Result<Option<ObservedScope>, SystemdScopeError> {
    match observed {
        Ok(observed) => Ok(Some(observed)),
        Err(SystemdScopeError::ScopeAbsent)
            if cgroup_is_empty_or_absent(expected.control_group.as_str()) =>
        {
            Ok(None)
        }
        Err(error) => Err(error),
    }
}

fn verify_recorded_scope_binding(
    expected: &LauncherSystemdScopeV1,
    child: &LauncherChildProcessV1,
) -> Result<(), SystemdScopeError> {
    if launcher_systemd_scope_identity(expected).ok().as_deref() != Some(expected.identity.as_str())
        || child.identity != expected.child_identity
        || child.pid != expected.child_pid
    {
        return Err(SystemdScopeError::ScopeMismatch);
    }
    Ok(())
}

fn observed_scope_matches(expected: &LauncherSystemdScopeV1, observed: &ObservedScope) -> bool {
    observed.unit_object_path == expected.unit_object_path
        && observed.slice == expected.slice
        && observed.control_group == expected.control_group
        && observed.delegate == expected.delegate
        && observed.kill_mode == expected.kill_mode
        && observed.collect_mode == expected.collect_mode
}

fn scope_unit_name(request_identity: &str) -> Result<String, SystemdScopeError> {
    let digest = request_identity
        .strip_prefix("sha256:")
        .filter(|digest| {
            digest.len() == 64
                && digest
                    .bytes()
                    .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
        })
        .ok_or(SystemdScopeError::ScopeMismatch)?;
    Ok(format!("ota-authority-invocation-{digest}.scope"))
}

fn start_error_requires_reconciliation(error: &zbus::Error) -> bool {
    !matches!(error, zbus::Error::MethodError(_, _, _))
}

fn verify_system_bus_socket() -> Result<(), SystemdScopeError> {
    let socket = fs::symlink_metadata(SYSTEM_BUS_SOCKET)
        .map_err(|_| SystemdScopeError::ManagerUnavailable)?;
    let parent =
        fs::symlink_metadata("/run/dbus").map_err(|_| SystemdScopeError::ManagerUnavailable)?;
    if !socket.file_type().is_socket()
        || socket.uid() != 0
        || !parent.is_dir()
        || parent.uid() != 0
        || parent.permissions().mode() & 0o022 != 0
    {
        return Err(SystemdScopeError::ManagerUnavailable);
    }
    Ok(())
}

fn cgroup_path(control_group: &str) -> Option<PathBuf> {
    if !control_group.starts_with('/') || control_group.contains("..") {
        return None;
    }
    Some(Path::new("/sys/fs/cgroup").join(control_group.trim_start_matches('/')))
}

fn cgroup_pids(control_group: &str) -> Option<Vec<u32>> {
    let path = cgroup_path(control_group)?.join("cgroup.procs");
    let content = fs::read_to_string(path).ok()?;
    content
        .lines()
        .map(|line| line.parse::<u32>().ok())
        .collect()
}

fn cgroup_contains_exact_pid(control_group: &str, expected_pid: u32) -> bool {
    cgroup_pids(control_group).as_deref() == Some(&[expected_pid])
}

fn cgroup_is_empty_or_absent(control_group: &str) -> bool {
    match cgroup_path(control_group) {
        Some(path) if !path.exists() => true,
        Some(_) => cgroup_pids(control_group).is_some_and(|pids| pids.is_empty()),
        None => false,
    }
}

#[cfg(test)]
mod tests {
    use std::process::Command;

    use super::*;

    #[test]
    fn scope_name_is_exactly_request_bound() {
        let request = format!("sha256:{}", "a".repeat(64));
        assert_eq!(
            scope_unit_name(request.as_str()).expect("scope name"),
            format!("ota-authority-invocation-{}.scope", "a".repeat(64))
        );
        assert!(scope_unit_name("sha256:not-a-digest").is_err());
        assert!(start_error_requires_reconciliation(&zbus::Error::Failure(
            String::from("transport outcome unavailable")
        )));
    }

    #[test]
    fn cleanup_accepts_scope_disappearance_between_terminal_observations() {
        let expected = LauncherSystemdScopeV1 {
            schema_version: 1,
            identity: String::new(),
            invocation_id: String::from("invocation-cleanup-race"),
            request_identity: format!("sha256:{}", "a".repeat(64)),
            child_identity: format!("sha256:{}", "b".repeat(64)),
            child_pid: 42,
            unit_name: String::from("ota-authority-invocation-cleanup-race.scope"),
            unit_object_path: String::from(
                "/org/freedesktop/systemd1/unit/ota_2dauthority_2dcleanup_2erace_2escope",
            ),
            slice: String::from("system.slice"),
            control_group: String::from("/ota-authority-cleanup-race-does-not-exist"),
            delegate: false,
            kill_mode: String::from("control-group"),
            collect_mode: String::from("inactive-or-failed"),
        };

        assert!(
            cleanup_observation(&expected, Err(SystemdScopeError::ScopeAbsent))
                .expect("absent exact scope and cgroup are terminal")
                .is_none()
        );
        assert!(
            cleanup_observation(&expected, Err(SystemdScopeError::ManagerUnavailable)).is_err()
        );
    }

    #[test]
    #[ignore = "requires a root Linux host with a systemd manager that supports transient PID scopes"]
    fn root_systemd_manager_owns_and_removes_exact_stopped_child() {
        assert_eq!(unsafe { libc::geteuid() }, 0, "root is required");
        let mut child = Command::new("/bin/sleep")
            .arg("30")
            .spawn()
            .expect("spawn pressure child");
        let pid = child.id();
        assert_eq!(unsafe { libc::kill(pid as libc::pid_t, libc::SIGSTOP) }, 0);
        let mut status = 0;
        assert_eq!(
            unsafe { libc::waitpid(pid as libc::pid_t, &mut status, libc::WUNTRACED) },
            pid as libc::pid_t
        );
        assert!(libc::WIFSTOPPED(status));
        let identity = |character: char| format!("sha256:{}", character.to_string().repeat(64));
        let request_identity = identity('a');
        let mut child_record = LauncherChildProcessV1 {
            schema_version: 1,
            identity: String::new(),
            invocation_id: String::from("invocation-systemd-pressure"),
            request_identity: request_identity.clone(),
            pid,
            process_start_time_identity: crate::prepared_child::process_start_identity(
                pid as libc::pid_t,
            )
            .expect("process start identity"),
            ota_binary_identity: identity('c'),
            principal_mapping_identity: identity('d'),
            working_directory_identity: identity('e'),
        };
        child_record.identity =
            ota_authority_protocol::launcher_child_process_identity(&child_record)
                .expect("child identity");
        let manager = SystemdScopeManager::connect().expect("systemd manager");
        let scope = match manager.attach_stopped_child(
            child_record.invocation_id.as_str(),
            request_identity.as_str(),
            &child_record,
            Duration::from_secs(5),
        ) {
            Ok(scope) => scope,
            Err(error) => {
                let _ = unsafe { libc::kill(pid as libc::pid_t, libc::SIGKILL) };
                let _ = child.wait();
                panic!("attach exact stopped child: {error:?}");
            }
        };
        if let Err(error) = manager.verify_scope(&scope, &child_record) {
            let _ = manager.recover_unrecorded_scope(
                child_record.invocation_id.as_str(),
                request_identity.as_str(),
                &child_record,
                Duration::from_secs(10),
            );
            let _ = unsafe { libc::kill(pid as libc::pid_t, libc::SIGKILL) };
            let _ = child.wait();
            panic!("verify exact scope: {error:?}");
        }
        if let Err(error) =
            manager.stop_and_confirm_empty(&scope, &child_record, Duration::from_secs(10))
        {
            let _ = manager.recover_unrecorded_scope(
                child_record.invocation_id.as_str(),
                request_identity.as_str(),
                &child_record,
                Duration::from_secs(10),
            );
            let _ = unsafe { libc::kill(pid as libc::pid_t, libc::SIGKILL) };
            let _ = child.wait();
            panic!("remove exact scope: {error:?}");
        }
        assert!(matches!(
            manager.observe_existing_scope(scope.unit_name.as_str()),
            Err(SystemdScopeError::ScopeAbsent)
        ));
        assert!(cgroup_is_empty_or_absent(scope.control_group.as_str()));
        let status = child.wait().expect("reap pressure child");
        assert!(!status.success());
    }
}
