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

//! Stopped fixed-binary child preparation for the systemd launcher.
//!
//! The child remains root and stopped until the launcher has durably recorded its identity and a
//! later slice binds it to the exact systemd invocation scope. No code path in this module resumes
//! the child. Terminal cleanup kills and reaps it while it is still stopped.

use std::collections::{BTreeMap, BTreeSet};
use std::ffi::CString;
use std::fs::File;
use std::io;
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd, RawFd};
use std::os::unix::fs::MetadataExt;
use std::os::unix::net::UnixStream;
use std::time::{Duration, Instant};

use ota_authority_protocol::{
    LauncherChildProcessV1, launcher_child_process_identity, sha256_identity,
};
use thiserror::Error;

use crate::config::{RunAs, SystemdLauncherServiceConfigV1};
use crate::target_directory::OpenedRepositoryDirectory;

pub(crate) const SYSTEMD_OTA_SESSION_DESCRIPTOR: RawFd = 3;

#[derive(Debug, Error, PartialEq, Eq)]
pub(crate) enum PreparedChildError {
    #[error("the protected Ota child inputs are invalid")]
    InvalidInputs,
    #[error("the protected Ota child could not be created")]
    ForkFailed,
    #[error("the protected Ota child did not stop before execution")]
    StopFailed,
    #[error("the protected Ota child exited and was reaped before it stopped")]
    ExitedBeforeStop,
    #[error("the protected Ota child identity could not be observed")]
    IdentityUnavailable,
    #[error("the protected Ota child could not be terminated")]
    CleanupFailed,
}

pub(crate) struct PreparedChild {
    pid: libc::pid_t,
    pub record: LauncherChildProcessV1,
    _launcher_session: UnixStream,
}

pub(crate) struct PreparedChildBinding<'a> {
    pub invocation_id: &'a str,
    pub request_identity: &'a str,
    pub principal_mapping_identity: &'a str,
    pub working_directory_identity: &'a str,
}

#[derive(Clone, Copy, PartialEq, Eq)]
struct DescriptorObject {
    device: u64,
    inode: u64,
    file_type: u32,
}

impl PreparedChild {
    pub(crate) fn terminate_and_reap(&mut self) -> Result<(), PreparedChildError> {
        if self.pid <= 0 {
            return Ok(());
        }
        if unsafe { libc::kill(self.pid, libc::SIGKILL) } != 0 {
            let error = io::Error::last_os_error();
            if error.raw_os_error() != Some(libc::ESRCH) {
                return Err(PreparedChildError::CleanupFailed);
            }
        }
        let mut status = 0;
        loop {
            let observed = unsafe { libc::waitpid(self.pid, &mut status, 0) };
            if observed == self.pid {
                self.pid = 0;
                return Ok(());
            }
            if observed < 0 && io::Error::last_os_error().kind() == io::ErrorKind::Interrupted {
                continue;
            }
            return Err(PreparedChildError::CleanupFailed);
        }
    }

    #[cfg(test)]
    pub(crate) fn abandon_for_recovery(mut self) {
        self.pid = 0;
    }
}

impl Drop for PreparedChild {
    fn drop(&mut self) {
        let _ = self.terminate_and_reap();
    }
}

pub(crate) fn prepare_stopped_child(
    config: &SystemdLauncherServiceConfigV1,
    ota_binary: &File,
    repository: &OpenedRepositoryDirectory,
    execution: &RunAs,
    binding: &PreparedChildBinding<'_>,
    ota_arguments: &[String],
) -> Result<PreparedChild, PreparedChildError> {
    if unsafe { libc::geteuid() } != 0 {
        return Err(PreparedChildError::InvalidInputs);
    }
    let argv = child_arguments(ota_arguments)?;
    let mut argv_pointers: Vec<*const libc::c_char> =
        argv.iter().map(|value| value.as_ptr()).collect();
    argv_pointers.push(std::ptr::null());
    let environment = child_environment(&config.environment)?;
    let mut environment_pointers: Vec<*const libc::c_char> =
        environment.iter().map(|value| value.as_ptr()).collect();
    environment_pointers.push(std::ptr::null());
    let (launcher_session, child_session) =
        UnixStream::pair().map_err(|_| PreparedChildError::ForkFailed)?;
    set_cloexec(launcher_session.as_raw_fd())?;
    set_cloexec(child_session.as_raw_fd())?;
    let null = open_null()?;
    let ota_binary = duplicate_high(ota_binary.as_raw_fd(), 1_000)?;
    let repository_descriptor = duplicate_high(repository.descriptor.as_raw_fd(), 1_000)?;
    let expected_descriptors = [
        (
            libc::STDIN_FILENO,
            descriptor_object(null.as_raw_fd())?,
            false,
        ),
        (
            libc::STDOUT_FILENO,
            descriptor_object(null.as_raw_fd())?,
            false,
        ),
        (
            libc::STDERR_FILENO,
            descriptor_object(null.as_raw_fd())?,
            false,
        ),
        (
            SYSTEMD_OTA_SESSION_DESCRIPTOR,
            descriptor_object(child_session.as_raw_fd())?,
            false,
        ),
        (
            ota_binary.as_raw_fd(),
            descriptor_object(ota_binary.as_raw_fd())?,
            true,
        ),
        (
            repository_descriptor.as_raw_fd(),
            descriptor_object(repository_descriptor.as_raw_fd())?,
            true,
        ),
    ];
    let parent_pid = unsafe { libc::getpid() };
    let open_max = open_maximum();

    let child_pid = unsafe { libc::fork() };
    if child_pid < 0 {
        return Err(PreparedChildError::ForkFailed);
    }
    if child_pid == 0 {
        let status = run_child(
            parent_pid,
            child_session.as_raw_fd(),
            SYSTEMD_OTA_SESSION_DESCRIPTOR,
            ota_binary.as_raw_fd(),
            repository_descriptor.as_raw_fd(),
            null.as_raw_fd(),
            execution,
            argv_pointers.as_slice(),
            environment_pointers.as_slice(),
            open_max,
        );
        unsafe { libc::_exit(status) };
    }
    drop(child_session);

    if let Err(error) = wait_for_stop(
        child_pid,
        Duration::from_secs(config.maximum_startup_seconds),
    ) {
        if error == PreparedChildError::ExitedBeforeStop {
            return Err(error);
        }
        return Err(failed_prepare_error(child_pid, error));
    }
    if verify_stopped_child(child_pid, &expected_descriptors).is_err() {
        return Err(failed_prepare_error(
            child_pid,
            PreparedChildError::IdentityUnavailable,
        ));
    }
    let process_start_time_identity = match process_start_identity(child_pid) {
        Ok(identity) => identity,
        Err(error) => {
            return Err(failed_prepare_error(child_pid, error));
        }
    };
    let mut record = LauncherChildProcessV1 {
        schema_version: 1,
        identity: String::new(),
        invocation_id: binding.invocation_id.into(),
        request_identity: binding.request_identity.into(),
        pid: child_pid as u32,
        process_start_time_identity,
        ota_binary_identity: config.ota_binary_identity.clone(),
        principal_mapping_identity: binding.principal_mapping_identity.into(),
        working_directory_identity: binding.working_directory_identity.into(),
    };
    record.identity = match launcher_child_process_identity(&record) {
        Ok(identity) => identity,
        Err(_) => {
            return Err(failed_prepare_error(
                child_pid,
                PreparedChildError::IdentityUnavailable,
            ));
        }
    };
    Ok(PreparedChild {
        pid: child_pid,
        record,
        _launcher_session: launcher_session,
    })
}

fn child_arguments(arguments: &[String]) -> Result<Vec<CString>, PreparedChildError> {
    std::iter::once("ota")
        .chain(arguments.iter().map(String::as_str))
        .map(|argument| CString::new(argument).map_err(|_| PreparedChildError::InvalidInputs))
        .collect()
}

fn child_environment(
    environment: &BTreeMap<String, String>,
) -> Result<Vec<CString>, PreparedChildError> {
    environment
        .iter()
        .map(|(name, value)| {
            CString::new(format!("{name}={value}")).map_err(|_| PreparedChildError::InvalidInputs)
        })
        .collect()
}

fn open_null() -> Result<OwnedFd, PreparedChildError> {
    let path = c"/dev/null";
    let descriptor = unsafe { libc::open(path.as_ptr(), libc::O_RDWR | libc::O_CLOEXEC) };
    if descriptor < 0 {
        return Err(PreparedChildError::ForkFailed);
    }
    Ok(unsafe { OwnedFd::from_raw_fd(descriptor) })
}

#[allow(clippy::too_many_arguments)]
fn run_child(
    parent_pid: libc::pid_t,
    child_session: RawFd,
    session_target: RawFd,
    ota_binary: RawFd,
    repository: RawFd,
    null: RawFd,
    execution: &RunAs,
    argv: &[*const libc::c_char],
    environment: &[*const libc::c_char],
    open_max: RawFd,
) -> i32 {
    if unsafe { libc::prctl(libc::PR_SET_PDEATHSIG, libc::SIGKILL, 0, 0, 0) } != 0
        || unsafe { libc::getppid() } != parent_pid
    {
        return 10;
    }
    if !duplicate_descriptor(child_session, session_target, false)
        || !duplicate_descriptor(null, libc::STDIN_FILENO, false)
        || !duplicate_descriptor(null, libc::STDOUT_FILENO, false)
        || !duplicate_descriptor(null, libc::STDERR_FILENO, false)
    {
        return 11;
    }
    let retained = [session_target, ota_binary, repository];
    if !close_unretained_descriptors(open_max, retained) {
        return 12;
    }

    if unsafe { libc::raise(libc::SIGSTOP) } != 0 {
        return 13;
    }

    if unsafe { libc::setgroups(0, std::ptr::null()) } != 0
        || unsafe { libc::setresgid(execution.gid, execution.gid, execution.gid) } != 0
        || unsafe { libc::setresuid(execution.uid, execution.uid, execution.uid) } != 0
        || unsafe { libc::prctl(libc::PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) } != 0
        || unsafe { libc::fchdir(repository) } != 0
    {
        return 14;
    }
    unsafe { libc::close(repository) };

    unsafe { libc::fexecve(ota_binary, argv.as_ptr(), environment.as_ptr()) };
    15
}

fn duplicate_descriptor(source: RawFd, target: RawFd, cloexec: bool) -> bool {
    if source == target {
        let flags = unsafe { libc::fcntl(target, libc::F_GETFD) };
        let desired = if cloexec {
            flags | libc::FD_CLOEXEC
        } else {
            flags & !libc::FD_CLOEXEC
        };
        return flags >= 0 && unsafe { libc::fcntl(target, libc::F_SETFD, desired) } == 0;
    }
    (unsafe { libc::dup3(source, target, if cloexec { libc::O_CLOEXEC } else { 0 }) }) >= 0
}

fn close_unretained_descriptors(open_max: RawFd, retained: [RawFd; 3]) -> bool {
    for descriptor in 3..open_max {
        if !retained.contains(&descriptor) {
            unsafe { libc::close(descriptor) };
        }
    }
    true
}

fn duplicate_high(descriptor: RawFd, minimum: RawFd) -> Result<OwnedFd, PreparedChildError> {
    let duplicate = unsafe { libc::fcntl(descriptor, libc::F_DUPFD_CLOEXEC, minimum) };
    if duplicate < 0 {
        return Err(PreparedChildError::ForkFailed);
    }
    Ok(unsafe { OwnedFd::from_raw_fd(duplicate) })
}

fn set_cloexec(descriptor: RawFd) -> Result<(), PreparedChildError> {
    let flags = unsafe { libc::fcntl(descriptor, libc::F_GETFD) };
    if flags < 0 || unsafe { libc::fcntl(descriptor, libc::F_SETFD, flags | libc::FD_CLOEXEC) } < 0
    {
        return Err(PreparedChildError::ForkFailed);
    }
    Ok(())
}

fn open_maximum() -> RawFd {
    let observed = unsafe { libc::sysconf(libc::_SC_OPEN_MAX) };
    if observed <= 0 {
        65_536
    } else {
        observed.min(i32::MAX as libc::c_long) as RawFd
    }
}

fn wait_for_stop(pid: libc::pid_t, timeout: Duration) -> Result<(), PreparedChildError> {
    let deadline = Instant::now() + timeout;
    loop {
        let mut status = 0;
        let observed = unsafe { libc::waitpid(pid, &mut status, libc::WUNTRACED | libc::WNOHANG) };
        if observed == pid {
            if libc::WIFSTOPPED(status) && libc::WSTOPSIG(status) == libc::SIGSTOP {
                return Ok(());
            }
            if libc::WIFEXITED(status) || libc::WIFSIGNALED(status) {
                return Err(PreparedChildError::ExitedBeforeStop);
            }
            return Err(PreparedChildError::StopFailed);
        }
        if observed < 0 {
            if io::Error::last_os_error().kind() == io::ErrorKind::Interrupted {
                continue;
            }
            return Err(PreparedChildError::StopFailed);
        }
        if Instant::now() >= deadline {
            return Err(PreparedChildError::StopFailed);
        }
        std::thread::sleep(Duration::from_millis(2));
    }
}

fn process_start_identity(pid: libc::pid_t) -> Result<String, PreparedChildError> {
    let stat = std::fs::read_to_string(format!("/proc/{pid}/stat"))
        .map_err(|_| PreparedChildError::IdentityUnavailable)?;
    let closing = stat
        .rfind(')')
        .ok_or(PreparedChildError::IdentityUnavailable)?;
    let start_time = stat[closing + 1..]
        .split_whitespace()
        .nth(19)
        .ok_or(PreparedChildError::IdentityUnavailable)?;
    Ok(sha256_identity(
        format!("pid:{pid};start_time:{start_time}").as_bytes(),
    ))
}

fn verify_stopped_child(
    pid: libc::pid_t,
    expected_descriptors: &[(RawFd, DescriptorObject, bool)],
) -> Result<(), PreparedChildError> {
    let status = std::fs::read_to_string(format!("/proc/{pid}/status"))
        .map_err(|_| PreparedChildError::IdentityUnavailable)?;
    if !status.lines().any(|line| line == "State:\tT (stopped)")
        || !status.lines().any(|line| line == "Uid:\t0\t0\t0\t0")
        || !status.lines().any(|line| line == "Gid:\t0\t0\t0\t0")
    {
        return Err(PreparedChildError::IdentityUnavailable);
    }

    let descriptors = std::fs::read_dir(format!("/proc/{pid}/fd"))
        .map_err(|_| PreparedChildError::IdentityUnavailable)?
        .map(|entry| {
            entry
                .map_err(|_| PreparedChildError::IdentityUnavailable)?
                .file_name()
                .to_string_lossy()
                .parse::<RawFd>()
                .map_err(|_| PreparedChildError::IdentityUnavailable)
        })
        .collect::<Result<BTreeSet<_>, _>>()?;
    let expected = expected_descriptors
        .iter()
        .map(|(descriptor, _, _)| *descriptor)
        .collect();
    if descriptors != expected {
        return Err(PreparedChildError::IdentityUnavailable);
    }
    for (descriptor, expected_object, expected_cloexec) in expected_descriptors {
        let metadata = std::fs::metadata(format!("/proc/{pid}/fd/{descriptor}"))
            .map_err(|_| PreparedChildError::IdentityUnavailable)?;
        let observed = DescriptorObject {
            device: metadata.dev(),
            inode: metadata.ino(),
            file_type: metadata.mode() & libc::S_IFMT,
        };
        if observed != *expected_object
            || descriptor_cloexec(pid, *descriptor)? != *expected_cloexec
        {
            return Err(PreparedChildError::IdentityUnavailable);
        }
    }
    Ok(())
}

fn descriptor_object(descriptor: RawFd) -> Result<DescriptorObject, PreparedChildError> {
    let mut stat: libc::stat = unsafe { std::mem::zeroed() };
    if unsafe { libc::fstat(descriptor, &mut stat) } != 0 {
        return Err(PreparedChildError::IdentityUnavailable);
    }
    Ok(DescriptorObject {
        device: stat.st_dev,
        inode: stat.st_ino,
        file_type: stat.st_mode & libc::S_IFMT,
    })
}

fn descriptor_cloexec(pid: libc::pid_t, descriptor: RawFd) -> Result<bool, PreparedChildError> {
    let info = std::fs::read_to_string(format!("/proc/{pid}/fdinfo/{descriptor}"))
        .map_err(|_| PreparedChildError::IdentityUnavailable)?;
    let flags = info
        .lines()
        .find_map(|line| line.strip_prefix("flags:\t"))
        .and_then(|value| u32::from_str_radix(value, 8).ok())
        .ok_or(PreparedChildError::IdentityUnavailable)?;
    Ok(flags & libc::O_CLOEXEC as u32 != 0)
}

pub(crate) fn terminate_recorded_child(
    child: &LauncherChildProcessV1,
    timeout: Duration,
) -> Result<(), PreparedChildError> {
    match process_start_identity(child.pid as libc::pid_t) {
        Ok(identity) if identity == child.process_start_time_identity => {}
        Err(PreparedChildError::IdentityUnavailable)
            if !std::path::Path::new(format!("/proc/{}", child.pid).as_str()).exists() =>
        {
            return Ok(());
        }
        _ => return Err(PreparedChildError::IdentityUnavailable),
    }

    let descriptor = unsafe { libc::syscall(libc::SYS_pidfd_open, child.pid as libc::pid_t, 0) };
    if descriptor < 0 {
        return Err(PreparedChildError::CleanupFailed);
    }
    let pidfd = unsafe { OwnedFd::from_raw_fd(descriptor as RawFd) };
    if process_start_identity(child.pid as libc::pid_t)
        .ok()
        .as_deref()
        != Some(child.process_start_time_identity.as_str())
    {
        return Err(PreparedChildError::IdentityUnavailable);
    }
    if unsafe {
        libc::syscall(
            libc::SYS_pidfd_send_signal,
            pidfd.as_raw_fd(),
            libc::SIGKILL,
            std::ptr::null::<libc::siginfo_t>(),
            0,
        )
    } < 0
    {
        return Err(PreparedChildError::CleanupFailed);
    }
    let milliseconds = timeout.as_millis().min(i32::MAX as u128) as i32;
    let mut poll = libc::pollfd {
        fd: pidfd.as_raw_fd(),
        events: libc::POLLIN,
        revents: 0,
    };
    loop {
        let result = unsafe { libc::poll(&mut poll, 1, milliseconds) };
        if result > 0 && poll.revents & libc::POLLIN != 0 {
            let mut status = 0;
            loop {
                let observed =
                    unsafe { libc::waitpid(child.pid as libc::pid_t, &mut status, libc::WNOHANG) };
                if observed >= 0 || io::Error::last_os_error().raw_os_error() == Some(libc::ECHILD)
                {
                    break;
                }
                if io::Error::last_os_error().kind() != io::ErrorKind::Interrupted {
                    break;
                }
            }
            return Ok(());
        }
        if result < 0 && io::Error::last_os_error().kind() == io::ErrorKind::Interrupted {
            continue;
        }
        return Err(PreparedChildError::CleanupFailed);
    }
}

fn failed_prepare_error(pid: libc::pid_t, error: PreparedChildError) -> PreparedChildError {
    match kill_and_reap(pid) {
        Ok(()) => error,
        Err(()) => PreparedChildError::CleanupFailed,
    }
}

fn kill_and_reap(pid: libc::pid_t) -> Result<(), ()> {
    if unsafe { libc::kill(pid, libc::SIGKILL) } != 0 {
        let error = io::Error::last_os_error();
        if error.raw_os_error() != Some(libc::ESRCH) {
            return Err(());
        }
    }
    let mut status = 0;
    loop {
        let observed = unsafe { libc::waitpid(pid, &mut status, 0) };
        if observed == pid {
            return Ok(());
        }
        if observed < 0 && io::Error::last_os_error().kind() == io::ErrorKind::Interrupted {
            continue;
        }
        return Err(());
    }
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeMap;
    use std::fs;
    use std::os::unix::fs::{MetadataExt, PermissionsExt};
    use std::path::PathBuf;

    use ota_authority_protocol::{LauncherWorkingDirectoryV1, launcher_working_directory_identity};
    use tempfile::tempdir;

    use super::*;

    fn identity(character: char) -> String {
        format!("sha256:{}", character.to_string().repeat(64))
    }

    #[test]
    fn child_exit_before_stop_is_already_reaped() {
        let child = unsafe { libc::fork() };
        assert!(child >= 0, "fork child");
        if child == 0 {
            unsafe { libc::_exit(0) };
        }
        assert_eq!(
            wait_for_stop(child, Duration::from_secs(5)),
            Err(PreparedChildError::ExitedBeforeStop)
        );
        let mut status = 0;
        assert_eq!(
            unsafe { libc::waitpid(child, &mut status, libc::WNOHANG) },
            -1
        );
        assert_eq!(
            io::Error::last_os_error().raw_os_error(),
            Some(libc::ECHILD)
        );
    }

    #[test]
    fn root_prepares_stopped_child_without_executing_it() {
        if unsafe { libc::geteuid() } != 0 {
            return;
        }
        let temporary = tempdir().expect("temporary directory");
        fs::set_permissions(temporary.path(), fs::Permissions::from_mode(0o755))
            .expect("permissions");
        let repository_file = File::open(temporary.path()).expect("repository descriptor");
        let metadata = repository_file.metadata().expect("repository metadata");
        let mut working = LauncherWorkingDirectoryV1 {
            schema_version: 1,
            identity: String::new(),
            logical_path: temporary.path().to_string_lossy().into_owned(),
            device: metadata.dev(),
            inode: metadata.ino(),
        };
        working.identity = launcher_working_directory_identity(&working).expect("working identity");
        let repository = OpenedRepositoryDirectory {
            descriptor: repository_file.into(),
            device: metadata.dev(),
            inode: metadata.ino(),
        };
        let executable = File::open("/bin/true").expect("test executable");
        let config = SystemdLauncherServiceConfigV1 {
            schema_version: 1,
            identity: identity('a'),
            adapter: ota_authority_protocol::SYSTEMD_PROTECTED_LAUNCHER_ADAPTER_V1.into(),
            socket_path: PathBuf::from("/run/ota/authority-launcher.sock"),
            socket_group_gid: 1001,
            ota_binary: PathBuf::from("/bin/true"),
            environment: BTreeMap::from([(String::from("PATH"), String::from("/usr/bin"))]),
            allowed_repository_roots: vec![temporary.path().into()],
            mappings: Vec::new(),
            broker_proxy_socket: PathBuf::from("/run/ota/broker-proxy.sock"),
            broker_proxy_peer: crate::config::SessionPeer { uid: 0, gid: 0 },
            attestor_credential_name: String::from("authority-attestor"),
            service_unit_identity: identity('b'),
            socket_unit_identity: identity('c'),
            ota_binary_identity: identity('d'),
            broker_proxy_identity: identity('e'),
            attestor_key_set_identity: identity('f'),
            maximum_request_bytes: 4096,
            maximum_active_sessions: 1,
            maximum_startup_seconds: 5,
            maximum_terminal_wait_seconds: 30,
        };
        let mut child = prepare_stopped_child(
            &config,
            &executable,
            &repository,
            &RunAs {
                uid: 65_534,
                gid: 65_534,
            },
            &PreparedChildBinding {
                invocation_id: "invocation-test",
                request_identity: identity('2').as_str(),
                principal_mapping_identity: identity('1').as_str(),
                working_directory_identity: working.identity.as_str(),
            },
            &[String::from("run"), String::from("verify")],
        )
        .expect("prepare stopped child");
        assert!(PathBuf::from(format!("/proc/{}", child.record.pid)).exists());
        child.terminate_and_reap().expect("cleanup child");
        assert!(!PathBuf::from(format!("/proc/{}", child.record.pid)).exists());

        let abandoned = prepare_stopped_child(
            &config,
            &executable,
            &repository,
            &RunAs {
                uid: 65_534,
                gid: 65_534,
            },
            &PreparedChildBinding {
                invocation_id: "invocation-recovery",
                request_identity: identity('3').as_str(),
                principal_mapping_identity: identity('1').as_str(),
                working_directory_identity: working.identity.as_str(),
            },
            &[String::from("run"), String::from("verify")],
        )
        .expect("prepare abandoned child");
        let abandoned_record = abandoned.record.clone();
        abandoned.abandon_for_recovery();
        match terminate_recorded_child(&abandoned_record, Duration::from_secs(5)) {
            Ok(()) => {}
            Err(PreparedChildError::CleanupFailed) if !pidfd_available() => {
                kill_and_reap(abandoned_record.pid as libc::pid_t).expect("test fallback cleanup");
            }
            Err(error) => panic!("terminate recorded child: {error}"),
        }
        assert!(!PathBuf::from(format!("/proc/{}", abandoned_record.pid)).exists());
    }

    fn pidfd_available() -> bool {
        let descriptor = unsafe { libc::syscall(libc::SYS_pidfd_open, libc::getpid(), 0) };
        if descriptor < 0 {
            return false;
        }
        unsafe { libc::close(descriptor as RawFd) };
        true
    }
}
