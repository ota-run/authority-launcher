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

//! Target-principal repository opening for the systemd protected launcher.

use std::ffi::CString;
use std::io;
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd, RawFd};
use std::os::unix::ffi::OsStrExt;
use std::path::{Component, Path, PathBuf};
use std::time::{Duration, Instant};

use thiserror::Error;

use crate::config::{RunAs, SystemdLauncherServiceConfigV1};

const HELPER_DESCRIPTOR: RawFd = 3;
const CONTROL_BYTES: usize = 64;

#[repr(align(8))]
struct ControlBuffer([u8; CONTROL_BYTES]);

#[derive(Debug, Error)]
pub(crate) enum TargetDirectoryError {
    #[error("the repository path is outside the configured roots")]
    OutsideAllowedRoots,
    #[error("the repository path is unavailable to the configured execution principal")]
    UnavailableToExecutionPrincipal,
    #[error("the target-principal directory helper failed")]
    HelperFailed,
    #[error("the target-principal directory helper timed out")]
    HelperTimedOut,
    #[error("the target-principal directory helper wait failed")]
    HelperWaitFailed,
    #[error("the target-principal privilege transition failed")]
    PrivilegeTransitionFailed,
    #[error("the helper descriptor sanitization failed")]
    DescriptorSanitizationFailed,
    #[error("the helper parent binding failed")]
    ParentBindingFailed,
    #[error("the helper could not clear supplementary groups")]
    SupplementaryGroupClearFailed,
    #[error("the helper could not adopt the configured group")]
    GroupTransitionFailed,
    #[error("the helper could not adopt the configured user")]
    UserTransitionFailed,
    #[error("the helper could not verify the configured principal")]
    PrincipalVerificationFailed,
    #[error("the configured repository root is unavailable to the execution principal")]
    RootUnavailableToExecutionPrincipal,
    #[error("the repository descriptor transfer failed")]
    DescriptorTransferFailed,
}

#[derive(Debug)]
pub(crate) struct OpenedRepositoryDirectory {
    pub descriptor: OwnedFd,
    pub logical_path: PathBuf,
    pub device: u64,
    pub inode: u64,
}

pub(crate) fn open_repository_directory(
    config: &SystemdLauncherServiceConfigV1,
    execution: &RunAs,
    requested_path: &str,
) -> Result<OpenedRepositoryDirectory, TargetDirectoryError> {
    let requested = Path::new(requested_path);
    let (root, relative) = select_allowed_root(config, requested)?;
    let root = CString::new(root.as_os_str().as_bytes())
        .map_err(|_| TargetDirectoryError::OutsideAllowedRoots)?;
    let relative = CString::new(relative.as_os_str().as_bytes())
        .map_err(|_| TargetDirectoryError::OutsideAllowedRoots)?;

    let (parent, child) = socket_pair()?;
    let parent_pid = unsafe { libc::getpid() };
    let child_pid = unsafe { libc::fork() };
    if child_pid < 0 {
        return Err(TargetDirectoryError::HelperFailed);
    }
    if child_pid == 0 {
        let status = run_helper(
            parent.as_raw_fd(),
            child.as_raw_fd(),
            parent_pid,
            execution,
            root.as_ptr(),
            relative.as_ptr(),
        );
        unsafe { libc::_exit(status) };
    }
    drop(child);

    let descriptor = match wait_for_descriptor(
        parent.as_raw_fd(),
        Duration::from_secs(config.maximum_startup_seconds),
    ) {
        Ok(descriptor) => descriptor,
        Err(error) => {
            if matches!(
                error,
                TargetDirectoryError::HelperTimedOut | TargetDirectoryError::HelperWaitFailed
            ) {
                terminate_helper(child_pid);
                return Err(error);
            }
            return Err(helper_status_error(wait_for_helper(child_pid)?));
        }
    };
    let status = wait_for_helper(child_pid)?;
    if !libc::WIFEXITED(status) || libc::WEXITSTATUS(status) != 0 {
        return Err(helper_status_error(status));
    }

    let mut metadata: libc::stat = unsafe { std::mem::zeroed() };
    if unsafe { libc::fstat(descriptor.as_raw_fd(), &mut metadata) } != 0
        || metadata.st_mode & libc::S_IFMT != libc::S_IFDIR
    {
        return Err(TargetDirectoryError::HelperFailed);
    }
    Ok(OpenedRepositoryDirectory {
        descriptor,
        logical_path: requested.to_path_buf(),
        device: metadata.st_dev,
        inode: metadata.st_ino,
    })
}

fn select_allowed_root<'a>(
    config: &'a SystemdLauncherServiceConfigV1,
    requested: &Path,
) -> Result<(&'a Path, PathBuf), TargetDirectoryError> {
    if !requested.is_absolute()
        || requested
            .components()
            .any(|component| matches!(component, Component::CurDir | Component::ParentDir))
    {
        return Err(TargetDirectoryError::OutsideAllowedRoots);
    }
    let mut matches = config.allowed_repository_roots.iter().filter_map(|root| {
        requested
            .strip_prefix(root)
            .ok()
            .map(|relative| (root, relative))
    });
    let (root, relative) = matches
        .next()
        .ok_or(TargetDirectoryError::OutsideAllowedRoots)?;
    if matches.next().is_some() {
        return Err(TargetDirectoryError::OutsideAllowedRoots);
    }
    let relative = if relative.as_os_str().is_empty() {
        PathBuf::from(".")
    } else {
        relative.to_path_buf()
    };
    Ok((root.as_path(), relative))
}

fn socket_pair() -> Result<(OwnedFd, OwnedFd), TargetDirectoryError> {
    let mut descriptors = [-1; 2];
    let result = unsafe {
        libc::socketpair(
            libc::AF_UNIX,
            libc::SOCK_SEQPACKET | libc::SOCK_CLOEXEC,
            0,
            descriptors.as_mut_ptr(),
        )
    };
    if result != 0 {
        return Err(TargetDirectoryError::HelperFailed);
    }
    Ok(unsafe {
        (
            OwnedFd::from_raw_fd(descriptors[0]),
            OwnedFd::from_raw_fd(descriptors[1]),
        )
    })
}

fn run_helper(
    parent_descriptor: RawFd,
    child_descriptor: RawFd,
    parent_pid: libc::pid_t,
    execution: &RunAs,
    root: *const libc::c_char,
    relative: *const libc::c_char,
) -> i32 {
    unsafe { libc::close(parent_descriptor) };
    if child_descriptor != HELPER_DESCRIPTOR
        && unsafe { libc::dup3(child_descriptor, HELPER_DESCRIPTOR, libc::O_CLOEXEC) } < 0
    {
        return 10;
    }
    if child_descriptor != HELPER_DESCRIPTOR {
        unsafe { libc::close(child_descriptor) };
    }
    if !close_helper_descriptors() {
        return 14;
    }
    if unsafe { libc::prctl(libc::PR_SET_PDEATHSIG, libc::SIGKILL, 0, 0, 0) } != 0
        || unsafe { libc::getppid() } != parent_pid
    {
        return 15;
    }
    if unsafe { libc::setgroups(0, std::ptr::null()) } != 0 {
        return 16;
    }
    if unsafe { libc::setresgid(execution.gid, execution.gid, execution.gid) } != 0 {
        return 17;
    }
    if unsafe { libc::setresuid(execution.uid, execution.uid, execution.uid) } != 0 {
        return 18;
    }
    if unsafe { libc::prctl(libc::PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) } != 0 {
        return 19;
    }
    let mut real_uid = 0;
    let mut effective_uid = 0;
    let mut saved_uid = 0;
    let mut real_gid = 0;
    let mut effective_gid = 0;
    let mut saved_gid = 0;
    if unsafe { libc::getresuid(&mut real_uid, &mut effective_uid, &mut saved_uid) } != 0
        || unsafe { libc::getresgid(&mut real_gid, &mut effective_gid, &mut saved_gid) } != 0
        || real_uid != execution.uid
        || effective_uid != execution.uid
        || saved_uid != execution.uid
        || real_gid != execution.gid
        || effective_gid != execution.gid
        || saved_gid != execution.gid
        || unsafe { libc::setfsuid(u32::MAX) } as u32 != execution.uid
        || unsafe { libc::setfsgid(u32::MAX) } as u32 != execution.gid
        || unsafe { libc::getgroups(0, std::ptr::null_mut()) } != 0
        || unsafe { libc::prctl(libc::PR_GET_NO_NEW_PRIVS, 0, 0, 0, 0) } != 1
    {
        return 20;
    }

    let root_descriptor = open_directory(
        libc::AT_FDCWD,
        root,
        libc::RESOLVE_NO_MAGICLINKS | libc::RESOLVE_NO_SYMLINKS,
    );
    if root_descriptor < 0 {
        return 11;
    }
    let repository_descriptor = open_directory(
        root_descriptor,
        relative,
        libc::RESOLVE_BENEATH
            | libc::RESOLVE_NO_MAGICLINKS
            | libc::RESOLVE_NO_SYMLINKS
            | libc::RESOLVE_NO_XDEV,
    );
    unsafe { libc::close(root_descriptor) };
    if repository_descriptor < 0 {
        return 12;
    }
    let sent = send_descriptor(HELPER_DESCRIPTOR, repository_descriptor);
    unsafe { libc::close(repository_descriptor) };
    if sent { 0 } else { 13 }
}

fn close_helper_descriptors() -> bool {
    if unsafe { libc::syscall(libc::SYS_close_range, 4_u32, u32::MAX, 0_u32) } == 0 {
        return true;
    }
    let error = io::Error::last_os_error();
    if !matches!(
        error.raw_os_error(),
        Some(code) if code == libc::ENOSYS || code == libc::EINVAL || code == libc::EPERM
    ) {
        return false;
    }
    let limit = unsafe { libc::sysconf(libc::_SC_OPEN_MAX) };
    let upper = if limit <= 0 { 65_536 } else { limit as RawFd };
    for descriptor in 4..upper {
        unsafe { libc::close(descriptor) };
    }
    true
}

fn open_directory(directory: RawFd, path: *const libc::c_char, resolve: u64) -> RawFd {
    let mut how: libc::open_how = unsafe { std::mem::zeroed() };
    how.flags = (libc::O_PATH | libc::O_DIRECTORY | libc::O_CLOEXEC) as u64;
    how.resolve = resolve;
    unsafe {
        libc::syscall(
            libc::SYS_openat2,
            directory,
            path,
            &how,
            std::mem::size_of::<libc::open_how>(),
        ) as RawFd
    }
}

fn send_descriptor(socket: RawFd, descriptor: RawFd) -> bool {
    let mut byte = [1_u8];
    let mut iovec = libc::iovec {
        iov_base: byte.as_mut_ptr().cast(),
        iov_len: byte.len(),
    };
    let mut control = ControlBuffer([0_u8; CONTROL_BYTES]);
    let mut message: libc::msghdr = unsafe { std::mem::zeroed() };
    message.msg_iov = &mut iovec;
    message.msg_iovlen = 1;
    message.msg_control = control.0.as_mut_ptr().cast();
    message.msg_controllen = control.0.len();
    let header = unsafe { libc::CMSG_FIRSTHDR(&message) };
    if header.is_null() {
        return false;
    }
    unsafe {
        (*header).cmsg_level = libc::SOL_SOCKET;
        (*header).cmsg_type = libc::SCM_RIGHTS;
        (*header).cmsg_len = libc::CMSG_LEN(std::mem::size_of::<RawFd>() as _) as _;
        std::ptr::copy_nonoverlapping(
            (&descriptor as *const RawFd).cast::<u8>(),
            libc::CMSG_DATA(header),
            std::mem::size_of::<RawFd>(),
        );
        message.msg_controllen = libc::CMSG_SPACE(std::mem::size_of::<RawFd>() as _) as usize;
        libc::sendmsg(socket, &message, libc::MSG_NOSIGNAL) == 1
    }
}

fn wait_for_descriptor(socket: RawFd, timeout: Duration) -> Result<OwnedFd, TargetDirectoryError> {
    let deadline = Instant::now() + timeout;
    loop {
        let remaining = deadline.saturating_duration_since(Instant::now());
        if remaining.is_zero() {
            return Err(TargetDirectoryError::HelperTimedOut);
        }
        let timeout_millis = remaining.as_millis().clamp(1, i32::MAX as u128) as i32;
        let mut poll_descriptor = libc::pollfd {
            fd: socket,
            events: libc::POLLIN | libc::POLLHUP,
            revents: 0,
        };
        let result = unsafe { libc::poll(&mut poll_descriptor, 1, timeout_millis) };
        if result > 0 {
            return receive_descriptor(socket);
        }
        if result == 0 {
            return Err(TargetDirectoryError::HelperTimedOut);
        }
        if io::Error::last_os_error().kind() != io::ErrorKind::Interrupted {
            return Err(TargetDirectoryError::HelperWaitFailed);
        }
    }
}

fn receive_descriptor(socket: RawFd) -> Result<OwnedFd, TargetDirectoryError> {
    let mut byte = [0_u8];
    let mut iovec = libc::iovec {
        iov_base: byte.as_mut_ptr().cast(),
        iov_len: byte.len(),
    };
    let mut control = ControlBuffer([0_u8; CONTROL_BYTES]);
    let mut message: libc::msghdr = unsafe { std::mem::zeroed() };
    message.msg_iov = &mut iovec;
    message.msg_iovlen = 1;
    message.msg_control = control.0.as_mut_ptr().cast();
    message.msg_controllen = control.0.len();
    let received = unsafe { libc::recvmsg(socket, &mut message, libc::MSG_CMSG_CLOEXEC) };
    if received != 1
        || byte[0] != 1
        || message.msg_flags & (libc::MSG_CTRUNC | libc::MSG_TRUNC) != 0
    {
        close_received_descriptors(&message);
        return Err(TargetDirectoryError::DescriptorTransferFailed);
    }
    let header = unsafe { libc::CMSG_FIRSTHDR(&message) };
    if header.is_null()
        || unsafe { (*header).cmsg_level } != libc::SOL_SOCKET
        || unsafe { (*header).cmsg_type } != libc::SCM_RIGHTS
        || unsafe { (*header).cmsg_len }
            != unsafe { libc::CMSG_LEN(std::mem::size_of::<RawFd>() as _) as usize }
        || !unsafe { libc::CMSG_NXTHDR(&message, header) }.is_null()
    {
        close_received_descriptors(&message);
        return Err(TargetDirectoryError::DescriptorTransferFailed);
    }
    let descriptor = unsafe { *(libc::CMSG_DATA(header).cast::<RawFd>()) };
    if descriptor < 0 {
        return Err(TargetDirectoryError::DescriptorTransferFailed);
    }
    Ok(unsafe { OwnedFd::from_raw_fd(descriptor) })
}

fn close_received_descriptors(message: &libc::msghdr) {
    let mut header = unsafe { libc::CMSG_FIRSTHDR(message) };
    while !header.is_null() {
        let minimum = unsafe { libc::CMSG_LEN(0) as usize };
        if unsafe { (*header).cmsg_level } == libc::SOL_SOCKET
            && unsafe { (*header).cmsg_type } == libc::SCM_RIGHTS
            && unsafe { (*header).cmsg_len } >= minimum
        {
            let bytes = unsafe { (*header).cmsg_len } - minimum;
            let count = bytes / std::mem::size_of::<RawFd>();
            let descriptors = unsafe { libc::CMSG_DATA(header).cast::<RawFd>() };
            for index in 0..count {
                unsafe { libc::close(*descriptors.add(index)) };
            }
        }
        header = unsafe { libc::CMSG_NXTHDR(message, header) };
    }
}

fn wait_for_helper(child_pid: libc::pid_t) -> Result<i32, TargetDirectoryError> {
    let mut status = 0;
    loop {
        let result = unsafe { libc::waitpid(child_pid, &mut status, 0) };
        if result == child_pid {
            return Ok(status);
        }
        if result < 0 && io::Error::last_os_error().kind() == io::ErrorKind::Interrupted {
            continue;
        }
        return Err(TargetDirectoryError::HelperFailed);
    }
}

fn helper_status_error(status: i32) -> TargetDirectoryError {
    if !libc::WIFEXITED(status) {
        return TargetDirectoryError::HelperFailed;
    }
    match libc::WEXITSTATUS(status) {
        10 => TargetDirectoryError::PrivilegeTransitionFailed,
        14 => TargetDirectoryError::DescriptorSanitizationFailed,
        15 => TargetDirectoryError::ParentBindingFailed,
        16 => TargetDirectoryError::SupplementaryGroupClearFailed,
        17 => TargetDirectoryError::GroupTransitionFailed,
        18 => TargetDirectoryError::UserTransitionFailed,
        19 => TargetDirectoryError::PrivilegeTransitionFailed,
        20 => TargetDirectoryError::PrincipalVerificationFailed,
        11 => TargetDirectoryError::RootUnavailableToExecutionPrincipal,
        12 => TargetDirectoryError::UnavailableToExecutionPrincipal,
        13 => TargetDirectoryError::DescriptorTransferFailed,
        _ => TargetDirectoryError::HelperFailed,
    }
}

fn terminate_helper(child_pid: libc::pid_t) {
    unsafe { libc::kill(child_pid, libc::SIGKILL) };
    let _ = wait_for_helper(child_pid);
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeMap;
    use std::fs;
    use std::os::fd::AsRawFd;
    use std::os::unix::fs::{MetadataExt, PermissionsExt, symlink};

    use ota_authority_protocol::SYSTEMD_PROTECTED_LAUNCHER_ADAPTER_V1;
    use tempfile::tempdir;

    use super::*;
    use crate::config::{SessionPeer, SystemdPrincipalMappingV1};

    fn identity(value: char) -> String {
        format!("sha256:{}", value.to_string().repeat(64))
    }

    fn config(root: PathBuf) -> SystemdLauncherServiceConfigV1 {
        SystemdLauncherServiceConfigV1 {
            schema_version: 1,
            identity: identity('0'),
            adapter: SYSTEMD_PROTECTED_LAUNCHER_ADAPTER_V1.into(),
            socket_path: "/run/ota/authority-launcher.sock".into(),
            socket_group_gid: 1001,
            ota_binary: "/opt/ota/bin/ota".into(),
            environment: BTreeMap::new(),
            allowed_repository_roots: vec![root],
            mappings: vec![SystemdPrincipalMappingV1 {
                authority_id: "release".into(),
                job_peer: SessionPeer {
                    uid: 1001,
                    gid: 1001,
                },
                execution: RunAs {
                    uid: 65_534,
                    gid: 65_534,
                },
            }],
            broker_proxy_socket: "/run/ota/broker-proxy.sock".into(),
            broker_proxy_peer: SessionPeer { uid: 0, gid: 0 },
            attestor_credential_name: "authority-attestor".into(),
            service_unit_identity: identity('1'),
            socket_unit_identity: identity('2'),
            ota_binary_identity: identity('3'),
            broker_proxy_identity: identity('4'),
            attestor_key_set_identity: identity('5'),
            maximum_request_bytes: 4096,
            maximum_active_sessions: 1,
            maximum_startup_seconds: 5,
            maximum_terminal_wait_seconds: 30,
        }
    }

    #[test]
    fn descriptor_transport_carries_exact_open_file() {
        let temporary = tempdir().expect("temporary directory");
        let file = fs::File::open(temporary.path()).expect("directory descriptor");
        let (sender, receiver) = socket_pair().expect("socket pair");
        assert!(send_descriptor(sender.as_raw_fd(), file.as_raw_fd()));
        let received = receive_descriptor(receiver.as_raw_fd()).expect("received descriptor");
        let original = file.metadata().expect("original metadata");
        let mut observed: libc::stat = unsafe { std::mem::zeroed() };
        assert_eq!(
            unsafe { libc::fstat(received.as_raw_fd(), &mut observed) },
            0
        );
        assert_eq!(
            (original.dev(), original.ino()),
            (observed.st_dev, observed.st_ino)
        );
    }

    #[test]
    fn target_principal_open_binds_descriptor_and_refuses_symlink_escape() {
        if unsafe { libc::geteuid() } != 0 {
            return;
        }
        let temporary = tempdir().expect("temporary root");
        fs::set_permissions(temporary.path(), fs::Permissions::from_mode(0o755))
            .expect("root permissions");
        let allowed = temporary.path().join("allowed");
        let repository = allowed.join("repository");
        fs::create_dir(&allowed).expect("allowed root");
        fs::create_dir(&repository).expect("repository");
        fs::set_permissions(&allowed, fs::Permissions::from_mode(0o755))
            .expect("allowed permissions");
        fs::set_permissions(&repository, fs::Permissions::from_mode(0o755))
            .expect("repository permissions");

        let root_path = CString::new(allowed.as_os_str().as_bytes()).expect("root C string");
        let root_descriptor = open_directory(
            libc::AT_FDCWD,
            root_path.as_ptr(),
            libc::RESOLVE_NO_MAGICLINKS | libc::RESOLVE_NO_SYMLINKS,
        );
        if root_descriptor < 0 && io::Error::last_os_error().raw_os_error() == Some(libc::ENOSYS) {
            let config = config(allowed.clone());
            let error = open_repository_directory(
                &config,
                &config.mappings[0].execution,
                repository.to_str().expect("repository path"),
            )
            .expect_err("openat2-unavailable host must refuse");
            assert!(
                matches!(
                    error,
                    TargetDirectoryError::RootUnavailableToExecutionPrincipal
                ),
                "unexpected unsupported-host refusal: {error:?}"
            );
            return;
        }
        assert!(
            root_descriptor >= 0,
            "root openat2 failed: {}",
            io::Error::last_os_error()
        );
        unsafe { libc::close(root_descriptor) };

        let config = config(allowed.clone());
        let opened = open_repository_directory(
            &config,
            &config.mappings[0].execution,
            repository.to_str().expect("repository path"),
        )
        .unwrap_or_else(|error| {
            panic!(
                "target-principal open under {} failed: {error:?}",
                allowed.display()
            )
        });
        let metadata = fs::metadata(&repository).expect("repository metadata");
        assert_eq!(
            (opened.device, opened.inode),
            (metadata.dev(), metadata.ino())
        );
        assert!(opened.descriptor.as_raw_fd() >= 0);

        let moved = allowed.join("moved");
        fs::rename(&repository, &moved).expect("move repository");
        fs::create_dir(&repository).expect("replacement repository");
        assert_ne!(
            opened.inode,
            fs::metadata(&repository)
                .expect("replacement metadata")
                .ino()
        );

        let outside = temporary.path().join("outside");
        fs::create_dir(&outside).expect("outside directory");
        fs::set_permissions(&outside, fs::Permissions::from_mode(0o755))
            .expect("outside permissions");
        let escape = allowed.join("escape");
        symlink(&outside, &escape).expect("escape symlink");
        assert!(matches!(
            open_repository_directory(
                &config,
                &config.mappings[0].execution,
                escape.to_str().expect("escape path"),
            ),
            Err(TargetDirectoryError::UnavailableToExecutionPrincipal)
                | Err(TargetDirectoryError::HelperFailed)
        ));
        assert!(matches!(
            open_repository_directory(
                &config,
                &config.mappings[0].execution,
                outside.to_str().expect("outside path"),
            ),
            Err(TargetDirectoryError::OutsideAllowedRoots)
        ));
    }
}
