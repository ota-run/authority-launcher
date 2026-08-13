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

//! Linux kernel observations for the protected launcher job principal.
//!
//! These helpers accept no caller-authored posture labels. They derive peer credentials from a
//! connected Unix socket and process posture from the live `/proc` record. Missing, duplicate, or
//! malformed required fields refuse rather than becoming unknown or partially verified evidence.

use std::collections::BTreeMap;
use std::fs::OpenOptions;
use std::io::{Read, Write};
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd};
use std::os::unix::fs::OpenOptionsExt;
use std::os::unix::net::UnixStream;

use sha2::{Digest, Sha256};
use thiserror::Error;

const MAX_PROC_STATUS_BYTES: u64 = 64 * 1024;
pub const BROKER_PROXY_IDENTITY_CHALLENGE: &[u8] = b"I";
pub const BROKER_PROXY_IDENTITY_PREFACE: &[u8] = b"O";

#[derive(Debug, Error, PartialEq, Eq)]
pub enum LinuxObservationError {
    #[error("the connected job peer credentials are unavailable")]
    PeerCredentialsUnavailable,
    #[error("the connected job peer does not match protected configuration")]
    PeerCredentialsMismatch,
    #[error("the connected job peer process status is unavailable")]
    ProcessStatusUnavailable,
    #[error("the connected job peer process status is malformed")]
    ProcessStatusMalformed,
    #[error("the connected job peer process status violates the closed profile")]
    ProcessStatusMismatch,
    #[error("the connected peer executable is unavailable or mismatched")]
    ProcessExecutableMismatch,
}

#[derive(Debug)]
pub struct ObservedSessionPeer {
    pidfd: OwnedFd,
    pub pid: u32,
    pub uid: u32,
    pub gid: u32,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VerifiedPeerProcessStatus {
    pid: u32,
    uid: u32,
    gid: u32,
}

pub fn observe_connected_peer(
    stream: &UnixStream,
) -> Result<ObservedSessionPeer, LinuxObservationError> {
    let credentials = socket_peer_credentials(stream)?;
    let pidfd = socket_peer_pidfd(stream)?;
    require_live_pidfd(&pidfd)?;
    Ok(ObservedSessionPeer {
        pidfd,
        pid: credentials.pid as u32,
        uid: credentials.uid,
        gid: credentials.gid,
    })
}

/// Authenticate the process that accepted a systemd-activated Unix stream. `SO_PEERCRED` on the
/// client side identifies the process that created the listener, which is PID 1 for socket
/// activation. The accepting service therefore sends one private preface; Linux attaches both its
/// credentials and pidfd atomically as ancillary data.
pub fn receive_authenticated_peer_preface(
    stream: &UnixStream,
) -> Result<ObservedSessionPeer, LinuxObservationError> {
    const SO_PASSPIDFD: libc::c_int = 76;
    const SCM_PIDFD: libc::c_int = 0x04;
    let enabled: libc::c_int = 1;
    for option in [libc::SO_PASSCRED, SO_PASSPIDFD] {
        if unsafe {
            libc::setsockopt(
                stream.as_raw_fd(),
                libc::SOL_SOCKET,
                option,
                (&enabled as *const libc::c_int).cast(),
                std::mem::size_of::<libc::c_int>() as libc::socklen_t,
            )
        } != 0
        {
            return Err(LinuxObservationError::PeerCredentialsUnavailable);
        }
    }

    let mut stream = stream;
    stream
        .write_all(BROKER_PROXY_IDENTITY_CHALLENGE)
        .map_err(|_| LinuxObservationError::PeerCredentialsUnavailable)?;

    let mut preface = [0_u8; 1];
    let mut iov = libc::iovec {
        iov_base: preface.as_mut_ptr().cast(),
        iov_len: preface.len(),
    };
    // `usize` storage keeps the ancillary buffer aligned for `cmsghdr`.
    let mut control = [0_usize; 16];
    let mut message: libc::msghdr = unsafe { std::mem::zeroed() };
    message.msg_iov = &mut iov;
    message.msg_iovlen = 1;
    message.msg_control = control.as_mut_ptr().cast();
    message.msg_controllen = std::mem::size_of_val(&control);
    let received =
        unsafe { libc::recvmsg(stream.as_raw_fd(), &mut message, libc::MSG_CMSG_CLOEXEC) };
    if received != 1
        || preface.as_slice() != BROKER_PROXY_IDENTITY_PREFACE
        || message.msg_flags & (libc::MSG_CTRUNC | libc::MSG_TRUNC) != 0
    {
        return Err(LinuxObservationError::PeerCredentialsUnavailable);
    }

    let mut credentials = None;
    let mut pidfd = None;
    let mut header = unsafe { libc::CMSG_FIRSTHDR(&message) };
    while !header.is_null() {
        let level = unsafe { (*header).cmsg_level };
        let kind = unsafe { (*header).cmsg_type };
        let length = unsafe { (*header).cmsg_len } as usize;
        if level == libc::SOL_SOCKET
            && kind == libc::SCM_CREDENTIALS
            && length == unsafe { libc::CMSG_LEN(std::mem::size_of::<libc::ucred>() as _) } as usize
            && credentials.is_none()
        {
            credentials = Some(unsafe {
                std::ptr::read_unaligned(libc::CMSG_DATA(header).cast::<libc::ucred>())
            });
        } else if level == libc::SOL_SOCKET
            && kind == SCM_PIDFD
            && length == unsafe { libc::CMSG_LEN(std::mem::size_of::<libc::c_int>() as _) } as usize
            && pidfd.is_none()
        {
            let descriptor =
                unsafe { std::ptr::read_unaligned(libc::CMSG_DATA(header).cast::<libc::c_int>()) };
            if descriptor < 0 {
                return Err(LinuxObservationError::PeerCredentialsUnavailable);
            }
            // SAFETY: `SCM_PIDFD` transferred a new descriptor owned by this process.
            pidfd = Some(unsafe { OwnedFd::from_raw_fd(descriptor) });
        } else {
            return Err(LinuxObservationError::PeerCredentialsUnavailable);
        }
        header = unsafe { libc::CMSG_NXTHDR(&message, header) };
    }

    let credentials = credentials.ok_or(LinuxObservationError::PeerCredentialsUnavailable)?;
    let pidfd = pidfd.ok_or(LinuxObservationError::PeerCredentialsUnavailable)?;
    if credentials.pid <= 0 {
        return Err(LinuxObservationError::PeerCredentialsUnavailable);
    }
    require_live_pidfd(&pidfd)?;
    Ok(ObservedSessionPeer {
        pidfd,
        pid: credentials.pid as u32,
        uid: credentials.uid,
        gid: credentials.gid,
    })
}

pub fn revalidate_observed_peer(
    expected: &ObservedSessionPeer,
) -> Result<(), LinuxObservationError> {
    require_live_pidfd(&expected.pidfd)
}

pub fn revalidate_connected_peer(
    stream: &UnixStream,
    expected: &ObservedSessionPeer,
) -> Result<(), LinuxObservationError> {
    require_live_pidfd(&expected.pidfd)?;
    let credentials = socket_peer_credentials(stream)?;
    if credentials.pid as u32 != expected.pid
        || credentials.uid != expected.uid
        || credentials.gid != expected.gid
    {
        return Err(LinuxObservationError::PeerCredentialsMismatch);
    }
    require_live_pidfd(&expected.pidfd)
}

pub fn reconcile_connected_peer(
    peer: &ObservedSessionPeer,
    expected_uid: u32,
    expected_gid: u32,
) -> Result<(), LinuxObservationError> {
    require_live_pidfd(&peer.pidfd)?;
    if peer.uid != expected_uid || peer.gid != expected_gid {
        return Err(LinuxObservationError::PeerCredentialsMismatch);
    }
    Ok(())
}

pub fn verify_peer_executable_identity(
    peer: &ObservedSessionPeer,
    expected_identity: &str,
) -> Result<(), LinuxObservationError> {
    require_live_pidfd(&peer.pidfd)?;
    let mut executable = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_CLOEXEC)
        .open(format!("/proc/{}/exe", peer.pid))
        .map_err(|_| LinuxObservationError::ProcessExecutableMismatch)?;
    let mut hasher = Sha256::new();
    let mut buffer = [0_u8; 16 * 1024];
    loop {
        let read = executable
            .read(&mut buffer)
            .map_err(|_| LinuxObservationError::ProcessExecutableMismatch)?;
        if read == 0 {
            break;
        }
        hasher.update(&buffer[..read]);
    }
    if format!("sha256:{:x}", hasher.finalize()) != expected_identity {
        return Err(LinuxObservationError::ProcessExecutableMismatch);
    }
    require_live_pidfd(&peer.pidfd)
}

pub fn verify_peer_process_status(
    peer: &ObservedSessionPeer,
) -> Result<VerifiedPeerProcessStatus, LinuxObservationError> {
    require_live_pidfd(&peer.pidfd)?;
    let path = format!("/proc/{}/status", peer.pid);
    let file = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_CLOEXEC | libc::O_NOFOLLOW)
        .open(path)
        .map_err(|_| LinuxObservationError::ProcessStatusUnavailable)?;
    if file
        .metadata()
        .map_err(|_| LinuxObservationError::ProcessStatusUnavailable)?
        .len()
        > MAX_PROC_STATUS_BYTES
    {
        return Err(LinuxObservationError::ProcessStatusMalformed);
    }
    let mut status = String::new();
    file.take(MAX_PROC_STATUS_BYTES + 1)
        .read_to_string(&mut status)
        .map_err(|_| LinuxObservationError::ProcessStatusUnavailable)?;
    if status.len() as u64 > MAX_PROC_STATUS_BYTES {
        return Err(LinuxObservationError::ProcessStatusMalformed);
    }
    let verified = verify_peer_process_status_text(peer.pid, peer.uid, peer.gid, &status)?;
    require_live_pidfd(&peer.pidfd)?;
    Ok(verified)
}

fn verify_peer_process_status_text(
    pid: u32,
    uid: u32,
    gid: u32,
    status: &str,
) -> Result<VerifiedPeerProcessStatus, LinuxObservationError> {
    let fields = parse_unique_status_fields(status)?;
    let expected_uid = [uid; 4];
    let expected_gid = [gid; 4];
    if parse_four_ids(required(&fields, "Uid")?)? != expected_uid
        || parse_four_ids(required(&fields, "Gid")?)? != expected_gid
        || !supplementary_groups_limited_to_primary(required(&fields, "Groups")?, gid)?
        || parse_hex(required(&fields, "CapInh")?)? != 0
        || parse_hex(required(&fields, "CapPrm")?)? != 0
        || parse_hex(required(&fields, "CapEff")?)? != 0
        || parse_hex(required(&fields, "CapAmb")?)? != 0
        || required(&fields, "NoNewPrivs")?.trim() != "1"
    {
        return Err(LinuxObservationError::ProcessStatusMismatch);
    }
    Ok(VerifiedPeerProcessStatus { pid, uid, gid })
}

fn supplementary_groups_limited_to_primary(
    value: &str,
    primary_gid: u32,
) -> Result<bool, LinuxObservationError> {
    let groups = value
        .split_whitespace()
        .map(|group| {
            group
                .parse::<u32>()
                .map_err(|_| LinuxObservationError::ProcessStatusMalformed)
        })
        .collect::<Result<Vec<_>, _>>()?;
    Ok(groups.iter().all(|group| *group == primary_gid))
}

fn socket_peer_pidfd(stream: &UnixStream) -> Result<OwnedFd, LinuxObservationError> {
    const SO_PEERPIDFD: libc::c_int = 77;
    let mut descriptor = -1_i32;
    let mut length = std::mem::size_of::<i32>() as libc::socklen_t;
    if unsafe {
        libc::getsockopt(
            stream.as_raw_fd(),
            libc::SOL_SOCKET,
            SO_PEERPIDFD,
            (&mut descriptor as *mut i32).cast(),
            &mut length,
        )
    } != 0
        || length != std::mem::size_of::<i32>() as libc::socklen_t
        || descriptor < 0
        || unsafe { libc::fcntl(descriptor, libc::F_SETFD, libc::FD_CLOEXEC) } != 0
    {
        if descriptor >= 0 {
            unsafe { libc::close(descriptor) };
        }
        return Err(LinuxObservationError::PeerCredentialsUnavailable);
    }
    // SAFETY: SO_PEERPIDFD returned a new descriptor now owned by this process.
    Ok(unsafe { OwnedFd::from_raw_fd(descriptor) })
}

fn socket_peer_credentials(stream: &UnixStream) -> Result<libc::ucred, LinuxObservationError> {
    let mut credentials = libc::ucred {
        pid: 0,
        uid: 0,
        gid: 0,
    };
    let mut length = std::mem::size_of::<libc::ucred>() as libc::socklen_t;
    // SAFETY: `credentials` is a valid writable buffer and `stream` owns a connected socket.
    if unsafe {
        libc::getsockopt(
            stream.as_raw_fd(),
            libc::SOL_SOCKET,
            libc::SO_PEERCRED,
            (&mut credentials as *mut libc::ucred).cast(),
            &mut length,
        )
    } != 0
        || length != std::mem::size_of::<libc::ucred>() as libc::socklen_t
        || credentials.pid <= 0
    {
        return Err(LinuxObservationError::PeerCredentialsUnavailable);
    }
    Ok(credentials)
}

fn require_live_pidfd(pidfd: &OwnedFd) -> Result<(), LinuxObservationError> {
    if unsafe {
        libc::syscall(
            libc::SYS_pidfd_send_signal,
            pidfd.as_raw_fd(),
            0,
            std::ptr::null::<libc::siginfo_t>(),
            0,
        )
    } < 0
    {
        return Err(LinuxObservationError::PeerCredentialsUnavailable);
    }
    Ok(())
}

fn parse_unique_status_fields(status: &str) -> Result<BTreeMap<&str, &str>, LinuxObservationError> {
    let mut fields = BTreeMap::new();
    for line in status.lines() {
        let Some((name, value)) = line.split_once(':') else {
            return Err(LinuxObservationError::ProcessStatusMalformed);
        };
        if fields.insert(name, value).is_some() {
            return Err(LinuxObservationError::ProcessStatusMalformed);
        }
    }
    Ok(fields)
}

fn required<'a>(
    fields: &'a BTreeMap<&str, &str>,
    name: &str,
) -> Result<&'a str, LinuxObservationError> {
    fields
        .get(name)
        .copied()
        .ok_or(LinuxObservationError::ProcessStatusMalformed)
}

fn parse_four_ids(value: &str) -> Result<[u32; 4], LinuxObservationError> {
    let values = value
        .split_whitespace()
        .map(str::parse::<u32>)
        .collect::<Result<Vec<_>, _>>()
        .map_err(|_| LinuxObservationError::ProcessStatusMalformed)?;
    values
        .try_into()
        .map_err(|_| LinuxObservationError::ProcessStatusMalformed)
}

fn parse_hex(value: &str) -> Result<u64, LinuxObservationError> {
    u64::from_str_radix(value.trim(), 16).map_err(|_| LinuxObservationError::ProcessStatusMalformed)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::fs::PermissionsExt;
    use std::os::unix::net::UnixListener;

    #[test]
    fn process_status_requires_every_exact_peer_control() {
        let status = "Uid:\t1001\t1001\t1001\t1001\nGid:\t1001\t1001\t1001\t1001\nGroups:\t\nCapInh:\t0000000000000000\nCapPrm:\t0000000000000000\nCapEff:\t0000000000000000\nCapAmb:\t0000000000000000\nNoNewPrivs:\t1\n";
        assert_eq!(
            verify_peer_process_status_text(41, 1001, 1001, status),
            Ok(VerifiedPeerProcessStatus {
                pid: 41,
                uid: 1001,
                gid: 1001,
            })
        );
        assert_eq!(
            verify_peer_process_status_text(
                41,
                1001,
                1001,
                &status.replace("Groups:\t", "Groups:\t1001 ")
            ),
            Ok(VerifiedPeerProcessStatus {
                pid: 41,
                uid: 1001,
                gid: 1001,
            })
        );

        for replacement in [
            status.replace("Groups:\t", "Groups:\t27"),
            status.replace("Groups:\t", "Groups:\t1001 27"),
            status.replace("CapEff:\t0000000000000000", "CapEff:\t0000000000000001"),
            status.replace("NoNewPrivs:\t1", "NoNewPrivs:\t0"),
            status.replace("Uid:\t1001", "Uid:\t1002"),
        ] {
            assert_eq!(
                verify_peer_process_status_text(41, 1001, 1001, &replacement),
                Err(LinuxObservationError::ProcessStatusMismatch)
            );
        }
    }

    #[test]
    fn process_status_refuses_missing_duplicate_and_malformed_fields() {
        let valid = "Uid:\t1001\t1001\t1001\t1001\nGid:\t1001\t1001\t1001\t1001\nGroups:\t\nCapInh:\t0\nCapPrm:\t0\nCapEff:\t0\nCapAmb:\t0\nNoNewPrivs:\t1\n";
        for malformed in [
            valid.replace("NoNewPrivs:\t1\n", ""),
            format!("{valid}Uid:\t1001\t1001\t1001\t1001\n"),
            valid.replace("CapEff:\t0", "CapEff:\tnot-hex"),
            valid.replace("Uid:\t1001\t1001\t1001\t1001", "Uid:\t1001"),
        ] {
            assert_eq!(
                verify_peer_process_status_text(41, 1001, 1001, &malformed),
                Err(LinuxObservationError::ProcessStatusMalformed)
            );
        }
    }

    #[test]
    fn connected_peer_credentials_are_kernel_derived_and_exact() {
        let (stream, _peer) = UnixStream::pair().expect("unix pair");
        let expected_uid = unsafe { libc::geteuid() };
        let expected_gid = unsafe { libc::getegid() };
        let observed = observe_connected_peer(&stream).expect("peer credentials");
        assert_eq!(observed.pid, std::process::id());
        assert_eq!(observed.uid, expected_uid);
        assert_eq!(observed.gid, expected_gid);
        assert_ne!(
            unsafe { libc::fcntl(observed.pidfd.as_raw_fd(), libc::F_GETFD) } & libc::FD_CLOEXEC,
            0
        );
        assert_eq!(revalidate_connected_peer(&stream, &observed), Ok(()));
        let mut current_executable = OpenOptions::new()
            .read(true)
            .custom_flags(libc::O_CLOEXEC)
            .open("/proc/self/exe")
            .expect("current executable");
        let mut hasher = Sha256::new();
        let mut buffer = [0_u8; 16 * 1024];
        loop {
            let read = current_executable
                .read(&mut buffer)
                .expect("executable read");
            if read == 0 {
                break;
            }
            hasher.update(&buffer[..read]);
        }
        let executable_identity = format!("sha256:{:x}", hasher.finalize());
        assert_eq!(
            verify_peer_executable_identity(&observed, &executable_identity),
            Ok(())
        );
        assert_eq!(
            verify_peer_executable_identity(&observed, &format!("sha256:{}", "f".repeat(64))),
            Err(LinuxObservationError::ProcessExecutableMismatch)
        );
        assert_eq!(
            reconcile_connected_peer(&observed, expected_uid, expected_gid),
            Ok(())
        );

        assert_eq!(
            reconcile_connected_peer(&observed, expected_uid.saturating_add(1), expected_gid),
            Err(LinuxObservationError::PeerCredentialsMismatch)
        );
    }

    #[test]
    fn live_non_root_peer_requires_the_complete_kernel_posture() {
        if unsafe { libc::geteuid() } != 0 {
            return;
        }
        run_live_peer_control(true, true);
        run_live_peer_control(false, false);
    }

    fn run_live_peer_control(no_new_privileges: bool, should_pass: bool) {
        let (_directory, stream, observed, pid) = spawn_live_test_peer(no_new_privileges);
        let verified = verify_peer_process_status(&observed);
        if should_pass {
            assert!(verified.is_ok(), "complete peer posture must verify");
        } else {
            assert_eq!(verified, Err(LinuxObservationError::ProcessStatusMismatch));
        }
        terminate_test_peer(pid);
        assert_eq!(
            revalidate_connected_peer(&stream, &observed),
            Err(LinuxObservationError::PeerCredentialsUnavailable)
        );
    }

    #[test]
    fn exited_socket_bound_peer_refuses_revalidation_and_status() {
        if unsafe { libc::geteuid() } != 0 {
            return;
        }
        let (_directory, stream, observed, pid) = spawn_live_test_peer(true);
        terminate_test_peer(pid);
        assert_eq!(
            revalidate_connected_peer(&stream, &observed),
            Err(LinuxObservationError::PeerCredentialsUnavailable)
        );
        assert_eq!(
            verify_peer_process_status(&observed),
            Err(LinuxObservationError::PeerCredentialsUnavailable)
        );
    }

    fn spawn_live_test_peer(
        no_new_privileges: bool,
    ) -> (
        tempfile::TempDir,
        UnixStream,
        ObservedSessionPeer,
        libc::pid_t,
    ) {
        let directory = tempfile::tempdir().expect("temporary socket directory");
        std::fs::set_permissions(directory.path(), std::fs::Permissions::from_mode(0o777))
            .expect("socket directory permissions");
        let socket_path = directory.path().join("peer.sock");
        let listener = UnixListener::bind(&socket_path).expect("listener");
        std::fs::set_permissions(&socket_path, std::fs::Permissions::from_mode(0o777))
            .expect("socket permissions");

        let pid = unsafe { libc::fork() };
        assert!(pid >= 0, "fork must succeed");
        if pid == 0 {
            drop(listener);
            let result = configure_test_principal(no_new_privileges)
                .and_then(|()| UnixStream::connect(&socket_path).map_err(|_| ()))
                .and_then(|mut stream| stream.write_all(b"ready").map_err(|_| ()))
                .map(|()| unsafe { libc::pause() });
            unsafe { libc::_exit(if result.is_ok() { 0 } else { 90 }) };
        }

        let (mut stream, _) = listener.accept().expect("accepted peer");
        let mut ready = [0_u8; 5];
        stream.read_exact(&mut ready).expect("peer ready");
        assert_eq!(&ready, b"ready");
        let observed = observe_connected_peer(&stream).expect("socket-bound peer");
        assert_eq!(observed.pid, pid as u32);
        reconcile_connected_peer(&observed, 65_534, 65_534).expect("protected mapping");
        (directory, stream, observed, pid)
    }

    fn terminate_test_peer(pid: libc::pid_t) {
        unsafe {
            libc::kill(pid, libc::SIGKILL);
            libc::waitpid(pid, std::ptr::null_mut(), 0);
        }
    }

    fn configure_test_principal(no_new_privileges: bool) -> Result<(), ()> {
        if unsafe {
            libc::setgroups(0, std::ptr::null())
                | libc::setresgid(65_534, 65_534, 65_534)
                | libc::setresuid(65_534, 65_534, 65_534)
        } != 0
        {
            return Err(());
        }
        if no_new_privileges && unsafe { libc::prctl(libc::PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) } != 0 {
            return Err(());
        }
        Ok(())
    }
}
