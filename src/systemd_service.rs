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

//! Linux socket-activation admission for the planned protected launcher service.
//!
//! This foundation deliberately stops before broker or child-process work. It proves the service
//! can consume only the fixed systemd listener, derive the connecting job principal through
//! `SO_PEERCRED`, and reject invalid requests before any governed process exists.

use std::env;
use std::io::{Read, Write};
use std::os::fd::{AsRawFd, FromRawFd, RawFd};
use std::os::unix::fs::{FileTypeExt, MetadataExt};
use std::os::unix::net::{UnixListener, UnixStream};
use std::path::Path;
use std::time::Duration;

use ota_authority_protocol::{
    LAUNCHER_TERMINAL, LauncherInvocationRequestV1, LauncherTerminalFrameV1,
    LauncherTerminalOutcomeV1, MAX_FRAME_BYTES, SYSTEMD_LAUNCHER_SERVICE_PROTOCOL_V1, decode_frame,
    encode_frame, validate_launcher_invocation_request_v1, validate_launcher_terminal_frame_v1,
};
use thiserror::Error;

use crate::config::{
    SYSTEMD_AUTHORITY_LAUNCHER_CONFIG_PATH, SessionPeer, SystemdLauncherServiceConfigV1,
    load_systemd_launcher_service_config,
};
use crate::target_directory::{TargetDirectoryError, open_repository_directory};

const SYSTEMD_LISTEN_FD: RawFd = 3;
const REQUEST_TIMEOUT: Duration = Duration::from_secs(5);

#[derive(Debug, Error)]
pub(crate) enum SystemdServiceError {
    #[error("the systemd launcher service must run as root")]
    RootRequired,
    #[error("the systemd launcher listener is unavailable or invalid")]
    ListenerUnavailable,
    #[error("the systemd launcher request is invalid")]
    InvalidRequest,
    #[error("the systemd launcher request peer is not mapped by protected configuration")]
    PeerUnmapped,
    #[error("the systemd launcher repository path is outside protected allowed roots")]
    RepositoryOutsideAllowedRoots,
    #[error("the systemd launcher repository is unavailable to the configured execution principal")]
    RepositoryUnavailableToExecutionPrincipal,
    #[error("the systemd launcher admission foundation does not yet execute governed work")]
    ExecutionNotEnabled,
}

pub(crate) fn serve_once() -> Result<u8, SystemdServiceError> {
    if unsafe { libc::geteuid() } != 0 {
        return Err(SystemdServiceError::RootRequired);
    }
    let loaded = load_systemd_launcher_service_config(SYSTEMD_AUTHORITY_LAUNCHER_CONFIG_PATH)
        .map_err(|_| SystemdServiceError::ListenerUnavailable)?;
    let config = &loaded.config;
    let listener =
        inherited_systemd_listener(config.socket_path.as_path(), config.socket_group_gid)?;
    let (mut stream, _) = listener
        .accept()
        .map_err(|_| SystemdServiceError::ListenerUnavailable)?;
    stream
        .set_read_timeout(Some(REQUEST_TIMEOUT))
        .map_err(|_| SystemdServiceError::ListenerUnavailable)?;
    stream
        .set_write_timeout(Some(REQUEST_TIMEOUT))
        .map_err(|_| SystemdServiceError::ListenerUnavailable)?;

    let peer = peer_credentials(&stream)?;
    let request = receive_request(&mut stream, config.maximum_request_bytes)?;
    let mapping = select_mapping(config, &request, peer)?;
    validate_requested_command(&request)?;

    // A random service-minted ID prevents the client from selecting a terminal carrier. The
    // service creates it before target-principal preparation so every admitted request receives
    // terminal refusal evidence even when directory opening is unavailable.
    let invocation_id = fresh_invocation_id()?;
    let repository = match open_repository_directory(
        config,
        &mapping.execution,
        request.repository_path.as_str(),
    ) {
        Ok(repository) => repository,
        Err(error) => {
            write_terminal(
                &mut stream,
                invocation_id.as_str(),
                LauncherTerminalOutcomeV1::Refused,
                Some(2),
            )?;
            return Err(map_target_directory_error(error));
        }
    };

    // The service intentionally refuses here until V3 attestation and broker relay are complete.
    write_terminal(
        &mut stream,
        invocation_id.as_str(),
        LauncherTerminalOutcomeV1::Refused,
        Some(2),
    )?;
    let _retained_authority_inputs = (
        &loaded.ota_binary,
        repository.descriptor.as_raw_fd(),
        repository.logical_path.as_path(),
        repository.device,
        repository.inode,
    );
    Err(SystemdServiceError::ExecutionNotEnabled)
}

fn validate_requested_command(
    request: &LauncherInvocationRequestV1,
) -> Result<(), SystemdServiceError> {
    crate::validate_ota_args(&request.ota_arguments)
        .map_err(|_| SystemdServiceError::InvalidRequest)
}

fn map_target_directory_error(error: TargetDirectoryError) -> SystemdServiceError {
    match error {
        TargetDirectoryError::OutsideAllowedRoots => {
            SystemdServiceError::RepositoryOutsideAllowedRoots
        }
        _ => SystemdServiceError::RepositoryUnavailableToExecutionPrincipal,
    }
}

fn inherited_systemd_listener(
    expected_path: &Path,
    expected_group_gid: u32,
) -> Result<UnixListener, SystemdServiceError> {
    let expected_pid = unsafe { libc::getpid() }.to_string();
    if env::var("LISTEN_PID").ok().as_deref() != Some(expected_pid.as_str())
        || env::var("LISTEN_FDS").ok().as_deref() != Some("1")
    {
        return Err(SystemdServiceError::ListenerUnavailable);
    }
    set_cloexec(SYSTEMD_LISTEN_FD)?;
    verify_listener_socket(SYSTEMD_LISTEN_FD)?;
    // SAFETY: the descriptor was verified as a listening AF_UNIX stream and ownership transfers
    // once to the returned listener.
    let listener = unsafe { UnixListener::from_raw_fd(SYSTEMD_LISTEN_FD) };
    if listener
        .local_addr()
        .ok()
        .and_then(|address| address.as_pathname().map(Path::to_path_buf))
        != Some(expected_path.to_path_buf())
    {
        return Err(SystemdServiceError::ListenerUnavailable);
    }
    verify_listener_path(&listener, expected_path, expected_group_gid)?;
    Ok(listener)
}

fn verify_listener_path(
    listener: &UnixListener,
    expected_path: &Path,
    expected_group_gid: u32,
) -> Result<(), SystemdServiceError> {
    let metadata = std::fs::symlink_metadata(expected_path)
        .map_err(|_| SystemdServiceError::ListenerUnavailable)?;
    let mut opened: libc::stat = unsafe { std::mem::zeroed() };
    if unsafe { libc::fstat(listener.as_raw_fd(), &mut opened) } != 0 {
        return Err(SystemdServiceError::ListenerUnavailable);
    }
    if !metadata.file_type().is_socket()
        || metadata.uid() != 0
        || metadata.gid() != expected_group_gid
        || metadata.mode() & 0o7777 != 0o660
        || opened.st_mode & libc::S_IFMT != libc::S_IFSOCK
        || opened.st_uid != 0
        || !proc_unix_socket_matches_path(opened.st_ino, expected_path)
    {
        return Err(SystemdServiceError::ListenerUnavailable);
    }
    Ok(())
}

fn proc_unix_socket_matches_path(socket_inode: libc::ino_t, expected_path: &Path) -> bool {
    let Some(expected_path) = expected_path.to_str() else {
        return false;
    };
    let Ok(table) = std::fs::read_to_string("/proc/net/unix") else {
        return false;
    };
    let mut matching_paths = table.lines().skip(1).filter_map(|line| {
        let mut fields = line.split_whitespace();
        let inode = fields.nth(6)?;
        if fields.next() != Some(expected_path) {
            return None;
        }
        inode.parse::<libc::ino_t>().ok()
    });
    matching_paths.next() == Some(socket_inode) && matching_paths.next().is_none()
}

fn receive_request(
    stream: &mut UnixStream,
    maximum_request_bytes: usize,
) -> Result<LauncherInvocationRequestV1, SystemdServiceError> {
    let mut header = [0_u8; 4];
    stream
        .read_exact(&mut header)
        .map_err(|_| SystemdServiceError::InvalidRequest)?;
    let length = u32::from_be_bytes(header) as usize;
    if length == 0 || length > maximum_request_bytes || length > MAX_FRAME_BYTES {
        return Err(SystemdServiceError::InvalidRequest);
    }
    let mut frame = Vec::with_capacity(4 + length);
    frame.extend_from_slice(&header);
    frame.resize(4 + length, 0);
    stream
        .read_exact(&mut frame[4..])
        .map_err(|_| SystemdServiceError::InvalidRequest)?;
    let payload = decode_frame(&frame).map_err(|_| SystemdServiceError::InvalidRequest)?;
    let request =
        serde_json::from_slice(payload).map_err(|_| SystemdServiceError::InvalidRequest)?;
    validate_launcher_invocation_request_v1(&request)
        .map_err(|_| SystemdServiceError::InvalidRequest)?;
    Ok(request)
}

fn select_mapping<'a>(
    config: &'a SystemdLauncherServiceConfigV1,
    request: &LauncherInvocationRequestV1,
    peer: SessionPeer,
) -> Result<&'a crate::config::SystemdPrincipalMappingV1, SystemdServiceError> {
    config
        .mappings
        .iter()
        .find(|mapping| mapping.authority_id == request.authority_id && mapping.job_peer == peer)
        .ok_or(SystemdServiceError::PeerUnmapped)
}

fn peer_credentials(stream: &UnixStream) -> Result<SessionPeer, SystemdServiceError> {
    let mut credentials = libc::ucred {
        pid: 0,
        uid: 0,
        gid: 0,
    };
    let mut length = std::mem::size_of::<libc::ucred>() as libc::socklen_t;
    // SAFETY: `credentials` is a valid writable buffer and the stream owns a connected socket.
    let result = unsafe {
        libc::getsockopt(
            stream.as_raw_fd(),
            libc::SOL_SOCKET,
            libc::SO_PEERCRED,
            (&mut credentials as *mut libc::ucred).cast(),
            &mut length,
        )
    };
    if result != 0 || length != std::mem::size_of::<libc::ucred>() as libc::socklen_t {
        return Err(SystemdServiceError::PeerUnmapped);
    }
    Ok(SessionPeer {
        uid: credentials.uid,
        gid: credentials.gid,
    })
}

fn write_terminal(
    stream: &mut UnixStream,
    invocation_id: &str,
    outcome: LauncherTerminalOutcomeV1,
    exit_code: Option<i32>,
) -> Result<(), SystemdServiceError> {
    let terminal = LauncherTerminalFrameV1 {
        message_kind: LAUNCHER_TERMINAL.into(),
        protocol_version: SYSTEMD_LAUNCHER_SERVICE_PROTOCOL_V1.into(),
        invocation_id: invocation_id.into(),
        outcome,
        exit_code,
    };
    validate_launcher_terminal_frame_v1(&terminal)
        .map_err(|_| SystemdServiceError::InvalidRequest)?;
    let payload = serde_json::to_vec(&terminal).map_err(|_| SystemdServiceError::InvalidRequest)?;
    let frame =
        encode_frame(payload.as_slice()).map_err(|_| SystemdServiceError::InvalidRequest)?;
    stream
        .write_all(&frame)
        .map_err(|_| SystemdServiceError::InvalidRequest)
}

fn fresh_invocation_id() -> Result<String, SystemdServiceError> {
    let mut random = [0_u8; 16];
    getrandom::getrandom(&mut random).map_err(|_| SystemdServiceError::InvalidRequest)?;
    let mut identity = String::from("invocation-");
    for byte in random {
        use std::fmt::Write as _;
        write!(&mut identity, "{byte:02x}").expect("writing to String cannot fail");
    }
    Ok(identity)
}

fn set_cloexec(descriptor: RawFd) -> Result<(), SystemdServiceError> {
    // SAFETY: `fcntl` only reads and updates flags on the supplied descriptor.
    let flags = unsafe { libc::fcntl(descriptor, libc::F_GETFD) };
    if flags < 0 || unsafe { libc::fcntl(descriptor, libc::F_SETFD, flags | libc::FD_CLOEXEC) } < 0
    {
        return Err(SystemdServiceError::ListenerUnavailable);
    }
    Ok(())
}

fn verify_listener_socket(descriptor: RawFd) -> Result<(), SystemdServiceError> {
    let mut socket_type = 0_i32;
    let mut length = std::mem::size_of::<i32>() as libc::socklen_t;
    // SAFETY: `socket_type` is a valid writable buffer for `SO_TYPE`.
    let result = unsafe {
        libc::getsockopt(
            descriptor,
            libc::SOL_SOCKET,
            libc::SO_TYPE,
            (&mut socket_type as *mut i32).cast(),
            &mut length,
        )
    };
    if result != 0
        || socket_type != libc::SOCK_STREAM
        || length != std::mem::size_of::<i32>() as libc::socklen_t
    {
        return Err(SystemdServiceError::ListenerUnavailable);
    }
    let mut address: libc::sockaddr_storage = unsafe { std::mem::zeroed() };
    let mut address_length = std::mem::size_of::<libc::sockaddr_storage>() as libc::socklen_t;
    // SAFETY: `address` is a correctly sized writable address buffer for `getsockname`.
    let result = unsafe {
        libc::getsockname(
            descriptor,
            (&mut address as *mut libc::sockaddr_storage).cast(),
            &mut address_length,
        )
    };
    if result != 0 || address.ss_family as libc::c_int != libc::AF_UNIX {
        return Err(SystemdServiceError::ListenerUnavailable);
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use std::fs;
    use std::os::unix::ffi::OsStrExt;
    use std::os::unix::fs::PermissionsExt;

    use tempfile::tempdir;

    use super::*;

    #[test]
    fn unsupported_command_refuses_during_systemd_request_admission() {
        let request = LauncherInvocationRequestV1 {
            message_kind: ota_authority_protocol::LAUNCHER_INVOCATION_REQUEST.into(),
            protocol_version: SYSTEMD_LAUNCHER_SERVICE_PROTOCOL_V1.into(),
            authority_id: "release".into(),
            ota_arguments: vec!["self-update".into()],
            repository_path: "/srv/repositories/project".into(),
        };
        assert!(matches!(
            validate_requested_command(&request),
            Err(SystemdServiceError::InvalidRequest)
        ));
    }

    #[test]
    fn listener_path_must_reference_the_inherited_socket_inode() {
        if unsafe { libc::geteuid() } != 0 {
            return;
        }
        let temporary = tempdir().expect("temporary directory");
        let path = temporary.path().join("launcher.sock");
        let listener = UnixListener::bind(&path).expect("listener");
        let path_c = std::ffi::CString::new(path.as_os_str().as_bytes()).expect("path");
        assert_eq!(unsafe { libc::chown(path_c.as_ptr(), 0, 1001) }, 0);
        fs::set_permissions(&path, fs::Permissions::from_mode(0o660)).expect("permissions");
        assert!(verify_listener_path(&listener, &path, 1001).is_ok());

        fs::remove_file(&path).expect("unlink original listener");
        let replacement = UnixListener::bind(&path).expect("replacement listener");
        assert_eq!(unsafe { libc::chown(path_c.as_ptr(), 0, 1001) }, 0);
        fs::set_permissions(&path, fs::Permissions::from_mode(0o660)).expect("permissions");
        assert!(verify_listener_path(&listener, &path, 1001).is_err());
        drop(replacement);
    }
}
