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

//! Protected launcher client for the separately isolated V3 attestation producer.

use std::fs::OpenOptions;
use std::io::{BufReader, Read, Seek};
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd};
use std::os::unix::fs::{FileTypeExt, MetadataExt, OpenOptionsExt};
use std::path::Path;

use base64::Engine;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use ed25519_dalek::{Signature, Verifier, VerifyingKey};
use ota_authority_protocol::{
    ATTESTATION_RESPONSE_DOMAIN_V3, LauncherAttestationProducerBindingV1,
    LauncherAttestationSigningRequestV1, LauncherAttestationSigningResponseV1, domain_separated,
    launcher_attestation_claims_v3, launcher_attestation_claims_v3_identity,
    launcher_attestation_producer_binding_v1_identity,
    launcher_attestation_signing_response_v1_identity, sha256_identity,
    validate_launcher_attestation_producer_binding_v1,
    validate_launcher_attestation_signing_request_v1,
    validate_launcher_attestation_signing_response_v1,
};
use serde::Deserialize;
use sha2::{Digest, Sha256};
use thiserror::Error;
use time::OffsetDateTime;
use time::format_description::well_known::Rfc3339;
use zbus::blocking::{Proxy, connection::Builder};
use zbus::zvariant::OwnedObjectPath;

pub const SYSTEMD_ATTESTOR_CONFIG_PATH: &str = "/etc/ota/authority-attestor.json";

#[derive(Debug, Error, PartialEq, Eq)]
pub enum AttestationClientError {
    #[error("the protected attestation producer binding is unavailable")]
    BindingUnavailable,
    #[error("the protected attestation producer transport is unavailable")]
    TransportUnavailable,
    #[error("the protected attestation producer response is invalid")]
    InvalidResponse,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct AttestorConfigV1 {
    schema_version: u32,
    binding: LauncherAttestationProducerBindingV1,
}

pub fn load_producer_binding()
-> Result<LauncherAttestationProducerBindingV1, AttestationClientError> {
    let file = open_protected_file(Path::new(SYSTEMD_ATTESTOR_CONFIG_PATH))
        .map_err(|_| AttestationClientError::BindingUnavailable)?;
    let config: AttestorConfigV1 = serde_json::from_reader(BufReader::new(file))
        .map_err(|_| AttestationClientError::BindingUnavailable)?;
    if config.schema_version != 1
        || validate_launcher_attestation_producer_binding_v1(&config.binding).is_err()
        || launcher_attestation_producer_binding_v1_identity(&config.binding)
            .map_err(|_| AttestationClientError::BindingUnavailable)?
            != config.binding.identity
    {
        return Err(AttestationClientError::BindingUnavailable);
    }
    decode_verifying_key(&config.binding)?;
    Ok(config.binding)
}

pub fn request_attestation(
    binding: &LauncherAttestationProducerBindingV1,
    request: &LauncherAttestationSigningRequestV1,
    now: OffsetDateTime,
) -> Result<LauncherAttestationSigningResponseV1, AttestationClientError> {
    validate_launcher_attestation_signing_request_v1(request)
        .map_err(|_| AttestationClientError::InvalidResponse)?;
    if request.producer_binding_identity != binding.identity {
        return Err(AttestationClientError::InvalidResponse);
    }
    let (connection, peer) = connect_seqpacket(binding)?;
    revalidate_peer(&connection, &peer, binding)?;
    let request_bytes =
        serde_jcs::to_vec(request).map_err(|_| AttestationClientError::InvalidResponse)?;
    send_packet(&connection, &request_bytes)?;
    let response_bytes = receive_packet(&connection, binding.maximum_request_bytes)?;
    revalidate_peer(&connection, &peer, binding)?;
    reject_queued_packet(&connection)?;
    let response: LauncherAttestationSigningResponseV1 = serde_json::from_slice(&response_bytes)
        .map_err(|_| AttestationClientError::InvalidResponse)?;
    if serde_jcs::to_vec(&response).map_err(|_| AttestationClientError::InvalidResponse)?
        != response_bytes
    {
        return Err(AttestationClientError::InvalidResponse);
    }
    verify_response(binding, request, &response, now)?;
    Ok(response)
}

pub fn verify_response(
    binding: &LauncherAttestationProducerBindingV1,
    request: &LauncherAttestationSigningRequestV1,
    response: &LauncherAttestationSigningResponseV1,
    now: OffsetDateTime,
) -> Result<(), AttestationClientError> {
    validate_launcher_attestation_signing_response_v1(response)
        .map_err(|_| AttestationClientError::InvalidResponse)?;
    if response.response_identity
        != launcher_attestation_signing_response_v1_identity(response)
            .map_err(|_| AttestationClientError::InvalidResponse)?
        || response.request_identity != request.request_identity
        || response.claims_identity != request.claims_identity
        || launcher_attestation_claims_v3(&response.attestation) != request.claims
        || launcher_attestation_claims_v3_identity(&launcher_attestation_claims_v3(
            &response.attestation,
        ))
        .map_err(|_| AttestationClientError::InvalidResponse)?
            != request.claims_identity
        || response.attestation.key_id != binding.signing_key_id
        || response.attestation.algorithm != "ed25519"
        || response.attestation.payload.issuer != binding.issuer
        || response.attestation.payload.audience != binding.audience
    {
        return Err(AttestationClientError::InvalidResponse);
    }
    let issued_at = OffsetDateTime::parse(&response.attestation.payload.issued_at, &Rfc3339)
        .map_err(|_| AttestationClientError::InvalidResponse)?;
    let expires_at = OffsetDateTime::parse(&response.attestation.payload.expires_at, &Rfc3339)
        .map_err(|_| AttestationClientError::InvalidResponse)?;
    let key_not_before = OffsetDateTime::parse(&binding.signing_key_not_before, &Rfc3339)
        .map_err(|_| AttestationClientError::InvalidResponse)?;
    let key_not_after = OffsetDateTime::parse(&binding.signing_key_not_after, &Rfc3339)
        .map_err(|_| AttestationClientError::InvalidResponse)?;
    let maximum_age = binding
        .maximum_attestation_age_seconds
        .min(binding.verifier_maximum_age_seconds)
        .min(request.requested_maximum_validity_seconds);
    if issued_at < key_not_before
        || expires_at > key_not_after
        || issued_at > now
        || expires_at <= now
        || expires_at <= issued_at
        || expires_at - issued_at > time::Duration::seconds(maximum_age as i64)
    {
        return Err(AttestationClientError::InvalidResponse);
    }
    let payload = serde_jcs::to_vec(&response.attestation.payload)
        .map_err(|_| AttestationClientError::InvalidResponse)?;
    let signature = URL_SAFE_NO_PAD
        .decode(&response.attestation.signature)
        .ok()
        .and_then(|bytes| Signature::from_slice(&bytes).ok())
        .ok_or(AttestationClientError::InvalidResponse)?;
    decode_verifying_key(binding)?
        .verify(
            &domain_separated(ATTESTATION_RESPONSE_DOMAIN_V3.as_bytes(), &payload),
            &signature,
        )
        .map_err(|_| AttestationClientError::InvalidResponse)
}

fn decode_verifying_key(
    binding: &LauncherAttestationProducerBindingV1,
) -> Result<VerifyingKey, AttestationClientError> {
    let bytes = URL_SAFE_NO_PAD
        .decode(&binding.signing_public_key)
        .map_err(|_| AttestationClientError::BindingUnavailable)?;
    let bytes: [u8; 32] = bytes
        .try_into()
        .map_err(|_| AttestationClientError::BindingUnavailable)?;
    if sha256_identity(&bytes) != binding.signing_public_key_identity {
        return Err(AttestationClientError::BindingUnavailable);
    }
    VerifyingKey::from_bytes(&bytes).map_err(|_| AttestationClientError::BindingUnavailable)
}

fn connect_seqpacket(
    binding: &LauncherAttestationProducerBindingV1,
) -> Result<(OwnedFd, ObservedPeer), AttestationClientError> {
    let path = Path::new(&binding.socket_path);
    let metadata = std::fs::symlink_metadata(path)
        .map_err(|_| AttestationClientError::TransportUnavailable)?;
    if !metadata.file_type().is_socket() || metadata.uid() != 0 || metadata.mode() & 0o022 != 0 {
        return Err(AttestationClientError::TransportUnavailable);
    }
    let descriptor =
        unsafe { libc::socket(libc::AF_UNIX, libc::SOCK_SEQPACKET | libc::SOCK_CLOEXEC, 0) };
    if descriptor < 0 {
        return Err(AttestationClientError::TransportUnavailable);
    }
    // SAFETY: socket returned a new owned descriptor.
    let connection = unsafe { OwnedFd::from_raw_fd(descriptor) };
    let (address, length) = unix_address(path)?;
    if unsafe {
        libc::connect(
            connection.as_raw_fd(),
            std::ptr::addr_of!(address).cast(),
            length,
        )
    } != 0
    {
        return Err(AttestationClientError::TransportUnavailable);
    }
    set_timeouts(&connection, binding.read_write_timeout_seconds)?;
    let peer = observe_peer(&connection, binding)?;
    Ok((connection, peer))
}

fn unix_address(
    path: &Path,
) -> Result<(libc::sockaddr_un, libc::socklen_t), AttestationClientError> {
    let bytes = path.as_os_str().as_encoded_bytes();
    let mut address: libc::sockaddr_un = unsafe { std::mem::zeroed() };
    if bytes.is_empty() || bytes.len() >= address.sun_path.len() || bytes.contains(&0) {
        return Err(AttestationClientError::TransportUnavailable);
    }
    address.sun_family = libc::AF_UNIX as libc::sa_family_t;
    for (target, source) in address.sun_path.iter_mut().zip(bytes.iter().copied()) {
        *target = source as libc::c_char;
    }
    let length = std::mem::size_of::<libc::sa_family_t>() + bytes.len() + 1;
    Ok((address, length as libc::socklen_t))
}

fn set_timeouts(connection: &OwnedFd, seconds: u64) -> Result<(), AttestationClientError> {
    let timeout = libc::timeval {
        tv_sec: i64::try_from(seconds).map_err(|_| AttestationClientError::TransportUnavailable)?,
        tv_usec: 0,
    };
    for option in [libc::SO_RCVTIMEO, libc::SO_SNDTIMEO] {
        if unsafe {
            libc::setsockopt(
                connection.as_raw_fd(),
                libc::SOL_SOCKET,
                option,
                std::ptr::addr_of!(timeout).cast(),
                std::mem::size_of::<libc::timeval>() as libc::socklen_t,
            )
        } != 0
        {
            return Err(AttestationClientError::TransportUnavailable);
        }
    }
    Ok(())
}

#[derive(Debug)]
struct ObservedPeer {
    pidfd: OwnedFd,
    pid: libc::pid_t,
    uid: u32,
    gid: u32,
    process_start_identity: String,
    executable_identity: String,
    unit_object_path: String,
    control_group: String,
}

fn observe_peer(
    connection: &OwnedFd,
    binding: &LauncherAttestationProducerBindingV1,
) -> Result<ObservedPeer, AttestationClientError> {
    let mut credentials: libc::ucred = unsafe { std::mem::zeroed() };
    let mut length = std::mem::size_of::<libc::ucred>() as libc::socklen_t;
    if unsafe {
        libc::getsockopt(
            connection.as_raw_fd(),
            libc::SOL_SOCKET,
            libc::SO_PEERCRED,
            std::ptr::addr_of_mut!(credentials).cast(),
            &mut length,
        )
    } != 0
        || credentials.uid != 0
        || credentials.gid != 0
        || credentials.pid <= 0
    {
        return Err(AttestationClientError::TransportUnavailable);
    }
    let pidfd = socket_peer_pidfd(connection)?;
    require_live_pidfd(&pidfd)?;
    let process_start_identity = process_start_identity(credentials.pid)?;
    let executable_identity = process_executable_identity(credentials.pid)?;
    if executable_identity != binding.producer_executable_identity {
        return Err(AttestationClientError::TransportUnavailable);
    }
    let (unit_object_path, control_group) = systemd_unit_for_pid(credentials.pid, binding)?;
    Ok(ObservedPeer {
        pidfd,
        pid: credentials.pid,
        uid: credentials.uid,
        gid: credentials.gid,
        process_start_identity,
        executable_identity,
        unit_object_path,
        control_group,
    })
}

fn revalidate_peer(
    connection: &OwnedFd,
    expected: &ObservedPeer,
    binding: &LauncherAttestationProducerBindingV1,
) -> Result<(), AttestationClientError> {
    require_live_pidfd(&expected.pidfd)?;
    let mut credentials: libc::ucred = unsafe { std::mem::zeroed() };
    let mut length = std::mem::size_of::<libc::ucred>() as libc::socklen_t;
    if unsafe {
        libc::getsockopt(
            connection.as_raw_fd(),
            libc::SOL_SOCKET,
            libc::SO_PEERCRED,
            std::ptr::addr_of_mut!(credentials).cast(),
            &mut length,
        )
    } != 0
        || credentials.pid != expected.pid
        || credentials.uid != expected.uid
        || credentials.gid != expected.gid
        || process_start_identity(expected.pid)? != expected.process_start_identity
        || process_executable_identity(expected.pid)? != expected.executable_identity
        || systemd_unit_for_pid(expected.pid, binding)?
            != (
                expected.unit_object_path.clone(),
                expected.control_group.clone(),
            )
    {
        return Err(AttestationClientError::TransportUnavailable);
    }
    require_live_pidfd(&expected.pidfd)
}

fn socket_peer_pidfd(connection: &OwnedFd) -> Result<OwnedFd, AttestationClientError> {
    const SO_PEERPIDFD: libc::c_int = 77;
    let mut descriptor = -1_i32;
    let mut length = std::mem::size_of::<i32>() as libc::socklen_t;
    if unsafe {
        libc::getsockopt(
            connection.as_raw_fd(),
            libc::SOL_SOCKET,
            SO_PEERPIDFD,
            std::ptr::addr_of_mut!(descriptor).cast(),
            &mut length,
        )
    } != 0
        || descriptor < 0
        || unsafe { libc::fcntl(descriptor, libc::F_SETFD, libc::FD_CLOEXEC) } != 0
    {
        if descriptor >= 0 {
            unsafe { libc::close(descriptor) };
        }
        return Err(AttestationClientError::TransportUnavailable);
    }
    // SAFETY: SO_PEERPIDFD returned a new descriptor owned by this process.
    Ok(unsafe { OwnedFd::from_raw_fd(descriptor) })
}

fn require_live_pidfd(pidfd: &OwnedFd) -> Result<(), AttestationClientError> {
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
        return Err(AttestationClientError::TransportUnavailable);
    }
    Ok(())
}

fn process_start_identity(pid: libc::pid_t) -> Result<String, AttestationClientError> {
    let stat = std::fs::read_to_string(format!("/proc/{pid}/stat"))
        .map_err(|_| AttestationClientError::TransportUnavailable)?;
    let closing = stat
        .rfind(')')
        .ok_or(AttestationClientError::TransportUnavailable)?;
    let start_time = stat[closing + 1..]
        .split_whitespace()
        .nth(19)
        .ok_or(AttestationClientError::TransportUnavailable)?;
    Ok(sha256_identity(
        format!("pid:{pid};start_time:{start_time}").as_bytes(),
    ))
}

fn process_executable_identity(pid: libc::pid_t) -> Result<String, AttestationClientError> {
    let mut executable = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_CLOEXEC)
        .open(format!("/proc/{pid}/exe"))
        .map_err(|_| AttestationClientError::TransportUnavailable)?;
    executable
        .rewind()
        .map_err(|_| AttestationClientError::TransportUnavailable)?;
    let mut digest = Sha256::new();
    let mut buffer = [0_u8; 16 * 1024];
    loop {
        let read = executable
            .read(&mut buffer)
            .map_err(|_| AttestationClientError::TransportUnavailable)?;
        if read == 0 {
            break;
        }
        digest.update(&buffer[..read]);
    }
    Ok(format!("sha256:{:x}", digest.finalize()))
}

fn systemd_unit_for_pid(
    pid: libc::pid_t,
    binding: &LauncherAttestationProducerBindingV1,
) -> Result<(String, String), AttestationClientError> {
    const SYSTEM_BUS_ADDRESS: &str = "unix:path=/run/dbus/system_bus_socket";
    const SYSTEMD_SERVICE: &str = "org.freedesktop.systemd1";
    const SYSTEMD_MANAGER_PATH: &str = "/org/freedesktop/systemd1";
    const SYSTEMD_MANAGER_INTERFACE: &str = "org.freedesktop.systemd1.Manager";
    const SYSTEMD_UNIT_INTERFACE: &str = "org.freedesktop.systemd1.Unit";
    let connection = Builder::address(SYSTEM_BUS_ADDRESS)
        .and_then(Builder::build)
        .map_err(|_| AttestationClientError::TransportUnavailable)?;
    let manager = Proxy::new(
        &connection,
        SYSTEMD_SERVICE,
        SYSTEMD_MANAGER_PATH,
        SYSTEMD_MANAGER_INTERFACE,
    )
    .map_err(|_| AttestationClientError::TransportUnavailable)?;
    let unit_path: OwnedObjectPath = manager
        .call("GetUnitByPID", &(pid as u32,))
        .map_err(|_| AttestationClientError::TransportUnavailable)?;
    let unit = Proxy::new(
        &connection,
        SYSTEMD_SERVICE,
        unit_path.as_str(),
        SYSTEMD_UNIT_INTERFACE,
    )
    .map_err(|_| AttestationClientError::TransportUnavailable)?;
    let id: String = unit
        .get_property("Id")
        .map_err(|_| AttestationClientError::TransportUnavailable)?;
    let control_group: String = unit
        .get_property("ControlGroup")
        .map_err(|_| AttestationClientError::TransportUnavailable)?;
    if id != binding.service_unit || control_group.is_empty() {
        return Err(AttestationClientError::TransportUnavailable);
    }
    let proc_cgroup = std::fs::read_to_string(format!("/proc/{pid}/cgroup"))
        .map_err(|_| AttestationClientError::TransportUnavailable)?;
    if !proc_cgroup
        .lines()
        .any(|line| line.strip_prefix("0::") == Some(control_group.as_str()))
    {
        return Err(AttestationClientError::TransportUnavailable);
    }
    Ok((unit_path.to_string(), control_group))
}

fn send_packet(connection: &OwnedFd, bytes: &[u8]) -> Result<(), AttestationClientError> {
    let written = unsafe {
        libc::send(
            connection.as_raw_fd(),
            bytes.as_ptr().cast(),
            bytes.len(),
            libc::MSG_NOSIGNAL,
        )
    };
    if written < 0 || written as usize != bytes.len() {
        return Err(AttestationClientError::TransportUnavailable);
    }
    Ok(())
}

fn receive_packet(connection: &OwnedFd, maximum: usize) -> Result<Vec<u8>, AttestationClientError> {
    let mut buffer = vec![0_u8; maximum];
    let mut control = [0_u8; 64];
    let mut vector = libc::iovec {
        iov_base: buffer.as_mut_ptr().cast(),
        iov_len: buffer.len(),
    };
    let mut message: libc::msghdr = unsafe { std::mem::zeroed() };
    message.msg_iov = std::ptr::addr_of_mut!(vector);
    message.msg_iovlen = 1;
    message.msg_control = control.as_mut_ptr().cast();
    message.msg_controllen = control.len();
    let observed = unsafe {
        libc::recvmsg(
            connection.as_raw_fd(),
            &mut message,
            libc::MSG_TRUNC | libc::MSG_CMSG_CLOEXEC,
        )
    };
    if observed <= 0
        || observed as usize > maximum
        || message.msg_flags & (libc::MSG_TRUNC | libc::MSG_CTRUNC) != 0
        || message.msg_controllen != 0
    {
        return Err(AttestationClientError::TransportUnavailable);
    }
    buffer.truncate(observed as usize);
    Ok(buffer)
}

fn reject_queued_packet(connection: &OwnedFd) -> Result<(), AttestationClientError> {
    let mut byte = 0_u8;
    let observed = unsafe {
        libc::recv(
            connection.as_raw_fd(),
            std::ptr::addr_of_mut!(byte).cast(),
            1,
            libc::MSG_PEEK | libc::MSG_DONTWAIT | libc::MSG_TRUNC,
        )
    };
    if observed > 0 {
        return Err(AttestationClientError::TransportUnavailable);
    }
    if observed < 0 && std::io::Error::last_os_error().raw_os_error() != Some(libc::EAGAIN) {
        return Err(AttestationClientError::TransportUnavailable);
    }
    Ok(())
}

fn open_protected_file(path: &Path) -> Result<std::fs::File, AttestationClientError> {
    if !path.is_absolute() {
        return Err(AttestationClientError::BindingUnavailable);
    }
    verify_protected_parents(
        path.parent()
            .ok_or(AttestationClientError::BindingUnavailable)?,
    )?;
    let metadata =
        std::fs::symlink_metadata(path).map_err(|_| AttestationClientError::BindingUnavailable)?;
    if !metadata.is_file() || metadata.uid() != 0 || metadata.mode() & 0o022 != 0 {
        return Err(AttestationClientError::BindingUnavailable);
    }
    let file = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_CLOEXEC | libc::O_NOFOLLOW)
        .open(path)
        .map_err(|_| AttestationClientError::BindingUnavailable)?;
    let opened = file
        .metadata()
        .map_err(|_| AttestationClientError::BindingUnavailable)?;
    if opened.dev() != metadata.dev() || opened.ino() != metadata.ino() {
        return Err(AttestationClientError::BindingUnavailable);
    }
    Ok(file)
}

fn verify_protected_parents(path: &Path) -> Result<(), AttestationClientError> {
    let mut current = Some(path);
    while let Some(parent) = current {
        let metadata = std::fs::symlink_metadata(parent)
            .map_err(|_| AttestationClientError::BindingUnavailable)?;
        if !metadata.is_dir() || metadata.uid() != 0 || metadata.mode() & 0o022 != 0 {
            return Err(AttestationClientError::BindingUnavailable);
        }
        current = parent.parent();
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn producer_peer_pidfd_is_socket_bound_cloexec_and_fail_closed() {
        let (client, producer) = seqpacket_pair();
        let pidfd = socket_peer_pidfd(&client).expect("socket-bound producer pidfd");
        require_live_pidfd(&pidfd).expect("producer remains live");
        assert_ne!(
            unsafe { libc::fcntl(pidfd.as_raw_fd(), libc::F_GETFD) } & libc::FD_CLOEXEC,
            0
        );

        let file = std::fs::File::open("/dev/null").expect("ordinary descriptor");
        let file = OwnedFd::from(file);
        assert!(matches!(
            socket_peer_pidfd(&file),
            Err(AttestationClientError::TransportUnavailable)
        ));
        drop(producer);
    }

    #[test]
    fn producer_client_rejects_an_additional_queued_response() {
        let (client, producer) = seqpacket_pair();
        send_packet(&producer, b"first").expect("first response");
        send_packet(&producer, b"second").expect("second response");
        assert_eq!(receive_packet(&client, 16).expect("first packet"), b"first");
        assert_eq!(
            reject_queued_packet(&client),
            Err(AttestationClientError::TransportUnavailable)
        );
    }

    #[test]
    fn socket_bound_pidfd_reports_connected_peer_exit() {
        let directory = tempfile::tempdir().expect("socket directory");
        let socket_path = directory.path().join("producer.sock");
        let listener =
            unsafe { libc::socket(libc::AF_UNIX, libc::SOCK_SEQPACKET | libc::SOCK_CLOEXEC, 0) };
        assert!(listener >= 0);
        let listener = unsafe { OwnedFd::from_raw_fd(listener) };
        let (address, length) = unix_address(&socket_path).expect("socket address");
        assert_eq!(
            unsafe {
                libc::bind(
                    listener.as_raw_fd(),
                    std::ptr::addr_of!(address).cast(),
                    length,
                )
            },
            0
        );
        assert_eq!(unsafe { libc::listen(listener.as_raw_fd(), 1) }, 0);

        let child = unsafe { libc::fork() };
        assert!(child >= 0);
        if child == 0 {
            let client = unsafe {
                libc::socket(libc::AF_UNIX, libc::SOCK_SEQPACKET | libc::SOCK_CLOEXEC, 0)
            };
            if client < 0
                || unsafe { libc::connect(client, std::ptr::addr_of!(address).cast(), length) } != 0
            {
                unsafe { libc::_exit(2) };
            }
            unsafe {
                libc::pause();
                libc::_exit(0);
            }
        }

        let connection = unsafe {
            libc::accept4(
                listener.as_raw_fd(),
                std::ptr::null_mut(),
                std::ptr::null_mut(),
                libc::SOCK_CLOEXEC,
            )
        };
        assert!(connection >= 0);
        let connection = unsafe { OwnedFd::from_raw_fd(connection) };
        let pidfd = socket_peer_pidfd(&connection).expect("child peer pidfd");
        require_live_pidfd(&pidfd).expect("child is live");
        assert_eq!(unsafe { libc::kill(child, libc::SIGKILL) }, 0);
        let mut status = 0;
        assert_eq!(unsafe { libc::waitpid(child, &mut status, 0) }, child);
        assert_eq!(
            require_live_pidfd(&pidfd),
            Err(AttestationClientError::TransportUnavailable)
        );
    }

    fn seqpacket_pair() -> (OwnedFd, OwnedFd) {
        let mut descriptors = [-1_i32; 2];
        assert_eq!(
            unsafe {
                libc::socketpair(
                    libc::AF_UNIX,
                    libc::SOCK_SEQPACKET | libc::SOCK_CLOEXEC,
                    0,
                    descriptors.as_mut_ptr(),
                )
            },
            0
        );
        // SAFETY: socketpair initialized two distinct owned descriptors.
        unsafe {
            (
                OwnedFd::from_raw_fd(descriptors[0]),
                OwnedFd::from_raw_fd(descriptors[1]),
            )
        }
    }
}
