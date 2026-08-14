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

//! Production unprivileged client for the fixed systemd protected-launcher socket.

use std::fs;
use std::io::{Read, Write};
use std::os::fd::AsRawFd;
use std::os::unix::fs::{FileTypeExt, MetadataExt, PermissionsExt};
use std::os::unix::net::UnixStream;
use std::path::{Path, PathBuf};
use std::time::Duration;

use ota_authority_protocol::{
    LAUNCHER_FINALIZATION_ARCHIVE_PERSISTENCE, LAUNCHER_FINALIZATION_ARCHIVE_REQUEST,
    LAUNCHER_FINALIZATION_RECOVERY_REQUEST, LAUNCHER_INVOCATION_REQUEST, LAUNCHER_OUTPUT,
    LAUNCHER_SIGNED_EXECUTION_FINALIZATION, LAUNCHER_TERMINAL, LAUNCHER_TERMINAL_PERSISTENCE,
    LauncherFinalizationArchivePersistenceV1, LauncherFinalizationArchiveRequestV1,
    LauncherFinalizationArchiveResponseV1, LauncherFinalizationRecoveryRequestV1,
    LauncherInvocationRequestV1, LauncherOutputFrameV1, LauncherOutputStreamV1,
    LauncherSignedExecutionFinalizationFrameV1, LauncherTerminalFrameV1,
    LauncherTerminalPersistenceV1, MAX_FRAME_BYTES, SYSTEMD_LAUNCHER_SERVICE_PROTOCOL_V1,
    decode_frame, encode_frame, launcher_finalization_archive_persistence_v1_identity,
    launcher_finalization_archive_request_v1_identity,
    launcher_finalization_archive_response_v1_identity,
    launcher_finalization_recovery_request_v1_identity, launcher_invocation_request_identity,
    launcher_terminal_frame_v1_identity, launcher_terminal_persistence_v1_identity,
    validate_launcher_invocation_request_v1, validate_launcher_output_frame_v1,
    validate_launcher_signed_execution_finalization_frame_v1, validate_launcher_terminal_frame_v1,
};
use serde::Serialize;
use thiserror::Error;

pub const SYSTEMD_LAUNCHER_SOCKET: &str = "/run/ota/authority-launcher.sock";
const IO_TIMEOUT: Duration = Duration::from_secs(10);

#[derive(Debug, Clone)]
pub struct InvocationRequest {
    pub authority_id: String,
    pub repository: PathBuf,
    pub ota_arguments: Vec<String>,
}

#[derive(Debug, Clone, Serialize)]
pub struct InvocationResult {
    pub ok: bool,
    pub request_identity: String,
    pub output_complete: bool,
    pub terminal: LauncherTerminalFrameV1,
}

#[derive(Debug, Error, Clone, PartialEq, Eq)]
pub enum ClientError {
    #[error("the invocation request is invalid")]
    Usage,
    #[error("the protected launcher client boundary is unavailable")]
    LocalBoundary,
    #[error("the protected launcher service is unavailable")]
    ServiceUnavailable,
    #[error("the protected launcher protocol is invalid")]
    Protocol,
    #[error("the protected launcher output is incomplete")]
    OutputIncomplete,
}

impl ClientError {
    pub fn exit_code(&self) -> u8 {
        match self {
            Self::Usage => 64,
            Self::LocalBoundary | Self::Protocol => 70,
            Self::ServiceUnavailable | Self::OutputIncomplete => 75,
        }
    }

    pub fn reason_code(&self) -> &'static str {
        match self {
            Self::Usage => "invalid_invocation",
            Self::LocalBoundary => "client_boundary_unavailable",
            Self::ServiceUnavailable => "launcher_service_unavailable",
            Self::Protocol => "launcher_protocol_invalid",
            Self::OutputIncomplete => "output_incomplete",
        }
    }

    pub fn execution_started(&self) -> Option<bool> {
        match self {
            Self::Usage | Self::LocalBoundary => Some(false),
            Self::OutputIncomplete => Some(true),
            Self::ServiceUnavailable | Self::Protocol => None,
        }
    }
}

pub fn invoke(request: InvocationRequest) -> Result<InvocationResult, ClientError> {
    let mut stdout = std::io::stdout().lock();
    let mut stderr = std::io::stderr().lock();
    invoke_with_writers(request, &mut stdout, &mut stderr)
}

fn invoke_with_writers(
    request: InvocationRequest,
    stdout: &mut impl Write,
    stderr: &mut impl Write,
) -> Result<InvocationResult, ClientError> {
    validate_authority_label(&request.authority_id)?;
    validate_ota_arguments(&request.ota_arguments)?;
    let repository = request
        .repository
        .canonicalize()
        .map_err(|_| ClientError::Usage)?;
    let invocation = LauncherInvocationRequestV1 {
        message_kind: LAUNCHER_INVOCATION_REQUEST.into(),
        protocol_version: SYSTEMD_LAUNCHER_SERVICE_PROTOCOL_V1.into(),
        authority_id: request.authority_id.clone(),
        ota_arguments: request.ota_arguments,
        repository_path: repository.to_string_lossy().into_owned(),
    };
    validate_launcher_invocation_request_v1(&invocation).map_err(|_| ClientError::Usage)?;
    let request_identity =
        launcher_invocation_request_identity(&invocation).map_err(|_| ClientError::Usage)?;
    let mut stream = connect_fixed_launcher()?;
    write_typed_frame(&mut stream, &invocation)?;
    match read_session(
        &mut stream,
        &request.authority_id,
        &request_identity,
        stdout,
        stderr,
    ) {
        Ok(terminal) => Ok(InvocationResult {
            ok: terminal.exit_code == Some(0),
            request_identity,
            output_complete: true,
            terminal,
        }),
        Err(ClientError::ServiceUnavailable | ClientError::OutputIncomplete) => {
            let terminal = recover_finalization(&request.authority_id, &request_identity)?;
            Err(if terminal.finalization.is_some() {
                ClientError::OutputIncomplete
            } else {
                ClientError::ServiceUnavailable
            })
        }
        Err(error) => Err(error),
    }
}

fn read_session(
    stream: &mut UnixStream,
    authority_id: &str,
    request_identity: &str,
    stdout: &mut impl Write,
    stderr: &mut impl Write,
) -> Result<LauncherTerminalFrameV1, ClientError> {
    let mut next_sequence = 0_u64;
    let mut signed_finalization = None;
    loop {
        let value: serde_json::Value = read_typed_frame(stream)?;
        match value
            .get("message_kind")
            .and_then(serde_json::Value::as_str)
        {
            Some(LAUNCHER_OUTPUT) => {
                let output: LauncherOutputFrameV1 =
                    serde_json::from_value(value).map_err(|_| ClientError::Protocol)?;
                validate_launcher_output_frame_v1(&output).map_err(|_| ClientError::Protocol)?;
                if output.sequence != next_sequence {
                    return Err(ClientError::Protocol);
                }
                next_sequence = next_sequence.checked_add(1).ok_or(ClientError::Protocol)?;
                match output.stream {
                    LauncherOutputStreamV1::Stdout => stdout.write_all(&output.payload),
                    LauncherOutputStreamV1::Stderr => stderr.write_all(&output.payload),
                }
                .and_then(|()| stdout.flush())
                .and_then(|()| stderr.flush())
                .map_err(|_| ClientError::LocalBoundary)?;
            }
            Some(LAUNCHER_SIGNED_EXECUTION_FINALIZATION) => {
                if signed_finalization.is_some() {
                    return Err(ClientError::Protocol);
                }
                let frame: LauncherSignedExecutionFinalizationFrameV1 =
                    serde_json::from_value(value).map_err(|_| ClientError::Protocol)?;
                validate_launcher_signed_execution_finalization_frame_v1(&frame)
                    .map_err(|_| ClientError::Protocol)?;
                acknowledge_archive(stream, authority_id, request_identity, &frame)?;
                signed_finalization = Some(frame);
            }
            Some(LAUNCHER_TERMINAL) => {
                let terminal: LauncherTerminalFrameV1 =
                    serde_json::from_value(value).map_err(|_| ClientError::Protocol)?;
                validate_launcher_terminal_frame_v1(&terminal)
                    .map_err(|_| ClientError::Protocol)?;
                let finalization_matches = match (&terminal.finalization, &signed_finalization) {
                    (Some(finalization), Some(frame)) => {
                        &frame.signed_finalization.finalization == finalization
                            && frame.invocation_id == terminal.invocation_id
                    }
                    (None, None) => true,
                    _ => false,
                };
                if !finalization_matches {
                    return Err(ClientError::Protocol);
                }
                reject_queued_trailing_frame(stream)?;
                acknowledge_terminal(stream, &terminal)?;
                return Ok(terminal);
            }
            _ => return Err(ClientError::Protocol),
        }
    }
}

fn acknowledge_archive(
    stream: &mut UnixStream,
    authority_id: &str,
    launcher_request_identity: &str,
    frame: &LauncherSignedExecutionFinalizationFrameV1,
) -> Result<(), ClientError> {
    let completion = &frame.signed_finalization.finalization.completion;
    let mut request = LauncherFinalizationArchiveRequestV1 {
        schema_version: 1,
        message_kind: LAUNCHER_FINALIZATION_ARCHIVE_REQUEST.into(),
        request_identity: String::new(),
        authority_id: authority_id.into(),
        launcher_request_identity: launcher_request_identity.into(),
        receipt_archive_identity: completion
            .receipt_archive_identity
            .clone()
            .ok_or(ClientError::Protocol)?,
        crossing_transaction_identity: completion.crossing_transaction_identity.clone(),
        signed_finalization_identity: Some(frame.signed_finalization.identity.clone()),
    };
    request.request_identity = launcher_finalization_archive_request_v1_identity(&request)
        .map_err(|_| ClientError::Protocol)?;
    write_typed_frame(stream, &request)?;
    let response: LauncherFinalizationArchiveResponseV1 = read_typed_frame(stream)?;
    if launcher_finalization_archive_response_v1_identity(&response)
        .map_err(|_| ClientError::Protocol)?
        != response.response_identity
        || response.request_identity != request.request_identity
        || response.invocation_id != frame.invocation_id
        || response.sidecar.signed_finalization != frame.signed_finalization
        || response.sidecar.signed_archive.receipt_archive_identity
            != request.receipt_archive_identity
        || response
            .sidecar
            .signed_archive
            .crossing_transaction_identity
            != request.crossing_transaction_identity
    {
        return Err(ClientError::Protocol);
    }
    let mut persistence = LauncherFinalizationArchivePersistenceV1 {
        schema_version: 1,
        message_kind: LAUNCHER_FINALIZATION_ARCHIVE_PERSISTENCE.into(),
        identity: String::new(),
        request_identity: request.request_identity,
        sidecar_identity: response.sidecar.identity,
    };
    persistence.identity = launcher_finalization_archive_persistence_v1_identity(&persistence)
        .map_err(|_| ClientError::Protocol)?;
    write_typed_frame(stream, &persistence)
}

fn recover_finalization(
    authority_id: &str,
    launcher_request_identity: &str,
) -> Result<LauncherTerminalFrameV1, ClientError> {
    let mut request = LauncherFinalizationRecoveryRequestV1 {
        schema_version: 1,
        message_kind: LAUNCHER_FINALIZATION_RECOVERY_REQUEST.into(),
        request_identity: String::new(),
        authority_id: authority_id.into(),
        launcher_request_identity: launcher_request_identity.into(),
    };
    request.request_identity = launcher_finalization_recovery_request_v1_identity(&request)
        .map_err(|_| ClientError::Protocol)?;
    let mut stream = connect_fixed_launcher()?;
    write_typed_frame(&mut stream, &request)?;
    let frame: LauncherSignedExecutionFinalizationFrameV1 = read_typed_frame(&mut stream)?;
    validate_launcher_signed_execution_finalization_frame_v1(&frame)
        .map_err(|_| ClientError::Protocol)?;
    acknowledge_archive(&mut stream, authority_id, launcher_request_identity, &frame)?;
    let terminal: LauncherTerminalFrameV1 = read_typed_frame(&mut stream)?;
    validate_launcher_terminal_frame_v1(&terminal).map_err(|_| ClientError::Protocol)?;
    if terminal.finalization.as_ref() != Some(&frame.signed_finalization.finalization) {
        return Err(ClientError::Protocol);
    }
    acknowledge_terminal(&mut stream, &terminal)?;
    Ok(terminal)
}

fn acknowledge_terminal(
    stream: &mut UnixStream,
    terminal: &LauncherTerminalFrameV1,
) -> Result<(), ClientError> {
    if terminal.finalization.is_none() {
        return Ok(());
    }
    let mut persistence = LauncherTerminalPersistenceV1 {
        schema_version: 1,
        message_kind: LAUNCHER_TERMINAL_PERSISTENCE.into(),
        identity: String::new(),
        invocation_id: terminal.invocation_id.clone(),
        terminal_identity: launcher_terminal_frame_v1_identity(terminal)
            .map_err(|_| ClientError::Protocol)?,
    };
    persistence.identity = launcher_terminal_persistence_v1_identity(&persistence)
        .map_err(|_| ClientError::Protocol)?;
    write_typed_frame(stream, &persistence)
}

fn connect_fixed_launcher() -> Result<UnixStream, ClientError> {
    verify_socket_path(Path::new(SYSTEMD_LAUNCHER_SOCKET))?;
    let stream = UnixStream::connect(SYSTEMD_LAUNCHER_SOCKET)
        .map_err(|_| ClientError::ServiceUnavailable)?;
    verify_root_peer(&stream)?;
    stream
        .set_read_timeout(Some(IO_TIMEOUT))
        .and_then(|()| stream.set_write_timeout(Some(IO_TIMEOUT)))
        .map_err(|_| ClientError::LocalBoundary)?;
    Ok(stream)
}

fn verify_socket_path(path: &Path) -> Result<(), ClientError> {
    let parent = path.parent().ok_or(ClientError::LocalBoundary)?;
    let parent_metadata = fs::symlink_metadata(parent).map_err(|_| ClientError::LocalBoundary)?;
    let socket_metadata =
        fs::symlink_metadata(path).map_err(|_| ClientError::ServiceUnavailable)?;
    if !parent_metadata.is_dir()
        || parent_metadata.uid() != 0
        || parent_metadata.permissions().mode() & 0o022 != 0
        || !socket_metadata.file_type().is_socket()
        || socket_metadata.uid() != 0
        || socket_metadata.permissions().mode() & 0o7777 != 0o660
    {
        return Err(ClientError::LocalBoundary);
    }
    Ok(())
}

fn verify_root_peer(stream: &UnixStream) -> Result<(), ClientError> {
    let mut credentials = libc::ucred {
        pid: 0,
        uid: u32::MAX,
        gid: u32::MAX,
    };
    let mut length = std::mem::size_of::<libc::ucred>() as libc::socklen_t;
    let result = unsafe {
        libc::getsockopt(
            stream.as_raw_fd(),
            libc::SOL_SOCKET,
            libc::SO_PEERCRED,
            (&mut credentials as *mut libc::ucred).cast(),
            &mut length,
        )
    };
    if result != 0
        || length as usize != std::mem::size_of::<libc::ucred>()
        || credentials.pid <= 0
        || credentials.uid != 0
        || credentials.gid != 0
    {
        return Err(ClientError::LocalBoundary);
    }
    Ok(())
}

fn write_typed_frame<T: Serialize>(stream: &mut UnixStream, value: &T) -> Result<(), ClientError> {
    let payload = serde_json::to_vec(value).map_err(|_| ClientError::Protocol)?;
    let frame = encode_frame(&payload).map_err(|_| ClientError::Protocol)?;
    stream
        .write_all(&frame)
        .map_err(|_| ClientError::ServiceUnavailable)
}

fn read_typed_frame<T: serde::de::DeserializeOwned>(
    stream: &mut UnixStream,
) -> Result<T, ClientError> {
    let mut header = [0_u8; 4];
    stream
        .read_exact(&mut header)
        .map_err(|_| ClientError::ServiceUnavailable)?;
    let length = u32::from_be_bytes(header) as usize;
    if length == 0 || length > MAX_FRAME_BYTES {
        return Err(ClientError::Protocol);
    }
    let mut frame = Vec::with_capacity(4 + length);
    frame.extend_from_slice(&header);
    frame.resize(4 + length, 0);
    stream
        .read_exact(&mut frame[4..])
        .map_err(|_| ClientError::OutputIncomplete)?;
    let payload = decode_frame(&frame).map_err(|_| ClientError::Protocol)?;
    serde_json::from_slice(payload).map_err(|_| ClientError::Protocol)
}

fn reject_queued_trailing_frame(stream: &UnixStream) -> Result<(), ClientError> {
    let mut byte = 0_u8;
    let received = unsafe {
        libc::recv(
            stream.as_raw_fd(),
            (&mut byte as *mut u8).cast(),
            1,
            libc::MSG_PEEK | libc::MSG_DONTWAIT,
        )
    };
    if received > 0 {
        return Err(ClientError::Protocol);
    }
    if received == 0 {
        return Ok(());
    }
    match std::io::Error::last_os_error().raw_os_error() {
        Some(libc::EAGAIN) => Ok(()),
        _ => Err(ClientError::Protocol),
    }
}

fn validate_authority_label(value: &str) -> Result<(), ClientError> {
    if !value.is_empty()
        && value.len() <= 128
        && value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.'))
    {
        Ok(())
    } else {
        Err(ClientError::Usage)
    }
}

fn validate_ota_arguments(arguments: &[String]) -> Result<(), ClientError> {
    let allowed = matches!(arguments.first().map(String::as_str), Some("run" | "up"))
        || matches!(
            arguments.get(0..2),
            Some([proof, kind]) if proof == "proof" && matches!(kind.as_str(), "runtime" | "lifecycle")
        );
    if allowed {
        Ok(())
    } else {
        Err(ClientError::Usage)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::net::UnixStream;

    #[test]
    fn production_arguments_admit_only_governed_execution_surfaces() {
        assert!(validate_ota_arguments(&["run".into(), "publish".into()]).is_ok());
        assert!(validate_ota_arguments(&["up".into()]).is_ok());
        assert!(validate_ota_arguments(&["proof".into(), "runtime".into()]).is_ok());
        assert!(validate_ota_arguments(&["doctor".into()]).is_err());
        assert!(validate_ota_arguments(&[]).is_err());
    }

    #[test]
    fn client_failures_have_stable_bounded_exit_codes() {
        assert_eq!(ClientError::Usage.exit_code(), 64);
        assert_eq!(ClientError::Protocol.exit_code(), 70);
        assert_eq!(ClientError::ServiceUnavailable.exit_code(), 75);
        assert_eq!(
            ClientError::OutputIncomplete.reason_code(),
            "output_incomplete"
        );
        assert_eq!(ClientError::Usage.execution_started(), Some(false));
        assert_eq!(
            ClientError::OutputIncomplete.execution_started(),
            Some(true)
        );
        assert_eq!(ClientError::Protocol.execution_started(), None);
        assert_eq!(ClientError::ServiceUnavailable.execution_started(), None);
    }

    #[test]
    fn queued_trailing_response_data_refuses() {
        let (left, mut right) = UnixStream::pair().expect("socket pair");
        right.write_all(b"trailing").expect("queued data");
        assert_eq!(
            reject_queued_trailing_frame(&left),
            Err(ClientError::Protocol)
        );
    }
}
