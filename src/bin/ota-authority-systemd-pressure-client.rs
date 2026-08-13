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

//! Feature-gated unprivileged client for the protected systemd pressure boundary.

#[cfg(target_os = "linux")]
use std::io::{Read, Write};
#[cfg(target_os = "linux")]
use std::os::unix::fs::{FileTypeExt, MetadataExt, PermissionsExt};
#[cfg(target_os = "linux")]
use std::os::unix::net::UnixStream;
#[cfg(target_os = "linux")]
use std::path::Path;
#[cfg(target_os = "linux")]
use std::path::PathBuf;
#[cfg(target_os = "linux")]
use std::time::Duration;

#[cfg(target_os = "linux")]
use clap::{Parser, ValueEnum};
#[cfg(target_os = "linux")]
use ota_authority_protocol::{
    LAUNCHER_FINALIZATION_ARCHIVE_PERSISTENCE, LAUNCHER_FINALIZATION_ARCHIVE_REQUEST,
    LAUNCHER_FINALIZATION_RECOVERY_REQUEST, LAUNCHER_INVOCATION_REQUEST, LAUNCHER_OUTPUT,
    LAUNCHER_SIGNED_EXECUTION_FINALIZATION, LAUNCHER_TERMINAL, LAUNCHER_TERMINAL_PERSISTENCE,
    LauncherFinalizationArchivePersistenceV1, LauncherFinalizationArchiveRequestV1,
    LauncherFinalizationArchiveResponseV1, LauncherFinalizationRecoveryRequestV1,
    LauncherInvocationRequestV1, LauncherOutputFrameV1, LauncherSignedExecutionFinalizationFrameV1,
    LauncherTerminalFrameV1, LauncherTerminalOutcomeV1, LauncherTerminalPersistenceV1,
    LauncherTerminalStageV1, MAX_FRAME_BYTES, SYSTEMD_LAUNCHER_SERVICE_PROTOCOL_V1, decode_frame,
    encode_frame, launcher_finalization_archive_persistence_v1_identity,
    launcher_finalization_archive_request_v1_identity,
    launcher_finalization_archive_response_v1_identity,
    launcher_finalization_recovery_request_v1_identity, launcher_invocation_request_identity,
    launcher_terminal_frame_v1_identity, launcher_terminal_persistence_v1_identity,
    validate_launcher_invocation_request_v1, validate_launcher_output_frame_v1,
    validate_launcher_signed_execution_finalization_frame_v1, validate_launcher_terminal_frame_v1,
};
#[cfg(target_os = "linux")]
use serde::Serialize;

#[cfg(target_os = "linux")]
const SYSTEMD_LAUNCHER_SOCKET: &str = "/run/ota/authority-launcher.sock";
#[cfg(target_os = "linux")]
const IO_TIMEOUT: Duration = Duration::from_secs(10);
#[cfg(target_os = "linux")]
const MAX_CAPTURED_OUTPUT_BYTES: usize = 4 * 1024 * 1024;

#[cfg(target_os = "linux")]
#[derive(Debug, Parser)]
#[command(name = "ota-authority-systemd-pressure-client", version, about)]
struct Cli {
    #[arg(long)]
    authority_id: String,
    #[arg(long)]
    repository: PathBuf,
    #[arg(long, value_enum, default_value_t = ExpectedTerminal::AllowedDecision)]
    expected_terminal: ExpectedTerminal,
    #[arg(last = true, required = true)]
    ota_args: Vec<String>,
}

#[cfg(target_os = "linux")]
#[derive(Debug, Clone, Copy, ValueEnum)]
enum ExpectedTerminal {
    AllowedDecision,
    LeaseConsumedExecutionDisabled,
    DeniedDecision,
    ObservedDecisionOutcome,
    ProtocolRefusal,
    SelectedSuccess,
    SelectedFailure,
}

#[cfg(target_os = "linux")]
#[derive(Debug, Serialize)]
struct PressureEvidence {
    ok: bool,
    kind: &'static str,
    request_identity: String,
    output_frames: Vec<LauncherOutputFrameV1>,
    #[serde(skip_serializing_if = "Option::is_none")]
    finalization_sidecar: Option<String>,
    terminal: LauncherTerminalFrameV1,
}

#[cfg(target_os = "linux")]
type SessionEvidence = (
    Vec<LauncherOutputFrameV1>,
    Option<LauncherSignedExecutionFinalizationFrameV1>,
    Option<PathBuf>,
    LauncherTerminalFrameV1,
);

fn main() -> std::process::ExitCode {
    #[cfg(not(target_os = "linux"))]
    {
        eprintln!("ota-authority-systemd-pressure-client: this pressure client requires Linux");
        std::process::ExitCode::FAILURE
    }

    #[cfg(target_os = "linux")]
    match run(Cli::parse()) {
        Ok(evidence) => match serde_json::to_string_pretty(&evidence) {
            Ok(encoded) => {
                println!("{encoded}");
                if evidence.ok {
                    std::process::ExitCode::SUCCESS
                } else {
                    std::process::ExitCode::FAILURE
                }
            }
            Err(_) => std::process::ExitCode::FAILURE,
        },
        Err(error) => {
            eprintln!("ota-authority-systemd-pressure-client: {error}");
            std::process::ExitCode::FAILURE
        }
    }
}

#[cfg(target_os = "linux")]
fn run(cli: Cli) -> Result<PressureEvidence, String> {
    let repository = cli
        .repository
        .canonicalize()
        .map_err(|_| String::from("the pressure repository is unavailable"))?;
    let authority_id = cli.authority_id.clone();
    let request = LauncherInvocationRequestV1 {
        message_kind: LAUNCHER_INVOCATION_REQUEST.into(),
        protocol_version: SYSTEMD_LAUNCHER_SERVICE_PROTOCOL_V1.into(),
        authority_id: cli.authority_id,
        ota_arguments: cli.ota_args,
        repository_path: repository.to_string_lossy().into_owned(),
    };
    validate_launcher_invocation_request_v1(&request)
        .map_err(|_| String::from("the pressure request is invalid"))?;
    let request_identity = launcher_invocation_request_identity(&request)
        .map_err(|_| String::from("the pressure request identity is unavailable"))?;
    let payload = serde_json::to_vec(&request)
        .map_err(|_| String::from("the pressure request could not be encoded"))?;
    let frame = encode_frame(payload.as_slice())
        .map_err(|_| String::from("the pressure request could not be framed"))?;

    verify_socket_path(Path::new(SYSTEMD_LAUNCHER_SOCKET))?;
    let mut stream = UnixStream::connect(SYSTEMD_LAUNCHER_SOCKET)
        .map_err(|_| String::from("the fixed systemd launcher socket is unavailable"))?;
    verify_root_peer(&stream)?;
    stream
        .set_read_timeout(Some(IO_TIMEOUT))
        .and_then(|()| stream.set_write_timeout(Some(IO_TIMEOUT)))
        .map_err(|_| String::from("the pressure session timeout could not be applied"))?;
    stream
        .write_all(frame.as_slice())
        .map_err(|_| String::from("the pressure request could not be sent"))?;
    let archive_context = ArchiveContext {
        repository: &repository,
        authority_id: authority_id.as_str(),
        launcher_request_identity: request_identity.as_str(),
    };
    let (output_frames, _signed_finalization, finalization_sidecar, terminal) =
        match read_session(&mut stream, Some(archive_context)) {
            Ok(session) => session,
            Err(primary_error) => recover_finalization_session(
                &repository,
                authority_id.as_str(),
                request_identity.as_str(),
            )
            .map_err(|recovery_error| {
                format!("{primary_error}; launcher finalization recovery failed: {recovery_error}")
            })?,
        };
    let finalization_sidecar = finalization_sidecar.map(|path| path.to_string_lossy().into_owned());
    let ok = validate_pressure_terminal(&terminal, cli.expected_terminal).is_ok();
    Ok(PressureEvidence {
        ok,
        kind: "systemd_transient_scope_pressure",
        request_identity,
        output_frames,
        finalization_sidecar,
        terminal,
    })
}

#[cfg(target_os = "linux")]
fn recover_finalization_session(
    repository: &Path,
    authority_id: &str,
    launcher_request_identity: &str,
) -> Result<SessionEvidence, String> {
    let mut recovery = LauncherFinalizationRecoveryRequestV1 {
        schema_version: 1,
        message_kind: LAUNCHER_FINALIZATION_RECOVERY_REQUEST.into(),
        request_identity: String::new(),
        authority_id: authority_id.into(),
        launcher_request_identity: launcher_request_identity.into(),
    };
    recovery.request_identity = launcher_finalization_recovery_request_v1_identity(&recovery)
        .map_err(|_| String::from("the launcher finalization recovery request is invalid"))?;
    verify_socket_path(Path::new(SYSTEMD_LAUNCHER_SOCKET))?;
    let mut stream = UnixStream::connect(SYSTEMD_LAUNCHER_SOCKET)
        .map_err(|_| String::from("the fixed systemd launcher socket is unavailable"))?;
    verify_root_peer(&stream)?;
    stream
        .set_read_timeout(Some(IO_TIMEOUT))
        .and_then(|()| stream.set_write_timeout(Some(IO_TIMEOUT)))
        .map_err(|_| String::from("the pressure session timeout could not be applied"))?;
    write_client_frame(&mut stream, &recovery)?;
    let signed_frame: LauncherSignedExecutionFinalizationFrameV1 = read_client_frame(&mut stream)?;
    validate_launcher_signed_execution_finalization_frame_v1(&signed_frame)
        .map_err(|_| String::from("the recovered launcher finalization is invalid"))?;
    let context = ArchiveContext {
        repository,
        authority_id,
        launcher_request_identity,
    };
    let sidecar_path = attach_finalization_sidecar(&mut stream, &context, &signed_frame)?;
    let terminal: LauncherTerminalFrameV1 = read_client_frame(&mut stream)?;
    validate_launcher_terminal_frame_v1(&terminal)
        .map_err(|_| String::from("the recovered launcher terminal is invalid"))?;
    acknowledge_selected_terminal(&mut stream, &terminal)?;
    Ok((Vec::new(), Some(signed_frame), Some(sidecar_path), terminal))
}

#[cfg(target_os = "linux")]
fn validate_pressure_terminal(
    terminal: &LauncherTerminalFrameV1,
    expected: ExpectedTerminal,
) -> Result<(), String> {
    let refusal_stage_matches = matches!(
        (expected, terminal.stage),
        (
            ExpectedTerminal::AllowedDecision,
            Some(LauncherTerminalStageV1::AuthorizationDecisionVerifiedBeforeLeaseBoundaryRemoved),
        ) | (
            ExpectedTerminal::LeaseConsumedExecutionDisabled,
            Some(LauncherTerminalStageV1::LeaseConsumedBeforeExecutionDisabledBoundaryRemoved),
        ) | (
            ExpectedTerminal::DeniedDecision,
            Some(LauncherTerminalStageV1::AuthorityRefusedBoundaryRemoved),
        ) | (
            ExpectedTerminal::ProtocolRefusal,
            Some(LauncherTerminalStageV1::PreAuthorizationProtocolRefusedBoundaryRemoved),
        ) | (
            ExpectedTerminal::ObservedDecisionOutcome,
            Some(
                LauncherTerminalStageV1::AuthorizationDecisionVerifiedBeforeLeaseBoundaryRemoved
                    | LauncherTerminalStageV1::LeaseConsumedBeforeExecutionDisabledBoundaryRemoved
                    | LauncherTerminalStageV1::AuthorityRefusedBoundaryRemoved
                    | LauncherTerminalStageV1::PreAuthorizationProtocolRefusedBoundaryRemoved,
            ),
        )
    );
    let selected_matches = match (
        expected,
        terminal.outcome,
        terminal.stage,
        terminal.exit_code,
    ) {
        (
            ExpectedTerminal::SelectedSuccess,
            LauncherTerminalOutcomeV1::Completed,
            Some(LauncherTerminalStageV1::SelectedExecutionCompletedBoundaryRemoved),
            Some(0),
        ) => true,
        (
            ExpectedTerminal::SelectedFailure,
            LauncherTerminalOutcomeV1::Failed,
            Some(LauncherTerminalStageV1::SelectedExecutionFailedBoundaryRemoved),
            Some(code),
        ) => code != 0,
        (
            ExpectedTerminal::ObservedDecisionOutcome,
            LauncherTerminalOutcomeV1::Completed,
            Some(LauncherTerminalStageV1::SelectedExecutionCompletedBoundaryRemoved),
            Some(0),
        ) => true,
        (
            ExpectedTerminal::ObservedDecisionOutcome,
            LauncherTerminalOutcomeV1::Failed,
            Some(LauncherTerminalStageV1::SelectedExecutionFailedBoundaryRemoved),
            Some(code),
        ) => code != 0,
        (
            ExpectedTerminal::ObservedDecisionOutcome,
            LauncherTerminalOutcomeV1::Cancelled,
            Some(LauncherTerminalStageV1::SelectedExecutionInterruptedBoundaryRemoved),
            Some(code),
        ) => matches!(code, 129 | 130 | 131 | 143),
        _ => false,
    };
    let refusal_matches = terminal.outcome == LauncherTerminalOutcomeV1::Refused
        && terminal.exit_code == Some(2)
        && refusal_stage_matches;
    if !refusal_matches && !selected_matches {
        return Err(format!(
            "the launcher did not confirm the expected bounded terminal outcome: outcome={:?}, stage={:?}, exit_code={:?}",
            terminal.outcome, terminal.stage, terminal.exit_code
        ));
    }
    Ok(())
}

#[cfg(target_os = "linux")]
fn verify_socket_path(path: &Path) -> Result<(), String> {
    let parent = path
        .parent()
        .ok_or_else(|| String::from("the fixed systemd launcher socket is unprotected"))?;
    let parent_metadata = std::fs::symlink_metadata(parent)
        .map_err(|_| String::from("the fixed systemd launcher socket is unprotected"))?;
    let socket_metadata = std::fs::symlink_metadata(path)
        .map_err(|_| String::from("the fixed systemd launcher socket is unavailable"))?;
    if !parent_metadata.is_dir()
        || parent_metadata.uid() != 0
        || parent_metadata.permissions().mode() & 0o022 != 0
        || !socket_metadata.file_type().is_socket()
        || socket_metadata.uid() != 0
        || socket_metadata.permissions().mode() & 0o7777 != 0o660
    {
        return Err(String::from(
            "the fixed systemd launcher socket is unprotected",
        ));
    }
    Ok(())
}

#[cfg(target_os = "linux")]
fn verify_root_peer(stream: &UnixStream) -> Result<(), String> {
    use std::os::fd::AsRawFd;

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
        || !credentials_are_root_launcher(credentials.pid, credentials.uid, credentials.gid)
    {
        return Err(String::from(
            "the fixed systemd launcher peer is not root-owned",
        ));
    }
    Ok(())
}

#[cfg(target_os = "linux")]
fn credentials_are_root_launcher(pid: i32, uid: u32, gid: u32) -> bool {
    pid > 0 && uid == 0 && gid == 0
}

#[cfg(target_os = "linux")]
fn read_session(
    stream: &mut UnixStream,
    archive_context: Option<ArchiveContext<'_>>,
) -> Result<SessionEvidence, String> {
    let mut output_frames = Vec::new();
    let mut signed_finalization: Option<LauncherSignedExecutionFinalizationFrameV1> = None;
    let mut finalization_sidecar = None;
    let mut next_sequence = 0_u64;
    let mut captured_output_bytes = 0_usize;
    loop {
        let payload = read_frame_payload(stream)?;
        let value: serde_json::Value = serde_json::from_slice(&payload)
            .map_err(|_| String::from("the launcher session record is invalid"))?;
        match value
            .get("message_kind")
            .and_then(serde_json::Value::as_str)
        {
            Some(LAUNCHER_OUTPUT) => {
                let output: LauncherOutputFrameV1 = serde_json::from_value(value)
                    .map_err(|_| String::from("the launcher output record is invalid"))?;
                validate_launcher_output_frame_v1(&output)
                    .map_err(|_| String::from("the launcher output record is invalid"))?;
                if output.sequence != next_sequence {
                    return Err(String::from("the launcher output sequence is invalid"));
                }
                captured_output_bytes = captured_output_bytes
                    .checked_add(output.payload.len())
                    .filter(|total| *total <= MAX_CAPTURED_OUTPUT_BYTES)
                    .ok_or_else(|| {
                        String::from("the launcher output exceeds the pressure bound")
                    })?;
                next_sequence = next_sequence.saturating_add(1);
                output_frames.push(output);
            }
            Some(LAUNCHER_TERMINAL) => {
                let terminal: LauncherTerminalFrameV1 = serde_json::from_value(value)
                    .map_err(|_| String::from("the launcher terminal record is invalid"))?;
                validate_launcher_terminal_frame_v1(&terminal)
                    .map_err(|_| String::from("the launcher terminal record is invalid"))?;
                if output_frames
                    .iter()
                    .any(|output| output.invocation_id != terminal.invocation_id)
                {
                    return Err(String::from("the launcher output invocation is invalid"));
                }
                let signed_matches_terminal =
                    match (terminal.finalization.as_ref(), signed_finalization.as_ref()) {
                        (Some(finalization), Some(frame)) => {
                            &frame.signed_finalization.finalization == finalization
                                && frame.invocation_id == terminal.invocation_id
                        }
                        (None, None) => true,
                        _ => false,
                    };
                if !signed_matches_terminal {
                    return Err(String::from(
                        "the launcher portable finalization record is missing or unexpected",
                    ));
                }
                acknowledge_selected_terminal(stream, &terminal)?;
                return Ok((
                    output_frames,
                    signed_finalization,
                    finalization_sidecar,
                    terminal,
                ));
            }
            Some(LAUNCHER_SIGNED_EXECUTION_FINALIZATION) => {
                if signed_finalization.is_some() {
                    return Err(String::from(
                        "the launcher finalization record is duplicated",
                    ));
                }
                let frame: LauncherSignedExecutionFinalizationFrameV1 =
                    serde_json::from_value(value)
                        .map_err(|_| String::from("the launcher finalization record is invalid"))?;
                validate_launcher_signed_execution_finalization_frame_v1(&frame)
                    .map_err(|_| String::from("the launcher finalization record is invalid"))?;
                if let Some(context) = archive_context.as_ref() {
                    finalization_sidecar =
                        Some(attach_finalization_sidecar(stream, context, &frame)?);
                }
                signed_finalization = Some(frame);
            }
            _ => return Err(String::from("the launcher session record is unsupported")),
        }
    }
}

#[cfg(target_os = "linux")]
fn acknowledge_selected_terminal(
    stream: &mut UnixStream,
    terminal: &LauncherTerminalFrameV1,
) -> Result<(), String> {
    if terminal.finalization.is_none() {
        return Ok(());
    }
    let mut persistence = LauncherTerminalPersistenceV1 {
        schema_version: 1,
        message_kind: LAUNCHER_TERMINAL_PERSISTENCE.into(),
        identity: String::new(),
        invocation_id: terminal.invocation_id.clone(),
        terminal_identity: launcher_terminal_frame_v1_identity(terminal)
            .map_err(|_| String::from("the launcher terminal identity is invalid"))?,
    };
    persistence.identity = launcher_terminal_persistence_v1_identity(&persistence)
        .map_err(|_| String::from("the launcher terminal persistence is invalid"))?;
    write_client_frame(stream, &persistence)
}

#[cfg(target_os = "linux")]
#[derive(Clone, Copy)]
struct ArchiveContext<'a> {
    repository: &'a Path,
    authority_id: &'a str,
    launcher_request_identity: &'a str,
}

#[cfg(target_os = "linux")]
fn attach_finalization_sidecar(
    stream: &mut UnixStream,
    context: &ArchiveContext<'_>,
    frame: &LauncherSignedExecutionFinalizationFrameV1,
) -> Result<PathBuf, String> {
    let completion = &frame.signed_finalization.finalization.completion;
    let transaction_identity = &completion.crossing_transaction_identity;
    let archive_identity = completion.receipt_archive_identity.clone().ok_or_else(|| {
        String::from("the launcher completion omits its receipt archive identity")
    })?;
    let mut request = LauncherFinalizationArchiveRequestV1 {
        schema_version: 1,
        message_kind: LAUNCHER_FINALIZATION_ARCHIVE_REQUEST.into(),
        request_identity: String::new(),
        authority_id: context.authority_id.into(),
        launcher_request_identity: context.launcher_request_identity.into(),
        receipt_archive_identity: archive_identity,
        crossing_transaction_identity: transaction_identity.clone(),
        signed_finalization_identity: Some(frame.signed_finalization.identity.clone()),
    };
    request.request_identity = launcher_finalization_archive_request_v1_identity(&request)
        .map_err(|_| String::from("the launcher finalization archive request is invalid"))?;
    write_client_frame(stream, &request)?;
    let response: LauncherFinalizationArchiveResponseV1 = read_client_frame(stream)?;
    if launcher_finalization_archive_response_v1_identity(&response)
        .map_err(|_| String::from("the launcher finalization archive response is invalid"))?
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
        return Err(String::from(
            "the launcher finalization archive response is invalid",
        ));
    }
    let sidecar_file_name = response
        .sidecar_file_name
        .clone()
        .ok_or_else(|| String::from("the launcher finalization sidecar path is unavailable"))?;
    let sidecar = response.sidecar;
    let sidecar_path = receipt_archive_dir(context.repository).join(sidecar_file_name);
    let mut persistence = LauncherFinalizationArchivePersistenceV1 {
        schema_version: 1,
        message_kind: LAUNCHER_FINALIZATION_ARCHIVE_PERSISTENCE.into(),
        identity: String::new(),
        request_identity: request.request_identity,
        sidecar_identity: sidecar.identity,
    };
    persistence.identity = launcher_finalization_archive_persistence_v1_identity(&persistence)
        .map_err(|_| String::from("the launcher finalization persistence is invalid"))?;
    write_client_frame(stream, &persistence)?;
    Ok(sidecar_path)
}

#[cfg(target_os = "linux")]
fn receipt_archive_dir(repository: &Path) -> PathBuf {
    repository.join(".ota/receipts")
}

#[cfg(target_os = "linux")]
fn write_client_frame<T: serde::Serialize>(
    stream: &mut UnixStream,
    value: &T,
) -> Result<(), String> {
    let payload = serde_json::to_vec(value)
        .map_err(|_| String::from("the launcher finalization frame cannot be encoded"))?;
    let frame = encode_frame(&payload)
        .map_err(|_| String::from("the launcher finalization frame cannot be encoded"))?;
    stream
        .write_all(&frame)
        .map_err(|_| String::from("the launcher finalization frame cannot be sent"))
}

#[cfg(target_os = "linux")]
fn read_client_frame<T: serde::de::DeserializeOwned>(stream: &mut UnixStream) -> Result<T, String> {
    let payload = read_frame_payload(stream)?;
    serde_json::from_slice(&payload)
        .map_err(|_| String::from("the launcher finalization frame is invalid"))
}

#[cfg(target_os = "linux")]
fn read_frame_payload(stream: &mut UnixStream) -> Result<Vec<u8>, String> {
    let mut header = [0_u8; 4];
    stream
        .read_exact(&mut header)
        .map_err(|_| String::from("the launcher terminal frame is unavailable"))?;
    let length = u32::from_be_bytes(header) as usize;
    if length == 0 || length > MAX_FRAME_BYTES {
        return Err(String::from("the launcher terminal frame is invalid"));
    }
    let mut frame = Vec::with_capacity(4 + length);
    frame.extend_from_slice(&header);
    frame.resize(4 + length, 0);
    stream
        .read_exact(&mut frame[4..])
        .map_err(|_| String::from("the launcher terminal frame is incomplete"))?;
    let payload = decode_frame(frame.as_slice())
        .map_err(|_| String::from("the launcher terminal frame is invalid"))?;
    Ok(payload.to_vec())
}

#[cfg(all(test, target_os = "linux"))]
mod tests {
    use super::*;
    use ota_authority_protocol::{
        LAUNCHER_TERMINAL, LauncherTerminalOutcomeV1, LauncherTerminalStageV1,
    };

    #[test]
    fn receipt_archives_use_otas_canonical_receipt_directory() {
        let repository = Path::new("/srv/ota-pressure");
        assert_eq!(
            receipt_archive_dir(repository),
            repository.join(".ota/receipts")
        );
    }

    #[test]
    fn terminal_reader_accepts_only_a_protocol_valid_frame() {
        let (mut client, mut server) = UnixStream::pair().expect("socket pair");
        let terminal = LauncherTerminalFrameV1 {
            message_kind: LAUNCHER_TERMINAL.into(),
            protocol_version: SYSTEMD_LAUNCHER_SERVICE_PROTOCOL_V1.into(),
            invocation_id: String::from("invocation-0123456789abcdef0123456789abcdef"),
            outcome: LauncherTerminalOutcomeV1::Refused,
            exit_code: Some(2),
            stage: Some(LauncherTerminalStageV1::PostureAdmittedBoundaryRemoved),
            finalization: None,
        };
        let payload = serde_json::to_vec(&terminal).expect("terminal payload");
        let frame = encode_frame(payload.as_slice()).expect("terminal frame");
        std::thread::spawn(move || server.write_all(frame.as_slice()).expect("write terminal"));
        assert_eq!(
            read_session(&mut client, None).expect("read terminal"),
            (Vec::new(), None, None, terminal)
        );
    }

    #[test]
    fn session_reader_preserves_ordered_output_before_terminal() {
        let (mut client, mut server) = UnixStream::pair().expect("socket pair");
        let invocation_id = String::from("invocation-0123456789abcdef0123456789abcdef");
        let output = LauncherOutputFrameV1 {
            message_kind: LAUNCHER_OUTPUT.into(),
            protocol_version: SYSTEMD_LAUNCHER_SERVICE_PROTOCOL_V1.into(),
            invocation_id: invocation_id.clone(),
            sequence: 0,
            stream: ota_authority_protocol::LauncherOutputStreamV1::Stdout,
            payload: b"selected output\n".to_vec(),
        };
        let terminal = LauncherTerminalFrameV1 {
            message_kind: LAUNCHER_TERMINAL.into(),
            protocol_version: SYSTEMD_LAUNCHER_SERVICE_PROTOCOL_V1.into(),
            invocation_id,
            outcome: LauncherTerminalOutcomeV1::Refused,
            exit_code: Some(2),
            stage: Some(LauncherTerminalStageV1::AuthorityRefusedBoundaryRemoved),
            finalization: None,
        };
        let output_frame = encode_frame(&serde_json::to_vec(&output).expect("output payload"))
            .expect("output frame");
        let terminal_frame =
            encode_frame(&serde_json::to_vec(&terminal).expect("terminal payload"))
                .expect("terminal frame");
        std::thread::spawn(move || {
            server.write_all(&output_frame).expect("write output");
            server.write_all(&terminal_frame).expect("write terminal");
        });
        assert_eq!(
            read_session(&mut client, None).expect("read session"),
            (vec![output], None, None, terminal)
        );
    }

    #[test]
    fn terminal_reader_rejects_an_oversized_frame_before_allocation() {
        let (mut client, mut server) = UnixStream::pair().expect("socket pair");
        let oversized = u32::try_from(MAX_FRAME_BYTES + 1)
            .expect("protocol frame bound fits in u32")
            .to_be_bytes();
        std::thread::spawn(move || server.write_all(&oversized).expect("write header"));
        assert!(read_session(&mut client, None).is_err());
    }

    #[test]
    fn pressure_terminal_rejects_a_pre_boundary_refusal() {
        let terminal = LauncherTerminalFrameV1 {
            message_kind: LAUNCHER_TERMINAL.into(),
            protocol_version: SYSTEMD_LAUNCHER_SERVICE_PROTOCOL_V1.into(),
            invocation_id: String::from("invocation-0123456789abcdef0123456789abcdef"),
            outcome: LauncherTerminalOutcomeV1::Refused,
            exit_code: Some(2),
            stage: Some(LauncherTerminalStageV1::RequestRefusedBeforeBoundary),
            finalization: None,
        };

        assert!(validate_pressure_terminal(&terminal, ExpectedTerminal::AllowedDecision).is_err());
    }

    #[test]
    fn pressure_terminal_requires_verified_decision_before_lease_cleanup() {
        let terminal = LauncherTerminalFrameV1 {
            message_kind: LAUNCHER_TERMINAL.into(),
            protocol_version: SYSTEMD_LAUNCHER_SERVICE_PROTOCOL_V1.into(),
            invocation_id: String::from("invocation-0123456789abcdef0123456789abcdef"),
            outcome: LauncherTerminalOutcomeV1::Refused,
            exit_code: Some(2),
            stage: Some(
                LauncherTerminalStageV1::AuthorizationDecisionVerifiedBeforeLeaseBoundaryRemoved,
            ),
            finalization: None,
        };
        assert!(validate_pressure_terminal(&terminal, ExpectedTerminal::AllowedDecision).is_ok());
        assert!(
            validate_pressure_terminal(&terminal, ExpectedTerminal::ObservedDecisionOutcome)
                .is_ok()
        );
        assert!(validate_pressure_terminal(&terminal, ExpectedTerminal::DeniedDecision).is_err());
    }

    #[test]
    fn observed_decision_outcome_accepts_only_bounded_decision_terminals() {
        for stage in [
            LauncherTerminalStageV1::AuthorizationDecisionVerifiedBeforeLeaseBoundaryRemoved,
            LauncherTerminalStageV1::AuthorityRefusedBoundaryRemoved,
            LauncherTerminalStageV1::PreAuthorizationProtocolRefusedBoundaryRemoved,
        ] {
            let terminal = LauncherTerminalFrameV1 {
                message_kind: LAUNCHER_TERMINAL.into(),
                protocol_version: SYSTEMD_LAUNCHER_SERVICE_PROTOCOL_V1.into(),
                invocation_id: String::from("invocation-0123456789abcdef0123456789abcdef"),
                outcome: LauncherTerminalOutcomeV1::Refused,
                exit_code: Some(2),
                stage: Some(stage),
                finalization: None,
            };
            assert!(
                validate_pressure_terminal(&terminal, ExpectedTerminal::ObservedDecisionOutcome)
                    .is_ok()
            );
        }

        let unrelated = LauncherTerminalFrameV1 {
            message_kind: LAUNCHER_TERMINAL.into(),
            protocol_version: SYSTEMD_LAUNCHER_SERVICE_PROTOCOL_V1.into(),
            invocation_id: String::from("invocation-0123456789abcdef0123456789abcdef"),
            outcome: LauncherTerminalOutcomeV1::Refused,
            exit_code: Some(2),
            stage: Some(LauncherTerminalStageV1::RequestRefusedBeforeBoundary),
            finalization: None,
        };
        assert!(
            validate_pressure_terminal(&unrelated, ExpectedTerminal::ObservedDecisionOutcome)
                .is_err()
        );
    }

    #[test]
    fn peer_credentials_require_a_root_launcher_process() {
        assert!(credentials_are_root_launcher(42, 0, 0));
        assert!(credentials_are_root_launcher(1, 0, 0));
        assert!(!credentials_are_root_launcher(0, 0, 0));
        assert!(!credentials_are_root_launcher(42, 1000, 0));
        assert!(!credentials_are_root_launcher(42, 0, 1000));
    }
}
