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
    LAUNCHER_INVOCATION_REQUEST, LAUNCHER_OUTPUT, LAUNCHER_TERMINAL, LauncherInvocationRequestV1,
    LauncherOutputFrameV1, LauncherTerminalFrameV1, LauncherTerminalOutcomeV1,
    LauncherTerminalStageV1, MAX_FRAME_BYTES, SYSTEMD_LAUNCHER_SERVICE_PROTOCOL_V1, decode_frame,
    encode_frame, launcher_invocation_request_identity, validate_launcher_invocation_request_v1,
    validate_launcher_output_frame_v1, validate_launcher_terminal_frame_v1,
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
    terminal: LauncherTerminalFrameV1,
}

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
                std::process::ExitCode::SUCCESS
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
    let (output_frames, terminal) = read_session(&mut stream)?;
    validate_pressure_terminal(&terminal, cli.expected_terminal)?;
    Ok(PressureEvidence {
        ok: true,
        kind: "systemd_transient_scope_pressure",
        request_identity,
        output_frames,
        terminal,
    })
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
        return Err(String::from(
            "the launcher did not confirm the expected bounded terminal outcome",
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
) -> Result<(Vec<LauncherOutputFrameV1>, LauncherTerminalFrameV1), String> {
    let mut output_frames = Vec::new();
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
                return Ok((output_frames, terminal));
            }
            _ => return Err(String::from("the launcher session record is unsupported")),
        }
    }
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
            read_session(&mut client).expect("read terminal"),
            (Vec::new(), terminal)
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
            read_session(&mut client).expect("read session"),
            (vec![output], terminal)
        );
    }

    #[test]
    fn terminal_reader_rejects_an_oversized_frame_before_allocation() {
        let (mut client, mut server) = UnixStream::pair().expect("socket pair");
        let oversized = u32::try_from(MAX_FRAME_BYTES + 1)
            .expect("protocol frame bound fits in u32")
            .to_be_bytes();
        std::thread::spawn(move || server.write_all(&oversized).expect("write header"));
        assert!(read_session(&mut client).is_err());
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
