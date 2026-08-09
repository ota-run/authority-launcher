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

//! Feature-gated unprivileged client for the execution-disabled systemd pressure boundary.

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
use clap::Parser;
#[cfg(target_os = "linux")]
use ota_authority_protocol::{
    LAUNCHER_INVOCATION_REQUEST, LauncherInvocationRequestV1, LauncherTerminalFrameV1,
    LauncherTerminalOutcomeV1, MAX_FRAME_BYTES, SYSTEMD_LAUNCHER_SERVICE_PROTOCOL_V1, decode_frame,
    encode_frame, launcher_invocation_request_identity, validate_launcher_invocation_request_v1,
    validate_launcher_terminal_frame_v1,
};
#[cfg(target_os = "linux")]
use serde::Serialize;

#[cfg(target_os = "linux")]
const SYSTEMD_LAUNCHER_SOCKET: &str = "/run/ota/authority-launcher.sock";
#[cfg(target_os = "linux")]
const IO_TIMEOUT: Duration = Duration::from_secs(10);

#[cfg(target_os = "linux")]
#[derive(Debug, Parser)]
#[command(name = "ota-authority-systemd-pressure-client", version, about)]
struct Cli {
    #[arg(long)]
    authority_id: String,
    #[arg(long)]
    repository: PathBuf,
    #[arg(last = true, required = true)]
    ota_args: Vec<String>,
}

#[cfg(target_os = "linux")]
#[derive(Debug, Serialize)]
struct PressureEvidence {
    ok: bool,
    kind: &'static str,
    request_identity: String,
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
    let terminal = read_terminal(&mut stream)?;
    if terminal.outcome != LauncherTerminalOutcomeV1::Refused || terminal.exit_code != Some(2) {
        return Err(String::from(
            "the execution-disabled launcher did not confirm its bounded terminal refusal",
        ));
    }
    Ok(PressureEvidence {
        ok: true,
        kind: "systemd_transient_scope_pressure",
        request_identity,
        terminal,
    })
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
fn read_terminal(stream: &mut UnixStream) -> Result<LauncherTerminalFrameV1, String> {
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
    let terminal: LauncherTerminalFrameV1 = serde_json::from_slice(payload)
        .map_err(|_| String::from("the launcher terminal record is invalid"))?;
    validate_launcher_terminal_frame_v1(&terminal)
        .map_err(|_| String::from("the launcher terminal record is invalid"))?;
    Ok(terminal)
}

#[cfg(all(test, target_os = "linux"))]
mod tests {
    use super::*;
    use ota_authority_protocol::{LAUNCHER_TERMINAL, LauncherTerminalOutcomeV1};

    #[test]
    fn terminal_reader_accepts_only_a_protocol_valid_frame() {
        let (mut client, mut server) = UnixStream::pair().expect("socket pair");
        let terminal = LauncherTerminalFrameV1 {
            message_kind: LAUNCHER_TERMINAL.into(),
            protocol_version: SYSTEMD_LAUNCHER_SERVICE_PROTOCOL_V1.into(),
            invocation_id: String::from("invocation-0123456789abcdef0123456789abcdef"),
            outcome: LauncherTerminalOutcomeV1::Refused,
            exit_code: Some(2),
        };
        let payload = serde_json::to_vec(&terminal).expect("terminal payload");
        let frame = encode_frame(payload.as_slice()).expect("terminal frame");
        std::thread::spawn(move || server.write_all(frame.as_slice()).expect("write terminal"));
        assert_eq!(read_terminal(&mut client).expect("read terminal"), terminal);
    }

    #[test]
    fn terminal_reader_rejects_an_oversized_frame_before_allocation() {
        let (mut client, mut server) = UnixStream::pair().expect("socket pair");
        let oversized = u32::try_from(MAX_FRAME_BYTES + 1)
            .expect("protocol frame bound fits in u32")
            .to_be_bytes();
        std::thread::spawn(move || server.write_all(&oversized).expect("write header"));
        assert!(read_terminal(&mut client).is_err());
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
