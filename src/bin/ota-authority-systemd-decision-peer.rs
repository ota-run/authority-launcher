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

//! Pressure-only signed authorization-decision peer for the execution-disabled systemd gate.
//!
//! This binary is not a production broker. It issues no lease and has no selected-work path.

#[cfg(target_os = "linux")]
mod linux {
    use std::fs;
    use std::io::{Read, Write};
    use std::os::fd::FromRawFd;
    use std::os::unix::fs::{MetadataExt, PermissionsExt};
    use std::os::unix::net::{UnixListener, UnixStream};
    use std::path::Path;
    use std::time::Duration;

    use base64::Engine;
    use base64::engine::general_purpose::URL_SAFE_NO_PAD;
    use ed25519_dalek::{Signer, SigningKey};
    use ota_authority_launcher::linux_observations::BROKER_PROXY_IDENTITY_PREFACE;
    use ota_authority_protocol::{
        AUTHORIZATION_DECISION, AUTHORIZATION_DECISION_DOMAIN_V1, AUTHORIZATION_REQUEST_DOMAIN_V1,
        AuthorizationDecision, AuthorizationDecisionPayload, AuthorizationRequest, MAX_FRAME_BYTES,
        SignedBrokerMessage, decode_frame, domain_separated, encode_frame, message_identity,
    };
    use time::OffsetDateTime;
    use time::format_description::well_known::Rfc3339;

    const SYSTEMD_LISTEN_FD: i32 = 3;
    const CREDENTIAL_NAME: &str = "ota-broker-ed25519";
    const KEY_ID: &str = "systemd-broker-pressure-v1";
    const SCENARIO_PATH: &str = "/run/ota/authority-broker-pressure-scenario";

    pub(super) fn run() -> Result<(), String> {
        let expected_pid = unsafe { libc::getpid() }.to_string();
        if std::env::var("LISTEN_PID").ok().as_deref() != Some(expected_pid.as_str())
            || std::env::var("LISTEN_FDS").ok().as_deref() != Some("1")
        {
            return Err(String::from("decision peer requires one systemd listener"));
        }
        set_cloexec(SYSTEMD_LISTEN_FD)?;
        // SAFETY: systemd supplied and owns exactly one listener descriptor for this process.
        let listener = unsafe { UnixListener::from_raw_fd(SYSTEMD_LISTEN_FD) };
        let (mut stream, _) = listener
            .accept()
            .map_err(|_| String::from("decision peer could not accept launcher"))?;
        stream
            .set_read_timeout(Some(Duration::from_secs(5)))
            .and_then(|()| stream.set_write_timeout(Some(Duration::from_secs(5))))
            .map_err(|_| String::from("decision peer timeout setup failed"))?;
        stream
            .write_all(BROKER_PROXY_IDENTITY_PREFACE)
            .map_err(|_| String::from("decision peer identity preface failed"))?;

        let request: AuthorizationRequest = read_frame(&mut stream)?;
        let request_identity =
            message_identity(AUTHORIZATION_REQUEST_DOMAIN_V1.as_bytes(), &request)
                .map_err(|_| String::from("decision peer request identity failed"))?;
        let scenario = load_scenario()?;
        eprintln!(
            "ota-authority-systemd-decision-peer: bounded pressure scenario_selected scenario={scenario} request_identity={request_identity}"
        );
        let key = load_key()?;
        let now = OffsetDateTime::now_utc();
        let decision_time = if scenario == "stale" {
            now - time::Duration::minutes(5)
        } else {
            now
        };
        let mut payload = AuthorizationDecisionPayload {
            message_kind: String::from(AUTHORIZATION_DECISION),
            request_identity,
            binding_identity: request.binding_identity,
            authority_id: request.authority_id,
            attestation_identity: request.attestation_identity,
            challenge_nonce_commitment: request.challenge_nonce_commitment,
            work_unit_identity: request.work_unit_identity,
            contract_identity: request.contract_identity,
            semantic_scope_identity: request.semantic_scope_identity,
            decision: AuthorizationDecision::Allowed,
            approval_reference: Some(String::from("pressure:decision-only")),
            broker_revision: 1,
            issued_at: decision_time
                .format(&Rfc3339)
                .map_err(|_| String::from("decision peer clock format failed"))?,
            expires_at: (decision_time + time::Duration::seconds(30))
                .format(&Rfc3339)
                .map_err(|_| String::from("decision peer clock format failed"))?,
        };
        match scenario.as_str() {
            "allowed" | "stale" => {}
            "denied" => {
                payload.decision = AuthorizationDecision::Denied;
                payload.approval_reference = Some(String::from("pressure:denied"));
            }
            "wrong_scope" => {
                payload.semantic_scope_identity = format!("sha256:{}", "f".repeat(64));
            }
            "pending_timeout" | "ambiguous" => {
                payload.decision = AuthorizationDecision::Pending;
                payload.approval_reference = None;
            }
            _ => return Err(String::from("decision peer scenario is unsupported")),
        }
        let first = sign(&key, payload.clone())?;
        write_frame(&mut stream, &first)?;
        log_decision_sent(&scenario, 1, &first)?;
        if scenario == "pending_timeout" {
            std::thread::sleep(Duration::from_secs(3));
            eprintln!(
                "ota-authority-systemd-decision-peer: bounded pressure pending_timeout_wait_completed seconds=3"
            );
        } else if scenario == "ambiguous" {
            payload.broker_revision = 2;
            payload.issued_at = OffsetDateTime::now_utc()
                .format(&Rfc3339)
                .map_err(|_| String::from("decision peer clock format failed"))?;
            payload.expires_at = (OffsetDateTime::now_utc() + time::Duration::seconds(30))
                .format(&Rfc3339)
                .map_err(|_| String::from("decision peer clock format failed"))?;
            let second = sign(&key, payload)?;
            write_frame(&mut stream, &second)?;
            log_decision_sent(&scenario, 2, &second)?;
        }
        wait_for_launcher_close(&mut stream)?;
        Ok(())
    }

    fn wait_for_launcher_close(stream: &mut UnixStream) -> Result<(), String> {
        let mut unexpected = [0_u8; 1];
        match stream.read(&mut unexpected) {
            Ok(0) => Ok(()),
            Ok(_) => Err(String::from(
                "decision peer received unexpected data after its response",
            )),
            Err(_) => Err(String::from(
                "decision peer did not observe launcher-owned session completion",
            )),
        }
    }

    fn log_decision_sent(
        scenario: &str,
        ordinal: u8,
        decision: &SignedBrokerMessage<AuthorizationDecisionPayload>,
    ) -> Result<(), String> {
        let identity = message_identity(AUTHORIZATION_DECISION_DOMAIN_V1.as_bytes(), decision)
            .map_err(|_| String::from("decision peer response identity failed"))?;
        let decision_label = match decision.payload.decision {
            AuthorizationDecision::Allowed => "allowed",
            AuthorizationDecision::Denied => "denied",
            AuthorizationDecision::Pending => "pending",
        };
        let encoded = serde_json::to_string(decision)
            .map_err(|_| String::from("decision peer response evidence failed"))?;
        eprintln!(
            "ota-authority-systemd-decision-peer: bounded pressure decision_sent scenario={scenario} ordinal={ordinal} decision={decision_label} decision_identity={identity}"
        );
        eprintln!(
            "ota-authority-systemd-decision-peer: bounded pressure signed decision scenario={scenario} ordinal={ordinal} evidence={encoded}"
        );
        Ok(())
    }

    fn load_scenario() -> Result<String, String> {
        let metadata = fs::symlink_metadata(SCENARIO_PATH)
            .map_err(|_| String::from("decision peer scenario is unavailable"))?;
        if !metadata.file_type().is_file()
            || metadata.uid() != 0
            || metadata.permissions().mode() & 0o7777 != 0o600
            || metadata.nlink() != 1
        {
            return Err(String::from("decision peer scenario is unprotected"));
        }
        let scenario = fs::read_to_string(SCENARIO_PATH)
            .map_err(|_| String::from("decision peer scenario is unavailable"))?;
        Ok(scenario.trim().to_owned())
    }

    fn load_key() -> Result<SigningKey, String> {
        let directory = std::env::var("CREDENTIALS_DIRECTORY")
            .map_err(|_| String::from("decision peer credential directory is unavailable"))?;
        let path = Path::new(&directory).join(CREDENTIAL_NAME);
        let encoded = fs::read_to_string(path)
            .map_err(|_| String::from("decision peer credential is unavailable"))?;
        let bytes = URL_SAFE_NO_PAD
            .decode(encoded.trim())
            .map_err(|_| String::from("decision peer credential is invalid"))?;
        let seed: [u8; 32] = bytes
            .try_into()
            .map_err(|_| String::from("decision peer credential is invalid"))?;
        Ok(SigningKey::from_bytes(&seed))
    }

    fn sign(
        key: &SigningKey,
        payload: AuthorizationDecisionPayload,
    ) -> Result<SignedBrokerMessage<AuthorizationDecisionPayload>, String> {
        let canonical = serde_jcs::to_vec(&payload)
            .map_err(|_| String::from("decision peer canonicalization failed"))?;
        Ok(SignedBrokerMessage {
            payload,
            key_id: String::from(KEY_ID),
            algorithm: String::from("ed25519"),
            signature: URL_SAFE_NO_PAD.encode(
                key.sign(&domain_separated(
                    AUTHORIZATION_DECISION_DOMAIN_V1.as_bytes(),
                    &canonical,
                ))
                .to_bytes(),
            ),
        })
    }

    fn read_frame<T: serde::de::DeserializeOwned>(stream: &mut impl Read) -> Result<T, String> {
        let mut header = [0_u8; 4];
        stream
            .read_exact(&mut header)
            .map_err(|_| String::from("decision peer request is incomplete"))?;
        let length = u32::from_be_bytes(header) as usize;
        if length == 0 || length > MAX_FRAME_BYTES {
            return Err(String::from("decision peer request is invalid"));
        }
        let mut frame = Vec::with_capacity(4 + length);
        frame.extend_from_slice(&header);
        frame.resize(4 + length, 0);
        stream
            .read_exact(&mut frame[4..])
            .map_err(|_| String::from("decision peer request is incomplete"))?;
        serde_json::from_slice(
            decode_frame(&frame).map_err(|_| String::from("decision peer request is invalid"))?,
        )
        .map_err(|_| String::from("decision peer request is invalid"))
    }

    fn write_frame<T: serde::Serialize>(stream: &mut impl Write, value: &T) -> Result<(), String> {
        let payload = serde_json::to_vec(value)
            .map_err(|_| String::from("decision peer response is invalid"))?;
        let frame = encode_frame(&payload)
            .map_err(|_| String::from("decision peer response is too large"))?;
        stream
            .write_all(&frame)
            .map_err(|_| String::from("decision peer response failed"))
    }

    fn set_cloexec(descriptor: i32) -> Result<(), String> {
        let flags = unsafe { libc::fcntl(descriptor, libc::F_GETFD) };
        if flags < 0
            || unsafe { libc::fcntl(descriptor, libc::F_SETFD, flags | libc::FD_CLOEXEC) } < 0
        {
            return Err(String::from("decision peer listener is invalid"));
        }
        Ok(())
    }
}

#[cfg(target_os = "linux")]
fn main() {
    if let Err(error) = linux::run() {
        eprintln!("ota-authority-systemd-decision-peer: {error}");
        std::process::exit(1);
    }
}

#[cfg(not(target_os = "linux"))]
fn main() {
    eprintln!("ota-authority-systemd-decision-peer is supported only on Linux");
    std::process::exit(2);
}
