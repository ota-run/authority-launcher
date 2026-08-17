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
//! This binary is not a production broker. It relays one pressure-only consumed lease and has no
//! selected-work path.

#[cfg(target_os = "linux")]
mod linux {
    use std::collections::BTreeSet;
    use std::fs;
    use std::fs::{File, OpenOptions};
    use std::io::{Read, Seek, SeekFrom, Write};
    use std::os::fd::{AsRawFd, FromRawFd};
    use std::os::unix::fs::{MetadataExt, OpenOptionsExt, PermissionsExt};
    use std::os::unix::net::{UnixListener, UnixStream};
    use std::path::Path;
    use std::time::Duration;

    use base64::Engine;
    use base64::engine::general_purpose::URL_SAFE_NO_PAD;
    use ed25519_dalek::{Signer, SigningKey};
    use ota_authority_launcher::linux_observations::{
        BROKER_PROXY_IDENTITY_CHALLENGE, BROKER_PROXY_IDENTITY_PREFACE,
    };
    use ota_authority_protocol::{
        AUTHORIZATION_DECISION, AUTHORIZATION_DECISION_DOMAIN_V1, AUTHORIZATION_REQUEST_DOMAIN_V1,
        AuthorizationDecision, AuthorizationDecisionPayload, AuthorizationRequest, LEASE_CONSUME,
        LEASE_CONSUME_DOMAIN_V1, LEASE_CONSUME_RESPONSE, LEASE_CONSUME_RESPONSE_DOMAIN_V1,
        LEASE_ISSUANCE, LEASE_ISSUANCE_DOMAIN_V1, LeaseConsumeRequest, LeaseConsumeResponsePayload,
        LeaseConsumeState, MAX_FRAME_BYTES, PreparedLeasePayload, SignedBrokerMessage,
        decode_frame, domain_separated, encode_frame, message_identity,
    };
    use time::OffsetDateTime;
    use time::format_description::well_known::Rfc3339;

    const SYSTEMD_LISTEN_FD: i32 = 3;
    const CREDENTIAL_NAME: &str = "ota-broker-ed25519";
    const KEY_ID: &str = "systemd-broker-pressure-v1";
    const SCENARIO_PATH: &str = "/var/lib/ota/authority-broker-pressure/scenario";
    const SPENT_LEASES_PATH: &str = "/var/lib/ota/authority-broker-pressure/consumed-leases.json";
    const SPENT_LEASES_LOCK_PATH: &str =
        "/var/lib/ota/authority-broker-pressure/consumed-leases.lock";
    // Keep the pressure lease below both the configured lease ceiling and attestation lifetime.
    const LEASE_VALIDITY_SECONDS: i64 = 20;

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
        let mut identity_challenge = [0_u8; 1];
        stream
            .read_exact(&mut identity_challenge)
            .map_err(|_| String::from("decision peer identity challenge failed"))?;
        if identity_challenge.as_slice() != BROKER_PROXY_IDENTITY_CHALLENGE {
            return Err(String::from("decision peer identity challenge mismatched"));
        }
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
            binding_identity: request.binding_identity.clone(),
            authority_id: request.authority_id.clone(),
            attestation_identity: request.attestation_identity.clone(),
            challenge_nonce_commitment: request.challenge_nonce_commitment.clone(),
            work_unit_identity: request.work_unit_identity.clone(),
            contract_identity: request.contract_identity.clone(),
            semantic_scope_identity: request.semantic_scope_identity.clone(),
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
        if scenario == "allowed" {
            relay_consumed_lease(&key, &mut stream, &request, &first)?;
        }
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
        sign_message(key, AUTHORIZATION_DECISION_DOMAIN_V1.as_bytes(), payload)
    }

    fn sign_message<T: serde::Serialize>(
        key: &SigningKey,
        domain: &[u8],
        payload: T,
    ) -> Result<SignedBrokerMessage<T>, String> {
        let canonical = serde_jcs::to_vec(&payload)
            .map_err(|_| String::from("decision peer canonicalization failed"))?;
        Ok(SignedBrokerMessage {
            payload,
            key_id: String::from(KEY_ID),
            algorithm: String::from("ed25519"),
            signature: URL_SAFE_NO_PAD
                .encode(key.sign(&domain_separated(domain, &canonical)).to_bytes()),
        })
    }

    fn relay_consumed_lease(
        key: &SigningKey,
        stream: &mut UnixStream,
        request: &AuthorizationRequest,
        decision: &SignedBrokerMessage<AuthorizationDecisionPayload>,
    ) -> Result<(), String> {
        let decision_identity =
            message_identity(AUTHORIZATION_DECISION_DOMAIN_V1.as_bytes(), decision)
                .map_err(|_| String::from("decision peer decision identity failed"))?;
        let lease = sign_message(
            key,
            LEASE_ISSUANCE_DOMAIN_V1.as_bytes(),
            PreparedLeasePayload {
                message_kind: LEASE_ISSUANCE.into(),
                authorization_decision_identity: decision_identity,
                binding_identity: decision.payload.binding_identity.clone(),
                authority_id: decision.payload.authority_id.clone(),
                attestation_identity: decision.payload.attestation_identity.clone(),
                challenge_nonce_commitment: decision.payload.challenge_nonce_commitment.clone(),
                work_unit_identity: decision.payload.work_unit_identity.clone(),
                contract_identity: decision.payload.contract_identity.clone(),
                semantic_scope_identity: decision.payload.semantic_scope_identity.clone(),
                runner_principal: request.runner_principal.clone(),
                broker_revision: 1,
                lease_sequence: 1,
                issued_at: decision.payload.issued_at.clone(),
                expires_at: lease_expiration(&decision.payload.issued_at)?,
            },
        )?;
        let lease_identity = message_identity(LEASE_ISSUANCE_DOMAIN_V1.as_bytes(), &lease)
            .map_err(|_| String::from("decision peer lease identity failed"))?;
        write_frame(stream, &lease)?;
        let consume: LeaseConsumeRequest = read_frame(stream)?;
        if consume.message_kind != LEASE_CONSUME
            || consume.lease_identity != lease_identity
            || consume.binding_identity != lease.payload.binding_identity
            || consume.work_unit_identity != lease.payload.work_unit_identity
        {
            return Err(String::from("decision peer consume request is invalid"));
        }
        let consume_identity = message_identity(LEASE_CONSUME_DOMAIN_V1.as_bytes(), &consume)
            .map_err(|_| String::from("decision peer consume identity failed"))?;
        let state = consume_lease_once(lease_identity.as_str())?;
        if state != LeaseConsumeState::Consumed {
            return Err(String::from("decision peer lease was already spent"));
        }
        let response = signed_consume_response(
            key,
            &consume,
            consume_identity.as_str(),
            lease_identity.as_str(),
            state,
            2,
            decision.payload.issued_at.as_str(),
        )?;
        write_frame(stream, &response)?;
        eprintln!("ota-authority-systemd-decision-peer: bounded pressure lease_consumed_relayed");

        // Reopen the durable store and replay the exact consume request. This response is retained
        // as public pressure evidence but is never forwarded to Core.
        let replay_state = consume_lease_once(lease_identity.as_str())?;
        if replay_state != LeaseConsumeState::AlreadyConsumed {
            return Err(String::from("decision peer exact replay was not refused"));
        }
        let replay = signed_consume_response(
            key,
            &consume,
            consume_identity.as_str(),
            lease_identity.as_str(),
            replay_state,
            3,
            decision.payload.issued_at.as_str(),
        )?;
        let replay_identity =
            message_identity(LEASE_CONSUME_RESPONSE_DOMAIN_V1.as_bytes(), &replay)
                .map_err(|_| String::from("decision peer replay response identity failed"))?;
        let encoded = serde_json::to_string(&replay)
            .map_err(|_| String::from("decision peer replay evidence failed"))?;
        eprintln!(
            "ota-authority-systemd-decision-peer: bounded pressure exact_replay_refused state=already_consumed response_identity={replay_identity} evidence={encoded}"
        );
        Ok(())
    }

    fn signed_consume_response(
        key: &SigningKey,
        consume: &LeaseConsumeRequest,
        consume_identity: &str,
        lease_identity: &str,
        state: LeaseConsumeState,
        broker_revision: u64,
        consumed_at: &str,
    ) -> Result<SignedBrokerMessage<LeaseConsumeResponsePayload>, String> {
        sign_message(
            key,
            LEASE_CONSUME_RESPONSE_DOMAIN_V1.as_bytes(),
            LeaseConsumeResponsePayload {
                message_kind: LEASE_CONSUME_RESPONSE.into(),
                consume_request_identity: consume_identity.to_string(),
                binding_identity: consume.binding_identity.clone(),
                lease_identity: lease_identity.to_string(),
                challenge_nonce_commitment: consume.challenge_nonce_commitment.clone(),
                work_unit_identity: consume.work_unit_identity.clone(),
                crossing_transaction_id: consume.crossing_transaction_id.clone(),
                crossing_transaction_identity: consume.crossing_transaction_identity.clone(),
                state,
                broker_revision,
                consumed_at: consumed_at.to_string(),
            },
        )
    }

    fn consume_lease_once(lease_identity: &str) -> Result<LeaseConsumeState, String> {
        consume_lease_once_at(
            Path::new(SPENT_LEASES_LOCK_PATH),
            Path::new(SPENT_LEASES_PATH),
            lease_identity,
        )
    }

    fn consume_lease_once_at(
        lock_path: &Path,
        state_path: &Path,
        lease_identity: &str,
    ) -> Result<LeaseConsumeState, String> {
        let lock = open_protected_state_file(lock_path)?;
        if unsafe { libc::flock(lock.as_raw_fd(), libc::LOCK_EX) } != 0 {
            return Err(String::from("decision peer spent-lease lock failed"));
        }
        let mut consumed = read_consumed_leases(state_path)?;
        if !consumed.insert(lease_identity.to_string()) {
            return Ok(LeaseConsumeState::AlreadyConsumed);
        }
        persist_consumed_leases(state_path, &consumed)?;
        Ok(LeaseConsumeState::Consumed)
    }

    fn open_protected_state_file(path: &Path) -> Result<File, String> {
        let file = OpenOptions::new()
            .create(true)
            .read(true)
            .write(true)
            .mode(0o600)
            .custom_flags(libc::O_CLOEXEC | libc::O_NOFOLLOW)
            .open(path)
            .map_err(|_| String::from("decision peer spent-lease state is unavailable"))?;
        let metadata = file
            .metadata()
            .map_err(|_| String::from("decision peer spent-lease state is unavailable"))?;
        if !metadata.file_type().is_file()
            || metadata.uid() != 0
            || metadata.permissions().mode() & 0o7777 != 0o600
            || metadata.nlink() != 1
        {
            return Err(String::from(
                "decision peer spent-lease state is unprotected",
            ));
        }
        Ok(file)
    }

    fn read_consumed_leases(path: &Path) -> Result<BTreeSet<String>, String> {
        let mut file = open_protected_state_file(path)?;
        file.seek(SeekFrom::Start(0))
            .map_err(|_| String::from("decision peer spent-lease state is unavailable"))?;
        let mut bytes = Vec::new();
        file.read_to_end(&mut bytes)
            .map_err(|_| String::from("decision peer spent-lease state is unavailable"))?;
        if bytes.is_empty() {
            Ok(BTreeSet::new())
        } else {
            serde_json::from_slice(&bytes)
                .map_err(|_| String::from("decision peer spent-lease state is invalid"))
        }
    }

    fn persist_consumed_leases(
        state_path: &Path,
        consumed: &BTreeSet<String>,
    ) -> Result<(), String> {
        let directory = state_path
            .parent()
            .ok_or_else(|| String::from("decision peer spent-lease state path is invalid"))?;
        let file_name = state_path
            .file_name()
            .and_then(|name| name.to_str())
            .ok_or_else(|| String::from("decision peer spent-lease state path is invalid"))?;
        let temporary = directory.join(format!("{file_name}.{}", unsafe { libc::getpid() }));
        let bytes = serde_json::to_vec(consumed)
            .map_err(|_| String::from("decision peer spent-lease state is invalid"))?;
        let mut file = OpenOptions::new()
            .create_new(true)
            .write(true)
            .mode(0o600)
            .custom_flags(libc::O_CLOEXEC | libc::O_NOFOLLOW)
            .open(&temporary)
            .map_err(|_| String::from("decision peer spent-lease state write failed"))?;
        let result = (|| {
            file.write_all(&bytes)
                .and_then(|()| file.sync_all())
                .map_err(|_| String::from("decision peer spent-lease state write failed"))?;
            fs::rename(&temporary, state_path)
                .map_err(|_| String::from("decision peer spent-lease state commit failed"))?;
            File::open(directory)
                .and_then(|directory| directory.sync_all())
                .map_err(|_| String::from("decision peer spent-lease directory sync failed"))
        })();
        if result.is_err() {
            fs::remove_file(&temporary).ok();
        }
        result
    }

    fn lease_expiration(issued_at: &str) -> Result<String, String> {
        (OffsetDateTime::parse(issued_at, &Rfc3339)
            .map_err(|_| String::from("decision peer lease clock is invalid"))?
            + time::Duration::seconds(LEASE_VALIDITY_SECONDS))
        .format(&Rfc3339)
        .map_err(|_| String::from("decision peer lease clock format failed"))
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

    #[cfg(test)]
    mod tests {
        use super::*;

        #[test]
        fn pressure_lease_keeps_a_fixed_attestation_margin() {
            assert_eq!(
                lease_expiration("2026-08-12T12:00:00Z").expect("lease expiration"),
                "2026-08-12T12:00:20Z"
            );
        }

        #[test]
        fn spent_lease_state_refuses_exact_replay_durably() {
            if unsafe { libc::geteuid() } != 0 {
                return;
            }
            let directory = tempfile::tempdir_in("/root").expect("protected temporary state");
            let lock = directory.path().join("consumed-leases.lock");
            let state = directory.path().join("consumed-leases.json");
            assert_eq!(
                consume_lease_once_at(&lock, &state, "sha256:lease-a").expect("first consumption"),
                LeaseConsumeState::Consumed
            );
            assert_eq!(
                consume_lease_once_at(&lock, &state, "sha256:lease-a")
                    .expect("replayed consumption"),
                LeaseConsumeState::AlreadyConsumed
            );
            let persisted: BTreeSet<String> =
                serde_json::from_slice(&fs::read(&state).expect("persisted spent-lease state"))
                    .expect("valid spent-lease state");
            assert_eq!(persisted, BTreeSet::from([String::from("sha256:lease-a")]));
        }
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
